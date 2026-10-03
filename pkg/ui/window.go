// Package ui is the GTK3 user interface: a menu bar and toolbar over three panes, the type
// tree, the item list and the detail view.
//
// Every backend call can block (D-Bus round trips, running gpg, waiting on an unlock
// prompt), so they run on goroutines via App.background and only touch widgets from the
// GTK main loop.
package ui

import (
	"context"
	"runtime"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"github.com/spf13/afero"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/landhorse/pkg/backend"
	"github.com/wrouesnel/landhorse/version"
)

//nolint:gochecknoinits // GTK must be driven from the thread that called gtk_init.
func init() {
	runtime.LockOSThread()
}

// Options configures the window.
type Options struct {
	Groups []backend.Group
	// Fs is where exported files are written.
	Fs afero.Fs
	// InitialCategory, when set, selects the category with this key on startup.
	InitialCategory string
	// ConfigPath is the configuration file, named in help text about settings.
	ConfigPath string
	// Settings reads and saves the preferences shown in Edit → Preferences. Nil hides it.
	Settings Settings
}

// Settings is what the preferences dialog edits.
type Settings interface {
	// KeyringGroupings are the attributes keyring items are grouped by.
	KeyringGroupings() []backend.AttributeGrouping
	// SetKeyringGroupings saves and applies new groupings; refresh the tree to see them.
	SetKeyringGroupings(groupings []backend.AttributeGrouping) error
	// KeyringAttributes counts the items having each attribute, to suggest groupings.
	KeyringAttributes(ctx context.Context) (map[string]int, error)
}

// App is the main window and its state.
type App struct {
	ctx    context.Context
	opts   Options
	window *gtk.Window

	types *typeTree
	list  *itemList
	info  *detailView

	toolbar *toolbar
	search  *gtk.SearchEntry

	status        *gtk.Statusbar
	statusContext uint

	// related indexes items across backends for the detail view's Related Items.
	related           *relatedIndex
	relatedGeneration int
}

// Run shows the window and runs the GTK main loop until the window is closed or ctx is
// cancelled. It must be called from the main goroutine.
func Run(ctx context.Context, opts Options) error {
	// The program name becomes the Wayland app ID and X11 WM_CLASS, which desktops match
	// against the .desktop file name to find the icon and group windows.
	glib.SetPrgname(version.AppID)
	glib.SetApplicationName("Passwords and Keys")

	// gotk3 releases GObjects from Go's finalizer goroutine by default, but GTK isn't thread
	// safe: dropping the last reference to a widget, such as a confirmation dialog that was
	// just destroyed, runs its dispose and finalize on that goroutine while the main loop is
	// busy, which crashed landhorse after deleting a password. Release them on the main loop.
	glib.FinalizerStrategy = func(f glib.Finalizer) {
		glib.IdleAdd(func() { f() })
	}

	gtk.Init(nil)

	installCSS()

	app := &App{ctx: ctx, opts: opts}
	if err := app.build(); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		glib.IdleAdd(gtk.MainQuit)
	}()

	app.window.ShowAll()
	app.refreshTypes()
	gtk.Main()
	return nil
}

// appCSS keeps the detail view's copy buttons no taller than a line of text, so fields stay
// evenly spaced.
const appCSS = `
button.copy-button { padding: 0 4px; min-height: 0; min-width: 0; }
`

func installCSS() {
	provider, err := gtk.CssProviderNew()
	if err != nil {
		return
	}
	if err := provider.LoadFromData(appCSS); err != nil {
		return
	}
	if screen, err := gdk.ScreenGetDefault(); err == nil {
		gtk.AddProviderForScreen(screen, provider, gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
	}
}

func (a *App) build() error {
	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		return err
	}
	a.window = win
	win.SetTitle("Passwords and Keys — " + version.Name)
	win.SetIconName(version.AppID)
	win.SetDefaultSize(1180, 720)
	win.Connect("destroy", gtk.MainQuit)

	accel, err := gtk.AccelGroupNew()
	if err != nil {
		return err
	}
	win.AddAccelGroup(accel)

	menubar, err := a.buildMenuBar(accel)
	if err != nil {
		return err
	}
	tb, err := a.buildToolbar()
	if err != nil {
		return err
	}
	a.toolbar = tb

	if a.types, err = newTypeTree(a); err != nil {
		return err
	}
	if a.list, err = newItemList(a); err != nil {
		return err
	}
	if a.info, err = newDetailView(a); err != nil {
		return err
	}

	// type tree | ( item list | detail view )
	inner, err := gtk.PanedNew(gtk.ORIENTATION_HORIZONTAL)
	if err != nil {
		return err
	}
	inner.Pack1(a.list.widget(), true, false)
	inner.Pack2(a.info.widget(), true, false)
	inner.SetPosition(560)

	outer, err := gtk.PanedNew(gtk.ORIENTATION_HORIZONTAL)
	if err != nil {
		return err
	}
	outer.Pack1(a.types.widget(), false, false)
	outer.Pack2(inner, true, false)
	outer.SetPosition(230)

	a.status, err = gtk.StatusbarNew()
	if err != nil {
		return err
	}
	a.statusContext = a.status.GetContextId("main")

	vbox, err := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)
	if err != nil {
		return err
	}
	vbox.PackStart(menubar, false, false, 0)
	vbox.PackStart(tb.bar, false, false, 0)
	vbox.PackStart(outer, true, true, 0)
	vbox.PackStart(a.status, false, false, 0)
	win.Add(vbox)

	a.updateActions()
	return nil
}

// setStatus replaces the status bar message.
func (a *App) setStatus(msg string) {
	a.status.RemoveAll(a.statusContext)
	a.status.Push(a.statusContext, msg)
}

// background runs work on a goroutine. work returns a function, which is run on the GTK main
// loop to apply the result to the widgets.
func (a *App) background(work func(ctx context.Context) func()) {
	go func() {
		apply := work(a.ctx)
		if apply != nil {
			glib.IdleAdd(apply)
		}
	}()
}

// showError reports a failed action in a dialog and logs it.
func (a *App) showError(title string, err error) {
	logutil.FromCtx(a.ctx).Warn(title, zap.Error(err))
	dlg := gtk.MessageDialogNew(a.window, gtk.DIALOG_MODAL|gtk.DIALOG_DESTROY_WITH_PARENT,
		gtk.MESSAGE_ERROR, gtk.BUTTONS_CLOSE, "%s", title)
	dlg.FormatSecondaryText("%s", err.Error())
	dlg.Run()
	dlg.Destroy()
}

// showInfo shows a simple informational dialog.
func (a *App) showInfo(title, text string) {
	dlg := gtk.MessageDialogNew(a.window, gtk.DIALOG_MODAL|gtk.DIALOG_DESTROY_WITH_PARENT,
		gtk.MESSAGE_INFO, gtk.BUTTONS_CLOSE, "%s", title)
	if text != "" {
		dlg.FormatSecondaryText("%s", text)
	}
	dlg.Run()
	dlg.Destroy()
}

// selectedCategory returns the category selected in the type tree, if any.
func (a *App) selectedCategory() backend.Category {
	return a.types.selected()
}

// selectedItem returns the item selected in the item list, if any.
func (a *App) selectedItem() backend.Item {
	return a.list.selected()
}

// onCategorySelected is called by the type tree when its selection changes.
func (a *App) onCategorySelected(cat backend.Category) {
	a.list.load(cat)
	a.updateActions()
}

// onItemSelected is called by the item list when its selection changes.
func (a *App) onItemSelected(item backend.Item) {
	a.info.show(item)
	a.updateActions()
}

// lockStateChanged updates the lock icons, status bar and toolbar after a keyring was
// unlocked as a side effect, without reloading anything (which would reset the detail view).
func (a *App) lockStateChanged() {
	a.types.refreshIcons()
	a.list.updateStatus()
	a.updateActions()
}

// refreshTypes reloads the type tree, which in turn reloads the selected category.
func (a *App) refreshTypes() {
	a.types.load()
}
