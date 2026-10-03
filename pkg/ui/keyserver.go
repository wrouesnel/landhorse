package ui

import (
	"context"
	"errors"
	"fmt"
	"html"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// followTableLink goes to the item a table row links to, or if it isn't here, searches
// the keyservers for it in the detail view's results pane.
func (a *App) followTableLink(link *backend.TableLink) {
	if a.related != nil {
		if refs := a.related.byKey[link.LinkKey]; len(refs) > 0 {
			a.navigateTo(refs[0].categoryKey, refs[0].item.Key())
			return
		}
	}
	if link.Search == "" {
		a.setStatus("That item isn't here.")
		return
	}
	a.info.results.search(link.Search)
}

// plural formats a count with the singular or plural noun.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// keySearcher returns the category that searches every keyserver, if there is one.
func (a *App) keySearcher() backend.KeySearcher {
	for _, cat := range a.types.categories {
		if s, ok := cat.(backend.KeySearcher); ok && s.SearchesEverywhere() {
			return s
		}
	}
	return nil
}

// importRemote imports an item found elsewhere, such as on a keyserver.
func (a *App) importRemote(importer backend.RemoteImporter) {
	a.setStatus("Importing…")
	a.background(func(ctx context.Context) func() {
		report, err := importer.ImportToLocal(ctx)
		return func() {
			if err != nil {
				a.setStatus("")
				a.showError("Import failed", err)
				return
			}
			a.setStatus("Imported.")
			a.showInfo("Imported", report)
			// The keyring changed: refresh the tree, the lists and what's related.
			a.refreshTypes()
		}
	})
}

// resultsPane is the lower part of the detail view, showing keyserver search results for a
// signer that isn't in the keyring.
type resultsPane struct {
	app     *App
	box     *gtk.Box
	heading *gtk.Label
	store   *gtk.ListStore
	view    *gtk.TreeView
	items   []backend.Item
	gen     int
}

func newResultsPane(app *App) (*resultsPane, error) {
	r := &resultsPane{app: app}
	var err error
	r.box, err = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 6)
	if err != nil {
		return nil, err
	}
	r.box.SetMarginStart(12)
	r.box.SetMarginEnd(12)
	r.box.SetMarginTop(6)
	r.box.SetMarginBottom(6)
	r.box.SetNoShowAll(true)

	top, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 6)
	r.heading = newLabel("")
	r.heading.SetLineWrap(true)
	top.PackStart(r.heading, true, true, 0)
	closeBtn, _ := gtk.ButtonNewFromIconName("window-close-symbolic", gtk.ICON_SIZE_MENU)
	closeBtn.SetRelief(gtk.RELIEF_NONE)
	closeBtn.SetTooltipText("Close the search results")
	closeBtn.Connect("clicked", r.hide)
	top.PackEnd(closeBtn, false, false, 0)
	r.box.PackStart(top, false, false, 0)

	// Name, email, key ID, status, then the index into items.
	r.store, err = gtk.ListStoreNew(glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT)
	if err != nil {
		return nil, err
	}
	r.view, err = gtk.TreeViewNewWithModel(r.store)
	if err != nil {
		return nil, err
	}
	for i, title := range []string{"Name", "Email", "Key ID", "Status"} {
		cell, _ := gtk.CellRendererTextNew()
		col, _ := gtk.TreeViewColumnNewWithAttribute(title, cell, "text", i)
		col.SetResizable(true)
		r.view.AppendColumn(col)
	}
	r.view.SetTooltipText("Right-click a key to import it")
	r.view.Connect("button-press-event", r.onButtonPress)
	scroll, _ := gtk.ScrolledWindowNew(nil, nil)
	scroll.SetShadowType(gtk.SHADOW_IN)
	scroll.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	scroll.Add(r.view)
	r.box.PackStart(scroll, true, true, 0)
	return r, nil
}

func (r *resultsPane) widget() gtk.IWidget { return r.box }

func (r *resultsPane) hide() {
	r.gen++
	r.box.Hide()
}

// search shows the pane and searches all keyservers for query.
func (r *resultsPane) search(query string) {
	searcher := r.app.keySearcher()
	if searcher == nil {
		r.app.showError("Can't search for this key", errors.New("it isn't in your keyring, and no keyservers are configured"))
		return
	}
	r.gen++
	gen := r.gen
	r.items = nil
	r.store.Clear()
	r.heading.SetMarkup("<b>Searching keyservers for " + html.EscapeString(query) + "…</b>")
	r.box.SetNoShowAll(false)
	r.box.ShowAll()
	// Give the results a good share of the pane.
	if h := r.app.info.paned.GetAllocatedHeight(); h > 0 {
		r.app.info.paned.SetPosition(h * 55 / 100)
	}
	r.app.background(func(ctx context.Context) func() {
		items, problems, err := searcher.Search(ctx, query)
		return func() {
			if gen != r.gen {
				return
			}
			if err != nil {
				r.heading.SetMarkup("<b>Searching for " + html.EscapeString(query) + " failed</b>\n" + html.EscapeString(err.Error()))
				return
			}
			r.items = items
			for i, item := range items {
				cells := item.Cells()
				iter := r.store.Append()
				_ = r.store.SetValue(iter, 0, cells[0])
				_ = r.store.SetValue(iter, 1, cells[1])
				_ = r.store.SetValue(iter, 2, cells[2])
				_ = r.store.SetValue(iter, 3, cells[4])
				_ = r.store.SetValue(iter, 4, i)
			}
			heading := fmt.Sprintf("<b>%s on keyservers for %s</b>", plural(len(items), "key", "keys"), html.EscapeString(query))
			if len(items) == 0 {
				heading = "<b>No keyserver has " + html.EscapeString(query) + "</b>"
			}
			if len(problems) > 0 {
				heading += fmt.Sprintf("\n%d keyservers couldn't be searched.", len(problems))
			}
			r.heading.SetMarkup(heading)
		}
	})
}

// onButtonPress shows the Import menu for the row under a right-click.
func (r *resultsPane) onButtonPress(_ *gtk.TreeView, ev *gdk.Event) bool {
	btn := gdk.EventButtonNewFromEvent(ev)
	if btn.Button() != gdk.BUTTON_SECONDARY || btn.Type() != gdk.EVENT_BUTTON_PRESS {
		return false
	}
	path, _, _, _, ok := r.view.GetPathAtPos(int(btn.X()), int(btn.Y()))
	if !ok || path == nil {
		return true
	}
	r.view.SetCursor(path, nil, false)
	iter, err := r.store.ToTreeModel().GetIter(path)
	if err != nil {
		return true
	}
	v, _ := r.store.ToTreeModel().GetValue(iter, 4)
	gv, _ := v.GoValue()
	idx, _ := gv.(int)
	if idx < 0 || idx >= len(r.items) {
		return true
	}
	importer, ok := r.items[idx].(backend.RemoteImporter)
	if !ok {
		return true
	}
	menu, _ := gtk.MenuNew()
	item, _ := gtk.MenuItemNewWithMnemonic("_Import")
	item.Connect("activate", func() { r.app.importRemote(importer) })
	menu.Append(item)
	menu.ShowAll()
	menu.PopupAtPointer(ev)
	return true
}
