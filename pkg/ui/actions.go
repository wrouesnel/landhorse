package ui

import (
	"context"
	"fmt"

	"github.com/chigopher/pathlib"
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
	"github.com/wrouesnel/landhorse/version"
)

// toolbar holds the buttons whose sensitivity follows the selection.
type toolbar struct {
	bar *gtk.Toolbar

	refresh, unlock, lock, copy, importBtn, export, publish, del *gtk.ToolButton
}

// menuItems are the menu entries whose sensitivity follows the selection.
type menuItems struct {
	importItem, export, publish, revoke, copy, del, unlock, lock *gtk.MenuItem
}

//nolint:gochecknoglobals // set once by buildMenuBar, read by updateActions
var menus menuItems

func newToolButton(icon, label, tooltip string, onClick func()) (*gtk.ToolButton, error) {
	btn, err := gtk.ToolButtonNew(nil, label)
	if err != nil {
		return nil, err
	}
	btn.SetIconName(icon)
	btn.SetTooltipText(tooltip)
	btn.SetIsImportant(true)
	btn.Connect("clicked", onClick)
	return btn, nil
}

func (a *App) buildToolbar() (*toolbar, error) {
	bar, err := gtk.ToolbarNew()
	if err != nil {
		return nil, err
	}
	// Icons with labels beside them: every action is discoverable without hovering.
	bar.SetStyle(gtk.TOOLBAR_BOTH_HORIZ)
	if ctx, err := bar.GetStyleContext(); err == nil {
		ctx.AddClass("primary-toolbar")
	}

	tb := &toolbar{bar: bar}
	buttons := []struct {
		target  **gtk.ToolButton
		icon    string
		label   string
		tooltip string
		action  func()
	}{
		{&tb.refresh, "view-refresh", "Refresh", "Reload everything (F5)", a.actionRefresh},
		{nil, "", "", "", nil},
		{&tb.unlock, "changes-allow", "Unlock", "Unlock the selected keyring", a.actionUnlock},
		{&tb.lock, "changes-prevent", "Lock", "Lock the selected keyring", a.actionLock},
		{nil, "", "", "", nil},
		{&tb.copy, "edit-copy", "Copy", "Copy the password or public key (Ctrl+C in the list)", a.actionCopy},
		{&tb.importBtn, "document-open", "Import…", "Import keys from a file (Ctrl+O)", a.actionImport},
		{&tb.export, "document-save-as", "Export…", "Save the public key to a file (Ctrl+S)", a.actionExport},
		{&tb.publish, "document-send", "Publish…", "Upload the public key to a keyserver", a.actionPublish},
		{&tb.del, "edit-delete", "Delete", "Delete the selected item (Delete in the list)", a.actionDelete},
	}
	for _, b := range buttons {
		if b.target == nil {
			sep, err := gtk.SeparatorToolItemNew()
			if err != nil {
				return nil, err
			}
			bar.Insert(sep, -1)
			continue
		}
		btn, err := newToolButton(b.icon, b.label, b.tooltip, b.action)
		if err != nil {
			return nil, err
		}
		*b.target = btn
		bar.Insert(btn, -1)
	}

	// Push the search box to the right hand end.
	spacer, err := gtk.SeparatorToolItemNew()
	if err != nil {
		return nil, err
	}
	spacer.SetDraw(false)
	spacer.SetExpand(true)
	bar.Insert(spacer, -1)

	a.search, err = gtk.SearchEntryNew()
	if err != nil {
		return nil, err
	}
	a.search.SetPlaceholderText("Filter list (Ctrl+F)")
	a.search.SetWidthChars(28)
	a.search.Connect("search-changed", func() {
		text, _ := a.search.GetText()
		a.list.setFilter(text)
	})
	searchItem, err := gtk.ToolItemNew()
	if err != nil {
		return nil, err
	}
	searchItem.Add(a.search)
	bar.Insert(searchItem, -1)

	return tb, nil
}

// buildMenuBar builds the File/Edit/View/Help menus. Global shortcuts live here; shortcuts
// that would clash with text editing (Ctrl+C, Delete) are handled by the item list instead.
func (a *App) buildMenuBar(accel *gtk.AccelGroup) (*gtk.MenuBar, error) {
	bar, err := gtk.MenuBarNew()
	if err != nil {
		return nil, err
	}

	addMenu := func(title string) *gtk.Menu {
		top, _ := gtk.MenuItemNewWithMnemonic(title)
		menu, _ := gtk.MenuNew()
		top.SetSubmenu(menu)
		bar.Append(top)
		return menu
	}
	addItem := func(menu *gtk.Menu, label string, key uint, mods gdk.ModifierType, action func()) *gtk.MenuItem {
		item, _ := gtk.MenuItemNewWithMnemonic(label)
		item.Connect("activate", action)
		if key != 0 {
			item.AddAccelerator("activate", accel, key, mods, gtk.ACCEL_VISIBLE)
		}
		menu.Append(item)
		return item
	}
	addSeparator := func(menu *gtk.Menu) {
		sep, _ := gtk.SeparatorMenuItemNew()
		menu.Append(sep)
	}

	file := addMenu("_File")
	menus.importItem = addItem(file, "_Import…", gdk.KEY_o, gdk.CONTROL_MASK, a.actionImport)
	menus.export = addItem(file, "_Export…", gdk.KEY_s, gdk.CONTROL_MASK, a.actionExport)
	menus.publish = addItem(file, "_Publish to Keyserver…", 0, 0, a.actionPublish)
	addSeparator(file)
	addItem(file, "_Quit", gdk.KEY_q, gdk.CONTROL_MASK, func() { a.window.Destroy() })

	edit := addMenu("_Edit")
	menus.copy = addItem(edit, "_Copy Password or Key", 0, 0, a.actionCopy)
	menus.del = addItem(edit, "_Delete", 0, 0, a.actionDelete)
	menus.revoke = addItem(edit, "Re_voke Key…", 0, 0, a.actionRevoke)
	addSeparator(edit)
	menus.unlock = addItem(edit, "_Unlock Keyring", 0, 0, a.actionUnlock)
	menus.lock = addItem(edit, "_Lock Keyring", gdk.KEY_l, gdk.CONTROL_MASK, a.actionLock)
	addSeparator(edit)
	addItem(edit, "_Find", gdk.KEY_f, gdk.CONTROL_MASK, func() { a.search.GrabFocus() })
	if a.opts.Settings != nil {
		addSeparator(edit)
		addItem(edit, "Prefere_nces", gdk.KEY_comma, gdk.CONTROL_MASK, a.actionPreferences)
	}

	view := addMenu("_View")
	addItem(view, "_Refresh", gdk.KEY_F5, 0, a.actionRefresh)

	help := addMenu("_Help")
	addItem(help, "_About", 0, 0, a.actionAbout)

	return bar, nil
}

// popupItemMenu shows the item list's context menu. ev is nil when opened from the keyboard.
func (a *App) popupItemMenu(ev *gdk.Event) {
	item := a.selectedItem()
	if item == nil {
		return
	}
	menu, err := gtk.MenuNew()
	if err != nil {
		return
	}
	add := func(label string, enabled bool, action func()) {
		mi, _ := gtk.MenuItemNewWithMnemonic(label)
		mi.SetSensitive(enabled)
		mi.Connect("activate", action)
		menu.Append(mi)
	}
	copier, canCopy := item.(backend.Copier)
	copyLabel := "_Copy"
	if canCopy {
		copyLabel = "_Copy " + copier.CopyLabel()
	}
	_, canExport := item.(backend.Exporter)
	_, canDelete := item.(backend.Deleter)
	add(copyLabel, canCopy, a.actionCopy)
	add("_Export…", canExport, a.actionExport)
	add("_Publish…", canPublish(item), a.actionPublish)
	if _, ok := item.(backend.Revoker); ok {
		add("Re_voke…", canRevoke(item), a.actionRevoke)
	}
	sep, _ := gtk.SeparatorMenuItemNew()
	menu.Append(sep)
	add("_Delete", canDelete, a.actionDelete)
	menu.ShowAll()
	menu.PopupAtPointer(ev)
}

// updateActions enables the toolbar buttons and menu items that apply to the selection.
func (a *App) updateActions() {
	if a.toolbar == nil {
		return
	}
	cat := a.selectedCategory()
	item := a.selectedItem()

	lockable, isLockable := cat.(backend.Lockable)
	_, canImport := cat.(backend.Importer)
	_, canCopy := item.(backend.Copier)
	_, canExport := item.(backend.Exporter)
	_, canDelete := item.(backend.Deleter)
	locked := isLockable && lockable.Locked()

	set := func(enabled bool, widgets ...interface{ SetSensitive(bool) }) {
		for _, w := range widgets {
			if w != nil {
				w.SetSensitive(enabled)
			}
		}
	}
	set(isLockable && locked, a.toolbar.unlock, menus.unlock)
	set(isLockable && !locked, a.toolbar.lock, menus.lock)
	set(canImport, a.toolbar.importBtn, menus.importItem)
	set(canCopy, a.toolbar.copy, menus.copy)
	set(canExport, a.toolbar.export, menus.export)
	set(canPublish(item), a.toolbar.publish, menus.publish)
	set(canRevoke(item), menus.revoke)
	set(canDelete, a.toolbar.del, menus.del)

	if copier, ok := item.(backend.Copier); ok {
		a.toolbar.copy.SetTooltipText(fmt.Sprintf("Copy the %s to the clipboard (Ctrl+C in the list)", copier.CopyLabel()))
	}
}

func (a *App) actionRefresh() {
	a.refreshTypes()
}

func (a *App) actionUnlock() {
	lk, ok := a.selectedCategory().(backend.Lockable)
	if !ok {
		return
	}
	a.setStatus("Waiting for the keyring to be unlocked…")
	a.background(func(ctx context.Context) func() {
		err := lk.Unlock(ctx)
		return func() {
			if err != nil {
				a.setStatus("")
				a.showError("Could not unlock the keyring", err)
			}
			a.refreshTypes()
		}
	})
}

func (a *App) actionLock() {
	lk, ok := a.selectedCategory().(backend.Lockable)
	if !ok {
		return
	}
	a.background(func(ctx context.Context) func() {
		err := lk.Lock(ctx)
		return func() {
			if err != nil {
				a.showError("Could not lock the keyring", err)
			}
			a.refreshTypes()
		}
	})
}

func (a *App) actionCopy() {
	copier, ok := a.selectedItem().(backend.Copier)
	if !ok {
		return
	}
	lockable, _ := a.selectedCategory().(backend.Lockable)
	wasLocked := lockable != nil && lockable.Locked()
	a.background(func(ctx context.Context) func() {
		text, err := copier.CopyText(ctx)
		return func() {
			if wasLocked {
				// Copying may have unlocked the keyring.
				defer a.lockStateChanged()
			}
			if err != nil {
				a.showError("Could not copy the "+copier.CopyLabel(), err)
				return
			}
			a.copyToClipboard(text, "the "+copier.CopyLabel())
		}
	})
}

// copyToClipboard puts text on the clipboard and says what was copied in the status bar.
func (a *App) copyToClipboard(text, what string) {
	clipboard, err := gtk.ClipboardGet(gdk.SELECTION_CLIPBOARD)
	if err != nil {
		a.showError("Could not access the clipboard", err)
		return
	}
	clipboard.SetText(text)
	a.setStatus(fmt.Sprintf("Copied %s to the clipboard.", what))
}

func (a *App) actionImport() {
	importer, ok := a.selectedCategory().(backend.Importer)
	if !ok {
		return
	}
	dlg, err := gtk.FileChooserNativeDialogNew(importer.ImportTitle(), a.window,
		gtk.FILE_CHOOSER_ACTION_OPEN, "_Import", "_Cancel")
	if err != nil {
		a.showError("Could not open the file chooser", err)
		return
	}
	defer dlg.Destroy()
	if gtk.ResponseType(dlg.Run()) != gtk.RESPONSE_ACCEPT {
		return
	}
	path := dlg.GetFilename()

	a.setStatus("Importing…")
	a.background(func(ctx context.Context) func() {
		summary, err := importer.Import(ctx, path)
		return func() {
			if err != nil {
				a.setStatus("")
				a.showError("Import failed", err)
				return
			}
			a.showInfo("Import finished", summary)
			a.list.reload()
		}
	})
}

func (a *App) actionExport() {
	exporter, ok := a.selectedItem().(backend.Exporter)
	if !ok {
		return
	}
	if secret, ok := exporter.(backend.SecretExporter); ok && secret.CanExportSecret() {
		a.exportWithSecret(secret)
		return
	}
	dlg, err := gtk.FileChooserNativeDialogNew("Export", a.window,
		gtk.FILE_CHOOSER_ACTION_SAVE, "_Export", "_Cancel")
	if err != nil {
		a.showError("Could not open the file chooser", err)
		return
	}
	defer dlg.Destroy()
	startInHome(&dlg.FileChooser)
	dlg.SetCurrentName(exporter.ExportName())
	dlg.SetDoOverwriteConfirmation(true)
	if gtk.ResponseType(dlg.Run()) != gtk.RESPONSE_ACCEPT {
		return
	}
	target := pathlib.NewPath(dlg.GetFilename(), pathlib.PathWithAfero(a.opts.Fs))

	a.background(func(ctx context.Context) func() {
		data, err := exporter.Export(ctx)
		if err == nil {
			err = target.WriteFileMode(data, 0o644)
		}
		return func() {
			if err != nil {
				a.showError("Export failed", err)
				return
			}
			a.setStatus("Exported to " + target.String())
		}
	})
}

// canRevoke reports whether item can be revoked. Revoking is offered even without a
// keyserver, so the dialog can explain that one is needed.
func canRevoke(item backend.Item) bool {
	r, ok := item.(backend.Revoker)
	return ok && !r.Revoked()
}

// canPublish reports whether item can be published somewhere configured.
func canPublish(item backend.Item) bool {
	p, ok := item.(backend.Publisher)
	return ok && len(p.PublishTargets()) > 0
}

// actionPublish asks where to publish the selected item, warning that it becomes public,
// and uploads it.
func (a *App) actionPublish() {
	item := a.selectedItem()
	publisher, ok := item.(backend.Publisher)
	if !ok {
		return
	}
	targets := publisher.PublishTargets()
	if len(targets) == 0 {
		return
	}

	dlg, err := gtk.DialogNew()
	if err != nil {
		a.showError("Could not open the publish dialog", err)
		return
	}
	defer dlg.Destroy()
	dlg.SetTitle("Publish")
	dlg.SetTransientFor(a.window)
	dlg.SetModal(true)
	dlg.SetResizable(false)

	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 12)
	box.SetMarginStart(18)
	box.SetMarginEnd(18)
	box.SetMarginTop(18)
	box.SetMarginBottom(12)

	heading := newLabel("")
	heading.SetMarkup("<b>Publish to a keyserver?</b>")
	box.PackStart(heading, false, false, 0)

	warning := newLabel(publisher.PublishWarning())
	warning.SetLineWrap(true)
	warning.SetMaxWidthChars(60)
	warning.SetSelectable(true)
	box.PackStart(warning, false, false, 0)

	row, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
	label, _ := gtk.LabelNewWithMnemonic("_Keyserver:")
	combo, _ := gtk.ComboBoxTextNew()
	for _, t := range targets {
		combo.Append(t.ID, t.Label)
	}
	combo.SetActive(0)
	label.SetMnemonicWidget(combo)
	row.PackStart(label, false, false, 0)
	row.PackStart(combo, true, true, 0)
	box.PackStart(row, false, false, 0)

	content, _ := dlg.GetContentArea()
	content.Add(box)
	_, _ = dlg.AddButton("_Cancel", gtk.RESPONSE_CANCEL)
	_, _ = dlg.AddButton("_Publish", gtk.RESPONSE_ACCEPT)
	// Publishing can't be undone, so Enter must not do it by accident.
	dlg.SetDefaultResponse(gtk.RESPONSE_CANCEL)
	dlg.ShowAll()

	response := dlg.Run()
	target := combo.GetActiveID()
	if response != gtk.RESPONSE_ACCEPT || target == "" {
		return
	}

	a.setStatus("Publishing to " + target + "…")
	a.background(func(ctx context.Context) func() {
		report, err := publisher.Publish(ctx, target)
		return func() {
			if err != nil {
				a.setStatus("")
				a.showError("Publishing failed", err)
				return
			}
			a.setStatus("Published to " + target)
			a.showInfo("Published", report)
		}
	})
}

func (a *App) actionDelete() {
	deleter, ok := a.selectedItem().(backend.Deleter)
	if !ok {
		return
	}
	dlg := gtk.MessageDialogNew(a.window, gtk.DIALOG_MODAL|gtk.DIALOG_DESTROY_WITH_PARENT,
		gtk.MESSAGE_WARNING, gtk.BUTTONS_NONE, "%s", "Delete this item?")
	dlg.FormatSecondaryText("%s", deleter.DeleteWarning())
	_, _ = dlg.AddButton("_Cancel", gtk.RESPONSE_CANCEL)
	if btn, err := dlg.AddButton("_Delete", gtk.RESPONSE_ACCEPT); err == nil {
		addClass(btn, "destructive-action")
	}
	dlg.SetDefaultResponse(gtk.RESPONSE_CANCEL)
	response := dlg.Run()
	dlg.Destroy()
	if response != gtk.RESPONSE_ACCEPT {
		return
	}

	a.background(func(ctx context.Context) func() {
		err := deleter.Delete(ctx)
		return func() {
			if err != nil {
				a.showError("Could not delete the item", err)
			}
			a.list.reload()
		}
	})
}

func (a *App) actionAbout() {
	dlg, err := gtk.AboutDialogNew()
	if err != nil {
		return
	}
	dlg.SetTransientFor(a.window)
	dlg.SetProgramName(version.Name)
	dlg.SetVersion(version.Version)
	dlg.SetComments(version.Description)
	dlg.SetLogoIconName(version.AppID)
	dlg.SetLicenseType(gtk.LICENSE_GPL_2_0)
	dlg.Run()
	dlg.Destroy()
}
