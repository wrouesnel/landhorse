package ui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// Columns of the keyring groupings store.
const (
	groupColAttribute = iota
	groupColTitle
)

// actionPreferences opens the preferences dialog.
func (a *App) actionPreferences() {
	if a.opts.Settings == nil {
		return
	}
	p := &preferences{app: a, settings: a.opts.Settings}
	if err := p.build(); err != nil {
		a.showError("Could not open preferences", err)
		return
	}
	p.dlg.ShowAll()
}

type preferences struct {
	app      *App
	settings Settings

	dlg        *gtk.Dialog
	store      *gtk.ListStore
	view       *gtk.TreeView
	attributes *gtk.ListStore
}

func (p *preferences) build() error {
	dlg, err := gtk.DialogNew()
	if err != nil {
		return err
	}
	p.dlg = dlg
	dlg.SetTitle("Preferences")
	dlg.SetTransientFor(p.app.window)
	dlg.SetModal(true)
	dlg.SetDefaultSize(560, 420)
	_, _ = dlg.AddButton("_Cancel", gtk.RESPONSE_CANCEL)
	save, _ := dlg.AddButton("_Save", gtk.RESPONSE_ACCEPT)
	addClass(save, "suggested-action")
	dlg.SetDefaultResponse(gtk.RESPONSE_ACCEPT)
	dlg.Connect("response", func(_ *gtk.Dialog, response gtk.ResponseType) {
		if response == gtk.RESPONSE_ACCEPT && !p.save() {
			return
		}
		dlg.Destroy()
	})

	notebook, _ := gtk.NotebookNew()
	page, err := p.keyringsPage()
	if err != nil {
		return err
	}
	tab, _ := gtk.LabelNew("Keyrings")
	notebook.AppendPage(page, tab)
	notebook.SetMarginStart(12)
	notebook.SetMarginEnd(12)
	notebook.SetMarginTop(12)
	area, _ := dlg.GetContentArea()
	area.PackStart(notebook, true, true, 0)
	return nil
}

// keyringsPage edits the attributes that keyring items are grouped by.
func (p *preferences) keyringsPage() (gtk.IWidget, error) {
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 8)
	box.SetMarginStart(12)
	box.SetMarginEnd(12)
	box.SetMarginTop(12)
	box.SetMarginBottom(12)

	heading := newLabel("")
	heading.SetMarkup("<b>Group passwords by attribute</b>")
	box.PackStart(heading, false, false, 0)
	box.PackStart(wrapLabel("Each attribute here adds a group under every keyring, with a "+
		"subcategory for each of the attribute's values; the group itself lists every password "+
		"that has the attribute. The group name defaults to the attribute's name. Network "+
		"passwords are always grouped by host."), false, false, 0)

	var err error
	p.store, err = gtk.ListStoreNew(glib.TYPE_STRING, glib.TYPE_STRING)
	if err != nil {
		return nil, err
	}
	for _, g := range p.settings.KeyringGroupings() {
		iter := p.store.Append()
		_ = p.store.SetValue(iter, groupColAttribute, g.Attribute)
		_ = p.store.SetValue(iter, groupColTitle, g.Title)
	}
	p.attributes, err = gtk.ListStoreNew(glib.TYPE_STRING)
	if err != nil {
		return nil, err
	}

	p.view, err = gtk.TreeViewNewWithModel(p.store)
	if err != nil {
		return nil, err
	}
	p.view.SetEnableSearch(false)

	// Attribute: typed, or picked from the attributes found in the keyrings.
	attrCell, err := gtk.CellRendererComboNew()
	if err != nil {
		return nil, err
	}
	_ = attrCell.SetProperty("editable", true)
	_ = attrCell.SetProperty("has-entry", true)
	// gotk3 only converts *glib.Object property values, not the wrapper types.
	_ = attrCell.SetProperty("model", p.attributes.Object)
	_ = attrCell.SetProperty("text-column", 0)
	attrCell.Connect("edited", func(_ *gtk.CellRendererCombo, path, text string) {
		p.setCell(path, groupColAttribute, strings.TrimSpace(text))
	})
	attrCol, _ := gtk.TreeViewColumnNewWithAttribute("Attribute", attrCell, "text", groupColAttribute)
	attrCol.SetExpand(true)
	attrCol.SetResizable(true)
	p.view.AppendColumn(attrCol)

	titleCell, err := gtk.CellRendererTextNew()
	if err != nil {
		return nil, err
	}
	_ = titleCell.SetProperty("editable", true)
	_ = titleCell.SetProperty("placeholder-text", "Same as attribute")
	titleCell.Connect("edited", func(_ *gtk.CellRendererText, path, text string) {
		p.setCell(path, groupColTitle, strings.TrimSpace(text))
	})
	titleCol, _ := gtk.TreeViewColumnNewWithAttribute("Group name", titleCell, "text", groupColTitle)
	titleCol.SetExpand(true)
	titleCol.SetResizable(true)
	p.view.AppendColumn(titleCol)

	scroll, _ := gtk.ScrolledWindowNew(nil, nil)
	scroll.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	scroll.SetShadowType(gtk.SHADOW_IN)
	scroll.Add(p.view)

	// An inline toolbar under the list, as GTK list editors conventionally have.
	bar, _ := gtk.ToolbarNew()
	bar.SetIconSize(gtk.ICON_SIZE_SMALL_TOOLBAR)
	if ctx, err := bar.GetStyleContext(); err == nil {
		ctx.AddClass("inline-toolbar")
	}
	for _, b := range []struct {
		icon, tooltip string
		action        func()
	}{
		{"list-add-symbolic", "Add a group", p.add},
		{"list-remove-symbolic", "Remove the selected group", p.remove},
		{"go-up-symbolic", "Move the selected group up", func() { p.move(-1) }},
		{"go-down-symbolic", "Move the selected group down", func() { p.move(1) }},
	} {
		btn, err := gtk.ToolButtonNew(nil, "")
		if err != nil {
			return nil, err
		}
		btn.SetIconName(b.icon)
		btn.SetTooltipText(b.tooltip)
		btn.Connect("clicked", b.action)
		bar.Insert(btn, -1)
	}

	list, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)
	list.PackStart(scroll, true, true, 0)
	list.PackStart(bar, false, false, 0)
	box.PackStart(list, true, true, 0)

	hint := wrapLabel("Loading the attributes used in your keyrings…")
	addClass(hint, "dim-label")
	box.PackStart(hint, false, false, 0)
	p.loadAttributes(hint)
	return box, nil
}

// loadAttributes fills the attribute suggestions, most used first, and summarises them.
func (p *preferences) loadAttributes(hint *gtk.Label) {
	p.app.background(func(ctx context.Context) func() {
		counts, err := p.settings.KeyringAttributes(ctx)
		return func() {
			if err != nil {
				hint.SetText("Couldn't read your keyrings' attributes: " + err.Error())
				return
			}
			names := make([]string, 0, len(counts))
			for name := range counts {
				names = append(names, name)
			}
			sort.Slice(names, func(i, j int) bool {
				if counts[names[i]] != counts[names[j]] {
					return counts[names[i]] > counts[names[j]]
				}
				return names[i] < names[j]
			})
			for _, name := range names {
				_ = p.attributes.SetValue(p.attributes.Append(), 0, name)
			}
			top := names
			if len(top) > 6 {
				top = top[:6]
			}
			parts := make([]string, 0, len(top))
			for _, name := range top {
				parts = append(parts, fmt.Sprintf("%s (%d)", name, counts[name]))
			}
			if len(parts) == 0 {
				hint.SetText("Your keyrings' passwords have no attributes.")
				return
			}
			hint.SetText("Most used attributes, with how many passwords have them: " +
				strings.Join(parts, ", ") + ". Click an attribute cell to pick from all of them.")
		}
	})
}

func (p *preferences) setCell(path string, column int, text string) {
	iter, err := p.store.ToTreeModel().GetIterFromString(path)
	if err != nil {
		return
	}
	_ = p.store.SetValue(iter, column, text)
}

func (p *preferences) selected() (*gtk.TreeIter, bool) {
	sel, err := p.view.GetSelection()
	if err != nil {
		return nil, false
	}
	_, iter, ok := sel.GetSelected()
	return iter, ok
}

// add appends a row and starts editing its attribute.
func (p *preferences) add() {
	iter := p.store.Append()
	_ = p.store.SetValue(iter, groupColAttribute, "")
	_ = p.store.SetValue(iter, groupColTitle, "")
	if path, err := p.store.ToTreeModel().GetPath(iter); err == nil {
		p.view.SetCursor(path, p.view.GetColumn(0), true)
	}
}

func (p *preferences) remove() {
	if iter, ok := p.selected(); ok {
		p.store.Remove(iter)
	}
}

// move swaps the selected row with its neighbour above (-1) or below (1).
func (p *preferences) move(direction int) {
	iter, ok := p.selected()
	if !ok {
		return
	}
	model := p.store.ToTreeModel()
	other, err := iterCopy(model, iter)
	if err != nil {
		return
	}
	moved := false
	if direction < 0 {
		moved = model.IterPrevious(other)
	} else {
		moved = model.IterNext(other)
	}
	if moved {
		p.store.Swap(iter, other)
	}
}

// iterCopy returns an independent iterator at the same row.
func iterCopy(model *gtk.TreeModel, iter *gtk.TreeIter) (*gtk.TreeIter, error) {
	path, err := model.GetPath(iter)
	if err != nil {
		return nil, err
	}
	return model.GetIter(path)
}

// save validates and applies the groupings, reporting problems and keeping the dialog open
// if there are any.
func (p *preferences) save() bool {
	model := p.store.ToTreeModel()
	var groupings []backend.AttributeGrouping
	seen := map[string]bool{}
	for iter, ok := model.GetIterFirst(); ok; ok = model.IterNext(iter) {
		attr := stringAt(model, iter, groupColAttribute)
		title := stringAt(model, iter, groupColTitle)
		if attr == "" {
			continue // a row added but never filled in
		}
		if seen[attr] {
			p.app.showError("Each attribute can only be grouped once",
				fmt.Errorf("%q is listed more than once", attr))
			return false
		}
		seen[attr] = true
		groupings = append(groupings, backend.AttributeGrouping{Attribute: attr, Title: title})
	}
	if err := p.settings.SetKeyringGroupings(groupings); err != nil {
		p.app.showError("Could not save preferences", err)
		return false
	}
	p.app.setStatus("Preferences saved.")
	p.app.refreshTypes()
	return true
}
