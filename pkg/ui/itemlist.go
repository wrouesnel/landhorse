package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"github.com/gotk3/gotk3/pango"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// itemList is the middle pane: a sortable, filterable list of the selected category's items.
//
// Its columns depend on the category, so the store and columns are rebuilt whenever the
// category changes. The store holds the icon, one string per column, and the item's index
// into items, which is how a selected row maps back to its backend.Item.
type itemList struct {
	app    *App
	view   *gtk.TreeView
	scroll *gtk.ScrolledWindow
	box    *gtk.Box

	searchBar   *gtk.Box
	searchField *gtk.SearchEntry

	store  *gtk.ListStore
	filter *gtk.TreeModelFilter
	sorted *gtk.TreeModelSort

	category backend.Category
	items    []backend.Item
	// indexCol is the store column holding the index into items.
	indexCol int
	// rankCols maps a cell column (0-based) to the hidden store column holding its rank,
	// for columns that sort by backend.Column.SortRank.
	rankCols map[int]int
	ranks    map[int]func(string) int
	// current is the selected item's key, kept across reloads.
	current string
	// want is the key of an item to select once the next category loads, set when
	// navigating to a related item.
	want string
	// generation discards results of loads that were superseded while running.
	generation int
	loading    bool
	filterText string
}

func newItemList(app *App) (*itemList, error) {
	l := &itemList{app: app}

	var err error
	l.view, err = gtk.TreeViewNew()
	if err != nil {
		return nil, err
	}
	l.view.SetEnableSearch(false)

	sel, err := l.view.GetSelection()
	if err != nil {
		return nil, err
	}
	sel.SetMode(gtk.SELECTION_SINGLE)
	sel.Connect("changed", l.onSelectionChanged)

	l.view.Connect("button-press-event", l.onButtonPress)
	l.view.Connect("key-press-event", l.onKeyPress)
	// Double-click or Enter: copy, for items that ask for it.
	l.view.Connect("row-activated", func() {
		if _, ok := l.selected().(backend.CopyOnActivate); ok {
			l.app.actionCopy()
		}
	})
	l.view.Connect("popup-menu", func() bool {
		l.app.popupItemMenu(nil)
		return true
	})

	l.scroll, err = gtk.ScrolledWindowNew(nil, nil)
	if err != nil {
		return nil, err
	}
	l.scroll.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	l.scroll.SetShadowType(gtk.SHADOW_IN)
	l.scroll.Add(l.view)

	if err := l.buildSearchBar(); err != nil {
		return nil, err
	}
	l.box, err = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 6)
	if err != nil {
		return nil, err
	}
	l.box.PackStart(l.searchBar, false, false, 0)
	l.box.PackStart(l.scroll, true, true, 0)
	return l, nil
}

func (l *itemList) widget() gtk.IWidget { return l.box }

// buildSearchBar builds the bar shown above the list for categories that are searched,
// such as keyservers: a search field, where to search, and a Search button.
func (l *itemList) buildSearchBar() error {
	var err error
	l.searchBar, err = gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 6)
	if err != nil {
		return err
	}
	l.searchBar.SetNoShowAll(true)
	l.searchField, _ = gtk.SearchEntryNew()
	l.searchField.SetHExpand(true)
	l.searchField.Connect("activate", l.runSearch)
	button, _ := gtk.ButtonNewWithMnemonic("_Search")
	button.Connect("clicked", l.runSearch)
	l.searchBar.PackStart(l.searchField, true, true, 0)
	l.searchBar.PackStart(button, false, false, 0)
	return nil
}

// showSearchBar shows the search bar if cat is searched, set up for it.
func (l *itemList) showSearchBar(cat backend.Category) {
	searcher, ok := cat.(backend.KeySearcher)
	if !ok {
		l.searchBar.Hide()
		return
	}
	l.searchField.SetPlaceholderText(searcher.SearchPlaceholder())
	l.searchBar.SetNoShowAll(false)
	l.searchBar.ShowAll()
	// After the click that selected the category, which would take focus back.
	glib.IdleAdd(func() { l.searchField.GrabFocus() })
}

// runSearch searches the current category and lists the results.
func (l *itemList) runSearch() {
	searcher, ok := l.category.(backend.KeySearcher)
	if !ok {
		return
	}
	query, _ := l.searchField.GetText()
	l.generation++
	gen := l.generation
	l.app.setStatus("Searching…")
	l.app.background(func(ctx context.Context) func() {
		items, problems, err := searcher.Search(ctx, query)
		return func() {
			if gen != l.generation {
				return
			}
			if err != nil {
				l.app.setStatus("")
				l.app.showError("Search failed", err)
				return
			}
			l.current = ""
			l.fill(items)
			msg := fmt.Sprintf("%s found for %q", plural(len(items), "key", "keys"), strings.TrimSpace(query))
			if len(problems) > 0 {
				msg += fmt.Sprintf(" (%d keyservers failed)", len(problems))
				l.app.showError("Some keyservers couldn't be searched", errors.New(strings.Join(problems, "\n")))
			}
			l.app.setStatus(msg)
		}
	})
}

// selected returns the selected item, if any.
func (l *itemList) selected() backend.Item {
	sel, err := l.view.GetSelection()
	if err != nil {
		return nil
	}
	model, iter, ok := sel.GetSelected()
	if !ok {
		return nil
	}
	return l.itemAt(model.ToTreeModel(), iter)
}

func (l *itemList) itemAt(model *gtk.TreeModel, iter *gtk.TreeIter) backend.Item {
	v, err := model.GetValue(iter, l.indexCol)
	if err != nil {
		return nil
	}
	gv, err := v.GoValue()
	if err != nil {
		return nil
	}
	idx, ok := gv.(int)
	if !ok || idx < 0 || idx >= len(l.items) {
		return nil
	}
	return l.items[idx]
}

// load shows cat's items. Passing the category that is already shown reloads it and keeps
// the selection.
func (l *itemList) load(cat backend.Category) {
	l.generation++
	gen := l.generation

	if cat == nil || l.category == nil || cat.Key() != l.category.Key() {
		// A new category. Replacing the model clears the selection (and l.current with it),
		// so choose the item to select, the one navigated to if any, afterwards.
		l.setColumns(cat)
		l.current = l.want
		l.want = ""
	}
	l.category = cat
	l.showSearchBar(cat)
	if cat == nil {
		l.fill(nil)
		l.app.setStatus("")
		return
	}

	l.app.setStatus(fmt.Sprintf("Loading %s…", cat.Title()))
	l.app.background(func(ctx context.Context) func() {
		items, err := cat.Items(ctx)
		return func() {
			if gen != l.generation {
				return
			}
			if err != nil {
				l.fill(nil)
				l.app.setStatus(fmt.Sprintf("Could not load %s: %v", cat.Title(), err))
				l.app.info.showMessage("Could not load "+cat.Title(), err.Error())
				return
			}
			l.fill(items)
			l.updateStatus()
		}
	})
}

// reload refreshes the current category in place.
func (l *itemList) reload() {
	l.load(l.category)
	// Whatever changed may have changed what's related to what.
	l.app.rebuildRelated()
}

// selectWanted selects the item navigated to within the category already on show.
func (l *itemList) selectWanted() {
	if l.want == "" {
		return
	}
	l.current = l.want
	l.want = ""
	l.reselect()
}

// setColumns rebuilds the store and columns for cat.
func (l *itemList) setColumns(cat backend.Category) {
	for _, col := range l.columns() {
		l.view.RemoveColumn(col)
	}

	var cols []backend.Column
	if cat != nil {
		cols = cat.Columns()
	}

	// icon, cells..., index
	types := []glib.Type{glib.TYPE_STRING}
	for range cols {
		types = append(types, glib.TYPE_STRING)
	}
	types = append(types, glib.TYPE_INT)
	l.indexCol = len(types) - 1
	l.rankCols = map[int]int{}
	l.ranks = map[int]func(string) int{}
	for i, c := range cols {
		if c.SortRank != nil {
			types = append(types, glib.TYPE_INT)
			l.rankCols[i] = len(types) - 1
			l.ranks[i] = c.SortRank
		}
	}

	store, err := gtk.ListStoreNew(types...)
	if err != nil {
		l.app.showError("Could not create the item list", err)
		return
	}
	filter, err := store.FilterNew(nil)
	if err != nil {
		l.app.showError("Could not create the item list", err)
		return
	}
	filter.SetVisibleFunc(l.visible)
	sorted, err := gtk.TreeModelSortNew(filter)
	if err != nil {
		l.app.showError("Could not create the item list", err)
		return
	}
	l.store, l.filter, l.sorted = store, filter, sorted

	for i, c := range cols {
		storeCol := i + 1
		col, err := gtk.TreeViewColumnNew()
		if err != nil {
			continue
		}
		col.SetTitle(c.Title)
		col.SetResizable(true)
		if rankCol, ok := l.rankCols[i]; ok {
			col.SetSortColumnID(rankCol)
		} else {
			col.SetSortColumnID(storeCol)
		}
		col.SetExpand(c.Expand)

		if i == 0 {
			// The first column carries the item's icon.
			icon, err := gtk.CellRendererPixbufNew()
			if err == nil {
				col.PackStart(icon, false)
				col.AddAttribute(icon, "icon-name", 0)
			}
		}
		text, err := gtk.CellRendererTextNew()
		if err != nil {
			continue
		}
		if c.Monospace {
			_ = text.SetProperty("family", "monospace")
		}
		// Tree view columns are sized from each cell's minimum width, so only columns
		// that opt in may ellipsize; the rest keep their full width.
		if c.Expand || c.Truncate {
			_ = text.SetProperty("ellipsize", pango.ELLIPSIZE_END)
			_ = text.SetProperty("width-chars", 16)
		}
		col.PackStart(text, true)
		col.AddAttribute(text, "text", storeCol)
		l.view.AppendColumn(col)
	}
	l.view.SetModel(sorted)
	if len(cols) > 0 {
		sorted.SetSortColumnId(1, gtk.SORT_ASCENDING)
	}
}

func (l *itemList) columns() []*gtk.TreeViewColumn {
	var result []*gtk.TreeViewColumn
	list := l.view.GetColumns()
	if list == nil {
		return nil
	}
	list.Foreach(func(item interface{}) {
		if col, ok := item.(*gtk.TreeViewColumn); ok {
			result = append(result, col)
		}
	})
	return result
}

// fill replaces the rows, then reselects the previously selected item if it still exists.
func (l *itemList) fill(items []backend.Item) {
	if l.store == nil {
		return
	}
	l.loading = true
	l.items = items
	l.store.Clear()
	for i, item := range items {
		iter := l.store.Append()
		_ = l.store.SetValue(iter, 0, item.IconName())
		for c, cell := range item.Cells() {
			if c+1 >= l.indexCol {
				break
			}
			_ = l.store.SetValue(iter, c+1, cell)
			if rankCol, ok := l.rankCols[c]; ok {
				_ = l.store.SetValue(iter, rankCol, l.ranks[c](cell))
			}
		}
		_ = l.store.SetValue(iter, l.indexCol, i)
	}
	l.loading = false
	l.reselect()
}

// reselect selects the row for l.current, or clears the detail view if it is gone.
func (l *itemList) reselect() {
	sel, err := l.view.GetSelection()
	if err != nil {
		return
	}
	model := l.sorted.ToTreeModel()
	if l.current != "" {
		for iter, ok := model.GetIterFirst(); ok; ok = model.IterNext(iter) {
			item := l.itemAt(model, iter)
			if item != nil && item.Key() == l.current {
				sel.SelectIter(iter)
				if path, err := model.GetPath(iter); err == nil {
					l.view.ScrollToCell(path, nil, false, 0, 0)
				}
				// SelectIter doesn't emit "changed" when the row was already selected,
				// but the item object is new, so refresh the details explicitly.
				l.app.onItemSelected(item)
				return
			}
		}
	}
	l.current = ""
	sel.UnselectAll()
	l.app.onItemSelected(nil)
}

func (l *itemList) onSelectionChanged(sel *gtk.TreeSelection) {
	if l.loading {
		return
	}
	model, iter, ok := sel.GetSelected()
	if !ok {
		if l.current != "" {
			l.current = ""
			l.app.onItemSelected(nil)
		}
		return
	}
	item := l.itemAt(model.ToTreeModel(), iter)
	if item == nil || item.Key() == l.current {
		return
	}
	l.current = item.Key()
	l.app.onItemSelected(item)
}

// setFilter shows only rows with a cell containing text, ignoring case.
func (l *itemList) setFilter(text string) {
	l.filterText = strings.ToLower(strings.TrimSpace(text))
	if l.filter == nil {
		return
	}
	l.filter.Refilter()
	l.updateStatus()
	// Drop the selection if its row was filtered out.
	if l.selected() == nil && l.current != "" {
		l.current = ""
		l.app.onItemSelected(nil)
	}
}

func (l *itemList) visible(model *gtk.TreeModel, iter *gtk.TreeIter) bool {
	if l.filterText == "" {
		return true
	}
	item := l.itemAt(model, iter)
	if item == nil {
		return false
	}
	for _, cell := range item.Cells() {
		if strings.Contains(strings.ToLower(cell), l.filterText) {
			return true
		}
	}
	return false
}

func (l *itemList) updateStatus() {
	if l.category == nil {
		l.app.setStatus("")
		return
	}
	shown := l.sorted.ToTreeModel().IterNChildren(nil)
	total := len(l.items)
	noun := "items"
	if total == 1 {
		noun = "item"
	}
	msg := fmt.Sprintf("%s: %d %s", l.category.Title(), total, noun)
	if shown != total {
		msg = fmt.Sprintf("%s: %d of %d %s match", l.category.Title(), shown, total, noun)
	}
	if lk, ok := l.category.(backend.Lockable); ok && lk.Locked() {
		msg += " — locked"
	}
	l.app.setStatus(msg)
}

func (l *itemList) onButtonPress(_ *gtk.TreeView, ev *gdk.Event) bool {
	btn := gdk.EventButtonNewFromEvent(ev)
	if btn.Button() != gdk.BUTTON_SECONDARY || btn.Type() != gdk.EVENT_BUTTON_PRESS {
		return false
	}
	// Select the row under the pointer first, as file managers do.
	path, _, _, _, ok := l.view.GetPathAtPos(int(btn.X()), int(btn.Y()))
	if ok && path != nil {
		l.view.SetCursor(path, nil, false)
	}
	l.app.popupItemMenu(ev)
	return true
}

func (l *itemList) onKeyPress(_ *gtk.TreeView, ev *gdk.Event) bool {
	key := gdk.EventKeyNewFromEvent(ev)
	ctrl := key.State()&uint(gdk.CONTROL_MASK) != 0
	switch {
	case key.KeyVal() == gdk.KEY_Delete:
		l.app.actionDelete()
		return true
	case ctrl && (key.KeyVal() == gdk.KEY_c || key.KeyVal() == gdk.KEY_C):
		l.app.actionCopy()
		return true
	}
	return false
}
