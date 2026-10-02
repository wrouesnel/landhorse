package ui

import (
	"context"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"github.com/gotk3/gotk3/pango"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// Columns of the type tree's store.
const (
	typeColIcon = iota
	typeColTitle
	typeColKey
	typeColWeight
)

// typeTree is the left pane: groups such as "Passwords" with their categories beneath.
type typeTree struct {
	app    *App
	store  *gtk.TreeStore
	view   *gtk.TreeView
	scroll *gtk.ScrolledWindow

	categories map[string]backend.Category
	current    string
	// expanded remembers which rows the user expanded or collapsed, by node ID, so a
	// refresh doesn't reset the tree. Rows not in it use the default (see populate).
	expanded map[string]bool
	// loading suppresses selection callbacks while the store is rebuilt.
	loading bool
}

func newTypeTree(app *App) (*typeTree, error) {
	t := &typeTree{app: app, categories: map[string]backend.Category{}, expanded: map[string]bool{}}

	var err error
	t.store, err = gtk.TreeStoreNew(glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT)
	if err != nil {
		return nil, err
	}
	t.view, err = gtk.TreeViewNewWithModel(t.store)
	if err != nil {
		return nil, err
	}
	t.view.SetHeadersVisible(false)
	t.view.SetEnableSearch(false)

	col, err := gtk.TreeViewColumnNew()
	if err != nil {
		return nil, err
	}
	icon, err := gtk.CellRendererPixbufNew()
	if err != nil {
		return nil, err
	}
	text, err := gtk.CellRendererTextNew()
	if err != nil {
		return nil, err
	}
	col.PackStart(icon, false)
	col.AddAttribute(icon, "icon-name", typeColIcon)
	// Long titles such as email addresses are cut short rather than widening the pane.
	_ = text.SetProperty("ellipsize", pango.ELLIPSIZE_END)
	col.PackStart(text, true)
	col.AddAttribute(text, "text", typeColTitle)
	col.AddAttribute(text, "weight", typeColWeight)
	t.view.AppendColumn(col)

	sel, err := t.view.GetSelection()
	if err != nil {
		return nil, err
	}
	sel.SetMode(gtk.SELECTION_BROWSE)
	// Group rows are headings, not things to show; only categories can be selected.
	sel.SetSelectFunction(func(_ *gtk.TreeSelection, model *gtk.TreeModel, path *gtk.TreePath, _ bool) bool {
		iter, err := model.GetIter(path)
		if err != nil {
			return false
		}
		return stringAt(model, iter, typeColKey) != ""
	})
	sel.Connect("changed", t.onSelectionChanged)

	t.scroll, err = gtk.ScrolledWindowNew(nil, nil)
	if err != nil {
		return nil, err
	}
	t.scroll.SetPolicy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
	t.scroll.SetShadowType(gtk.SHADOW_IN)
	t.scroll.Add(t.view)
	return t, nil
}

func (t *typeTree) widget() gtk.IWidget { return t.scroll }

func (t *typeTree) selected() backend.Category {
	return t.categories[t.current]
}

type groupResult struct {
	group      backend.Group
	categories []backend.Category
	err        error
}

// load queries every group for its categories and rebuilds the tree, keeping the selection.
func (t *typeTree) load() {
	t.app.setStatus("Loading…")
	groups := t.app.opts.Groups
	t.app.background(func(ctx context.Context) func() {
		results := make([]groupResult, len(groups))
		for i, g := range groups {
			cats, err := g.Categories(ctx)
			results[i] = groupResult{group: g, categories: cats, err: err}
		}
		return func() { t.populate(results) }
	})
}

func (t *typeTree) populate(results []groupResult) {
	l := logutil.FromCtx(t.app.ctx)

	want := t.current
	if want == "" {
		want = t.app.opts.InitialCategory
	}

	t.loading = true
	t.rememberExpansion()
	t.store.Clear()
	t.categories = map[string]backend.Category{}

	var wantIter, firstIter *gtk.TreeIter
	var addCategory func(parent *gtk.TreeIter, cat backend.Category)
	addCategory = func(parent *gtk.TreeIter, cat backend.Category) {
		iter := t.store.Append(parent)
		t.set(iter, cat.IconName(), cat.Title(), cat.Key(), pango.WEIGHT_NORMAL)
		t.categories[cat.Key()] = cat
		if cat.Key() == want {
			wantIter = iter
		}
		if firstIter == nil {
			firstIter = iter
		}
		if p, ok := cat.(backend.Parent); ok {
			for _, child := range p.Children() {
				addCategory(iter, child)
			}
		}
	}

	for _, r := range results {
		parent := t.store.Append(nil)
		t.set(parent, r.group.IconName(), r.group.Title(), "", pango.WEIGHT_BOLD)
		if r.err != nil {
			l.Warn("Could not load group", zap.String("group", r.group.Title()), zap.Error(r.err))
			child := t.store.Append(parent)
			t.set(child, "dialog-warning", "Unavailable", "", pango.WEIGHT_NORMAL)
			continue
		}
		for _, cat := range r.categories {
			addCategory(parent, cat)
		}
	}
	t.restoreExpansion()
	t.loading = false

	target := wantIter
	if target == nil {
		target = firstIter
	}
	sel, _ := t.view.GetSelection()
	if target == nil {
		t.current = ""
		t.app.onCategorySelected(nil)
		return
	}
	// Selecting the row fires "changed" unless it is already selected, and either way the
	// category object was replaced, so load it explicitly.
	t.loading = true
	if path, err := t.store.ToTreeModel().GetPath(target); err == nil {
		t.view.ExpandToPath(path)
	}
	sel.SelectIter(target)
	t.loading = false
	t.current = stringAt(t.store.ToTreeModel(), target, typeColKey)
	t.app.onCategorySelected(t.selected())
	t.app.rebuildRelated()
}

// topCategories returns the categories directly under each group.
func (t *typeTree) topCategories() []backend.Category {
	var result []backend.Category
	model := t.store.ToTreeModel()
	for group, ok := model.GetIterFirst(); ok; ok = model.IterNext(group) {
		var child gtk.TreeIter
		for ok := model.IterChildren(group, &child); ok; ok = model.IterNext(&child) {
			if cat, found := t.categories[stringAt(model, &child, typeColKey)]; found {
				result = append(result, cat)
			}
		}
	}
	return result
}

// selectKey selects the category with key, expanding the tree to show it. It returns false
// if there is no such category.
func (t *typeTree) selectKey(key string) bool {
	var target *gtk.TreePath
	model := t.store.ToTreeModel()
	t.walk(func(iter *gtk.TreeIter, path *gtk.TreePath) {
		if target == nil && stringAt(model, iter, typeColKey) == key {
			target, _ = path.Copy()
		}
	})
	if target == nil {
		return false
	}
	if key == t.current {
		// Selecting it again wouldn't change anything, so select the item directly.
		t.app.list.selectWanted()
		return true
	}
	t.view.ExpandToPath(target)
	t.view.SetCursor(target, nil, false)
	return true
}

// nodeID identifies a row for remembering its expansion: the category key, or the group
// title for group rows, which have no key.
func (t *typeTree) nodeID(model *gtk.TreeModel, iter *gtk.TreeIter) string {
	if key := stringAt(model, iter, typeColKey); key != "" {
		return key
	}
	return "group:" + stringAt(model, iter, typeColTitle)
}

// walk calls fn for every row, parents before their children.
func (t *typeTree) walk(fn func(iter *gtk.TreeIter, path *gtk.TreePath)) {
	model := t.store.ToTreeModel()
	var visit func(iter *gtk.TreeIter, ok bool)
	visit = func(iter *gtk.TreeIter, ok bool) {
		for ; ok; ok = model.IterNext(iter) {
			if path, err := model.GetPath(iter); err == nil {
				fn(iter, path)
			}
			var child gtk.TreeIter
			visit(&child, model.IterChildren(iter, &child))
		}
	}
	first, ok := model.GetIterFirst()
	visit(first, ok)
}

// rememberExpansion records the expansion of every row that has children.
func (t *typeTree) rememberExpansion() {
	model := t.store.ToTreeModel()
	t.walk(func(iter *gtk.TreeIter, path *gtk.TreePath) {
		var child gtk.TreeIter
		if model.IterChildren(iter, &child) {
			t.expanded[t.nodeID(model, iter)] = t.view.RowExpanded(path)
		}
	})
}

// restoreExpansion re-applies remembered expansion. Rows seen for the first time are
// expanded down to the second level, so groups and their categories show but deeper
// subcategories (such as one per email address) start collapsed.
func (t *typeTree) restoreExpansion() {
	model := t.store.ToTreeModel()
	t.walk(func(iter *gtk.TreeIter, path *gtk.TreePath) {
		expand, known := t.expanded[t.nodeID(model, iter)]
		if !known {
			expand = path.GetDepth() <= 2
		}
		if expand {
			t.view.ExpandRow(path, false)
		}
	})
}

// refreshIcons re-reads each category's icon, which reflects its lock state.
func (t *typeTree) refreshIcons() {
	model := t.store.ToTreeModel()
	t.walk(func(iter *gtk.TreeIter, _ *gtk.TreePath) {
		if cat, found := t.categories[stringAt(model, iter, typeColKey)]; found {
			_ = t.store.SetValue(iter, typeColIcon, cat.IconName())
		}
	})
}

func (t *typeTree) set(iter *gtk.TreeIter, icon, title, key string, weight pango.Weight) {
	_ = t.store.SetValue(iter, typeColIcon, icon)
	_ = t.store.SetValue(iter, typeColTitle, title)
	_ = t.store.SetValue(iter, typeColKey, key)
	_ = t.store.SetValue(iter, typeColWeight, int(weight))
}

func (t *typeTree) onSelectionChanged(sel *gtk.TreeSelection) {
	if t.loading {
		return
	}
	model, iter, ok := sel.GetSelected()
	if !ok {
		return
	}
	key := stringAt(model.ToTreeModel(), iter, typeColKey)
	if key == "" || key == t.current {
		return
	}
	t.current = key
	t.app.onCategorySelected(t.selected())
}

// stringAt reads a string column from a tree model, returning "" on any error.
func stringAt(model *gtk.TreeModel, iter *gtk.TreeIter, column int) string {
	v, err := model.GetValue(iter, column)
	if err != nil {
		return ""
	}
	s, err := v.GetString()
	if err != nil {
		return ""
	}
	return s
}
