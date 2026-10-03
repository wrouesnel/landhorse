package ui

import (
	"context"
	"html"

	"github.com/gotk3/gotk3/gtk"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// relatedRef is an item that can appear under another item's Related Items.
type relatedRef struct {
	categoryKey   string
	categoryTitle string
	item          backend.Linkable
	// relation describes a one-way relation, e.g. "Signed this key"; empty for shared keys.
	relation string
}

// relatedIndex maps link keys to the items that report them, and to the items that refer
// to them, across every backend.
type relatedIndex struct {
	byKey map[string][]relatedRef
	byRef map[string][]relatedRef
}

// lookup returns the items related to item, excluding item itself: items sharing a link
// key, items it refers to, and items referring to it.
func (r *relatedIndex) lookup(item backend.Linkable) []relatedRef {
	if r == nil {
		return nil
	}
	seen := map[string]bool{}
	var result []relatedRef
	addRef := func(ref relatedRef, relation string) {
		id := ref.categoryKey + "\x00" + ref.item.Key()
		if ref.item.Key() == item.Key() || seen[id] {
			return
		}
		seen[id] = true
		ref.relation = relation
		result = append(result, ref)
	}
	for _, key := range item.LinkKeys() {
		for _, ref := range r.byKey[key] {
			addRef(ref, "")
		}
		for _, ref := range r.byRef[key] {
			_, incoming := ref.item.(backend.Referrer).ReferenceLabels()
			addRef(ref, incoming)
		}
	}
	if referrer, ok := item.(backend.Referrer); ok {
		outgoing, _ := referrer.ReferenceLabels()
		for _, key := range referrer.LinkReferences() {
			for _, ref := range r.byKey[key] {
				addRef(ref, outgoing)
			}
		}
	}
	return result
}

// rebuildRelated indexes the linkable items of every top level category in the background,
// then refreshes the Related Items of the item on show. Subcategories are skipped, as their
// items also appear in their parent.
func (a *App) rebuildRelated() {
	a.relatedGeneration++
	gen := a.relatedGeneration
	categories := a.types.topCategories()
	a.background(func(ctx context.Context) func() {
		index := &relatedIndex{byKey: map[string][]relatedRef{}, byRef: map[string][]relatedRef{}}
		for _, cat := range categories {
			items, err := cat.Items(ctx)
			if err != nil {
				logutil.FromCtx(ctx).Debug("Skipping category for related items",
					zap.String("category", cat.Title()), zap.Error(err))
				continue
			}
			for _, item := range items {
				linkable, ok := item.(backend.Linkable)
				if !ok {
					continue
				}
				ref := relatedRef{categoryKey: cat.Key(), categoryTitle: cat.Title(), item: linkable}
				for _, key := range linkable.LinkKeys() {
					index.byKey[key] = append(index.byKey[key], ref)
				}
				if referrer, ok := item.(backend.Referrer); ok {
					for _, key := range referrer.LinkReferences() {
						index.byRef[key] = append(index.byRef[key], ref)
					}
				}
			}
		}
		return func() {
			if gen != a.relatedGeneration {
				return
			}
			a.related = index
			a.info.fillRelated()
		}
	})
}

// navigateTo selects a category in the type tree and an item in its list, as when a related
// item is clicked.
func (a *App) navigateTo(categoryKey, itemKey string) {
	// The filter might hide the item.
	a.search.SetText("")
	a.list.want = itemKey
	if !a.types.selectKey(categoryKey) {
		a.list.want = ""
		a.setStatus("That item is no longer available.")
	}
}

// fillRelated shows the Related Items of the item on show, if it has any. It is called when
// the details are rendered and again whenever the index is rebuilt.
func (d *detailView) fillRelated() {
	if d.relatedBox == nil {
		return
	}
	d.relatedBox.GetChildren().Foreach(func(child interface{}) {
		if w, ok := child.(gtk.IWidget); ok {
			w.ToWidget().Destroy()
		}
	})
	linkable, ok := d.item.(backend.Linkable)
	if !ok {
		return
	}
	refs := d.app.related.lookup(linkable)
	if len(refs) == 0 {
		d.relatedBox.Hide()
		return
	}

	heading := newLabel("")
	heading.SetMarkup("<b>Related items</b>")
	d.relatedBox.PackStart(heading, false, false, 0)

	list, _ := gtk.ListBoxNew()
	list.SetSelectionMode(gtk.SELECTION_NONE)
	list.SetActivateOnSingleClick(true)
	for _, ref := range refs {
		list.Insert(relatedRow(ref), -1)
	}
	list.Connect("row-activated", func(_ *gtk.ListBox, row *gtk.ListBoxRow) {
		if idx := row.GetIndex(); idx >= 0 && idx < len(refs) {
			d.app.navigateTo(refs[idx].categoryKey, refs[idx].item.Key())
		}
	})

	frame, _ := gtk.FrameNew("")
	frame.SetShadowType(gtk.SHADOW_IN)
	frame.SetMarginStart(12)
	frame.Add(list)
	d.relatedBox.PackStart(frame, false, false, 0)
	d.relatedBox.ShowAll()
}

// relatedRow shows an item's icon, its name, and what and where it is, with an arrow to
// show that clicking it goes there.
func relatedRow(ref relatedRef) gtk.IWidget {
	row, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 10)
	row.SetMarginStart(8)
	row.SetMarginEnd(8)
	row.SetMarginTop(6)
	row.SetMarginBottom(6)
	row.SetTooltipText("Go to this item")

	if icon, err := gtk.ImageNewFromIconName(ref.item.IconName(), gtk.ICON_SIZE_LARGE_TOOLBAR); err == nil {
		row.PackStart(icon, false, false, 0)
	}
	text, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 2)
	title := newLabel("")
	title.SetMarkup("<b>" + html.EscapeString(ref.item.Cells()[0]) + "</b>")
	title.SetLineWrap(true)
	text.PackStart(title, false, false, 0)
	subtitle := ref.item.LinkDescription() + " · " + ref.categoryTitle
	if ref.relation != "" {
		subtitle = ref.relation + " · " + subtitle
	}
	sub := newLabel(subtitle)
	sub.SetLineWrap(true)
	addClass(sub, "dim-label")
	text.PackStart(sub, false, false, 0)
	row.PackStart(text, true, true, 0)
	if arrow, err := gtk.ImageNewFromIconName("go-next-symbolic", gtk.ICON_SIZE_MENU); err == nil {
		row.PackEnd(arrow, false, false, 0)
	}
	return row
}
