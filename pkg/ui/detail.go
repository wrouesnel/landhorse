package ui

import (
	"context"
	"html"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"github.com/gotk3/gotk3/pango"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

const secretMask = "••••••••••••"

// detailView is the right pane. It is rebuilt from a backend.Detail for each selection.
type detailView struct {
	app    *App
	scroll *gtk.ScrolledWindow
	box    *gtk.Box
	// generation discards details that arrive after the selection moved on.
	generation int
}

func newDetailView(app *App) (*detailView, error) {
	d := &detailView{app: app}
	var err error
	d.scroll, err = gtk.ScrolledWindowNew(nil, nil)
	if err != nil {
		return nil, err
	}
	d.scroll.SetPolicy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
	d.scroll.SetShadowType(gtk.SHADOW_IN)
	d.scroll.SetSizeRequest(320, -1)

	d.box, err = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 6)
	if err != nil {
		return nil, err
	}
	d.box.SetMarginStart(18)
	d.box.SetMarginEnd(18)
	d.box.SetMarginTop(18)
	d.box.SetMarginBottom(18)
	d.scroll.Add(d.box)

	d.showMessage("", "Select an item to see its details.")
	return d, nil
}

func (d *detailView) widget() gtk.IWidget { return d.scroll }

func (d *detailView) clear() {
	d.box.GetChildren().Foreach(func(item interface{}) {
		if w, ok := item.(gtk.IWidget); ok {
			w.ToWidget().Destroy()
		}
	})
}

// showMessage replaces the view with a centered, dimmed message.
func (d *detailView) showMessage(title, text string) {
	d.generation++
	d.clear()
	if title != "" {
		heading := newLabel("")
		heading.SetMarkup("<b>" + html.EscapeString(title) + "</b>")
		heading.SetXAlign(0.5)
		heading.SetMarginTop(48)
		d.box.PackStart(heading, false, false, 0)
	}
	msg := newLabel(text)
	msg.SetXAlign(0.5)
	msg.SetJustify(gtk.JUSTIFY_CENTER)
	if title == "" {
		msg.SetMarginTop(48)
	}
	addClass(msg, "dim-label")
	d.box.PackStart(msg, false, false, 0)
	d.box.ShowAll()
}

// show loads and displays item's details.
func (d *detailView) show(item backend.Item) {
	if item == nil {
		d.showMessage("", "Select an item to see its details.")
		return
	}
	d.generation++
	gen := d.generation
	d.app.background(func(ctx context.Context) func() {
		detail, err := item.Detail(ctx)
		return func() {
			if gen != d.generation {
				return
			}
			if err != nil {
				d.showMessage("Could not load details", err.Error())
				return
			}
			d.render(detail)
		}
	})
}

func (d *detailView) render(detail *backend.Detail) {
	d.clear()

	// Header: large icon beside the title and subtitle.
	header, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
	if detail.IconName != "" {
		if img, err := gtk.ImageNewFromIconName(detail.IconName, gtk.ICON_SIZE_DIALOG); err == nil {
			img.SetVAlign(gtk.ALIGN_START)
			header.PackStart(img, false, false, 0)
		}
	}
	titles, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 2)
	title := newLabel("")
	title.SetMarkup(`<span size="large" weight="bold">` + html.EscapeString(detail.Title) + `</span>`)
	title.SetSelectable(true)
	title.SetLineWrap(true)
	title.SetLineWrapMode(pango.WRAP_WORD_CHAR)
	titles.PackStart(title, false, false, 0)
	if detail.Subtitle != "" {
		sub := newLabel(detail.Subtitle)
		sub.SetSelectable(true)
		addClass(sub, "dim-label")
		titles.PackStart(sub, false, false, 0)
	}
	header.PackStart(titles, true, true, 0)
	d.box.PackStart(header, false, false, 0)

	for _, section := range detail.Sections {
		d.box.PackStart(d.renderSection(section), false, false, 0)
	}
	d.box.ShowAll()
}

func (d *detailView) renderSection(section backend.Section) gtk.IWidget {
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 6)
	box.SetMarginTop(12)

	heading := newLabel("")
	heading.SetMarkup("<b>" + html.EscapeString(section.Title) + "</b>")
	box.PackStart(heading, false, false, 0)

	if len(section.Fields) > 0 {
		grid, _ := gtk.GridNew()
		grid.SetColumnSpacing(12)
		grid.SetRowSpacing(6)
		grid.SetMarginStart(12)
		for row, f := range section.Fields {
			label := newLabel(f.Label)
			label.SetXAlign(1)
			label.SetYAlign(0)
			if f.Reveal != nil {
				label.SetYAlign(0.5)
			}
			addClass(label, "dim-label")
			grid.Attach(label, 0, row, 1, 1)
			grid.Attach(d.renderValue(f), 1, row, 1, 1)
		}
		box.PackStart(grid, false, false, 0)
	}

	if section.Table != nil {
		box.PackStart(renderTable(section.Table), false, false, 0)
	}
	return box
}

// renderValue renders a field's value. Secret fields start masked, with a Show button
// that fetches the secret.
func (d *detailView) renderValue(f backend.Field) gtk.IWidget {
	value := newLabel(f.Value)
	value.SetSelectable(true)
	value.SetLineWrap(true)
	value.SetLineWrapMode(pango.WRAP_WORD_CHAR)
	value.SetHExpand(true)
	if f.Monospace {
		value.SetMarkup(`<span font_family="monospace">` + html.EscapeString(f.Value) + `</span>`)
	}
	if f.Value == "" && f.Reveal == nil {
		value.SetText("—")
		addClass(value, "dim-label")
	}
	if f.Reveal == nil {
		return value
	}

	value.SetText(secretMask)
	value.SetSelectable(false)

	row, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 6)
	row.PackStart(value, true, true, 0)

	toggle, _ := gtk.ToggleButtonNewWithLabel("Show")
	toggle.SetVAlign(gtk.ALIGN_START)
	// The secret is fetched on each Show and dropped on Hide, so it isn't kept in the
	// widget tree while hidden.
	gen := d.generation
	lockable, _ := d.app.selectedCategory().(backend.Lockable)
	toggle.Connect("toggled", func() {
		if !toggle.GetActive() {
			value.SetText(secretMask)
			value.SetSelectable(false)
			toggle.SetLabel("Show")
			return
		}
		toggle.SetLabel("Hide")
		wasLocked := lockable != nil && lockable.Locked()
		d.app.background(func(ctx context.Context) func() {
			secret, err := f.Reveal(ctx)
			return func() {
				if gen != d.generation || !toggle.GetActive() {
					return
				}
				if err != nil {
					toggle.SetActive(false)
					d.app.showError("Could not show the secret", err)
					return
				}
				value.SetText(secret)
				value.SetSelectable(true)
				if wasLocked {
					// Reading the secret unlocked the keyring.
					d.app.lockStateChanged()
				}
			}
		})
	})
	row.PackStart(toggle, false, false, 0)
	return row
}

// renderTable renders a table as a non-scrolling tree view, so it grows with its rows and
// the detail pane scrolls as a whole.
func renderTable(table *backend.Table) gtk.IWidget {
	types := make([]glib.Type, len(table.Columns))
	for i := range types {
		types[i] = glib.TYPE_STRING
	}
	store, err := gtk.ListStoreNew(types...)
	if err != nil {
		return newLabel(err.Error())
	}
	for _, row := range table.Rows {
		iter := store.Append()
		for i, cell := range row {
			if i < len(types) {
				_ = store.SetValue(iter, i, cell)
			}
		}
	}

	view, err := gtk.TreeViewNewWithModel(store)
	if err != nil {
		return newLabel(err.Error())
	}
	view.SetEnableSearch(false)
	view.SetCanFocus(true)
	for i, title := range table.Columns {
		text, err := gtk.CellRendererTextNew()
		if err != nil {
			continue
		}
		col, err := gtk.TreeViewColumnNewWithAttribute(title, text, "text", i)
		if err != nil {
			continue
		}
		col.SetResizable(true)
		view.AppendColumn(col)
	}
	if len(table.Rows) == 0 {
		return newLabel("None")
	}

	frame, _ := gtk.FrameNew("")
	frame.SetShadowType(gtk.SHADOW_IN)
	frame.SetMarginStart(12)
	// Wide tables (many subkey columns) scroll sideways rather than widening the pane.
	scroll, _ := gtk.ScrolledWindowNew(nil, nil)
	scroll.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_NEVER)
	scroll.SetPropagateNaturalHeight(true)
	scroll.Add(view)
	frame.Add(scroll)
	return frame
}

func newLabel(text string) *gtk.Label {
	label, _ := gtk.LabelNew(text)
	label.SetXAlign(0)
	return label
}

func addClass(w gtk.IWidget, class string) {
	if ctx, err := w.ToWidget().GetStyleContext(); err == nil {
		ctx.AddClass(class)
	}
}
