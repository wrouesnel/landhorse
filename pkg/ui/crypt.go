package ui

import (
	"context"
	"fmt"
	"html"
	"strings"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// renderCryptAreas adds drop areas to the detail view for encrypting files to the key and,
// where the private key is here, signing files with it.
func (d *detailView) renderCryptAreas(crypter backend.Crypter) gtk.IWidget {
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 8)
	box.SetMarginTop(12)

	if ok, why := crypter.CanEncrypt(); ok {
		box.PackStart(d.app.dropZone("channel-secure-symbolic",
			"Drop files here to encrypt them to "+crypter.CryptName(),
			"Each file is saved beside the original with .gpg added; only this key's owner can read it.",
			func(paths []string) { d.app.encryptFiles(crypter, paths) }), false, false, 0)
	} else {
		reason := wrapLabel("Encrypting to this key isn't possible. " + why)
		addClass(reason, "dim-label")
		box.PackStart(reason, false, false, 0)
	}
	if ok, _ := crypter.CanSign(); ok {
		box.PackStart(d.app.dropZone("document-edit-symbolic",
			"Drop files here to sign them",
			"Each signature is saved beside the file with .sig added.",
			func(paths []string) { d.app.signFiles(crypter, paths) }), false, false, 0)
	}
	return box
}

// dropZone is a dashed area that accepts dropped files, with a button to choose them
// instead.
func (a *App) dropZone(icon, title, subtitle string, onFiles func(paths []string)) gtk.IWidget {
	inner, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
	addClass(inner, "drop-zone")
	if img, err := gtk.ImageNewFromIconName(icon, gtk.ICON_SIZE_DND); err == nil {
		inner.PackStart(img, false, false, 0)
	}
	text, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 2)
	heading := wrapLabel("")
	heading.SetMarkup("<b>" + html.EscapeString(title) + "</b>")
	text.PackStart(heading, false, false, 0)
	sub := wrapLabel(subtitle)
	addClass(sub, "dim-label")
	text.PackStart(sub, false, false, 0)
	inner.PackStart(text, true, true, 0)

	choose, _ := gtk.ButtonNewWithMnemonic("Choose _Files…")
	choose.SetVAlign(gtk.ALIGN_CENTER)
	choose.Connect("clicked", func() {
		chooser, err := gtk.FileChooserNativeDialogNew(title, a.window, gtk.FILE_CHOOSER_ACTION_OPEN, "_Open", "_Cancel")
		if err != nil {
			return
		}
		defer chooser.Destroy()
		chooser.SetSelectMultiple(true)
		if gtk.ResponseType(chooser.Run()) != gtk.RESPONSE_ACCEPT {
			return
		}
		paths, _ := chooser.GetFilenames()
		if len(paths) > 0 {
			onFiles(paths)
		}
	})
	inner.PackStart(choose, false, false, 0)

	zone, _ := gtk.EventBoxNew()
	zone.Add(inner)
	uris, _ := gtk.TargetEntryNew("text/uri-list", 0, dropURIs)
	zone.DragDestSet(gtk.DEST_DEFAULT_ALL, []gtk.TargetEntry{*uris}, gdk.ACTION_COPY)
	zone.Connect("drag-data-received",
		func(_ *gtk.EventBox, _ *gdk.DragContext, _, _ int, data *gtk.SelectionData, _ uint, _ uint) {
			paths := droppedFiles(data)
			if len(paths) == 0 {
				a.showError("Only local files can be used", fmt.Errorf("nothing usable was dropped"))
				return
			}
			onFiles(paths)
		})
	return zone
}

// fileJob is one file to process and where its result goes.
type fileJob struct {
	in, out string
}

// prepareFileJobs pairs each regular file with its output path, and asks before replacing
// outputs that exist. It returns nil if there's nothing to do.
func (a *App) prepareFileJobs(paths []string, suffix string) []fileJob {
	var jobs []fileJob
	var skipped, existing []string
	for _, p := range paths {
		info, err := a.opts.Fs.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			skipped = append(skipped, p)
			continue
		}
		out := p + suffix
		if _, err := a.opts.Fs.Stat(out); err == nil {
			existing = append(existing, out)
		}
		jobs = append(jobs, fileJob{in: p, out: out})
	}
	if len(skipped) > 0 {
		a.showError("Some items aren't files", fmt.Errorf("these were skipped:\n%s", strings.Join(skipped, "\n")))
	}
	if len(jobs) > 0 && len(existing) > 0 &&
		!a.confirmAction("Replace existing files?", "These files already exist and will be replaced:\n\n"+
			strings.Join(existing, "\n"), "_Replace") {
		return nil
	}
	return jobs
}

// confirmAction asks a yes/no question about a destructive step, defaulting to No.
func (a *App) confirmAction(title, text, action string) bool {
	dlg := gtk.MessageDialogNew(a.window, gtk.DIALOG_MODAL|gtk.DIALOG_DESTROY_WITH_PARENT,
		gtk.MESSAGE_WARNING, gtk.BUTTONS_NONE, "%s", title)
	dlg.FormatSecondaryText("%s", text)
	_, _ = dlg.AddButton("_Cancel", gtk.RESPONSE_CANCEL)
	if btn, err := dlg.AddButton(action, gtk.RESPONSE_ACCEPT); err == nil {
		addClass(btn, "destructive-action")
	}
	dlg.SetDefaultResponse(gtk.RESPONSE_CANCEL)
	response := dlg.Run()
	dlg.Destroy()
	return response == gtk.RESPONSE_ACCEPT
}

// acceptUnverified asks whether to encrypt to a key gpg hasn't verified, if it hasn't.
// ok is false if the user declined.
func (a *App) acceptUnverified(crypter backend.Crypter) (trustAnyway, ok bool) {
	warning := crypter.EncryptionWarning()
	if warning == "" {
		return false, true
	}
	if !a.confirmAction("Encrypt to an unverified key?", warning, "_Encrypt Anyway") {
		return false, false
	}
	return true, true
}

func (a *App) encryptFiles(crypter backend.Crypter, paths []string) {
	trustAnyway, ok := a.acceptUnverified(crypter)
	if !ok {
		return
	}
	jobs := a.prepareFileJobs(paths, ".gpg")
	a.runFileJobs(jobs, "Encrypting", "Encrypted", func(ctx context.Context, j fileJob) error {
		return crypter.EncryptFile(ctx, j.in, j.out, trustAnyway)
	})
}

func (a *App) signFiles(crypter backend.Crypter, paths []string) {
	jobs := a.prepareFileJobs(paths, ".sig")
	a.runFileJobs(jobs, "Signing", "Signed", func(ctx context.Context, j fileJob) error {
		return crypter.SignFile(ctx, j.in, j.out)
	})
}

// runFileJobs processes files in the background and reports what was written.
func (a *App) runFileJobs(jobs []fileJob, doing, done string, work func(context.Context, fileJob) error) {
	if len(jobs) == 0 {
		return
	}
	a.setStatus(fmt.Sprintf("%s %d file(s)…", doing, len(jobs)))
	a.background(func(ctx context.Context) func() {
		var written, failed []string
		for _, j := range jobs {
			if err := work(ctx, j); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", j.in, err))
				continue
			}
			written = append(written, j.out)
		}
		return func() {
			a.setStatus(fmt.Sprintf("%s %d of %d file(s).", done, len(written), len(jobs)))
			if len(failed) > 0 {
				a.showError(fmt.Sprintf("%d file(s) failed", len(failed)), fmt.Errorf("%s", strings.Join(failed, "\n\n")))
			}
			if len(written) > 0 {
				a.showInfo(fmt.Sprintf("%s %d file(s)", done, len(written)), "Saved:\n"+strings.Join(written, "\n"))
			}
		}
	})
}

// canCryptText reports whether the selection can encrypt or sign text, and the menu label.
func canCryptText(item backend.Item) (bool, string) {
	c, ok := item.(backend.Crypter)
	if !ok {
		return false, ""
	}
	canEncrypt, _ := c.CanEncrypt()
	canSign, _ := c.CanSign()
	switch {
	case canSign && canEncrypt:
		return true, "_Sign or Encrypt Text…"
	case canSign:
		return true, "_Sign Text…"
	default:
		return canEncrypt, "_Encrypt Text…"
	}
}

// actionCryptText opens a pane to encrypt text to, or sign text with, the selected key.
func (a *App) actionCryptText() {
	crypter, ok := a.selectedItem().(backend.Crypter)
	if !ok {
		return
	}
	canEncrypt, _ := crypter.CanEncrypt()
	canSign, _ := crypter.CanSign()
	if !canEncrypt && !canSign {
		return
	}

	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		return
	}
	title := "Encrypt Text"
	switch {
	case canSign && canEncrypt:
		title = "Sign or Encrypt Text"
	case canSign:
		title = "Sign Text"
	}
	win.SetTitle(title + " — " + crypter.CryptName())
	win.SetTransientFor(a.window)
	// An ordinary, movable window, opening centred over landhorse's.
	win.SetPosition(gtk.WIN_POS_CENTER_ON_PARENT)
	win.SetDefaultSize(640, 600)

	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 8)
	box.SetMarginStart(12)
	box.SetMarginEnd(12)
	box.SetMarginTop(12)
	box.SetMarginBottom(12)
	win.Add(box)
	box.PackStart(identityHeader(crypter.CryptIdentity(), canSign), false, false, 0)

	textArea := func(editable bool) (*gtk.TextView, *gtk.TextBuffer, gtk.IWidget) {
		view, _ := gtk.TextViewNew()
		view.SetWrapMode(gtk.WRAP_WORD_CHAR)
		view.SetEditable(editable)
		view.SetMonospace(!editable)
		buf, _ := view.GetBuffer()
		scroll, _ := gtk.ScrolledWindowNew(nil, nil)
		scroll.SetShadowType(gtk.SHADOW_IN)
		scroll.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
		scroll.Add(view)
		return view, buf, scroll
	}
	inLabel, _ := gtk.LabelNewWithMnemonic("_Text")
	inLabel.SetXAlign(0)
	inView, input, inScroll := textArea(true)
	inLabel.SetMnemonicWidget(inView)
	box.PackStart(inLabel, false, false, 0)
	box.PackStart(inScroll, true, true, 0)

	actions, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 6)
	box.PackStart(actions, false, false, 0)

	outLabel := newLabel("Result")
	_, output, outScroll := textArea(false)
	box.PackStart(outLabel, false, false, 0)
	box.PackStart(outScroll, true, true, 0)

	bottom, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 6)
	copyBtn, _ := gtk.ButtonNewWithMnemonic("_Copy Result")
	copyBtn.SetSensitive(false)
	closeBtn, _ := gtk.ButtonNewWithMnemonic("C_lose")
	closeBtn.Connect("clicked", win.Destroy)
	bottom.PackEnd(closeBtn, false, false, 0)
	bottom.PackEnd(copyBtn, false, false, 0)
	box.PackStart(bottom, false, false, 0)

	text := func(buf *gtk.TextBuffer) string {
		start, end := buf.GetBounds()
		s, _ := buf.GetText(start, end, false)
		return s
	}
	copyBtn.Connect("clicked", func() { a.copyToClipboard(text(output), "the result") })

	busy := false
	run := func(label string, work func(ctx context.Context, in string) (string, error)) {
		in := text(input)
		if busy || in == "" {
			return
		}
		busy = true
		actions.SetSensitive(false)
		a.background(func(ctx context.Context) func() {
			out, err := work(ctx, in)
			return func() {
				busy = false
				actions.SetSensitive(true)
				if err != nil {
					a.showError(label+" failed", err)
					return
				}
				output.SetText(out)
				copyBtn.SetSensitive(true)
			}
		})
	}

	if canEncrypt {
		btn, _ := gtk.ButtonNewWithMnemonic("_Encrypt to " + crypter.CryptName())
		accepted := false
		trust := false
		btn.Connect("clicked", func() {
			if !accepted {
				var ok bool
				if trust, ok = a.acceptUnverified(crypter); !ok {
					return
				}
				accepted = true
			}
			run("Encrypting", func(ctx context.Context, in string) (string, error) {
				return crypter.EncryptText(ctx, in, trust)
			})
		})
		actions.PackStart(btn, false, false, 0)
	}
	if canSign {
		btn, _ := gtk.ButtonNewWithMnemonic("_Sign")
		btn.SetTooltipText("Clear-sign the text: it stays readable, with a signature around it")
		btn.Connect("clicked", func() {
			run("Signing", crypter.SignText)
		})
		actions.PackStart(btn, false, false, 0)
	}
	win.ShowAll()
	inView.GrabFocus()
}

// identityHeader shows whose key the text pane uses: name, email, comment and key ID.
func identityHeader(id backend.Identity, private bool) gtk.IWidget {
	row, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
	row.SetMarginBottom(6)
	iconName := "avatar-default-symbolic"
	if private {
		iconName = "dialog-password"
	}
	if icon, err := gtk.ImageNewFromIconName(iconName, gtk.ICON_SIZE_DIALOG); err == nil {
		icon.SetVAlign(gtk.ALIGN_START)
		row.PackStart(icon, false, false, 0)
	}
	grid, _ := gtk.GridNew()
	grid.SetColumnSpacing(12)
	grid.SetRowSpacing(2)
	name := id.Name
	if name == "" {
		name = "(no name)"
	}
	heading := newLabel("")
	heading.SetMarkup(`<span size="large" weight="bold">` + html.EscapeString(name) + `</span>`)
	grid.Attach(heading, 0, 0, 2, 1)
	r := 1
	for _, f := range []struct {
		label, value string
		mono         bool
	}{
		{"Email", id.Email, false},
		{"Comment", id.Comment, false},
		{"Key ID", id.KeyID, true},
	} {
		if f.value == "" {
			continue
		}
		l := newLabel(f.label)
		addClass(l, "dim-label")
		l.SetXAlign(1)
		v := newLabel(f.value)
		if f.mono {
			v.SetMarkup(`<span font_family="monospace">` + html.EscapeString(f.value) + `</span>`)
		}
		grid.Attach(l, 0, r, 1, 1)
		grid.Attach(v, 1, r, 1, 1)
		r++
	}
	row.PackStart(grid, true, true, 0)
	return row
}
