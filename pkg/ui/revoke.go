package ui

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"

	"github.com/chigopher/pathlib"
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// maxCertificateSize bounds what is read from a dropped or chosen file. Revocation
// certificates are well under a kilobyte.
const maxCertificateSize = 1 << 20

// checkDelay is how long typing must pause before a pasted certificate is checked, so gpg
// isn't run for every keystroke.
const checkDelay = 400

// Drag and drop target IDs.
const (
	dropURIs = 1
	dropText = 2
)

// revokeDialog revokes an item, either with a revocation certificate the user supplies or
// by generating one, and always publishes the revocation.
type revokeDialog struct {
	app     *App
	item    backend.Item
	revoker backend.Revoker
	name    string

	dlg      *gtk.Dialog
	content  *gtk.Box
	target   *gtk.ComboBoxText
	buffer   *gtk.TextBuffer
	status   *gtk.Label
	statusIc *gtk.Image
	revoke   *gtk.Button

	// checked is the certificate text that last passed CheckRevocation, or "".
	checked    string
	generation int
	pending    glib.SourceHandle
	busy       bool
}

func (a *App) actionRevoke() {
	item := a.selectedItem()
	revoker, ok := item.(backend.Revoker)
	if !ok || revoker.Revoked() {
		return
	}
	d := &revokeDialog{app: a, item: item, revoker: revoker, name: item.Cells()[0]}
	if err := d.build(); err != nil {
		a.showError("Could not open the revoke dialog", err)
		return
	}
	d.dlg.ShowAll()
}

func (d *revokeDialog) build() error {
	dlg, err := gtk.DialogNew()
	if err != nil {
		return err
	}
	d.dlg = dlg
	dlg.SetTitle("Revoke Key")
	dlg.SetTransientFor(d.app.window)
	dlg.SetModal(true)
	dlg.SetDefaultSize(620, -1)
	_, _ = dlg.AddButton("_Close", gtk.RESPONSE_CLOSE)
	dlg.Connect("response", func() {
		if !d.busy {
			dlg.Destroy()
		}
	})
	// Closing the window mid-operation would orphan its result.
	dlg.Connect("delete-event", func() bool { return d.busy })

	d.content, _ = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 12)
	d.content.SetMarginStart(18)
	d.content.SetMarginEnd(18)
	d.content.SetMarginTop(18)
	d.content.SetMarginBottom(12)
	area, _ := dlg.GetContentArea()
	area.Add(d.content)

	heading := newLabel("")
	heading.SetMarkup("<b>Revoke " + html.EscapeString(d.name) + "’s key?</b>")
	d.content.PackStart(heading, false, false, 0)
	d.content.PackStart(wrapLabel("Revoking a key tells everyone it must no longer be used, and it "+
		"can't be undone. The revocation is imported into your keyring and published to a "+
		"keyserver, so that others learn of it."), false, false, 0)

	targets := d.revoker.RevokeTargets()
	if len(targets) == 0 {
		d.content.PackStart(d.noKeyserverHelp(), false, false, 0)
	} else {
		row, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
		label, _ := gtk.LabelNewWithMnemonic("Publish to _keyserver:")
		d.target, _ = gtk.ComboBoxTextNew()
		for _, t := range targets {
			d.target.Append(t.ID, t.Label)
		}
		d.target.SetActive(0)
		label.SetMnemonicWidget(d.target)
		row.PackStart(label, false, false, 0)
		row.PackStart(d.target, true, true, 0)
		d.content.PackStart(row, false, false, 0)
	}

	certFrame, err := d.buildCertificateSection()
	if err != nil {
		return err
	}
	d.content.PackStart(certFrame, true, true, 0)
	d.content.PackStart(d.buildGenerateSection(), false, false, 0)

	d.updateSensitivity()
	return nil
}

// noKeyserverHelp explains why revoking is unavailable and how to fix it.
func (d *revokeDialog) noKeyserverHelp() gtk.IWidget {
	row, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
	icon, _ := gtk.ImageNewFromIconName("dialog-warning", gtk.ICON_SIZE_DIALOG)
	icon.SetVAlign(gtk.ALIGN_START)
	row.PackStart(icon, false, false, 0)
	where := "the pgp.keyservers setting"
	if d.app.opts.ConfigPath != "" {
		where = "pgp.keyservers in " + d.app.opts.ConfigPath
	}
	row.PackStart(wrapLabel("Revoking needs a keyserver to publish the revocation to, and none is "+
		"configured. A revocation that isn't published only changes your own keyring, and "+
		"everyone else would go on trusting the key.\n\nAdd a keyserver to "+where+", for "+
		"example hkps://keys.openpgp.org, then try again."), true, true, 0)
	return row
}

func (d *revokeDialog) buildCertificateSection() (gtk.IWidget, error) {
	frame, _ := gtk.FrameNew("Use a revocation certificate")
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 8)
	box.SetMarginStart(12)
	box.SetMarginEnd(12)
	box.SetMarginTop(8)
	box.SetMarginBottom(12)
	frame.Add(box)

	help, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
	help.PackStart(wrapLabel("Choose a file, drop one here, or paste the certificate text. gpg "+
		"saves one for each key it creates, in openpgp-revocs.d in your GnuPG home."), true, true, 0)
	choose, _ := gtk.ButtonNewWithMnemonic("_Choose File…")
	choose.SetVAlign(gtk.ALIGN_START)
	choose.Connect("clicked", d.chooseFile)
	help.PackStart(choose, false, false, 0)
	box.PackStart(help, false, false, 0)

	view, err := gtk.TextViewNew()
	if err != nil {
		return nil, err
	}
	view.SetMonospace(true)
	view.SetWrapMode(gtk.WRAP_CHAR)
	view.SetAcceptsTab(false)
	d.buffer, _ = view.GetBuffer()
	d.buffer.Connect("changed", d.onTextChanged)
	scroll, _ := gtk.ScrolledWindowNew(nil, nil)
	scroll.SetPolicy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
	scroll.SetShadowType(gtk.SHADOW_IN)
	scroll.SetSizeRequest(-1, 110)
	scroll.Add(view)
	box.PackStart(scroll, true, true, 0)

	statusRow, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 8)
	d.statusIc, _ = gtk.ImageNew()
	d.statusIc.SetVAlign(gtk.ALIGN_START)
	d.status = wrapLabel("")
	statusRow.PackStart(d.statusIc, false, false, 0)
	statusRow.PackStart(d.status, true, true, 0)

	d.revoke, _ = gtk.ButtonNewWithMnemonic("_Revoke and Publish…")
	addClass(d.revoke, "destructive-action")
	d.revoke.SetVAlign(gtk.ALIGN_START)
	d.revoke.Connect("clicked", d.revokeWithCertificate)
	statusRow.PackEnd(d.revoke, false, false, 0)
	box.PackStart(statusRow, false, false, 0)
	d.setStatus("", "")

	// Accept files and text dropped anywhere on the section. Drops onto the text view
	// itself are inserted as text by GTK, and onTextChanged loads a dropped file's URI.
	uris, _ := gtk.TargetEntryNew("text/uri-list", 0, dropURIs)
	text, _ := gtk.TargetEntryNew("text/plain", 0, dropText)
	utf8, _ := gtk.TargetEntryNew("UTF8_STRING", 0, dropText)
	frame.DragDestSet(gtk.DEST_DEFAULT_ALL, []gtk.TargetEntry{*uris, *text, *utf8}, gdk.ACTION_COPY)
	frame.Connect("drag-data-received",
		func(_ *gtk.Frame, _ *gdk.DragContext, _, _ int, data *gtk.SelectionData, info uint, _ uint) {
			if info == dropURIs {
				if list := data.GetURIs(); len(list) > 0 {
					d.loadURI(list[0])
				}
				return
			}
			d.buffer.SetText(data.GetText())
		})
	return frame, nil
}

func (d *revokeDialog) buildGenerateSection() gtk.IWidget {
	frame, _ := gtk.FrameNew("Make a revocation certificate now")
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 8)
	box.SetMarginStart(12)
	box.SetMarginEnd(12)
	box.SetMarginTop(8)
	box.SetMarginBottom(12)
	frame.Add(box)

	ok, why := d.revoker.CanGenerateRevocation()
	if !ok {
		label := wrapLabel(why)
		addClass(label, "dim-label")
		box.PackStart(label, false, false, 0)
		return frame
	}

	box.PackStart(wrapLabel("This key's secret part is on this computer, so it can sign a "+
		"revocation right away. If it has a passphrase, you'll be asked for it."), false, false, 0)

	grid, _ := gtk.GridNew()
	grid.SetColumnSpacing(12)
	grid.SetRowSpacing(6)
	reasonLabel, _ := gtk.LabelNewWithMnemonic("R_eason:")
	reasonLabel.SetXAlign(1)
	reason, _ := gtk.ComboBoxTextNew()
	for _, r := range d.revoker.RevocationReasons() {
		reason.Append(r.ID, r.Label)
	}
	reason.SetActive(0)
	reason.SetHExpand(true)
	reasonLabel.SetMnemonicWidget(reason)
	descLabel, _ := gtk.LabelNewWithMnemonic("_Description:")
	descLabel.SetXAlign(1)
	desc, _ := gtk.EntryNew()
	desc.SetPlaceholderText("Optional, e.g. “Replaced by key 0x1234ABCD”")
	descLabel.SetMnemonicWidget(desc)
	grid.Attach(reasonLabel, 0, 0, 1, 1)
	grid.Attach(reason, 1, 0, 1, 1)
	grid.Attach(descLabel, 0, 1, 1, 1)
	grid.Attach(desc, 1, 1, 1, 1)
	box.PackStart(grid, false, false, 0)

	generate, _ := gtk.ButtonNewWithMnemonic("_Generate, Revoke and Publish…")
	addClass(generate, "destructive-action")
	generate.SetHAlign(gtk.ALIGN_END)
	generate.SetSensitive(d.target != nil)
	generate.Connect("clicked", func() {
		text, _ := desc.GetText()
		d.generateAndRevoke(reason.GetActiveID(), reason.GetActiveText(), text)
	})
	box.PackStart(generate, false, false, 0)
	return frame
}

// setStatus shows the certificate check result. kind is "ok", "error", "busy" or "".
func (d *revokeDialog) setStatus(kind, text string) {
	icons := map[string]string{"ok": "emblem-ok-symbolic", "error": "dialog-error-symbolic", "busy": "content-loading-symbolic"}
	if icon, ok := icons[kind]; ok {
		d.statusIc.SetFromIconName(icon, gtk.ICON_SIZE_BUTTON)
		d.statusIc.Show()
	} else {
		d.statusIc.Clear()
	}
	d.status.SetText(text)
}

func (d *revokeDialog) updateSensitivity() {
	d.revoke.SetSensitive(!d.busy && d.checked != "" && d.target != nil)
	d.content.SetSensitive(!d.busy)
}

func (d *revokeDialog) text() string {
	start, end := d.buffer.GetBounds()
	text, _ := d.buffer.GetText(start, end, false)
	return text
}

// onTextChanged checks the certificate once typing pauses. A lone file:// URI, which is
// what dropping a file onto the text view inserts, is replaced by the file's contents.
func (d *revokeDialog) onTextChanged() {
	d.checked = ""
	d.generation++
	d.updateSensitivity()
	if d.pending != 0 {
		glib.SourceRemove(d.pending)
		d.pending = 0
	}

	text := strings.TrimSpace(d.text())
	if strings.HasPrefix(text, "file://") && !strings.ContainsAny(text, "\n ") {
		d.loadURI(text)
		return
	}
	if text == "" {
		d.setStatus("", "")
		return
	}

	d.setStatus("busy", "Checking…")
	gen := d.generation
	d.pending = glib.TimeoutAdd(checkDelay, func() bool {
		d.pending = 0
		cert := d.text()
		d.app.background(func(ctx context.Context) func() {
			desc, err := d.revoker.CheckRevocation(ctx, cert)
			return func() {
				if gen != d.generation {
					return
				}
				if err != nil {
					d.setStatus("error", capitalize(err.Error())+".")
					return
				}
				d.checked = cert
				d.setStatus("ok", desc)
				d.updateSensitivity()
			}
		})
		return false
	})
}

func (d *revokeDialog) chooseFile() {
	chooser, err := gtk.FileChooserNativeDialogNew("Choose a Revocation Certificate", d.dlg,
		gtk.FILE_CHOOSER_ACTION_OPEN, "_Open", "_Cancel")
	if err != nil {
		d.app.showError("Could not open the file chooser", err)
		return
	}
	defer chooser.Destroy()
	if gtk.ResponseType(chooser.Run()) == gtk.RESPONSE_ACCEPT {
		d.loadFile(chooser.GetFilename())
	}
}

func (d *revokeDialog) loadURI(uri string) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u.Scheme != "file" {
		d.setStatus("error", "Only local files can be used.")
		return
	}
	d.loadFile(u.Path)
}

// loadFile puts a certificate file's contents in the text view, which checks it.
func (d *revokeDialog) loadFile(path string) {
	p := pathlib.NewPath(path, pathlib.PathWithAfero(d.app.opts.Fs))
	info, err := p.Stat()
	if err == nil && info.Size() > maxCertificateSize {
		err = errors.New("the file is too large to be a revocation certificate")
	}
	var data []byte
	if err == nil {
		data, err = p.ReadFile()
	}
	if err != nil {
		d.setStatus("error", fmt.Sprintf("Could not read %s: %v", path, err))
		return
	}
	d.buffer.SetText(string(data))
}

func (d *revokeDialog) targetID() string {
	if d.target == nil {
		return ""
	}
	return d.target.GetActiveID()
}

// confirm asks a yes/no question with a destructive default of No.
func (d *revokeDialog) confirm(title, text, action string) bool {
	dlg := gtk.MessageDialogNew(d.dlg, gtk.DIALOG_MODAL|gtk.DIALOG_DESTROY_WITH_PARENT,
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

// confirmByTyping is the second confirmation for generating a revocation: the user must
// type the key's confirmation code before the action button works.
func (d *revokeDialog) confirmByTyping() bool {
	code := d.revoker.ConfirmationCode()
	dlg, _ := gtk.DialogNew()
	defer dlg.Destroy()
	dlg.SetTitle("Confirm Revocation")
	dlg.SetTransientFor(d.dlg)
	dlg.SetModal(true)
	dlg.SetResizable(false)

	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 12)
	box.SetMarginStart(18)
	box.SetMarginEnd(18)
	box.SetMarginTop(18)
	box.SetMarginBottom(12)
	heading := newLabel("")
	heading.SetMarkup("<b>Are you sure?</b>")
	box.PackStart(heading, false, false, 0)
	prompt := wrapLabel("")
	prompt.SetMarkup("This is the last chance to stop. To revoke " + html.EscapeString(d.name) +
		"’s key for good, type its key ID, <tt>" + html.EscapeString(code) + "</tt>, below.")
	box.PackStart(prompt, false, false, 0)
	entry, _ := gtk.EntryNew()
	entry.SetPlaceholderText(code)
	box.PackStart(entry, false, false, 0)
	area, _ := dlg.GetContentArea()
	area.Add(box)

	_, _ = dlg.AddButton("_Cancel", gtk.RESPONSE_CANCEL)
	revoke, _ := dlg.AddButton("_Revoke Key", gtk.RESPONSE_ACCEPT)
	addClass(revoke, "destructive-action")
	revoke.SetSensitive(false)
	entry.Connect("changed", func() {
		typed, _ := entry.GetText()
		revoke.SetSensitive(strings.EqualFold(strings.TrimSpace(typed), code))
	})
	dlg.SetDefaultResponse(gtk.RESPONSE_CANCEL)
	dlg.ShowAll()
	return dlg.Run() == gtk.RESPONSE_ACCEPT
}

func (d *revokeDialog) revokeWithCertificate() {
	cert, target := d.checked, d.targetID()
	if cert == "" || target == "" {
		return
	}
	if !d.confirm("Revoke and publish?",
		fmt.Sprintf("%s’s key will be revoked in your keyring and the revocation published to %s. "+
			"This can't be undone.", d.name, target), "_Revoke and Publish") {
		return
	}
	d.run("Revoking…", func(ctx context.Context) (string, error) {
		return d.revoker.Revoke(ctx, cert, target)
	})
}

func (d *revokeDialog) generateAndRevoke(reason, reasonLabel, description string) {
	target := d.targetID()
	if target == "" {
		return
	}
	if !d.confirm("Generate a revocation and publish it?",
		fmt.Sprintf("Your secret key will sign a revocation of %s’s key (reason: %s), which is then "+
			"imported into your keyring and published to %s. This can't be undone.",
			d.name, reasonLabel, target), "_Continue") {
		return
	}
	if !d.confirmByTyping() {
		return
	}
	d.run("Generating the revocation; enter the key's passphrase if asked…", func(ctx context.Context) (string, error) {
		cert, err := d.revoker.GenerateRevocation(ctx, reason, description)
		if err != nil {
			return "", err
		}
		return d.revoker.Revoke(ctx, cert, target)
	})
}

// run performs a revocation in the background, keeping the dialog open but inert until it
// finishes. On success the dialog closes; either way the item list is reloaded, since a
// failed publish can still leave the key revoked locally.
func (d *revokeDialog) run(status string, work func(ctx context.Context) (string, error)) {
	d.busy = true
	d.updateSensitivity()
	d.app.setStatus(status)
	d.app.background(func(ctx context.Context) func() {
		report, err := work(ctx)
		return func() {
			d.busy = false
			d.updateSensitivity()
			d.app.list.reload()
			if err != nil {
				d.app.setStatus("")
				d.app.showError("Revoking failed", err)
				return
			}
			d.dlg.Destroy()
			d.app.showInfo("Key revoked", report)
		}
	})
}

func wrapLabel(text string) *gtk.Label {
	label := newLabel(text)
	label.SetLineWrap(true)
	label.SetMaxWidthChars(70)
	return label
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
