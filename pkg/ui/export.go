package ui

import (
	"context"
	"errors"
	"os"

	"github.com/chigopher/pathlib"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// exportWithSecret exports an item whose secret part is available. The save dialog has
// options to include the secret part, protected by a password the export is encrypted
// with, or deliberately unencrypted.
func (a *App) exportWithSecret(exporter backend.SecretExporter) {
	dlg, err := gtk.FileChooserDialogNewWith2Buttons("Export", a.window, gtk.FILE_CHOOSER_ACTION_SAVE,
		"_Cancel", gtk.RESPONSE_CANCEL, "_Export", gtk.RESPONSE_ACCEPT)
	if err != nil {
		a.showError("Could not open the file chooser", err)
		return
	}
	defer dlg.Destroy()
	dlg.SetDoOverwriteConfirmation(true)
	startInHome(&dlg.FileChooser)
	dlg.SetCurrentName(exporter.ExportName())
	dlg.SetDefaultResponse(gtk.RESPONSE_ACCEPT)

	opts, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 6)
	includeSecret, _ := gtk.CheckButtonNewWithMnemonic("Export the _private key too")
	opts.PackStart(includeSecret, false, false, 0)

	grid, _ := gtk.GridNew()
	grid.SetColumnSpacing(12)
	grid.SetRowSpacing(6)
	grid.SetMarginStart(24)
	password := passwordEntry()
	confirm := passwordEntry()
	passLabel, _ := gtk.LabelNewWithMnemonic("Encrypt with _password:")
	passLabel.SetXAlign(1)
	passLabel.SetMnemonicWidget(password)
	confirmLabel, _ := gtk.LabelNewWithMnemonic("Con_firm password:")
	confirmLabel.SetXAlign(1)
	confirmLabel.SetMnemonicWidget(confirm)
	grid.Attach(passLabel, 0, 0, 1, 1)
	grid.Attach(password, 1, 0, 1, 1)
	grid.Attach(confirmLabel, 0, 1, 1, 1)
	grid.Attach(confirm, 1, 1, 1, 1)
	noPassword, _ := gtk.CheckButtonNewWithMnemonic("Export _without a password (not recommended)")
	grid.Attach(noPassword, 1, 2, 1, 1)
	hint := wrapLabel("")
	addClass(hint, "dim-label")
	grid.Attach(hint, 0, 3, 2, 1)

	secretOpts, _ := gtk.RevealerNew()
	secretOpts.Add(grid)
	opts.PackStart(secretOpts, false, false, 0)
	opts.ShowAll()
	dlg.SetExtraWidget(opts)

	update := func() {
		withSecret := includeSecret.GetActive()
		secretOpts.SetRevealChild(withSecret)
		password.SetSensitive(!noPassword.GetActive())
		confirm.SetSensitive(!noPassword.GetActive())
		passLabel.SetSensitive(!noPassword.GetActive())
		confirmLabel.SetSensitive(!noPassword.GetActive())
		if noPassword.GetActive() {
			hint.SetText("The file won't be encrypted: anyone who gets it can use your private " +
				"key, unless the key has its own passphrase.")
		} else {
			hint.SetText("The file is encrypted with this password. To restore it, run " +
				"gpg --decrypt FILE | gpg --import")
		}
	}
	includeSecret.Connect("toggled", func() {
		if includeSecret.GetActive() {
			dlg.SetCurrentName(exporter.SecretExportName())
		} else {
			dlg.SetCurrentName(exporter.ExportName())
		}
		update()
	})
	noPassword.Connect("toggled", update)
	update()

	var withSecret bool
	var secretPassword string
	for {
		if dlg.Run() != gtk.RESPONSE_ACCEPT {
			return
		}
		withSecret = includeSecret.GetActive()
		if !withSecret || noPassword.GetActive() {
			break
		}
		p1, _ := password.GetText()
		p2, _ := confirm.GetText()
		switch {
		case p1 == "":
			a.showError("Choose a password", errors.New("enter a password to encrypt the private key "+
				"export with, or tick “Export without a password”"))
		case p1 != p2:
			a.showError("The passwords don't match", errors.New("type the same password in both fields"))
		default:
			secretPassword = p1
		}
		if secretPassword != "" {
			break
		}
	}
	target := pathlib.NewPath(dlg.GetFilename(), pathlib.PathWithAfero(a.opts.Fs))
	password.SetText("")
	confirm.SetText("")

	a.setStatus("Exporting…")
	a.background(func(ctx context.Context) func() {
		var data []byte
		var err error
		mode := os.FileMode(0o644)
		if withSecret {
			// Private key exports are readable by their owner only. A file being replaced
			// (the dialog confirmed that) would keep its old permissions, so remove it first.
			mode = 0o600
			data, err = exporter.ExportSecret(ctx, secretPassword)
			if err == nil {
				if removeErr := target.Remove(); removeErr != nil && !os.IsNotExist(removeErr) {
					err = removeErr
				}
			}
		} else {
			data, err = exporter.Export(ctx)
		}
		if err == nil {
			err = target.WriteFileMode(data, mode)
			clear(data)
		}
		return func() {
			if err != nil {
				a.setStatus("")
				a.showError("Export failed", err)
				return
			}
			a.setStatus("Exported to " + target.String())
		}
	})
}

func passwordEntry() *gtk.Entry {
	entry, _ := gtk.EntryNew()
	entry.SetVisibility(false)
	entry.SetInputPurpose(gtk.INPUT_PURPOSE_PASSWORD)
	entry.SetHExpand(true)
	// Enter exports, as in the file name field.
	entry.SetActivatesDefault(true)
	return entry
}

// startInHome opens a save dialog in the home folder rather than the working directory,
// which may be a project checkout that exported keys shouldn't land in.
func startInHome(chooser *gtk.FileChooser) {
	if home, err := os.UserHomeDir(); err == nil {
		chooser.SetCurrentFolder(home)
	}
}
