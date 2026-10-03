package ui

import (
	"errors"
	"html"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// unlockWithPIN asks for a PIN and unlocks with it, asking again if it's wrong.
func (a *App) unlockWithPIN(cat backend.Category, unlocker backend.PINUnlocker) {
	dlg, err := gtk.DialogNew()
	if err != nil {
		return
	}
	defer dlg.Destroy()
	dlg.SetTitle("Unlock " + cat.Title())
	dlg.SetTransientFor(a.window)
	dlg.SetModal(true)
	dlg.SetResizable(false)

	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 12)
	box.SetMarginStart(18)
	box.SetMarginEnd(18)
	box.SetMarginTop(18)
	box.SetMarginBottom(12)
	heading := newLabel("")
	heading.SetMarkup("<b>Unlock " + html.EscapeString(cat.Title()) + "</b>")
	box.PackStart(heading, false, false, 0)
	box.PackStart(wrapLabel(unlocker.PINPrompt()), false, false, 0)
	row, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 12)
	label, _ := gtk.LabelNewWithMnemonic("_PIN:")
	entry := passwordEntry()
	label.SetMnemonicWidget(entry)
	row.PackStart(label, false, false, 0)
	row.PackStart(entry, true, true, 0)
	box.PackStart(row, false, false, 0)
	problem := wrapLabel("")
	addClass(problem, "error")
	box.PackStart(problem, false, false, 0)
	area, _ := dlg.GetContentArea()
	area.Add(box)
	_, _ = dlg.AddButton("_Cancel", gtk.RESPONSE_CANCEL)
	unlock, _ := dlg.AddButton("_Unlock", gtk.RESPONSE_ACCEPT)
	addClass(unlock, "suggested-action")
	dlg.SetDefaultResponse(gtk.RESPONSE_ACCEPT)
	dlg.ShowAll()
	problem.Hide()

	for {
		if dlg.Run() != gtk.RESPONSE_ACCEPT {
			return
		}
		pin, _ := entry.GetText()
		if pin == "" {
			continue
		}
		// Check the PIN while the dialog waits, so a wrong one can be retyped.
		var unlockErr error
		finished := false
		dlg.SetSensitive(false)
		go func() {
			err := unlocker.UnlockWithPIN(a.ctx, pin)
			glib.IdleAdd(func() { unlockErr, finished = err, true })
		}()
		for !finished {
			gtk.MainIterationDo(true)
		}
		dlg.SetSensitive(true)
		entry.SetText("")
		switch {
		case errors.Is(unlockErr, backend.ErrWrongPassphrase):
			problem.SetText("That PIN is wrong. Each wrong PIN uses up one of the limited attempts.")
			problem.Show()
			entry.GrabFocus()
			continue
		case unlockErr != nil:
			a.showError("Could not unlock "+cat.Title(), unlockErr)
			return
		}
		a.lockStateChanged()
		a.list.reload()
		return
	}
}
