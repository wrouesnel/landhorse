package ui

import (
	"context"
	"errors"
	"fmt"
	"html"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// canChangePassphrase reports whether item's passphrase can be changed.
func canChangePassphrase(item backend.Item) bool {
	p, ok := item.(backend.PassphraseChanger)
	return ok && p.CanChangePassphrase()
}

// actionChangePassphrase sets a new passphrase on the selected item, and optionally saves it
// in the login keyring so the desktop unlocks the item at login.
func (a *App) actionChangePassphrase() {
	item := a.selectedItem()
	changer, ok := item.(backend.PassphraseChanger)
	if !ok || !changer.CanChangePassphrase() {
		return
	}
	store := a.opts.SecretStore
	label, attrs, lookup := changer.SavedPassphrase()
	name := item.Cells()[0]

	dlg, err := gtk.DialogNew()
	if err != nil {
		a.showError("Could not open the passphrase dialog", err)
		return
	}
	defer dlg.Destroy()
	dlg.SetTitle("Change Passphrase")
	dlg.SetTransientFor(a.window)
	dlg.SetModal(true)
	dlg.SetResizable(false)

	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 12)
	box.SetMarginStart(18)
	box.SetMarginEnd(18)
	box.SetMarginTop(18)
	box.SetMarginBottom(12)
	heading := newLabel("")
	heading.SetMarkup("<b>Change the passphrase of " + html.EscapeString(name) + "</b>")
	box.PackStart(heading, false, false, 0)
	intro := "Choose a new passphrase. Programs using the key will ask for it, unless it's saved."
	if !changer.HasPassphrase() {
		intro = "This key has no passphrase, so anyone who gets the file can use it. Choose one to protect it."
	}
	box.PackStart(wrapLabel(intro), false, false, 0)

	grid, _ := gtk.GridNew()
	grid.SetColumnSpacing(12)
	grid.SetRowSpacing(6)
	row := 0
	addField := func(mnemonic string) *gtk.Entry {
		label, _ := gtk.LabelNewWithMnemonic(mnemonic)
		label.SetXAlign(1)
		entry := passwordEntry()
		label.SetMnemonicWidget(entry)
		grid.Attach(label, 0, row, 1, 1)
		grid.Attach(entry, 1, row, 1, 1)
		row++
		return entry
	}
	var current *gtk.Entry
	if changer.HasPassphrase() {
		current = addField("C_urrent passphrase:")
	}
	replacement := addField("_New passphrase:")
	confirm := addField("Con_firm passphrase:")
	box.PackStart(grid, false, false, 0)

	var save *gtk.CheckButton
	if store != nil {
		save, _ = gtk.CheckButtonNewWithMnemonic(fmt.Sprintf("_Save the passphrase in the %s", store.StoreName()))
		save.SetActive(true)
		box.PackStart(save, false, false, 0)
		hint := wrapLabel("")
		addClass(hint, "dim-label")
		hint.SetMarginStart(24)
		box.PackStart(hint, false, false, 0)
		existing := 0
		update := func() {
			switch {
			case save.GetActive():
				hint.SetText("The key is then unlocked automatically when you log in.")
			case existing > 0:
				hint.SetText(fmt.Sprintf("The passphrase saved in the %s won't work any more, so it "+
					"will be removed.", store.StoreName()))
			default:
				hint.SetText("You'll be asked for the passphrase when the key is used.")
			}
		}
		save.Connect("toggled", update)
		update()
		a.background(func(ctx context.Context) func() {
			n, err := store.CountSecrets(ctx, lookup)
			return func() {
				if err == nil {
					existing = n
					update()
				}
			}
		})
	}

	area, _ := dlg.GetContentArea()
	area.Add(box)
	_, _ = dlg.AddButton("_Cancel", gtk.RESPONSE_CANCEL)
	ok2, _ := dlg.AddButton("_Change Passphrase", gtk.RESPONSE_ACCEPT)
	addClass(ok2, "suggested-action")
	dlg.SetDefaultResponse(gtk.RESPONSE_ACCEPT)
	dlg.ShowAll()

	for {
		if dlg.Run() != gtk.RESPONSE_ACCEPT {
			return
		}
		cur := ""
		if current != nil {
			cur, _ = current.GetText()
		}
		p1, _ := replacement.GetText()
		p2, _ := confirm.GetText()
		if p1 == "" {
			a.showError("Choose a passphrase", errors.New("the new passphrase can't be empty"))
			continue
		}
		if p1 != p2 {
			a.showError("The passphrases don't match", errors.New("type the same passphrase in both fields"))
			continue
		}
		saveIt := save != nil && save.GetActive()

		// Change the passphrase while the dialog waits, so a wrong current passphrase can be
		// retyped. Keyring work happens afterwards, in the background.
		// Completion is signalled on the main loop, which also wakes the loop below.
		var changeErr error
		finished := false
		dlg.SetSensitive(false)
		go func() {
			err := changer.ChangePassphrase(a.ctx, cur, p1)
			glib.IdleAdd(func() { changeErr, finished = err, true })
		}()
		for !finished {
			gtk.MainIterationDo(true)
		}
		dlg.SetSensitive(true)
		if errors.Is(changeErr, backend.ErrWrongPassphrase) {
			a.showError("The current passphrase is wrong", errors.New("the key wasn't changed"))
			continue
		}
		if changeErr != nil {
			a.showError("Could not change the passphrase", changeErr)
			return
		}

		a.background(func(ctx context.Context) func() {
			var err error
			removed := 0
			if store != nil {
				if saveIt {
					// Remove old entries first: the store only replaces an entry whose
					// attributes match exactly, and older entries may differ.
					if _, err = store.DeleteSecrets(ctx, lookup); err == nil {
						err = store.StoreSecret(ctx, label, attrs, p1)
					}
				} else {
					removed, err = store.DeleteSecrets(ctx, lookup)
				}
			}
			return func() {
				a.list.reload()
				switch {
				case err != nil && saveIt:
					a.showError("The passphrase was changed, but not saved", err)
				case err != nil:
					a.showError("The passphrase was changed, but the old saved one wasn't removed", err)
				case saveIt:
					a.showInfo("Passphrase changed", fmt.Sprintf("The new passphrase is saved in the %s, "+
						"so the key is unlocked automatically when you log in.", store.StoreName()))
				case removed > 0:
					a.showInfo("Passphrase changed", fmt.Sprintf("The old passphrase was removed from the "+
						"%s. You'll be asked for the new one when the key is used.", store.StoreName()))
				default:
					a.showInfo("Passphrase changed", "You'll be asked for it when the key is used.")
				}
			}
		})
		return
	}
}
