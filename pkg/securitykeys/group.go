package securitykeys

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// Group is the "Security Keys" node of the type tree.
type Group struct {
	P11  *P11
	FIDO *FIDO

	// passkeys keeps unlocked authenticators (their PINs) across refreshes.
	passkeys map[string]*DeviceCategory
}

// Title implements backend.Group.
func (g *Group) Title() string { return "Security Keys" }

// IconName implements backend.Group.
func (g *Group) IconName() string { return "auth-smartcard-symbolic" }

// Categories implements backend.Group. Devices are listed afresh each time, so plugging in
// or removing a key shows on Refresh.
func (g *Group) Categories(ctx context.Context) ([]backend.Category, error) {
	var cats []backend.Category
	var missing []string

	cards, err := newSmartCards(ctx, g.P11)
	switch {
	case errors.Is(err, exec.ErrNotFound):
		missing = append(missing, "p11tool (package gnutls-bin)")
	case err != nil:
		return nil, err
	default:
		cats = append(cats, cards)
	}

	devices, err := g.FIDO.Devices(ctx)
	switch {
	case errors.Is(err, exec.ErrNotFound):
		missing = append(missing, "fido2-token (package fido2-tools)")
		if len(cats) == 0 {
			return nil, fmt.Errorf("security keys need %s", strings.Join(missing, " and "))
		}
		return cats, nil
	case err != nil:
		return nil, err
	}
	if g.passkeys == nil {
		g.passkeys = map[string]*DeviceCategory{}
	}
	keys := &Passkeys{}
	present := map[string]bool{}
	for _, d := range devices {
		present[d.Path] = true
		cat, ok := g.passkeys[d.Path]
		if !ok || cat.Device != d {
			cat = &DeviceCategory{FIDO: g.FIDO, Device: d}
			g.passkeys[d.Path] = cat
		}
		keys.devices = append(keys.devices, cat)
	}
	// A removed key forgets its PIN.
	for path := range g.passkeys {
		if !present[path] {
			delete(g.passkeys, path)
		}
	}
	return append(cats, keys), nil
}
