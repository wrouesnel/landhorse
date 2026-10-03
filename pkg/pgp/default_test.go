package pgp_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/pgp"
)

func TestResolveDefaultKey(t *testing.T) {
	t.Setenv("GNUPGHOME", "")
	ctx := context.Background()
	home := newGnuPGHome(t)
	first := generateKey(t, home, "First <first@example.com>")
	second := generateKey(t, home, "Second <second@example.com>")
	g := &pgp.GPG{Home: home}
	keys, err := g.ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}

	def := g.ResolveDefaultKey(ctx, keys)
	if def == nil {
		t.Fatal("no default key with two private keys")
	}
	// Without gpg.conf (and whatever Seahorse's setting is), it's a private key that can sign.
	if def.Fingerprint != first.Fingerprint && def.Fingerprint != second.Fingerprint {
		t.Errorf("default %s is neither key", def.Fingerprint)
	}

	conf := "# settings\ndefault-key second@example.com\n"
	if err := os.WriteFile(filepath.Join(home, "gpg.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	def = g.ResolveDefaultKey(ctx, keys)
	if def == nil || def.Fingerprint != second.Fingerprint || def.Source != "default-key in gpg.conf" {
		t.Errorf("with gpg.conf: %+v", def)
	}

	conf = "default-key 0x" + first.Fingerprint[24:] + "\n"
	if err := os.WriteFile(filepath.Join(home, "gpg.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if def = g.ResolveDefaultKey(ctx, keys); def == nil || def.Fingerprint != first.Fingerprint {
		t.Errorf("with a key ID in gpg.conf: %+v", def)
	}
}
