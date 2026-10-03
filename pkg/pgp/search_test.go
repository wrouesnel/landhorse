package pgp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/backend"
	"github.com/wrouesnel/landhorse/pkg/pgp"
)

func TestKeyserverSearch(t *testing.T) {
	ctx := context.Background()
	ks := newFakeKeyserver(t)

	bobHome := newGnuPGHome(t)
	bob := generateKey(t, bobHome, "Bob Builder <bob@example.org>")
	armored, _ := gpgIn(t, bobHome, nil, "--armor", "--export", bob.Fingerprint)
	ks.add(bob.Fingerprint, "Bob Builder <bob@example.org>", armored)

	home := newGnuPGHome(t)
	g := &pgp.GPG{Home: home, Keyservers: []pgp.Keyserver{{URI: ks.URI, Name: "Fake"}}}
	cat := pgp.NewKeyserverCategory(g)
	if len(cat.Children()) != 1 || cat.Children()[0].Title() != "Fake" {
		t.Fatalf("children: %v", cat.Children())
	}
	if items, _, err := cat.Children()[0].(*pgp.KeyserverCategory).Search(ctx, "bob"); err != nil || len(items) != 1 {
		t.Fatalf("searching one keyserver: %v %v", items, err)
	}

	items, problems, err := cat.Search(ctx, "bob")
	if err != nil || len(problems) != 0 {
		t.Fatalf("Search: %v %v", err, problems)
	}
	if len(items) != 1 || items[0].Cells()[0] != "Bob Builder" || items[0].Cells()[1] != "bob@example.org" {
		t.Fatalf("results: %v", items)
	}
	if listed, _ := cat.Items(ctx); len(listed) != 1 {
		t.Errorf("Items after a search: %d, want 1", len(listed))
	}
	remote := items[0].(*pgp.RemoteItem) //nolint:forcetypeassert

	// Used directly, the key never enters the keyring.
	text, err := remote.CopyText(ctx)
	if err != nil || !strings.Contains(text, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("CopyText: %q %v", text, err)
	}
	if remote.EncryptionWarning() == "" {
		t.Error("no warning for encrypting to a keyserver key")
	}
	enc, err := remote.EncryptText(ctx, "hello bob", true)
	if err != nil {
		t.Fatal(err)
	}
	if dec, err := gpgIn(t, bobHome, []byte(enc), "--decrypt"); err != nil || string(dec) != "hello bob" {
		t.Errorf("bob decrypted %q, %v", dec, err)
	}
	if keys, _ := g.ListKeys(ctx); len(keys) != 0 {
		t.Fatalf("using the key imported it: %d keys in the keyring", len(keys))
	}

	// Imported, it does.
	if _, err := backend.RemoteImporter(remote).ImportToLocal(ctx); err != nil {
		t.Fatal(err)
	}
	keys, _ := g.ListKeys(ctx)
	if len(keys) != 1 || keys[0].Fingerprint != bob.Fingerprint {
		t.Fatalf("after import: %+v", keys)
	}

	if items, _, err := cat.Search(ctx, "nobody-at-all"); err != nil || len(items) != 0 {
		t.Errorf("empty search: %v %v", items, err)
	}
}
