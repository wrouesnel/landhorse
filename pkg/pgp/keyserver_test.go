package pgp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/pgp"
)

func TestSendKey(t *testing.T) {
	home := newGnuPGHome(t)
	key := generateKey(t, home, "Pub Lisher <pub@example.com>")
	ks := newFakeKeyserver(t)

	if _, err := (&pgp.GPG{Home: home}).SendKey(context.Background(), ks.URI, key.Fingerprint); err != nil {
		t.Fatal(err)
	}
	uploads := ks.uploads()
	if len(uploads) != 1 || !strings.Contains(uploads[0], "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("keyserver received %q, want one armored public key", uploads)
	}
	if strings.Contains(uploads[0], "PRIVATE KEY") {
		t.Error("keyserver received secret key material")
	}
}
