package pgp_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/pgp"
)

func TestRevocation(t *testing.T) {
	ctx := context.Background()
	home := newGnuPGHome(t)
	ks := newFakeKeyserver(t)
	g := &pgp.GPG{Home: home, Keyservers: []pgp.Keyserver{{URI: ks.URI}}}
	alice := &pgp.Item{GPG: g, PGPKey: generateKey(t, home, "Alice <alice@example.com>")}
	bob := &pgp.Item{GPG: g, PGPKey: generateKey(t, home, "Bob <bob@example.com>")}

	if ok, why := alice.CanGenerateRevocation(); !ok {
		t.Fatalf("CanGenerateRevocation: %s", why)
	}
	cert, err := alice.GenerateRevocation(ctx, "1", "Laptop stolen\n\nsecond line")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid certificate is described", func(t *testing.T) {
		desc, err := alice.CheckRevocation(ctx, cert)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Valid revocation certificate", "Key has been compromised", "Laptop stolen"} {
			if !strings.Contains(desc, want) {
				t.Errorf("description %q does not contain %q", desc, want)
			}
		}
	})

	t.Run("certificate for another key is rejected", func(t *testing.T) {
		if _, err := bob.CheckRevocation(ctx, cert); err == nil || !strings.Contains(err.Error(), "different key") {
			t.Errorf("got %v, want a different key error", err)
		}
	})

	t.Run("public key is not a certificate", func(t *testing.T) {
		public, err := g.ExportPublic(ctx, alice.PGPKey.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := alice.CheckRevocation(ctx, string(public)); err == nil || !strings.Contains(err.Error(), "doesn't contain a key revocation") {
			t.Errorf("got %v, want a not-a-revocation error", err)
		}
	})

	t.Run("garbage and empty input are rejected", func(t *testing.T) {
		for _, input := range []string{"", "hello world", "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot base64\n-----END PGP PUBLIC KEY BLOCK-----"} {
			if _, err := alice.CheckRevocation(ctx, input); err == nil {
				t.Errorf("CheckRevocation(%q) succeeded", input)
			}
		}
	})

	t.Run("gpg's saved certificate with its colon guard is accepted", func(t *testing.T) {
		saved, err := os.ReadFile(filepath.Join(home, "openpgp-revocs.d", alice.PGPKey.Fingerprint+".rev"))
		if err != nil {
			t.Skipf("gpg did not save a revocation certificate: %v", err)
		}
		if !strings.Contains(string(saved), ":-----BEGIN") {
			t.Fatal("expected gpg's colon-guarded armor line")
		}
		if _, err := alice.CheckRevocation(ctx, string(saved)); err != nil {
			t.Errorf("saved certificate rejected: %v", err)
		}
	})

	t.Run("checking does not revoke", func(t *testing.T) {
		if keyValidity(t, g, alice.PGPKey.Fingerprint) == "r" {
			t.Fatal("CheckRevocation revoked the key in the real keyring")
		}
	})

	t.Run("revoke imports and publishes", func(t *testing.T) {
		before := len(ks.uploads())
		if _, err := alice.Revoke(ctx, cert, ks.URI); err != nil {
			t.Fatal(err)
		}
		if v := keyValidity(t, g, alice.PGPKey.Fingerprint); v != "r" {
			t.Errorf("validity after revoking: got %q, want r", v)
		}
		if len(ks.uploads()) != before+1 {
			t.Error("the revoked key was not published")
		}
	})

	// Last: after a failure gpg's dirmngr treats the host as dead for a while, which would
	// also fail later publishes to the fake keyserver on the same address.
	t.Run("failed publish still reports the local revocation", func(t *testing.T) {
		bobCert, err := bob.GenerateRevocation(ctx, "3", "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = bob.Revoke(ctx, bobCert, "hkp://127.0.0.1:1")
		if err == nil || !strings.Contains(err.Error(), "revoked in your keyring") {
			t.Errorf("got %v, want an error saying the key is revoked locally", err)
		}
	})
}

func keyValidity(t *testing.T, g *pgp.GPG, fpr string) string {
	t.Helper()
	keys, err := g.ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Fingerprint == fpr {
			return k.Validity
		}
	}
	t.Fatalf("key %s not found", fpr)
	return ""
}
