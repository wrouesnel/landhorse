package pgp_test

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/pgp"
)

func TestExportSecret(t *testing.T) {
	ctx := context.Background()
	home := newGnuPGHome(t)
	key := generateKey(t, home, "Exporter <export@example.com>")
	item := &pgp.Item{GPG: &pgp.GPG{Home: home}, PGPKey: key}

	if !item.CanExportSecret() {
		t.Fatal("CanExportSecret is false for a key with its secret part")
	}

	plain, err := item.ExportSecret(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Fatalf("unencrypted export isn't a private key block:\n%.200s", plain)
	}

	encrypted, err := item.ExportSecret(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encrypted), "BEGIN PGP MESSAGE") || strings.Contains(string(encrypted), "PRIVATE KEY BLOCK") {
		t.Fatalf("encrypted export isn't an encrypted message:\n%.200s", encrypted)
	}

	decrypt := func(password string) ([]byte, error) {
		cmd := exec.Command("gpg", "--homedir", newGnuPGHome(t), "--batch", "--pinentry-mode", "loopback",
			"--passphrase", password, "--decrypt")
		cmd.Stdin = bytes.NewReader(encrypted)
		return cmd.Output()
	}
	if _, err := decrypt("wrong"); err == nil {
		t.Error("the encrypted export decrypted with the wrong password")
	}
	decrypted, err := decrypt("correct horse")
	if err != nil {
		t.Fatalf("decrypting with the right password: %v", err)
	}

	// The decrypted export restores the private key into an empty keyring.
	restoreHome := newGnuPGHome(t)
	imp := exec.Command("gpg", "--homedir", restoreHome, "--batch", "--import")
	imp.Stdin = bytes.NewReader(decrypted)
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("importing the decrypted export: %v\n%s", err, out)
	}
	keys, err := (&pgp.GPG{Home: restoreHome}).ListKeys(ctx)
	if err != nil || len(keys) != 1 || !keys[0].HasSecret() || keys[0].Fingerprint != key.Fingerprint {
		t.Fatalf("restored keyring: %+v, %v", keys, err)
	}

	public := &pgp.Item{GPG: &pgp.GPG{Home: restoreHome}, PGPKey: &pgp.Key{SubKey: pgp.SubKey{Fingerprint: "00"}}}
	if public.CanExportSecret() {
		t.Error("CanExportSecret is true for a key without a secret part")
	}
}
