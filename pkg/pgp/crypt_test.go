package pgp_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/pgp"
)

func gpgIn(t *testing.T, home string, stdin []byte, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--pinentry-mode", "loopback",
		"--passphrase", ""}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Logf("gpg %v: %s", args, stderr.String())
	}
	return out, err
}

func TestEncryptAndSign(t *testing.T) {
	ctx := context.Background()
	home := newGnuPGHome(t)
	g := &pgp.GPG{Home: home}
	alice := &pgp.Item{GPG: g, PGPKey: generateKey(t, home, "Alice <alice@example.com>")}

	// Bob's public key only, imported unverified.
	bobHome := newGnuPGHome(t)
	bobKey := generateKey(t, bobHome, "Bob <bob@example.com>")
	public, _ := gpgIn(t, bobHome, nil, "--armor", "--export", bobKey.Fingerprint)
	if _, err := gpgIn(t, home, public, "--import"); err != nil {
		t.Fatal(err)
	}
	keys, _ := g.ListKeys(ctx)
	var bob *pgp.Item
	for _, k := range keys {
		if k.Fingerprint == bobKey.Fingerprint {
			bob = &pgp.Item{GPG: g, PGPKey: k}
		}
	}

	if ok, why := alice.CanEncrypt(); !ok {
		t.Fatalf("alice CanEncrypt: %s", why)
	}
	if ok, why := alice.CanSign(); !ok {
		t.Fatalf("alice CanSign: %s", why)
	}
	if ok, _ := bob.CanSign(); ok {
		t.Error("CanSign is true without the private key")
	}
	if alice.EncryptionWarning() != "" || bob.EncryptionWarning() == "" {
		t.Errorf("warnings: alice %q, bob %q", alice.EncryptionWarning(), bob.EncryptionWarning())
	}

	dir := t.TempDir()
	plain := filepath.Join(dir, "report.txt")
	content := []byte("quarterly numbers\n")
	if err := os.WriteFile(plain, content, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("encrypt a file", func(t *testing.T) {
		out := plain + ".gpg"
		if err := alice.EncryptFile(ctx, plain, out, false); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		decrypted, err := gpgIn(t, home, data, "--decrypt")
		if err != nil || !bytes.Equal(decrypted, content) {
			t.Errorf("decrypted %q, %v", decrypted, err)
		}
	})

	t.Run("sign a file", func(t *testing.T) {
		sig := plain + ".sig"
		if err := alice.SignFile(ctx, plain, sig); err != nil {
			t.Fatal(err)
		}
		if _, err := gpgIn(t, home, nil, "--verify", sig, plain); err != nil {
			t.Error("the detached signature doesn't verify")
		}
	})

	t.Run("unverified recipient needs accepting", func(t *testing.T) {
		out := filepath.Join(dir, "for-bob.gpg")
		if err := bob.EncryptFile(ctx, plain, out, false); err == nil {
			t.Error("gpg encrypted to an unverified key without it being accepted")
		}
		if err := bob.EncryptFile(ctx, plain, out, true); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		decrypted, err := gpgIn(t, bobHome, data, "--decrypt")
		if err != nil || !bytes.Equal(decrypted, content) {
			t.Errorf("bob decrypted %q, %v", decrypted, err)
		}
	})

	t.Run("text", func(t *testing.T) {
		enc, err := alice.EncryptText(ctx, "meet at noon", false)
		if err != nil || !strings.Contains(enc, "BEGIN PGP MESSAGE") {
			t.Fatalf("EncryptText: %q, %v", enc, err)
		}
		if dec, _ := gpgIn(t, home, []byte(enc), "--decrypt"); string(dec) != "meet at noon" {
			t.Errorf("decrypted %q", dec)
		}
		signed, err := alice.SignText(ctx, "I agree")
		if err != nil || !strings.Contains(signed, "BEGIN PGP SIGNED MESSAGE") || !strings.Contains(signed, "I agree") {
			t.Fatalf("SignText: %q, %v", signed, err)
		}
		if _, err := gpgIn(t, home, []byte(signed), "--verify"); err != nil {
			t.Error("the clear-signed text doesn't verify")
		}
	})

	t.Run("sign-only key can't encrypt", func(t *testing.T) {
		cmd := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
			"--quick-generate-key", "Signer <signer@example.com>", "ed25519", "sign", "never")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		keys, _ := g.ListKeys(ctx)
		for _, k := range keys {
			if k.PrimaryUserID().Email() == "signer@example.com" {
				if ok, why := (&pgp.Item{GPG: g, PGPKey: k}).CanEncrypt(); ok || why == "" {
					t.Errorf("CanEncrypt: %v %q", ok, why)
				}
			}
		}
	})
}
