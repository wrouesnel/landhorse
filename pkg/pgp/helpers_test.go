package pgp_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/pgp"
)

// newGnuPGHome returns a disposable GnuPG home, removed with the test along with its agent.
// Generating throwaway keys here is allowed by the exception in CLAUDE.md.
func newGnuPGHome(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not installed")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run() })
	return home
}

// generateKey makes a passphrase-less key in home and returns it as listed by gpg.
func generateKey(t *testing.T, home, uid string) *pgp.Key {
	t.Helper()
	gen := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", uid, "ed25519", "default", "never")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generating a test key: %v\n%s", err, out)
	}
	keys, err := (&pgp.GPG{Home: home}).ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.PrimaryUserID().Raw == uid {
			return k
		}
	}
	t.Fatalf("generated key %q not listed", uid)
	return nil
}

// fakeKeyserver is an HKP keyserver on localhost that records uploads, so publishing
// tests never reach a real keyserver.
type fakeKeyserver struct {
	URI      string
	mu       sync.Mutex
	uploaded []string
}

func newFakeKeyserver(t *testing.T) *fakeKeyserver {
	t.Helper()
	ks := &fakeKeyserver{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/pks/add" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		ks.mu.Lock()
		ks.uploaded = append(ks.uploaded, form.Get("keytext"))
		ks.mu.Unlock()
	}))
	t.Cleanup(server.Close)
	ks.URI = "hkp://" + strings.TrimPrefix(server.URL, "http://")
	return ks
}

func (ks *fakeKeyserver) uploads() []string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return append([]string(nil), ks.uploaded...)
}
