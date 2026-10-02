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

// TestSendKey publishes to a fake HKP keyserver on localhost, so nothing leaves the machine.
func TestSendKey(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not installed")
	}

	var mu sync.Mutex
	var uploaded string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/pks/add" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		uploaded = form.Get("keytext")
		mu.Unlock()
	}))
	defer server.Close()

	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run() })
	gen := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", "Pub Lisher <pub@example.com>", "ed25519", "default", "never")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generating a test key: %v\n%s", err, out)
	}

	g := &pgp.GPG{Home: home}
	keys, err := g.ListKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListKeys: %v, %v", keys, err)
	}

	keyserver := "hkp://" + strings.TrimPrefix(server.URL, "http://")
	if _, err := g.SendKey(context.Background(), keyserver, keys[0].Fingerprint); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(uploaded, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Errorf("keyserver received %q, want an armored public key", uploaded)
	}
	if strings.Contains(uploaded, "PRIVATE KEY") {
		t.Error("keyserver received secret key material")
	}
}
