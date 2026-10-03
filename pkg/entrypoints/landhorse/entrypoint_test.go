package landhorse_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wrouesnel/ctxstdio"
	"github.com/wrouesnel/landhorse/pkg/entrypoints/landhorse"
	"github.com/wrouesnel/landhorse/version"
)

// runEntrypoint invokes the entrypoint as though from the command line and captures its output.
func runEntrypoint(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	stdOut, stdErr := new(bytes.Buffer), new(bytes.Buffer)
	ctx := ctxstdio.Set(context.Background(), stdOut, stdErr, os.Stdin)
	exitCode := landhorse.Entrypoint(ctx, args)
	return exitCode, stdOut.String(), stdErr.String()
}

// writeConfig writes a config file to a temporary directory and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestVersion(t *testing.T) {
	exitCode, stdOut, _ := runEntrypoint(t, "--version")
	if exitCode != 0 {
		t.Fatalf("exit code: got %d, want 0", exitCode)
	}
	if !strings.Contains(stdOut, version.Version) {
		t.Errorf("stdout %q does not contain version %q", stdOut, version.Version)
	}
}

// newGnuPGHome creates a GnuPG home holding one personal key, and stops its agent afterwards.
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

	cmd := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback",
		"--passphrase", "", "--quick-generate-key", "Test User <test@example.com>", "ed25519", "default", "never")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating a test key: %v\n%s", err, out)
	}
	return home
}

func TestList(t *testing.T) {
	// Never list the real user's SSH agent.
	t.Setenv("SSH_AUTH_SOCK", "")
	gnupgHome := newGnuPGHome(t)

	sshDir := t.TempDir()
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@laptop\n"
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519.pub"), []byte(pub), 0o600); err != nil {
		t.Fatal(err)
	}

	// The Secret Service is left out so the test doesn't depend on the user's keyring.
	configPath := writeConfig(t, fmt.Sprintf(
		"passwords:\n  disabled: true\nsecurity_keys:\n  disabled: true\npgp:\n  home: %q\nssh:\n  directory: %q\n",
		gnupgHome, sshDir))

	exitCode, stdOut, stdErr := runEntrypoint(t, "--config-file", configPath, "list")
	if exitCode != 0 {
		t.Fatalf("exit code: got %d, want 0\nstdout:\n%s\nstderr:\n%s", exitCode, stdOut, stdErr)
	}
	for _, want := range []string{
		"PGP Keys", "GnuPG keys", "Test User | test@example.com", "| Private |",
		"Private keys", "test@example.com  (pgp:" + gnupgHome + ":private:email:test@example.com)",
		"Public keys", "Secure Shell", "OpenSSH keys",
		"id_ed25519 | Ed25519 256 | test@laptop | No private key",
	} {
		if !strings.Contains(stdOut, want) {
			t.Errorf("stdout does not contain %q:\n%s", want, stdOut)
		}
	}
	if strings.Contains(stdOut, "Passwords") {
		t.Errorf("disabled Passwords group was listed:\n%s", stdOut)
	}
}

func TestListReportsBackendFailure(t *testing.T) {
	configPath := writeConfig(t,
		"passwords:\n  disabled: true\nssh:\n  disabled: true\nsecurity_keys:\n  disabled: true\n"+
			"pgp:\n  binary: /nonexistent/gpg\n")
	exitCode, stdOut, _ := runEntrypoint(t, "--config-file", configPath, "list")
	if exitCode != 1 {
		t.Fatalf("exit code: got %d, want 1", exitCode)
	}
	if !strings.Contains(stdOut, "! gpg") {
		t.Errorf("stdout does not report the gpg failure:\n%s", stdOut)
	}
}

func TestMissingConfigFileFails(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "missing.yml")
	if exitCode, _, _ := runEntrypoint(t, "--config-file", configPath); exitCode != 1 {
		t.Fatalf("exit code: got %d, want 1", exitCode)
	}
}

func TestInvalidFlagFails(t *testing.T) {
	exitCode, _, stdErr := runEntrypoint(t, "--no-such-flag")
	if exitCode == 0 {
		t.Fatal("exit code: got 0, want non-zero")
	}
	if !strings.Contains(stdErr, "no-such-flag") {
		t.Errorf("stderr %q does not mention the bad flag", stdErr)
	}
}
