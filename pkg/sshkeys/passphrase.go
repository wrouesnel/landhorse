package sshkeys

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

var _ backend.PassphraseChanger = (*Item)(nil)

// CanChangePassphrase implements backend.PassphraseChanger.
func (i *Item) CanChangePassphrase() bool { return i.SSHKey.PrivatePath != nil }

// HasPassphrase implements backend.PassphraseChanger.
func (i *Item) HasPassphrase() bool { return i.SSHKey.Encrypted }

// ChangePassphrase implements backend.PassphraseChanger. The key is decrypted and
// re-encrypted in memory (no passphrase is passed to another program), checked against
// the original public key, and written in OpenSSH format, replacing the file atomically
// with owner-only permissions. Legacy PEM keys are converted to OpenSSH format.
func (i *Item) ChangePassphrase(_ context.Context, current, replacement string) error {
	k := i.SSHKey
	if k.PrivatePath == nil {
		return errors.New("this key has no private key file")
	}
	if replacement == "" {
		return errors.New("the new passphrase is empty")
	}
	data, err := k.PrivatePath.ReadFile()
	if err != nil {
		return err
	}

	var raw any
	if k.Encrypted {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(current))
	} else {
		raw, err = ssh.ParseRawPrivateKey(data)
	}
	if errors.Is(err, x509.IncorrectPasswordError) {
		return backend.ErrWrongPassphrase
	}
	if err != nil {
		return fmt.Errorf("reading the private key: %w", err)
	}

	block, err := ssh.MarshalPrivateKeyWithPassphrase(raw, k.Comment, []byte(replacement))
	if err != nil {
		return fmt.Errorf("this kind of key can't be re-encrypted here (use ssh-keygen -p): %w", err)
	}
	encoded := pem.EncodeToMemory(block)

	// Prove the new file opens with the new passphrase and holds the same key.
	check, err := ssh.ParsePrivateKeyWithPassphrase(encoded, []byte(replacement))
	if err != nil {
		return fmt.Errorf("checking the re-encrypted key: %w", err)
	}
	original, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(check.PublicKey().Marshal(), original.PublicKey().Marshal()) {
		return errors.New("the re-encrypted key doesn't match the original; the file was not changed")
	}

	return replaceFile(k.PrivatePath.Fs(), k.PrivatePath.String(), encoded, 0o600)
}

// replaceFile writes data to a temporary file beside path and renames it over path, so the
// key is never half written.
func replaceFile(fs afero.Fs, path string, data []byte, mode os.FileMode) error {
	tmp, err := afero.TempFile(fs, filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = fs.Remove(name) }() // no-op once renamed
	if err := fs.Chmod(name, mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return fs.Rename(name, path)
}

// SavedPassphrase implements backend.PassphraseChanger with the entry gnome-keyring's and
// gcr's SSH agents look for: "unique" is "ssh-store:" and the private key's path.
func (i *Item) SavedPassphrase() (string, map[string]string, map[string]string) {
	path := i.SSHKey.PrivatePath.String()
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	unique := "ssh-store:" + filepath.Clean(path)
	attrs := map[string]string{"unique": unique, "xdg:schema": "org.freedesktop.Secret.Generic"}
	return "Unlock password for: " + i.SSHKey.DisplayName(), attrs, map[string]string{"unique": unique}
}
