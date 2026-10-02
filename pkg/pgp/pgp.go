// Package pgp lists and manages OpenPGP keys by running the gpg command line tool.
//
// gpg is driven through its stable machine readable interface (--with-colons) rather than
// through gpgme, which keeps the build free of another C library and means landhorse sees
// exactly what the user's own gpg does.
package pgp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// GPG runs the gpg binary.
type GPG struct {
	// Binary is the gpg executable, looked up on PATH if it has no slash.
	Binary string
	// Home overrides GNUPGHOME when non-empty.
	Home string
}

// run executes gpg and returns its standard output. On failure the error includes the
// tail of standard error, which is where gpg explains itself.
func (g *GPG) run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	full := []string{"--batch", "--no-tty", "--with-colons", "--fixed-list-mode"}
	if g.Home != "" {
		full = append(full, "--homedir", g.Home)
	}
	full = append(full, args...)

	binary := g.Binary
	if binary == "" {
		binary = "gpg"
	}

	logutil.FromCtx(ctx).Debug("Running gpg", zap.String("binary", binary), zap.Strings("args", full))
	cmd := exec.CommandContext(ctx, binary, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("gpg %s: %w", strings.Join(args, " "), err)
		}
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("gpg %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

// ListKeys returns all keys in the public keyring. Keys whose secret part is available
// have Secret set.
func (g *GPG) ListKeys(ctx context.Context) ([]*Key, error) {
	out, _, err := g.run(ctx, "--with-fingerprint", "--with-keygrip", "--list-keys")
	if err != nil {
		return nil, err
	}
	keys, err := ParseColons(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}

	out, _, err = g.run(ctx, "--with-fingerprint", "--with-keygrip", "--list-secret-keys")
	if err != nil {
		return nil, err
	}
	secretKeys, err := ParseColons(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}

	secret := map[string]*Key{}
	for _, k := range secretKeys {
		secret[k.Fingerprint] = k
	}
	for _, k := range keys {
		sk, ok := secret[k.Fingerprint]
		if !ok {
			continue
		}
		k.Secret = sk.Secret
		k.SecretStatus = sk.SecretStatus
		for i := range k.SubKeys {
			for _, ssb := range sk.SubKeys {
				if ssb.Fingerprint == k.SubKeys[i].Fingerprint {
					k.SubKeys[i].SecretStatus = ssb.SecretStatus
				}
			}
		}
	}
	return keys, nil
}

// ExportPublic returns the ASCII armored public key.
func (g *GPG) ExportPublic(ctx context.Context, fingerprint string) ([]byte, error) {
	out, _, err := g.run(ctx, "--armor", "--export", fingerprint)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("gpg exported nothing for %s", fingerprint)
	}
	return out, nil
}

// Import imports keys from a file and returns gpg's summary.
func (g *GPG) Import(ctx context.Context, path string) (string, error) {
	_, stderr, err := g.run(ctx, "--import", path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(stderr)), nil
}

// Delete removes a key. When secret is true the secret key is removed as well, which is the
// only way gpg allows a key with a secret part to be deleted.
func (g *GPG) Delete(ctx context.Context, fingerprint string, secret bool) error {
	op := "--delete-keys"
	if secret {
		op = "--delete-secret-and-public-key"
	}
	_, _, err := g.run(ctx, "--yes", op, fingerprint)
	return err
}

// Group is the "PGP Keys" node of the type tree.
type Group struct {
	GPG *GPG
}

// Title implements backend.Group.
func (g *Group) Title() string { return "PGP Keys" }

// IconName implements backend.Group.
func (g *Group) IconName() string { return "application-certificate" }

// Categories implements backend.Group.
func (g *Group) Categories(_ context.Context) ([]backend.Category, error) {
	return []backend.Category{&Category{GPG: g.GPG}}, nil
}

// Category is the GnuPG keyring.
type Category struct {
	GPG *GPG
}

var _ backend.Importer = (*Category)(nil)

// Key implements backend.Category.
func (c *Category) Key() string { return "pgp:" + c.GPG.Home }

// Title implements backend.Category.
func (c *Category) Title() string { return "GnuPG keys" }

// IconName implements backend.Category.
func (c *Category) IconName() string { return "folder" }

// Columns implements backend.Category.
func (c *Category) Columns() []backend.Column {
	return []backend.Column{
		{Title: "Name", Expand: true},
		{Title: "Email"},
		{Title: "Key ID", Monospace: true},
		{Title: "Type"},
		{Title: "Validity"},
		{Title: "Expires"},
	}
}

// Items implements backend.Category.
func (c *Category) Items(ctx context.Context) ([]backend.Item, error) {
	keys, err := c.GPG.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]backend.Item, 0, len(keys))
	for _, k := range keys {
		items = append(items, &Item{GPG: c.GPG, PGPKey: k})
	}
	return items, nil
}

// ImportTitle implements backend.Importer.
func (c *Category) ImportTitle() string { return "Import PGP Keys" }

// Import implements backend.Importer.
func (c *Category) Import(ctx context.Context, path string) (string, error) {
	return c.GPG.Import(ctx, path)
}

// Item is a key in the middle list.
type Item struct {
	GPG    *GPG
	PGPKey *Key
}

var (
	_ backend.Copier   = (*Item)(nil)
	_ backend.Exporter = (*Item)(nil)
	_ backend.Deleter  = (*Item)(nil)
)

// Key implements backend.Item.
func (i *Item) Key() string { return i.PGPKey.Fingerprint }

// IconName implements backend.Item.
func (i *Item) IconName() string {
	if i.PGPKey.Secret {
		return "dialog-password"
	}
	return "avatar-default-symbolic"
}

func (i *Item) kind() string {
	if i.PGPKey.Secret {
		return "Personal"
	}
	return "Public"
}

// shortKeyID is the 16 hex digit long key ID, grouped for reading.
func shortKeyID(id string) string {
	if len(id) == 16 {
		return id[:8] + " " + id[8:]
	}
	return id
}

// groupFingerprint splits a fingerprint into blocks of four, as gpg prints it.
func groupFingerprint(fpr string) string {
	var b strings.Builder
	for i := 0; i < len(fpr); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
			if i == len(fpr)/2 {
				b.WriteByte(' ')
			}
		}
		end := min(i+4, len(fpr))
		b.WriteString(fpr[i:end])
	}
	return b.String()
}

// Cells implements backend.Item.
func (i *Item) Cells() []string {
	k := i.PGPKey
	uid := k.PrimaryUserID()
	return []string{
		uid.Name(),
		uid.Email(),
		shortKeyID(k.KeyID),
		i.kind(),
		ValidityName(k.Validity),
		backend.FormatDate(k.Expires, "Never"),
	}
}

// Detail implements backend.Item.
func (i *Item) Detail(_ context.Context) (*backend.Detail, error) {
	k := i.PGPKey
	uid := k.PrimaryUserID()

	strength := fmt.Sprintf("%d bits", k.Bits)
	if k.Bits == 0 {
		strength = "Unknown"
	}

	keyFields := []backend.Field{
		{Label: "Key ID", Value: shortKeyID(k.KeyID), Monospace: true},
		{Label: "Fingerprint", Value: groupFingerprint(k.Fingerprint), Monospace: true},
		{Label: "Type", Value: i.kind()},
		{Label: "Algorithm", Value: AlgorithmName(k.Algorithm, k.Curve)},
		{Label: "Strength", Value: strength},
		{Label: "Usage", Value: CapabilityNames(k.Capabilities)},
		{Label: "Created", Value: backend.FormatDate(k.Created, "Unknown")},
		{Label: "Expires", Value: backend.FormatDate(k.Expires, "Never")},
	}
	trustFields := []backend.Field{
		{Label: "Validity", Value: ValidityName(k.Validity)},
		{Label: "Owner trust", Value: ValidityName(k.OwnerTrust)},
	}

	uids := &backend.Table{Columns: []string{"Name", "Email", "Comment", "Validity"}}
	for _, u := range k.UserIDs {
		uids.Rows = append(uids.Rows, []string{u.Name(), u.Email(), u.Comment(), ValidityName(u.Validity)})
	}

	subkeys := &backend.Table{Columns: []string{"Key ID", "Algorithm", "Usage", "Created", "Expires", "Status", "Secret"}}
	for _, sk := range append([]SubKey{k.SubKey}, k.SubKeys...) {
		bits := ""
		if sk.Bits > 0 {
			bits = fmt.Sprintf(" %d", sk.Bits)
		}
		subkeys.Rows = append(subkeys.Rows, []string{
			shortKeyID(sk.KeyID),
			AlgorithmName(sk.Algorithm, sk.Curve) + bits,
			CapabilityNames(sk.Capabilities),
			backend.FormatDate(sk.Created, ""),
			backend.FormatDate(sk.Expires, "Never"),
			ValidityName(sk.Validity),
			secretStatusName(sk.SecretStatus),
		})
	}

	title := uid.Name()
	if title == "" {
		title = uid.Raw
	}
	return &backend.Detail{
		Title:    title,
		Subtitle: uid.Email(),
		IconName: i.IconName(),
		Sections: []backend.Section{
			{Title: "Key", Fields: keyFields},
			{Title: "Trust", Fields: trustFields},
			{Title: "Names and signatures", Table: uids},
			{Title: "Subkeys", Table: subkeys},
		},
	}, nil
}

func secretStatusName(status string) string {
	switch status {
	case "":
		return "No"
	case "+":
		return "Yes"
	case "#":
		return "Stub only"
	default:
		return "On card " + status
	}
}

// CopyLabel implements backend.Copier.
func (i *Item) CopyLabel() string { return "public key" }

// CopyText implements backend.Copier.
func (i *Item) CopyText(ctx context.Context) (string, error) {
	data, err := i.GPG.ExportPublic(ctx, i.PGPKey.Fingerprint)
	return string(data), err
}

// ExportName implements backend.Exporter.
func (i *Item) ExportName() string {
	return fmt.Sprintf("%s.asc", i.PGPKey.KeyID)
}

// Export implements backend.Exporter.
func (i *Item) Export(ctx context.Context) ([]byte, error) {
	return i.GPG.ExportPublic(ctx, i.PGPKey.Fingerprint)
}

// DeleteWarning implements backend.Deleter.
func (i *Item) DeleteWarning() string {
	k := i.PGPKey
	desc := fmt.Sprintf("%s\n%s", k.PrimaryUserID().Raw, groupFingerprint(k.Fingerprint))
	if k.Secret {
		return "This is a personal key. Its SECRET key will be permanently deleted along with the " +
			"public key. Anything encrypted to it can no longer be decrypted unless you have a backup.\n\n" + desc
	}
	return "The public key will be removed from your keyring.\n\n" + desc
}

// Delete implements backend.Deleter.
func (i *Item) Delete(ctx context.Context) error {
	if i.PGPKey.Fingerprint == "" {
		return errors.New("key has no fingerprint")
	}
	return i.GPG.Delete(ctx, i.PGPKey.Fingerprint, i.PGPKey.Secret)
}
