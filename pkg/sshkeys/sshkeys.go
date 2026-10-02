// Package sshkeys lists the OpenSSH key pairs kept in a directory, normally ~/.ssh.
package sshkeys

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/chigopher/pathlib"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// maxKeyFileSize bounds how much of a file is read while looking for keys. Real key files are
// a few kilobytes; anything larger is not a key.
const maxKeyFileSize = 64 * 1024

// skippedFiles are the well-known files in ~/.ssh that are never keys.
//
//nolint:gochecknoglobals
var skippedFiles = map[string]bool{
	"authorized_keys":  true,
	"authorized_keys2": true,
	"known_hosts":      true,
	"known_hosts.old":  true,
	"config":           true,
	"environment":      true,
	"rc":               true,
}

// Key is an OpenSSH key pair, or a lone public or private key.
type Key struct {
	// Name is the file name without the .pub suffix.
	Name string
	// PublicPath and PrivatePath are nil when that half of the pair is missing.
	PublicPath  *pathlib.Path
	PrivatePath *pathlib.Path

	// PublicKey is nil when no public key could be found or derived.
	PublicKey ssh.PublicKey
	Comment   string
	// Encrypted is true when the private key needs a passphrase.
	Encrypted bool
	// Authorized is true when the public key is listed in authorized_keys.
	Authorized bool
}

// Algorithm returns a readable name for the key type.
func (k *Key) Algorithm() string {
	if k.PublicKey == nil {
		return "Unknown"
	}
	switch k.PublicKey.Type() {
	case ssh.KeyAlgoRSA:
		return "RSA"
	case ssh.KeyAlgoED25519:
		return "Ed25519"
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return "ECDSA"
	case ssh.KeyAlgoSKED25519:
		return "Ed25519 (security key)"
	case ssh.KeyAlgoSKECDSA256:
		return "ECDSA (security key)"
	case ssh.KeyAlgoDSA: //nolint:staticcheck // still found in old ~/.ssh directories
		return "DSA"
	default:
		return k.PublicKey.Type()
	}
}

// Bits returns the key size in bits, or 0 if it is not known.
func (k *Key) Bits() int {
	if k.PublicKey == nil {
		return 0
	}
	switch k.PublicKey.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519:
		return 256
	}
	cpk, ok := k.PublicKey.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch pub := cpk.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	}
	return 0
}

// Fingerprint returns the SHA256 fingerprint as printed by ssh-keygen -l.
func (k *Key) Fingerprint() string {
	if k.PublicKey == nil {
		return ""
	}
	return ssh.FingerprintSHA256(k.PublicKey)
}

// AuthorizedKeyLine returns the public key in authorized_keys format, with its comment.
func (k *Key) AuthorizedKeyLine() string {
	if k.PublicKey == nil {
		return ""
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey)))
	if k.Comment != "" {
		line += " " + k.Comment
	}
	return line
}

// DisplayName is the comment when there is one, since that's usually user@host, and
// otherwise the file name.
func (k *Key) DisplayName() string {
	if k.Comment != "" {
		return k.Comment
	}
	return k.Name
}

// Scan lists the keys in dir. A missing directory yields no keys rather than an error.
func Scan(ctx context.Context, dir *pathlib.Path) ([]*Key, error) {
	l := logutil.FromCtx(ctx)

	exists, err := dir.Exists()
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}

	entries, err := dir.ReadDir()
	if err != nil {
		return nil, err
	}

	keys := map[string]*Key{}
	get := func(name string) *Key {
		if k, ok := keys[name]; ok {
			return k
		}
		k := &Key{Name: name}
		keys[name] = k
		return k
	}

	for _, entry := range entries {
		name := entry.Name()
		if skippedFiles[name] || strings.HasPrefix(name, ".") {
			continue
		}
		isFile, err := entry.IsFile()
		if err != nil || !isFile {
			continue
		}
		info, err := entry.Stat()
		if err != nil || info.Size() > maxKeyFileSize {
			continue
		}
		data, err := entry.ReadFile()
		if err != nil {
			l.Debug("Skipping unreadable file", zap.String("path", entry.String()), zap.Error(err))
			continue
		}

		if strings.HasSuffix(name, ".pub") {
			pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				l.Debug("Skipping unparseable public key", zap.String("path", entry.String()), zap.Error(err))
				continue
			}
			k := get(strings.TrimSuffix(name, ".pub"))
			k.PublicPath = entry
			k.PublicKey = pub
			k.Comment = comment
			continue
		}

		if !looksLikePrivateKey(data) {
			continue
		}
		k := get(name)
		k.PrivatePath = entry
		pub, encrypted := inspectPrivateKey(data)
		k.Encrypted = encrypted
		// Prefer the .pub file's key and comment, but fall back to the private key's.
		if k.PublicKey == nil {
			k.PublicKey = pub
		}
	}

	authorized := readAuthorizedKeys(dir.Join("authorized_keys"))

	result := make([]*Key, 0, len(keys))
	for _, k := range keys {
		if k.PublicKey != nil {
			k.Authorized = authorized[string(k.PublicKey.Marshal())]
		}
		result = append(result, k)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// tildePath abbreviates paths under the home directory to ~/..., as a shell would.
func tildePath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/" {
		return path
	}
	if rel, ok := strings.CutPrefix(path, home+string(os.PathSeparator)); ok {
		return "~" + string(os.PathSeparator) + rel
	}
	return path
}

func looksLikePrivateKey(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) &&
		bytes.Contains(data, []byte("PRIVATE KEY-----"))
}

// inspectPrivateKey returns the public half of a private key, if it can be derived without
// a passphrase, and whether the key is encrypted.
func inspectPrivateKey(data []byte) (ssh.PublicKey, bool) {
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer.PublicKey(), false
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		// OpenSSH format keys store the public key unencrypted; PEM keys don't, so this may
		// be nil.
		return missing.PublicKey, true
	}
	// Encrypted PKCS#8 isn't understood by the ssh package, but is plainly encrypted.
	return nil, bytes.Contains(data, []byte("BEGIN ENCRYPTED PRIVATE KEY"))
}

func readAuthorizedKeys(path *pathlib.Path) map[string]bool {
	result := map[string]bool{}
	data, err := path.ReadFile()
	if err != nil {
		return result
	}
	for len(data) > 0 {
		pub, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		result[string(pub.Marshal())] = true
		data = rest
	}
	return result
}

// Group is the "Secure Shell" node of the type tree.
type Group struct {
	Dir *pathlib.Path
}

// Title implements backend.Group.
func (g *Group) Title() string { return "Secure Shell" }

// IconName implements backend.Group.
func (g *Group) IconName() string { return "utilities-terminal" }

// Categories implements backend.Group.
func (g *Group) Categories(_ context.Context) ([]backend.Category, error) {
	return []backend.Category{&Category{Dir: g.Dir}}, nil
}

// Category lists the keys in one directory.
type Category struct {
	Dir *pathlib.Path
}

// Key implements backend.Category.
func (c *Category) Key() string { return "ssh:" + c.Dir.String() }

// Title implements backend.Category.
func (c *Category) Title() string { return "OpenSSH keys" }

// IconName implements backend.Category.
func (c *Category) IconName() string { return "folder" }

// Columns implements backend.Category.
func (c *Category) Columns() []backend.Column {
	return []backend.Column{
		{Title: "Name"},
		{Title: "Type"},
		{Title: "Comment", Expand: true},
		{Title: "Passphrase Protected"},
	}
}

// Items implements backend.Category.
func (c *Category) Items(ctx context.Context) ([]backend.Item, error) {
	keys, err := Scan(ctx, c.Dir)
	if err != nil {
		return nil, err
	}
	items := make([]backend.Item, 0, len(keys))
	for _, k := range keys {
		items = append(items, &Item{SSHKey: k})
	}
	return items, nil
}

// Item is a key in the middle list.
type Item struct {
	SSHKey *Key
}

// Ensure Item implements the optional behaviours the toolbar looks for.
var (
	_ backend.Copier         = (*Item)(nil)
	_ backend.CopyOnActivate = (*Item)(nil)
	_ backend.Exporter       = (*Item)(nil)
	_ backend.Deleter        = (*Item)(nil)
)

// Key implements backend.Item.
func (i *Item) Key() string { return i.SSHKey.Name }

// IconName implements backend.Item.
func (i *Item) IconName() string {
	if i.SSHKey.PrivatePath != nil {
		return "dialog-password"
	}
	return "network-server"
}

// Cells implements backend.Item.
func (i *Item) Cells() []string {
	return []string{i.SSHKey.Name, i.typeDescription(), i.SSHKey.Comment, i.passphraseProtected()}
}

// passphraseProtected describes whether the private key needs a passphrase. A lone public
// key has no private key to protect.
func (i *Item) passphraseProtected() string {
	switch {
	case i.SSHKey.PrivatePath == nil:
		return "No private key"
	case i.SSHKey.Encrypted:
		return "Yes"
	default:
		return "No"
	}
}

func (i *Item) typeDescription() string {
	if bits := i.SSHKey.Bits(); bits > 0 {
		return fmt.Sprintf("%s %d", i.SSHKey.Algorithm(), bits)
	}
	return i.SSHKey.Algorithm()
}

// Detail implements backend.Item.
func (i *Item) Detail(_ context.Context) (*backend.Detail, error) {
	k := i.SSHKey
	kind := "Public key"
	if k.PrivatePath != nil {
		kind = "Key pair"
		if k.PublicPath == nil {
			kind = "Private key"
		}
	}

	pathOf := func(p *pathlib.Path) string {
		if p == nil {
			return "Not present"
		}
		return tildePath(p.String())
	}
	yesNo := func(b bool) string {
		if b {
			return "Yes"
		}
		return "No"
	}

	keyFields := []backend.Field{
		{Label: "Comment", Value: k.Comment},
		{Label: "Algorithm", Value: k.Algorithm()},
	}
	if bits := k.Bits(); bits > 0 {
		keyFields = append(keyFields, backend.Field{Label: "Strength", Value: fmt.Sprintf("%d bits", bits)})
	}
	keyFields = append(keyFields,
		backend.Field{Label: "Fingerprint", Value: k.Fingerprint(), Monospace: true},
		backend.Field{Label: "Allows login here", Value: yesNo(k.Authorized)},
	)

	fileFields := []backend.Field{
		{Label: "Public key", Value: pathOf(k.PublicPath)},
		{Label: "Private key", Value: pathOf(k.PrivatePath)},
	}
	if k.PrivatePath != nil {
		fileFields = append(fileFields, backend.Field{Label: "Passphrase protected", Value: yesNo(k.Encrypted)})
	}

	sections := []backend.Section{
		{Title: "Key", Fields: keyFields},
		{Title: "Files", Fields: fileFields},
	}
	if line := k.AuthorizedKeyLine(); line != "" {
		sections = append(sections, backend.Section{
			Title:  "Public key",
			Fields: []backend.Field{{Label: "authorized_keys", Value: line, Monospace: true}},
		})
	}

	return &backend.Detail{
		Title:    k.DisplayName(),
		Subtitle: fmt.Sprintf("%s · %s", kind, i.typeDescription()),
		IconName: i.IconName(),
		Sections: sections,
	}, nil
}

// CopyLabel implements backend.Copier.
func (i *Item) CopyLabel() string { return "public key" }

// CopyOnActivate implements backend.CopyOnActivate: double-clicking a key copies its
// public key.
func (i *Item) CopyOnActivate() {}

// CopyText implements backend.Copier.
func (i *Item) CopyText(_ context.Context) (string, error) {
	line := i.SSHKey.AuthorizedKeyLine()
	if line == "" {
		return "", errors.New("the public key for this entry is not available")
	}
	return line + "\n", nil
}

// ExportName implements backend.Exporter.
func (i *Item) ExportName() string { return i.SSHKey.Name + ".pub" }

// Export implements backend.Exporter.
func (i *Item) Export(ctx context.Context) ([]byte, error) {
	text, err := i.CopyText(ctx)
	return []byte(text), err
}

// DeleteWarning implements backend.Deleter.
func (i *Item) DeleteWarning() string {
	files := []string{}
	for _, p := range []*pathlib.Path{i.SSHKey.PrivatePath, i.SSHKey.PublicPath} {
		if p != nil {
			files = append(files, p.String())
		}
	}
	msg := "These files will be permanently deleted:\n\n" + strings.Join(files, "\n")
	if i.SSHKey.PrivatePath != nil {
		msg += "\n\nDeleting the private key means you can no longer log in anywhere it is authorized."
	}
	return msg
}

// Delete implements backend.Deleter.
func (i *Item) Delete(_ context.Context) error {
	for _, p := range []*pathlib.Path{i.SSHKey.PrivatePath, i.SSHKey.PublicPath} {
		if p == nil {
			continue
		}
		if err := p.Remove(); err != nil {
			return fmt.Errorf("deleting %s: %w", p, err)
		}
	}
	return nil
}
