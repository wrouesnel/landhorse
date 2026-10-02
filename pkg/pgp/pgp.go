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
	"slices"
	"sort"
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
	// Keyservers are offered when publishing keys.
	Keyservers []Keyserver
}

// invocation adjusts how gpg is run.
type invocation struct {
	// stdin is fed to gpg's standard input.
	stdin []byte
	// interactive drops --batch, for commands gpg refuses to run in batch mode (such as
	// --gen-revoke), which are then driven through --command-fd 0.
	interactive bool
	// home overrides the GnuPG home, for scratch keyrings.
	home string
}

// run executes gpg and returns its standard output and standard error.
func (g *GPG) run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return g.runWith(ctx, invocation{}, args...)
}

// runWith executes gpg. On failure the error includes standard error, which is where gpg
// explains itself.
func (g *GPG) runWith(ctx context.Context, inv invocation, args ...string) ([]byte, []byte, error) {
	full := []string{"--no-tty"}
	if !inv.interactive {
		full = append(full, "--batch", "--with-colons", "--fixed-list-mode")
	}
	home := g.Home
	if inv.home != "" {
		home = inv.home
	}
	if home != "" {
		full = append(full, "--homedir", home)
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
	if inv.stdin != nil {
		cmd.Stdin = bytes.NewReader(inv.stdin)
	}
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

// Categories implements backend.Group. It lists the keyring once to build the tree:
//
//	GnuPG keys            every key
//	  Private keys        keys with a secret part here, listed first
//	    alice@example.com one per email address
//	  Public keys         keys with only the public part
//	    bob@example.org
func (g *Group) Categories(ctx context.Context) ([]backend.Category, error) {
	keys, err := g.GPG.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	base := "pgp:" + g.GPG.Home
	private := g.byEmail(&Category{
		GPG: g.GPG, key: base + ":private", title: "Private keys", icon: "dialog-password",
		match: (*Key).HasSecret,
	}, keys)
	public := g.byEmail(&Category{
		GPG: g.GPG, key: base + ":public", title: "Public keys", icon: "avatar-default-symbolic",
		match: func(k *Key) bool { return !k.HasSecret() },
	}, keys)

	all := &Category{
		GPG: g.GPG, key: base, title: "GnuPG keys", icon: "folder",
		children: []backend.Category{private, public},
	}
	return []backend.Category{all}, nil
}

// byEmail adds a child to parent for each email address among the keys it matches, sorted
// by address, plus one for keys without any address.
func (g *Group) byEmail(parent *Category, keys []*Key) *Category {
	emails := map[string]bool{}
	noEmail := false
	for _, k := range keys {
		if !parent.match(k) {
			continue
		}
		addrs := k.Emails()
		if len(addrs) == 0 {
			noEmail = true
		}
		for _, e := range addrs {
			emails[e] = true
		}
	}

	sorted := make([]string, 0, len(emails))
	for e := range emails {
		sorted = append(sorted, e)
	}
	sort.Strings(sorted)

	parentMatch := parent.match
	for _, email := range sorted {
		parent.children = append(parent.children, &Category{
			GPG: g.GPG, key: parent.key + ":email:" + email, title: email, icon: "mail-unread-symbolic",
			match: func(k *Key) bool { return parentMatch(k) && slices.Contains(k.Emails(), email) },
		})
	}
	if noEmail {
		parent.children = append(parent.children, &Category{
			GPG: g.GPG, key: parent.key + ":no-email", title: "No email address", icon: "mail-unread-symbolic",
			match: func(k *Key) bool { return parentMatch(k) && len(k.Emails()) == 0 },
		})
	}
	return parent
}

// Category is a set of keys from the keyring: all of them, private or public ones, or those
// for one email address.
type Category struct {
	GPG      *GPG
	key      string
	title    string
	icon     string
	match    func(*Key) bool // nil matches every key
	children []backend.Category
}

var (
	_ backend.Importer = (*Category)(nil)
	_ backend.Parent   = (*Category)(nil)
)

// Key implements backend.Category.
func (c *Category) Key() string { return c.key }

// Title implements backend.Category.
func (c *Category) Title() string { return c.title }

// IconName implements backend.Category.
func (c *Category) IconName() string { return c.icon }

// Children implements backend.Parent.
func (c *Category) Children() []backend.Category { return c.children }

// Columns implements backend.Category.
func (c *Category) Columns() []backend.Column {
	return []backend.Column{
		{Title: "Name", Expand: true},
		{Title: "Email"},
		{Title: "Comment"},
		{Title: "Key ID", Monospace: true},
		{Title: "Type"},
		{Title: "Validity", SortRank: ValidityNameRank},
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
		if c.match == nil || c.match(k) {
			items = append(items, &Item{GPG: c.GPG, PGPKey: k})
		}
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
	_ backend.Copier    = (*Item)(nil)
	_ backend.Exporter  = (*Item)(nil)
	_ backend.Deleter   = (*Item)(nil)
	_ backend.Publisher = (*Item)(nil)
)

// Key implements backend.Item.
func (i *Item) Key() string { return i.PGPKey.Fingerprint }

// IconName implements backend.Item.
func (i *Item) IconName() string {
	if i.PGPKey.HasSecret() {
		return "dialog-password"
	}
	return "avatar-default-symbolic"
}

func (i *Item) kind() string {
	if i.PGPKey.HasSecret() {
		return "Private"
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
		k.LatestComment(),
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
	if k.HasSecret() {
		return "This is a private key. Its SECRET key will be permanently deleted along with the " +
			"public key. Anything encrypted to it can no longer be decrypted unless you have a backup.\n\n" + desc
	}
	return "The public key will be removed from your keyring.\n\n" + desc
}

// Delete implements backend.Deleter.
func (i *Item) Delete(ctx context.Context) error {
	if i.PGPKey.Fingerprint == "" {
		return errors.New("key has no fingerprint")
	}
	return i.GPG.Delete(ctx, i.PGPKey.Fingerprint, i.PGPKey.HasSecret())
}

// PublishTargets implements backend.Publisher.
func (i *Item) PublishTargets() []backend.Choice {
	targets := make([]backend.Choice, 0, len(i.GPG.Keyservers))
	for _, ks := range i.GPG.Keyservers {
		targets = append(targets, backend.Choice{ID: ks.URI, Label: ks.Label()})
	}
	return targets
}

// PublishWarning implements backend.Publisher.
func (i *Item) PublishWarning() string {
	k := i.PGPKey
	names := make([]string, 0, len(k.UserIDs))
	// Revoked user IDs are uploaded too, marked as revoked, so they're listed.
	for _, u := range k.UserIDs {
		if u.Validity == "r" {
			names = append(names, u.Raw+" (revoked)")
		} else {
			names = append(names, u.Raw)
		}
	}
	return "The public key " + shortKeyID(k.KeyID) + " will be uploaded. Keyservers are public, " +
		"and most never delete keys: anyone will be able to find it, along with these names " +
		"and addresses:\n\n" + strings.Join(names, "\n") +
		"\n\nOnly the public key is sent; the secret key never leaves this computer."
}

// Publish implements backend.Publisher.
func (i *Item) Publish(ctx context.Context, target string) (string, error) {
	return i.GPG.SendKey(ctx, target, i.PGPKey.Fingerprint)
}

var _ backend.Linkable = (*Item)(nil)

// LinkKeys implements backend.Linkable: the fingerprints and keygrips of the primary key and
// its subkeys, which saved passphrases refer to.
func (i *Item) LinkKeys() []string {
	k := i.PGPKey
	var keys []string
	for _, sk := range append([]SubKey{k.SubKey}, k.SubKeys...) {
		if sk.Fingerprint != "" {
			keys = append(keys, "gpg-fpr:"+strings.ToUpper(sk.Fingerprint))
		}
		if sk.Keygrip != "" {
			keys = append(keys, "gpg-keygrip:"+strings.ToUpper(sk.Keygrip))
		}
	}
	return keys
}

// LinkDescription implements backend.Linkable.
func (i *Item) LinkDescription() string {
	return i.kind() + " PGP key " + shortKeyID(i.PGPKey.KeyID)
}
