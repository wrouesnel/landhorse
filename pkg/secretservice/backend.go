package secretservice

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// schemaNames are readable names for the common xdg:schema values.
//
//nolint:gochecknoglobals
var schemaNames = map[string]string{
	"org.freedesktop.Secret.Generic":            "Password",
	"org.gnome.keyring.Note":                    "Stored note",
	"org.gnome.keyring.NetworkPassword":         "Network password",
	"org.gnome.keyring.ChainedKeyring":          "Keyring password",
	"org.gnome.keyring.EncryptionKey":           "Encryption key",
	"org.gnome.keyring.PkiStorage":              "Certificate storage",
	"org.gnome.keyring.PrivateKey":              "Private key password",
	"org.freedesktop.NetworkManager.Connection": "Network connection secret",
	"org.gnome.Epiphany.FormPassword":           "Web password",
	"org.gnome.OnlineAccounts":                  "Online account",
	"org.gnome.Evolution.Data.Source":           "Mail and calendar password",
}

// SchemaName returns a readable name for an item's schema.
func SchemaName(schema string) string {
	if name, ok := schemaNames[schema]; ok {
		return name
	}
	if schema == "" {
		return "Password"
	}
	return schema
}

// Group is the "Passwords" node of the type tree. It connects to the Secret Service on
// first use and keeps the connection.
type Group struct {
	mu     sync.Mutex
	client *Client
}

// Close releases the Secret Service connection, if one was made.
func (g *Group) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.client == nil {
		return nil
	}
	err := g.client.Close()
	g.client = nil
	return err
}

func (g *Group) getClient() (*Client, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.client != nil {
		return g.client, nil
	}
	client, err := Connect()
	if err != nil {
		return nil, err
	}
	g.client = client
	return client, nil
}

// Title implements backend.Group.
func (g *Group) Title() string { return "Passwords" }

// IconName implements backend.Group.
func (g *Group) IconName() string { return "dialog-password" }

// Categories implements backend.Group.
func (g *Group) Categories(_ context.Context) ([]backend.Category, error) {
	client, err := g.getClient()
	if err != nil {
		return nil, err
	}
	cols, err := client.Collections()
	if err != nil {
		return nil, err
	}
	// The default keyring first, then the rest by name. The transient "session" keyring
	// lives in memory only and goes last.
	sort.SliceStable(cols, func(i, j int) bool {
		rank := func(c *Collection) int {
			switch {
			case c.Default:
				return 0
			case c.Path == "/org/freedesktop/secrets/collection/session":
				return 2
			default:
				return 1
			}
		}
		if rank(cols[i]) != rank(cols[j]) {
			return rank(cols[i]) < rank(cols[j])
		}
		return strings.ToLower(cols[i].Label) < strings.ToLower(cols[j].Label)
	})

	result := make([]backend.Category, 0, len(cols))
	for _, col := range cols {
		result = append(result, &Keyring{client: client, collection: col})
	}
	return result, nil
}

// Keyring is a collection in the type tree.
type Keyring struct {
	client     *Client
	collection *Collection
}

var _ backend.Lockable = (*Keyring)(nil)

// Key implements backend.Category.
func (c *Keyring) Key() string { return "secret:" + string(c.collection.Path) }

// Title implements backend.Category.
func (c *Keyring) Title() string {
	title := c.collection.Label
	if title == "" {
		title = string(c.collection.Path[strings.LastIndex(string(c.collection.Path), "/")+1:])
	}
	if c.collection.Default {
		title += " (default)"
	}
	return title
}

// IconName implements backend.Category.
func (c *Keyring) IconName() string {
	if c.collection.Locked {
		return "changes-prevent"
	}
	return "changes-allow"
}

// Columns implements backend.Category.
func (c *Keyring) Columns() []backend.Column {
	return []backend.Column{
		{Title: "Name", Expand: true},
		{Title: "Type"},
		{Title: "Modified"},
	}
}

// Items implements backend.Category. A locked keyring still lists its items, but their
// secrets can't be read until it is unlocked.
func (c *Keyring) Items(_ context.Context) ([]backend.Item, error) {
	// Re-read the collection so the item list and lock state are current.
	col, err := c.client.Collection(c.collection.Path)
	if err != nil {
		return nil, err
	}
	col.Default = c.collection.Default
	c.collection = col

	items := make([]backend.Item, 0, len(col.Items))
	for _, p := range col.Items {
		item, err := c.client.Item(p)
		if err != nil {
			return nil, err
		}
		items = append(items, &PasswordItem{client: c.client, keyring: c, item: item})
	}
	return items, nil
}

// Locked implements backend.Lockable.
func (c *Keyring) Locked() bool { return c.collection.Locked }

// Lock implements backend.Lockable.
func (c *Keyring) Lock(ctx context.Context) error {
	return c.client.Lock(ctx, c.collection.Path)
}

// Unlock implements backend.Lockable.
func (c *Keyring) Unlock(ctx context.Context) error {
	return c.client.Unlock(ctx, c.collection.Path)
}

// PasswordItem is a stored password in the middle list.
type PasswordItem struct {
	client  *Client
	keyring *Keyring
	item    *Item
}

var (
	_ backend.Copier  = (*PasswordItem)(nil)
	_ backend.Deleter = (*PasswordItem)(nil)
)

// Key implements backend.Item.
func (i *PasswordItem) Key() string { return string(i.item.Path) }

// IconName implements backend.Item.
func (i *PasswordItem) IconName() string {
	if i.item.Schema() == "org.gnome.keyring.Note" {
		return "text-x-generic"
	}
	return "dialog-password"
}

func (i *PasswordItem) title() string {
	if i.item.Label != "" {
		return i.item.Label
	}
	return "Unnamed"
}

// Cells implements backend.Item.
func (i *PasswordItem) Cells() []string {
	return []string{i.title(), SchemaName(i.item.Schema()), backend.FormatTime(i.item.Modified, "")}
}

// Detail implements backend.Item.
func (i *PasswordItem) Detail(_ context.Context) (*backend.Detail, error) {
	it := i.item
	secretLabel := "Password"
	if it.Schema() == "org.gnome.keyring.Note" {
		secretLabel = "Note"
	}

	fields := []backend.Field{
		{Label: "Name", Value: i.title()},
		{Label: secretLabel, Reveal: i.reveal},
		{Label: "Type", Value: SchemaName(it.Schema())},
		{Label: "Keyring", Value: i.keyring.Title()},
		{Label: "Created", Value: backend.FormatTime(it.Created, "Unknown")},
		{Label: "Modified", Value: backend.FormatTime(it.Modified, "Unknown")},
	}

	keys := make([]string, 0, len(it.Attributes))
	for k := range it.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := &backend.Table{Columns: []string{"Attribute", "Value"}}
	for _, k := range keys {
		attrs.Rows = append(attrs.Rows, []string{k, it.Attributes[k]})
	}

	sections := []backend.Section{{Title: "Details", Fields: fields}}
	if len(attrs.Rows) > 0 {
		sections = append(sections, backend.Section{Title: "Attributes", Table: attrs})
	}

	return &backend.Detail{
		Title:    i.title(),
		Subtitle: SchemaName(it.Schema()),
		IconName: i.IconName(),
		Sections: sections,
	}, nil
}

// reveal reads the secret. If the keyring is locked it asks the Secret Service to unlock it,
// which shows the system password prompt, and then tries again.
func (i *PasswordItem) reveal(ctx context.Context) (string, error) {
	value, err := i.client.Secret(i.item.Path)
	if errors.Is(err, ErrLocked) {
		if err := i.client.Unlock(ctx, i.keyring.collection.Path); err != nil {
			return "", fmt.Errorf("unlocking %q: %w", i.keyring.collection.Label, err)
		}
		i.keyring.collection.Locked = false
		value, err = i.client.Secret(i.item.Path)
	}
	return string(value), err
}

// CopyLabel implements backend.Copier.
func (i *PasswordItem) CopyLabel() string { return "password" }

// CopyText implements backend.Copier.
func (i *PasswordItem) CopyText(ctx context.Context) (string, error) {
	return i.reveal(ctx)
}

// DeleteWarning implements backend.Deleter.
func (i *PasswordItem) DeleteWarning() string {
	return fmt.Sprintf("The password %q will be permanently deleted from the %q keyring.",
		i.title(), i.keyring.collection.Label)
}

// Delete implements backend.Deleter.
func (i *PasswordItem) Delete(ctx context.Context) error {
	return i.client.DeleteItem(ctx, i.item.Path)
}

// Path returns the item's D-Bus object path, for diagnostics.
func (i *PasswordItem) Path() dbus.ObjectPath { return i.item.Path }
