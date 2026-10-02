// Package secretservice is a client for the freedesktop.org Secret Service D-Bus API, which
// gnome-keyring and KeePassXC implement. It lists keyrings (collections) and the passwords
// (items) stored in them.
//
// See https://specifications.freedesktop.org/secret-service/latest/ for the API.
package secretservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	busName       = "org.freedesktop.secrets"
	servicePath   = dbus.ObjectPath("/org/freedesktop/secrets")
	ifService     = "org.freedesktop.Secret.Service"
	ifCollection  = "org.freedesktop.Secret.Collection"
	ifItem        = "org.freedesktop.Secret.Item"
	ifPrompt      = "org.freedesktop.Secret.Prompt"
	ifProperties  = "org.freedesktop.DBus.Properties"
	noPrompt      = dbus.ObjectPath("/")
	defaultAlias  = "default"
	plainAlgoName = "plain"
)

// ErrLocked is returned when a secret is requested from a locked keyring.
var ErrLocked = errors.New("the keyring is locked")

// ErrDismissed is returned when the user cancels an unlock or delete prompt.
var ErrDismissed = errors.New("the prompt was dismissed")

// Client is a connection to the Secret Service.
type Client struct {
	conn    *dbus.Conn
	session dbus.ObjectPath
}

// Connect opens a connection to the Secret Service on the session bus.
//
// It negotiates a "plain" session: secrets travel unencrypted over the session bus, which is
// only reachable by the user's own processes. That matches what libsecret falls back to.
func Connect() (*Client, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connecting to the session bus: %w", err)
	}
	c := &Client{conn: conn}

	var output dbus.Variant
	if err := c.service().Call(ifService+".OpenSession", 0, plainAlgoName, dbus.MakeVariant("")).
		Store(&output, &c.session); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("opening a Secret Service session: %w", err)
	}
	return c, nil
}

// Close ends the session and closes the connection.
func (c *Client) Close() error {
	_ = c.conn.Object(busName, c.session).Call("org.freedesktop.Secret.Session.Close", 0).Err
	return c.conn.Close()
}

func (c *Client) service() dbus.BusObject {
	return c.conn.Object(busName, servicePath)
}

func (c *Client) properties(path dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	props := map[string]dbus.Variant{}
	err := c.conn.Object(busName, path).Call(ifProperties+".GetAll", 0, iface).Store(&props)
	return props, err
}

// Collection is a keyring.
type Collection struct {
	Path     dbus.ObjectPath
	Label    string
	Locked   bool
	Created  time.Time
	Modified time.Time
	Items    []dbus.ObjectPath
	// Default is true for the collection the "default" alias points to.
	Default bool
}

// Item is a stored secret, without the secret itself.
type Item struct {
	Path       dbus.ObjectPath
	Label      string
	Locked     bool
	Created    time.Time
	Modified   time.Time
	Attributes map[string]string
}

// Schema returns the xdg:schema attribute, which says what kind of secret this is.
func (i *Item) Schema() string {
	return i.Attributes["xdg:schema"]
}

// Collections lists all keyrings.
func (c *Client) Collections() ([]*Collection, error) {
	v, err := c.service().GetProperty(ifService + ".Collections")
	if err != nil {
		return nil, err
	}
	paths, ok := v.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, fmt.Errorf("unexpected Collections type %s", v.Signature())
	}

	var defaultPath dbus.ObjectPath
	_ = c.service().Call(ifService+".ReadAlias", 0, defaultAlias).Store(&defaultPath)

	result := make([]*Collection, 0, len(paths))
	for _, p := range paths {
		col, err := c.Collection(p)
		if err != nil {
			return nil, err
		}
		col.Default = p == defaultPath
		result = append(result, col)
	}
	return result, nil
}

// Collection reads one keyring's properties.
func (c *Client) Collection(path dbus.ObjectPath) (*Collection, error) {
	props, err := c.properties(path, ifCollection)
	if err != nil {
		return nil, fmt.Errorf("reading keyring %s: %w", path, err)
	}
	col := &Collection{Path: path}
	col.Label, _ = props["Label"].Value().(string)
	col.Locked, _ = props["Locked"].Value().(bool)
	col.Items, _ = props["Items"].Value().([]dbus.ObjectPath)
	col.Created = unixTime(props["Created"])
	col.Modified = unixTime(props["Modified"])
	return col, nil
}

// Item reads one item's properties.
func (c *Client) Item(path dbus.ObjectPath) (*Item, error) {
	props, err := c.properties(path, ifItem)
	if err != nil {
		return nil, fmt.Errorf("reading item %s: %w", path, err)
	}
	item := &Item{Path: path}
	item.Label, _ = props["Label"].Value().(string)
	item.Locked, _ = props["Locked"].Value().(bool)
	item.Attributes, _ = props["Attributes"].Value().(map[string]string)
	item.Created = unixTime(props["Created"])
	item.Modified = unixTime(props["Modified"])
	return item, nil
}

func unixTime(v dbus.Variant) time.Time {
	secs, ok := v.Value().(uint64)
	if !ok || secs == 0 {
		return time.Time{}
	}
	return time.Unix(int64(secs), 0) //nolint:gosec // timestamps fit easily
}

// secret mirrors the Secret Service (oayays) Secret struct.
type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// Secret fetches an item's secret. The keyring must be unlocked.
func (c *Client) Secret(path dbus.ObjectPath) ([]byte, error) {
	var s secret
	err := c.conn.Object(busName, path).Call(ifItem+".GetSecret", 0, c.session).Store(&s)
	if err != nil {
		var dbusErr dbus.Error
		if errors.As(err, &dbusErr) && dbusErr.Name == "org.freedesktop.Secret.Error.IsLocked" {
			return nil, ErrLocked
		}
		return nil, err
	}
	return s.Value, nil
}

// Unlock unlocks objects (keyrings or items), showing the system's password prompt if needed.
// It blocks until the prompt is answered or ctx is done.
func (c *Client) Unlock(ctx context.Context, objects ...dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := c.service().Call(ifService+".Unlock", 0, objects).Store(&unlocked, &prompt); err != nil {
		return err
	}
	return c.runPrompt(ctx, prompt)
}

// Lock locks objects.
func (c *Client) Lock(ctx context.Context, objects ...dbus.ObjectPath) error {
	var locked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := c.service().Call(ifService+".Lock", 0, objects).Store(&locked, &prompt); err != nil {
		return err
	}
	return c.runPrompt(ctx, prompt)
}

// DeleteItem deletes a stored secret.
func (c *Client) DeleteItem(ctx context.Context, path dbus.ObjectPath) error {
	var prompt dbus.ObjectPath
	if err := c.conn.Object(busName, path).Call(ifItem+".Delete", 0).Store(&prompt); err != nil {
		return err
	}
	return c.runPrompt(ctx, prompt)
}

// runPrompt shows a prompt returned by the service and waits for its Completed signal.
func (c *Client) runPrompt(ctx context.Context, prompt dbus.ObjectPath) error {
	if prompt == noPrompt || prompt == "" {
		return nil
	}

	matches := []dbus.MatchOption{
		dbus.WithMatchObjectPath(prompt),
		dbus.WithMatchInterface(ifPrompt),
		dbus.WithMatchMember("Completed"),
	}
	if err := c.conn.AddMatchSignal(matches...); err != nil {
		return err
	}
	defer func() { _ = c.conn.RemoveMatchSignal(matches...) }()

	signals := make(chan *dbus.Signal, 4)
	c.conn.Signal(signals)
	defer c.conn.RemoveSignal(signals)

	// The window ID lets the prompter attach to our window; an empty one is allowed.
	if err := c.conn.Object(busName, prompt).Call(ifPrompt+".Prompt", 0, "").Err; err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			_ = c.conn.Object(busName, prompt).Call(ifPrompt+".Dismiss", 0).Err
			return ctx.Err()
		case sig := <-signals:
			if sig == nil || sig.Path != prompt || sig.Name != ifPrompt+".Completed" {
				continue
			}
			if len(sig.Body) > 0 {
				if dismissed, ok := sig.Body[0].(bool); ok && dismissed {
					return ErrDismissed
				}
			}
			return nil
		}
	}
}
