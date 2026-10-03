package securitykeys

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// FIDO runs fido2-token.
type FIDO struct {
	Binary string
}

func (f *FIDO) binary() string {
	if f.Binary != "" {
		return f.Binary
	}
	return "fido2-token"
}

// Device is a connected FIDO2 authenticator.
type Device struct {
	Path        string
	Vendor      string
	Product     string
	Description string
}

// Name is how the device is shown.
func (d Device) Name() string {
	if strings.TrimSpace(d.Description) != "" {
		return strings.TrimSpace(d.Description)
	}
	return "Security key"
}

//nolint:gochecknoglobals
var deviceLine = regexp.MustCompile(`^(\S+): vendor=(0x[0-9a-fA-F]+), product=(0x[0-9a-fA-F]+) \((.*)\)$`)

// Devices lists connected authenticators (fido2-token -L).
func (f *FIDO) Devices(ctx context.Context) ([]Device, error) {
	out, _, err := run(ctx, f.binary(), "", "-L")
	if err != nil {
		return nil, err
	}
	var devices []Device
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if m := deviceLine.FindStringSubmatch(strings.TrimSpace(scanner.Text())); m != nil {
			devices = append(devices, Device{Path: m[1], Vendor: m[2], Product: m[3], Description: m[4]})
		}
	}
	return devices, nil
}

// Info returns the authenticator's properties (fido2-token -I), as name and value pairs in
// the order printed. No PIN is needed.
func (f *FIDO) Info(ctx context.Context, d Device) ([][2]string, error) {
	out, _, err := run(ctx, f.binary(), "", "-I", d.Path)
	if err != nil {
		return nil, err
	}
	var info [][2]string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if name, value, ok := strings.Cut(scanner.Text(), ": "); ok {
			info = append(info, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
		}
	}
	return info, nil
}

// ErrNoPIN means the authenticator has no PIN, which managing passkeys requires.
var ErrNoPIN = errors.New("this security key has no PIN set; passkeys can only be listed once one is set")

// pinError turns libfido2's PIN failures into readable errors.
func pinError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "FIDO_ERR_PIN_INVALID"):
		return backend.ErrWrongPassphrase
	case strings.Contains(msg, "FIDO_ERR_PIN_BLOCKED"):
		return errors.New("the PIN is blocked after too many wrong attempts; the security key must be reset")
	case strings.Contains(msg, "FIDO_ERR_PIN_AUTH_BLOCKED"):
		return errors.New("too many wrong PINs; remove the security key, plug it in again and retry")
	case strings.Contains(msg, "FIDO_ERR_PIN_NOT_SET"):
		return ErrNoPIN
	case strings.Contains(msg, "FIDO_ERR_INVALID_COMMAND"), strings.Contains(msg, "FIDO_ERR_UNSUPPORTED_OPTION"):
		return errors.New("this security key can't list or manage its passkeys")
	}
	return err
}

// RP is a website (relying party) with passkeys on the authenticator.
type RP struct {
	ID string
}

// RPs lists the sites with passkeys (fido2-token -L -r). The PIN is given on stdin.
func (f *FIDO) RPs(ctx context.Context, d Device, pin string) ([]RP, error) {
	out, _, err := run(ctx, f.binary(), pin+"\n", "-L", "-r", d.Path)
	if err != nil {
		return nil, pinError(err)
	}
	var rps []RP
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		// "NN: <rp id hash> <rp id>"
		f := strings.Fields(scanner.Text())
		if len(f) >= 3 && strings.HasSuffix(f[0], ":") {
			rps = append(rps, RP{ID: strings.Join(f[2:], " ")})
		}
	}
	return rps, nil
}

// Credential is a passkey (discoverable credential) on the authenticator.
type Credential struct {
	RP          string
	ID          string
	DisplayName string
	UserID      string
	Type        string
	Protection  string
	Payment     bool
}

// parseCredential parses fido2-token -L -k output:
// "NN: <id> <display name> <user id> <type> <protection> <pay|nopay>", where the
// display name may contain spaces.
func parseCredential(rp, line string) (Credential, bool) {
	f := strings.Fields(line)
	if len(f) < 7 || !strings.HasSuffix(f[0], ":") {
		return Credential{}, false
	}
	n := len(f)
	display := strings.Join(f[2:n-4], " ")
	if display == "(null)" {
		display = ""
	}
	return Credential{
		RP: rp, ID: f[1], DisplayName: display, UserID: f[n-4], Type: f[n-3], Protection: f[n-2],
		Payment: f[n-1] == "pay",
	}, true
}

// Credentials lists the passkeys for one site (fido2-token -L -k).
func (f *FIDO) Credentials(ctx context.Context, d Device, rp, pin string) ([]Credential, error) {
	out, _, err := run(ctx, f.binary(), pin+"\n", "-L", "-k", rp, d.Path)
	if err != nil {
		return nil, pinError(err)
	}
	var creds []Credential
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if c, ok := parseCredential(rp, scanner.Text()); ok {
			creds = append(creds, c)
		}
	}
	return creds, nil
}

// Delete deletes a passkey (fido2-token -D -i).
func (f *FIDO) Delete(ctx context.Context, d Device, credentialID, pin string) error {
	_, _, err := run(ctx, f.binary(), pin+"\n", "-D", "-i", credentialID, d.Path)
	return pinError(err)
}

// Passkeys is the "Passkeys" category: a subcategory per connected authenticator.
type Passkeys struct {
	devices []*DeviceCategory
}

var (
	_ backend.Parent       = (*Passkeys)(nil)
	_ backend.EmptyMessage = (*Passkeys)(nil)
)

// Key implements backend.Category.
func (c *Passkeys) Key() string { return "passkeys" }

// Title implements backend.Category.
func (c *Passkeys) Title() string { return "Passkeys" }

// IconName implements backend.Category.
func (c *Passkeys) IconName() string { return "auth-fingerprint-symbolic" }

// Columns implements backend.Category.
func (c *Passkeys) Columns() []backend.Column { return passkeyColumns() }

// Children implements backend.Parent.
func (c *Passkeys) Children() []backend.Category {
	cats := make([]backend.Category, len(c.devices))
	for i, d := range c.devices {
		cats[i] = d
	}
	return cats
}

// Items implements backend.Category: every connected authenticator, and the passkeys of
// those unlocked.
func (c *Passkeys) Items(ctx context.Context) ([]backend.Item, error) {
	var items []backend.Item
	for _, d := range c.devices {
		di, err := d.Items(ctx)
		if err != nil {
			return nil, err
		}
		items = append(items, di...)
	}
	return items, nil
}

// EmptyMessage implements backend.EmptyMessage.
func (c *Passkeys) EmptyMessage() string {
	return "No FIDO2 security key is connected. Plug one in and press Refresh."
}

// DeviceCategory is one authenticator. Listing its passkeys needs its PIN, which is kept
// in memory while it's unlocked.
type DeviceCategory struct {
	FIDO   *FIDO
	Device Device

	mu  sync.Mutex
	pin string
}

var (
	_ backend.Lockable     = (*DeviceCategory)(nil)
	_ backend.PINUnlocker  = (*DeviceCategory)(nil)
	_ backend.EmptyMessage = (*DeviceCategory)(nil)
)

// Key implements backend.Category.
func (c *DeviceCategory) Key() string { return "passkeys:" + c.Device.Path }

// Title implements backend.Category.
func (c *DeviceCategory) Title() string { return c.Device.Name() }

// IconName implements backend.Category.
func (c *DeviceCategory) IconName() string {
	if c.Locked() {
		return "changes-prevent"
	}
	return "changes-allow"
}

// Columns implements backend.Category.
func (c *DeviceCategory) Columns() []backend.Column { return passkeyColumns() }

func passkeyColumns() []backend.Column {
	return []backend.Column{
		{Title: "Site", Expand: true},
		{Title: "User"},
		{Title: "Type"},
		{Title: "Security key"},
	}
}

func (c *DeviceCategory) currentPIN() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pin
}

// Items implements backend.Category: the authenticator itself, then its passkeys if it's
// unlocked.
func (c *DeviceCategory) Items(ctx context.Context) ([]backend.Item, error) {
	items := []backend.Item{&DeviceItem{FIDO: c.FIDO, Device: c.Device}}
	pin := c.currentPIN()
	if pin == "" {
		return items, nil
	}
	rps, err := c.FIDO.RPs(ctx, c.Device, pin)
	if err != nil {
		return nil, err
	}
	for _, rp := range rps {
		creds, err := c.FIDO.Credentials(ctx, c.Device, rp.ID, pin)
		if err != nil {
			return nil, err
		}
		for _, cred := range creds {
			items = append(items, &PasskeyItem{category: c, Credential: cred})
		}
	}
	return items, nil
}

// EmptyMessage implements backend.EmptyMessage.
func (c *DeviceCategory) EmptyMessage() string {
	return "Unlock this security key with its PIN to list its passkeys."
}

// Locked implements backend.Lockable.
func (c *DeviceCategory) Locked() bool { return c.currentPIN() == "" }

// Lock implements backend.Lockable: forgets the PIN.
func (c *DeviceCategory) Lock(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pin = ""
	return nil
}

// Unlock implements backend.Lockable. A PIN is needed; see UnlockWithPIN.
func (c *DeviceCategory) Unlock(_ context.Context) error {
	return errors.New("this security key is unlocked with its PIN")
}

// PINPrompt implements backend.PINUnlocker.
func (c *DeviceCategory) PINPrompt() string {
	return fmt.Sprintf("Enter the PIN of %s to list and manage its passkeys. A security key allows only "+
		"a few wrong PINs before it blocks, so check it carefully.", c.Device.Name())
}

// UnlockWithPIN implements backend.PINUnlocker: the PIN is checked by listing the sites
// with passkeys, and kept only if it works.
func (c *DeviceCategory) UnlockWithPIN(ctx context.Context, pin string) error {
	if _, err := c.FIDO.RPs(ctx, c.Device, pin); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pin = pin
	return nil
}

// DeviceItem is the authenticator itself, showing its properties.
type DeviceItem struct {
	FIDO   *FIDO
	Device Device
}

// Key implements backend.Item.
func (i *DeviceItem) Key() string { return "device:" + i.Device.Path }

// IconName implements backend.Item.
func (i *DeviceItem) IconName() string { return "auth-fingerprint-symbolic" }

// Cells implements backend.Item.
func (i *DeviceItem) Cells() []string {
	return []string{"(this security key)", "", "", i.Device.Name()}
}

// Detail implements backend.Item.
func (i *DeviceItem) Detail(ctx context.Context) (*backend.Detail, error) {
	info, err := i.FIDO.Info(ctx, i.Device)
	if err != nil {
		return nil, err
	}
	fields := []backend.Field{
		{Label: "Device", Value: i.Device.Path, Monospace: true},
		{Label: "Vendor ID", Value: i.Device.Vendor, Monospace: true},
		{Label: "Product ID", Value: i.Device.Product, Monospace: true},
	}
	table := &backend.Table{Columns: []string{"Property", "Value"}}
	for _, kv := range info {
		table.Rows = append(table.Rows, []string{kv[0], kv[1]})
		if kv[0] == "options" {
			pinSet := "No"
			if strings.Contains(", "+kv[1]+",", ", clientPin,") {
				pinSet = "Yes"
			}
			fields = append(fields, backend.Field{Label: "PIN set", Value: pinSet})
		}
		if kv[0] == "pin retries" {
			fields = append(fields, backend.Field{Label: "PIN attempts left", Value: kv[1]})
		}
		if kv[0] == "remaining rk(s)" {
			fields = append(fields, backend.Field{Label: "Space for passkeys", Value: kv[1]})
		}
	}
	return &backend.Detail{
		Title:    i.Device.Name(),
		Subtitle: "FIDO2 security key",
		IconName: i.IconName(),
		Sections: []backend.Section{
			{Title: "Security key", Fields: fields},
			{Title: "Properties", Table: table},
		},
	}, nil
}

// PasskeyItem is a passkey on an authenticator.
type PasskeyItem struct {
	category   *DeviceCategory
	Credential Credential
}

var _ backend.Deleter = (*PasskeyItem)(nil)

// Key implements backend.Item.
func (i *PasskeyItem) Key() string {
	return "passkey:" + i.category.Device.Path + ":" + i.Credential.ID
}

// IconName implements backend.Item.
func (i *PasskeyItem) IconName() string { return "dialog-password" }

// Cells implements backend.Item.
func (i *PasskeyItem) Cells() []string {
	c := i.Credential
	return []string{c.RP, c.DisplayName, c.Type, i.category.Device.Name()}
}

// Detail implements backend.Item.
func (i *PasskeyItem) Detail(_ context.Context) (*backend.Detail, error) {
	c := i.Credential
	protection := map[string]string{
		"uvopt": "User verification optional", "uvopt+id": "User verification optional unless listed",
		"uvreq": "User verification required",
	}[c.Protection]
	if protection == "" {
		protection = c.Protection
	}
	payment := "No"
	if c.Payment {
		payment = "Yes"
	}
	return &backend.Detail{
		Title:    c.RP,
		Subtitle: "Passkey on " + i.category.Device.Name(),
		IconName: i.IconName(),
		Sections: []backend.Section{
			{Title: "Passkey", Fields: []backend.Field{
				{Label: "Site", Value: c.RP},
				{Label: "User", Value: c.DisplayName},
				{Label: "User ID", Value: c.UserID, Monospace: true},
				{Label: "Algorithm", Value: c.Type},
				{Label: "Protection", Value: protection},
				{Label: "Payments", Value: payment},
				{Label: "Credential ID", Value: c.ID, Monospace: true},
				{Label: "Security key", Value: i.category.Device.Name()},
			}},
		},
	}, nil
}

// DeleteWarning implements backend.Deleter.
func (i *PasskeyItem) DeleteWarning() string {
	c := i.Credential
	who := c.DisplayName
	if who == "" {
		who = "this account"
	}
	return fmt.Sprintf("The passkey for %s on %s will be deleted from %s. You won't be able to sign in "+
		"to %s with this security key any more; make sure you have another way to sign in.",
		who, c.RP, i.category.Device.Name(), c.RP)
}

// Delete implements backend.Deleter.
func (i *PasskeyItem) Delete(ctx context.Context) error {
	pin := i.category.currentPIN()
	if pin == "" {
		return errors.New("unlock the security key with its PIN first")
	}
	return i.category.FIDO.Delete(ctx, i.category.Device, i.Credential.ID, pin)
}
