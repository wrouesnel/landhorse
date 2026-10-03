package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// AgentCategory lists the keys loaded in an SSH agent, such as ssh-agent or gnome-keyring's.
type AgentCategory struct {
	// Socket is the agent's socket path, normally $SSH_AUTH_SOCK.
	Socket string
}

// Key implements backend.Category.
func (c *AgentCategory) Key() string { return "ssh-agent:" + c.Socket }

// Title implements backend.Category.
func (c *AgentCategory) Title() string { return "SSH agent" }

// IconName implements backend.Category.
func (c *AgentCategory) IconName() string { return "system-run-symbolic" }

// Columns implements backend.Category.
func (c *AgentCategory) Columns() []backend.Column {
	return []backend.Column{
		{Title: "Comment", Expand: true},
		{Title: "Type"},
		{Title: "Fingerprint", Monospace: true, Truncate: true},
	}
}

// withAgent connects to the agent for one operation.
func (c *AgentCategory) withAgent(ctx context.Context, fn func(agent.ExtendedAgent) error) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return fmt.Errorf("connecting to the SSH agent at %s: %w", c.Socket, err)
	}
	defer conn.Close()
	return fn(agent.NewClient(conn))
}

// Items implements backend.Category.
func (c *AgentCategory) Items(ctx context.Context) ([]backend.Item, error) {
	var keys []*agent.Key
	err := c.withAgent(ctx, func(a agent.ExtendedAgent) error {
		var err error
		keys, err = a.List()
		return err
	})
	if err != nil {
		return nil, err
	}
	items := make([]backend.Item, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		items = append(items, &AgentItem{category: c, key: &Key{Name: k.Comment, PublicKey: pub, Comment: k.Comment}})
	}
	return items, nil
}

// AgentItem is a key loaded in the agent.
type AgentItem struct {
	category *AgentCategory
	key      *Key
}

var (
	_ backend.CopyOnActivate = (*AgentItem)(nil)
	_ backend.Exporter       = (*AgentItem)(nil)
	_ backend.Deleter        = (*AgentItem)(nil)
	_ backend.Linkable       = (*AgentItem)(nil)
)

// Key implements backend.Item.
func (i *AgentItem) Key() string { return i.key.Fingerprint() }

// IconName implements backend.Item.
func (i *AgentItem) IconName() string { return "dialog-password" }

func (i *AgentItem) typeDescription() string {
	if bits := i.key.Bits(); bits > 0 {
		return fmt.Sprintf("%s %d", i.key.Algorithm(), bits)
	}
	return i.key.Algorithm()
}

func (i *AgentItem) title() string {
	if i.key.Comment != "" {
		return i.key.Comment
	}
	return i.key.Fingerprint()
}

// Cells implements backend.Item.
func (i *AgentItem) Cells() []string {
	return []string{i.title(), i.typeDescription(), i.key.Fingerprint()}
}

// Detail implements backend.Item.
func (i *AgentItem) Detail(_ context.Context) (*backend.Detail, error) {
	k := i.key
	fields := []backend.Field{
		{Label: "Comment", Value: k.Comment},
		{Label: "Algorithm", Value: k.Algorithm()},
	}
	if bits := k.Bits(); bits > 0 {
		fields = append(fields, backend.Field{Label: "Strength", Value: fmt.Sprintf("%d bits", bits)})
	}
	fields = append(fields,
		backend.Field{Label: "Fingerprint", Value: k.Fingerprint(), Monospace: true},
		backend.Field{Label: "Agent", Value: tildePath(i.category.Socket)},
	)
	if cert, ok := k.PublicKey.(*ssh.Certificate); ok {
		fields = append(fields, backend.Field{Label: "Certificate", Value: fmt.Sprintf("Key ID %q, principals %s",
			cert.KeyId, strings.Join(cert.ValidPrincipals, ", "))})
	}
	return &backend.Detail{
		Title:    i.title(),
		Subtitle: "Loaded in the SSH agent · " + i.typeDescription(),
		IconName: i.IconName(),
		Sections: []backend.Section{
			{Title: "Key", Fields: fields},
			{Title: "Public key", Fields: []backend.Field{
				{Label: "authorized_keys", Value: k.AuthorizedKeyLine(), Monospace: true},
			}},
		},
	}, nil
}

// CopyLabel implements backend.Copier.
func (i *AgentItem) CopyLabel() string { return "public key" }

// CopyText implements backend.Copier.
func (i *AgentItem) CopyText(_ context.Context) (string, error) {
	return i.key.AuthorizedKeyLine() + "\n", nil
}

// CopyOnActivate implements backend.CopyOnActivate.
func (i *AgentItem) CopyOnActivate() {}

// ExportName implements backend.Exporter.
func (i *AgentItem) ExportName() string {
	name := strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' || r == '@' {
			return '_'
		}
		return r
	}, i.title())
	return name + ".pub"
}

// Export implements backend.Exporter.
func (i *AgentItem) Export(ctx context.Context) ([]byte, error) {
	text, err := i.CopyText(ctx)
	return []byte(text), err
}

// DeleteWarning implements backend.Deleter.
func (i *AgentItem) DeleteWarning() string {
	return fmt.Sprintf("%q will be removed from the SSH agent, so it can no longer be used "+
		"without being added again. No key files are deleted.", i.title())
}

// Delete implements backend.Deleter by removing the key from the agent.
func (i *AgentItem) Delete(ctx context.Context) error {
	return i.category.withAgent(ctx, func(a agent.ExtendedAgent) error {
		if err := a.Remove(i.key.PublicKey); err != nil {
			return errors.New("the agent refused to remove the key (it may have been added with a lock or by another agent)")
		}
		return nil
	})
}

// LinkKeys implements backend.Linkable: the fingerprint, which the key's files share.
func (i *AgentItem) LinkKeys() []string {
	return []string{"ssh-fingerprint:" + i.key.Fingerprint()}
}

// LinkDescription implements backend.Linkable.
func (i *AgentItem) LinkDescription() string {
	return "Loaded in the SSH agent"
}
