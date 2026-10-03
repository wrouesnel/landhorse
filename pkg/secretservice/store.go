package secretservice

import (
	"context"
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

var _ backend.SecretStore = (*Group)(nil)

// StoreName implements backend.SecretStore.
func (g *Group) StoreName() string { return "login keyring" }

// loginCollection is the keyring that's unlocked when the user logs in: the "login" alias,
// or the default keyring where that alias isn't supported.
func (g *Group) loginCollection(client *Client) (dbus.ObjectPath, error) {
	for _, alias := range []string{"login", defaultAlias} {
		path, err := client.ReadAlias(alias)
		if err == nil && path != "" {
			return path, nil
		}
	}
	return "", errors.New("there is no login or default keyring")
}

// StoreSecret implements backend.SecretStore, saving to the login keyring and unlocking it
// first if needed.
func (g *Group) StoreSecret(ctx context.Context, label string, attrs map[string]string, value string) error {
	client, err := g.getClient()
	if err != nil {
		return err
	}
	path, err := g.loginCollection(client)
	if err != nil {
		return err
	}
	col, err := client.Collection(path)
	if err != nil {
		return err
	}
	if col.Locked {
		if err := client.Unlock(ctx, path); err != nil {
			return fmt.Errorf("unlocking the %s keyring: %w", col.Label, err)
		}
	}
	return client.CreateItem(ctx, path, label, attrs, []byte(value))
}

// CountSecrets implements backend.SecretStore.
func (g *Group) CountSecrets(_ context.Context, attrs map[string]string) (int, error) {
	client, err := g.getClient()
	if err != nil {
		return 0, err
	}
	items, err := client.SearchItems(attrs)
	return len(items), err
}

// DeleteSecrets implements backend.SecretStore.
func (g *Group) DeleteSecrets(ctx context.Context, attrs map[string]string) (int, error) {
	client, err := g.getClient()
	if err != nil {
		return 0, err
	}
	items, err := client.SearchItems(attrs)
	if err != nil {
		return 0, err
	}
	for i, item := range items {
		if err := client.DeleteItem(ctx, item); err != nil {
			return i, err
		}
	}
	return len(items), nil
}
