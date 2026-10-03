package secretservice

import (
	"context"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

const networkPasswordSchema = "org.gnome.keyring.NetworkPassword"

// hostAttributes name the item attributes that hold a bare host name.
//
//nolint:gochecknoglobals
var hostAttributes = []string{"server", "host", "hostname"}

// urlAttributes name the item attributes that may hold a URL whose host the password is
// for. Applications using libsecret's generic schema often store one as "service".
//
//nolint:gochecknoglobals
var urlAttributes = []string{"url", "uri", "origin", "action_url", "signon_realm", "service"}

// NetworkHost returns the host a password is for, if it is a network password: one with
// gnome-keyring's network password schema, a host attribute, or a URL attribute. The host
// is lower case without a port. ok is false for other passwords; a network password whose
// host isn't recorded returns ok with an empty host.
func NetworkHost(it *Item) (string, bool) {
	for _, attr := range hostAttributes {
		if host := normalizeHost(it.Attributes[attr]); host != "" {
			return host, true
		}
	}
	for _, attr := range urlAttributes {
		u, err := url.Parse(strings.TrimSpace(it.Attributes[attr]))
		if err == nil && u.Scheme != "" && u.Host != "" {
			if host := normalizeHost(u.Hostname()); host != "" {
				return host, true
			}
		}
	}
	return "", it.Schema() == networkPasswordSchema
}

// normalizeHost lower cases a host and drops any port: "host:port" with a single colon, or
// "[ipv6]:port". A bare IPv6 address has several colons and is left alone.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case strings.HasPrefix(host, "["):
		if end := strings.Index(host, "]"); end > 0 {
			host = host[1:end]
		}
	case strings.Count(host, ":") == 1:
		host, _, _ = strings.Cut(host, ":")
	}
	return host
}

// inferCategories derives a keyring's subcategories from its items:
//
//	Login                 every item
//	  Network passwords   passwords for network services
//	    example.com       one per host
//	  Services            one per configured attribute grouping, here "service"
//	    github.com        one per value of the attribute
//
// Subcategories are a browsing aid; each parent still lists everything beneath it.
func inferCategories(k *Keyring, items []*PasswordItem, groupings []backend.AttributeGrouping) []backend.Category {
	var result []backend.Category
	if network := networkCategory(k, items); network != nil {
		result = append(result, network)
	}
	for _, g := range groupings {
		if cat := attributeCategory(k, items, g); cat != nil {
			result = append(result, cat)
		}
	}
	return result
}

// attributeCategory groups the items that have the grouping's attribute by its value, or
// returns nil if no item has the attribute.
func attributeCategory(k *Keyring, items []*PasswordItem, g backend.AttributeGrouping) backend.Category {
	attr := g.Attribute
	values := map[string]bool{}
	for _, item := range items {
		if v, ok := item.item.Attributes[attr]; ok {
			values[v] = true
		}
	}
	if len(values) == 0 {
		return nil
	}
	parent := &subset{
		keyring: k, key: k.Key() + ":attr:" + attr, title: g.Label(), icon: "folder-symbolic",
		match: func(it *Item) bool { _, ok := it.Attributes[attr]; return ok },
	}
	sorted := make([]string, 0, len(values))
	for v := range values {
		sorted = append(sorted, v)
	}
	sort.Strings(sorted)
	for _, value := range sorted {
		title := value
		if title == "" {
			title = "(empty)"
		}
		parent.children = append(parent.children, &subset{
			keyring: k, key: parent.key + "=" + value, title: title, icon: "text-x-generic-symbolic",
			match: func(it *Item) bool { v, ok := it.Attributes[attr]; return ok && v == value },
		})
	}
	return parent
}

// networkCategory groups network passwords by host, or returns nil if there are none.
func networkCategory(k *Keyring, items []*PasswordItem) backend.Category {
	hosts := map[string]bool{}
	anyNetwork := false
	for _, item := range items {
		host, ok := NetworkHost(item.item)
		if !ok {
			continue
		}
		anyNetwork = true
		if host != "" {
			hosts[host] = true
		}
	}
	if !anyNetwork {
		return nil
	}

	network := &subset{
		keyring: k, key: k.Key() + ":network", title: "Network passwords", icon: "network-server-symbolic",
		match: func(it *Item) bool { _, ok := NetworkHost(it); return ok },
	}
	sorted := make([]string, 0, len(hosts))
	for h := range hosts {
		sorted = append(sorted, h)
	}
	sort.Strings(sorted)
	for _, host := range sorted {
		network.children = append(network.children, &subset{
			keyring: k, key: network.key + ":" + host, title: host, icon: "network-workgroup-symbolic",
			match: func(it *Item) bool { h, ok := NetworkHost(it); return ok && h == host },
		})
	}
	return network
}

// subset is an inferred category: the keyring's items that match a predicate. Locking it
// locks the whole keyring.
type subset struct {
	keyring  *Keyring
	key      string
	title    string
	icon     string
	match    func(*Item) bool
	children []backend.Category
}

var (
	_ backend.Lockable = (*subset)(nil)
	_ backend.Parent   = (*subset)(nil)
)

// Key implements backend.Category.
func (s *subset) Key() string { return s.key }

// Title implements backend.Category.
func (s *subset) Title() string { return s.title }

// IconName implements backend.Category.
func (s *subset) IconName() string { return s.icon }

// Columns implements backend.Category.
func (s *subset) Columns() []backend.Column { return s.keyring.Columns() }

// Children implements backend.Parent.
func (s *subset) Children() []backend.Category { return s.children }

// Items implements backend.Category.
func (s *subset) Items(ctx context.Context) ([]backend.Item, error) {
	items, err := s.keyring.passwordItems(ctx)
	if err != nil {
		return nil, err
	}
	var result []backend.Item
	for _, item := range items {
		if s.match(item.item) {
			result = append(result, item)
		}
	}
	return result, nil
}

// Locked implements backend.Lockable.
func (s *subset) Locked() bool { return s.keyring.Locked() }

// Lock implements backend.Lockable.
func (s *subset) Lock(ctx context.Context) error { return s.keyring.Lock(ctx) }

// Unlock implements backend.Lockable.
func (s *subset) Unlock(ctx context.Context) error { return s.keyring.Unlock(ctx) }

//nolint:gochecknoglobals
var hexFingerprint = regexp.MustCompile(`^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`)

var _ backend.Linkable = (*PasswordItem)(nil)

// LinkKeys implements backend.Linkable, relating saved passphrases to the keys they unlock:
//
//   - gpg-agent saves passphrases with a "keygrip" attribute of "n/<keygrip>";
//   - any attribute holding a full PGP fingerprint, as scripts often record;
//   - gnome-keyring's SSH agent saves key passphrases with "unique" set to
//     "ssh-store:<path to the private key>".
func (i *PasswordItem) LinkKeys() []string {
	var keys []string
	for name, value := range i.item.Attributes {
		value = strings.TrimSpace(value)
		switch {
		case name == "keygrip":
			grip := strings.TrimPrefix(value, "n/")
			if hexFingerprint.MatchString(grip) {
				keys = append(keys, "gpg-keygrip:"+strings.ToUpper(grip))
			}
		case name == "unique" && strings.HasPrefix(value, "ssh-store:"):
			if path := strings.TrimPrefix(value, "ssh-store:"); filepath.IsAbs(path) {
				keys = append(keys, "ssh-private-key:"+filepath.Clean(path))
			}
		case hexFingerprint.MatchString(value):
			keys = append(keys, "gpg-fpr:"+strings.ToUpper(value))
		}
	}
	return keys
}

// LinkDescription implements backend.Linkable.
func (i *PasswordItem) LinkDescription() string {
	return "Saved password"
}
