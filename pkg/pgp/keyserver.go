package pgp

import (
	"context"
	"strings"
)

// DefaultKeyservers are Seahorse's defaults (the "keyservers" key of the
// org.gnome.seahorse GSettings schema).
//
//nolint:gochecknoglobals
var DefaultKeyservers = []string{"ldap://keyserver.pgp.com", "hkps://keys.openpgp.org"}

// Keyserver is a keyserver URI with an optional display name.
type Keyserver struct {
	URI  string
	Name string
}

// ParseKeyserver parses Seahorse's keyserver setting format: a URI, optionally followed by
// a space and a display name.
func ParseKeyserver(s string) Keyserver {
	uri, name, _ := strings.Cut(strings.TrimSpace(s), " ")
	return Keyserver{URI: uri, Name: strings.TrimSpace(name)}
}

// ParseKeyservers parses a list of keyserver settings, skipping blank entries.
func ParseKeyservers(entries []string) []Keyserver {
	var result []Keyserver
	for _, e := range entries {
		if ks := ParseKeyserver(e); ks.URI != "" {
			result = append(result, ks)
		}
	}
	return result
}

// Label is the display name, or the URI when there is none.
func (k Keyserver) Label() string {
	if k.Name != "" {
		return k.Name + " (" + k.URI + ")"
	}
	return k.URI
}

// SendKey uploads a public key to a keyserver and returns gpg's report.
func (g *GPG) SendKey(ctx context.Context, keyserver string, fingerprint string) (string, error) {
	_, stderr, err := g.run(ctx, "--keyserver", keyserver, "--send-keys", fingerprint)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(stderr)), nil
}
