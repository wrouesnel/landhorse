package pgp

import (
	"context"
	"os/exec"
	"strings"
)

// DefaultKeyservers are upstream Seahorse's defaults (the "keyservers" key of its
// org.gnome.seahorse schema), used when the system has no keyserver setting.
//
//nolint:gochecknoglobals
var DefaultKeyservers = []string{"ldap://keyserver.pgp.com", "hkps://keys.openpgp.org"}

// SystemKeyservers returns the keyservers Seahorse uses on this system: the keyservers key
// of gcr's org.gnome.crypto.pgp GSettings schema, which Seahorse 43 (as shipped by Ubuntu
// and Debian) reads, and which distributions set to their own keyserver. It is read with
// the gsettings tool, so no GLib binding is needed. ok is false when it isn't available.
func SystemKeyservers(ctx context.Context) ([]string, bool) {
	out, err := exec.CommandContext(ctx, "gsettings", "get", "org.gnome.crypto.pgp", "keyservers").Output()
	if err != nil {
		return nil, false
	}
	return parseStringArray(string(out))
}

// parseStringArray parses the text form of a GVariant string array, as gsettings prints
// it: ['a', "b"] or @as [].
func parseStringArray(text string) ([]string, bool) {
	text = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), "@as"))
	if !strings.HasPrefix(text, "[") || !strings.HasSuffix(text, "]") {
		return nil, false
	}
	body := text[1 : len(text)-1]
	result := []string{}
	for i := 0; i < len(body); i++ {
		quote := body[i]
		if quote != '\'' && quote != '"' {
			continue
		}
		var b strings.Builder
		for i++; i < len(body) && body[i] != quote; i++ {
			if body[i] == '\\' && i+1 < len(body) {
				i++
			}
			b.WriteByte(body[i])
		}
		result = append(result, b.String())
	}
	return result, true
}

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
