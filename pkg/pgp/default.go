package pgp

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultKey is the key gpg signs with when none is named: the default identity.
type DefaultKey struct {
	Fingerprint string
	// Source says where the choice comes from, for display.
	Source string
}

// homeDir is the GnuPG home in use.
func (g *GPG) homeDir() string {
	if g.Home != "" {
		return g.Home
	}
	if env := os.Getenv("GNUPGHOME"); env != "" {
		return env
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gnupg")
}

// confDefaultKey returns the default-key setting from gpg.conf, if any. The last one wins,
// as in gpg.
func (g *GPG) confDefaultKey() string {
	f, err := os.Open(filepath.Join(g.homeDir(), "gpg.conf"))
	if err != nil {
		return ""
	}
	defer f.Close()
	value := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(line, "default-key"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			value = strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return value
}

// seahorseDefaultKey returns Seahorse's default key setting (org.gnome.crypto.pgp
// default-key), if any.
func seahorseDefaultKey(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "gsettings", "get", "org.gnome.crypto.pgp", "default-key").Output()
	if err != nil {
		return ""
	}
	value := strings.Trim(strings.TrimSpace(string(out)), "'")
	return strings.TrimPrefix(value, "openpgp:")
}

// matchKey finds the key a key specification (fingerprint, key ID, email or name) names
// among keys with a secret part.
func matchKey(spec string, keys []*Key) *Key {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	hex := strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(spec, "0x"), "0X"), " ", ""))
	hex = strings.TrimSuffix(hex, "!")
	for _, k := range keys {
		if !k.HasSecret() {
			continue
		}
		if len(hex) >= 8 && strings.HasSuffix(k.Fingerprint, hex) {
			return k
		}
		for _, u := range k.UserIDs {
			if strings.Contains(strings.ToLower(u.Raw), strings.ToLower(strings.Trim(spec, "<>"))) {
				return k
			}
		}
	}
	return nil
}

// ResolveDefaultKey finds the default identity among keys: gpg.conf's default-key, then
// Seahorse's setting, then, as gpg does, the first private key that can sign.
func (g *GPG) ResolveDefaultKey(ctx context.Context, keys []*Key) *DefaultKey {
	if k := matchKey(g.confDefaultKey(), keys); k != nil {
		return &DefaultKey{Fingerprint: k.Fingerprint, Source: "default-key in gpg.conf"}
	}
	if k := matchKey(seahorseDefaultKey(ctx), keys); k != nil {
		return &DefaultKey{Fingerprint: k.Fingerprint, Source: "Seahorse's default key setting"}
	}
	for _, k := range keys {
		if k.Secret && k.unusableReason() == "" && strings.Contains(k.Capabilities, "S") {
			return &DefaultKey{Fingerprint: k.Fingerprint, Source: "your first private key (gpg's default)"}
		}
	}
	return nil
}
