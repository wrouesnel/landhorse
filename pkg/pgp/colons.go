package pgp

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"
)

// Key is a primary key with its user IDs and subkeys, as listed by gpg --with-colons.
// See doc/DETAILS in the GnuPG sources for the format.
type Key struct {
	SubKey
	// OwnerTrust is the trust the user assigned to the key owner (field 9 of pub).
	OwnerTrust string
	UserIDs    []UserID
	SubKeys    []SubKey
	// Secret is true when the secret part of the primary key is available.
	Secret bool
}

// SubKey is a primary key or subkey record (pub/sub/sec/ssb).
type SubKey struct {
	Validity     string
	Bits         int
	Algorithm    int
	KeyID        string
	Created      time.Time
	Expires      time.Time
	Capabilities string
	Curve        string
	Fingerprint  string
	Keygrip      string
	// SecretStatus is field 15 of sec/ssb: "+" for available, "#" for a stub (secret not
	// here), or a card serial number.
	SecretStatus string
}

// UserID is a uid record.
type UserID struct {
	Validity string
	Created  time.Time
	// Raw is the full user ID string, normally "Name (Comment) <email>".
	Raw string
}

// Name, Comment and Email split a user ID of the form "Name (Comment) <email>".
func (u UserID) Name() string {
	name, _, _ := splitUserID(u.Raw)
	return name
}

// Comment returns the parenthesised comment of the user ID.
func (u UserID) Comment() string {
	_, comment, _ := splitUserID(u.Raw)
	return comment
}

// Email returns the address in angle brackets of the user ID.
func (u UserID) Email() string {
	_, _, email := splitUserID(u.Raw)
	return email
}

func splitUserID(raw string) (name, comment, email string) {
	rest := strings.TrimSpace(raw)
	if start := strings.LastIndex(rest, "<"); start >= 0 && strings.HasSuffix(rest, ">") {
		email = rest[start+1 : len(rest)-1]
		rest = strings.TrimSpace(rest[:start])
	}
	if strings.HasSuffix(rest, ")") {
		if start := strings.LastIndex(rest, "("); start >= 0 {
			comment = rest[start+1 : len(rest)-1]
			rest = strings.TrimSpace(rest[:start])
		}
	}
	return rest, comment, email
}

// PrimaryUserID returns the first user ID, which gpg lists as the primary one.
func (k *Key) PrimaryUserID() UserID {
	if len(k.UserIDs) == 0 {
		return UserID{}
	}
	return k.UserIDs[0]
}

// ParseColons parses the output of gpg --with-colons --fixed-list-mode --list-keys or
// --list-secret-keys.
func ParseColons(r io.Reader) ([]*Key, error) {
	var (
		keys    []*Key
		current *Key
		// last is the key record the next fpr/grp record belongs to.
		last *SubKey
	)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		field := func(n int) string {
			// Fields are numbered from 1 in the GnuPG documentation.
			if n-1 < len(fields) {
				return fields[n-1]
			}
			return ""
		}

		switch field(1) {
		case "pub", "sec":
			current = &Key{SubKey: parseSubKey(field), OwnerTrust: field(9), Secret: field(1) == "sec"}
			if current.Secret && current.SecretStatus == "#" {
				// Only a stub: the secret primary key isn't on this machine.
				current.Secret = false
			}
			keys = append(keys, current)
			last = &current.SubKey
		case "sub", "ssb":
			if current == nil {
				continue
			}
			current.SubKeys = append(current.SubKeys, parseSubKey(field))
			last = &current.SubKeys[len(current.SubKeys)-1]
		case "uid":
			if current == nil {
				continue
			}
			current.UserIDs = append(current.UserIDs, UserID{
				Validity: field(2),
				Created:  parseTime(field(6)),
				Raw:      unescape(field(10)),
			})
			last = nil
		case "fpr":
			if last != nil && last.Fingerprint == "" {
				last.Fingerprint = field(10)
			}
		case "grp":
			if last != nil && last.Keygrip == "" {
				last.Keygrip = field(10)
			}
		}
	}
	return keys, scanner.Err()
}

func parseSubKey(field func(int) string) SubKey {
	bits, _ := strconv.Atoi(field(3))
	algo, _ := strconv.Atoi(field(4))
	return SubKey{
		Validity:     field(2),
		Bits:         bits,
		Algorithm:    algo,
		KeyID:        field(5),
		Created:      parseTime(field(6)),
		Expires:      parseTime(field(7)),
		Capabilities: field(12),
		SecretStatus: field(15),
		Curve:        field(17),
	}
}

// parseTime handles both seconds since the epoch and the ISO 8601 form gpg may emit.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		if secs == 0 {
			return time.Time{}
		}
		return time.Unix(secs, 0)
	}
	if t, err := time.Parse("20060102T150405", s); err == nil {
		return t
	}
	return time.Time{}
}

// unescape decodes the \xNN escapes gpg uses in colon listings.
func unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// AlgorithmName returns a readable name for an OpenPGP public key algorithm number.
func AlgorithmName(algo int, curve string) string {
	var name string
	switch algo {
	case 1, 2, 3:
		name = "RSA"
	case 16, 20:
		name = "Elgamal"
	case 17:
		name = "DSA"
	case 18:
		name = "ECDH"
	case 19:
		name = "ECDSA"
	case 22:
		name = "EdDSA"
	case 25:
		name = "X25519"
	case 26:
		name = "X448"
	case 27:
		name = "Ed25519"
	case 28:
		name = "Ed448"
	default:
		name = "Algorithm " + strconv.Itoa(algo)
	}
	if curve != "" {
		return name + " (" + curve + ")"
	}
	return name
}

// ValidityName describes a validity or owner trust code.
func ValidityName(code string) string {
	switch code {
	case "o":
		return "Unknown (new)"
	case "i":
		return "Invalid"
	case "d":
		return "Disabled"
	case "r":
		return "Revoked"
	case "e":
		return "Expired"
	case "-", "":
		return "Unknown"
	case "q":
		return "Undefined"
	case "n":
		return "Never"
	case "m":
		return "Marginal"
	case "f":
		return "Full"
	case "u":
		return "Ultimate"
	case "w":
		return "Well known private"
	case "s":
		return "Special"
	default:
		return code
	}
}

// CapabilityNames describes the lowercase usage flags of a key, e.g. "esc".
func CapabilityNames(caps string) string {
	names := []string{}
	for _, c := range caps {
		switch c {
		case 'e':
			names = append(names, "Encrypt")
		case 's':
			names = append(names, "Sign")
		case 'c':
			names = append(names, "Certify")
		case 'a':
			names = append(names, "Authenticate")
		}
	}
	return strings.Join(names, ", ")
}
