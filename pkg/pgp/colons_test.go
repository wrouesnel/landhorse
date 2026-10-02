package pgp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/wrouesnel/landhorse/pkg/pgp"
)

// listing is gpg --with-colons --fixed-list-mode --with-fingerprint --with-keygrip
// --list-secret-keys output for a key with two user IDs, one subkey and a \x3a escape.
const listing = `sec:u:255:22:1111222233334444:1700000000:1800000000::u:::scESC:::+::ed25519:::0:
fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF1111222233334444:
grp:::::::::0123456789ABCDEF0123456789ABCDEF01234567:
uid:u::::1700000000::HASH1::Alice Example (work) <alice@example.com>::::::::::0:
uid:u::::1700000001::HASH2::Alice\x3a Home <alice@home.example>::::::::::0:
ssb:u:255:18:5555666677778888:1700000000::::::e:::#::cv25519:::
fpr:::::::::99990000AAAABBBBCCCCDDDDEEEEFFFF55556666:
grp:::::::::FEDCBA9876543210FEDCBA9876543210FEDCBA98:
`

func TestParseColons(t *testing.T) {
	keys, err := pgp.ParseColons(strings.NewReader(listing))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	k := keys[0]

	checks := []struct{ name, got, want string }{
		{"key id", k.KeyID, "1111222233334444"},
		{"fingerprint", k.Fingerprint, "AAAABBBBCCCCDDDDEEEEFFFF1111222233334444"},
		{"keygrip", k.Keygrip, "0123456789ABCDEF0123456789ABCDEF01234567"},
		{"owner trust", k.OwnerTrust, "u"},
		{"curve", k.Curve, "ed25519"},
		{"primary name", k.PrimaryUserID().Name(), "Alice Example"},
		{"primary comment", k.PrimaryUserID().Comment(), "work"},
		{"primary email", k.PrimaryUserID().Email(), "alice@example.com"},
		{"unescaped uid", k.UserIDs[1].Raw, "Alice: Home <alice@home.example>"},
		{"subkey fingerprint", k.SubKeys[0].Fingerprint, "99990000AAAABBBBCCCCDDDDEEEEFFFF55556666"},
		{"subkey secret status", k.SubKeys[0].SecretStatus, "#"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
	if !k.Secret {
		t.Error("primary key should be secret")
	}
	if len(k.UserIDs) != 2 || len(k.SubKeys) != 1 {
		t.Errorf("got %d uids and %d subkeys, want 2 and 1", len(k.UserIDs), len(k.SubKeys))
	}
	if !k.Created.Equal(time.Unix(1700000000, 0)) || !k.Expires.Equal(time.Unix(1800000000, 0)) {
		t.Errorf("created %v expires %v", k.Created, k.Expires)
	}
	if !k.SubKeys[0].Expires.IsZero() {
		t.Errorf("subkey without expiry got %v", k.SubKeys[0].Expires)
	}
}

func TestStubPrimaryIsNotSecret(t *testing.T) {
	keys, err := pgp.ParseColons(strings.NewReader("sec:u:255:22:1111222233334444:1700000000:::u:::scESC:::#::ed25519:::0:\n"))
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Secret {
		t.Error("a stub (#) primary key must not be reported as secret")
	}
}

func TestUserIDWithoutEmail(t *testing.T) {
	u := pgp.UserID{Raw: "Just A Name"}
	if u.Name() != "Just A Name" || u.Email() != "" || u.Comment() != "" {
		t.Errorf("got name %q email %q comment %q", u.Name(), u.Email(), u.Comment())
	}
}

func TestDescriptions(t *testing.T) {
	if got := pgp.AlgorithmName(22, "ed25519"); got != "EdDSA (ed25519)" {
		t.Errorf("AlgorithmName: got %q", got)
	}
	if got := pgp.CapabilityNames("scESC"); got != "Sign, Certify" {
		t.Errorf("CapabilityNames: got %q", got)
	}
	if got := pgp.ValidityName("f"); got != "Full" {
		t.Errorf("ValidityName: got %q", got)
	}
}
