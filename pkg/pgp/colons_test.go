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

func TestHasSecretWithOfflinePrimary(t *testing.T) {
	// Primary key is a stub (#), but a subkey's secret is here (+): still a private key.
	keys, err := pgp.ParseColons(strings.NewReader(
		"sec:u:255:22:1111222233334444:1700000000:::u:::scESC:::#::ed25519:::0:\n" +
			"ssb:u:255:18:5555666677778888:1700000000::::::e:::+::cv25519:::\n"))
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Secret || !keys[0].HasSecret() {
		t.Errorf("Secret %v HasSecret %v; want false, true", keys[0].Secret, keys[0].HasSecret())
	}
}

func TestEmailsAndLatestComment(t *testing.T) {
	k := &pgp.Key{UserIDs: []pgp.UserID{
		{Raw: "Alice (old) <Alice@Example.com>", Created: time.Unix(1000, 0)},
		{Raw: "Alice (newest) <alice@example.com>", Created: time.Unix(3000, 0)},
		{Raw: "Alice (middle) <alice@work.example>", Created: time.Unix(2000, 0)},
		{Raw: "Alice (revoked) <alice@gone.example>", Created: time.Unix(4000, 0), Validity: "r"},
		{Raw: "Alice <alice@nocomment.example>", Created: time.Unix(5000, 0)},
	}}
	got := strings.Join(k.Emails(), ",")
	if want := "alice@example.com,alice@work.example,alice@nocomment.example"; got != want {
		t.Errorf("Emails: got %q, want %q", got, want)
	}
	if got := k.LatestComment(); got != "newest" {
		t.Errorf("LatestComment: got %q, want %q", got, "newest")
	}
	if got := (&pgp.Key{UserIDs: []pgp.UserID{{Raw: "Bob <bob@example.org>"}}}).LatestComment(); got != "" {
		t.Errorf("LatestComment without comments: got %q", got)
	}
}

func TestParseKeyservers(t *testing.T) {
	got := pgp.ParseKeyservers([]string{"hkps://keys.openpgp.org", "  ", "ldap://keyserver.pgp.com PGP Global Directory"})
	if len(got) != 2 {
		t.Fatalf("got %d keyservers, want 2: %v", len(got), got)
	}
	if got[0].URI != "hkps://keys.openpgp.org" || got[0].Name != "" || got[0].Label() != "hkps://keys.openpgp.org" {
		t.Errorf("first: %+v", got[0])
	}
	if got[1].URI != "ldap://keyserver.pgp.com" || got[1].Label() != "PGP Global Directory (ldap://keyserver.pgp.com)" {
		t.Errorf("second: %+v label %q", got[1], got[1].Label())
	}
}

func TestValiditySortOrder(t *testing.T) {
	// Strongest first: trust levels, then unknown, expired and revoked last.
	order := []string{"Ultimate", "Full", "Marginal", "Never", "Unknown", "Expired", "Revoked"}
	for i := 1; i < len(order); i++ {
		if pgp.ValidityNameRank(order[i-1]) >= pgp.ValidityNameRank(order[i]) {
			t.Errorf("%s (%d) should sort before %s (%d)", order[i-1], pgp.ValidityNameRank(order[i-1]),
				order[i], pgp.ValidityNameRank(order[i]))
		}
	}
	if pgp.ValidityNameRank("Unknown (new)") != pgp.ValidityNameRank("Unknown") {
		t.Error("the unknown variants should rank together")
	}
}

func TestRevokedKeyKeepsEmails(t *testing.T) {
	k := &pgp.Key{SubKey: pgp.SubKey{Validity: "r"}, UserIDs: []pgp.UserID{
		{Raw: "Dave (old) <dave@example.net>", Validity: "r"},
	}}
	if got := strings.Join(k.Emails(), ","); got != "dave@example.net" {
		t.Errorf("Emails: got %q, want the revoked key's address", got)
	}
	if got := k.LatestComment(); got != "old" {
		t.Errorf("LatestComment: got %q, want %q", got, "old")
	}
}

func TestParseSignatures(t *testing.T) {
	listing := `pub:u:255:22:8DEA3EF258D43F24:1791037695:::u:::scESC
fpr:::::::::F41BA2836056D52FDAB02CA58DEA3EF258D43F24:
uid:u::::1791037695::HASH::Bob <b@x>::
sig:::22:8DEA3EF258D43F24:1791037695::::Bob <b@x>:13x:
sig:::22:F6A44FBCB9791A3F:1791037696::::Alice <a@x>:10x:
rev:::22:1234123412341234:1791037697::::Carol <c@x>:30x:
sub:u:255:18:D7D22B4512A1614F:1791037695::::::e
fpr:::::::::12FCB571C17138FEB5A2994BD7D22B4512A1614F:
sig:::22:8DEA3EF258D43F24:1791037695::::Bob <b@x>:18x:
`
	keys, err := pgp.ParseColons(strings.NewReader(listing))
	if err != nil {
		t.Fatal(err)
	}
	sigs := keys[0].Signatures
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2 (no self or binding signatures): %+v", len(sigs), sigs)
	}
	if sigs[0].SignerKeyID != "F6A44FBCB9791A3F" || sigs[0].SignerUserID != "Alice <a@x>" || sigs[0].Revocation {
		t.Errorf("first: %+v", sigs[0])
	}
	if !sigs[1].Revocation || sigs[1].Class != "30x" {
		t.Errorf("second: %+v", sigs[1])
	}
	if got := strings.Join(keys[0].Signers(), ","); got != "F6A44FBCB9791A3F,1234123412341234" {
		t.Errorf("Signers: %s", got)
	}
}
