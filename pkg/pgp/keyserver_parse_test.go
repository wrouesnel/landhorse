package pgp

import (
	"reflect"
	"testing"
)

func TestParseStringArray(t *testing.T) {
	cases := map[string][]string{
		"['hkps://keyserver.ubuntu.com']\n":                       {"hkps://keyserver.ubuntu.com"},
		"['ldap://keyserver.pgp.com', 'hkps://keys.openpgp.org']": {"ldap://keyserver.pgp.com", "hkps://keys.openpgp.org"},
		`["hkp://a Name", 'it\'s']`:                               {"hkp://a Name", "it's"},
		"@as []":                                                  {},
	}
	for input, want := range cases {
		got, ok := parseStringArray(input)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("parseStringArray(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	if _, ok := parseStringArray("No such schema “org.gnome.crypto.pgp”"); ok {
		t.Error("an error message parsed as an array")
	}
}
