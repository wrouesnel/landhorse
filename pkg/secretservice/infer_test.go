package secretservice

import (
	"reflect"
	"sort"
	"testing"
)

func item(schema string, attrs map[string]string) *Item {
	if attrs == nil {
		attrs = map[string]string{}
	}
	if schema != "" {
		attrs["xdg:schema"] = schema
	}
	return &Item{Attributes: attrs}
}

func TestNetworkHost(t *testing.T) {
	cases := []struct {
		name  string
		item  *Item
		host  string
		isNet bool
	}{
		{"network schema with server", item(networkPasswordSchema, map[string]string{"server": "Mail.Example.COM", "protocol": "imap"}), "mail.example.com", true},
		{"network schema without server", item(networkPasswordSchema, nil), "", true},
		{"host attribute with port", item("", map[string]string{"host": "git.example.org:2222"}), "git.example.org", true},
		{"service URL", item("org.freedesktop.Secret.Generic", map[string]string{"service": "https://vault.example.net:8200/ui"}), "vault.example.net", true},
		{"IPv6 URL", item("", map[string]string{"url": "https://[::1]:8443/"}), "::1", true},
		{"service that isn't a URL", item("org.freedesktop.Secret.Generic", map[string]string{"service": "aws_sso:portal:https://x.example/start"}), "", false},
		{"plain password", item("org.freedesktop.Secret.Generic", map[string]string{"service": "gpg-passphrase"}), "", false},
	}
	for _, c := range cases {
		host, isNet := NetworkHost(c.item)
		if host != c.host || isNet != c.isNet {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, host, isNet, c.host, c.isNet)
		}
	}
}

func TestInferCategories(t *testing.T) {
	k := &Keyring{collection: &Collection{Path: "/org/freedesktop/secrets/collection/login", Label: "Login"}}
	items := []*PasswordItem{
		{keyring: k, item: item(networkPasswordSchema, map[string]string{"server": "a.example"})},
		{keyring: k, item: item(networkPasswordSchema, map[string]string{"server": "b.example"})},
		{keyring: k, item: item("", map[string]string{"url": "https://a.example/login"})},
		{keyring: k, item: item("org.freedesktop.Secret.Generic", nil)},
	}
	cats := inferCategories(k, items)
	if len(cats) != 1 || cats[0].Title() != "Network passwords" {
		t.Fatalf("got %v, want one Network passwords category", cats)
	}
	network := cats[0].(*subset)
	var hosts []string
	for _, c := range network.Children() {
		hosts = append(hosts, c.Title())
	}
	if !reflect.DeepEqual(hosts, []string{"a.example", "b.example"}) {
		t.Errorf("hosts: got %v", hosts)
	}
	matched := 0
	for _, it := range items {
		if network.children[0].(*subset).match(it.item) {
			matched++
		}
	}
	if matched != 2 {
		t.Errorf("a.example matched %d items, want 2", matched)
	}

	if cats := inferCategories(k, items[3:]); cats != nil {
		t.Errorf("keyring without network passwords got categories %v", cats)
	}
}

func TestPasswordLinkKeys(t *testing.T) {
	grip := "0123456789ABCDEF0123456789ABCDEF01234567"
	fpr := "aaaabbbbccccddddeeeeffff0000111122223333"
	cases := []struct {
		name  string
		attrs map[string]string
		want  []string
	}{
		{"gpg-agent passphrase", map[string]string{"keygrip": "n/" + grip, "stored-by": "GnuPG Pinentry"},
			[]string{"gpg-keygrip:" + grip}},
		{"fingerprint attribute", map[string]string{"fingerprint": fpr, "service": "gpg-passphrase"},
			[]string{"gpg-fpr:" + "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"}},
		{"gnome-keyring SSH passphrase", map[string]string{"unique": "ssh-store:/home/me/.ssh/../.ssh/id_rsa"},
			[]string{"ssh-private-key:/home/me/.ssh/id_rsa"}},
		{"relative SSH path is ignored", map[string]string{"unique": "ssh-store:id_rsa"}, nil},
		{"ordinary password", map[string]string{"service": "example", "user": "me"}, nil},
	}
	for _, c := range cases {
		p := &PasswordItem{item: item("org.freedesktop.Secret.Generic", c.attrs)}
		got := p.LinkKeys()
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"Example.com":    "example.com",
		"example.com:22": "example.com",
		"[fe80::1]:443":  "fe80::1",
		"fe80::1":        "fe80::1",
		" ":              "",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
