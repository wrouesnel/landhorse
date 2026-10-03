package landhorse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

func TestSaveKeyringGroupingsKeepsTheRestOfTheFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "landhorse.yml")
	original := `# My landhorse settings
pgp:
  # Ubuntu's keyserver only
  keyservers:
    - hkps://keyserver.ubuntu.com
passwords:
  disabled: false
`
	if err := os.WriteFile(file, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &settings{path: pathlib.NewPath(file, pathlib.PathWithAfero(afero.NewOsFs())), config: &EntrypointConfig{}}

	if err := s.SetKeyringGroupings([]backend.AttributeGrouping{
		{Attribute: "service", Title: "Services"}, {Attribute: "user"},
	}); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(file)
	for _, want := range []string{"# My landhorse settings", "# Ubuntu's keyserver only",
		"hkps://keyserver.ubuntu.com", "attribute: service", "title: Services", "attribute: user"} {
		if !strings.Contains(string(saved), want) {
			t.Errorf("saved file lacks %q:\n%s", want, saved)
		}
	}

	var reloaded EntrypointConfig
	if err := UnmarshalConfig(s.path, &reloaded); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Passwords.Groups) != 2 || reloaded.Passwords.Groups[0].Title != "Services" ||
		len(reloaded.PGP.Keyservers) != 1 {
		t.Errorf("reloaded config: %+v", reloaded)
	}

	// Clearing the groupings removes the key.
	if err := s.SetKeyringGroupings(nil); err != nil {
		t.Fatal(err)
	}
	saved, _ = os.ReadFile(file)
	if strings.Contains(string(saved), "groups") || !strings.Contains(string(saved), "keyservers") {
		t.Errorf("after clearing:\n%s", saved)
	}
}

func TestSaveCreatesConfigFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config", "landhorse", "landhorse.yml")
	s := &settings{path: pathlib.NewPath(file, pathlib.PathWithAfero(afero.NewOsFs())), config: &EntrypointConfig{}}
	if err := s.SetKeyringGroupings([]backend.AttributeGrouping{{Attribute: "service"}}); err != nil {
		t.Fatal(err)
	}
	var reloaded EntrypointConfig
	if err := UnmarshalConfig(s.path, &reloaded); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Passwords.Groups) != 1 || reloaded.Passwords.Groups[0].Attribute != "service" {
		t.Errorf("reloaded: %+v", reloaded.Passwords.Groups)
	}
}
