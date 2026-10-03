package landhorse

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/chigopher/pathlib"
	"github.com/wrouesnel/landhorse/version"
	"go.yaml.in/yaml/v4"
)

// UnmarshalConfig wraps the yaml.Unmarshaling process for entrypoint configuration files.
// This includes ensuring that the necessary providers from other parts of the application
// are loaded.
func UnmarshalConfig(path *pathlib.Path, config *EntrypointConfig) error {
	configFile, err := path.Open()
	if err != nil {
		return err
	}
	defer configFile.Close()

	loader, err := yaml.NewLoader(configFile, YamlOption())
	if err != nil {
		return err
	}
	return loader.Load(config)
}

// YamlOption returns the correct YAML options for decoding entrypoint configuration.
func YamlOption() yaml.Option {
	return yaml.Options()
}

// EntrypointConfig unmarshals to configure the application. Every key is optional.
type EntrypointConfig struct {
	Passwords PasswordsConfig `yaml:"passwords"`
	PGP       PGPConfig       `yaml:"pgp"`
	SSH       SSHConfig       `yaml:"ssh"`
	// SecurityKeys configures smart cards and passkeys.
	SecurityKeys SecurityKeysConfig `yaml:"security_keys"`
}

// SecurityKeysConfig configures the smart card and passkey backend.
type SecurityKeysConfig struct {
	Disabled bool `yaml:"disabled"`
	// P11Tool is GnuTLS's p11tool, which reads smart cards. Defaults to "p11tool".
	P11Tool string `yaml:"p11tool"`
	// FIDO2Token is libfido2's fido2-token, which manages passkeys. Defaults to
	// "fido2-token".
	FIDO2Token string `yaml:"fido2_token"`
}

// PasswordsConfig configures the Secret Service (keyrings and passwords) backend.
type PasswordsConfig struct {
	Disabled bool `yaml:"disabled"`
	// Groups add a category to each keyring per attribute, with a subcategory for each of
	// the attribute's values. Edited in Edit → Preferences.
	Groups []GroupConfig `yaml:"groups,omitempty"`
}

// GroupConfig groups passwords by an attribute.
type GroupConfig struct {
	// Attribute is the item attribute to group by, e.g. "service".
	Attribute string `yaml:"attribute"`
	// Title names the category; empty means the attribute name.
	Title string `yaml:"title,omitempty"`
}

// PGPConfig configures the GnuPG backend.
type PGPConfig struct {
	Disabled bool `yaml:"disabled"`
	// Binary is the gpg executable. Defaults to "gpg" on the PATH.
	Binary string `yaml:"binary"`
	// Home overrides GNUPGHOME.
	Home string `yaml:"home"`
	// Keyservers are offered when publishing keys, each a URI optionally followed by a space
	// and a display name. Unset means the keyservers Seahorse uses on this system (gcr's
	// org.gnome.crypto.pgp keyservers setting), falling back to upstream Seahorse's
	// defaults; an empty list disables publishing.
	Keyservers []string `yaml:"keyservers"`
}

// SSHConfig configures the OpenSSH key backend.
type SSHConfig struct {
	Disabled bool `yaml:"disabled"`
	// Directory holds the keys. Defaults to ~/.ssh.
	Directory string `yaml:"directory"`
	// AgentSocket is the SSH agent whose loaded keys are listed. Defaults to
	// $SSH_AUTH_SOCK; with neither, the SSH agent category is left out.
	AgentSocket string `yaml:"agent_socket"`
}

// defaultConfigPath is $XDG_CONFIG_HOME/landhorse/landhorse.yml, or landhorse.yml in the
// working directory if the user config directory can't be determined.
func defaultConfigPath() string {
	name := fmt.Sprintf("%s.yml", version.Name)
	dir, err := os.UserConfigDir()
	if err != nil {
		return name
	}
	return filepath.Join(dir, version.Name, name)
}
