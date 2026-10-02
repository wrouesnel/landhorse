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
}

// PasswordsConfig configures the Secret Service (keyrings and passwords) backend.
type PasswordsConfig struct {
	Disabled bool `yaml:"disabled"`
}

// PGPConfig configures the GnuPG backend.
type PGPConfig struct {
	Disabled bool `yaml:"disabled"`
	// Binary is the gpg executable. Defaults to "gpg" on the PATH.
	Binary string `yaml:"binary"`
	// Home overrides GNUPGHOME.
	Home string `yaml:"home"`
}

// SSHConfig configures the OpenSSH key backend.
type SSHConfig struct {
	Disabled bool `yaml:"disabled"`
	// Directory holds the keys. Defaults to ~/.ssh.
	Directory string `yaml:"directory"`
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
