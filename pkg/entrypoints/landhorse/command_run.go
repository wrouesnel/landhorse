package landhorse

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
	"github.com/wrouesnel/ctxstdio"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/landhorse/pkg/backend"
	"github.com/wrouesnel/landhorse/pkg/pgp"
	"github.com/wrouesnel/landhorse/pkg/secretservice"
	"github.com/wrouesnel/landhorse/pkg/sshkeys"
	"github.com/wrouesnel/landhorse/pkg/ui"
)

// RunCmd opens the main window.
type RunCmd struct {
	Category string `help:"Key of the category to select on startup, as printed by the list command"`
}

// Run is invoked by kong with the values bound in Entrypoint.
func (r *RunCmd) Run(ctx context.Context, cli *CLIConfig, config *EntrypointConfig) error {
	l := logutil.FromCtx(ctx)
	fs := afero.NewOsFs()

	groups, closeGroups, err := buildGroups(ctx, config, fs)
	if err != nil {
		return err
	}
	defer closeGroups()

	prefs := &settings{path: pathlib.NewPath(cli.ConfigFile.String(), pathlib.PathWithAfero(fs)), config: config}
	for _, g := range groups {
		if ss, ok := g.(*secretservice.Group); ok {
			prefs.passwords = ss
		}
	}

	l.Debug("Opening main window", zap.Int("groups", len(groups)))
	return ui.Run(ctx, ui.Options{
		Groups:          groups,
		Fs:              fs,
		InitialCategory: r.Category,
		ConfigPath:      cli.ConfigFile.String(),
		Settings:        prefs,
	})
}

// ListCmd prints what the main window would show, for scripting and diagnostics.
type ListCmd struct{}

// Run prints each group, category and item. A group that fails to load is reported and
// skipped so the others still print; the command then fails.
func (c *ListCmd) Run(ctx context.Context, config *EntrypointConfig) error {
	out := ctxstdio.StdOut(ctx)
	groups, closeGroups, err := buildGroups(ctx, config, afero.NewOsFs())
	if err != nil {
		return err
	}
	defer closeGroups()

	failed := 0
	for _, g := range groups {
		_, _ = fmt.Fprintf(out, "%s\n", g.Title())
		cats, err := g.Categories(ctx)
		if err != nil {
			_, _ = fmt.Fprintf(out, "  ! %v\n", err)
			failed++
			continue
		}
		for _, cat := range cats {
			failed += listCategory(ctx, out, cat, 1)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d groups or categories could not be listed", failed)
	}
	return nil
}

// listCategory prints a category, its items and its subcategories, indented by depth. It
// returns how many categories failed to load.
func listCategory(ctx context.Context, out io.Writer, cat backend.Category, depth int) int {
	indent := strings.Repeat("  ", depth)
	locked := ""
	if lk, ok := cat.(backend.Lockable); ok && lk.Locked() {
		locked = " [locked]"
	}
	_, _ = fmt.Fprintf(out, "%s%s%s  (%s)\n", indent, cat.Title(), locked, cat.Key())

	failed := 0
	items, err := cat.Items(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(out, "%s  ! %v\n", indent, err)
		failed++
	}
	for _, item := range items {
		_, _ = fmt.Fprintf(out, "%s  %s\n", indent, strings.Join(item.Cells(), " | "))
	}
	if p, ok := cat.(backend.Parent); ok {
		for _, child := range p.Children() {
			failed += listCategory(ctx, out, child, depth+1)
		}
	}
	return failed
}

// buildGroups creates the enabled backends. The returned function releases them.
func buildGroups(ctx context.Context, config *EntrypointConfig, fs afero.Fs) ([]backend.Group, func(), error) {
	var groups []backend.Group
	var closers []func() error

	if !config.Passwords.Disabled {
		g := &secretservice.Group{}
		groupings := make([]backend.AttributeGrouping, 0, len(config.Passwords.Groups))
		for _, gc := range config.Passwords.Groups {
			groupings = append(groupings, backend.AttributeGrouping{Attribute: gc.Attribute, Title: gc.Title})
		}
		g.SetGroupings(groupings)
		groups = append(groups, g)
		closers = append(closers, g.Close)
	}

	if !config.PGP.Disabled {
		// Unset means whatever Seahorse uses on this system, or upstream Seahorse's defaults.
		keyservers := config.PGP.Keyservers
		if keyservers == nil {
			if system, ok := pgp.SystemKeyservers(ctx); ok {
				keyservers = system
			} else {
				keyservers = pgp.DefaultKeyservers
			}
		}
		groups = append(groups, &pgp.Group{GPG: &pgp.GPG{
			Binary:     config.PGP.Binary,
			Home:       config.PGP.Home,
			Keyservers: pgp.ParseKeyservers(keyservers),
		}})
	}

	if !config.SSH.Disabled {
		dir := config.SSH.Directory
		if dir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, nil, fmt.Errorf("finding the home directory for ~/.ssh: %w", err)
			}
			dir = filepath.Join(home, ".ssh")
		}
		socket := config.SSH.AgentSocket
		if socket == "" {
			socket = os.Getenv("SSH_AUTH_SOCK")
		}
		groups = append(groups, &sshkeys.Group{
			Dir:         pathlib.NewPath(dir, pathlib.PathWithAfero(fs)),
			AgentSocket: socket,
		})
	}

	closeAll := func() {
		for _, c := range closers {
			_ = c()
		}
	}
	return groups, closeAll, nil
}
