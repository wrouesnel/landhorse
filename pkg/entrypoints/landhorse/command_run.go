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
func (r *RunCmd) Run(ctx context.Context, config *EntrypointConfig) error {
	l := logutil.FromCtx(ctx)
	fs := afero.NewOsFs()

	groups, closeGroups, err := buildGroups(config, fs)
	if err != nil {
		return err
	}
	defer closeGroups()

	l.Debug("Opening main window", zap.Int("groups", len(groups)))
	return ui.Run(ctx, ui.Options{Groups: groups, Fs: fs, InitialCategory: r.Category})
}

// ListCmd prints what the main window would show, for scripting and diagnostics.
type ListCmd struct{}

// Run prints each group, category and item. A group that fails to load is reported and
// skipped so the others still print; the command then fails.
func (c *ListCmd) Run(ctx context.Context, config *EntrypointConfig) error {
	out := ctxstdio.StdOut(ctx)
	groups, closeGroups, err := buildGroups(config, afero.NewOsFs())
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
			if err := listCategory(ctx, out, cat); err != nil {
				_, _ = fmt.Fprintf(out, "    ! %v\n", err)
				failed++
			}
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d groups or categories could not be listed", failed)
	}
	return nil
}

func listCategory(ctx context.Context, out io.Writer, cat backend.Category) error {
	locked := ""
	if lk, ok := cat.(backend.Lockable); ok && lk.Locked() {
		locked = " [locked]"
	}
	_, _ = fmt.Fprintf(out, "  %s%s  (%s)\n", cat.Title(), locked, cat.Key())
	items, err := cat.Items(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		_, _ = fmt.Fprintf(out, "    %s\n", strings.Join(item.Cells(), " | "))
	}
	return nil
}

// buildGroups creates the enabled backends. The returned function releases them.
func buildGroups(config *EntrypointConfig, fs afero.Fs) ([]backend.Group, func(), error) {
	var groups []backend.Group
	var closers []func() error

	if !config.Passwords.Disabled {
		g := &secretservice.Group{}
		groups = append(groups, g)
		closers = append(closers, g.Close)
	}

	if !config.PGP.Disabled {
		groups = append(groups, &pgp.Group{GPG: &pgp.GPG{Binary: config.PGP.Binary, Home: config.PGP.Home}})
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
		groups = append(groups, &sshkeys.Group{Dir: pathlib.NewPath(dir, pathlib.PathWithAfero(fs))})
	}

	closeAll := func() {
		for _, c := range closers {
			_ = c()
		}
	}
	return groups, closeAll, nil
}
