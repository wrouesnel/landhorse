Use README.md files to understand program intent and structure.

Binary outputs must build via `go run mage.go binary`.

Build without CGO, except for the GTK3 user interface: `pkg/ui` uses
[gotk3](https://github.com/gotk3/gotk3), which needs cgo, so the magefile builds with
`CGO_ENABLED=1`, links dynamically against the system GTK3 and only targets Linux. Keep cgo
confined to `pkg/ui`; every other package must stay pure Go. Building needs `libgtk-3-dev`.

Use the [afero package](https://github.com/spf13/afero) to abstract filesystem
access, ideally via the [pathlib package](https://github.com/chigopher/pathlib)
except in application startup entrypoints where no configuration has been loaded
yet.

If a web application is being developed then implement all endpoints using OpenAPI 3
and use `oapi-codegen` to build Echo v5 (`go get github.com/labstack/echo/v5`) based
servers.

Use the [zap logger](https://go.uber.org/zap) for logging and favor using the
[logutil package](https://github.com/wrouesnel/go.logutil). Any function taking
a `context.Context` should use `logutil.FromCtx` to get a context-aware logger.

Implement all binary applications as exportable packages under `pkg/entrypoints/<binary name>`
and keep code under `cmd/` to an absolute minimum. Replace `-` with `_` in the binary name to
get the package name, e.g. `cmd/foo-bar` is implemented by `pkg/entrypoints/foo_bar`. Each new
binary also needs an entry in `.gitignore` for the symlink `go run mage.go binary` creates.

Test entrypoints by calling `Entrypoint(ctx, args)` directly, as in
`pkg/entrypoints/landhorse/entrypoint_test.go`. The default command opens a window, so tests
use the `list` command, which runs the same backends without GTK.

## Build commands

Run all build commands from the repository root. `go run mage.go -l` lists every target.

* `go run mage.go binary` - build for the current platform into `bin/` and symlink it into
  the repository root.
* `go run mage.go test` - run the tests. `go run mage.go coverage` merges coverage into
  `.cover.out` afterwards.
* `go run mage.go lint` - run golangci-lint (configured by `.golangci.yml`).
* `go run mage.go style` - check formatting. `go run mage.go fmt` fixes it.

CI runs `style`, `lint`, `test` and `binary`, all of which must pass.

## Web interface

A web interface is optional. If `web/package.json` exists, the build installs the Node.js
version in `.nvmrc` and builds `web/` into `web/dist` for embedding. Otherwise the web build
is skipped. Set `SKIP_WEB=1` to skip it regardless.

## User interface

The window is a menu bar and toolbar over three panes: the type tree, the item list and the
detail view. Keep it conventional: actions belong in the toolbar and menus (never a
hamburger menu), lists are GtkTreeViews with sortable, resizable column headers, and
destructive actions always confirm.

Backends implement the interfaces in `pkg/backend`. The UI knows nothing about a specific
backend: it enables toolbar buttons from the optional interfaces (`Lockable`, `Importer`,
`Copier`, `Exporter`, `Deleter`) a selection implements. Backend calls block, so the UI runs
them through `App.background` and only touches widgets on the GTK main loop.

## Testing the user interface

Never test against the real user's keyring, `~/.gnupg` or `~/.ssh`: deleting, locking or
importing there changes real data. Use the sandbox, which runs landhorse on an Xvfb display
with a private D-Bus session, its own gnome-keyring (password `sandbox`) and throwaway keys:

```sh
go run mage.go binary
tools/sandbox/start.sh            # prints the DISPLAY and XAUTHORITY to use
DISPLAY=:77 XAUTHORITY=... xdotool mousemove 98 166 click 1
tools/sandbox/shot.sh name        # screenshot to $SANDBOX_STATE/name.png
tools/sandbox/stop.sh
```

Read-only commands such as `./landhorse list` are safe to run against real data.

Tests and the sandbox generate disposable GPG keys in temporary `GNUPGHOME`s only; see the
exception in `CLAUDE.md`. Never commit private keys or revocation certificates.
