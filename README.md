# landhorse

![landhorse showing a PGP key](docs/screenshot.png)

A GTK3 manager for passwords, keyrings, PGP keys and SSH keys, modelled on GNOME's
[Seahorse](https://gitlab.gnome.org/GNOME/seahorse) ("Passwords and Keys") but with a
conventional desktop layout:

* a **menu bar and a labelled toolbar** instead of hamburger and popover menus;
* **three panes**: the type of thing on the left, a list of that type in the middle, and
  the details of the selected item on the right;
* **tree views** with sortable, resizable columns, a filter box, a status bar and a
  right-click menu.

## What it manages

| Type tree | Source | Actions |
|---|---|---|
| Passwords → each keyring | The Secret Service D-Bus API (gnome-keyring, KeePassXC) | Show and copy passwords, delete, lock and unlock keyrings |
| PGP Keys → GnuPG keys | The `gpg` command (`--with-colons`) | Copy or export public keys, import keys, delete |
| Secure Shell → OpenSSH keys | Key files in `~/.ssh` | Copy or export public keys, delete key pairs |

Showing or copying a password from a locked keyring brings up the system unlock prompt.
Every delete asks for confirmation and says exactly what will be removed.

Not done yet: creating passwords, keyrings and keys; editing; trust and signing; keyservers;
certificates (PKCS#11).

## Building

landhorse needs Go and the GTK3 development files (`sudo apt install libgtk-3-dev` on
Debian and Ubuntu). It uses cgo for GTK, so it builds natively on Linux only.

```sh
go run mage.go binary
./landhorse
```

The first build compiles the GTK bindings and takes a couple of minutes.

## Usage

```sh
landhorse                       # open the window
landhorse --category ssh:/home/me/.ssh
landhorse list                  # print every category and item to the terminal
```

`list` prints category keys, which `--category` accepts to pick the startup selection.

Keyboard: F5 refreshes, Ctrl+F filters the list, Ctrl+O imports, Ctrl+S exports, Ctrl+L
locks. In the item list, Ctrl+C copies and Delete deletes.

## Configuration

landhorse reads `~/.config/landhorse/landhorse.yml` if it exists, or the file named by
`--config-file`. Every key is optional; `landhorse.yml` in this repository lists them with
their defaults. You can hide a backend, point it at a different GnuPG home or SSH
directory, or use a different `gpg` binary.

## Layout

| Path | Purpose |
|---|---|
| `cmd/landhorse` | `main`, which only calls the entrypoint. |
| `pkg/entrypoints/landhorse` | Command line, config and logging; the `run` and `list` commands. |
| `pkg/backend` | The toolkit-independent model the UI renders: groups, categories, items, details and optional actions. |
| `pkg/secretservice` | Secret Service D-Bus client and its backend. |
| `pkg/pgp` | `gpg --with-colons` parser and its backend. |
| `pkg/sshkeys` | `~/.ssh` scanner and its backend. |
| `pkg/ui` | The GTK3 window. The only package that uses cgo. |
| `tools/sandbox` | Runs landhorse on a virtual display against throwaway keys, for UI testing. |

See `AGENTS.md` for development conventions.
