#!/bin/bash
# populate.sh STATE_DIR COMMAND... - runs inside xvfb-run and dbus-run-session (see start.sh).
#
# Builds a throwaway HOME in STATE_DIR with its own gnome-keyring (password "sandbox"),
# GnuPG keys and SSH keys, then execs COMMAND. Nothing here touches the real user's
# keyring, ~/.gnupg or ~/.ssh: the keyring daemon is on the private session bus and every
# tool is pointed at the throwaway HOME.
set -euo pipefail
STATE=$1; shift

export HOME=$STATE/home
export XDG_CONFIG_HOME=$HOME/.config XDG_DATA_HOME=$HOME/.local/share XDG_RUNTIME_DIR=$STATE/run
export GNUPGHOME=$HOME/.gnupg
rm -rf "$HOME" "$XDG_RUNTIME_DIR"
mkdir -p "$HOME/.ssh" "$GNUPGHOME" "$XDG_DATA_HOME/keyrings" "$XDG_RUNTIME_DIR"
chmod 700 "$HOME/.ssh" "$GNUPGHOME" "$XDG_RUNTIME_DIR"

# Keyring: an unlocked "login" keyring with a few passwords.
eval "$(printf sandbox | gnome-keyring-daemon --unlock --components=secrets)"
sleep 1
printf 'correct horse battery staple' | secret-tool store --label="Mail account" service imap.example.com user alice
printf 's3cr3t-token' | secret-tool store --label="GitHub token" service github.com user alice
printf 'wifi-pass' | secret-tool store --label="Home Wi-Fi" xdg:schema org.gnome.keyring.NetworkPassword server router.lan
printf 'deleteme' | secret-tool store --label="Old password" service old.example.com

# GnuPG: a personal key with two user IDs, and someone else's public key.
gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Alice Example <alice@example.com>" ed25519 default 2y 2>/dev/null
gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-uid alice@example.com "Alice Example (work) <alice@work.example>" 2>/dev/null
other=$(mktemp -d "$STATE/other.XXXXXX"); chmod 700 "$other"
gpg --homedir "$other" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Bob Builder <bob@example.org>" rsa3072 default never 2>/dev/null
gpg --homedir "$other" --armor --export bob@example.org > "$HOME/bob.asc"
gpgconf --homedir "$other" --kill all; rm -rf "$other"
gpg --batch --import "$HOME/bob.asc" 2>/dev/null

# SSH: an unencrypted pair, a passphrase protected pair, and a lone public key.
ssh-keygen -q -t ed25519 -N '' -C alice@laptop -f "$HOME/.ssh/id_ed25519"
ssh-keygen -q -t rsa -b 3072 -N 'pw' -C alice@work -f "$HOME/.ssh/work_rsa"
ssh-keygen -q -t ecdsa -N '' -C deploy@ci -f "$STATE/deploy"
mv "$STATE/deploy.pub" "$HOME/.ssh/deploy.pub"; rm -f "$STATE/deploy"
cp "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/authorized_keys"

touch "$STATE/ready"
exec "$@"
