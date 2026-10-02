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
rm -rf "$HOME" "$XDG_RUNTIME_DIR" "$STATE/published"
mkdir -p "$HOME/.ssh" "$GNUPGHOME" "$XDG_DATA_HOME/keyrings" "$XDG_RUNTIME_DIR"
chmod 700 "$HOME/.ssh" "$GNUPGHOME" "$XDG_RUNTIME_DIR"

# Keyring: an unlocked "login" keyring with a few passwords.
eval "$(printf sandbox | gnome-keyring-daemon --unlock --components=secrets)"
sleep 1
printf 'correct horse battery staple' | secret-tool store --label="Mail account" service imap.example.com user alice
printf 's3cr3t-token' | secret-tool store --label="GitHub token" service github.com user alice
printf 'wifi-pass' | secret-tool store --label="Home Wi-Fi" xdg:schema org.gnome.keyring.NetworkPassword server router.lan
printf 'deleteme' | secret-tool store --label="Old password" service old.example.com

# GnuPG: a private key (Ultimate) with two user IDs, and other people's public keys at
# each validity: Bob signed by Alice (Full), Erin unsigned (Unknown), Carol expired and
# Dave revoked.
quiet() { "$@" >/dev/null 2>&1; }
nopass=(--batch --pinentry-mode loopback --passphrase '')
quiet gpg "${nopass[@]}" --quick-generate-key "Alice Example <alice@example.com>" ed25519 default 2y
quiet gpg "${nopass[@]}" --quick-add-uid alice@example.com "Alice Example (work) <alice@work.example>"
# A private key with a passphrase ("sandbox"), to exercise gpg-agent's passphrase prompt.
quiet gpg --batch --pinentry-mode loopback --passphrase sandbox \
    --quick-generate-key "Pat Passphrase <pat@example.com>" ed25519 default never

other=$(mktemp -d "$STATE/other.XXXXXX"); chmod 700 "$other"
og() { quiet gpg --homedir "$other" "${nopass[@]}" "$@"; }
og --quick-generate-key "Bob Builder <bob@example.org>" rsa3072 default never
sleep 1 # so the second user ID's self-signature is newer
og --quick-add-uid bob@example.org "Bob Builder (site foreman) <bob@site.example>"
og --quick-generate-key "Erin Unknown <erin@example.net>" ed25519 default never
og --faked-system-time 20200101T000000 --quick-generate-key "Carol Expired <carol@example.net>" ed25519 default 1y
og --quick-generate-key "Dave Revoked <dave@example.net>" ed25519 default never
# gpg writes a revocation certificate for each new key, with its armor line prefixed by ":"
# to stop accidental import.
dave=$(gpg --homedir "$other" --with-colons --list-keys dave@example.net | awk -F: '/^fpr/{print $10; exit}')
sed 's/^:-----BEGIN/-----BEGIN/' "$other/openpgp-revocs.d/$dave.rev" > "$STATE/dave.rev"
# Keep Erin's revocation certificate as gpg saved it (colon guard and all), to test revoking
# a key whose secret part isn't here.
erin=$(gpg --homedir "$other" --with-colons --list-keys erin@example.net | awk -F: '/^fpr/{print $10; exit}')
cp "$other/openpgp-revocs.d/$erin.rev" "$HOME/erin.rev"
og --import "$STATE/dave.rev"
gpg --homedir "$other" --armor --export > "$HOME/others.asc"
gpgconf --homedir "$other" --kill all; rm -rf "$other" "$STATE/dave.rev"
quiet gpg --batch --import "$HOME/others.asc"
quiet gpg "${nopass[@]}" --yes --quick-sign-key \
    "$(gpg --with-colons --list-keys bob@example.org | awk -F: '/^fpr/{print $10; exit}')"

# A fake keyserver, so Publish never reaches a real one. Uploads land in $STATE/published.
"$(dirname "$0")/hkp-stub.py" 11371 "$STATE/published" &
mkdir -p "$XDG_CONFIG_HOME/landhorse"
cat > "$XDG_CONFIG_HOME/landhorse/landhorse.yml" <<YAML
pgp:
  keyservers:
    - hkp://127.0.0.1:11371 Sandbox keyserver
YAML

# SSH: an unencrypted pair, a passphrase protected pair, and a lone public key.
ssh-keygen -q -t ed25519 -N '' -C alice@laptop -f "$HOME/.ssh/id_ed25519"
ssh-keygen -q -t rsa -b 3072 -N 'pw' -C alice@work -f "$HOME/.ssh/work_rsa"
ssh-keygen -q -t ecdsa -N '' -C deploy@ci -f "$STATE/deploy"
mv "$STATE/deploy.pub" "$HOME/.ssh/deploy.pub"; rm -f "$STATE/deploy"
cp "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/authorized_keys"

touch "$STATE/ready"
exec "$@"
