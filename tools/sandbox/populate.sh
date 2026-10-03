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
rm -rf "$HOME" "$XDG_RUNTIME_DIR" "$STATE/published" "$STATE/published-2"
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
quiet gpg "${nopass[@]}" --quick-generate-key "Alice Example <alice@example.com>" future-default default 2y
quiet gpg "${nopass[@]}" --quick-add-uid alice@example.com "Alice Example (work) <alice@work.example>"
# A private key with a passphrase ("sandbox"), to exercise gpg-agent's passphrase prompt.
quiet gpg --batch --pinentry-mode loopback --passphrase sandbox \
    --quick-generate-key "Pat Passphrase <pat@example.com>" future-default default never

other=$(mktemp -d "$STATE/other.XXXXXX"); chmod 700 "$other"
og() { quiet gpg --homedir "$other" "${nopass[@]}" "$@"; }
og --quick-generate-key "Bob Builder <bob@example.org>" rsa3072 default never
og --quick-add-key "$(gpg --homedir "$other" --with-colons --list-keys bob@example.org | awk -F: '/^fpr/{print $10; exit}')" rsa3072 encr never
sleep 1 # so the second user ID's self-signature is newer
og --quick-add-uid bob@example.org "Bob Builder (site foreman) <bob@site.example>"
og --quick-generate-key "Erin Unknown <erin@example.net>" future-default default never
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
# Frank isn't imported: his key is only on the fake keyserver, and he has signed Bob's key,
# so double-clicking his signature searches the keyserver.
og --quick-generate-key "Frank Faraway <frank@faraway.example>" future-default default never
frank=$(gpg --homedir "$other" --with-colons --list-keys frank@faraway.example | awk -F: '/^fpr/{print $10; exit}')
og -u "$frank" --yes --quick-sign-key \
    "$(gpg --homedir "$other" --with-colons --list-keys bob@example.org | awk -F: '/^fpr/{print $10; exit}')"
mkdir -p "$STATE/published"
gpg --homedir "$other" --armor --export "$frank" > "$STATE/published/frank.asc"
gpg --homedir "$other" --armor --export bob@example.org erin@example.net carol@example.net dave@example.net \
    > "$HOME/others.asc"
gpgconf --homedir "$other" --kill all; rm -rf "$other" "$STATE/dave.rev"
quiet gpg --batch --import "$HOME/others.asc"
quiet gpg "${nopass[@]}" --yes --quick-sign-key \
    "$(gpg --with-colons --list-keys bob@example.org | awk -F: '/^fpr/{print $10; exit}')"

# A fake keyserver, so Publish never reaches a real one. Uploads land in $STATE/published.
"$(dirname "$0")/hkp-stub.py" 11371 "$STATE/published" &
# A second, empty keyserver, so searching all keyservers can be compared with one.
"$(dirname "$0")/hkp-stub.py" 11372 "$STATE/published-2" &
# Fake security keys: a PIV card with a self-signed certificate and a FIDO2 key (PIN 123456).
export LANDHORSE_SANDBOX_STATE=$STATE
rm -f "$STATE/fido-deleted"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj "/CN=Alice Example (PIV Authentication)/O=Example Corp" -addext "subjectAltName=email:alice@example.com" \
    -addext "extendedKeyUsage=clientAuth" -keyout /dev/null -out "$STATE/piv-cert.pem" 2>/dev/null

mkdir -p "$XDG_CONFIG_HOME/landhorse"
cat > "$XDG_CONFIG_HOME/landhorse/landhorse.yml" <<YAML
pgp:
  keyservers:
    - hkp://127.0.0.1:11371 Sandbox keyserver
    - hkp://127.0.0.1:11372 Empty keyserver
security_keys:
  p11tool: $(dirname "$0")/fake-p11tool
  fido2_token: $(dirname "$0")/fake-fido2-token
YAML

# SSH: an unencrypted pair, a passphrase protected pair, and a lone public key.
ssh-keygen -q -t ed25519 -N '' -C alice@laptop -f "$HOME/.ssh/id_ed25519"
ssh-keygen -q -t rsa -b 3072 -N 'pw' -C alice@work -f "$HOME/.ssh/work_rsa"
ssh-keygen -q -t ecdsa -N '' -C deploy@ci -f "$STATE/deploy"
mv "$STATE/deploy.pub" "$HOME/.ssh/deploy.pub"; rm -f "$STATE/deploy"
cp "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/authorized_keys"

# The sandbox's own SSH agent, never the user's: in the foreground (-D) so it stays in the
# sandbox's process group and stop.sh ends it. It holds id_ed25519 and a key with no file.
# Unix socket paths are limited to about 100 characters, so the socket goes in a short
# directory under /tmp, which stop.sh removes.
agent_dir=$(mktemp -d /tmp/landhorse-agent.XXXXXX)
echo "$agent_dir" > "$STATE/agent-dir"
export SSH_AUTH_SOCK=$agent_dir/agent.sock
ssh-agent -D -a "$SSH_AUTH_SOCK" >/dev/null &
for _ in $(seq 1 20); do [ -S "$SSH_AUTH_SOCK" ] && break; sleep 0.1; done
ssh-add -q "$HOME/.ssh/id_ed25519"
ssh-keygen -q -t ed25519 -N '' -C agent-only@sandbox -f "$STATE/agent-only"
ssh-add -q "$STATE/agent-only"; rm -f "$STATE/agent-only" "$STATE/agent-only.pub"

# Passwords related to the keys above, stored the way gpg-agent and gnome-keyring's SSH
# agent store them, so the detail view lists them under Related Items.
pat_grip=$(gpg --with-colons --with-keygrip --list-secret-keys pat@example.com | awk -F: '/^grp/{print $10; exit}')
printf sandbox | secret-tool store --label="GnuPG: n/$pat_grip" \
    xdg:schema org.gnupg.Passphrase keygrip "n/$pat_grip" stored-by "GnuPG Pinentry"
printf pw | secret-tool store --label="Unlock password for: alice@work" \
    unique "ssh-store:$HOME/.ssh/work_rsa"
# More network passwords, so they group by host.
printf 'imap-pass' | secret-tool store --label="alice@mail.example.com (IMAP)" \
    xdg:schema org.gnome.keyring.NetworkPassword server mail.example.com protocol imap user alice
printf 'smtp-pass' | secret-tool store --label="alice@mail.example.com (SMTP)" \
    xdg:schema org.gnome.keyring.NetworkPassword server mail.example.com protocol smtp user alice
printf 'vault-token' | secret-tool store --label="Vault token" service "https://vault.example.net:8200/"

touch "$STATE/ready"
exec "$@"
