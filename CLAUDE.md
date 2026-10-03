# landhorse

Read `AGENTS.md` for the project's conventions, build commands and UI testing sandbox.

## Approved GPG key exception: release signing (approved 2026-10-04)

PPA uploads are signed in CI with the user's shared Launchpad signing key. The user approved
exporting it to this repository's CI secrets on 2026-10-04 ("Launchpad signing key").

- Key: `2A12 8435 A6FE 8BD7 51AA 5787 2095 9AB8 0709 6ADB`, "Will Rouesnel (GPG key for launchpad
  signing)", registered on Launchpad as `~w-rouesnel`; here for `ppa:w-rouesnel/landhorse`.
- It is exported only to the GitHub repository secrets `PACKAGE_SIGNING_KEY` and
  `PACKAGE_SIGNING_KEY_PASSPHRASE` of `wrouesnel/landhorse`, with the fingerprint in the
  repository variable `PACKAGE_SIGNING_KEY_FINGERPRINT`. They were set by piping from gpg
  and the login keyring into `gh secret set`, never through a file. The release workflow uses
  them to sign source uploads on version tags.
- The passphrase lives in the login keyring and is looked up only as
  `secret-tool lookup service gpg-passphrase fingerprint 2A128435A6FE8BD751AA578720959AB807096ADB`.
  Never print it.
- COPR uploads use the secret `COPR_CONFIG`, a copy of the user's `~/.config/copr` (API token
  for COPR user `wrouesnel`), approved the same day.
- This exception covers that key and those secrets only. Any other export of a release key
  still needs the user's approval first.

## Exception to the global GPG key rules (approved 2026-10-03)

landhorse's tests and `tools/sandbox` may generate **disposable** GPG keys and revocation
certificates in temporary `GNUPGHOME` directories, because testing a key manager against
the user's real `~/.gnupg` would add, revoke or delete real keys. Limits:

- Only in temporary directories that are deleted afterwards: `t.TempDir()` in Go tests, and
  the sandbox state directory, whose keys `tools/sandbox/stop.sh` deletes.
- Never in `~/.gnupg`, and never committed: no private keys, revocation certificates or
  key backups in the repository. Test fixtures, if any, are public keys only.
- Keys made for the user's own use still follow the global rules.
