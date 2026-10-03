# landhorse

Read `AGENTS.md` for the project's conventions, build commands and UI testing sandbox.

## Release signing (not set up yet)

The release workflow signs PPA uploads with a key from the repository secrets
`PACKAGE_SIGNING_KEY` and `PACKAGE_SIGNING_KEY_PASSPHRASE` (fingerprint in the variable
`PACKAGE_SIGNING_KEY_FINGERPRINT`), following the user's ks3fs project, and uploads to COPR
with the secret `COPR_CONFIG`. On 2026-10-04 the user chose CI publishing on version tags;
the repository isn't on GitHub yet, so no secret has been set and no key exported.

Which key goes into those secrets needs the user's explicit approval at the time: ks3fs
uses their shared Launchpad key (`2A12 8435 A6FE 8BD7 51AA 5787 2095 9AB8 0709 6ADB`), and
its approval covers only ks3fs's secrets. Once approved, record the key and the secrets
here, and set them by piping (`gpg --export-secret-keys --armor FPR | gh secret set
PACKAGE_SIGNING_KEY`), never through a file. The passphrase comes from the login keyring.

## Exception to the global GPG key rules (approved 2026-10-03)

landhorse's tests and `tools/sandbox` may generate **disposable** GPG keys and revocation
certificates in temporary `GNUPGHOME` directories, because testing a key manager against
the user's real `~/.gnupg` would add, revoke or delete real keys. Limits:

- Only in temporary directories that are deleted afterwards: `t.TempDir()` in Go tests, and
  the sandbox state directory, whose keys `tools/sandbox/stop.sh` deletes.
- Never in `~/.gnupg`, and never committed: no private keys, revocation certificates or
  key backups in the repository. Test fixtures, if any, are public keys only.
- Keys made for the user's own use still follow the global rules.
