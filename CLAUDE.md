# landhorse

Read `AGENTS.md` for the project's conventions, build commands and UI testing sandbox.

## Exception to the global GPG key rules (approved 2026-10-03)

landhorse's tests and `tools/sandbox` may generate **disposable** GPG keys and revocation
certificates in temporary `GNUPGHOME` directories, because testing a key manager against
the user's real `~/.gnupg` would add, revoke or delete real keys. Limits:

- Only in temporary directories that are deleted afterwards: `t.TempDir()` in Go tests, and
  the sandbox state directory, whose keys `tools/sandbox/stop.sh` deletes.
- Never in `~/.gnupg`, and never committed: no private keys, revocation certificates or
  key backups in the repository. Test fixtures, if any, are public keys only.
- Keys made for the user's own use still follow the global rules.
