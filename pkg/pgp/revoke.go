package pgp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

var _ backend.Revoker = (*Item)(nil)

// revocationReason is an OpenPGP key revocation reason (RFC 4880 section 5.2.3.23).
type revocationReason struct {
	// id is the answer to gpg --gen-revoke's reason menu.
	id    string
	code  int
	label string
}

// revocationReasons are the reasons gpg --gen-revoke offers, most common first.
//
//nolint:gochecknoglobals
var revocationReasons = []revocationReason{
	{id: "1", code: 0x02, label: "Key has been compromised"},
	{id: "2", code: 0x01, label: "Key is superseded"},
	{id: "3", code: 0x03, label: "Key is no longer used"},
	{id: "0", code: 0x00, label: "No reason specified"},
}

func reasonLabel(code int) string {
	for _, r := range revocationReasons {
		if r.code == code {
			return r.label
		}
	}
	return fmt.Sprintf("Reason 0x%02x", code)
}

// revocationSig is a key revocation signature found by gpg --list-packets.
type revocationSig struct {
	keyID       string
	fingerprint string
	reason      int
	description string
}

//nolint:gochecknoglobals
var (
	packetKeyID  = regexp.MustCompile(`^:signature packet: algo \d+, keyid ([0-9A-F]+)`)
	packetClass  = regexp.MustCompile(`sigclass 0x([0-9a-f]+)`)
	packetIssuer = regexp.MustCompile(`\(issuer fpr v\d+ ([0-9A-F]+)\)`)
	packetReason = regexp.MustCompile(`\(revocation reason 0x([0-9a-f]+) \((.*)\)\)`)
)

// parseRevocations finds the key revocation signatures (class 0x20) in gpg --list-packets
// output.
func parseRevocations(listing string) []revocationSig {
	var sigs []revocationSig
	var current *revocationSig
	isRevocation := false
	flush := func() {
		if current != nil && isRevocation {
			sigs = append(sigs, *current)
		}
		current, isRevocation = nil, false
	}

	scanner := bufio.NewScanner(strings.NewReader(listing))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ":") {
			// A new packet starts.
			flush()
			if m := packetKeyID.FindStringSubmatch(line); m != nil {
				current = &revocationSig{keyID: m[1], reason: -1}
			}
			continue
		}
		if current == nil {
			continue
		}
		if m := packetClass.FindStringSubmatch(line); m != nil {
			isRevocation = m[1] == "20"
		}
		if m := packetIssuer.FindStringSubmatch(line); m != nil {
			current.fingerprint = m[1]
		}
		if m := packetReason.FindStringSubmatch(line); m != nil {
			code, _ := strconv.ParseInt(m[1], 16, 32)
			current.reason = int(code)
			current.description = strings.ReplaceAll(m[2], `\n`, "\n")
		}
	}
	flush()
	return sigs
}

// normalizeCertificate trims a pasted certificate and undoes the ":" gpg puts in front of
// the armor line of the certificates it saves in openpgp-revocs.d, which stops them being
// imported by accident.
func normalizeCertificate(cert string) []byte {
	lines := strings.Split(strings.TrimSpace(cert), "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, ":-----") {
			line = line[1:]
		}
		lines[i] = line
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// withScratchHome runs fn with a temporary GnuPG home, removed afterwards along with any
// gpg daemons started in it. Only public keys are ever put in it.
func (g *GPG) withScratchHome(ctx context.Context, fn func(home string) error) error {
	// gpg needs a real directory, so this can't go through afero.
	home, err := os.MkdirTemp("", "landhorse-gpg-")
	if err != nil {
		return err
	}
	defer func() {
		gpgconf := "gpgconf"
		if g.Binary != "" && strings.Contains(g.Binary, "/") {
			gpgconf = filepath.Join(filepath.Dir(g.Binary), "gpgconf")
		}
		_ = exec.CommandContext(ctx, gpgconf, "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	}()
	return fn(home)
}

// CheckRevocation verifies that cert is a valid revocation certificate for the key and
// returns a description of it.
//
// It checks the packets first, to give a specific error for the common mistakes, then
// proves the signature by importing the key's public part and the certificate into a
// scratch keyring and checking that the key comes out revoked. The user's keyring is not
// touched.
func (i *Item) CheckRevocation(ctx context.Context, cert string) (string, error) {
	data := normalizeCertificate(cert)
	if len(strings.TrimSpace(string(data))) == 0 {
		return "", errors.New("choose, drop or paste a revocation certificate")
	}
	k := i.PGPKey

	listing, _, err := i.GPG.runWith(ctx, invocation{stdin: data, interactive: true}, "--list-packets")
	if err != nil {
		return "", errors.New("this isn't an OpenPGP revocation certificate")
	}
	sigs := parseRevocations(string(listing))
	if len(sigs) == 0 {
		return "", errors.New("this doesn't contain a key revocation; it may be a public key or an ordinary signature")
	}
	var match *revocationSig
	for idx := range sigs {
		s := &sigs[idx]
		if strings.EqualFold(s.fingerprint, k.Fingerprint) || strings.EqualFold(s.keyID, k.KeyID) {
			match = s
			break
		}
	}
	if match == nil {
		return "", fmt.Errorf("this certificate revokes a different key (%s), not %s",
			shortKeyID(sigs[0].keyID), shortKeyID(k.KeyID))
	}

	public, err := i.GPG.ExportPublic(ctx, k.Fingerprint)
	if err != nil {
		return "", err
	}
	err = i.GPG.withScratchHome(ctx, func(home string) error {
		if _, _, err := i.GPG.runWith(ctx, invocation{home: home, stdin: public}, "--import"); err != nil {
			return err
		}
		if _, _, err := i.GPG.runWith(ctx, invocation{home: home, stdin: data}, "--import"); err != nil {
			return errors.New("gpg rejected the certificate")
		}
		out, _, err := i.GPG.runWith(ctx, invocation{home: home}, "--list-keys", k.Fingerprint)
		if err != nil {
			return err
		}
		keys, err := ParseColons(strings.NewReader(string(out)))
		if err != nil {
			return err
		}
		if len(keys) != 1 || keys[0].Validity != "r" {
			return errors.New("the certificate's signature isn't valid for this key")
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	desc := fmt.Sprintf("Valid revocation certificate for %s.\nReason: %s", shortKeyID(k.KeyID), reasonLabel(match.reason))
	if match.description != "" {
		desc += "\n“" + match.description + "”"
	}
	return desc, nil
}

// Revoked implements backend.Revoker.
func (i *Item) Revoked() bool { return i.PGPKey.Validity == "r" }

// RevokeTargets implements backend.Revoker: revocations are published to the keyservers.
func (i *Item) RevokeTargets() []backend.Choice { return i.PublishTargets() }

// Revoke implements backend.Revoker. It checks cert, imports it into the keyring, which
// revokes the key here, then publishes the revoked key to target so others learn of it.
func (i *Item) Revoke(ctx context.Context, cert string, target string) (string, error) {
	if _, err := i.CheckRevocation(ctx, cert); err != nil {
		return "", err
	}
	if _, _, err := i.GPG.runWith(ctx, invocation{stdin: normalizeCertificate(cert)}, "--import"); err != nil {
		return "", fmt.Errorf("importing the revocation: %w", err)
	}
	report, err := i.GPG.SendKey(ctx, target, i.PGPKey.Fingerprint)
	if err != nil {
		return "", fmt.Errorf("the key is now revoked in your keyring, but publishing the revocation "+
			"to %s failed, so nobody else knows yet. Use Publish… to try again.\n\n%w", target, err)
	}
	return "The key is revoked and the revocation was published to " + target + ".\n\n" + report, nil
}

// CanGenerateRevocation implements backend.Revoker. A revocation must be signed by the
// primary secret key.
func (i *Item) CanGenerateRevocation() (bool, string) {
	k := i.PGPKey
	switch {
	case k.Secret:
		return true, ""
	case k.HasSecret():
		return false, "Only subkeys are on this computer. A revocation must be signed by the " +
			"primary key, so make it where the primary key is kept."
	default:
		return false, "This key's secret part isn't on this computer, so only its owner can make " +
			"a revocation certificate."
	}
}

// ConfirmationCode implements backend.Revoker: the last eight digits of the key ID, the
// short ID people often know a key by.
func (i *Item) ConfirmationCode() string {
	id := i.PGPKey.KeyID
	if len(id) > 8 {
		return id[len(id)-8:]
	}
	return id
}

// RevocationReasons implements backend.Revoker.
func (i *Item) RevocationReasons() []backend.Choice {
	choices := make([]backend.Choice, 0, len(revocationReasons))
	for _, r := range revocationReasons {
		choices = append(choices, backend.Choice{ID: r.id, Label: r.label})
	}
	return choices
}

// GenerateRevocation implements backend.Revoker. gpg signs the certificate with the
// primary secret key; if that has a passphrase, gpg-agent asks for it with the system's
// pinentry prompt.
func (i *Item) GenerateRevocation(ctx context.Context, reason string, description string) (string, error) {
	if ok, why := i.CanGenerateRevocation(); !ok {
		return "", errors.New(why)
	}
	valid := false
	for _, r := range revocationReasons {
		valid = valid || r.id == reason
	}
	if !valid {
		return "", fmt.Errorf("unknown revocation reason %q", reason)
	}

	// Answers to --gen-revoke's prompts: confirm, reason, description lines ended by an
	// empty line, confirm again.
	var answers strings.Builder
	answers.WriteString("y\n" + reason + "\n")
	for _, line := range strings.Split(description, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			answers.WriteString(line + "\n")
		}
	}
	answers.WriteString("\ny\n")

	out, _, err := i.GPG.runWith(ctx, invocation{stdin: []byte(answers.String()), interactive: true},
		"--command-fd", "0", "--armor", "--gen-revoke", i.PGPKey.Fingerprint)
	if err != nil {
		return "", err
	}
	if !strings.Contains(string(out), "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return "", errors.New("gpg did not produce a revocation certificate")
	}
	return string(out), nil
}
