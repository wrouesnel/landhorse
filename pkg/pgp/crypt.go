package pgp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

var _ backend.Crypter = (*Item)(nil)

// unusableReason says why the key can't be used at all, or returns "".
func (k *Key) unusableReason() string {
	switch k.Validity {
	case "r":
		return "This key has been revoked."
	case "e":
		return "This key has expired."
	case "i":
		return "This key is invalid."
	case "d":
		return "This key is disabled."
	}
	return ""
}

// CanEncrypt implements backend.Crypter. gpg marks a key usable for encryption with an
// upper case E in its key-wide capabilities.
func (i *Item) CanEncrypt() (bool, string) {
	k := i.PGPKey
	if why := k.unusableReason(); why != "" {
		return false, why
	}
	if !strings.Contains(k.Capabilities, "E") {
		return false, "This key has no subkey that can encrypt."
	}
	return true, ""
}

// CanSign implements backend.Crypter: the secret part must be here and the key able to sign.
func (i *Item) CanSign() (bool, string) {
	k := i.PGPKey
	if !k.HasSecret() {
		return false, "Only the owner of the private key can sign with it."
	}
	if why := k.unusableReason(); why != "" {
		return false, why
	}
	if !strings.Contains(k.Capabilities, "S") {
		return false, "This key has no subkey that can sign."
	}
	return true, ""
}

// EncryptionWarning implements backend.Crypter: a warning when gpg can't confirm the key
// belongs to its owner, which encrypting to it accepts.
func (i *Item) EncryptionWarning() string {
	switch i.PGPKey.Validity {
	case "f", "u":
		return ""
	}
	uid := i.PGPKey.PrimaryUserID().Raw
	return fmt.Sprintf("gpg can't confirm that this key belongs to %s (its validity is %s): nobody you "+
		"trust has certified it. Only encrypt to it if you've checked its fingerprint with them.",
		uid, strings.ToLower(ValidityName(i.PGPKey.Validity)))
}

// encryptArgs are the gpg options to encrypt to this key. A full fingerprint names exactly
// this key, and gpg picks its encryption subkey (a trailing "!" would force the primary
// key, which often can only sign). trustAnyway accepts a key gpg hasn't verified, after the
// user has confirmed EncryptionWarning.
func (i *Item) encryptArgs(trustAnyway bool) []string {
	args := []string{"--recipient", i.PGPKey.Fingerprint}
	if trustAnyway {
		args = append(args, "--trust-model", "always")
	}
	return args
}

// signArgs are the gpg options to sign with this key's signing subkey.
func (i *Item) signArgs() []string {
	return []string{"--local-user", i.PGPKey.Fingerprint}
}

// EncryptFile implements backend.Crypter, writing a binary OpenPGP message.
func (i *Item) EncryptFile(ctx context.Context, in, out string, trustAnyway bool) error {
	if ok, why := i.CanEncrypt(); !ok {
		return errors.New(why)
	}
	args := append(i.encryptArgs(trustAnyway), "--yes", "--output", out, "--encrypt", "--", in)
	_, _, err := i.GPG.runWith(ctx, invocation{interactive: true}, append([]string{"--batch"}, args...)...)
	return err
}

// SignFile implements backend.Crypter, writing a binary detached signature. gpg-agent asks
// for the key's passphrase if it isn't cached.
func (i *Item) SignFile(ctx context.Context, in, out string) error {
	if ok, why := i.CanSign(); !ok {
		return errors.New(why)
	}
	args := append(i.signArgs(), "--yes", "--output", out, "--detach-sign", "--", in)
	_, _, err := i.GPG.runWith(ctx, invocation{interactive: true}, append([]string{"--batch"}, args...)...)
	return err
}

// EncryptText implements backend.Crypter, returning an ASCII armored message.
func (i *Item) EncryptText(ctx context.Context, text string, trustAnyway bool) (string, error) {
	if ok, why := i.CanEncrypt(); !ok {
		return "", errors.New(why)
	}
	args := append([]string{"--batch", "--armor"}, i.encryptArgs(trustAnyway)...)
	out, _, err := i.GPG.runWith(ctx, invocation{interactive: true, stdin: []byte(text)}, append(args, "--encrypt")...)
	return string(out), err
}

// SignText implements backend.Crypter, returning the text clear-signed.
func (i *Item) SignText(ctx context.Context, text string) (string, error) {
	if ok, why := i.CanSign(); !ok {
		return "", errors.New(why)
	}
	args := append([]string{"--batch"}, i.signArgs()...)
	out, _, err := i.GPG.runWith(ctx, invocation{interactive: true, stdin: []byte(text)}, append(args, "--clearsign")...)
	return string(out), err
}

// CryptName implements backend.Crypter: who files are encrypted to.
func (i *Item) CryptName() string {
	uid := i.PGPKey.PrimaryUserID()
	if uid.Name() != "" {
		return uid.Name()
	}
	return uid.Raw
}
