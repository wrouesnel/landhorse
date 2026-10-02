package sshkeys_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"

	"github.com/wrouesnel/landhorse/pkg/sshkeys"
)

type keyFiles struct {
	private []byte
	public  []byte
	pub     ssh.PublicKey
}

func newKey(t *testing.T, comment string, passphrase string) keyFiles {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(privKey, comment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, comment, []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	line := append(ssh.MarshalAuthorizedKey(pub)[:len(ssh.MarshalAuthorizedKey(pub))-1], []byte(" "+comment+"\n")...)
	return keyFiles{private: pem.EncodeToMemory(block), public: line, pub: pub}
}

func write(t *testing.T, fs afero.Fs, path string, data []byte) {
	t.Helper()
	if err := afero.WriteFile(fs, path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	fs := afero.NewMemMapFs()
	dir := pathlib.NewPath("/home/user/.ssh", pathlib.PathWithAfero(fs))
	if err := dir.MkdirAll(); err != nil {
		t.Fatal(err)
	}

	pair := newKey(t, "user@laptop", "")
	write(t, fs, "/home/user/.ssh/id_ed25519", pair.private)
	write(t, fs, "/home/user/.ssh/id_ed25519.pub", pair.public)

	encrypted := newKey(t, "user@work", "hunter2")
	write(t, fs, "/home/user/.ssh/work", encrypted.private)

	lonePublic := newKey(t, "friend@elsewhere", "")
	write(t, fs, "/home/user/.ssh/friend.pub", lonePublic.public)

	// Files that must be ignored.
	write(t, fs, "/home/user/.ssh/config", []byte("Host *\n"))
	write(t, fs, "/home/user/.ssh/known_hosts", []byte("example.com ssh-ed25519 AAAA\n"))
	write(t, fs, "/home/user/.ssh/authorized_keys", pair.public)

	keys, err := sshkeys.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*sshkeys.Key{}
	for _, k := range keys {
		byName[k.Name] = k
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys (%v), want 3", len(keys), byName)
	}

	k := byName["id_ed25519"]
	if k == nil || k.PrivatePath == nil || k.PublicPath == nil {
		t.Fatalf("id_ed25519 should be a complete pair: %+v", k)
	}
	if k.Comment != "user@laptop" || k.Encrypted || !k.Authorized {
		t.Errorf("id_ed25519: comment %q encrypted %v authorized %v", k.Comment, k.Encrypted, k.Authorized)
	}
	if k.Algorithm() != "Ed25519" || k.Bits() != 256 {
		t.Errorf("id_ed25519: algorithm %q bits %d", k.Algorithm(), k.Bits())
	}
	if k.Fingerprint() != ssh.FingerprintSHA256(pair.pub) {
		t.Errorf("id_ed25519: fingerprint %q", k.Fingerprint())
	}

	w := byName["work"]
	if w == nil || !w.Encrypted || w.PublicPath != nil {
		t.Fatalf("work should be an encrypted lone private key: %+v", w)
	}
	if w.PublicKey == nil || w.Fingerprint() != ssh.FingerprintSHA256(encrypted.pub) {
		t.Error("work: public key should be derived from the encrypted OpenSSH private key")
	}

	f := byName["friend"]
	if f == nil || f.PrivatePath != nil || f.Authorized {
		t.Fatalf("friend should be an unauthorized lone public key: %+v", f)
	}
}

func TestScanMissingDirectory(t *testing.T) {
	keys, err := sshkeys.Scan(context.Background(), pathlib.NewPath("/nope", pathlib.PathWithAfero(afero.NewMemMapFs())))
	if err != nil || len(keys) != 0 {
		t.Fatalf("got %v, %v; want no keys and no error", keys, err)
	}
}

func TestDelete(t *testing.T) {
	fs := afero.NewMemMapFs()
	pair := newKey(t, "user@laptop", "")
	write(t, fs, "/ssh/id", pair.private)
	write(t, fs, "/ssh/id.pub", pair.public)

	cat := &sshkeys.Category{Dir: pathlib.NewPath("/ssh", pathlib.PathWithAfero(fs))}
	items, err := cat.Items(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("got %v, %v", items, err)
	}
	item := items[0].(*sshkeys.Item) //nolint:forcetypeassert
	if err := item.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/ssh/id", "/ssh/id.pub"} {
		if ok, _ := afero.Exists(fs, p); ok {
			t.Errorf("%s still exists", p)
		}
	}
}
