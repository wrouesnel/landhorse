package securitykeys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wrouesnel/landhorse/pkg/backend"
	"github.com/wrouesnel/landhorse/pkg/securitykeys"
)

// script writes an executable shell script.
func script(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/bash\n"+body), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	return path
}

func testCertificate(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(0xBEEF),
		Subject:        pkix.Name{CommonName: "Alice PIV Authentication"},
		NotBefore:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:       time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{"alice@example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// fakeP11tool answers like p11tool with the system trust store, an uninitialised TPM and
// one PIV card holding a certificate.
func fakeP11tool(t *testing.T) string {
	t.Helper()
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(certFile, []byte(testCertificate(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	return script(t, "p11tool", `
case "$*" in
"--batch --list-tokens")
	printf 'Token 0:\n\tURL: pkcs11:model=p11-kit-trust\n\tLabel: System Trust\n\tType: Trust module\n\tFlags: uPIN uninitialized\n\tManufacturer: PKCS#11 Kit\n\tModel: p11-kit-trust\n\n'
	printf 'Token 1:\n\tURL: pkcs11:model=AMD\n\tLabel: \n\tType: Hardware token\n\tFlags: RNG, Requires login, Uninitialized, uPIN uninitialized\n\tManufacturer: AMD\n\tModel: AMD\n\n'
	printf 'Token 2:\n\tURL: pkcs11:model=PKCS%%2315%%20emulated;token=Alice%%20PIV\n\tLabel: Alice PIV\n\tType: Hardware token\n\tFlags: RNG, Requires login, Token initialized, PIN initialized\n\tManufacturer: piv_II\n\tModel: PKCS#15 emulated\n\tSerial: 00a1b2c3\n\n'
	;;
"--batch --list-all pkcs11:model=PKCS%2315%20emulated;token=Alice%20PIV")
	printf 'Object 0:\n\tURL: pkcs11:token=Alice%%20PIV;object=Certificate%%20for%%20PIV%%20Authentication;type=cert\n\tType: X.509 Certificate (EC/ECDSA-SECP256R1)\n\tExpires: Fri Jan  1 00:00:00 2027\n\tLabel: Certificate for PIV Authentication\n\tID: 01\n\n'
	printf 'Object 1:\n\tURL: pkcs11:token=Alice%%20PIV;object=PIV%%20AUTH%%20pubkey;type=public\n\tType: Public key (EC/ECDSA-SECP256R1)\n\tLabel: PIV AUTH pubkey\n\tID: 01\n\n'
	;;
"--batch --export pkcs11:token=Alice%20PIV;object=Certificate%20for%20PIV%20Authentication;type=cert")
	cat `+certFile+`
	;;
*)
	echo "unexpected: $*" >&2; exit 1 ;;
esac
`)
}

func TestSmartCards(t *testing.T) {
	ctx := context.Background()
	g := &securitykeys.Group{P11: &securitykeys.P11{Binary: fakeP11tool(t)},
		FIDO: &securitykeys.FIDO{Binary: script(t, "fido2-token", "exit 0\n")}}
	cats, err := g.Categories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cards := cats[0]
	children := cards.(backend.Parent).Children()
	if len(children) != 1 || children[0].Title() != "Alice PIV" {
		t.Fatalf("tokens (trust store and blank TPM must be left out): %v", children)
	}
	items, err := cards.Items(ctx)
	if err != nil || len(items) != 2 {
		t.Fatalf("items: %v %v", items, err)
	}
	if cells := items[0].Cells(); cells[0] != "Certificate for PIV Authentication" || cells[2] != "Alice PIV" {
		t.Errorf("cells: %v", cells)
	}
	detail, err := items[0].Detail(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, s := range detail.Sections {
		for _, f := range s.Fields {
			fields[s.Title+"/"+f.Label] = f.Value
		}
	}
	for key, want := range map[string]string{
		"Certificate/Subject":       "CN=Alice PIV Authentication",
		"Certificate/Serial number": "BEEF",
		"Certificate/Usage":         "Client authentication, Digital signature",
		"Certificate/Other names":   "alice@example.com",
		"Card/Serial number":        "00a1b2c3",
	} {
		if fields[key] != want {
			t.Errorf("%s: got %q, want %q", key, fields[key], want)
		}
	}
	text, err := items[0].(backend.Copier).CopyText(ctx)
	if err != nil || !strings.Contains(text, "BEGIN CERTIFICATE") {
		t.Errorf("copy: %v", err)
	}
}

// fakeFIDO answers like fido2-token for one YubiKey whose PIN is 123456. It fails if it
// can open a terminal, as the PIN must come only on stdin.
func fakeFIDO(t *testing.T, state string) string {
	t.Helper()
	return script(t, "fido2-token", `
if (exec 3</dev/tty) 2>/dev/null; then echo "fido2-token was given a terminal" >&2; exit 9; fi
checkpin() {
	read -r pin
	if [ "$pin" != 123456 ]; then echo "fido2-token: fido_credman_get_dev_rp: FIDO_ERR_PIN_INVALID" >&2; exit 1; fi
}
case "$*" in
"-L")
	echo "/dev/hidraw7: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)" ;;
"-I /dev/hidraw7")
	printf 'proto: 0x02\nversion strings: U2F_V2, FIDO_2_0, FIDO_2_1\noptions: rk, up, noplat, clientPin, credMgmt\nremaining rk(s): 23\npin retries: 8\n' ;;
"-L -r /dev/hidraw7")
	checkpin
	echo "00: c2l0ZWhhc2g= github.com"
	grep -q gone `+state+` 2>/dev/null || echo "01: b3RoZXJoYXNo example.com" ;;
"-L -k github.com /dev/hidraw7")
	checkpin
	echo "00: Y3JlZDE= Alice Example dXNlcjE= es256 uvopt nopay" ;;
"-L -k example.com /dev/hidraw7")
	checkpin
	echo "00: Y3JlZDI= (null) dXNlcjI= eddsa uvreq pay" ;;
"-D -i Y3JlZDI= /dev/hidraw7")
	checkpin
	echo gone > `+state+` ;;
*)
	echo "unexpected: $*" >&2; exit 1 ;;
esac
`)
}

func TestPasskeys(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "state")
	g := &securitykeys.Group{P11: &securitykeys.P11{Binary: script(t, "p11tool", "exit 0\n")},
		FIDO: &securitykeys.FIDO{Binary: fakeFIDO(t, state)}}
	cats, err := g.Categories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	devices := cats[1].(backend.Parent).Children()
	if len(devices) != 1 || devices[0].Title() != "Yubico YubiKey OTP+FIDO+CCID" {
		t.Fatalf("devices: %v", devices)
	}
	device := devices[0]
	lock := device.(backend.Lockable)
	if !lock.Locked() {
		t.Fatal("a security key starts locked")
	}
	items, err := device.Items(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("locked items (just the key itself): %v %v", items, err)
	}
	detail, err := items[0].Detail(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f := detail.Sections[0].Fields; f[3].Value != "Yes" || f[4].Value != "23" || f[5].Value != "8" {
		t.Errorf("device fields: %+v", f)
	}

	unlocker := device.(backend.PINUnlocker)
	if err := unlocker.UnlockWithPIN(ctx, "000000"); !errors.Is(err, backend.ErrWrongPassphrase) {
		t.Fatalf("wrong PIN: %v", err)
	}
	if !lock.Locked() {
		t.Fatal("a wrong PIN unlocked it")
	}
	if err := unlocker.UnlockWithPIN(ctx, "123456"); err != nil {
		t.Fatal(err)
	}
	items, err = device.Items(ctx)
	if err != nil || len(items) != 3 {
		t.Fatalf("unlocked items: %v %v", items, err)
	}
	if c := items[1].Cells(); c[0] != "github.com" || c[1] != "Alice Example" || c[2] != "es256" {
		t.Errorf("first passkey: %v", c)
	}
	if c := items[2].Cells(); c[0] != "example.com" || c[1] != "" {
		t.Errorf("second passkey (no display name): %v", c)
	}

	// Refreshing keeps the PIN; deleting uses it.
	cats, _ = g.Categories(ctx)
	device = cats[1].(backend.Parent).Children()[0]
	if device.(backend.Lockable).Locked() {
		t.Fatal("refreshing forgot the PIN")
	}
	items, _ = device.Items(ctx)
	if err := items[2].(backend.Deleter).Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if items, _ = device.Items(ctx); len(items) != 2 {
		t.Errorf("after deleting: %d items, want 2", len(items))
	}

	_ = device.(backend.Lockable).Lock(ctx)
	if items, _ = device.Items(ctx); len(items) != 1 {
		t.Errorf("after locking: %d items, want 1", len(items))
	}
}

func TestFormatExpiry(t *testing.T) {
	obj := &securitykeys.ObjectItem{Object: securitykeys.Object{Label: "x", Expires: "Tue May  6 01:22:07 2036"}}
	if got := obj.Cells()[3]; !strings.HasPrefix(got, "2036-05-0") {
		t.Errorf("expiry: %q", got)
	}
}
