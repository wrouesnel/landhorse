// Package securitykeys lists hardware security keys: smart cards (such as PIV cards and
// YubiKeys' PIV application) through PKCS#11, and FIDO2 authenticators with the passkeys
// stored on them.
//
// Like the pgp package with gpg, it drives the standard command line tools, p11tool
// (GnuTLS, using p11-kit's registered PKCS#11 modules such as OpenSC) and fido2-token
// (libfido2), rather than linking their C libraries.
package securitykeys

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// run executes a tool in its own session, so it has no controlling terminal to prompt
// on, with stdin as its input. On failure the error includes standard error.
func run(ctx context.Context, binary string, stdin string, args ...string) (string, string, error) {
	logutil.FromCtx(ctx).Debug("Running", zap.String("binary", binary), zap.Strings("args", args))
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			err = fmt.Errorf("%s: %w: %s", binary, err, msg)
		} else {
			err = fmt.Errorf("%s: %w", binary, err)
		}
	}
	return stdout.String(), stderr.String(), err
}

// parseBlocks parses p11tool's listing: "Token N:" or "Object N:" headers, each followed
// by indented "Name: value" lines.
func parseBlocks(out string) []map[string]string {
	var blocks []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if line[0] != '\t' && line[0] != ' ' && strings.HasSuffix(line, ":") {
			blocks = append(blocks, map[string]string{})
			continue
		}
		if len(blocks) == 0 {
			continue
		}
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			blocks[len(blocks)-1][strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return blocks
}

// P11 runs p11tool.
type P11 struct {
	Binary string
}

func (p *P11) binary() string {
	if p.Binary != "" {
		return p.Binary
	}
	return "p11tool"
}

// Token is a PKCS#11 token, such as an inserted smart card.
type Token struct {
	URL, Label, Type, Flags, Manufacturer, Model, Serial string
}

// Name is how the token is shown: its label, else its model.
func (t Token) Name() string {
	if t.Label != "" {
		return t.Label
	}
	if t.Model != "" {
		return t.Model
	}
	return "Smart card"
}

// Tokens lists the hardware tokens that are initialised, leaving out software stores such
// as the system trust store and blank tokens such as an unprovisioned TPM.
func (p *P11) Tokens(ctx context.Context) ([]Token, error) {
	out, _, err := run(ctx, p.binary(), "", "--batch", "--list-tokens")
	if err != nil {
		return nil, err
	}
	var tokens []Token
	for _, b := range parseBlocks(out) {
		t := Token{URL: b["URL"], Label: b["Label"], Type: b["Type"], Flags: b["Flags"],
			Manufacturer: b["Manufacturer"], Model: b["Model"], Serial: b["Serial"]}
		if t.Type != "Hardware token" || strings.Contains(t.Flags, "Uninitialized") || t.URL == "" {
			continue
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// Object is something stored on a token: a certificate, public key or data object.
type Object struct {
	URL, Type, Label, ID, Flags, Expires string
	Token                                Token
}

// IsCertificate reports whether the object is an X.509 certificate.
func (o Object) IsCertificate() bool { return strings.Contains(o.Type, "Certificate") }

// Objects lists what a token shows without logging in: certificates and public keys.
// A token with nothing to show returns no objects.
func (p *P11) Objects(ctx context.Context, token Token) ([]Object, error) {
	out, stderr, err := run(ctx, p.binary(), "", "--batch", "--list-all", token.URL)
	if err != nil {
		if strings.Contains(stderr, "No matching objects") || strings.Contains(out, "No matching objects") {
			return nil, nil
		}
		return nil, err
	}
	var objects []Object
	for _, b := range parseBlocks(out) {
		if b["URL"] == "" {
			continue
		}
		objects = append(objects, Object{URL: b["URL"], Type: b["Type"], Label: b["Label"], ID: b["ID"],
			Flags: b["Flags"], Expires: b["Expires"], Token: token})
	}
	return objects, nil
}

// ExportCertificate returns a certificate or public key object as PEM.
func (p *P11) ExportCertificate(ctx context.Context, object Object) ([]byte, error) {
	out, _, err := run(ctx, p.binary(), "", "--batch", "--export", object.URL)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(out, "-----BEGIN ") {
		return nil, errors.New("the card didn't return the object")
	}
	return []byte(out), nil
}

// SmartCards is the "Smart cards" category: every inserted token's objects, with a
// subcategory per token.
type SmartCards struct {
	P11      *P11
	tokens   []Token
	children []backend.Category
}

var (
	_ backend.Parent       = (*SmartCards)(nil)
	_ backend.EmptyMessage = (*SmartCards)(nil)
)

// newSmartCards lists the tokens to build the category.
func newSmartCards(ctx context.Context, p *P11) (*SmartCards, error) {
	tokens, err := p.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	c := &SmartCards{P11: p, tokens: tokens}
	for _, t := range tokens {
		c.children = append(c.children, &TokenCategory{P11: p, Token: t})
	}
	return c, nil
}

// Key implements backend.Category.
func (c *SmartCards) Key() string { return "smartcards" }

// Title implements backend.Category.
func (c *SmartCards) Title() string { return "Smart cards" }

// IconName implements backend.Category.
func (c *SmartCards) IconName() string { return "auth-smartcard-symbolic" }

// Columns implements backend.Category.
func (c *SmartCards) Columns() []backend.Column { return objectColumns() }

// Children implements backend.Parent.
func (c *SmartCards) Children() []backend.Category { return c.children }

// Items implements backend.Category.
func (c *SmartCards) Items(ctx context.Context) ([]backend.Item, error) {
	var items []backend.Item
	for _, t := range c.tokens {
		objects, err := c.P11.Objects(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, o := range objects {
			items = append(items, &ObjectItem{P11: c.P11, Object: o})
		}
	}
	return items, nil
}

// EmptyMessage implements backend.EmptyMessage.
func (c *SmartCards) EmptyMessage() string {
	if len(c.tokens) == 0 {
		return "No smart card is inserted. Insert one (for example a PIV card or a YubiKey) and press Refresh."
	}
	return "The inserted smart cards have no certificates or public keys."
}

// TokenCategory lists one token's objects.
type TokenCategory struct {
	P11   *P11
	Token Token
}

var _ backend.EmptyMessage = (*TokenCategory)(nil)

// Key implements backend.Category.
func (c *TokenCategory) Key() string { return "smartcard:" + c.Token.URL }

// Title implements backend.Category.
func (c *TokenCategory) Title() string { return c.Token.Name() }

// IconName implements backend.Category.
func (c *TokenCategory) IconName() string { return "auth-smartcard-symbolic" }

// Columns implements backend.Category.
func (c *TokenCategory) Columns() []backend.Column { return objectColumns() }

// Items implements backend.Category.
func (c *TokenCategory) Items(ctx context.Context) ([]backend.Item, error) {
	objects, err := c.P11.Objects(ctx, c.Token)
	if err != nil {
		return nil, err
	}
	items := make([]backend.Item, 0, len(objects))
	for _, o := range objects {
		items = append(items, &ObjectItem{P11: c.P11, Object: o})
	}
	return items, nil
}

// EmptyMessage implements backend.EmptyMessage.
func (c *TokenCategory) EmptyMessage() string {
	return "This card has no certificates or public keys that can be read without its PIN."
}

func objectColumns() []backend.Column {
	return []backend.Column{
		{Title: "Label", Expand: true},
		{Title: "Type"},
		{Title: "Card"},
		{Title: "Expires"},
	}
}

// ObjectItem is a certificate or key on a smart card.
type ObjectItem struct {
	P11    *P11
	Object Object
}

var (
	_ backend.Copier   = (*ObjectItem)(nil)
	_ backend.Exporter = (*ObjectItem)(nil)
)

// Key implements backend.Item.
func (i *ObjectItem) Key() string { return i.Object.URL }

// IconName implements backend.Item.
func (i *ObjectItem) IconName() string {
	if i.Object.IsCertificate() {
		return "application-certificate"
	}
	return "dialog-password"
}

func (i *ObjectItem) label() string {
	if i.Object.Label != "" {
		return i.Object.Label
	}
	return i.Object.Type
}

// Cells implements backend.Item.
func (i *ObjectItem) Cells() []string {
	return []string{i.label(), i.Object.Type, i.Object.Token.Name(), formatExpiry(i.Object.Expires)}
}

// formatExpiry shows p11tool's C-locale date ("Tue May  6 01:22:07 2036") as a date.
func formatExpiry(expires string) string {
	if t, err := time.Parse("Mon Jan _2 15:04:05 2006", strings.TrimSpace(expires)); err == nil {
		return backend.FormatDate(t, "")
	}
	return expires
}

// Detail implements backend.Item. Certificates are read from the card and decoded.
func (i *ObjectItem) Detail(ctx context.Context) (*backend.Detail, error) {
	o := i.Object
	cardFields := []backend.Field{
		{Label: "Card", Value: o.Token.Name()},
		{Label: "Manufacturer", Value: o.Token.Manufacturer},
		{Label: "Model", Value: o.Token.Model},
		{Label: "Serial number", Value: o.Token.Serial, Monospace: true},
	}
	objectFields := []backend.Field{
		{Label: "Label", Value: o.Label},
		{Label: "Type", Value: o.Type},
		{Label: "ID", Value: o.ID, Monospace: true},
		{Label: "PKCS#11 URL", Value: unescapeURL(o.URL), Monospace: true},
	}
	sections := []backend.Section{{Title: "Object", Fields: objectFields}}

	if o.IsCertificate() {
		data, err := i.P11.ExportCertificate(ctx, o)
		if err != nil {
			return nil, err
		}
		certSection, err := certificateSection(data)
		if err != nil {
			return nil, err
		}
		sections = append([]backend.Section{certSection}, sections...)
	}
	sections = append(sections, backend.Section{Title: "Card", Fields: cardFields})
	return &backend.Detail{
		Title:    i.label(),
		Subtitle: o.Type + " on " + o.Token.Name(),
		IconName: i.IconName(),
		Sections: sections,
	}, nil
}

// unescapeURL makes a PKCS#11 URL's percent-escapes readable.
func unescapeURL(u string) string {
	if s, err := url.PathUnescape(u); err == nil {
		return s
	}
	return u
}

// certificateSection decodes a PEM certificate's details.
func certificateSection(data []byte) (backend.Section, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return backend.Section{}, errors.New("the certificate isn't valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return backend.Section{}, err
	}
	sum := sha256.Sum256(cert.Raw)
	fields := []backend.Field{
		{Label: "Subject", Value: cert.Subject.String()},
		{Label: "Issuer", Value: cert.Issuer.String()},
		{Label: "Serial number", Value: strings.ToUpper(cert.SerialNumber.Text(16)), Monospace: true},
		{Label: "Valid from", Value: backend.FormatTime(cert.NotBefore, "")},
		{Label: "Valid until", Value: backend.FormatTime(cert.NotAfter, "")},
		{Label: "Key", Value: cert.PublicKeyAlgorithm.String()},
		{Label: "SHA-256 fingerprint", Value: colonHex(sum[:]), Monospace: true},
	}
	if usage := keyUsages(cert); usage != "" {
		fields = append(fields, backend.Field{Label: "Usage", Value: usage})
	}
	var names []string
	names = append(names, cert.DNSNames...)
	names = append(names, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		names = append(names, u.String())
	}
	if len(names) > 0 {
		fields = append(fields, backend.Field{Label: "Other names", Value: strings.Join(names, "\n")})
	}
	return backend.Section{Title: "Certificate", Fields: fields}, nil
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func keyUsages(cert *x509.Certificate) string {
	var uses []string
	for bit, name := range map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "Digital signature",
		x509.KeyUsageKeyEncipherment:   "Key encipherment",
		x509.KeyUsageKeyAgreement:      "Key agreement",
		x509.KeyUsageCertSign:          "Certificate signing",
		x509.KeyUsageContentCommitment: "Non-repudiation",
	} {
		if cert.KeyUsage&bit != 0 {
			uses = append(uses, name)
		}
	}
	for _, e := range cert.ExtKeyUsage {
		switch e {
		case x509.ExtKeyUsageClientAuth:
			uses = append(uses, "Client authentication")
		case x509.ExtKeyUsageServerAuth:
			uses = append(uses, "Server authentication")
		case x509.ExtKeyUsageEmailProtection:
			uses = append(uses, "Email protection")
		case x509.ExtKeyUsageCodeSigning:
			uses = append(uses, "Code signing")
		}
	}
	// Map iteration order varies; keep the list stable.
	sort.Strings(uses)
	return strings.Join(uses, ", ")
}

// CopyLabel implements backend.Copier.
func (i *ObjectItem) CopyLabel() string {
	if i.Object.IsCertificate() {
		return "certificate"
	}
	return "public key"
}

// CopyText implements backend.Copier: the certificate or public key as PEM.
func (i *ObjectItem) CopyText(ctx context.Context) (string, error) {
	data, err := i.P11.ExportCertificate(ctx, i.Object)
	return string(data), err
}

// ExportName implements backend.Exporter.
func (i *ObjectItem) ExportName() string {
	name := strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' {
			return '_'
		}
		return r
	}, i.label())
	return name + ".pem"
}

// Export implements backend.Exporter.
func (i *ObjectItem) Export(ctx context.Context) ([]byte, error) {
	text, err := i.CopyText(ctx)
	return []byte(text), err
}
