package pgp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// SearchResult is a key found on a keyserver, from its machine-readable index.
type SearchResult struct {
	// ID is the fingerprint or long key ID the keyserver gave.
	ID        string
	Algorithm int
	Bits      int
	Created   time.Time
	Expires   time.Time
	// Flags holds r (revoked), d (disabled) and e (expired).
	Flags   string
	UserIDs []string
	// Keyservers are where it was found.
	Keyservers []string
}

// parseSearchResults parses the machine-readable keyserver index gpg --search-keys prints
// with --with-colons: "pub:" records, each followed by its "uid:" records.
func parseSearchResults(out string) []SearchResult {
	var results []SearchResult
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		f := strings.Split(scanner.Text(), ":")
		field := func(n int) string {
			if n < len(f) {
				return f[n]
			}
			return ""
		}
		switch f[0] {
		case "pub":
			algo, _ := strconv.Atoi(field(2))
			bits, _ := strconv.Atoi(field(3))
			results = append(results, SearchResult{
				ID: strings.ToUpper(field(1)), Algorithm: algo, Bits: bits,
				Created: parseTime(field(4)), Expires: parseTime(field(5)), Flags: field(6),
			})
		case "uid":
			if len(results) == 0 {
				continue
			}
			uid, err := url.QueryUnescape(field(1))
			if err != nil {
				uid = field(1)
			}
			r := &results[len(results)-1]
			r.UserIDs = append(r.UserIDs, uid)
		}
	}
	return results
}

// SearchKeys searches one keyserver. A search that finds nothing returns no results and
// no error.
func (g *GPG) SearchKeys(ctx context.Context, keyserver, query string) ([]SearchResult, error) {
	out, _, err := g.run(ctx, "--keyserver", keyserver, "--search-keys", "--", query)
	results := parseSearchResults(string(out))
	if err != nil && len(results) == 0 {
		if strings.Contains(err.Error(), "No data") || strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	for i := range results {
		results[i].Keyservers = []string{keyserver}
	}
	return results, nil
}

// RecvKey imports a key from a keyserver into the keyring and returns gpg's report.
func (g *GPG) RecvKey(ctx context.Context, keyserver, id string) (string, error) {
	_, stderr, err := g.run(ctx, "--keyserver", keyserver, "--recv-keys", "--", id)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(stderr)), nil
}

// FetchKey downloads a key from a keyserver into a scratch keyring, without touching the
// user's keyring, and returns it ASCII armored with its listing.
func (g *GPG) FetchKey(ctx context.Context, keyserver, id string) ([]byte, *Key, error) {
	var armored []byte
	var key *Key
	err := g.withScratchHome(ctx, func(home string) error {
		scratch := invocation{home: home}
		if _, _, err := g.runWith(ctx, scratch, "--keyserver", keyserver, "--recv-keys", "--", id); err != nil {
			return err
		}
		var err error
		if armored, _, err = g.runWith(ctx, scratch, "--armor", "--export", "--", id); err != nil {
			return err
		}
		out, _, err := g.runWith(ctx, scratch, "--with-fingerprint", "--list-keys", "--", id)
		if err != nil {
			return err
		}
		keys, err := ParseColons(strings.NewReader(string(out)))
		if err != nil {
			return err
		}
		if len(keys) == 0 || len(armored) == 0 {
			return fmt.Errorf("the keyserver didn't return key %s", id)
		}
		key = keys[0]
		return nil
	})
	return armored, key, err
}

// KeyserverCategory is the "Keyservers" node under PGP Keys: the results of the last
// search, which the user runs from the search bar above the list.
type KeyserverCategory struct {
	GPG *GPG

	mu      sync.Mutex
	results []backend.Item
}

var _ backend.KeySearcher = (*KeyserverCategory)(nil)

// Key implements backend.Category.
func (c *KeyserverCategory) Key() string { return "pgp-keyservers:" + c.GPG.Home }

// Title implements backend.Category.
func (c *KeyserverCategory) Title() string { return "Keyservers" }

// IconName implements backend.Category.
func (c *KeyserverCategory) IconName() string { return "network-server-symbolic" }

// Columns implements backend.Category.
func (c *KeyserverCategory) Columns() []backend.Column {
	return []backend.Column{
		{Title: "Name", Expand: true},
		{Title: "Email"},
		{Title: "Key ID", Monospace: true},
		{Title: "Created"},
		{Title: "Status"},
		{Title: "Keyserver", Truncate: true},
	}
}

// Items implements backend.Category: the last search's results.
func (c *KeyserverCategory) Items(_ context.Context) ([]backend.Item, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]backend.Item(nil), c.results...), nil
}

// SearchTargets implements backend.KeySearcher.
func (c *KeyserverCategory) SearchTargets() []backend.Choice {
	targets := make([]backend.Choice, 0, len(c.GPG.Keyservers))
	for _, ks := range c.GPG.Keyservers {
		targets = append(targets, backend.Choice{ID: ks.URI, Label: ks.Label()})
	}
	return targets
}

// SearchPlaceholder implements backend.KeySearcher.
func (c *KeyserverCategory) SearchPlaceholder() string {
	return "Search keyservers by name, email or key ID"
}

// Search implements backend.KeySearcher. An empty target searches every keyserver;
// results found on several are listed once. Keyservers that fail are reported as problems
// unless all of them fail.
func (c *KeyserverCategory) Search(ctx context.Context, query, target string) ([]backend.Item, []string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil, errors.New("enter something to search for")
	}
	servers := []string{target}
	if target == "" {
		servers = nil
		for _, ks := range c.GPG.Keyservers {
			servers = append(servers, ks.URI)
		}
	}
	if len(servers) == 0 {
		return nil, nil, errors.New("no keyservers are configured")
	}

	type outcome struct {
		results []SearchResult
		err     error
	}
	outcomes := make([]outcome, len(servers))
	var wg sync.WaitGroup
	for idx, ks := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.GPG.SearchKeys(ctx, ks, query)
			outcomes[idx] = outcome{r, err}
		}()
	}
	wg.Wait()

	var merged []SearchResult
	index := map[string]int{}
	var problems []string
	failed := 0
	for idx, o := range outcomes {
		if o.err != nil {
			failed++
			problems = append(problems, fmt.Sprintf("%s: %v", servers[idx], o.err))
			continue
		}
		for _, r := range o.results {
			if at, ok := index[r.ID]; ok {
				merged[at].Keyservers = append(merged[at].Keyservers, r.Keyservers...)
				continue
			}
			index[r.ID] = len(merged)
			merged = append(merged, r)
		}
	}
	if failed == len(servers) {
		return nil, nil, fmt.Errorf("searching failed:\n%s", strings.Join(problems, "\n"))
	}

	items := make([]backend.Item, 0, len(merged))
	for _, r := range merged {
		items = append(items, &RemoteItem{GPG: c.GPG, Result: r})
	}
	c.mu.Lock()
	c.results = items
	c.mu.Unlock()
	return items, problems, nil
}

// RemoteItem is a key on a keyserver. It can be imported, or used without importing:
// copying, exporting and encrypting fetch it into a scratch keyring first.
type RemoteItem struct {
	GPG    *GPG
	Result SearchResult

	mu      sync.Mutex
	armored []byte
	key     *Key
}

var (
	_ backend.RemoteImporter = (*RemoteItem)(nil)
	_ backend.Copier         = (*RemoteItem)(nil)
	_ backend.Exporter       = (*RemoteItem)(nil)
	_ backend.Crypter        = (*RemoteItem)(nil)
)

// fetch downloads the key once, from the first keyserver it was found on.
func (r *RemoteItem) fetch(ctx context.Context) ([]byte, *Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.armored != nil {
		return r.armored, r.key, nil
	}
	armored, key, err := r.GPG.FetchKey(ctx, r.Result.Keyservers[0], r.Result.ID)
	if err != nil {
		return nil, nil, err
	}
	r.armored, r.key = armored, key
	return armored, key, nil
}

func (r *RemoteItem) primaryUID() UserID {
	if len(r.Result.UserIDs) == 0 {
		return UserID{}
	}
	return UserID{Raw: r.Result.UserIDs[0]}
}

func (r *RemoteItem) status() string {
	var parts []string
	for flag, name := range map[byte]string{'r': "Revoked", 'e': "Expired", 'd': "Disabled"} {
		if strings.IndexByte(r.Result.Flags, flag) >= 0 {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ", ")
}

// Key implements backend.Item.
func (r *RemoteItem) Key() string { return "remote:" + r.Result.ID }

// IconName implements backend.Item.
func (r *RemoteItem) IconName() string { return "avatar-default-symbolic" }

// Cells implements backend.Item.
func (r *RemoteItem) Cells() []string {
	uid := r.primaryUID()
	name := uid.Name()
	if name == "" {
		name = uid.Raw
	}
	return []string{name, uid.Email(), shortKeyID(lastN(r.Result.ID, 16)), backend.FormatDate(r.Result.Created, ""),
		r.status(), strings.Join(r.Result.Keyservers, ", ")}
}

func lastN(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// Detail implements backend.Item, from the keyserver's index.
func (r *RemoteItem) Detail(_ context.Context) (*backend.Detail, error) {
	res := r.Result
	id := res.ID
	if len(id) >= 40 {
		id = groupFingerprint(id)
	}
	status := r.status()
	if status == "" {
		status = "Valid"
	}
	fields := []backend.Field{
		{Label: "Key ID", Value: id, Monospace: true},
		{Label: "Algorithm", Value: AlgorithmName(res.Algorithm, "")},
		{Label: "Strength", Value: fmt.Sprintf("%d bits", res.Bits)},
		{Label: "Created", Value: backend.FormatDate(res.Created, "Unknown")},
		{Label: "Expires", Value: backend.FormatDate(res.Expires, "Never")},
		{Label: "Status", Value: status},
		{Label: "Found on", Value: strings.Join(res.Keyservers, "\n")},
	}
	uids := &backend.Table{Columns: []string{"Name", "Email", "Comment"}}
	for _, raw := range res.UserIDs {
		u := UserID{Raw: raw}
		uids.Rows = append(uids.Rows, []string{u.Name(), u.Email(), u.Comment()})
	}
	uid := r.primaryUID()
	title := uid.Name()
	if title == "" {
		title = uid.Raw
	}
	return &backend.Detail{
		Title:    title,
		Subtitle: "On a keyserver · not in your keyring",
		IconName: r.IconName(),
		Sections: []backend.Section{
			{Title: "Key", Fields: fields},
			{Title: "Names", Table: uids},
		},
	}, nil
}

// ImportLabel implements backend.RemoteImporter.
func (r *RemoteItem) ImportLabel() string { return "Import into Keyring" }

// ImportToLocal implements backend.RemoteImporter.
func (r *RemoteItem) ImportToLocal(ctx context.Context) (string, error) {
	return r.GPG.RecvKey(ctx, r.Result.Keyservers[0], r.Result.ID)
}

// CopyLabel implements backend.Copier.
func (r *RemoteItem) CopyLabel() string { return "public key" }

// CopyText implements backend.Copier.
func (r *RemoteItem) CopyText(ctx context.Context) (string, error) {
	armored, _, err := r.fetch(ctx)
	return string(armored), err
}

// ExportName implements backend.Exporter.
func (r *RemoteItem) ExportName() string { return lastN(r.Result.ID, 16) + ".asc" }

// Export implements backend.Exporter.
func (r *RemoteItem) Export(ctx context.Context) ([]byte, error) {
	armored, _, err := r.fetch(ctx)
	return armored, err
}

// CryptName implements backend.Crypter.
func (r *RemoteItem) CryptName() string {
	if name := r.primaryUID().Name(); name != "" {
		return name
	}
	return r.primaryUID().Raw
}

// CanEncrypt implements backend.Crypter. Whether the key has an encryption subkey is only
// known once it's fetched, so this only rules out keys the keyserver marks unusable.
func (r *RemoteItem) CanEncrypt() (bool, string) {
	if status := r.status(); status != "" {
		return false, "The keyserver lists this key as " + strings.ToLower(status) + "."
	}
	return true, ""
}

// CanSign implements backend.Crypter.
func (r *RemoteItem) CanSign() (bool, string) {
	return false, "Only the owner of the private key can sign with it."
}

// EncryptionWarning implements backend.Crypter: keyservers don't vouch for keys.
func (r *RemoteItem) EncryptionWarning() string {
	return fmt.Sprintf("This key comes from a keyserver and isn't in your keyring. Anyone can upload a "+
		"key with any name, so only encrypt to it if you've checked its fingerprint with %s.", r.CryptName())
}

// withRecipientFile fetches the key and writes it to a temporary file for gpg's
// --recipient-file, which encrypts to it without importing it.
func (r *RemoteItem) withRecipientFile(ctx context.Context, fn func(file string) error) error {
	armored, _, err := r.fetch(ctx)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "landhorse-recipient-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "key.asc")
	if err := os.WriteFile(file, armored, 0o600); err != nil {
		return err
	}
	return fn(file)
}

// EncryptFile implements backend.Crypter.
func (r *RemoteItem) EncryptFile(ctx context.Context, in, out string, _ bool) error {
	return r.withRecipientFile(ctx, func(file string) error {
		_, _, err := r.GPG.runWith(ctx, invocation{interactive: true},
			"--batch", "--recipient-file", file, "--yes", "--output", out, "--encrypt", "--", in)
		return err
	})
}

// SignFile implements backend.Crypter.
func (r *RemoteItem) SignFile(_ context.Context, _, _ string) error {
	return errors.New("only the owner of the private key can sign with it")
}

// EncryptText implements backend.Crypter.
func (r *RemoteItem) EncryptText(ctx context.Context, text string, _ bool) (string, error) {
	var result string
	err := r.withRecipientFile(ctx, func(file string) error {
		out, _, err := r.GPG.runWith(ctx, invocation{interactive: true, stdin: []byte(text)},
			"--batch", "--armor", "--recipient-file", file, "--encrypt")
		result = string(out)
		return err
	})
	return result, err
}

// SignText implements backend.Crypter.
func (r *RemoteItem) SignText(_ context.Context, _ string) (string, error) {
	return "", errors.New("only the owner of the private key can sign with it")
}
