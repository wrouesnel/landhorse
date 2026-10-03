// Package backend defines the toolkit-independent model the user interface is built on.
//
// The window has three panes, and each maps onto a type here:
//
//   - the type tree on the left lists Groups, each holding Categories;
//   - the list in the middle shows the Items of the selected Category;
//   - the detail view on the right renders the Detail of the selected Item.
//
// Optional behaviour (locking, importing, copying, exporting, deleting) is expressed as
// small interfaces that a Category or Item may also implement. The user interface enables
// the matching toolbar buttons only when the selection implements them.
package backend

import (
	"context"
	"errors"
	"time"
)

// Group is a top level node in the type tree, e.g. "Passwords" or "PGP Keys".
type Group interface {
	Title() string
	IconName() string
	// Categories lists the children of the group. It is re-run on refresh, because the
	// set of categories can change (for example when a keyring is created).
	Categories(ctx context.Context) ([]Category, error)
}

// Category is a selectable node in the type tree whose items fill the middle list.
type Category interface {
	// Key identifies the category across refreshes so the selection can be kept.
	Key() string
	Title() string
	IconName() string
	// Columns describes the middle list's columns. Each Item's Cells must match it.
	Columns() []Column
	Items(ctx context.Context) ([]Item, error)
}

// Parent is implemented by categories with subcategories beneath them in the type tree.
// Selecting the parent shows all of its items; each child shows a subset.
type Parent interface {
	// Children is computed when the group lists its categories, so it doesn't block.
	Children() []Category
}

// Linkable is implemented by items that can be related to items elsewhere, which the detail
// view lists under Related Items. Two items are related when they report a common link key:
// for example a saved passphrase and the PGP key it unlocks both report
// "gpg-keygrip:<keygrip>". Keys are opaque strings; backends agree on their prefixes:
//
//	gpg-fpr:<FINGERPRINT>      a PGP primary key or subkey fingerprint, upper case hex
//	gpg-keygrip:<KEYGRIP>      a PGP key or subkey keygrip, upper case hex
//	ssh-private-key:<path>     the absolute path of an SSH private key file
//	ssh-fingerprint:<SHA256:…> an SSH public key's SHA256 fingerprint
//	gpg-keyid:<KEYID>          a PGP primary key's long key ID, upper case hex
type Linkable interface {
	Item
	LinkKeys() []string
	// LinkDescription says what the item is when listed as related, e.g. "PGP key".
	LinkDescription() string
}

// AttributeGrouping groups items by the value of one of their attributes: a category named
// after the attribute, with a subcategory for each value.
type AttributeGrouping struct {
	// Attribute is the attribute's name, e.g. "service".
	Attribute string
	// Title names the category; empty means the attribute name.
	Title string
}

// Label is the category name for the grouping.
func (g AttributeGrouping) Label() string {
	if g.Title != "" {
		return g.Title
	}
	return g.Attribute
}

// Referrer is implemented by Linkable items that refer to other items in one direction,
// such as a PGP key referring to the keys that signed it. An item is related to the items
// whose link keys its references include, and to the items whose references include its
// link keys. Unlike shared link keys, two items referring to the same item aren't related.
type Referrer interface {
	LinkReferences() []string
	// ReferenceLabels describe the relation as listed under Related items: outgoing for
	// an item this one refers to, incoming for an item referring to this one.
	ReferenceLabels() (outgoing, incoming string)
}

// Column describes one column of the middle list.
type Column struct {
	Title string
	// Expand gives the column any spare horizontal space.
	Expand bool
	// Monospace renders the column in a fixed width font, for IDs and fingerprints.
	Monospace bool
	// Truncate lets a long value be cut short with an ellipsis instead of widening the
	// column. Expanding columns always truncate.
	Truncate bool
	// SortRank, when set, orders the column by rank instead of alphabetically. Lower ranks
	// come first when the column header is first clicked.
	SortRank func(cell string) int
}

// Item is a row in the middle list.
type Item interface {
	// Key identifies the item across refreshes so the selection can be kept.
	Key() string
	IconName() string
	// Cells are the values shown in the middle list, one per Column.
	Cells() []string
	Detail(ctx context.Context) (*Detail, error)
}

// Detail is what the right hand pane shows for an Item.
type Detail struct {
	Title    string
	Subtitle string
	IconName string
	Sections []Section
}

// Section is a titled block of the detail view. It holds fields, a table, or both.
type Section struct {
	Title  string
	Fields []Field
	Table  *Table
}

// Field is a labelled value in a Section.
type Field struct {
	Label     string
	Value     string
	Monospace bool
	// Reveal, when set, makes this a secret field. Value is ignored and the field is
	// shown masked until the user asks to see it, at which point Reveal is called.
	Reveal func(ctx context.Context) (string, error)
}

// Table is a grid of values in a Section, such as user IDs or subkeys.
type Table struct {
	Columns []string
	Rows    [][]string
	// Links, if set, has one entry per row (nil for none): double-clicking the row
	// follows it.
	Links []*TableLink
	// Children, if set, has one entry per row: rows nested beneath it, such as the
	// signatures on a user ID.
	Children [][]TableRow
}

// TableRow is a nested row in a Table.
type TableRow struct {
	Cells []string
	Link  *TableLink
}

// TableLink is where double-clicking a table row goes: the item with LinkKey among its
// link keys, or if there is none, a keyserver search for Search.
type TableLink struct {
	LinkKey string
	Search  string
}

// Lockable is implemented by categories that can be locked and unlocked, such as keyrings.
type Lockable interface {
	Locked() bool
	Lock(ctx context.Context) error
	// Unlock may show a system prompt for a password and block until it is answered.
	Unlock(ctx context.Context) error
}

// Importer is implemented by categories that accept files to import.
type Importer interface {
	// ImportTitle is the file chooser title, e.g. "Import PGP keys".
	ImportTitle() string
	// Import reads the file and returns a human readable summary of what was imported.
	Import(ctx context.Context, path string) (string, error)
}

// Copier is implemented by items with a natural text form for the clipboard: a password's
// secret, or a public key.
type Copier interface {
	// CopyLabel describes what gets copied, e.g. "password" or "public key".
	CopyLabel() string
	CopyText(ctx context.Context) (string, error)
}

// CopyOnActivate is implemented by Copier items that copy themselves to the clipboard when
// their row is activated (double-clicked, or Enter pressed).
type CopyOnActivate interface {
	Copier
	CopyOnActivate()
}

// Exporter is implemented by items that can be saved to a file.
type Exporter interface {
	// ExportName is the suggested file name.
	ExportName() string
	Export(ctx context.Context) ([]byte, error)
}

// Publisher is implemented by items that can be uploaded somewhere public, such as a PGP
// key to a keyserver.
type Publisher interface {
	// PublishTargets lists where the item can be published. Empty means nowhere is
	// configured.
	PublishTargets() []Choice
	// PublishWarning explains what will be made public, for the confirmation dialog.
	PublishWarning() string
	// Publish uploads the item to the target with the given ID and returns a report.
	Publish(ctx context.Context, target string) (string, error)
}

// Choice is one option offered to the user, such as a keyserver or a revocation reason.
type Choice struct {
	ID    string
	Label string
}

// Revoker is implemented by items that can be permanently revoked, such as PGP keys.
// Revoking only helps if others learn of it, so it is always published too.
type Revoker interface {
	// Revoked reports whether the item is already revoked.
	Revoked() bool
	// RevokeTargets lists where the revocation can be published. Revoking is only offered
	// when there is at least one.
	RevokeTargets() []Choice
	// CheckRevocation validates a revocation certificate for this item without applying it,
	// and describes it.
	CheckRevocation(ctx context.Context, cert string) (string, error)
	// Revoke applies a revocation certificate and publishes it to target.
	Revoke(ctx context.Context, cert string, target string) (string, error)
	// CanGenerateRevocation reports whether a certificate can be made here, and if not, why.
	CanGenerateRevocation() (bool, string)
	// RevocationReasons are the reasons GenerateRevocation accepts.
	RevocationReasons() []Choice
	// GenerateRevocation makes a revocation certificate. It may prompt for a passphrase.
	GenerateRevocation(ctx context.Context, reason string, description string) (string, error)
	// ConfirmationCode is a short code, such as the key ID, that the user must type to
	// confirm generating a revocation, so the right item is revoked.
	ConfirmationCode() string
}

// SecretExporter is implemented by Exporters whose secret part can be exported too, such as
// a PGP key's private key.
type SecretExporter interface {
	Exporter
	// CanExportSecret reports whether the secret part is available to export.
	CanExportSecret() bool
	// SecretExportName is the suggested file name for an export including the secret part.
	SecretExportName() string
	// ExportSecret exports the item including its secret part. With a non-empty password
	// the result is encrypted with it; an empty password exports it unencrypted. It may
	// prompt for the item's own passphrase.
	ExportSecret(ctx context.Context, password string) ([]byte, error)
}

// PassphraseChanger is implemented by items protected by a passphrase that can be changed,
// such as SSH private keys.
type PassphraseChanger interface {
	// CanChangePassphrase reports whether the item has something to protect.
	CanChangePassphrase() bool
	// HasPassphrase reports whether a passphrase is currently set.
	HasPassphrase() bool
	// ChangePassphrase replaces the passphrase. current is ignored if there is none. It
	// returns ErrWrongPassphrase if current is wrong.
	ChangePassphrase(ctx context.Context, current, replacement string) error
	// SavedPassphrase describes the SecretStore entry that unlocks the item automatically:
	// its label, the attributes to store it with, and the attributes that find it.
	SavedPassphrase() (label string, attrs, lookup map[string]string)
}

// ErrWrongPassphrase is returned when a passphrase doesn't unlock an item.
var ErrWrongPassphrase = errors.New("the passphrase is wrong")

// SecretStore saves secrets, such as passphrases, where the desktop unlocks them at login.
type SecretStore interface {
	// StoreName describes where secrets go, e.g. "login keyring".
	StoreName() string
	// StoreSecret saves a secret, replacing one with the same attributes.
	StoreSecret(ctx context.Context, label string, attrs map[string]string, secret string) error
	// CountSecrets counts the saved secrets whose attributes include attrs.
	CountSecrets(ctx context.Context, attrs map[string]string) (int, error)
	// DeleteSecrets deletes the saved secrets whose attributes include attrs.
	DeleteSecrets(ctx context.Context, attrs map[string]string) (int, error)
}

// Crypter is implemented by keys that encrypt to their owner or sign for them, such as
// PGP keys. Each operation reports why it isn't possible through the Can methods.
type Crypter interface {
	// CryptName is who encrypted data is for, e.g. the key owner's name.
	CryptName() string
	CanEncrypt() (bool, string)
	CanSign() (bool, string)
	// EncryptionWarning is non-empty when the key isn't verified as its owner's; the user
	// must accept it, and then trustAnyway is passed as true.
	EncryptionWarning() string
	// EncryptFile encrypts the file in to the file out, replacing out.
	EncryptFile(ctx context.Context, in, out string, trustAnyway bool) error
	// SignFile writes a detached signature of the file in to the file out, replacing out.
	SignFile(ctx context.Context, in, out string) error
	// EncryptText returns text encrypted as ASCII armor.
	EncryptText(ctx context.Context, text string, trustAnyway bool) (string, error)
	// SignText returns text clear-signed.
	SignText(ctx context.Context, text string) (string, error)
}

// KeySearcher is implemented by categories whose items are the results of a search the
// user runs, such as a keyserver search. The item list shows a search bar for them.
type KeySearcher interface {
	// SearchTargets are where a search can run, e.g. keyservers. Searching with an empty
	// target searches all of them.
	SearchTargets() []Choice
	// SearchPlaceholder is the search field's hint text.
	SearchPlaceholder() string
	// Search runs a search and remembers its results as the category's items. problems
	// lists targets that failed when others succeeded.
	Search(ctx context.Context, query, target string) (items []Item, problems []string, err error)
}

// RemoteImporter is implemented by items found elsewhere, such as on a keyserver, that can
// be imported into the local store.
type RemoteImporter interface {
	ImportLabel() string
	// ImportToLocal imports the item and returns a report.
	ImportToLocal(ctx context.Context) (string, error)
}

// Deleter is implemented by items that can be deleted.
type Deleter interface {
	// DeleteWarning explains exactly what will be removed, for the confirmation dialog.
	DeleteWarning() string
	Delete(ctx context.Context) error
}

// FormatTime formats a timestamp for display, or returns fallback for the zero time.
func FormatTime(t time.Time, fallback string) string {
	if t.IsZero() {
		return fallback
	}
	return t.Local().Format("2006-01-02 15:04")
}

// FormatDate formats a timestamp as a date for display, or returns fallback for the zero time.
func FormatDate(t time.Time, fallback string) string {
	if t.IsZero() {
		return fallback
	}
	return t.Local().Format("2006-01-02")
}
