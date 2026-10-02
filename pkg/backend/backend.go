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
	PublishTargets() []PublishTarget
	// PublishWarning explains what will be made public, for the confirmation dialog.
	PublishWarning() string
	// Publish uploads the item to the target with the given ID and returns a report.
	Publish(ctx context.Context, target string) (string, error)
}

// PublishTarget is somewhere an item can be published.
type PublishTarget struct {
	ID    string
	Label string
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
