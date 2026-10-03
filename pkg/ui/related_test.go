package ui

import (
	"context"
	"sort"
	"testing"

	"github.com/wrouesnel/landhorse/pkg/backend"
)

// fakeKey is a Linkable Referrer standing in for a PGP key.
type fakeKey struct {
	id      string
	signers []string
}

func (f *fakeKey) Key() string                                     { return f.id }
func (f *fakeKey) IconName() string                                { return "" }
func (f *fakeKey) Cells() []string                                 { return []string{f.id} }
func (f *fakeKey) Detail(context.Context) (*backend.Detail, error) { return &backend.Detail{}, nil }
func (f *fakeKey) LinkKeys() []string                              { return []string{"gpg-keyid:" + f.id} }
func (f *fakeKey) LinkDescription() string                         { return "key" }
func (f *fakeKey) ReferenceLabels() (string, string)               { return "Signed this key", "Signed by this key" }
func (f *fakeKey) LinkReferences() []string {
	var refs []string
	for _, s := range f.signers {
		refs = append(refs, "gpg-keyid:"+s)
	}
	return refs
}

func TestRelatedReferences(t *testing.T) {
	// B and C were both signed by A.
	a, b, c := &fakeKey{id: "A"}, &fakeKey{id: "B", signers: []string{"A"}}, &fakeKey{id: "C", signers: []string{"A"}}
	index := &relatedIndex{byKey: map[string][]relatedRef{}, byRef: map[string][]relatedRef{}}
	for _, k := range []*fakeKey{a, b, c} {
		ref := relatedRef{categoryKey: "pgp", item: k}
		for _, key := range k.LinkKeys() {
			index.byKey[key] = append(index.byKey[key], ref)
		}
		for _, key := range k.LinkReferences() {
			index.byRef[key] = append(index.byRef[key], ref)
		}
	}
	describe := func(refs []relatedRef) []string {
		var out []string
		for _, r := range refs {
			out = append(out, r.item.Key()+": "+r.relation)
		}
		sort.Strings(out)
		return out
	}
	if got := describe(index.lookup(b)); len(got) != 1 || got[0] != "A: Signed this key" {
		t.Errorf("B's related items: %v (C, signed by the same key, must not appear)", got)
	}
	if got := describe(index.lookup(a)); len(got) != 2 || got[0] != "B: Signed by this key" || got[1] != "C: Signed by this key" {
		t.Errorf("A's related items: %v", got)
	}
}
