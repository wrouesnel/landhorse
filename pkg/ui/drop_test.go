package ui

import (
	"reflect"
	"testing"
)

func TestParseURIList(t *testing.T) {
	list := "# dropped from a file manager\r\nfile:///home/me/plans.txt\r\nfile:///home/me/My%20Report.pdf\r\nhttps://example.com/x\r\n\r\n"
	want := []string{"/home/me/plans.txt", "/home/me/My Report.pdf"}
	if got := parseURIList(list); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := parseURIList(""); got != nil {
		t.Errorf("empty list: got %q", got)
	}
}
