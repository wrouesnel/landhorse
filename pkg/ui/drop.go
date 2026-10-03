package ui

import (
	"net/url"
	"strings"

	"github.com/gotk3/gotk3/gtk"
)

// droppedFiles returns the local file paths in dropped text/uri-list data.
//
// gotk3's SelectionData.GetURIs crashes (it reads past the end of GTK's string array), so
// the list is parsed from the raw data, which GTK only keeps during the signal handler.
func droppedFiles(data *gtk.SelectionData) []string {
	raw := data.GetData()
	return parseURIList(string(append([]byte(nil), raw...)))
}

// parseURIList parses text/uri-list (RFC 2483): one URI per line, "#" comments, CRLF line
// ends. Only file: URIs are kept, as paths.
func parseURIList(list string) []string {
	var paths []string
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Scheme != "file" || u.Path == "" {
			continue
		}
		paths = append(paths, u.Path)
	}
	return paths
}
