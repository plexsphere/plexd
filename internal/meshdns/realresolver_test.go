//go:build darwin || windows

// The real resolver tests of macOS and Windows share these helpers.

package meshdns

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// logServerLines logs every line the server logged, with its attributes.
func logServerLines(t *testing.T, logs *logRecorder) {
	t.Helper()
	for _, e := range logs.all() {
		attrs := make([]string, 0, len(e.attrs))
		for k, v := range e.attrs {
			attrs = append(attrs, k+"="+v.String())
		}
		slices.Sort(attrs)
		t.Logf("server %s %q %s", e.level, e.msg, strings.Join(attrs, " "))
	}
}

// askedFor reports whether f received a query for name.
func askedFor(f *fakeResolver, name string) bool {
	for _, q := range f.received() {
		var p dnsmessage.Parser
		if _, err := p.Start(q.msg); err != nil {
			continue
		}
		question, err := p.Question()
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSuffix(question.Name.String(), "."), name) {
			return true
		}
	}
	return false
}
