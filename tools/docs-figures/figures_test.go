package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryFigureRendersValidXML renders every registered figure and
// checks both files of each pair are well-formed and carry the pieces
// draw.io and a browser need.
func TestEveryFigureRendersValidXML(t *testing.T) {
	t.Parallel()
	files, err := render(allFigures())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, fl := range files {
		body := string(fl.body)
		wellFormed(t, fl.path, body)
		switch filepath.Ext(fl.path) {
		case ".drawio":
			if !strings.HasPrefix(body, "<mxfile") || !strings.Contains(body, "<mxGraphModel") {
				t.Errorf("%s is not a draw.io file", fl.path)
			}
		case ".svg":
			if !strings.Contains(body, `role="img"`) || !strings.Contains(body, "<title>") {
				t.Errorf("%s lacks role=img or a <title>", fl.path)
			}
		}
	}
}

// TestRenderIsDeterministic renders the figures twice; the bytes must
// not change, or the drift test would flap.
func TestRenderIsDeterministic(t *testing.T) {
	t.Parallel()
	a, err := render(allFigures())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, err := render(allFigures())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for i := range a {
		if a[i].path != b[i].path || !bytes.Equal(a[i].body, b[i].body) {
			t.Fatalf("%s renders differently on a second run", a[i].path)
		}
	}
}

// TestCellIDsAreUnique checks every draw.io cell id is used once, which
// draw.io needs to open the file.
func TestCellIDsAreUnique(t *testing.T) {
	t.Parallel()
	ids := regexp.MustCompile(`<mxCell id="([^"]+)"`)
	for _, f := range allFigures() {
		seen := map[string]bool{}
		for _, m := range ids.FindAllStringSubmatch(f.Drawio(), -1) {
			if seen[m[1]] {
				t.Errorf("%s: cell id %s is used twice", f.Name, m[1])
			}
			seen[m[1]] = true
		}
	}
}

// TestCommittedFiguresMatchTheGenerator is the drift gate: every pair
// under docs/diagrams/ must be exactly what the generator draws. A hand
// edit to a pair, or a figure function changed without `make
// docs-figures`, fails here.
func TestCommittedFiguresMatchTheGenerator(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s is not the repository root: %v", root, err)
	}
	if err := run(root, true); err != nil {
		t.Fatalf("the committed figures drifted from the generator: %v", err)
	}
}

// TestCheckModeReportsAStalePair runs the check against a copy of the
// pairs with one file changed and one missing.
func TestCheckModeReportsAStalePair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := run(dir, false); err != nil {
		t.Fatalf("write the pairs: %v", err)
	}
	if err := run(dir, true); err != nil {
		t.Fatalf("a fresh tree should pass the check: %v", err)
	}
	stale := filepath.Join(dir, diagramsDir, "conventions-legend.svg")
	if err := os.WriteFile(stale, []byte("<svg/>"), 0o600); err != nil {
		t.Fatalf("change a pair: %v", err)
	}
	missing := filepath.Join(dir, diagramsDir, "conventions-legend.drawio")
	if err := os.Remove(missing); err != nil {
		t.Fatalf("remove a pair file: %v", err)
	}
	err := run(dir, true)
	if err == nil {
		t.Fatal("the check passed although a pair changed")
	}
	for _, want := range []string{"conventions-legend.svg", "conventions-legend.drawio (missing)", "make docs-figures"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the check error does not mention %q: %v", want, err)
		}
	}
}
