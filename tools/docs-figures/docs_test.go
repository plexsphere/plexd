package main

// The inventory gate for the figures of the docs.
//
// Every figure is a pair under docs/diagrams/: a draw.io source and the
// SVG export the pages embed. docs/reference/development/diagrams.md
// lists every pair with the pages that embed it. The gate keeps the
// three in step: the files on disk, the inventory, and the embeds in the
// pages. It also keeps text drawings out: a fenced code block in the
// docs or the README that holds ASCII art or a Mermaid diagram fails it.

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// diagramsGuide is the repository-relative path of the guide that holds
// the inventory.
const diagramsGuide = "docs/reference/development/diagrams.md"

// diagramEmbedPattern matches a Markdown image whose target is a figure
// under docs/diagrams/: group 1 is the alt text, group 2 the target,
// group 3 the figure name.
var diagramEmbedPattern = regexp.MustCompile(`!\[([^\]]*)\]\(([^)\s]*diagrams/([a-z0-9-]+)\.svg)\)`)

// diagramRowPattern matches a row of the inventory table: group 1 is the
// figure name, group 2 the "Embedded in" cell.
var diagramRowPattern = regexp.MustCompile("^\\| `([a-z0-9-]+)` \\| [^|]+ \\| (.+) \\|$")

// markdownLinkPattern matches an inline Markdown link: group 2 is the
// target.
var markdownLinkPattern = regexp.MustCompile(`\[([^\]]*)\]\(([^)\s]+)\)`)

// textDiagramPattern matches the box corners and arrowheads of ASCII
// art. Directory trees use only ├, └, │ and ─, so they do not match.
var textDiagramPattern = regexp.MustCompile(`[┌┐┘╔╗╚╝▼▲►◄▶◀]`)

// asciiBoxPattern matches the top or bottom border of a box drawn with
// plus and minus signs, and the row separator of an RFC-style packet
// layout.
var asciiBoxPattern = regexp.MustCompile(`^\s*(\+-{3,}[-+]*\+|(\+-){4,}\+)\s*$`)

// textArrowPattern matches the arrows of a sequence drawn with pipes
// and dashes, and a pipeline of two or more → steps on one line. A rule
// listing with one → per line does not match.
var textArrowPattern = regexp.MustCompile(`\|-{2,}|-{2,}>\s*\||→.*→`)

// diagramEmbed is one figure embedded in one page.
type diagramEmbed struct {
	page string // repository-relative path of the embedding page
	alt  string
	fig  string
}

// repoRoot returns the repository root, two levels above this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s is not the repository root: %v", root, err)
	}
	return root
}

// diagramPages returns every Markdown file that may embed a figure: the
// pages under docs/ and the README, as repository-relative paths.
func diagramPages(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	pages := []string{"README.md"}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".vitepress" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".md") {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			pages = append(pages, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}
	return pages
}

// diagramPairs returns the figure names under docs/diagrams/ with the
// extensions found for each.
func diagramPairs(t *testing.T) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), filepath.FromSlash(diagramsDir)))
	if err != nil {
		t.Fatalf("read %s: %v", diagramsDir, err)
	}
	pairs := map[string][]string{}
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		name := strings.TrimSuffix(e.Name(), ext)
		pairs[name] = append(pairs[name], ext)
	}
	return pairs
}

// diagramEmbeds returns every figure embed outside fenced code blocks.
func diagramEmbeds(t *testing.T) []diagramEmbed {
	t.Helper()
	root := repoRoot(t)
	var out []diagramEmbed
	for _, rel := range diagramPages(t) {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		inFence := false
		for _, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimLeft(line, " \t")
			if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
				inFence = !inFence
				continue
			}
			if inFence {
				continue
			}
			for _, m := range diagramEmbedPattern.FindAllStringSubmatch(line, -1) {
				target := path.Join(path.Dir(rel), m[2])
				if want := path.Join(diagramsDir, m[3]+".svg"); target != want {
					t.Errorf("%s embeds %s, which resolves to %s instead of %s", rel, m[2], target, want)
				}
				out = append(out, diagramEmbed{page: rel, alt: m[1], fig: m[3]})
			}
		}
	}
	return out
}

// diagramInventory parses the inventory table of the guide into the
// pages each row lists, keyed by figure name.
func diagramInventory(t *testing.T) map[string][]string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(diagramsGuide)))
	if err != nil {
		t.Fatalf("read %s: %v", diagramsGuide, err)
	}
	section := false
	rows := map[string][]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "## ") {
			section = line == "## Inventory"
			continue
		}
		if !section {
			continue
		}
		m := diagramRowPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if _, dup := rows[m[1]]; dup {
			t.Errorf("%s lists %s twice in the inventory", diagramsGuide, m[1])
		}
		pages := []string{}
		for _, l := range markdownLinkPattern.FindAllStringSubmatch(m[2], -1) {
			target, _, _ := strings.Cut(l[2], "#")
			if target == "" {
				target = path.Base(diagramsGuide)
			}
			pages = append(pages, path.Join(path.Dir(diagramsGuide), target))
		}
		rows[m[1]] = pages
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no inventory rows under `## Inventory`", diagramsGuide)
	}
	return rows
}

// TestDiagramPairsAreComplete checks that docs/diagrams/ holds only
// pairs: a .drawio source and an .svg export for every figure.
func TestDiagramPairsAreComplete(t *testing.T) {
	t.Parallel()
	for name, exts := range diagramPairs(t) {
		sort.Strings(exts)
		if strings.Join(exts, " ") != ".drawio .svg" {
			t.Errorf("%s/%s has the files %v; a figure is exactly a .drawio source and its .svg export",
				diagramsDir, name, exts)
		}
	}
}

// TestDiagramInventoryMatchesThePairs checks that the inventory lists
// every pair and nothing else.
func TestDiagramInventoryMatchesThePairs(t *testing.T) {
	t.Parallel()
	pairs := diagramPairs(t)
	rows := diagramInventory(t)
	for name := range pairs {
		if _, ok := rows[name]; !ok {
			t.Errorf("%s/%s has no row in the inventory of %s", diagramsDir, name, diagramsGuide)
		}
	}
	for name := range rows {
		if _, ok := pairs[name]; !ok {
			t.Errorf("the inventory of %s lists %s, which is not a pair in %s", diagramsGuide, name, diagramsDir)
		}
	}
}

// TestDiagramEmbedsMatchTheInventory checks that every figure is
// embedded, that every embed of a figure carries the same non-empty alt
// text, and that the pages an inventory row lists are exactly the pages
// that embed the figure.
func TestDiagramEmbedsMatchTheInventory(t *testing.T) {
	t.Parallel()
	rows := diagramInventory(t)
	alts := map[string]string{}
	embedded := map[string]map[string]bool{}
	for _, e := range diagramEmbeds(t) {
		if strings.TrimSpace(e.alt) == "" {
			t.Errorf("%s embeds %s without an alt text; say what the figure shows", e.page, e.fig)
		}
		if prev, ok := alts[e.fig]; ok && prev != e.alt {
			t.Errorf("%s embeds %s with an alt text that differs from another embed of it:\n  %q\n  %q",
				e.page, e.fig, e.alt, prev)
		}
		alts[e.fig] = e.alt
		if embedded[e.fig] == nil {
			embedded[e.fig] = map[string]bool{}
		}
		embedded[e.fig][e.page] = true
	}
	for name, pages := range rows {
		listed := map[string]bool{}
		for _, p := range pages {
			listed[p] = true
			if !embedded[name][p] {
				t.Errorf("the inventory row of %s lists %s, which does not embed it", name, p)
			}
		}
		if len(embedded[name]) == 0 {
			t.Errorf("%s is in the inventory but no page embeds it", name)
		}
		for p := range embedded[name] {
			if !listed[p] {
				t.Errorf("%s embeds %s, but the inventory row of %s does not list the page", p, name, name)
			}
		}
	}
}

// TestNoTextDiagramsInTheDocs fails a fenced code block that holds a
// Mermaid diagram or ASCII art: box corners, arrowheads, a box border
// drawn with plus and minus signs, or arrows drawn with pipes and
// dashes.
func TestNoTextDiagramsInTheDocs(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, rel := range diagramPages(t) {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		fence, start, reported := "", 0, false
		for i, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimLeft(line, " \t")
			if fence == "" {
				if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
					fence, start, reported = trimmed[:3], i+1, false
					if strings.TrimSpace(strings.TrimLeft(trimmed, fence[:1])) == "mermaid" {
						t.Errorf("%s:%d: a Mermaid block; draw the figure in docs/diagrams/ instead (see %s)",
							rel, start, diagramsGuide)
					}
				}
				continue
			}
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
				continue
			}
			if !reported && (textDiagramPattern.MatchString(line) || asciiBoxPattern.MatchString(line) ||
				textArrowPattern.MatchString(line)) {
				t.Errorf("%s:%d: the code block opened on line %d holds ASCII art; draw the figure in docs/diagrams/ instead (see %s)",
					rel, i+1, start, diagramsGuide)
				reported = true
			}
		}
	}
}
