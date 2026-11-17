// Command docs-figures draws the figures of the documentation. For
// every figure it writes a pair into docs/diagrams/: a draw.io source
// (<name>.drawio) and the SVG export of that source (<name>.svg) that
// the pages embed.
//
// Both files of a pair are rendered from the same elements, so they
// cannot disagree. A figure is changed by changing its function in one
// of the fig_*.go files and running the tool again; a hand edit to a
// generated pair is overwritten on the next run, and the drift test
// fails it before that. docs/reference/development/diagrams.md is the guide:
// the inventory of every figure and the page that embeds it, the
// file-name prefixes, and the visual conventions.
//
// Usage:
//
//	go run ./tools/docs-figures            # rewrite every pair
//	go run ./tools/docs-figures -check     # exit non-zero if a pair is stale
//	go run ./tools/docs-figures -root DIR  # operate on a tree other than the cwd
//	go run ./tools/docs-figures -frames    # write the build stages under bin/figure-frames
//
// The frames of a staged figure are for slides, which build a figure up
// step by step. They are build output, not part of a pair: nothing
// embeds them in the docs and nothing commits them.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
)

// diagramsDir is the repository-relative directory of the pairs.
const diagramsDir = "docs/diagrams"

// framesDir is the repository-relative directory of the build stages.
const framesDir = "bin/figure-frames"

func main() {
	root := flag.String("root", ".", "repository root to operate on")
	check := flag.Bool("check", false, "report stale pairs and exit non-zero instead of rewriting them")
	frames := flag.Bool("frames", false, "write the build stages of the staged figures under "+framesDir+" instead of the pairs")
	flag.Parse()

	var err error
	if *frames {
		err = writeFrames(*root)
	} else {
		err = run(*root, *check)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "docs-figures:", err)
		os.Exit(1)
	}
}

// file is one rendered file of a pair.
type file struct {
	path string
	body []byte
}

// render validates every figure and returns the files of every pair.
func render(figs []*Figure) ([]file, error) {
	for _, f := range figs {
		if len(f.els) > 0 {
			f.normalize()
		}
	}
	if err := validateAll(figs); err != nil {
		return nil, err
	}
	out := make([]file, 0, 2*len(figs))
	for _, f := range figs {
		out = append(out,
			file{path: path.Join(diagramsDir, f.Name+".drawio"), body: []byte(f.Drawio())},
			file{path: path.Join(diagramsDir, f.Name+".svg"), body: []byte(f.SVG())},
		)
	}
	return out, nil
}

// renderFrames validates every figure and returns the build stages of
// the staged ones, one directory per figure.
func renderFrames(figs []*Figure) ([]file, error) {
	if _, err := render(figs); err != nil {
		return nil, err
	}
	var out []file
	for _, f := range figs {
		for i, frame := range f.Frames() {
			out = append(out, file{
				path: path.Join(framesDir, f.Name, fmt.Sprintf("%d.svg", i+1)),
				body: []byte(frame),
			})
		}
	}
	return out, nil
}

// writeFrames renders the build stages and writes them under root,
// replacing what an earlier run left there.
func writeFrames(root string) error {
	osRoot, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open root %s: %w", root, err)
	}
	defer func() { _ = osRoot.Close() }()

	files, err := renderFrames(allFigures())
	if err != nil {
		return err
	}
	if err := osRoot.RemoveAll(framesDir); err != nil {
		return fmt.Errorf("clear %s: %w", framesDir, err)
	}
	for _, fl := range files {
		if err := osRoot.MkdirAll(path.Dir(fl.path), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", path.Dir(fl.path), err)
		}
		if err := osRoot.WriteFile(fl.path, fl.body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", fl.path, err)
		}
	}
	return nil
}

// run renders every figure and writes the pairs under root, or, in
// check mode, compares them with the files on disk.
func run(root string, check bool) error {
	// DECISION: every read and write goes through an os.Root opened at
	// the repository root rather than raw os.ReadFile/os.WriteFile on
	// joined paths with a gosec carve-out. The tool only touches docs/diagrams/ inside the tree it
	// was pointed at, and the rooted API enforces exactly that.
	osRoot, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open root %s: %w", root, err)
	}
	defer func() { _ = osRoot.Close() }()

	files, err := render(allFigures())
	if err != nil {
		return err
	}
	if !check {
		if err := osRoot.MkdirAll(diagramsDir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", diagramsDir, err)
		}
		for _, fl := range files {
			if err := osRoot.WriteFile(fl.path, fl.body, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", fl.path, err)
			}
		}
		return nil
	}
	var stale []string
	for _, fl := range files {
		got, err := osRoot.ReadFile(fl.path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			stale = append(stale, fl.path+" (missing)")
		case err != nil:
			return fmt.Errorf("read %s: %w", fl.path, err)
		case !bytes.Equal(got, fl.body):
			stale = append(stale, fl.path)
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("%d figure files differ from the generator; run `make docs-figures`:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
	return nil
}
