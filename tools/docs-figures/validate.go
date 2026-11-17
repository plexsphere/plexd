package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// figureName is the shape of a figure's file name: lower case, words
// joined by hyphens.
var figureName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)+$`)

// figurePrefixes are the file-name prefixes of the inventory in
// docs/reference/development/diagrams.md (File names). A figure's name starts
// with one of them.
var figurePrefixes = []string{
	"architecture-", "communication-", "security-", "core-", "actions-",
	"bridge-", "networking-", "development-", "conventions-",
}

// validateAll checks every figure and the set as a whole.
func validateAll(figs []*Figure) error {
	var errs []error
	seen := map[string]bool{}
	for _, f := range figs {
		if seen[f.Name] {
			errs = append(errs, fmt.Errorf("figure %s is registered twice", f.Name))
		}
		seen[f.Name] = true
		errs = append(errs, f.validate()...)
	}
	return errors.Join(errs...)
}

// validate checks one figure: its name and title, that the drawing
// keeps the margin, that every label fits its box, that no two boxes
// overlap, and that no free text straddles the outline of a box.
func (f *Figure) validate() []error {
	var errs []error
	fail := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: "+format, append([]any{f.Name}, a...)...))
	}
	if !figureName.MatchString(f.Name) {
		fail("the name is not lower case words joined by hyphens")
	}
	if !hasPrefix(f.Name) {
		fail("the name starts with none of the prefixes %s", strings.Join(figurePrefixes, " "))
	}
	if strings.TrimSpace(f.Title) == "" {
		fail("the title is empty")
	}
	if len(f.els) == 0 {
		fail("the figure draws nothing")
		return errs
	}
	var solids, texts []*node
	var edges []*edge
	for _, e := range f.els {
		if ed, ok := e.(*edge); ok {
			if !ed.inner {
				edges = append(edges, ed)
			}
			continue
		}
		n, ok := e.(*node)
		if !ok {
			continue
		}
		switch {
		case n.solid:
			solids = append(solids, n)
		case n.shape == shapeText:
			texts = append(texts, n)
		}
	}
	for _, n := range solids {
		if len(n.lines) == 0 {
			continue
		}
		bw, bh := blockSize(n.lines)
		if bw+2*n.padX > n.w+0.5 {
			fail("the label %q is %s pixels wide, its box only %s", n.lines[0].Text, num(bw+2*n.padX), num(n.w))
		}
		need := bh + 4
		if n.valign == "top" {
			need = bh + 2*n.padY
		}
		if need > n.h+0.5 {
			fail("the label %q is %s pixels high, its box only %s", n.lines[0].Text, num(need), num(n.h))
		}
	}
	for i, a := range solids {
		for _, b := range solids[i+1:] {
			if overlap(a.bounds(), b.bounds()) {
				fail("the boxes %q and %q overlap", firstText(a), firstText(b))
			}
		}
	}
	for _, t := range texts {
		for _, s := range solids {
			if overlap(t.bounds(), s.bounds()) && !inside(t.bounds(), s.bounds()) {
				fail("the text %q crosses the outline of the box %q", firstText(t), firstText(s))
			}
		}
	}
	for _, e := range edges {
		for i := 1; i < len(e.pts); i++ {
			a, b := e.pts[i-1], e.pts[i]
			for _, s := range solids {
				r := s.bounds()
				if s.shape == shapeCylinder {
					// Above the rim of the cap is outside the shape.
					r.y0 += cylinderCap(s.w, s.h)
				}
				if crosses(a, b, r) {
					fail("an edge from %s,%s to %s,%s runs through the box %q",
						num(a.X), num(a.Y), num(b.X), num(b.Y), firstText(s))
				}
			}
		}
	}
	return errs
}

// crosses reports whether the segment from a to b passes through the
// inside of r. Touching the outline, as an edge does where it starts
// or ends at a box, does not count. It clips the segment against r
// shrunk by four pixels (Liang-Barsky), so an edge that ends on the
// rim of a cylinder, a little inside its bounding box, still touches.
func crosses(a, b pt, r box) bool {
	r = box{r.x0 + 4, r.y0 + 4, r.x1 - 4, r.y1 - 4}
	if r.x0 >= r.x1 || r.y0 >= r.y1 {
		return false
	}
	t0, t1 := 0.0, 1.0
	dx, dy := b.X-a.X, b.Y-a.Y
	for _, c := range [4][2]float64{
		{-dx, a.X - r.x0}, {dx, r.x1 - a.X}, {-dy, a.Y - r.y0}, {dy, r.y1 - a.Y},
	} {
		p, q := c[0], c[1]
		if p == 0 {
			if q < 0 {
				return false
			}
			continue
		}
		t := q / p
		if p < 0 {
			t0 = max(t0, t)
		} else {
			t1 = min(t1, t)
		}
		if t0 > t1 {
			return false
		}
	}
	return t1-t0 > 1e-9
}

func hasPrefix(name string) bool {
	for _, p := range figurePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// overlap reports whether a and b share more than a hairline.
func overlap(a, b box) bool {
	const eps = 0.5
	return a.x0 < b.x1-eps && b.x0 < a.x1-eps && a.y0 < b.y1-eps && b.y0 < a.y1-eps
}

// inside reports whether a lies within b.
func inside(a, b box) bool {
	return a.x0 >= b.x0 && a.y0 >= b.y0 && a.x1 <= b.x1 && a.y1 <= b.y1
}

func firstText(n *node) string {
	if len(n.lines) == 0 {
		return "(no label)"
	}
	return n.lines[0].Text
}
