package main

import (
	"strings"
	"testing"
)

// problems returns the validation errors of f as one string.
func problems(f *Figure) string {
	var b strings.Builder
	for _, err := range f.validate() {
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	return b.String()
}

func TestCrossesTellsPassingFromTouching(t *testing.T) {
	t.Parallel()
	r := box{100, 100, 200, 200}
	cases := []struct {
		name string
		a, b pt
		want bool
	}{
		{"through the middle", pt{50, 150}, pt{250, 150}, true},
		{"ends on the outline", pt{150, 20}, pt{150, 100}, false},
		{"runs along the outline", pt{100, 50}, pt{100, 250}, false},
		{"misses", pt{0, 0}, pt{50, 300}, false},
		{"diagonal through a corner region", pt{90, 110}, pt{130, 150}, true},
		{"starts inside", pt{150, 150}, pt{150, 300}, true},
	}
	for _, c := range cases {
		if got := crosses(c.a, c.b, r); got != c.want {
			t.Errorf("%s: crosses = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestValidateRejectsALabelWiderThanItsBox(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.box(roleCore, spec{x: 0, y: 0, w: 60, h: 40, lines: []Line{name("a label far too long")}})
	if got := problems(f); !strings.Contains(got, "pixels wide") {
		t.Errorf("want a width error, got %q", got)
	}
}

func TestValidateRejectsALabelTallerThanItsBox(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.box(roleCore, spec{x: 0, y: 0, w: 300, h: 30, lines: []Line{name("one"), body("two"), body("three")}})
	if got := problems(f); !strings.Contains(got, "pixels high") {
		t.Errorf("want a height error, got %q", got)
	}
}

func TestValidateRejectsOverlappingBoxes(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.box(roleCore, spec{x: 0, y: 0, w: 200, h: 60, lines: []Line{name("a")}})
	f.box(roleCore, spec{x: 150, y: 30, w: 200, h: 60, lines: []Line{name("b")}})
	if got := problems(f); !strings.Contains(got, `the boxes "a" and "b" overlap`) {
		t.Errorf("want an overlap error, got %q", got)
	}
}

func TestValidateAllowsBoxesThatOnlyTouch(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.box(roleCore, spec{x: 0, y: 0, w: 200, h: 60, lines: []Line{name("a")}})
	f.box(roleCore, spec{x: 200, y: 0, w: 200, h: 60, lines: []Line{name("b")}})
	if got := problems(f); got != "" {
		t.Errorf("want no error, got %q", got)
	}
}

func TestValidateRejectsTextAcrossAnOutline(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.box(roleCore, spec{x: 0, y: 0, w: 200, h: 60, lines: []Line{name("box")}})
	f.text(180, 20, "left", body("a label"))
	if got := problems(f); !strings.Contains(got, "crosses the outline") {
		t.Errorf("want a straddle error, got %q", got)
	}
}

func TestValidateRejectsAnEdgeThroughABox(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.box(roleCore, spec{x: 100, y: 0, w: 100, h: 60, lines: []Line{name("box")}})
	f.arrow(flow, pt{0, 30}, pt{300, 30})
	if got := problems(f); !strings.Contains(got, "runs through the box") {
		t.Errorf("want an edge error, got %q", got)
	}
}

func TestValidateChecksNameAndTitle(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "Bad_Name", Title: " "}
	f.text(0, 0, "left", body("x"))
	got := problems(f)
	for _, want := range []string{"lower case words", "none of the prefixes", "title is empty"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q among the errors, got %q", want, got)
		}
	}
}

func TestValidateAllRejectsADuplicateName(t *testing.T) {
	t.Parallel()
	mk := func() *Figure {
		f := &Figure{Name: "conventions-test", Title: "t"}
		f.text(0, 0, "left", body("x"))
		return f
	}
	err := validateAll([]*Figure{mk(), mk()})
	if err == nil || !strings.Contains(err.Error(), "registered twice") {
		t.Errorf("want a duplicate error, got %v", err)
	}
}
