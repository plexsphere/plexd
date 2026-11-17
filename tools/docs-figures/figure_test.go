package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// wellFormed parses s as XML and reports the first syntax error.
func wellFormed(t *testing.T, what, s string) {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := d.Token()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("%s is not well-formed XML: %v", what, err)
		}
	}
}

func TestNumFormatsStably(t *testing.T) {
	t.Parallel()
	for in, want := range map[float64]string{
		0: "0", 12: "12", 12.5: "12.5", 1.0 / 3: "0.33", -4.005: "-4.01", 100.004: "100",
	} {
		if got := num(in); got != want {
			t.Errorf("num(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestXMLEscapeEscapesMarkup(t *testing.T) {
	t.Parallel()
	if got, want := xmlEscape(`a<b> & "c"`), "a&lt;b&gt; &amp; &quot;c&quot;"; got != want {
		t.Errorf("xmlEscape = %q, want %q", got, want)
	}
}

func TestKeepSpacesKeepsIndentationAndRuns(t *testing.T) {
	t.Parallel()
	got := keepSpaces("  a  b c")
	want := "  a  b c"
	if got != want {
		t.Errorf("keepSpaces = %q, want %q", got, want)
	}
}

func TestSVGDashScalesWithStrokeWidth(t *testing.T) {
	t.Parallel()
	if got := svgDash("3 2", 2.5); got != "7.5 5" {
		t.Errorf("svgDash = %q, want %q", got, "7.5 5")
	}
}

func TestDrawioLabelEscapesTextTwice(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.box(roleCore, spec{x: 0, y: 0, lines: []Line{code("a < b && c")}})
	out := f.Drawio()
	// The label text is HTML inside an XML attribute: '<' becomes
	// &lt; in the HTML and &amp;lt; in the attribute.
	if !strings.Contains(out, "a &amp;lt; b &amp;amp;&amp;amp; c") {
		t.Errorf("draw.io value is not escaped as HTML inside XML:\n%s", out)
	}
	wellFormed(t, "draw.io source", out)
}

func TestSVGPreservesSpacesOnlyWhereNeeded(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	f.text(0, 0, "left", code("plain line"), code("    indented"))
	out := f.SVG()
	if strings.Count(out, `xml:space="preserve"`) != 1 {
		t.Errorf("want exactly the indented line to preserve spaces:\n%s", out)
	}
}

func TestEdgeHeadsShortenTheLine(t *testing.T) {
	t.Parallel()
	e := &edge{pts: []pt{{0, 0}, {100, 0}}, color: colorLine, sw: strokeArrow, end: headBlock}
	out := e.svg()
	if !strings.Contains(out, `points="0,0 91,0"`) {
		t.Errorf("the line does not stop short of the block head:\n%s", out)
	}
	if !strings.Contains(out, `<polygon points="100,0 87,6 87,-6"`) {
		t.Errorf("the block head is not drawn at the tip:\n%s", out)
	}
	e.end, e.start = headNone, headOpen
	if out := e.svg(); !strings.Contains(out, `points="0,0 100,0"`) || !strings.Contains(out, "<polyline points=\"13,-6 0,0 13,6\"") {
		t.Errorf("an open head at the start is not drawn as a chevron over the full line:\n%s", out)
	}
}

func TestDrawioHeadNamesBothSides(t *testing.T) {
	t.Parallel()
	for h, want := range map[head]string{
		headNone:  "endArrow=none;",
		headBlock: "endArrow=block;endFill=1;endSize=8;",
		headOpen:  "endArrow=open;endFill=0;endSize=10;",
	} {
		if got := drawioHead("end", h); got != want {
			t.Errorf("drawioHead(end, %d) = %q, want %q", h, got, want)
		}
	}
}

func TestNormalizeMovesTheDrawingToTheMargin(t *testing.T) {
	t.Parallel()
	f := &Figure{Name: "conventions-test", Title: "t"}
	n := f.box(roleCore, spec{x: -200, y: 300, w: 100, h: 40, lines: []Line{name("x")}})
	e := f.arrow(flow, pt{-200, 400}, pt{-100, 400})
	f.normalize()
	if n.x != margin || n.y != margin {
		t.Errorf("box at %v,%v, want %v,%v", n.x, n.y, margin, margin)
	}
	if e.pts[0] != (pt{margin, 140}) {
		t.Errorf("edge starts at %v, want {%v 140}", e.pts[0], margin)
	}
	// The drawing spans 100 by 100 pixels: the box's top to the edge.
	if w, h := f.size(); w != 100+2*margin || h != 100+2*margin {
		t.Errorf("canvas %vx%v, want %vx%v", w, h, 100+2*margin, 100+2*margin)
	}
}

func TestCylinderCapStaysWithinItsBox(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ w, h float64 }{{100, 20}, {300, 80}, {1200, 200}} {
		d := cylinderCap(c.w, c.h)
		if d <= 0 || d > c.h/4 || d > 20 {
			t.Errorf("cylinderCap(%v, %v) = %v, want within (0, min(h/4, 20)]", c.w, c.h, d)
		}
	}
	n := &node{shape: shapeCylinder, x: 0, y: 0, w: 300, h: 80}
	if p := n.capTop(150); p.Y != 0 {
		t.Errorf("the cap's apex is at y=%v, want 0", p.Y)
	}
	if p := n.capTop(0); p.Y != cylinderCap(300, 80) {
		t.Errorf("the cap meets the side at y=%v, want %v", p.Y, cylinderCap(300, 80))
	}
}

// stagedFigure is a small figure that builds up in three stages.
func stagedFigure() *Figure {
	f := &Figure{Name: "conventions-staged", Title: "A staged figure"}
	f.box(roleCore, spec{x: 0, y: 0, w: 200, h: 60, lines: []Line{name("before any stage")}})
	f.stage(2)
	f.box(roleAgent, spec{x: 300, y: 0, w: 200, h: 60, lines: []Line{name("second")}})
	f.stage(3)
	f.box(roleStore, spec{x: 600, y: 0, w: 200, h: 60, lines: []Line{name("third")}})
	f.normalize()
	return f
}

// TestStagesPartitionTheFigure pins what makes stacked frames safe on a
// slide: every frame has the canvas of the whole figure, each element
// sits in exactly one frame, and only the first paints the background.
func TestStagesPartitionTheFigure(t *testing.T) {
	t.Parallel()
	f := stagedFigure()
	frames := f.Frames()
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want one per stage", len(frames))
	}
	w, h := f.size()
	canvas := fmt.Sprintf(`viewBox="0 0 %s %s"`, num(w), num(h))
	for i, label := range []string{"before any stage", "second", "third"} {
		wellFormed(t, fmt.Sprintf("frame %d", i+1), frames[i])
		if !strings.Contains(frames[i], canvas) {
			t.Errorf("frame %d does not have the canvas of the whole figure", i+1)
		}
		if got := strings.Count(strings.Join(frames, ""), ">"+label+"<"); got != 1 {
			t.Errorf("%q is in %d frames, want exactly one", label, got)
		}
		if !strings.Contains(frames[i], ">"+label+"<") {
			t.Errorf("frame %d lacks %q", i+1, label)
		}
	}
	background := fmt.Sprintf(`fill="%s"/>`, colorBackground)
	if !strings.Contains(frames[0], background) {
		t.Error("the first frame must paint the background")
	}
	for i, frame := range frames[1:] {
		if strings.Contains(frame, background) {
			t.Errorf("frame %d paints the background and would hide the frames below it", i+2)
		}
	}
}

// TestStagesLeaveThePairUnchanged pins that a stage is only a slide
// concern: the pair of a staged figure is the pair of the same drawing
// without stages.
func TestStagesLeaveThePairUnchanged(t *testing.T) {
	t.Parallel()
	staged := stagedFigure()
	flat := stagedFigure()
	flat.stages = make([]int, len(flat.els))
	for i := range flat.stages {
		flat.stages[i] = 1
	}
	if staged.SVG() != flat.SVG() {
		t.Error("stages change the SVG of the figure")
	}
	if staged.Drawio() != flat.Drawio() {
		t.Error("stages change the draw.io source of the figure")
	}
	if flat.Frames() != nil {
		t.Error("a figure with a single stage must have no frames")
	}
}
