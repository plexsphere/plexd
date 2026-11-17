package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Figure is one diagram. It renders to a draw.io source and to the
// SVG export of that source; both come from the same elements, so the
// two files of a pair cannot disagree.
type Figure struct {
	// Name is the file name without extension, for example
	// "mesh-sse-publish".
	Name string
	// Title names the figure in the SVG <title>, its aria-label, and
	// the draw.io page name.
	Title string

	els []element
	// stages holds the build stage of every element of els, in step
	// with it; see stage.
	stages  []int
	current int
}

// element is anything drawn on the canvas.
type element interface {
	bounds() box
	drawio(id string) string
	svg() string
}

// pt is a point on the canvas.
type pt struct{ X, Y float64 }

// box is an axis-aligned rectangle.
type box struct{ x0, y0, x1, y1 float64 }

func (b box) union(o box) box {
	return box{min(b.x0, o.x0), min(b.y0, o.y0), max(b.x1, o.x1), max(b.y1, o.y1)}
}

// Line is one line of a label. Every line carries its own style, so a
// box can stack a bold name over a monospaced identifier.
type Line struct {
	Text  string
	Size  float64
	Bold  bool
	Mono  bool
	Color string
}

// shape is the outline of a node.
type shape int

const (
	shapeRect shape = iota
	shapeCylinder
	shapeNote
	shapeEllipse
	shapeText
)

// node is every element with an outline and a label: a box, a frame,
// a state, a store, a chip, a badge, or a free text.
type node struct {
	shape  shape
	x, y   float64
	w, h   float64
	arc    float64 // corner diameter; 0 draws square corners
	fill   string  // "" draws no fill
	stroke string  // "" draws no outline
	sw     float64
	dash   string // a draw.io dashPattern; "" is solid
	lines  []Line
	align  string // "left", "center" or "right"
	valign string // "top" or "middle"
	padX   float64
	padY   float64
	// solid marks a box that must not overlap another solid box and
	// must hold its label; frames and free texts are not solid.
	solid bool
}

func (n *node) bounds() box { return box{n.x, n.y, n.x + n.w, n.y + n.h} }

// Anchors on the outline.

func (n *node) top() pt    { return pt{n.x + n.w/2, n.y} }
func (n *node) bottom() pt { return pt{n.x + n.w/2, n.y + n.h} }
func (n *node) left() pt   { return pt{n.x, n.y + n.h/2} }
func (n *node) right() pt  { return pt{n.x + n.w, n.y + n.h/2} }
func (n *node) cx() float64 {
	return n.x + n.w/2
}
func (n *node) cy() float64 {
	return n.y + n.h/2
}

// capTop returns the point at x on the top of n; on a cylinder that
// is the upper rim of its cap, not the corner of its bounding box.
func (n *node) capTop(x float64) pt {
	if n.shape != shapeCylinder {
		return pt{x, n.y}
	}
	d, rx := cylinderCap(n.w, n.h), n.w/2
	dx := (x - n.cx()) / rx
	return pt{x, n.y + d - d*math.Sqrt(math.Max(0, 1-dx*dx))}
}

// topAt, bottomAt, leftAt and rightAt return the point on that side at
// the given absolute coordinate along it.
func (n *node) topAt(x float64) pt    { return pt{x, n.y} }
func (n *node) bottomAt(x float64) pt { return pt{x, n.y + n.h} }
func (n *node) leftAt(y float64) pt   { return pt{n.x, y} }
func (n *node) rightAt(y float64) pt  { return pt{n.x + n.w, y} }

// head is the end decoration of an edge.
type head int

const (
	headNone head = iota
	headBlock
	headOpen
)

// edge is a polyline with optional heads at either end.
type edge struct {
	pts   []pt
	color string
	sw    float64
	dash  string
	start head
	end   head
	// inner marks a rule drawn inside a box, such as the line under
	// a table's header; it may cross the box it belongs to.
	inner bool
}

func (e *edge) bounds() box {
	b := box{math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)}
	for _, p := range e.pts {
		b = b.union(box{p.X, p.Y, p.X, p.Y})
	}
	return b
}

// add appends elements to the figure, in the current build stage.
func (f *Figure) add(els ...element) {
	f.els = append(f.els, els...)
	for range els {
		f.stages = append(f.stages, max(f.current, 1))
	}
}

// stage starts build stage n: what the figure draws next appears in
// that stage when the figure is built up step by step on a slide. What
// a figure draws before its first call belongs to stage 1. Stages
// change nothing in the pair of a figure, which always shows the whole
// drawing; Frames renders them.
func (f *Figure) stage(n int) { f.current = n }

// lastStage returns the number of the figure's last build stage; 1
// means the figure has no stages to build through.
func (f *Figure) lastStage() int {
	last := 1
	for _, s := range f.stages {
		last = max(last, s)
	}
	return last
}

// extent is the union of every element's bounds.
func (f *Figure) extent() box {
	b := box{math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)}
	for _, e := range f.els {
		b = b.union(e.bounds())
	}
	return b
}

// normalize moves the drawing so that it starts at the margin on the
// left and at the top. A figure function may then draw around any
// origin it likes.
func (f *Figure) normalize() {
	b := f.extent()
	dx, dy := margin-b.x0, margin-b.y0
	for _, e := range f.els {
		switch v := e.(type) {
		case *node:
			v.x += dx
			v.y += dy
		case *edge:
			for i := range v.pts {
				v.pts[i].X += dx
				v.pts[i].Y += dy
			}
		}
	}
}

// size returns the canvas size: the drawing plus the margin on the
// right and at the bottom.
func (f *Figure) size() (w, h float64) {
	b := f.extent()
	return math.Ceil(b.x1 + margin), math.Ceil(b.y1 + margin)
}

// num formats a coordinate with at most two decimals and no trailing
// zeros, so the output is stable across platforms.
func num(v float64) string {
	return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64)
}

// keepSpaces turns every space that starts a line or follows another
// space into a no-break space, so indentation and aligned columns
// survive in a draw.io HTML label, which collapses runs of spaces.
func keepSpaces(s string) string {
	var b strings.Builder
	prevSpace := true
	for _, r := range s {
		if r == ' ' && prevSpace {
			b.WriteRune('\u00a0')
			continue
		}
		prevSpace = r == ' '
		b.WriteRune(r)
	}
	return b.String()
}

// xmlEscape escapes text for an XML text node or attribute value.
func xmlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- draw.io -------------------------------------------------------

// drawioLabel renders the lines as the HTML value of a draw.io cell.
// The HTML is escaped once as HTML (the label text) and the result is
// escaped again by the caller as an XML attribute.
func drawioLabel(lines []Line) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		style := fmt.Sprintf("font-size:%spx;color:%s;", num(l.Size), l.Color)
		if l.Bold {
			style += "font-weight:bold;"
		}
		if l.Mono {
			style += "font-family:" + fontMono + ";"
		}
		parts = append(parts, `<span style="`+style+`">`+xmlEscape(keepSpaces(l.Text))+`</span>`)
	}
	return strings.Join(parts, "<br>")
}

func (n *node) drawio(id string) string {
	var s strings.Builder
	switch n.shape {
	case shapeRect:
		if n.arc > 0 {
			fmt.Fprintf(&s, "rounded=1;absoluteArcSize=1;arcSize=%s;", num(n.arc))
		} else {
			s.WriteString("rounded=0;")
		}
	case shapeCylinder:
		fmt.Fprintf(&s, "shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=%s;", num(cylinderCap(n.w, n.h)))
	case shapeNote:
		fmt.Fprintf(&s, "shape=note;size=%s;", num(noteFold))
	case shapeEllipse:
		s.WriteString("ellipse;aspect=fixed;")
	case shapeText:
		s.WriteString("text;")
	}
	fill, stroke := n.fill, n.stroke
	if fill == "" {
		fill = "none"
	}
	if stroke == "" {
		stroke = "none"
	}
	fmt.Fprintf(&s, "fillColor=%s;strokeColor=%s;", fill, stroke)
	if n.stroke != "" {
		fmt.Fprintf(&s, "strokeWidth=%s;", num(n.sw))
	}
	if n.dash != "" {
		fmt.Fprintf(&s, "dashed=1;dashPattern=%s;", n.dash)
	}
	s.WriteString("whiteSpace=wrap;html=1;")
	value := ""
	if len(n.lines) > 0 {
		minSize := n.lines[0].Size
		for _, l := range n.lines {
			minSize = min(minSize, l.Size)
		}
		fmt.Fprintf(&s, "fontFamily=%s;fontSource=%s;fontSize=%s;fontColor=%s;align=%s;verticalAlign=%s;spacing=0;",
			fontSans, fontSourceSans, num(minSize), n.lines[0].Color, n.align, n.valign)
		if n.padX > 0 {
			fmt.Fprintf(&s, "spacingLeft=%s;spacingRight=%s;", num(n.padX), num(n.padX))
		}
		if n.padY > 0 {
			fmt.Fprintf(&s, "spacingTop=%s;", num(n.padY))
		}
		value = drawioLabel(n.lines)
	}
	return fmt.Sprintf(`<mxCell id="%s" value="%s" style="%s" vertex="1" parent="1">`+
		`<mxGeometry x="%s" y="%s" width="%s" height="%s" as="geometry"/></mxCell>`,
		id, xmlEscape(value), s.String(), num(n.x), num(n.y), num(n.w), num(n.h))
}

// drawioHead returns the style keys of one end of an edge; side is
// "start" or "end".
func drawioHead(side string, h head) string {
	switch h {
	case headBlock:
		return side + "Arrow=block;" + side + "Fill=1;" + side + "Size=8;"
	case headOpen:
		return side + "Arrow=open;" + side + "Fill=0;" + side + "Size=10;"
	case headNone:
	}
	return side + "Arrow=none;"
}

func (e *edge) drawio(id string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "edgeStyle=none;rounded=0;html=1;strokeColor=%s;strokeWidth=%s;", e.color, num(e.sw))
	s.WriteString(drawioHead("end", e.end))
	s.WriteString(drawioHead("start", e.start))
	if e.dash != "" {
		fmt.Fprintf(&s, "dashed=1;dashPattern=%s;", e.dash)
	}
	src, tgt := e.pts[0], e.pts[len(e.pts)-1]
	var mid strings.Builder
	for _, p := range e.pts[1 : len(e.pts)-1] {
		fmt.Fprintf(&mid, `<mxPoint x="%s" y="%s"/>`, num(p.X), num(p.Y))
	}
	arr := ""
	if mid.Len() > 0 {
		arr = `<Array as="points">` + mid.String() + `</Array>`
	}
	return fmt.Sprintf(`<mxCell id="%s" value="" style="%s" edge="1" parent="1"><mxGeometry relative="1" as="geometry">`+
		`<mxPoint x="%s" y="%s" as="sourcePoint"/><mxPoint x="%s" y="%s" as="targetPoint"/>%s</mxGeometry></mxCell>`,
		id, s.String(), num(src.X), num(src.Y), num(tgt.X), num(tgt.Y), arr)
}

// Drawio returns the draw.io source of the figure, stored
// uncompressed so a change shows up as a readable diff.
func (f *Figure) Drawio() string {
	w, h := f.size()
	var s strings.Builder
	fmt.Fprintf(&s, "<mxfile host=\"drawio\" type=\"device\">\n  <diagram id=\"%s\" name=\"%s\">\n", f.Name, xmlEscape(f.Title))
	fmt.Fprintf(&s, "    <mxGraphModel dx=\"%s\" dy=\"%s\" grid=\"1\" gridSize=\"10\" guides=\"1\" tooltips=\"1\" connect=\"1\" "+
		"arrows=\"1\" fold=\"1\" page=\"0\" pageScale=\"1\" pageWidth=\"%s\" pageHeight=\"%s\" background=\"%s\" math=\"0\" shadow=\"0\">\n",
		num(w), num(h), num(w), num(h), colorBackground)
	s.WriteString("      <root>\n        <mxCell id=\"0\"/>\n        <mxCell id=\"1\" parent=\"0\"/>\n")
	for i, e := range f.els {
		fmt.Fprintf(&s, "        %s\n", e.drawio(fmt.Sprintf("%s-%d", f.Name, i+1)))
	}
	s.WriteString("      </root>\n    </mxGraphModel>\n  </diagram>\n</mxfile>\n")
	return s.String()
}

// --- SVG -----------------------------------------------------------

// noteFold is the size of the folded corner of a note.
const noteFold = 14.0

// cylinderCap is the depth of the elliptic cap of a cylinder: deeper
// on a wide cylinder so its cap does not flatten into a line.
func cylinderCap(w, h float64) float64 { return math.Min(math.Min(math.Max(w/30, 8), 20), h/4) }

func (n *node) svgShape() string {
	attrs := func() string {
		fill := n.fill
		if fill == "" {
			fill = "none"
		}
		a := fmt.Sprintf(` fill="%s"`, fill)
		if n.stroke != "" {
			a += fmt.Sprintf(` stroke="%s" stroke-width="%s"`, n.stroke, num(n.sw))
			if n.dash != "" {
				a += fmt.Sprintf(` stroke-dasharray="%s"`, svgDash(n.dash, n.sw))
			}
		}
		return a
	}
	x, y, w, h := n.x, n.y, n.w, n.h
	switch n.shape {
	case shapeRect:
		rx := ""
		if n.arc > 0 {
			rx = fmt.Sprintf(` rx="%s"`, num(math.Min(n.arc/2, math.Min(w, h)/2)))
		}
		return fmt.Sprintf(`<rect x="%s" y="%s" width="%s" height="%s"%s%s/>`, num(x), num(y), num(w), num(h), rx, attrs())
	case shapeEllipse:
		return fmt.Sprintf(`<ellipse cx="%s" cy="%s" rx="%s" ry="%s"%s/>`, num(x+w/2), num(y+h/2), num(w/2), num(h/2), attrs())
	case shapeNote:
		s := noteFold
		body := fmt.Sprintf(`<path d="M%s %sH%sL%s %sV%sH%sZ"%s/>`,
			num(x), num(y), num(x+w-s), num(x+w), num(y+s), num(y+h), num(x), attrs())
		fold := fmt.Sprintf(`<path d="M%s %sV%sH%s" fill="none" stroke="%s" stroke-width="%s"/>`,
			num(x+w-s), num(y), num(y+s), num(x+w), n.stroke, num(n.sw))
		return body + "\n" + fold
	case shapeCylinder:
		// The same cubic curves draw.io's cylinder3 shape draws.
		d := cylinderCap(w, h)
		body := fmt.Sprintf(`<path d="M%s %sC%s %s %s %s %s %sV%sC%s %s %s %s %s %sZ"%s/>`,
			num(x), num(y+d),
			num(x), num(y-d/3), num(x+w), num(y-d/3), num(x+w), num(y+d),
			num(y+h-d),
			num(x+w), num(y+h+d/3), num(x), num(y+h+d/3), num(x), num(y+h-d),
			attrs())
		rim := fmt.Sprintf(`<path d="M%s %sC%s %s %s %s %s %s" fill="none" stroke="%s" stroke-width="%s"/>`,
			num(x), num(y+d), num(x), num(y+2*d), num(x+w), num(y+2*d), num(x+w), num(y+d), n.stroke, num(n.sw))
		return body + "\n" + rim
	case shapeText:
	}
	return ""
}

// svgDash converts a draw.io dashPattern, which is in units of the
// stroke width, into an SVG stroke-dasharray.
func svgDash(pattern string, sw float64) string {
	fields := strings.Fields(pattern)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		v, err := strconv.ParseFloat(f, 64)
		if err != nil {
			continue
		}
		out = append(out, num(v*sw))
	}
	return strings.Join(out, " ")
}

// textTop returns the y of the top of the label block.
func (n *node) textTop() float64 {
	_, bh := blockSize(n.lines)
	if n.valign == "top" {
		return n.y + n.padY
	}
	// A cylinder centres its label below the cap, like draw.io's
	// boundedLbl does.
	if n.shape == shapeCylinder {
		d := cylinderCap(n.w, n.h)
		return n.y + 2*d + (n.h-2*d)/2 - bh/2 - d/4
	}
	return n.y + n.h/2 - bh/2
}

func (n *node) svgText() string {
	var s strings.Builder
	y := n.textTop()
	for _, l := range n.lines {
		lh := l.Size * lineHeight
		base := y + lh/2 + 0.35*l.Size
		var x float64
		anchor := ""
		switch n.align {
		case "left":
			x = n.x + n.padX
		case "right":
			x = n.x + n.w - n.padX
			anchor = ` text-anchor="end"`
		default:
			x = n.x + n.w/2
			anchor = ` text-anchor="middle"`
		}
		weight := ""
		if l.Bold {
			weight = ` font-weight="700"`
		}
		family := ""
		if l.Mono {
			family = fmt.Sprintf(` font-family="%s"`, svgFontMono)
		}
		// xml:space="preserve" keeps an indentation or a run of spaces
		// that the default white-space handling would collapse.
		space := ""
		if strings.HasPrefix(l.Text, " ") || strings.Contains(l.Text, "  ") {
			space = ` xml:space="preserve"`
		}
		fmt.Fprintf(&s, "\n"+`<text x="%s" y="%s" font-size="%s"%s%s fill="%s"%s%s>%s</text>`,
			num(x), num(base), num(l.Size), weight, family, l.Color, anchor, space, xmlEscape(l.Text))
		y += lh
	}
	return s.String()
}

func (n *node) svg() string {
	out := ""
	if n.shape != shapeText && (n.fill != "" || n.stroke != "") {
		out = n.svgShape()
	}
	text := n.svgText()
	if out == "" {
		return strings.TrimPrefix(text, "\n")
	}
	return out + text
}

// arrowhead geometry for an arrow stroke width of 2.5.
const (
	headLength = 13.0
	headHalf   = 6.0
	headInset  = 9.0
)

func (e *edge) svg() string {
	pts := append([]pt(nil), e.pts...)
	var heads []string
	trim := func(tip, from pt, h head) pt {
		dx, dy := tip.X-from.X, tip.Y-from.Y
		l := math.Hypot(dx, dy)
		if l == 0 {
			return tip
		}
		ux, uy := dx/l, dy/l
		bx, by := tip.X-ux*headLength, tip.Y-uy*headLength
		px, py := -uy*headHalf, ux*headHalf
		switch h {
		case headBlock:
			heads = append(heads, fmt.Sprintf(`<polygon points="%s,%s %s,%s %s,%s" fill="%s"/>`,
				num(tip.X), num(tip.Y), num(bx+px), num(by+py), num(bx-px), num(by-py), e.color))
			return pt{tip.X - ux*headInset, tip.Y - uy*headInset}
		case headOpen:
			heads = append(heads, fmt.Sprintf(`<polyline points="%s,%s %s,%s %s,%s" fill="none" stroke="%s" stroke-width="%s"/>`,
				num(bx+px), num(by+py), num(tip.X), num(tip.Y), num(bx-px), num(by-py), e.color, num(e.sw)))
		case headNone:
		}
		return tip
	}
	n := len(pts)
	if e.end != headNone {
		pts[n-1] = trim(e.pts[n-1], e.pts[n-2], e.end)
	}
	if e.start != headNone {
		pts[0] = trim(e.pts[0], e.pts[1], e.start)
	}
	coords := make([]string, 0, n)
	for _, p := range pts {
		coords = append(coords, num(p.X)+","+num(p.Y))
	}
	dash := ""
	if e.dash != "" {
		dash = fmt.Sprintf(` stroke-dasharray="%s"`, svgDash(e.dash, e.sw))
	}
	line := fmt.Sprintf(`<polyline points="%s" fill="none" stroke="%s" stroke-width="%s"%s/>`,
		strings.Join(coords, " "), e.color, num(e.sw), dash)
	return strings.Join(append([]string{line}, heads...), "\n")
}

// SVG returns the SVG export of the figure.
func (f *Figure) SVG() string {
	return f.svgDoc(true, func(int) bool { return true })
}

// Frames returns one SVG per build stage of a staged figure, and nil
// for a figure with a single stage. Every frame has the size of the
// whole figure and holds only what its stage adds, and only the first
// paints the background, so frames stacked in order on one spot are the
// figure. A slide that shows them all at once, a printed page or a PDF
// for example, therefore still shows the whole drawing.
func (f *Figure) Frames() []string {
	last := f.lastStage()
	if last == 1 {
		return nil
	}
	frames := make([]string, 0, last)
	for n := 1; n <= last; n++ {
		frames = append(frames, f.svgDoc(n == 1, func(i int) bool { return f.stages[i] == n }))
	}
	return frames
}

// svgDoc renders the elements keep selects by index, on the canvas of
// the whole figure.
func (f *Figure) svgDoc(background bool, keep func(int) bool) string {
	w, h := f.size()
	var s strings.Builder
	fmt.Fprintf(&s, `<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s" font-family="%s" role="img" aria-label="%s">`+"\n",
		num(w), num(h), num(w), num(h), xmlEscape(svgFontSans), xmlEscape(f.Title))
	fmt.Fprintf(&s, "<title>%s</title>\n", xmlEscape(f.Title))
	if background {
		fmt.Fprintf(&s, `<rect width="%s" height="%s" fill="%s"/>`+"\n", num(w), num(h), colorBackground)
	}
	for i, e := range f.els {
		if !keep(i) {
			continue
		}
		s.WriteString(e.svg())
		s.WriteString("\n")
	}
	s.WriteString("</svg>\n")
	return s.String()
}
