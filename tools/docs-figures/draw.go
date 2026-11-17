package main

import "math"

// The drawing vocabulary of the figures. Every helper maps to one row
// of the notation table in docs/reference/development/diagrams.md, so a figure
// says what a thing is ("a store", "a state", "a call") and the helper
// decides how it looks.

// --- label lines ---------------------------------------------------

// name is the bold name of a box or a state.
func name(s string) Line { return Line{Text: s, Size: sizeName, Bold: true} }

// body is a second line in the regular weight.
func body(s string) Line { return Line{Text: s, Size: sizeBody} }

// code is a monospaced identifier: a Go symbol, a table, a path.
func code(s string) Line { return Line{Text: s, Size: sizeCode, Mono: true} }

// codeName is a monospaced identifier that names its box.
func codeName(s string) Line { return Line{Text: s, Size: sizeCode + 1, Mono: true, Bold: true} }

// heading is the bold title of a frame.
func heading(s string) Line { return Line{Text: s, Size: sizeHeading, Bold: true} }

// small is a caption or a footnote line.
func small(s string) Line { return Line{Text: s, Size: sizeCaption} }

// colored fills in the colour of every line that has none: strong for
// bold lines, weak for the rest.
func colored(lines []Line, strong, weak string) []Line {
	out := make([]Line, len(lines))
	for i, l := range lines {
		if l.Color == "" {
			if l.Bold {
				l.Color = strong
			} else {
				l.Color = weak
			}
		}
		out[i] = l
	}
	return out
}

// tinted sets the colour of every line.
func tinted(c string, lines ...Line) []Line {
	out := make([]Line, len(lines))
	for i, l := range lines {
		l.Color = c
		out[i] = l
	}
	return out
}

// --- boxes ---------------------------------------------------------

// Padding inside a box between the outline and the label.
const (
	padX = 14.0
	padY = 10.0
)

// spec places and sizes a box. A zero w or h sizes the box to its
// label.
type spec struct {
	x, y, w, h float64
	lines      []Line
}

func (f *Figure) placed(n *node, s spec) *node {
	bw, bh := blockSize(n.lines)
	n.x, n.y, n.w, n.h = s.x, s.y, s.w, s.h
	if n.w == 0 {
		n.w = math.Ceil(bw + 2*n.padX + 8)
	}
	if n.h == 0 {
		n.h = math.Ceil(bh + 2*padY)
	}
	f.add(n)
	return n
}

// box is a component: a service, a package, a process, a participant.
func (f *Figure) box(r role, s spec) *node {
	return f.placed(&node{
		shape: shapeRect, arc: 16, fill: colorPaper, stroke: r.stroke, sw: strokeBox,
		lines: colored(s.lines, r.text, colorMuted), align: "center", valign: "middle", padX: padX, solid: true,
	}, s)
}

// filled is a component drawn in the fill of its role, to set it
// apart from the plain boxes around it.
func (f *Figure) filled(r role, s spec) *node {
	n := f.box(r, s)
	n.fill = r.fill
	return n
}

// tile is a small named box in a row of many: its narrow padding fits
// short labels into narrow boxes.
func (f *Figure) tile(r role, x, y, w float64, label string) {
	n := f.box(r, spec{x: x, y: y, w: w, h: 50, lines: []Line{{Text: label, Size: sizeBody, Bold: true}}})
	n.padX = 4
}

// panel is a box with a left-aligned label that starts at the top:
// a list of steps, fields or notes.
func (f *Figure) panel(r role, s spec) *node {
	n := f.box(r, s)
	n.align, n.valign, n.padY = "left", "top", padY
	if s.h == 0 {
		_, bh := blockSize(n.lines)
		n.h = math.Ceil(bh + 2*padY)
	}
	if s.w == 0 {
		bw, _ := blockSize(n.lines)
		n.w = math.Ceil(bw + 2*padX + 4)
	}
	return n
}

// dashedBox is a component that is optional or not built yet.
func (f *Figure) dashedBox(r role, s spec) *node {
	n := f.box(r, s)
	n.dash = "3 2"
	return n
}

// store is a store or a backing service, drawn as a cylinder.
func (f *Figure) store(r role, s spec) *node {
	n := f.box(r, s)
	n.shape = shapeCylinder
	n.fill = r.fill
	if s.h == 0 {
		n.h += 2 * cylinderCap(n.w, n.h+40)
	}
	return n
}

// sheet is a document or a message on the wire, drawn as a note with
// a folded corner.
func (f *Figure) sheet(r role, s spec) *node {
	n := f.box(r, s)
	n.shape = shapeNote
	n.arc = 0
	if s.w == 0 {
		n.w += noteFold / 2
	}
	return n
}

// actor is someone or something outside the system that acts: an
// operator, a user, a browser, a CI runner.
func (f *Figure) actor(s spec) *node {
	n := f.box(role{stroke: colorLine, text: colorInk}, s)
	n.arc = 8
	return n
}

// stateKind is the flavour of a state of a state machine.
type stateKind int

const (
	stateNormal stateKind = iota
	stateFailed
	stateSink // a state left only after someone intervenes, or a sticky sink
)

// state is a state of a state machine or a step of a pipeline.
func (f *Figure) state(k stateKind, s spec) *node {
	n := f.placed(&node{
		shape: shapeRect, arc: 12, fill: colorPaper, stroke: colorLine, sw: strokeBox,
		lines: colored(s.lines, colorInk, colorMuted), align: "center", valign: "middle", padX: padX, solid: true,
	}, s)
	switch k {
	case stateFailed:
		n.fill, n.stroke = roleFailure.fill, roleFailure.stroke
		n.lines = colored(s.lines, roleFailure.text, roleFailure.text)
	case stateSink:
		n.fill, n.stroke = colorGreyFill, colorGrey
	case stateNormal:
	}
	return n
}

// frame groups the boxes it contains: a binary, a cluster, a scope.
// The title sits at the top left, after an optional dark chip.
func (f *Figure) frame(r role, x, y, w, h float64, chip, title, note string) *node {
	fill, stroke := colorFrameFill, colorGrey
	if r != roleNeutral {
		fill, stroke = r.fill, r.stroke
	}
	fr := &node{shape: shapeRect, x: x, y: y, w: w, h: h, arc: 24, fill: fill, stroke: stroke, sw: strokeFrame}
	f.add(fr)
	tx := x + 16
	if chip != "" {
		c := f.tag(tx, y+14, chip, colorLine)
		tx += c.w + 10
	}
	if title != "" {
		t := f.text(tx, y+12, "left", tinted(colorInk, heading(title))...)
		tx += t.w + 12
	}
	if note != "" {
		f.text(tx, y+15, "left", tinted(colorMuted, body(note))...)
	}
	return fr
}

// tag is a filled chip: the kind of a frame.
func (f *Figure) tag(x, y float64, label, fill string) *node {
	l := Line{Text: label, Size: sizeChip, Bold: true, Color: colorWhiteText}
	return f.placed(&node{
		shape: shapeRect, arc: 26, fill: fill, lines: []Line{l}, align: "center", valign: "middle", padX: 6,
	}, spec{x: x, y: y, w: math.Ceil(textWidth(l) + 22), h: 26})
}

// chip is an outlined marker on a box or an edge: "terminal",
// "sticky", "not built".
func (f *Figure) chip(x, y float64, label, color string) *node {
	l := Line{Text: label, Size: sizeChip, Bold: true, Color: color}
	return f.placed(&node{
		shape: shapeRect, arc: 24, fill: colorPaper, stroke: color, sw: 1.5, lines: []Line{l},
		align: "center", valign: "middle", padX: 6,
	}, spec{x: x, y: y, w: math.Ceil(textWidth(l) + 20), h: 24})
}

// chipOn puts a chip on the top edge of n, flush with its right side.
func (f *Figure) chipOn(n *node, label, color string) {
	c := f.chip(0, 0, label, color)
	c.x, c.y = n.x+n.w-c.w-12, n.y-c.h/2
}

// badge is the number of a step in a sequence.
func (f *Figure) badge(cx, cy float64, label string) {
	r := 14.0
	l := Line{Text: label, Size: sizeChip, Bold: true, Color: colorWhiteText}
	f.placed(&node{
		shape: shapeEllipse, fill: colorInkDark, lines: []Line{l}, align: "center", valign: "middle",
	}, spec{x: cx - r, y: cy - r, w: 2 * r, h: 2 * r})
}

// dot is the initial marker of a state machine.
func (f *Figure) dot(cx, cy float64) {
	f.placed(&node{shape: shapeEllipse, fill: colorInkDark}, spec{x: cx - 9, y: cy - 9, w: 18, h: 18})
}

// final is the final marker of a state machine: a ring around a dot.
func (f *Figure) final(cx, cy float64) {
	f.placed(&node{shape: shapeEllipse, fill: colorBackground, stroke: colorInkDark, sw: 2}, spec{x: cx - 12, y: cy - 12, w: 24, h: 24})
	f.placed(&node{shape: shapeEllipse, fill: colorInkDark}, spec{x: cx - 7, y: cy - 7, w: 14, h: 14})
}

// text is a free text. x is its left edge, its centre or its right
// edge, as align says; y is its top.
func (f *Figure) text(x, y float64, align string, lines ...Line) *node {
	lines = colored(lines, colorInk, colorMuted)
	bw, bh := blockSize(lines)
	w := math.Ceil(bw + 6)
	left := x
	switch align {
	case "center":
		left = x - w/2
	case "right":
		left = x - w
	}
	return f.placed(&node{shape: shapeText, lines: lines, align: align, valign: "middle"},
		spec{x: left, y: y, w: w, h: math.Ceil(bh)})
}

// label puts an edge label centred over p, its bottom 6 pixels above.
func (f *Figure) label(p pt, lines ...Line) {
	n := f.text(p.X, 0, "center", lines...)
	n.y = p.Y - 6 - n.h
}

// labelUnder puts an edge label centred under p.
func (f *Figure) labelUnder(p pt, lines ...Line) {
	f.text(p.X, p.Y+6, "center", lines...)
}

// labelRight puts an edge label to the right of p, vertically centred
// on it.
func (f *Figure) labelRight(p pt, lines ...Line) *node {
	n := f.text(p.X+10, 0, "left", lines...)
	n.y = p.Y - n.h/2
	return n
}

// labelLeft puts an edge label to the left of p, vertically centred
// on it.
func (f *Figure) labelLeft(p pt, lines ...Line) {
	n := f.text(p.X-10, 0, "right", lines...)
	n.y = p.Y - n.h/2
}

// notePanel is a note attached to a box: a grey panel with the lines
// left-aligned, joined to the box by a thin line from 'from'.
func (f *Figure) notePanel(x, y, w float64, from pt, lines ...Line) {
	n := f.panel(roleNeutral, spec{x: x, y: y, w: w, lines: lines})
	n.fill, n.arc = colorFrameFill, 8
	to := pt{n.x, min(max(from.Y, n.y+12), n.y+n.h-12)}
	switch {
	case from.X > n.x+n.w:
		to.X = n.x + n.w
	case from.Y < n.y:
		to = pt{min(max(from.X, n.x+12), n.x+n.w-12), n.y}
	case from.Y > n.y+n.h:
		to = pt{min(max(from.X, n.x+12), n.x+n.w-12), n.y + n.h}
	}
	f.arrow(relation, from, to)
}

// loop draws a transition from n back to itself on its right side,
// with the label right of the loop.
func (f *Figure) loop(n *node, lines ...Line) *node {
	d := min(14, n.h/4)
	x := n.x + n.w
	f.arrow(flow, pt{x, n.cy() - d}, pt{x + 34, n.cy() - d}, pt{x + 34, n.cy() + d}, pt{x, n.cy() + d})
	return f.labelRight(pt{x + 34, n.cy()}, lines...)
}

// caption writes a footnote at y, flush with the left edge of what
// the figure has drawn so far.
func (f *Figure) caption(y float64, lines ...string) {
	ls := make([]Line, 0, len(lines))
	for _, l := range lines {
		ls = append(ls, small(l))
	}
	f.text(f.extent().x0, y, "left", ls...)
}

// --- edges ---------------------------------------------------------

// arrowKind is what an edge means; it fixes colour, pattern and heads.
type arrowKind struct {
	color string
	dash  string
	start head
	end   head
}

var (
	// flow is order or data flow inside the system: a step leads to the
	// next, a transition of a state machine.
	flow = arrowKind{color: colorLine, end: headBlock}
	// call is a request across a process or network boundary.
	call = arrowKind{color: roleCore.stroke, end: headBlock}
	// reply is the response to a call.
	reply = arrowKind{color: colorLine, dash: "3 2", end: headOpen}
	// publish is an event or an audit row on its way.
	publish = arrowKind{color: roleEvent.stroke, end: headBlock}
	// secretFlow carries secret material in its direction.
	secretFlow = arrowKind{color: roleSecret.stroke, end: headBlock}
	// creates is plexd or the control plane creating or reconciling what
	// it points at.
	creates = arrowKind{color: roleAgent.stroke, end: headBlock}
	// outOfBand is a hand-off outside plexd and the control plane, by a
	// person.
	outOfBand = arrowKind{color: colorLine, dash: "4 3", end: headBlock}
	// derived is a relation that holds at run time without being
	// stored: a transitive membership, a resolved value.
	derived = arrowKind{color: colorGrey, dash: "1 3", end: headBlock}
	// planned is a path that is designed but not built.
	planned = arrowKind{color: colorGrey, dash: "3 2", end: headBlock}
	// refuse is the exit to a refusal or an error.
	refuse = arrowKind{color: roleFailure.stroke, end: headBlock}
	// relation is an association without a direction: a foreign key,
	// a mount, membership.
	relation = arrowKind{color: colorGrey}
	// wire is a connection drawn as a plain line in the colour of
	// the data plane: the shared uplink of several Nodes.
	wire = arrowKind{color: roleAgent.stroke}
	// both is traffic in both directions.
	both = arrowKind{color: roleAgent.stroke, start: headBlock, end: headBlock}
)

// arrow draws a polyline of the given kind through pts.
func (f *Figure) arrow(k arrowKind, pts ...pt) *edge {
	e := &edge{pts: pts, color: k.color, sw: strokeArrow, dash: k.dash, start: k.start, end: k.end}
	f.add(e)
	return e
}

// Routing helpers: each returns the points of an orthogonal path.

// hv goes horizontally first, then vertically.
func hv(a, b pt) []pt { return []pt{a, {b.X, a.Y}, b} }

// vh goes vertically first, then horizontally.
func vh(a, b pt) []pt { return []pt{a, {a.X, b.Y}, b} }

// vhv goes down or up to y, across, then on to b.
func vhv(a, b pt, y float64) []pt { return []pt{a, {a.X, y}, {b.X, y}, b} }

// hvh goes across to x, down or up, then on to b.
func hvh(a, b pt, x float64) []pt { return []pt{a, {x, a.Y}, {x, b.Y}, b} }

// mid returns the midpoint of a and b.
func mid(a, b pt) pt { return pt{(a.X + b.X) / 2, (a.Y + b.Y) / 2} }
