package main

// seqPart is one participant of a sequence diagram: a box centred on
// x whose lifeline runs down from it.
type seqPart struct {
	x     float64
	r     role
	lines []Line
}

// seq lays out a sequence diagram top to bottom. Every message moves
// the cursor y down, so a figure lists its messages in order and the
// builder spaces them.
type seq struct {
	f     *Figure
	xs    []float64
	lives []*edge
	y     float64
}

// sequence draws the participant boxes along the top of the figure and
// starts the lifelines under them.
func (f *Figure) sequence(parts ...seqPart) *seq {
	s := &seq{f: f}
	bottom := 0.0
	heads := make([]*node, 0, len(parts))
	for _, p := range parts {
		n := f.box(p.r, spec{lines: p.lines})
		n.x = p.x - n.w/2
		heads = append(heads, n)
		bottom = max(bottom, n.h)
	}
	for _, n := range heads {
		n.h = bottom
		e := &edge{pts: []pt{{n.cx(), bottom}, {n.cx(), bottom}}, color: colorGrey, sw: strokeLife, dash: "4 3"}
		f.add(e)
		s.xs = append(s.xs, n.cx())
		s.lives = append(s.lives, e)
	}
	s.y = bottom + 24
	return s
}

// masked turns a free text into a label that hides the lifelines it
// sits on.
func masked(n *node) *node {
	n.fill = colorBackground
	return n
}

// msg draws a message from participant a to participant b with its
// label above the arrow. The label is centred on the arrow, unless the
// arrow passes over another participant's lifeline: then the label is
// centred in the gap between the sender's lifeline and the next
// lifeline toward the receiver, not on the lifeline the arrow passes.
func (s *seq) msg(k arrowKind, a, b int, lines ...Line) {
	xa, xb := s.xs[a], s.xs[b]
	var lbl *node
	if len(lines) > 0 {
		cx := (xa + xb) / 2
		switch {
		case b > a+1:
			cx = (xa + s.xs[a+1]) / 2
		case b < a-1:
			cx = (xa + s.xs[a-1]) / 2
		}
		lbl = masked(s.f.text(cx, s.y, "center", lines...))
	}
	y := s.y + 8
	if lbl != nil {
		y = lbl.y + lbl.h + 6
	}
	s.f.arrow(k, pt{xa, y}, pt{xb, y})
	s.y = y + 20
}

// self draws a call a participant makes to itself: a loop to the right
// of its lifeline, with the label beside the loop.
func (s *seq) self(a int, lines ...Line) {
	x := s.xs[a]
	_, bh := blockSize(lines)
	h := max(28, bh)
	top := s.y + 4
	s.f.arrow(flow, pt{x, top}, pt{x + 36, top}, pt{x + 36, top + h}, pt{x, top + h})
	if len(lines) > 0 {
		n := masked(s.f.text(x+46, 0, "left", lines...))
		n.y = top + h/2 - n.h/2
	}
	s.y = top + h + 22
}

// note draws a panel to the right of a lifeline.
func (s *seq) note(a int, lines ...Line) {
	n := s.f.panel(roleNeutral, spec{x: s.xs[a] + 16, y: s.y, lines: lines})
	n.fill = colorFrameFill
	s.y = n.y + n.h + 18
}

// end finishes the lifelines just under the last message.
func (s *seq) end() {
	for _, e := range s.lives {
		e.pts[1].Y = s.y
	}
}
