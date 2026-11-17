package main

import "math"

// col is one row of a database table drawing: the key marker (PK, FK,
// UQ, CK, EX, TG or none), the column, its type, and a note. A row
// with neither type nor note may carry a long name, such as a
// constraint expression.
type col struct {
	key, name, typ, note string
}

// Row metrics of a table drawing.
const (
	tableHeader = 40.0
	tableRow    = 26.0
	tableGap    = 18.0
)

// record draws a table-shaped record in the colours of r: a database
// table, or the fields of a message on the wire.
func (f *Figure) record(r role, x, y float64, title string, cols []col) *node {
	keyW, nameW, typW, noteW, freeW := 0.0, 0.0, 0.0, 0.0, 0.0
	for _, c := range cols {
		keyW = max(keyW, textWidth(Line{Text: c.key, Size: sizeChip, Bold: true, Mono: true}))
		nw := textWidth(code(c.name))
		if c.typ == "" && c.note == "" {
			freeW = max(freeW, nw)
			continue
		}
		nameW = max(nameW, nw)
		typW = max(typW, textWidth(code(c.typ)))
		noteW = max(noteW, textWidth(body(c.note)))
	}
	if keyW > 0 {
		keyW += tableGap
	}
	if typW > 0 {
		typW += tableGap
	}
	if noteW > 0 {
		noteW += tableGap
	}
	nameW += tableGap
	titleW := textWidth(codeName(title))
	w := math.Ceil(max(keyW+nameW+typW+noteW, keyW+freeW, titleW) + 2*padX + 4)
	h := tableHeader + float64(len(cols))*tableRow + 10

	outline := f.placed(&node{
		shape: shapeRect, arc: 12, fill: colorPaper, stroke: r.stroke, sw: strokeBox, solid: true,
	}, spec{x: x, y: y, w: w, h: h})
	f.add(&edge{pts: []pt{{x, y + tableHeader}, {x + w, y + tableHeader}}, color: r.stroke, sw: 1.5, inner: true})
	t := f.text(x+padX, y+8, "left", tinted(r.text, codeName(title))...)
	t.y = y + tableHeader/2 - t.h/2

	ry := y + tableHeader + 5
	for _, c := range cols {
		cx := x + padX
		put := func(l Line, at float64) {
			n := f.text(at, 0, "left", l)
			n.y = ry + tableRow/2 - n.h/2
		}
		if c.key != "" {
			put(Line{Text: c.key, Size: sizeChip, Bold: true, Mono: true, Color: r.text}, cx)
		}
		cx += keyW
		if c.name != "" {
			put(tinted(colorInk, code(c.name))[0], cx)
		}
		cx += nameW
		if c.typ != "" {
			put(code(c.typ), cx)
		}
		cx += typW
		if c.note != "" {
			put(body(c.note), cx)
		}
		ry += tableRow
	}
	return outline
}
