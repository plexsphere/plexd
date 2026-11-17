package main

// conventionsFigures are the conventions- figures: the legend.
var conventionsFigures = []func() *Figure{conventionsLegend}

// conventionsLegend draws one sample of every element of the notation
// for docs/reference/development/diagrams.md (Notation legend).
func conventionsLegend() *Figure {
	f := &Figure{Name: "conventions-legend", Title: "Notation of the documentation figures"}
	const w = 1180.0
	under := func(n *node, s string) {
		f.text(n.cx(), n.y+n.h+10, "center", body(s))
	}

	// Roles.
	f.frame(roleNeutral, 0, 0, w, 210, "", "Roles", "the colour says what a thing is")
	type swatch struct {
		r     role
		label string
		sub   string
	}
	sw := []swatch{
		{roleCore, "control plane", "plexsphere, its API"},
		{roleAgent, "data plane", "plexd, Nodes"},
		{roleStore, "store", "data dir, cache, files"},
		{roleSecret, "secret material", "tokens, NSK, keys"},
		{roleEvent, "event, record", "SSE, reports, logs"},
		{roleExternal, "external system", "STUN, ACME, providers"},
		{roleSubstrate, "substrate", "hosts, kernel, clusters"},
		{roleFailure, "refusal, failure", "errors, failed states"},
	}
	for i, s := range sw {
		x := 24 + float64(i%4)*288
		y := 60 + float64(i/4)*72
		f.filled(s.r, spec{x: x, y: y, w: 260, h: 58, lines: []Line{name(s.label), body(s.sub)}})
	}

	// Shapes.
	sh := f.frame(roleNeutral, 0, 240, w, 250, "", "Shapes", "")
	comp := f.box(roleCore, spec{x: 24, y: 300, w: 200, h: 56, lines: []Line{name("Service")}})
	under(comp, "component")
	hl := f.filled(roleCore, spec{x: 250, y: 300, w: 200, h: 56, lines: []Line{name("Service")}})
	under(hl, "component, set apart")
	st := f.store(roleStore, spec{x: 476, y: 296, w: 200, h: 64, lines: []Line{name("state cache")}})
	under(st, "store")
	doc := f.sheet(roleSecret, spec{x: 702, y: 300, w: 200, h: 56, lines: []Line{name("response")}})
	under(doc, "message or document")
	act := f.actor(spec{x: 928, y: 300, w: 220, h: 56, lines: []Line{name("Operator")}})
	under(act, "outside actor")
	opt := f.dashedBox(roleNeutral, spec{x: 24, y: 400, w: 200, h: 56, lines: []Line{name("dispatcher")}})
	f.chipOn(opt, "not built", colorGrey)
	under(opt, "planned, not built")
	f.tag(270, 414, "binary", colorLine)
	f.text(360, 413, "left", heading("cmd/plexd"))
	f.text(270, 466, "left", body("frame: a binary, a cluster, a scope"))
	tb := f.record(roleStore, 702, 402, "table", []col{{"PK", "id", "uuid", ""}})
	f.text(tb.x+tb.w+20, tb.y+30, "left", body("database table,"), body("record on the wire"))
	sh.h = 540 - sh.y

	// Arrows.
	ar := f.frame(roleNeutral, 0, 570, w, 300, "", "Arrows", "")
	kinds := []struct {
		k     arrowKind
		label string
	}{
		{flow, "order, data flow, transition"},
		{call, "call across a boundary"},
		{reply, "reply"},
		{publish, "event or audit row"},
		{secretFlow, "secret material"},
		{creates, "creates, provisions"},
		{outOfBand, "out of band, by a person"},
		{planned, "planned, not built"},
		{refuse, "refusal, error exit"},
		{derived, "derived at run time"},
		{relation, "relation, no direction"},
		{both, "traffic both ways"},
	}
	for i, k := range kinds {
		x := 24 + float64(i%3)*384
		y := 634 + float64(i/3)*58
		f.arrow(k.k, pt{x, y}, pt{x + 110, y})
		t := f.text(x+126, 0, "left", body(k.label))
		t.y = y - t.h/2
	}
	ar.h = 870 - ar.y

	// State machines and sequences.
	sm := f.frame(roleNeutral, 0, 900, 750, 300, "", "State machines", "")
	f.dot(50, 1000)
	f.arrow(flow, pt{59, 1000}, pt{110, 1000})
	f.text(50, 1030, "center", body("initial"))
	s1 := f.state(stateNormal, spec{x: 110, y: 972, w: 150, h: 56, lines: []Line{name("active")}})
	under(s1, "state")
	s2 := f.state(stateNormal, spec{x: 390, y: 972, w: 150, h: 56, lines: []Line{name("expired")}})
	f.chipOn(s2, "terminal", colorGrey)
	f.arrow(flow, s1.right(), s2.left())
	f.label(mid(s1.right(), s2.left()), codeName("Expire"), body("trigger"))
	under(s2, "terminal state")
	f.arrow(flow, s2.right(), pt{s2.x + s2.w + 60, s2.cy()})
	f.final(s2.x+s2.w+72, s2.cy())
	f.text(s2.x+s2.w+72, s2.cy()+24, "center", body("final"))
	sink := f.state(stateSink, spec{x: 110, y: 1100, w: 150, h: 56, lines: []Line{name("Deleted")}})
	f.chipOn(sink, "sticky", colorGrey)
	f.loop(sink, body("self-transition"))
	failed := f.state(stateFailed, spec{x: 470, y: 1100, w: 150, h: 56, lines: []Line{name("Failed")}})
	under(failed, "failed state")
	sm.h = 1200 - sm.y

	f.frame(roleNeutral, 780, 900, w-780, 300, "", "Sequences and notes", "")
	f.badge(820, 980, "1")
	f.text(846, 968, "left", body("step badge: the step"), body("the page lists"))
	f.add(&edge{pts: []pt{{820, 1030}, {820, 1080}}, color: colorGrey, sw: strokeLife, dash: "4 3"})
	f.text(846, 1050, "left", body("a lifeline"))
	f.notePanel(970, 1100, 190, pt{910, 1128}, name("note"), body("attached to a box"))
	return f
}
