package main

// coreFigures are the core- figures of the core reference pages.
var coreFigures = []func() *Figure{
	coreRegistrationFlow,
	coreSSEConnectionStates,
	coreHeartbeatLoop,
	coreReconciliationCycle,
	coreEventVerificationPipeline,
	coreExecutionCallbackStates,
}

// coreFragment is a combined fragment of a sequence diagram: a loop,
// an alternative or an option, drawn as a thin outline around its
// messages with its kind in a dark chip at the top left.
type coreFragment struct {
	s      *seq
	out    *node
	x0, x1 float64
	gx     float64
}

// coreOpenFragment starts a combined fragment at the cursor of s that
// spans x0 to x1, and moves the cursor under its header. The guard
// starts at gx, right of the lifeline the chip sits left of, so no
// lifeline runs through it.
func coreOpenFragment(s *seq, x0, x1, gx float64, kind string, guard ...Line) *coreFragment {
	y := s.y
	out := &node{shape: shapeRect, x: x0, y: y, w: x1 - x0, arc: 12, stroke: colorGrey, sw: 1.5}
	s.f.add(out)
	c := s.f.tag(x0+12, y+12, kind, colorLine)
	gx = max(gx, c.x+c.w+10)
	bottom := c.y + c.h
	if len(guard) > 0 {
		t := s.f.text(gx, 0, "left", guard...)
		t.y = c.cy() - min(t.h, c.h)/2
		bottom = max(bottom, t.y+t.h)
	}
	s.y = bottom + 16
	return &coreFragment{s: s, out: out, x0: x0, x1: x1, gx: gx}
}

// orElse draws the dashed line that starts the next operand of an
// alternative, with the operand's guard under it.
func (fr *coreFragment) orElse(guard ...Line) {
	s := fr.s
	y := s.y - 6
	s.f.add(&edge{pts: []pt{{fr.x0, y}, {fr.x1, y}}, color: colorGrey, sw: 1.5, dash: "4 3"})
	t := s.f.text(fr.gx, y+8, "left", guard...)
	s.y = t.y + t.h + 14
}

// close ends the fragment under the last message drawn in it.
func (fr *coreFragment) close() {
	fr.out.h = fr.s.y - 6 - fr.out.y
	fr.s.y += 12
}

// coreMsg is seq.msg with the label centred on cx instead of between
// the two lifelines, so the label of a long message can sit in a lane
// that no other lifeline runs through.
func coreMsg(s *seq, k arrowKind, a, b int, cx float64, lines ...Line) {
	y := s.y + 8
	if len(lines) > 0 {
		lbl := masked(s.f.text(cx, s.y, "center", lines...))
		y = lbl.y + lbl.h + 6
	}
	s.f.arrow(k, pt{s.xs[a], y}, pt{s.xs[b], y})
	s.y = y + 20
}

// coreSelf is seq.self with an arrow kind of its own: a participant
// returning to itself is a reply, not a call.
func coreSelf(s *seq, k arrowKind, a int, lines ...Line) {
	x := s.xs[a]
	_, bh := blockSize(lines)
	h := max(28, bh)
	top := s.y + 4
	s.f.arrow(k, pt{x, top}, pt{x + 36, top}, pt{x + 36, top + h}, pt{x, top + h})
	if len(lines) > 0 {
		n := masked(s.f.text(x+46, 0, "left", lines...))
		n.y = top + h/2 - n.h/2
	}
	s.y = top + h + 22
}

// coreUpDown draws the two transitions between hub, above, and n,
// below it: the one down on the left with its label to the left, the
// one back up on the right with its label to the right.
func coreUpDown(f *Figure, hub, n *node, down, up []Line) {
	top, bottom := hub.y+hub.h, n.y
	my := (top + bottom) / 2
	f.arrow(flow, pt{n.cx() - 14, top}, pt{n.cx() - 14, bottom})
	f.arrow(flow, pt{n.cx() + 14, bottom}, pt{n.cx() + 14, top})
	if len(down) > 0 {
		f.labelLeft(pt{n.cx() - 14, my}, down...)
	}
	if len(up) > 0 {
		f.labelRight(pt{n.cx() + 14, my}, up...)
	}
}

// coreRegistrationFlow draws Registrar.Register for
// docs/reference/core/registration.md (Register): the cached identity,
// or the fresh registration from the bootstrap token to the NSK.
func coreRegistrationFlow() *Figure {
	f := &Figure{Name: "core-registration-flow", Title: "How the Registrar registers a node"}
	s := f.sequence(
		seqPart{x: 130, r: roleAgent, lines: []Line{codeName("Registrar")}},
		seqPart{x: 540, r: roleAgent, lines: []Line{codeName("TokenResolver")}},
		seqPart{x: 800, r: roleCore, lines: []Line{name("Control Plane")}},
		seqPart{x: 1030, r: roleStore, lines: []Line{name("Disk")}},
	)
	// Every message starts or ends at the Registrar, so every label
	// sits in the lane between it and the TokenResolver, where no other
	// lifeline runs through it.
	lane := (s.xs[0] + s.xs[1]) / 2
	msg := func(k arrowKind, a, b int, lines ...Line) { coreMsg(s, k, a, b, lane, lines...) }
	const x0, x1 = 10.0, 1090.0
	gx := s.xs[0] + 14
	msg(flow, 0, 3, code("LoadIdentity()"))
	alt := coreOpenFragment(s, x0, x1, gx, "alt", body("[identity exists]"))
	msg(reply, 3, 0, code("NodeIdentity"))
	s.self(0, code("BearerToken()"), body("bearer envelope"))
	msg(secretFlow, 0, 2, code("SetAuthToken(bearer)"))
	coreSelf(s, reply, 0, body("Return (cached)"))
	alt.orElse(body("[not registered]"))
	msg(reply, 3, 0, code("ErrNotRegistered"))
	msg(flow, 0, 1, code("Resolve()"), body("bootstrap token"))
	msg(reply, 1, 0, body("token + source"))
	s.self(0, code("GenerateKeypair()"))
	msg(flow, 0, 1, code("ResolveValue()"), code("project_id, resource_handle,"), code("requested_resource_id"))
	msg(reply, 1, 0, body("values (config or IMDS)"))
	s.self(0, body("Fail fast if project_id or"), body("resource_handle missing"))
	s.self(0, body("One nonce for the"), body("whole registration"))
	loop := coreOpenFragment(s, x0+16, x1-16, gx, "loop", body("[retry with backoff: max 5m,"), body("rate-limit waits excluded]"))
	msg(call, 0, 2, code("POST /v1/register"), body("no Authorization header,"), body("bootstrap token in body"))
	loop.close()
	msg(reply, 2, 0, code("node_id, mesh_ip, signing_public_key,"), code("signing_key_id, nsk, peer_snapshot,"), code("domain_mesh_cidr"))
	s.self(0, body("Build NodeIdentity,"), code("BearerToken()"))
	msg(flow, 0, 3, code("SaveIdentity()"), body("atomic write"))
	msg(flow, 0, 3, body("Remove or empty token file"), body("(if file-based)"))
	msg(secretFlow, 0, 2, code("SetAuthToken(bearer)"))
	alt.close()
	s.end()
	return f
}

// coreSSEConnectionStates draws the state machine of the SSE
// connection for docs/reference/core/control-plane-client.md (State
// Machine).
func coreSSEConnectionStates() *Figure {
	f := &Figure{Name: "core-sse-connection-states", Title: "States of the SSE connection"}
	const h = 56.0
	connecting := f.state(stateNormal, spec{x: 0, y: 190, w: 950, h: h, lines: []Line{name("Connecting")}})
	disc := f.state(stateNormal, spec{x: connecting.cx() - 120, y: 70, w: 240, h: h, lines: []Line{name("Disconnected")}})
	f.dot(disc.cx(), 0)
	f.arrow(flow, pt{disc.cx(), 9}, disc.top())
	f.arrow(flow, disc.bottom(), pt{disc.cx(), connecting.y})
	stopped := f.state(stateFailed, spec{x: 700, y: 70, w: 180, h: h, lines: []Line{name("Stopped")}})
	f.arrow(refuse, pt{stopped.cx(), connecting.y}, stopped.bottom())
	f.labelRight(pt{stopped.cx(), (stopped.y + stopped.h + connecting.y) / 2}, body("403 or 404"))
	f.final(stopped.cx(), 0)
	f.arrow(flow, stopped.top(), pt{stopped.cx(), 12})

	rowY := connecting.y + h + 130
	connected := f.state(stateNormal, spec{x: 10, y: rowY, w: 180, h: h, lines: []Line{name("Connected")}})
	pullOnly := f.state(stateNormal, spec{x: 350, y: rowY, w: 180, h: h, lines: []Line{name("PullOnly")}})
	backoff := f.state(stateNormal, spec{x: 730, y: rowY, w: 180, h: h, lines: []Line{name("Backoff")}})
	coreUpDown(f, connecting, connected, nil, []Line{body("connection"), body("dropped")})
	coreUpDown(f, connecting, pullOnly, []Line{body("501 descope")}, []Line{body("re-probe, every"), code("SSEReprobeInterval")})
	coreUpDown(f, connecting, backoff, []Line{body("transient error"), body("or 401")}, []Line{body("delay elapsed")})

	polling := f.state(stateNormal, spec{x: backoff.x, y: rowY + h + 120, w: 180, h: h, lines: []Line{name("Polling")}})
	f.arrow(flow, backoff.bottom(), polling.top())
	f.labelLeft(pt{backoff.cx(), (backoff.y + backoff.h + polling.y) / 2}, body("threshold exceeded"), body("(5 min)"))
	lane := connecting.x + connecting.w + 60
	f.arrow(flow, hvh(polling.right(), connecting.right(), lane)...)
	f.labelRight(pt{lane, (backoff.y + backoff.h + polling.y) / 2}, body("periodic"), body("SSE retry"))
	return f
}

// coreHeartbeatLoop draws HeartbeatService.Run for
// docs/reference/core/heartbeat-service.md (Heartbeat Loop).
func coreHeartbeatLoop() *Figure {
	f := &Figure{Name: "core-heartbeat-loop", Title: "The heartbeat loop"}
	s := f.sequence(
		seqPart{x: 150, r: roleAgent, lines: []Line{codeName("HeartbeatService")}},
		seqPart{x: 820, r: roleCore, lines: []Line{name("Control Plane")}},
	)
	const x0, x1 = 10.0, 960.0
	gx := s.xs[0] + 14
	s.self(0, body("Send initial heartbeat"))
	loop := coreOpenFragment(s, x0, x1, gx, "loop", body("[every 30s (configurable), or the probe delay while parked]"))
	s.self(0, body("Build HeartbeatRequest"))
	s.msg(call, 0, 1, code("POST /v1/nodes/{id}/heartbeat"))
	alt := coreOpenFragment(s, x0+16, x1-16, gx, "alt", body("[200 OK]"))
	s.msg(reply, 1, 0, code("HeartbeatResponse"))
	for _, o := range []struct {
		guard string
		lines []Line
	}{
		{"[parked]", []Line{body("Unpark:"), code("onCredentialRefused(false)")}},
		{"[reconcile = true]", []Line{code("TriggerReconcile()")}},
		{"[rotate_keys = true]", []Line{code("onRotateKeys()")}},
	} {
		opt := coreOpenFragment(s, x0+32, x1-32, gx, "opt", body(o.guard))
		s.self(0, o.lines...)
		opt.close()
	}
	alt.orElse(body("[401 Unauthorized]"))
	s.msg(reply, 1, 0, code("ErrUnauthorized"))
	s.self(0, body("Count the refusal, park on the third:"), code("onCredentialRefused(true)"))
	alt.orElse(body("[other error]"))
	s.msg(reply, 1, 0, body("Error"))
	s.self(0, body("Log error, continue"))
	alt.close()
	loop.close()
	s.end()
	return f
}

// coreReconciliationCycle draws one cycle of the Reconciler for
// docs/reference/core/reconciliation.md (Reconciliation Cycle). Every
// exit of a cycle whose fetch succeeded passes the cycle observer, and
// a failed fetch retries a pending withdrawal.
func coreReconciliationCycle() *Figure {
	f := &Figure{Name: "core-reconciliation-cycle", Title: "One reconciliation cycle"}
	const x, w, h, gap = 300.0, 370.0, 56.0, 60.0
	cx := x + w/2
	y := 60.0
	step := func(lines ...Line) *node {
		n := f.state(stateNormal, spec{x: x, y: y, w: w, h: h, lines: lines})
		y += h + gap
		return n
	}
	down := func(a, b *node, lines ...Line) {
		f.arrow(flow, a.bottom(), b.top())
		if len(lines) > 0 {
			f.labelRight(pt{cx, (a.y + a.h + b.y) / 2}, lines...)
		}
	}
	f.dot(cx, 0)
	f.text(cx+20, 0, "left", body("Tick / Trigger")).y = -11
	fetch := step(codeName("FetchState"))
	f.arrow(flow, pt{cx, 9}, fetch.top())
	dispatch := step(name("Invoke dispatch handlers"))
	diff := step(codeName("ComputeDiff"))
	empty := step(name("Diff empty, no reapply?"))
	handlers := step(name("Invoke handlers sequentially"))
	failed := step(name("Any handler failed?"))
	snapshot := step(name("Update snapshot"))
	observer := f.state(stateNormal, spec{x: x, y: y, w: 1110 - x, h: 80, lines: []Line{name("Call the cycle observer"), body("the state store writes the pull")}})
	done := f.state(stateNormal, spec{x: 0, y: observer.y + observer.h + gap, w: 1110, h: h, lines: []Line{name("Wait for next tick")}})

	down(fetch, dispatch, body("ok"))
	down(dispatch, diff)
	down(diff, empty)
	down(empty, handlers, body("no"))
	down(handlers, failed)
	down(failed, snapshot, body("no"))
	f.arrow(flow, snapshot.bottom(), observer.topAt(cx))
	f.arrow(flow, observer.bottomAt(cx), done.topAt(cx))

	skip := f.state(stateFailed, spec{x: 0, y: fetch.y, w: 220, h: 70, lines: []Line{body("Log warn or debug,"), body("skip cycle")}})
	skip.y = fetch.cy() - skip.h/2
	f.arrow(refuse, fetch.left(), skip.right())
	f.label(mid(fetch.left(), skip.right()), body("error"))
	retry := f.state(stateNormal, spec{x: 0, y: observer.y, w: 220, h: observer.h, lines: []Line{name("Retry a pending"), name("withdrawal")}})
	f.arrow(flow, skip.bottom(), retry.top())
	f.arrow(flow, retry.bottom(), done.topAt(retry.cx()))

	logErr := f.state(stateFailed, spec{x: x + w + 150, y: handlers.y, w: 230, h: 70, lines: []Line{body("Log error, continue"), body("next handler")}})
	logErr.y = handlers.cy() - logErr.h/2
	f.arrow(refuse, pt{x + w, handlers.cy() - 12}, pt{logErr.x, handlers.cy() - 12})
	f.label(pt{(x + w + logErr.x) / 2, handlers.cy() - 12}, body("handler error"))
	f.arrow(flow, pt{logErr.x, handlers.cy() + 12}, pt{x + w, handlers.cy() + 12})

	yesEmpty := observer.x + observer.w - 30
	f.arrow(flow, hv(empty.right(), observer.topAt(yesEmpty))...)
	f.label(pt{x + w + 40, empty.cy()}, body("yes"))
	yesFailed := logErr.cx()
	f.arrow(flow, hv(failed.right(), observer.topAt(yesFailed))...)
	f.label(pt{x + w + 40, failed.cy()}, body("yes"))
	return f
}

// coreEventVerificationPipeline draws the path of an SSE event from
// the control plane to its handlers for
// docs/reference/core/event-verification.md (Architecture): the
// SSEStream verifies each envelope and then dispatches it, and the
// SSEManager, off the path, builds the stream with the verifier and
// the dispatcher.
func coreEventVerificationPipeline() *Figure {
	f := &Figure{Name: "core-event-verification-pipeline", Title: "The path of an SSE event to its handlers"}
	const gap, rowY = 50.0, 160.0
	stages := [][]Line{
		{name("Control Plane")},
		{name("SSE Stream"), code("SSEStream")},
		{codeName("Ed25519Verifier")},
		{codeName("EventDispatcher")},
		{name("Handlers")},
	}
	x := 0.0
	var prev, stream *node
	for i, l := range stages {
		r, k := roleAgent, flow
		if i == 0 {
			r = roleCore
		}
		if i == 1 {
			k = publish
		}
		n := f.box(r, spec{x: x, y: rowY, h: 64, lines: l})
		if i == 1 {
			stream = n
		}
		if prev != nil {
			f.arrow(k, prev.right(), n.left())
		}
		prev = n
		x = n.x + n.w + gap
	}
	manager := f.box(roleAgent, spec{y: 0, h: 56, lines: []Line{codeName("SSEManager")}})
	manager.x = stream.cx() - manager.w/2
	f.arrow(creates, manager.bottom(), stream.top())
	f.labelRight(pt{stream.cx(), (manager.y + manager.h + stream.y) / 2}, body("builds, with the verifier"), body("and the dispatcher"))
	return f
}

// coreExecutionCallbackStates draws the callback states of an action
// execution for docs/reference/core/api-endpoints.md (POST
// /v1/nodes/{node_id}/executions/{execution_id}).
func coreExecutionCallbackStates() *Figure {
	f := &Figure{Name: "core-execution-callback-states", Title: "Callback states of an action execution"}
	const h = 56.0
	f.dot(0, h/2)
	pending := f.state(stateNormal, spec{x: 60, y: 0, w: 170, h: h, lines: []Line{codeName("pending")}})
	ack := f.state(stateNormal, spec{x: 300, y: 0, w: 170, h: h, lines: []Line{codeName("ack")}})
	started := f.state(stateNormal, spec{x: 540, y: 0, w: 190, h: h, lines: []Line{codeName("started")}})
	f.arrow(flow, pt{9, h / 2}, pending.left())
	f.arrow(flow, pending.right(), ack.left())
	f.arrow(flow, ack.right(), started.left())

	bus := started.x + started.w + 60
	for i, e := range []struct {
		label string
		k     stateKind
	}{{"succeeded", stateNormal}, {"failed", stateFailed}, {"cancelled", stateNormal}} {
		n := f.state(e.k, spec{x: bus + 60, y: float64(i) * 110, w: 210, h: h, lines: []Line{codeName(e.label)}})
		f.chipOn(n, "terminal", colorGrey)
		if i == 0 {
			f.arrow(flow, started.right(), n.left())
			continue
		}
		f.arrow(flow, hvh(started.right(), n.left(), bus)...)
	}

	const d = 26.0
	b := started.y + started.h
	f.arrow(flow, pt{started.cx() - d, b}, pt{started.cx() - d, b + 40}, pt{started.cx() + d, b + 40}, pt{started.cx() + d, b})
	f.labelUnder(pt{started.cx(), b + 40}, body("only to declare an"), body("over-ceiling output size"))
	return f
}
