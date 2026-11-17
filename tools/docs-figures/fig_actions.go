package main

import "math"

// actionsFigures are the actions- figures of the actions reference and the hook scripts how-to.
var actionsFigures = []func() *Figure{
	actionsIntegrityVerification,
	actionsDispatchFlow,
	actionsRunFlow,
	actionsSessionAuthorization,
	actionsLocalTransport,
	actionsHookExecutionLifecycle,
}

// actRow is one row of an actRules box: a step number, a condition,
// and the outcome the condition leads to. A row without a number
// continues the numbered row above it.
type actRow struct {
	num  string
	cond Line
	out  Line
}

// actRowH is the height of one row of an actRules box.
const actRowH = 26.0

// actRules draws a component as a box with a header band and a
// numbered list of its rules below: each row a condition, an arrow and
// the outcome. A row without an outcome is a plain step. A zero w
// sizes the box to its rows.
func (f *Figure) actRules(r role, x, y, w float64, head []Line, rows []actRow) *node {
	numW, condW, outW := 0.0, 0.0, 0.0
	for _, rw := range rows {
		numW = max(numW, textWidth(Line{Text: rw.num, Size: sizeBody, Bold: true}))
		condW = max(condW, textWidth(rw.cond))
		outW = max(outW, textWidth(rw.out))
	}
	const gap = 14.0
	arrowW := 0.0
	if outW > 0 {
		arrowW = textWidth(body("→")) + 2*gap
	}
	hw, hh := blockSize(head)
	headH := math.Ceil(hh + 2*padY)
	if w == 0 {
		w = math.Ceil(max(numW+gap+condW+arrowW+outW, hw) + 2*padX + 8)
	}
	h := headH + float64(len(rows))*actRowH + 10
	outline := f.placed(&node{
		shape: shapeRect, arc: 12, fill: colorPaper, stroke: r.stroke, sw: strokeBox, solid: true,
	}, spec{x: x, y: y, w: w, h: h})
	f.add(&edge{pts: []pt{{x, y + headH}, {x + w, y + headH}}, color: r.stroke, sw: 1.5, inner: true})
	t := f.text(x+padX, 0, "left", colored(head, r.text, colorMuted)...)
	t.y = y + headH/2 - t.h/2

	ry := y + headH + 5
	for _, rw := range rows {
		put := func(l Line, at float64) {
			n := f.text(at, 0, "left", l)
			n.y = ry + actRowH/2 - n.h/2
		}
		cx := x + padX
		if rw.num != "" {
			put(Line{Text: rw.num, Size: sizeBody, Bold: true, Color: r.text}, cx)
		}
		cx += numW + gap
		if rw.cond.Text != "" {
			put(tinted(colorInk, rw.cond)[0], cx)
		}
		cx += condW
		if rw.cond.Text != "" && rw.out.Text != "" {
			put(tinted(colorGrey, body("→"))[0], cx+gap-3)
		}
		cx += arrowW
		if rw.out.Text != "" {
			put(tinted(colorInk, rw.out)[0], cx)
		}
		ry += actRowH
	}
	return outline
}

// actSide writes a remark to the right of lifeline a, level with the
// message the sequence drew last, where the self-calls of a put their
// labels.
func actSide(s *seq, a int, lines ...Line) {
	n := s.f.text(s.xs[a]+46, 0, "left", lines...)
	n.y = s.y - 20 - n.h/2
}

// actionsIntegrityVerification draws the data flow of the integrity
// verifier for docs/reference/actions/integrity-verification.md (Data
// Flow): the startup check of the binary against its baseline, the
// report of a mismatch, and the periodic re-run of every check.
func actionsIntegrityVerification() *Figure {
	f := &Figure{Name: "actions-integrity-verification", Title: "Verifying the binary at startup and on a ticker"}
	const lx, lw = 0.0, 340.0

	start := f.state(stateNormal, spec{x: lx, y: 0, w: lw, lines: []Line{name("startup")}})
	run := f.box(roleAgent, spec{x: lx, y: start.y + start.h + 60, w: lw, lines: []Line{codeName("Verifier.Run"), code("VerifyBinary")}})
	f.arrow(flow, start.bottom(), run.top())
	hash := f.box(roleAgent, spec{x: lx, y: run.y + run.h + 60, w: lw, lines: []Line{codeName("HashFile(binary)"), code("crypto/sha256")}})
	f.arrow(flow, run.bottom(), hash.top())
	base := f.store(roleStore, spec{x: 440, w: 300, lines: []Line{codeName("Store.Get"), body("the baseline")}})
	base.y = hash.cy() - base.h/2
	f.arrow(flow, hash.right(), base.leftAt(hash.cy()))

	cmp := f.state(stateNormal, spec{x: lx, y: base.y + base.h + 60, w: base.x + base.w - lx, lines: []Line{name("compare the checksums")}})
	f.arrow(flow, hash.bottom(), cmp.topAt(hash.cx()))
	f.arrow(flow, base.bottom(), cmp.topAt(base.cx()))

	ok := f.state(stateNormal, spec{x: lx, y: cmp.y + cmp.h + 80, w: lw, lines: []Line{name("log OK")}})
	rep := f.box(roleAgent, spec{x: base.x, y: ok.y, w: base.w, lines: []Line{codeName("ViolationReporter"), code(".ReportViolations")}})
	f.arrow(flow, cmp.bottomAt(ok.cx()), ok.top())
	f.labelLeft(pt{ok.cx(), (cmp.y + cmp.h + ok.y) / 2}, body("match"))
	f.arrow(flow, cmp.bottomAt(rep.cx()), rep.top())
	f.labelRight(pt{rep.cx(), (cmp.y + cmp.h + rep.y) / 2}, body("mismatch"))

	cp := f.box(roleCore, spec{y: rep.y + rep.h + 80, lines: []Line{name("control plane"), code("POST /v1/nodes/{id}/integrity-violations")}})
	cp.x = rep.cx() - cp.w/2
	f.arrow(publish, rep.bottom(), cp.topAt(rep.cx()))

	// The periodic re-verification, which the page lists apart from
	// the startup sequence.
	const px, pw = 810.0, 260.0
	tick := f.state(stateNormal, spec{x: px, y: 0, w: pw, lines: []Line{name("periodic ticker"), body("at VerifyInterval")}})
	rerun := f.state(stateNormal, spec{x: px, y: tick.y + tick.h + 60, w: pw, lines: []Line{
		name("re-run"), code("VerifyBinary"), code("VerifyHooksDir"), code("VerifyHostKey"),
	}})
	f.arrow(flow, tick.bottom(), rerun.top())
	return f
}

// actionsDispatchFlow draws the first half of the data flow of
// docs/reference/actions/remote-actions-hooks.md (Data Flow): from the
// executions block of the state pull through the dispatcher and the
// executor's checks to the goroutine that runs the action.
func actionsDispatchFlow() *Figure {
	f := &Figure{Name: "actions-dispatch-flow", Title: "From the state pull to the run goroutine"}
	const x, w = 0.0, 760.0
	cx := x + w/2

	cp := f.box(roleCore, spec{x: cx - 170, y: 0, w: 340, lines: []Line{name("control plane")}})
	rec := f.box(roleAgent, spec{x: cx - 170, y: cp.y + cp.h + 90, w: 340, lines: []Line{name("Reconciler dispatch stage")}})
	f.arrow(reply, cp.bottom(), rec.top())
	f.labelRight(pt{cx, (cp.y + cp.h + rec.y) / 2}, body("executions block of"), code("GET /v1/nodes/{id}/state"))
	f.notePanel(rec.x+rec.w+50, rec.y-14, 330, rec.right(),
		code("reconcile.DispatchHandler"), body("invoked after every successful"), body("FetchState and before the diff"))

	disp := f.actRules(roleAgent, x, rec.y+rec.h+80, w,
		[]Line{codeName("Dispatcher.Handle"), code("dispatch.go"), body("per entry, in block order")},
		[]actRow{
			{"0", body("cancel requested, run active"), code("Executor.Cancel")},
			{"1", body("no execution_id"), body("drop, no callback")},
			{"2", body("already handled"), body("skip")},
			{"3", body("run still active"), body("skip")},
			{"4", body("pass budget short of one settlement"), body("stop, next pull")},
			{"5", body("expires_at absent"), body("refuse, mark settled, warn")},
			{"", body("expires_at not after now"), body("skip")},
			{"6", body("status pending or ack"), code("Executor.Execute")},
			{"", body("   and cancel requested"), body("not started")},
			{"", body("   and actions disabled"), body("reject")},
			{"7", body("status started"), body("Resume a plexd_hook entry,")},
			{"", Line{}, body("else FailOrphan")},
		})
	f.arrow(flow, rec.bottom(), disp.topAt(cx))
	f.labelRight(pt{cx, (rec.y + rec.h + disp.y) / 2}, code("*api.NodeStateSnapshot"))

	exec := f.actRules(roleAgent, x, disp.y+disp.h+80, w,
		[]Line{codeName("Executor.Execute"), code("executor.go")},
		[]actRow{
			{"1", body("shuttingDown, active id or MaxConcurrent"), code("ErrDispatchDeferred")},
			{"", Line{}, body("no callback, retry")},
			{"2", body("look up the action in the registry"), Line{}},
			{"", body("the entry's type names"), Line{}},
			{"", body("   not found"), body("reject: unknown_action")},
			{"", body("   a plexd_hook entry"), body("looked up by its run")},
			{"", body("   another type"), body("reject: unsupported_action_type")},
			{"", body("   plexd_hook with no runner"), body("reject: unsupported_action_type")},
			{"3", body("claim"), body("post ack (only when status is")},
			{"", Line{}, body("pending), then started, both")},
			{"", Line{}, body("before the run")},
		})
	f.arrow(flow, disp.bottomAt(cx), exec.topAt(cx))
	f.labelRight(pt{cx, (disp.y + disp.h + exec.y) / 2}, body("status pending or ack"))

	gor := f.box(roleAgent, spec{x: cx - 170, y: exec.y + exec.h + 100, w: 340, lines: []Line{
		name("goroutine"), code("runAction"), body("reads the hook sidecar"), code("runBound"),
	}})
	f.arrow(flow, exec.bottomAt(cx), gor.top())
	f.labelRight(pt{cx, (exec.y + exec.h + gor.y) / 2},
		body("if accepted; a plexd_hook entry runs"), body("runPlexdHook instead (Kubernetes CRD Hooks)"))
	return f
}

// actionsRunFlow draws the second half of the data flow of
// docs/reference/actions/remote-actions-hooks.md (Data Flow): the run
// goroutine, the builtin and the hook branch, and the terminal
// execution callback.
func actionsRunFlow() *Figure {
	f := &Figure{Name: "actions-run-flow", Title: "From the run goroutine to the terminal callback"}
	gor := f.box(roleAgent, spec{x: 330, y: 0, w: 340, lines: []Line{
		name("goroutine"), code("runAction"), body("reads the hook sidecar"), code("runBound"),
	}})
	busY := gor.y + gor.h + 50

	builtin := f.box(roleAgent, spec{x: 0, y: busY + 90, w: 320, lines: []Line{codeName("runBuiltin"), body("calls its function")}})
	hook := f.actRules(roleAgent, 480, busY+90, 0,
		[]Line{codeName("runHook")},
		[]actRow{
			{"1", body("path traversal check"), Line{}},
			{"2", body("discovery-snapshot lookup"), Line{}},
			{"3", body("file checks: links, type, owner, mode"), Line{}},
			{"4", body("verify against the pinned digest"), Line{}},
			{"5", code("exec.CommandContext"), Line{}},
			{"", body("in its own process group"), Line{}},
			{"6", body("capture stdout and stderr"), Line{}},
			{"7", body("truncate to MaxOutputBytes"), Line{}},
		})
	gor.x = (builtin.cx()+hook.x+hook.w/2)/2 - gor.w/2
	f.arrow(flow, vhv(gor.bottomAt(gor.cx()-60), builtin.top(), busY)...)
	f.labelLeft(pt{builtin.cx(), busY + 45}, body("builtin"))
	f.arrow(flow, vhv(gor.bottomAt(gor.cx()+60), hook.topAt(hook.x+hook.w/2), busY)...)
	f.labelRight(pt{hook.x + hook.w/2, busY + 45}, body("hook"))

	cbY := hook.y + hook.h + 80
	cb := f.box(roleAgent, spec{x: builtin.cx() - 80, y: cbY, w: hook.x + hook.w/2 + 80 - (builtin.cx() - 80), lines: []Line{
		codeName("ExecutionCallback"), body("terminal"),
	}})
	f.arrow(flow, builtin.bottom(), cb.topAt(builtin.cx()))
	f.arrow(flow, hook.bottomAt(hook.x+hook.w/2), cb.topAt(hook.x+hook.w/2))

	cp := f.box(roleCore, spec{y: cb.y + cb.h + 110, w: 340, lines: []Line{name("control plane")}})
	cp.x = cb.cx() - cp.w/2
	f.arrow(publish, cb.bottom(), cp.top())
	f.labelRight(pt{cb.cx(), (cb.y + cb.h + cp.y) / 2},
		code("POST /v1/nodes/{id}/executions/{eid}"), body("ack → started → succeeded | failed | cancelled"))
	return f
}

// actionsSessionAuthorization draws the authorization flow of a
// locally triggered action for
// docs/reference/actions/session-authorization.md (Authorization
// Flow).
func actionsSessionAuthorization() *Figure {
	f := &Figure{Name: "actions-session-authorization", Title: "Authorizing an action run in an SSH session"}
	s := f.sequence(
		seqPart{x: 70, r: role{stroke: colorLine, text: colorInk}, lines: []Line{name("User")}},
		seqPart{x: 380, r: roleCore, lines: []Line{name("Platform"), body("control plane")}},
		seqPart{x: 760, r: roleAgent, lines: []Line{name("plexd"), body("target Node")}},
	)
	s.msg(call, 0, 1, body("request an SSH session"))
	s.self(1, body("check RBAC:"), body("user × node × actions"))
	s.self(1, body("issue the session JWT"), code("{ sub, node_id, actions, exp }"))
	s.msg(reply, 1, 2, body("the session, in the state"), body("pull's sessions block"))
	s.self(2, body("start the SSH session"))
	s.msg(both, 0, 2, body("SSH session, relayed over plexd's socket"))
	s.self(2, body("inject"), code("PLEXD_SESSION_TOKEN"))
	s.msg(call, 0, 2, code("plexd actions run diagnostics.collect"))
	s.self(2, body("read the token from env"))
	s.self(2, body("validate the JWT locally"))
	s.self(2, body("check the action scope"))
	s.self(2, body("execute"))
	s.msg(reply, 2, 0, body("result"))
	s.msg(publish, 2, 1, body("callback: the result and"), body("the session context"))
	s.end()
	return f
}

// actionsLocalTransport draws how plexd actions run reaches the
// daemon over its Unix socket, for
// docs/reference/actions/session-authorization.md (Local Transport via
// Unix Socket).
func actionsLocalTransport() *Figure {
	f := &Figure{Name: "actions-local-transport", Title: "plexd actions run through the Unix socket"}
	daemon := f.frame(roleAgent, 0, 0, 0, 0, "", "plexd daemon", "")
	x := 30.0
	var steps []*node
	for _, l := range [][]Line{
		{name("validate"), body("the session JWT")},
		{name("check"), body("the action scope")},
		{name("verify"), body("the hook integrity")},
		{name("execute"), body("the action")},
	} {
		n := f.state(stateNormal, spec{x: x, y: daemon.y + 70, w: 200, lines: l})
		if len(steps) > 0 {
			f.arrow(flow, steps[len(steps)-1].right(), n.left())
		}
		steps = append(steps, n)
		x = n.x + n.w + 50
	}
	last := steps[len(steps)-1]
	daemon.w = last.x + last.w + 30
	daemon.h = last.y + last.h + 30 - daemon.y

	cli := f.actor(spec{lines: []Line{
		codeName("plexd actions run"), code("diagnostics.collect --param include_network=true"),
	}})
	cli.x, cli.y = daemon.cx()-cli.w/2, daemon.y-110-cli.h
	f.arrow(call, cli.bottom(), pt{cli.cx(), daemon.y})
	f.labelRight(pt{cli.cx(), daemon.y - 55}, body("Unix socket"), code("/var/run/plexd.sock"))

	cp := f.box(roleCore, spec{y: daemon.y + daemon.h + 90, w: 300, lines: []Line{name("control plane")}})
	cp.x = daemon.x + daemon.w - cp.w
	f.arrow(publish, last.bottom(), cp.topAt(last.cx()))
	f.labelLeft(pt{last.cx(), (daemon.y + daemon.h + cp.y) / 2}, body("report"))
	return f
}

// actionsHookExecutionLifecycle draws the execution lifecycle of a
// hook for docs/how-to/custom-hook-scripts.md (Execution Lifecycle).
func actionsHookExecutionLifecycle() *Figure {
	f := &Figure{Name: "actions-hook-execution-lifecycle", Title: "Lifecycle of a hook execution"}
	s := f.sequence(
		seqPart{x: 130, r: roleCore, lines: []Line{name("control plane")}},
		seqPart{x: 640, r: roleAgent, lines: []Line{name("Node"), code("plexd")}},
	)
	s.msg(call, 1, 0, code("GET /v1/nodes/{id}/state"))
	actSide(s, 1, body("reconciliation pull"))
	s.msg(reply, 0, 1, code("executions: [ entry ]"))
	actSide(s, 1, body("dispatch stage"))
	s.msg(publish, 1, 0, body("callback: ack"))
	actSide(s, 1, body("claim"))
	s.msg(publish, 1, 0, body("callback: started"))
	s.self(1, body("check the sidecar and the files"), body("(a refusal reports failed)"))
	s.self(1, body("verify against the discovery digest"))
	s.self(1, body("execute the script"))
	s.self(1, body("capture stdout and stderr"))
	s.msg(publish, 1, 0, body("callback: succeeded"))
	actSide(s, 1, body("report the terminal status and output;"), body("the entry drains from the block"))
	s.end()
	return f
}
