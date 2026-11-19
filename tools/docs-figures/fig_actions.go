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
// Flow): the start of Verifier.Run and every tick of its ticker run one
// pass of the three baseline checks, each compares what it observes
// with the stored baseline, a mismatch is reported to the control
// plane, and an accepted report makes the observed value the baseline.
func actionsIntegrityVerification() *Figure {
	f := &Figure{Name: "actions-integrity-verification", Title: "One integrity pass at start and on every tick"}
	const trigH, gap = 66.0, 70.0

	pass := f.actRules(roleAgent, 0, trigH+gap, 0,
		[]Line{name("one pass")},
		[]actRow{
			{"1", code("VerifyBinary"), body("SHA-256 of BinaryPath")},
			{"2", code("VerifyHooksDir"), body("each hook in HooksDir")},
			{"3", code("VerifyHostKey"), body("fingerprint of HostKeyPath")},
		})

	// The two triggers, side by side over the pass they both start.
	const trigW, trigGap = 210.0, 40.0
	tx := pass.cx() - trigW - trigGap/2
	start := f.state(stateNormal, spec{x: tx, y: 0, w: trigW, h: trigH, lines: []Line{name("start"), code("Verifier.Run")}})
	tick := f.state(stateNormal, spec{x: tx + trigW + trigGap, y: 0, w: trigW, h: trigH, lines: []Line{name("tick"), body("every VerifyInterval")}})
	f.arrow(flow, start.bottom(), pass.topAt(start.cx()))
	f.arrow(flow, tick.bottom(), pass.topAt(tick.cx()))

	base := f.store(roleStore, spec{x: pass.x + pass.w + 100, w: 260, lines: []Line{codeName("Store.Get"), body("the baseline of the path")}})
	base.y = pass.cy() - base.h/2
	f.arrow(flow, pass.right(), base.leftAt(pass.cy()))

	cmpY := max(pass.y+pass.h, base.y+base.h) + 60
	cmp := f.state(stateNormal, spec{x: pass.x, y: cmpY, w: base.x + base.w - pass.x, lines: []Line{name("compare the observed value with the baseline")}})
	f.arrow(flow, pass.bottom(), cmp.topAt(pass.cx()))
	f.arrow(flow, base.bottom(), cmp.topAt(base.cx()))

	// The three outcomes of the comparison, labelled level with each
	// other in the gap below it.
	rowY := cmp.y + cmp.h + 90
	labelY := (cmp.y + cmp.h + rowY) / 2
	ok := f.state(stateNormal, spec{x: pass.x, y: rowY, w: 230, lines: []Line{name("log the match"), code("binary verified"), code("host key verified")}})
	f.arrow(flow, cmp.bottomAt(ok.cx()), ok.top())
	f.labelLeft(pt{ok.cx(), labelY}, body("match"))

	cp := f.box(roleCore, spec{lines: []Line{name("control plane"), code("POST /v1/nodes/{id}/integrity-violations")}})
	rep := f.box(roleAgent, spec{y: rowY, w: 330, lines: []Line{codeName("ViolationReporter"), code(".ReportViolations")}})
	rep.x = cmp.x + cmp.w - cp.w/2 - 20 - rep.w/2
	f.arrow(flow, cmp.bottomAt(rep.cx()), rep.top())
	f.labelRight(pt{rep.cx(), labelY}, body("mismatch"))
	cp.x, cp.y = rep.cx()-cp.w/2, rep.y+rep.h+70
	f.arrow(publish, rep.bottom(), cp.topAt(rep.cx()))

	// The baseline moves when there was none and when the control
	// plane accepted the report; a failed report leaves it alone.
	outY := cp.y + cp.h + 90
	set := f.store(roleStore, spec{x: ok.x + ok.w + 30, y: outY, w: 260, lines: []Line{codeName("Store.Set"), body("the observed value"), body("becomes the baseline")}})
	fail := f.state(stateFailed, spec{x: set.x + set.w + 40, y: outY, lines: []Line{name("keep the baseline"), body("the next pass reports again")}})

	none := set.x + 40
	f.arrow(flow, cmp.bottomAt(none), set.capTop(none))
	f.labelRight(pt{none, labelY}, body("no baseline"))
	accepted := (cp.x + set.x + set.w) / 2
	f.arrow(reply, cp.bottomAt(accepted), set.capTop(accepted))
	f.labelRight(pt{accepted, (cp.y + cp.h + set.y) / 2}, body("accepted"))
	f.arrow(refuse, cp.bottomAt(fail.cx()), fail.top())
	f.labelRight(pt{fail.cx(), (cp.y + cp.h + fail.y) / 2}, body("error"))
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

// actionsSessionAuthorization draws an action run from a mediated SSH
// session for docs/reference/actions/session-authorization.md (Running
// an Action from an SSH Session): the session token authorizes the
// login only, the run from the user's shell needs the node API socket
// alone, and nothing is reported to the control plane.
func actionsSessionAuthorization() *Figure {
	f := &Figure{Name: "actions-session-authorization", Title: "An action run from a mediated SSH session"}
	s := f.sequence(
		seqPart{x: 70, r: role{stroke: colorLine, text: colorInk}, lines: []Line{name("User")}},
		seqPart{x: 500, r: roleCore, lines: []Line{name("Platform"), body("control plane")}},
		seqPart{x: 880, r: roleAgent, lines: []Line{name("plexd"), body("target Node")}},
	)
	s.msg(call, 0, 1, body("request an SSH session"))
	s.self(1, body("issue the session token"), code("{ jti, target.user, exp }"))
	s.msg(reply, 1, 2, body("the session, in the state"), body("pull's sessions block"))
	s.msg(both, 0, 2, body("SSH login, the token as password"))
	s.self(2, body("verify the token:"), body("signature, jti, user, exp"))
	s.self(2, body("start the user's shell"))
	s.msg(call, 0, 2, code("plexd actions run diagnostics.collect"))
	s.self(2, body("open the node API socket:"), body("root or the plexd group"))
	s.self(2, body("actions enabled? a built-in?"))
	s.self(2, body("run the built-in"))
	s.msg(reply, 2, 0, body("result"))
	s.note(2, body("nothing is reported"), body("to the control plane"))
	s.end()
	return f
}

// actionsLocalTransport draws how plexd actions run reaches the
// daemon over the node API socket, for
// docs/reference/actions/session-authorization.md (Local Transport):
// handleRunAction hands the action to Executor.RunLocal, which refuses
// the run while actions are disabled or for a name that is not a
// registered built-in and otherwise runs the built-in, and nothing
// reaches the control plane.
func actionsLocalTransport() *Figure {
	f := &Figure{Name: "actions-local-transport", Title: "plexd actions run through the node API socket"}
	// hx puts handleRunAction far enough right that the call and the
	// reply, d to either side of its centre, enter the frame right of
	// the frame's title. Their labels sit in the band between the
	// actor and the frame.
	const hx, d, band = 110.0, 40.0, 110.0
	daemon := f.frame(roleAgent, 0, 0, 0, 0, "", "plexd daemon", "")
	h := f.state(stateNormal, spec{x: hx, y: daemon.y + 70, lines: []Line{
		codeName("handleRunAction"), body("decode action and parameters"),
	}})
	run := f.actRules(roleAgent, h.x+h.w+70, h.y, 0,
		[]Line{codeName("Executor.RunLocal")},
		[]actRow{
			{"1", body("actions.enabled is false"), body("refuse")},
			{"2", body("not a registered built-in"), body("refuse")},
			{"3", body("run the built-in"), Line{}},
		})
	h.y = run.cy() - h.h/2
	f.arrow(flow, h.right(), run.leftAt(h.cy()))
	daemon.w = run.x + run.w + 30 - daemon.x
	daemon.h = run.y + run.h + 30 - daemon.y

	cli := f.actor(spec{lines: []Line{
		codeName("plexd actions run"), code("diagnostics.collect --param include_network=false"),
	}})
	cli.x, cli.y = h.cx()-cli.w/2, daemon.y-band-cli.h
	in, out := h.cx()-d, h.cx()+d
	f.arrow(call, cli.bottomAt(in), h.topAt(in))
	f.labelLeft(pt{in, daemon.y - band/2}, body("node API socket, root or the plexd group"), code("/var/run/plexd/api.sock"))
	f.arrow(reply, h.topAt(out), cli.bottomAt(out))
	f.labelRight(pt{out, daemon.y - band/2}, body("status, exit_code, stdout, stderr"))

	f.notePanel(run.x, daemon.y+daemon.h+50, 0, pt{run.cx(), daemon.y + daemon.h},
		body("no execution id, no callback:"), body("nothing reaches the control plane"))
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
