package main

import "math"

// architectureFigures are the architecture- figures: the overview, the architecture and lifecycle guides, and the internals page.
var architectureFigures = []func() *Figure{
	architectureOverview,
	architectureDetailed,
	architectureAgentLifecycle,
	architectureStartupSequence,
	architectureShutdownSequence,
}

// archStepHeight returns the height of the highest of the labels as a
// state: the height every state of a row takes.
func archStepHeight(labels ...[]Line) float64 {
	h := 0.0
	for _, l := range labels {
		_, bh := blockSize(l)
		h = max(h, bh+2*padY)
	}
	return h
}

// archStepWidth returns the width a state takes for its label.
func archStepWidth(lines []Line) float64 {
	bw, _ := blockSize(lines)
	return math.Ceil(bw + 2*padX + 8)
}

// archChain draws states left to right from x at y, all as high as
// the highest, with a flow arrow between each pair, and returns them.
func (f *Figure) archChain(x, y, gap float64, labels ...[]Line) []*node {
	h := archStepHeight(labels...)
	out := make([]*node, 0, len(labels))
	for _, l := range labels {
		n := f.state(stateNormal, spec{x: x, y: y, h: h, lines: l})
		if len(out) > 0 {
			f.arrow(flow, out[len(out)-1].right(), n.left())
		}
		out = append(out, n)
		x += n.w + gap
	}
	return out
}

// architectureOverview draws the three layers of a plexd deployment,
// for docs/index.md (High-Level Overview).
func architectureOverview() *Figure {
	f := &Figure{Name: "architecture-overview", Title: "High-level overview of a plexd deployment"}
	const nw, gap, ny, nh = 200.0, 25.0, 230.0, 70.0
	kinds := [][]Line{
		{name("Bare metal")},
		{name("VM")},
		{name("VM")},
		{name("Kubernetes"), body("cluster")},
		{name("Bridge"), body("gateway")},
	}
	busY := ny - 50
	nodes := make([]*node, 0, len(kinds))
	for i, k := range kinds {
		n := f.box(roleAgent, spec{x: float64(i) * (nw + gap), y: ny, w: nw, h: nh, lines: k})
		f.arrow(wire, pt{n.cx(), busY}, n.top())
		nodes = append(nodes, n)
	}
	bridge := nodes[4]
	f.arrow(wire, pt{nodes[0].cx(), busY}, pt{bridge.cx(), busY})

	cx := nodes[2].cx()
	cp := f.filled(roleCore, spec{x: cx - 200, y: 0, w: 400, lines: []Line{name("Plexsphere control plane")}})
	f.arrow(call, pt{cx, busY}, cp.bottom())
	f.labelRight(pt{cx, (cp.y + cp.h + busY) / 2}, body("HTTPS + SSE, outbound only:"), body("the nodes initiate every connection"))

	meshY := ny + nh + 50
	meshX := bridge.x + 30
	f.arrow(both, nodes[0].bottom(), pt{nodes[0].cx(), meshY}, pt{meshX, meshY}, bridge.bottomAt(meshX))
	for _, n := range nodes[1:4] {
		f.arrow(wire, n.bottom(), pt{n.cx(), meshY})
	}
	f.labelUnder(pt{(nodes[0].cx() + nodes[2].cx()) / 2, meshY},
		body("encrypted mesh: direct peer to peer,"), body("with NAT traversal"))

	ua := f.box(roleExternal, spec{x: 590, y: meshY + 80, w: 220, lines: []Line{
		name("User access"), body("Tailscale, Netbird,"), body("WireGuard"),
	}})
	et := f.box(roleExternal, spec{x: bridge.x, y: ua.y, w: bridge.w, h: ua.h, lines: []Line{
		name("External traffic"), body("public IPs,"), body("site-to-site VPN"),
	}})
	legX := bridge.x + 75
	f.arrow(both, vhv(bridge.bottomAt(legX), ua.top(), meshY+40)...)
	f.arrow(both, bridge.bottomAt(et.x+150), et.topAt(et.x+150))

	people := f.actor(spec{x: ua.x, y: ua.y + ua.h + 70, w: ua.w, lines: []Line{
		name("Developers"), body("admins, on-call"),
	}})
	nets := f.actor(spec{x: et.x, y: people.y, w: et.w, h: people.h, lines: []Line{
		name("Public internet"), body("partner networks"),
	}})
	f.arrow(both, ua.bottom(), people.top())
	f.arrow(both, et.bottom(), nets.top())
	return f
}

// architectureDetailed draws the control plane's components, the mesh
// addresses of the nodes, and the two sides of a bridge, for
// docs/guide/architecture.md (Detailed Architecture).
func architectureDetailed() *Figure {
	f := &Figure{Name: "architecture-detailed", Title: "Detailed architecture of a plexd deployment"}
	const w = 1120.0
	cp := f.frame(roleCore, 0, 0, w, 150, "", "Plexsphere control plane", "")
	comps := [][]Line{
		{name("Registration API")},
		{name("Key & Peer Manager")},
		{name("Policy Engine")},
		{name("Event Bus"), body("SSE")},
	}
	for i, c := range comps {
		f.box(roleCore, spec{x: 18 + float64(i)*274, y: 62, w: 260, h: 62, lines: c})
	}

	const ny, nw, ngap = 260.0, 145.0, 15.0
	hosts := []struct{ kind, ip string }{
		{"bare metal", "10.100.1.1"},
		{"VM", "10.100.1.2"},
		{"VM", "10.100.1.3"},
		{"Kubernetes", "10.100.1.4"},
	}
	busY := ny - 50
	nodes := make([]*node, 0, len(hosts))
	for i, h := range hosts {
		n := f.box(roleAgent, spec{x: float64(i) * (nw + ngap), y: ny, w: nw, lines: []Line{
			name("plexd"), body(h.kind), code(h.ip),
		}})
		f.arrow(wire, pt{n.cx(), busY}, n.top())
		nodes = append(nodes, n)
	}
	last := nodes[len(nodes)-1]

	bx := last.x + last.w + 40
	br := f.frame(roleAgent, bx, ny, w-bx, 0, "", "plexd (bridge)", "")
	f.arrow(wire, pt{nodes[0].cx(), busY}, pt{br.x + br.w/2, busY})
	f.arrow(wire, pt{br.x + br.w/2, busY}, pt{br.x + br.w/2, ny})
	callX := last.x + last.w + 20
	f.arrow(call, pt{callX, busY}, pt{callX, cp.y + cp.h})
	f.labelRight(pt{callX, (cp.y + cp.h + busY) / 2}, body("HTTPS + SSE"), body("outbound only"))

	meshSide := f.box(roleAgent, spec{x: bx + 24, y: ny + 62, w: br.w - 48, lines: []Line{
		name("Mesh side"), code("10.100.1.250"), body("NAT relay"),
	}})
	mesh := f.panel(roleAgent, spec{x: 0, y: last.y + last.h + 26, w: last.x + last.w, lines: []Line{
		name("Encrypted WireGuard mesh, full mesh"),
		body("Every node has a direct peer-to-peer tunnel to every"),
		body("node. Each peer uses STUN to discover its public"),
		body("endpoint for NAT traversal. Falls back to relay via"),
		body("the bridge when direct connectivity fails."),
	}})
	mesh.fill = roleAgent.fill
	for _, n := range nodes {
		f.arrow(wire, n.bottom(), pt{n.cx(), mesh.y})
	}
	linkY := (max(mesh.y, meshSide.y) + min(mesh.y+mesh.h, meshSide.y+meshSide.h)) / 2
	f.arrow(wire, mesh.rightAt(linkY), meshSide.leftAt(linkY))

	acc := f.frame(roleNeutral, meshSide.x, meshSide.y+meshSide.h+36, meshSide.w, 0, "", "Access side", "")
	f.arrow(relation, meshSide.bottom(), pt{meshSide.cx(), acc.y})
	sx, sw := acc.x+24, acc.w-48
	ua := f.box(roleAgent, spec{x: sx, y: acc.y + 56, w: sw, lines: []Line{
		name("User access"), body("Tailscale, Netbird, WireGuard"),
	}})
	ing := f.box(roleAgent, spec{x: sx, y: ua.y + ua.h + 14, w: sw, lines: []Line{name("Public ingress")}})
	s2s := f.box(roleAgent, spec{x: sx, y: ing.y + ing.h + 14, w: sw, lines: []Line{name("Site-to-site VPN")}})
	acc.h = s2s.y + s2s.h + 24 - acc.y
	br.h = acc.y + acc.h + 24 - br.y

	consumers := [][]Line{
		{name("Developers"), body("admins, on-call")},
		{name("Public internet"), body("traffic")},
		{name("Partner network"), body("or customer network")},
	}
	const cw, cgap = 240.0, 20.0
	cy := br.y + br.h + 76
	fanY := br.y + br.h + 38
	from := pt{acc.x + acc.w/2, acc.y + acc.h}
	for i, c := range consumers {
		n := f.actor(spec{x: w - float64(len(consumers)-i)*cw - float64(len(consumers)-1-i)*cgap, y: cy, w: cw, lines: c})
		f.arrow(both, vhv(from, n.top(), fanY)...)
	}
	return f
}

// architectureAgentLifecycle draws the phases of the agent from start
// to shutdown, for docs/guide/agent-lifecycle.md.
func architectureAgentLifecycle() *Figure {
	f := &Figure{Name: "architecture-agent-lifecycle", Title: "Lifecycle of the agent"}
	const bw, bh, gx, gy, cx0 = 320.0, 50.0, 16.0, 12.0, 400.0
	const right = cx0 + 2*bw + gx + 48
	phases := [][]Line{
		{name("Start"), body("binary checksum"), body("hook scan")},
		{name("Register")},
		{name("Configure tunnels")},
		{name("NAT discovery"), body("STUN")},
	}
	used := 0.0
	for _, p := range phases {
		used += archStepWidth(p)
	}
	steps := f.archChain(0, 0, (right-used)/float64(len(phases)-1), phases...)
	nat := steps[len(steps)-1]

	con := f.frame(roleAgent, cx0, nat.y+nat.h+70, right-cx0, 0, "", "Connected", "steady state")
	f.arrow(flow, nat.bottom(), pt{nat.cx(), con.y})
	subsystems := []string{
		"Heartbeat", "NAT refresh",
		"Reconcile", "SSE stream",
		"Policy enforcement", "Observe: logs, audit",
		"Access proxy", "Action dispatcher",
		"Hook file watcher", "Node API server",
	}
	for i, s := range subsystems {
		f.box(roleAgent, spec{
			x: con.x + 24 + float64(i%2)*(bw+gx), y: con.y + 60 + float64(i/2)*(bh+gy),
			w: bw, h: bh, lines: []Line{name(s)},
		})
	}
	con.h = 60 + 5*bh + 4*gy + 24

	down := f.state(stateNormal, spec{x: 0, y: con.y + 60, lines: []Line{name("Shutdown")}})
	f.arrow(flow, con.leftAt(down.cy()), down.right())
	f.label(mid(con.leftAt(down.cy()), down.right()), body("on shutdown"), body("or command"))
	f.notePanel(0, down.y+down.h+40, con.x-40, down.bottom(),
		body("1. Stop accepting new work"),
		body("2. Drain in-flight executions:"),
		body("    up to 30 s, then cancelled"),
		body("3. Tear down tunnels"),
		body("4. Stop subsystems"),
		body("The local identity is kept."),
	)
	return f
}

// architectureStartupSequence draws the initialization of plexd up,
// one band per group of steps, for docs/concepts.md (Startup Sequence).
func architectureStartupSequence() *Figure {
	f := &Figure{Name: "architecture-startup-sequence", Title: "Startup sequence of plexd up"}
	const w, x0, gap, bandGap = 1120.0, 200.0, 44.0, 56.0
	y := 0.0
	// band draws a frame across the figure at y, its title on the left,
	// and leaves room for a row of steps of height h.
	band := func(h float64, title ...string) *node {
		fr := f.frame(roleNeutral, 0, y, w, h+48, "", "", "")
		lines := make([]Line, 0, len(title))
		for _, t := range title {
			lines = append(lines, heading(t))
		}
		t := f.text(20, 0, "left", tinted(colorInk, lines...)...)
		t.y = fr.cy() - t.h/2
		y += fr.h + bandGap
		return fr
	}
	chain := func(title []string, labels ...[]Line) []*node {
		fr := band(archStepHeight(labels...), title...)
		return f.archChain(x0, fr.y+24, gap, labels...)
	}
	next := func(from, to *node) {
		f.arrow(flow, vhv(from.bottom(), to.top(), to.y-24-bandGap/2)...)
	}

	cfg := chain([]string{"Config and", "logger"},
		[]Line{name("Parse config")},
		[]Line{name("Set up logger")},
	)
	reg := chain([]string{"Registration"},
		[]Line{name("Create control"), name("plane client")},
		[]Line{name("Register node")},
		[]Line{name("Create Ed25519"), name("verifier")},
	)
	next(cfg[len(cfg)-1], reg[0])
	verifier := reg[len(reg)-1]

	netLabels := [][]Line{
		{name("Initialize"), name("WireGuard")},
		{name("Initialize"), name("NAT + Peer"), name("Exchange")},
		{name("Initialize"), name("Network Policy")},
		{name("Initialize"), name("Tunnel")},
		{name("Initialize"), name("Bridge"), body("bridge mode")},
	}
	netBand := band(archStepHeight(netLabels...), "Networking")
	used := 0.0
	for _, l := range netLabels {
		used += archStepWidth(l)
	}
	netGap := (w - 24 - x0 - used) / float64(len(netLabels)-1)
	var nets []*node
	nx := x0
	for _, l := range netLabels {
		n := f.state(stateNormal, spec{x: nx, y: netBand.y + 24, h: archStepHeight(netLabels...), lines: l})
		nets = append(nets, n)
		nx += n.w + netGap
	}
	for _, n := range nets {
		f.arrow(flow, vhv(verifier.bottom(), n.top(), netBand.y-bandGap/2)...)
	}

	core := chain([]string{"Core services"},
		[]Line{name("Create SSE manager")},
		[]Line{name("Create reconciler")},
		[]Line{name("Create heartbeat"), name("service")},
	)
	for _, n := range nets {
		f.arrow(flow, vhv(n.bottom(), core[0].top(), core[0].y-24-bandGap/2)...)
	}
	acts := chain([]string{"Actions and", "Node API"},
		[]Line{name("Create integrity"), name("store + verifier")},
		[]Line{name("Create action executor"), body("+ rollout installer"), body("+ capability reporter"), body("+ hook watchers")},
		[]Line{name("Create node"), name("API server")},
	)
	next(core[len(core)-1], acts[0])
	obs := chain([]string{"Observability"},
		[]Line{name("Create metrics"), name("collectors")},
		[]Line{name("Create log"), name("forwarder")},
		[]Line{name("Create audit"), name("forwarder")},
	)
	next(acts[len(acts)-1], obs[0])
	audit := obs[len(obs)-1]
	launch := f.state(stateNormal, spec{y: y - bandGap + 40, lines: []Line{name("Launch goroutines via WaitGroup")}})
	launch.x = audit.cx() - launch.w/2
	f.arrow(flow, audit.bottom(), launch.top())
	return f
}

// architectureShutdownSequence draws the shutdown of plexd up on
// SIGTERM or SIGINT, for docs/concepts.md (Shutdown Sequence).
func architectureShutdownSequence() *Figure {
	f := &Figure{Name: "architecture-shutdown-sequence", Title: "Shutdown sequence of plexd up"}
	const gap = 60.0
	sh := archStepHeight([]Line{name("Cancel context")})
	sse := f.state(stateNormal, spec{y: 0, w: 210, h: sh, lines: []Line{name("SSE shutdown")}})
	drain := f.state(stateNormal, spec{y: sh + 40, w: 210, h: sh, lines: []Line{name("Drain actions")}})
	c1 := (sse.y + drain.y + drain.h) / 2

	sig := f.actor(spec{x: 0, lines: []Line{name("SIGTERM"), body("or SIGINT")}})
	sig.y = c1 - sig.h/2
	cancel := f.state(stateNormal, spec{x: sig.x + sig.w + gap, y: c1 - sh/2, h: sh, lines: []Line{name("Cancel context")}})
	f.arrow(flow, sig.right(), cancel.left())
	sse.x = cancel.x + cancel.w + gap
	drain.x = sse.x
	forkX := cancel.x + cancel.w + gap/2
	f.arrow(flow, hvh(cancel.right(), sse.left(), forkX)...)
	f.arrow(flow, hvh(cancel.right(), drain.left(), forkX)...)
	mesh := f.state(stateNormal, spec{x: sse.x + sse.w + gap, y: c1 - sh/2, h: sh, lines: []Line{name("Mesh server shutdown")}})
	joinX := sse.x + sse.w + gap/2
	f.arrow(flow, hvh(sse.right(), mesh.left(), joinX)...)
	f.arrow(flow, hvh(drain.right(), mesh.left(), joinX)...)

	// The bridge teardown runs right to left, under the mesh server.
	teardown := [][]Line{
		{name("Ingress"), body("teardown")},
		{name("User access"), body("teardown")},
		{name("Site-to-site"), body("teardown")},
		{name("ACME"), body("teardown")},
		{name("Bridge"), body("teardown")},
	}
	th := archStepHeight(teardown...)
	fy := drain.y + drain.h + 60
	fr := f.frame(roleNeutral, 0, fy, 0, th+84, "", "Bridge teardown", "bridge mode only")
	var bridge []*node
	right := mesh.cx()
	for i, l := range teardown {
		n := f.state(stateNormal, spec{y: fy + 60, h: th, lines: l})
		n.dash = "3 2"
		if i == 0 {
			n.x = right - n.w/2
		} else {
			n.x = right - gap - n.w
			f.arrow(flow, bridge[i-1].left(), n.right())
		}
		right = n.x
		bridge = append(bridge, n)
	}
	f.arrow(flow, mesh.bottom(), bridge[0].top())
	first, lastB := bridge[0], bridge[len(bridge)-1]
	fr.x = lastB.x - 24
	fr.w = first.x + first.w + 24 - fr.x

	fw := f.state(stateNormal, spec{y: fr.y + fr.h + 84, h: sh, lines: []Line{name("Firewall teardown")}})
	fw.x = lastB.cx() - fw.w/2
	f.arrow(flow, lastB.bottom(), fw.top())
	wg := f.state(stateNormal, spec{x: fw.x + fw.w + gap, y: fw.y, h: sh, lines: []Line{name("WireGuard teardown")}})
	f.arrow(flow, fw.right(), wg.left())
	done := f.state(stateNormal, spec{x: wg.x + wg.w + gap, lines: []Line{name("WaitGroup done"), body("within 30 s?")}})
	done.y = wg.cy() - done.h/2
	f.arrow(flow, wg.right(), done.left())
	ex := done.x + done.w + 110
	exit := f.state(stateNormal, spec{x: ex, y: done.cy() - 30 - sh, h: sh, lines: []Line{name("Exit 0")}})
	force := f.state(stateFailed, spec{x: ex, y: done.cy() + 30, h: sh, lines: []Line{name("Force exit")}})
	branchX := done.x + done.w + 40
	f.arrow(flow, hvh(done.rightAt(done.cy()-8), exit.left(), branchX)...)
	f.label(pt{(branchX + ex) / 2, exit.cy()}, body("yes"))
	f.arrow(refuse, hvh(done.rightAt(done.cy()+8), force.left(), branchX)...)
	f.labelUnder(pt{(branchX + ex) / 2, force.cy()}, body("no"))
	return f
}
