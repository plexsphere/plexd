package main

// communicationFigures are the communication- figures of the platform communication guide.
var communicationFigures = []func() *Figure{
	communicationChannels,
	communicationNodeLifecycle,
	communicationMeshTopology,
	communicationMeshCapabilities,
}

// commSendBack moves n to the bottom of the drawing, so the lifelines
// and arrows drawn before it stay visible on top of it.
func commSendBack(f *Figure, n *node) {
	for i, e := range f.els {
		if e != element(n) {
			continue
		}
		st := f.stages[i]
		copy(f.els[1:i+1], f.els[:i])
		copy(f.stages[1:i+1], f.stages[:i])
		f.els[0], f.stages[0] = n, st
		return
	}
}

// commPhase starts a grey band behind the next messages of s: one
// phase of a sequence, with its number and title centred over the
// lifelines. The returned function closes the band after the last
// message of the phase.
func commPhase(f *Figure, s *seq, x0, x1 float64, step, title string) func() {
	start := len(f.els)
	fr := f.frame(roleNeutral, x0, s.y, x1-x0, 0, "", "", "")
	cx := (s.xs[0] + s.xs[len(s.xs)-1]) / 2
	t := masked(f.text(cx+18, s.y+14, "center", tinted(colorInk, name(title))...))
	f.badge(t.x-18, t.y+t.h/2, step)
	s.y = t.y + t.h + 16
	return func() {
		s.y -= 4
		fr.h = s.y - fr.y
		for _, e := range f.els[start:] {
			n, ok := e.(*node)
			switch {
			case !ok:
			case n.fill == colorBackground:
				n.fill = fr.fill // a masked label
			case n.solid && n.fill == colorFrameFill:
				n.fill = colorPaper // a note
			}
		}
		commSendBack(f, fr)
		s.y += 26
	}
}

// communicationChannels draws the five channels plexd opens to the
// control plane, for docs/guide/platform-communication.md (How plexd
// Communicates with Plexsphere).
func communicationChannels() *Figure {
	f := &Figure{Name: "communication-channels", Title: "The channels plexd opens to the control plane"}
	s := f.sequence(
		seqPart{x: 130, r: roleAgent, lines: []Line{name("plexd"), body("Node")}},
		seqPart{x: 680, r: roleCore, lines: []Line{name("Plexsphere"), body("Control Plane")}},
	)
	const x0, x1 = 0.0, 1086.0

	done := commPhase(f, s, x0, x1, "1", "Registration (one-time)")
	s.self(0, body("Generate Curve25519 keypair"))
	s.msg(call, 0, 1, code("POST /v1/register"), code("{project_id, resource_handle, bootstrap_token,"), code("nonce, public_key, requested_resource_id (optional)}"))
	s.msg(secretFlow, 1, 0, code("{node_id, mesh_ip, signing_public_key, signing_key_id,"), code("nsk, peer_snapshot, domain_mesh_cidr}"))
	s.self(0, body("Delete bootstrap token from disk"))
	done()

	done = commPhase(f, s, x0, x1, "2", "SSE Event Stream (persistent)")
	s.msg(call, 0, 1, code("GET /v1/nodes/{id}/events"), body("(SSE, Last-Event-ID)"))
	s.msg(publish, 1, 0, body("Ed25519-signed event envelopes"))
	s.note(1, code("node_state_updated, policy_updated,"), code("action_request, session_setup,"), code("bridge_config_updated, ..."))
	done()

	done = commPhase(f, s, x0, x1, "3", "Heartbeat (every 30s)")
	s.msg(call, 0, 1, code("POST /v1/nodes/{id}/heartbeat"), code("{client_now, binary_checksum,"), code("binary_version, nat_summary}"))
	s.msg(reply, 1, 0, code("200 OK"), body("accepted_at; optional reconcile,"), body("rotate_keys flags"))
	done()

	done = commPhase(f, s, x0, x1, "4", "Reconciliation (every 60s)")
	s.msg(call, 0, 1, code("GET /v1/nodes/{id}/state"))
	s.msg(reply, 1, 0, code("{peers, reachability, policy, bridge,"), code("state, reports, executions, sessions,"), code("secrets, signing_key, hooks, dns}"))
	s.self(0, body("Diff by presence and apply corrections"))
	done()

	done = commPhase(f, s, x0, x1, "5", "Observability (periodic)")
	s.msg(publish, 0, 1, code("POST /v1/nodes/{id}/metrics"))
	s.msg(publish, 0, 1, code("POST /v1/nodes/{id}/logs"))
	s.msg(publish, 0, 1, code("POST /v1/nodes/{id}/audit"))
	done()
	s.y -= 26
	s.end()
	return f
}

// commRow places states left to right from x at y, gap apart, gives
// them the height of the highest, and joins each to the next with a
// flow arrow.
func commRow(f *Figure, x, y, gap float64, steps ...[]Line) []*node {
	out := make([]*node, 0, len(steps))
	h := 0.0
	for _, lines := range steps {
		n := f.state(stateNormal, spec{x: x, y: y, lines: lines})
		h = max(h, n.h)
		x = n.x + n.w + gap
		out = append(out, n)
	}
	for i, n := range out {
		n.h = h
		if i > 0 {
			f.arrow(flow, out[i-1].right(), n.left())
		}
	}
	return out
}

// communicationNodeLifecycle draws the four phases of a node from
// first boot to shutdown, for docs/guide/platform-communication.md
// (Node Lifecycle).
func communicationNodeLifecycle() *Figure {
	f := &Figure{Name: "communication-node-lifecycle", Title: "The phases of a node from first boot to shutdown"}
	// The four frames are drawn first, so they sit behind their rows,
	// and are sized once the rows are placed.
	const pad, gap = 24.0, 30.0

	boot := f.frame(roleNeutral, 0, 0, 0, 0, "", "Bootstrap", "")
	b := commRow(f, pad, 56, gap,
		[]Line{name("Read config"), body("and locate the"), body("bootstrap token")},
		[]Line{name("Generate"), body("Curve25519"), body("keypair")},
		[]Line{codeName("POST /v1/register"), body("with token +"), body("public key")},
		[]Line{name("Receive"), code("node_id, mesh_ip,"), body("NSK, signing key,"), body("peers")},
		[]Line{name("Delete token"), body("from disk")},
	)
	boot.h = b[0].y + b[0].h + 24

	tun := f.frame(roleNeutral, 0, boot.y+boot.h+50, 0, 0, "", "Tunnel Setup", "")
	t := commRow(f, pad, tun.y+96, gap+10,
		[]Line{name("Create"), body("WireGuard interface"), code("plexd0")},
		[]Line{name("Add peers"), body("with public keys,"), body("PSKs, allowed IPs")},
		[]Line{name("STUN discovery"), body("of public endpoint")},
		[]Line{name("Report endpoint,"), body("receive freshness"), body("deadline")},
	)
	tun.h = t[0].y + t[0].h + 24 - tun.y
	// The arrows into a frame turn below its title, clear of it.
	last := b[len(b)-1]
	f.arrow(flow, vhv(last.bottom(), t[0].top(), tun.y+56)...)

	steady := f.frame(roleNeutral, 0, tun.y+tun.h+50, 0, 0, "", "Steady State", "")
	rowY := steady.y + 96
	box := func(x float64, lines ...Line) *node {
		return f.box(roleAgent, spec{x: x, y: rowY, lines: lines})
	}
	sse := box(pad, name("SSE event"), body("stream"))
	hb := box(sse.x+sse.w+gap, name("Heartbeat"), body("loop every 30s"))
	rec := box(hb.x+hb.w+110, name("Reconciliation"), body("loop every 60s"))
	obs := box(rec.x+rec.w+gap, name("Observability"), body("uploads"))
	napi := box(obs.x+obs.w+gap, name("Node API"), body("server"))
	busY := steady.y + 56
	for _, n := range []*node{sse, hb, rec, obs, napi} {
		f.arrow(flow, vhv(t[len(t)-1].bottom(), n.top(), busY)...)
	}
	f.arrow(flow, hb.right(), rec.left())
	f.label(mid(hb.right(), rec.left()), code("reconcile"), body("flag"))

	rot := f.box(roleAgent, spec{x: hb.x + 44, y: hb.y + hb.h + 70, lines: []Line{name("Key rotation")}})
	f.arrow(flow, hb.bottomAt(rot.cx()), rot.top())
	f.labelRight(pt{rot.cx(), hb.y + hb.h + 35}, code("rotate_keys"), body("flag"))
	disp := f.box(roleAgent, spec{x: rec.x + 44, y: rot.y, lines: []Line{name("Action"), body("dispatcher")}})
	f.arrow(flow, rec.bottomAt(disp.cx()), disp.top())
	steady.h = max(rot.y+rot.h, disp.y+disp.h) + 24 - steady.y

	down := f.frame(roleNeutral, 0, steady.y+steady.h+70, 0, 0, "", "Shutdown", "")
	d := commRow(f, pad, down.y+76, gap+10,
		[]Line{name("Stop accepting"), body("new work")},
		[]Line{name("Drain in-flight"), body("actions up to 30s")},
		[]Line{name("Tear down"), body("WireGuard interface")},
		[]Line{name("Stop subsystems")},
	)
	down.h = d[0].y + d[0].h + 24 - down.y
	// A signal ends the three loops; their arrows join between the
	// frames and enter the first step right of the Shutdown title.
	stopY := steady.y + steady.h + 35
	entry := d[0].topAt(d[0].x + d[0].w - 40)
	for _, from := range []pt{sse.bottom(), hb.bottomAt(hb.x + 20), rec.bottomAt(rec.x + 20)} {
		f.arrow(flow, vhv(from, entry, stopY)...)
	}
	f.labelRight(pt{entry.X, down.y + 24}, code("SIGTERM / SIGINT"))

	right := 0.0
	for _, n := range append(append(append(b, t...), d...), napi) {
		right = max(right, n.x+n.w)
	}
	for _, fr := range []*node{boot, tun, steady, down} {
		fr.w = right + pad
	}
	return f
}

// communicationMeshTopology draws the control plane, the full mesh of
// WireGuard tunnels between the nodes and the bridge, and the bridge's
// external access, for docs/guide/platform-communication.md (The
// Encrypted Mesh Network).
func communicationMeshTopology() *Figure {
	f := &Figure{Name: "communication-mesh-topology", Title: "The control plane, the encrypted mesh and the bridge"}
	const w = 1100.0

	cp := f.frame(roleCore, 0, 0, w, 150, "", "Plexsphere Control Plane", "")
	for i, l := range []string{"Registration API", "Key & Peer Manager", "SSE Event Bus"} {
		f.box(roleCore, spec{x: 150 + float64(i)*290, y: 64, w: 260, lines: []Line{name(l)}})
	}

	mesh := f.frame(roleAgent, 0, cp.y+cp.h+110, w, 0, "", "", "")
	f.text(w/2, mesh.y+14, "center", heading("Encrypted WireGuard Mesh"), body("10.100.0.0/16"))
	peer := func(x, y float64, title, ip string) *node {
		return f.box(roleAgent, spec{x: x, y: y, w: 220, lines: []Line{name(title), code(ip)}})
	}
	top := mesh.y + 100
	a := peer(150, top, "plexd Node A", "10.100.1.1")
	bn := peer(730, top, "plexd Node B", "10.100.1.2")
	c := peer(150, top+300, "plexd Node C", "10.100.1.3")
	br := peer(730, top+300, "plexd Bridge", "10.100.255.1")
	f.chipOn(br, "bridge mode", colorGrey)
	mesh.h = br.y + br.h + 40 - mesh.y

	p2p := []Line{body("P2P tunnel")}
	f.arrow(both, a.right(), bn.left())
	f.label(mid(a.right(), bn.left()), p2p...)
	f.arrow(both, c.right(), br.left())
	f.labelUnder(mid(c.right(), br.left()), p2p...)
	f.arrow(both, a.bottom(), c.top())
	f.labelLeft(mid(a.bottom(), c.top()), p2p...)
	// The tunnel from B to the bridge keeps left of the bridge's chip.
	bv, rv := bn.bottomAt(bn.x+60), br.topAt(br.x+60)
	f.arrow(both, bv, rv)
	f.labelRight(mid(bv, rv), p2p...)
	ad, bd := a.bottomAt(a.x+a.w-24), bn.bottomAt(bn.x+24)
	cd, rd := c.topAt(c.x+c.w-24), br.topAt(br.x+24)
	f.arrow(both, ad, rd)
	f.arrow(both, bd, cd)
	// Each diagonal is labelled near its lower end, on the side away
	// from the other diagonal.
	along := func(a, b pt, t float64) pt { return pt{a.X + t*(b.X-a.X), a.Y + t*(b.Y-a.Y)} }
	p := along(ad, rd, 0.7)
	f.labelRight(pt{p.X + 16, p.Y}, p2p...)
	p = along(bd, cd, 0.7)
	f.labelLeft(pt{p.X - 16, p.Y}, p2p...)

	up := cp.y + cp.h
	gapMid := (up + mesh.y) / 2
	https := body("HTTPS + SSE")
	f.arrow(call, a.top(), pt{a.cx(), up})
	f.labelRight(pt{a.cx(), gapMid}, https)
	f.arrow(call, bn.top(), pt{bn.cx(), up})
	f.labelLeft(pt{bn.cx(), gapMid}, https)
	xl, xr := 60.0, w-60
	f.arrow(call, c.left(), pt{xl, c.cy()}, pt{xl, up})
	f.labelRight(pt{xl, gapMid}, https)
	f.arrow(call, br.right(), pt{xr, br.cy()}, pt{xr, up})
	f.labelLeft(pt{xr, gapMid}, https)

	ext := f.frame(roleNeutral, 0, mesh.y+mesh.h+80, w, 0, "", "Bridge External Access", "")
	extBox := func(x float64, title, sub string) *node {
		return f.box(roleExternal, spec{x: x, y: ext.y + 110, w: 300, lines: []Line{name(title), body(sub)}})
	}
	ua := extBox(60, "User Access", "Tailscale / Netbird / WireGuard")
	pi := extBox(400, "Public Ingress", "ACME + SNI routing")
	s2s := extBox(740, "Site-to-Site VPN", "Partner networks")
	ext.h = ua.y + ua.h + 30 - ext.y
	f.chipOn(ext, "bridge mode", colorGrey)
	busY := ext.y + 62
	for _, it := range []struct {
		n     *node
		label string
	}{{ua, "access"}, {pi, "ingress"}, {s2s, "tunnel"}} {
		f.arrow(both, vhv(br.bottom(), it.n.top(), busY)...)
		f.labelRight(pt{it.n.cx(), (busY + it.n.y) / 2}, body(it.label))
	}
	return f
}

// commFan draws src on the left and the targets in a column to its
// right, each joined to src by a flow arrow through a shared trunk.
func commFan(f *Figure, src *node, x, y float64, targets ...[]Line) float64 {
	trunk := src.x + src.w + 40
	var ns []*node
	for _, lines := range targets {
		n := f.box(roleAgent, spec{x: x, y: y, w: 380, lines: lines})
		ns = append(ns, n)
		y = n.y + n.h + 16
	}
	src.y = (ns[0].cy()+ns[len(ns)-1].cy())/2 - src.h/2
	line := arrowKind{color: flow.color}
	f.arrow(line, src.right(), pt{trunk, src.cy()})
	f.arrow(line, pt{trunk, ns[0].cy()}, pt{trunk, ns[len(ns)-1].cy()})
	for _, n := range ns {
		f.arrow(flow, pt{trunk, n.cy()}, n.left())
	}
	return y
}

// communicationMeshCapabilities draws what the mesh enables on every
// node and what a bridge adds, for docs/guide/platform-communication.md
// (What the Mesh Enables).
func communicationMeshCapabilities() *Figure {
	f := &Figure{Name: "communication-mesh-capabilities", Title: "What the mesh enables"}
	const x = 330.0
	mesh := f.filled(roleAgent, spec{x: 0, y: 0, w: 230, lines: []Line{name("WireGuard Mesh"), body("all nodes")}})
	y := commFan(f, mesh, x, 0,
		[]Line{name("P2P Communication"), body("Direct encrypted tunnels")},
		[]Line{name("NAT Traversal"), body("STUN + endpoint reporting")},
		[]Line{name("Network Policy"), body("Peer visibility rules via the host firewall")},
		[]Line{name("Secure Tunnels"), body("SSH-based access through mesh")},
		[]Line{name("Remote Actions"), body("Pull-dispatched execution")},
		[]Line{name("Observability"), body("Metrics, logs, audit forwarding")},
	)
	bridge := f.box(roleAgent, spec{x: 0, y: 0, w: 230, h: mesh.h, lines: []Line{name("Bridge Node")}})
	commFan(f, bridge, x, y+50,
		[]Line{name("NAT Relay"), body("UDP relay for unreachable peers")},
		[]Line{name("Public Ingress"), body("ACME certs + SNI routing")},
		[]Line{name("User Access"), body("Tailscale / Netbird / WireGuard")},
		[]Line{name("Site-to-Site VPN"), body("Partner network connectivity")},
	)
	// commFan centres the bridge on its column, so its chip comes after.
	f.chipOn(bridge, "bridge mode", colorGrey)
	return f
}
