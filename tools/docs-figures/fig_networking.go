package main

import "strconv"

// networkingFigures are the networking- figures of the networking reference pages.
var networkingFigures = []func() *Figure{
	networkingMeshDNSDataFlow,
	networkingSTUNBindingRequest,
	networkingSTUNPaddedBindingRequest,
	networkingPolicyDataFlow,
	networkingNftablesArchitecture,
	networkingPeerEndpointDataFlow,
	networkingTunnelDataFlow,
}

// nwPull draws the state pull between the control plane box cp and the
// box rec under it: the call up on the left, the reply down on the
// right, with what the reply carries beside it.
func (f *Figure) nwPull(cp, rec *node, carries ...Line) {
	up, down := rec.cx()-50, rec.cx()+50
	f.arrow(call, rec.topAt(up), cp.bottomAt(up))
	f.arrow(reply, cp.bottomAt(down), rec.topAt(down))
	f.labelRight(pt{down, (cp.y + cp.h + rec.y) / 2}, carries...)
}

// networkingMeshDNSDataFlow draws how the dns block of the state pull
// reaches the resolver and its registration with the system resolver,
// for docs/reference/networking/mesh-dns.md (Data Flow).
func networkingMeshDNSDataFlow() *Figure {
	f := &Figure{Name: "networking-mesh-dns-data-flow", Title: "From the dns block to the mesh DNS resolver"}
	cp := f.box(roleCore, spec{x: 0, y: 0, w: 280, lines: []Line{name("Control Plane"), code("GET /v1/nodes/{id}/state")}})
	rec := f.box(roleAgent, spec{x: 0, y: 170, w: 280, h: 64, lines: []Line{name("Reconciler")}})
	f.nwPull(cp, rec, body("dns block"))
	mgr := f.box(roleAgent, spec{x: 380, y: 170, w: 260, h: 64, lines: []Line{codeName("meshdns.Manager"), code("Handle")}})
	f.arrow(flow, rec.right(), mgr.left())

	srv := f.filled(roleAgent, spec{x: 0, y: 330, w: 280, lines: []Line{
		name("Server"), body("mesh IP:5354 on Linux"), body("127.0.0.1:5354 on macOS"), body("127.0.0.1:53 on Windows"),
	}})
	const setX = 410.0
	f.arrow(flow, vh(mgr.bottomAt(setX), srv.right())...)
	f.labelLeft(pt{setX, (mgr.y + mgr.h + srv.cy()) / 2}, code("SetRecords"), code("SetForwarding"))

	regs := []struct{ reg, via, target, os string }{
		{"ResolvedRegistrar", "D-Bus", "systemd-resolved", "Linux"},
		{"ScutilRegistrar", "scutil", "configd", "macOS"},
		{"NRPTRegistrar", "registry", "Dnscache", "Windows"},
	}
	fr := f.frame(roleNeutral, 450, 300, 258, 0, "", "", "")
	y := fr.y + 22
	for i, r := range regs {
		if i > 0 {
			f.text(fr.x+fr.w/2, y+6, "center", body("or"))
			y += 34
		}
		reg := f.box(roleAgent, spec{x: fr.x + 24, y: y, w: 210, h: 66, lines: []Line{codeName(r.reg)}})
		tgt := f.box(roleSubstrate, spec{x: 810, y: y, w: 240, h: 66, lines: []Line{name(r.target), body(r.os)}})
		f.arrow(call, reg.right(), tgt.left())
		f.label(mid(reg.right(), tgt.left()), body(r.via))
		y += reg.h
	}
	fr.h = y + 22 - fr.y
	applyX := 590.0
	f.arrow(flow, mgr.bottomAt(applyX), pt{applyX, fr.y})
	f.labelRight(pt{applyX, (mgr.y + mgr.h + fr.y) / 2}, code("Apply / Revert"))

	res := f.box(roleExternal, spec{x: 450, y: fr.y + fr.h + 50, w: 258, lines: []Line{name("Forward zone and"), name("catch-all resolvers")}})
	const fwdX = 230.0
	f.arrow(call, vh(srv.bottomAt(fwdX), res.left())...)
	f.label(pt{(fwdX + res.x) / 2, res.cy()}, body("forwarded queries"), body("UDP or TCP, port 53"))

	sys := f.box(roleSubstrate, spec{x: 0, y: res.y + res.h + 130, w: 420, lines: []Line{
		name("System resolver"), body("systemd-resolved on Linux, mDNSResponder"), body("on macOS, or the DNS Client on Windows"),
	}})
	const askX = 70.0
	f.arrow(call, sys.topAt(askX), srv.bottomAt(askX))
	f.labelRight(pt{askX, sys.y - 58}, body("queries for the mesh zones and the forward zones,"),
		body("and with a catch-all every name no other domain"), body("matches: on Linux through the mesh interface,"),
		body("on macOS and Windows to 127.0.0.1"))
	return f
}

// Geometry of the packet layouts: the width of one bit and the height
// of one 32-bit row.
const (
	nwBitW = 32.0
	nwRowH = 64.0
)

// nwField is one field of a packet layout: its first bit, counted from
// the start of the message, the number of bits it spans, its label,
// and its kind.
type nwField struct {
	bit, bits int
	kind      nwFieldKind
	lines     []Line
}

// nwFieldKind says how a field of a packet layout is drawn.
type nwFieldKind int

const (
	nwHeader  nwFieldKind = iota // a field of the fixed header
	nwFixed                      // bits that are always zero
	nwPadding                    // a field of the PADDING attribute, set apart
)

// nwFieldName is the bold name of a field of a packet layout.
func nwFieldName(s string) Line { return Line{Text: s, Size: sizeBody, Bold: true} }

// nwPacket draws a packet layout the way the RFCs do: the bits 0 to 31
// as a ruler over a grid of 32-bit rows, one box per field. A field
// either fits in its row or fills whole rows from the first bit on.
func (f *Figure) nwPacket(fields []nwField) {
	for b := range 32 {
		f.text(float64(b)*nwBitW+nwBitW/2, -34, "center", Line{Text: strconv.Itoa(b), Size: sizeChip, Mono: true})
	}
	for b := range 33 {
		x := float64(b) * nwBitW
		f.add(&edge{pts: []pt{{x, -9}, {x, 0}}, color: colorGrey, sw: strokeLife})
	}
	for _, fd := range fields {
		row, col := fd.bit/32, fd.bit%32
		w, h := float64(fd.bits)*nwBitW, nwRowH
		if col+fd.bits > 32 {
			w, h = 32*nwBitW, float64(fd.bits/32)*nwRowH
		}
		s := spec{x: float64(col) * nwBitW, y: float64(row) * nwRowH, w: w, h: h, lines: fd.lines}
		var n *node
		switch fd.kind {
		case nwFixed:
			n = f.box(roleNeutral, s)
			n.fill = colorGreyFill
		case nwPadding:
			n = f.filled(roleAgent, s)
		case nwHeader:
			n = f.box(roleAgent, s)
		}
		n.arc = 0
	}
}

// networkingSTUNBindingRequest draws the 20-byte STUN Binding Request
// for docs/reference/networking/nat-traversal.md (Binding Request
// Format).
func networkingSTUNBindingRequest() *Figure {
	f := &Figure{Name: "networking-stun-binding-request", Title: "Layout of a STUN Binding Request"}
	f.nwPacket([]nwField{
		{0, 2, nwFixed, []Line{code("0 0")}},
		{2, 14, nwHeader, []Line{nwFieldName("STUN Message Type")}},
		{16, 16, nwHeader, []Line{nwFieldName("Message Length")}},
		{32, 32, nwHeader, []Line{nwFieldName("Magic Cookie"), code("0x2112A442")}},
		{64, 96, nwHeader, []Line{nwFieldName("Transaction ID"), body("96 bits")}},
	})
	return f
}

// networkingSTUNPaddedBindingRequest draws the padded Binding Request
// of the path MTU probe for docs/reference/networking/nat-traversal.md
// (Padded Binding Request): the header of the plain request with its
// message length set, followed by the PADDING attribute.
func networkingSTUNPaddedBindingRequest() *Figure {
	f := &Figure{Name: "networking-stun-padded-binding-request", Title: "Layout of a padded STUN Binding Request"}
	f.nwPacket([]nwField{
		{0, 2, nwFixed, []Line{code("0 0")}},
		{2, 14, nwHeader, []Line{nwFieldName("Binding Request"), code("0x0001")}},
		{16, 16, nwHeader, []Line{nwFieldName("Message Length"), code("size − 20")}},
		{32, 32, nwHeader, []Line{nwFieldName("Magic Cookie"), code("0x2112A442")}},
		{64, 96, nwHeader, []Line{nwFieldName("Transaction ID"), body("96 bits")}},
		{160, 16, nwPadding, []Line{nwFieldName("PADDING"), code("0x0026")}},
		{176, 16, nwPadding, []Line{nwFieldName("Attribute Length"), code("size − 24")}},
		{192, 96, nwPadding, []Line{nwFieldName("Value"), body("size − 24 zero bytes")}},
	})
	return f
}

// networkingPolicyDataFlow draws how the merged policy of the state
// pull reaches the firewall and how its status goes back, for
// docs/reference/networking/network-policy.md (Data Flow).
func networkingPolicyDataFlow() *Figure {
	f := &Figure{Name: "networking-policy-data-flow", Title: "From the merged policy to the firewall and back"}
	cp := f.box(roleCore, spec{x: 0, y: 0, w: 230, h: 56, lines: []Line{name("Control Plane")}})
	snap := f.sheet(roleCore, spec{x: 0, y: 170, w: 230, lines: []Line{codeName("NodeStateSnapshot"), code(".Policy"), body("merged block")}})
	f.arrow(reply, cp.bottom(), pt{cp.cx(), snap.y})
	f.labelRight(pt{cp.cx(), (cp.y + cp.h + snap.y) / 2}, body("state pull"))

	row := func(x float64, l Line) *node {
		n := f.box(roleAgent, spec{x: x, h: 56, lines: []Line{l}})
		n.y = snap.cy() - n.h/2
		return n
	}
	dh := row(snap.x+snap.w+90, codeName("DispatchHandler"))
	f.arrow(flow, pt{snap.x + snap.w, snap.cy()}, dh.left())
	es := row(dh.x+dh.w+90, codeName("Enforcer.Sync"))
	f.arrow(flow, dh.right(), es.left())
	sr := row(es.x+es.w+90, codeName("StatusReporter"))
	f.arrow(flow, es.right(), sr.left())
	f.arrow(publish, vh(sr.top(), cp.right())...)
	f.label(pt{(cp.x + cp.w + sr.cx()) / 2, cp.cy()}, code("PUT /v1/nodes/{node_id}/policy-status"))

	// The Enforcer asks the PolicyEngine for the rules and applies what
	// comes back through the FirewallController itself.
	pe := f.box(roleAgent, spec{x: snap.x, y: es.y + es.h + 90, w: snap.w, h: 64, lines: []Line{codeName("PolicyEngine")}})
	askX, backX := es.x+40, es.x+80
	f.arrow(flow, vh(es.bottomAt(askX), pe.rightAt(pe.cy()-12))...)
	f.label(pt{(pe.x + pe.w + askX) / 2, pe.cy() - 12}, code("BuildFirewallRules"))
	f.arrow(reply, hv(pe.rightAt(pe.cy()+12), es.bottomAt(backX))...)
	f.labelUnder(pt{(pe.x + pe.w + askX) / 2, pe.cy() + 12}, body("FirewallRule entries"))
	applyX := es.x + es.w - 30
	fc := f.box(roleAgent, spec{y: pe.y + pe.h + 70, w: 240, lines: []Line{codeName("FirewallController"), body("nftables, pf, WFP")}})
	fc.x = applyX - fc.w/2
	f.arrow(flow, es.bottomAt(applyX), fc.topAt(applyX))
	f.labelRight(pt{applyX, (pe.y + pe.y + pe.h) / 2}, code("ApplyRules"))
	return f
}

// networkingNftablesArchitecture draws how the firewall rules reach the
// nftables table of the Linux controller, for
// docs/reference/networking/nftables-firewall.md (Architecture).
func networkingNftablesArchitecture() *Figure {
	f := &Figure{Name: "networking-nftables-architecture", Title: "From the firewall rules to the nftables table"}
	pe := f.box(roleAgent, spec{x: 0, y: 0, w: 240, h: 56, lines: []Line{codeName("PolicyEngine")}})
	fr := f.sheet(roleAgent, spec{x: 0, y: 140, w: 240, lines: []Line{codeName("FirewallRule"), body("slice")}})
	f.arrow(flow, pe.bottom(), pt{pe.cx(), fr.y})
	nc := f.filled(roleAgent, spec{x: 360, w: 260, h: fr.h, lines: []Line{codeName("NftablesController")}})
	nc.y = fr.y
	f.arrow(flow, pt{fr.x + fr.w, fr.cy()}, nc.left())

	tbl := f.frame(roleSubstrate, 160, fr.y+fr.h+80, 760, 170, "", "nftables (nfnl)", "table plexd, family inet")
	f.arrow(call, nc.bottom(), pt{nc.cx(), tbl.y})
	for i, c := range []string{"<chain>-input", "<chain>-forward", "<chain>-output"} {
		f.box(roleSubstrate, spec{x: tbl.x + 30 + float64(i)*240, y: tbl.y + 76, w: 220, h: 64, lines: []Line{codeName(c)}})
	}
	return f
}

// networkingPeerEndpointDataFlow draws the two paths of the peer
// endpoint exchange, the STUN report loop out and the state pull in,
// for docs/reference/networking/peer-endpoint-exchange.md (Data Flow).
func networkingPeerEndpointDataFlow() *Figure {
	f := &Figure{Name: "networking-peer-endpoint-data-flow", Title: "The endpoint report loop and the state pull"}
	const fw = 930.0
	out := f.frame(roleNeutral, 0, 0, fw, 0, "", "Outbound", "the STUN report loop")
	disc := f.box(roleAgent, spec{x: 30, y: 80, w: 220, lines: []Line{name("Discoverer"), body("nat package")}})
	cp1 := f.box(roleCore, spec{x: 540, y: 80, w: 220, h: disc.h, lines: []Line{name("Control Plane"), body("api package")}})
	f.arrow(call, disc.rightAt(disc.cy()-12), cp1.leftAt(disc.cy()-12))
	f.label(pt{(disc.x + disc.w + cp1.x) / 2, disc.cy() - 12}, code("ReportEndpoint"))
	f.arrow(reply, cp1.leftAt(disc.cy()+12), disc.rightAt(disc.cy()+12))
	f.labelUnder(pt{(disc.x + disc.w + cp1.x) / 2, disc.cy() + 12}, code("stale_after"), body("deadline"))
	stun := f.box(roleExternal, spec{x: 30, y: disc.y + disc.h + 110, w: 220, h: 56, lines: []Line{name("STUN Servers")}})
	f.arrow(call, disc.bottomAt(disc.cx()-40), stun.topAt(disc.cx()-40))
	f.labelLeft(pt{disc.cx() - 40, (disc.y + disc.h + stun.y) / 2}, body("STUN"))
	f.arrow(reply, stun.topAt(disc.cx()+40), disc.bottomAt(disc.cx()+40))
	f.labelRight(pt{disc.cx() + 40, (disc.y + disc.h + stun.y) / 2}, body("public endpoint"))
	out.h = stun.y + stun.h + 30

	in := f.frame(roleNeutral, 0, out.h+40, fw, 0, "", "Inbound", "the reconciliation state pull")
	cp2 := f.box(roleCore, spec{x: 30, y: in.y + 80, w: 220, lines: []Line{name("Control Plane"), body("api package")}})
	rec := f.box(roleAgent, spec{x: 540, y: cp2.y, w: 220, h: cp2.h, lines: []Line{name("Reconciler"), body("reconcile package")}})
	f.arrow(call, rec.leftAt(rec.cy()-12), cp2.rightAt(rec.cy()-12))
	f.label(pt{(cp2.x + cp2.w + rec.x) / 2, rec.cy() - 12}, code("GET /v1/nodes/{id}/state"))
	f.arrow(reply, cp2.rightAt(rec.cy()+12), rec.leftAt(rec.cy()+12))
	f.labelUnder(pt{(cp2.x + cp2.w + rec.x) / 2, rec.cy() + 12}, code("peers[].endpoint"))
	busY := rec.y + rec.h + 60
	sseX := rec.x + 40
	f.arrow(publish, vhv(cp2.bottom(), rec.bottomAt(sseX), busY)...)
	f.labelUnder(pt{(cp2.cx() + sseX) / 2, busY}, code("peer_endpoint_changed"), body("SSE event: triggers a reconcile;"),
		body("the payload is never decoded"))
	wg := f.box(roleAgent, spec{x: rec.x + 80, y: busY + 110, w: 270, lines: []Line{name("WireGuard Manager"), body("wireguard package")}})
	addX := rec.x + 170
	f.arrow(flow, rec.bottomAt(addX), wg.topAt(addX))
	f.labelRight(pt{addX, (rec.y + rec.h + wg.y) / 2}, code("AddPeer,"), code("UpdatePeer"))
	in.h = wg.y + wg.h + 30 - in.y
	return f
}

// networkingTunnelDataFlow draws how the sessions block of the state
// pull becomes a listener that forwards to the target host, for
// docs/reference/networking/secure-access-tunneling.md (Data Flow).
func networkingTunnelDataFlow() *Figure {
	f := &Figure{Name: "networking-tunnel-data-flow", Title: "From the sessions block to a forwarding listener"}
	cp := f.box(roleCore, spec{x: 0, y: 0, w: 280, lines: []Line{name("Control Plane"), code("GET /v1/nodes/{id}/state")}})
	rec := f.box(roleAgent, spec{x: 0, y: 170, w: 280, lines: []Line{name("Reconciler"), code("internal/reconcile")}})
	f.nwPull(cp, rec, body("sessions block"))
	disp := f.box(roleAgent, spec{x: 380, y: rec.y, w: 270, h: rec.h, lines: []Line{codeName("tunnel.Dispatcher"), code("Handle")}})
	f.arrow(flow, rec.right(), disp.left())
	sm := f.box(roleAgent, spec{x: 740, y: rec.y, w: 270, h: rec.h, lines: []Line{codeName("SessionManager"), code("CreateSession")}})
	f.arrow(flow, disp.right(), sm.left())

	sess := f.frame(roleAgent, disp.x-30, sm.y+sm.h+70, sm.x+sm.w+30-(disp.x-30), 0, "", "Session", "")
	f.arrow(creates, sm.bottom(), pt{sm.cx(), sess.y})
	lis := f.box(roleAgent, spec{x: disp.x, y: sess.y + 64, w: 270, lines: []Line{name("Listener"), body("TCP"), code("bound to meshIP:0")}})
	fwd := f.box(roleAgent, spec{x: sm.x, y: lis.y, w: 270, h: lis.h, lines: []Line{name("Forwarder"), body("bidirectional"), code("io.Copy")}})
	f.arrow(flow, lis.right(), fwd.left())
	sess.h = fwd.y + fwd.h + 30 - sess.y
	tgt := f.box(roleExternal, spec{x: sm.x, y: sess.y + sess.h + 70, w: 270, lines: []Line{name("Target Host"), body("e.g. sshd")}})
	f.arrow(both, fwd.bottom(), tgt.top())
	return f
}
