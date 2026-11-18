package main

// bridgeFigures are the bridge- figures of bridge mode, the relay, the route controllers and public ingress.
var bridgeFigures = []func() *Figure{
	bridgeModeDataFlow,
	bridgeNATRelay,
	bridgeNetlinkRouteController,
	bridgeRouteControllersMacOSWindows,
	bridgePublicIngress,
	bridgeACMESNIRouting,
}

// brgSub is a bold sub-heading inside a box, in the size of a body line.
func brgSub(s string) Line { return Line{Text: s, Size: sizeBody, Bold: true} }

// bridgeModeDataFlow draws how a bridge forwards traffic from the mesh
// to the access subnets: the host kernel forwards and translates the
// packets, and the Bridge Manager, beside the path, programs forwarding
// and NAT through the RouteController, for
// docs/reference/bridge/bridge-mode.md.
func bridgeModeDataFlow() *Figure {
	f := &Figure{Name: "bridge-mode-data-flow", Title: "Traffic from the mesh through a bridge to the access subnets"}
	const rowY, rowH, lowY = 200.0, 90.0, 410.0
	wg := f.box(roleSubstrate, spec{x: 0, y: rowY, w: 200, h: rowH, lines: []Line{name("WireGuard"), name("interface"), code("plexd0")}})
	peers := f.box(roleAgent, spec{x: 0, y: 0, w: 200, h: 64, lines: []Line{name("Mesh peers")}})
	kernel := f.frame(roleSubstrate, 270, rowY-70, 540, rowH+100, "", "Host kernel", "")
	fwd := f.box(roleSubstrate, spec{x: 300, y: rowY, w: 210, h: rowH, lines: []Line{name("IP forwarding"), code("sysctl")}})
	nat := f.box(roleSubstrate, spec{x: 570, y: rowY, w: 210, h: rowH, lines: []Line{name("NAT"), code("nftables")}})
	acc := f.box(roleSubstrate, spec{x: 880, y: rowY, w: 200, h: rowH, lines: []Line{name("Access-side"), name("interface"), code("eth1")}})
	f.arrow(both, peers.bottom(), wg.top())
	f.arrow(both, wg.right(), fwd.left())
	f.arrow(both, fwd.right(), nat.left())
	f.arrow(both, nat.right(), acc.left())

	// Beside the path: the Bridge Manager programs the kernel and
	// carries no packets.
	rc := f.box(roleAgent, spec{y: lowY, w: 260, h: 64, lines: []Line{codeName("RouteController")}})
	rc.x = kernel.x + kernel.w/2 - rc.w/2
	mgr := f.filled(roleAgent, spec{x: 0, y: lowY, w: 240, h: 64, lines: []Line{name("Bridge Manager")}})
	f.arrow(flow, mgr.right(), rc.left())
	busY := (kernel.y + kernel.h + lowY) / 2
	f.arrow(call, vhv(rc.top(), fwd.bottom(), busY)...)
	f.arrow(call, vhv(rc.top(), nat.bottom(), busY)...)

	ext := f.frame(roleNeutral, acc.x+acc.w-260, lowY, 260, rowH, "", "External network", "")
	f.text(ext.x+16, ext.y+44, "left", body("subnets"))
	f.arrow(both, acc.bottom(), ext.topAt(acc.cx()))
	return f
}

// bridgeNATRelay draws how the relay of a bridge forwards a WireGuard
// datagram between two peers behind NAT, and how the state pull drives
// it, for docs/reference/bridge/nat-relay.md.
func bridgeNATRelay() *Figure {
	f := &Figure{Name: "bridge-nat-relay", Title: "How a bridge relays WireGuard between two peers behind NAT"}
	const rowY, rowH = 250.0, 110.0
	peerA := f.box(roleAgent, spec{x: 100, y: 0, w: 240, h: 76, lines: []Line{name("Peer A"), body("behind NAT")}})
	peerB := f.box(roleAgent, spec{x: 820, y: 0, w: 240, h: 76, lines: []Line{name("Peer B"), body("behind NAT")}})
	fr := f.frame(roleSubstrate, 0, 150, 1100, 0, "", "Bridge node", "relay")

	sock := f.box(roleAgent, spec{x: 40, y: rowY, w: 300, h: rowH, lines: []Line{
		name("UDP socket"), body("on the pulled"), code("listen_port"),
	}})
	parse := f.box(roleAgent, spec{x: 410, y: rowY, w: 260, h: rowH, lines: []Line{
		codeName("parseWGMessage"), body("type, sender and"), body("receiver index"),
	}})
	dest := f.box(roleAgent, spec{x: 740, y: rowY, w: 320, h: rowH, lines: []Line{
		brgSub("handshake:"), body("CheckMAC1 per listed peer"), brgSub("every message:"), body("indices table"),
	}})
	f.arrow(flow, sock.right(), parse.left())
	f.arrow(flow, parse.right(), dest.left())
	loopY := rowY + rowH + 50
	f.arrow(flow, dest.bottom(), pt{dest.cx(), loopY}, pt{sock.cx(), loopY}, sock.bottom())
	f.label(pt{parse.cx(), loopY}, body("dispatch loop"))

	busY := 110.0
	f.arrow(both, peerA.bottomAt(250), sock.topAt(250))
	f.labelLeft(pt{250, busY}, body("WireGuard datagram"))
	f.arrow(both, peerB.bottom(), pt{peerB.cx(), busY}, pt{310, busY}, sock.topAt(310))
	f.label(pt{(peerB.cx() + 310) / 2, busY}, body("WireGuard datagram"))

	ctlY := loopY + 60
	pull := f.sheet(roleCore, spec{x: 40, y: ctlY, w: 300, h: 80, lines: []Line{name("state pull"), code("bridge.relay, peers")}})
	h := f.box(roleAgent, spec{x: 410, y: ctlY, w: 320, h: 80, lines: []Line{codeName("RelayReconcileHandler")}})
	cfg := f.box(roleAgent, spec{x: 800, y: ctlY, w: 260, h: 80, lines: []Line{codeName("Configure / Stop")}})
	f.arrow(flow, pull.right(), h.left())
	f.arrow(flow, h.right(), cfg.left())
	fr.h = cfg.y + cfg.h + 30 - fr.y
	return f
}

// bridgeNetlinkRouteController draws the Linux route controller and the
// three kernel interfaces it programs, for
// docs/reference/bridge/netlink-route-controller.md.
func bridgeNetlinkRouteController() *Figure {
	f := &Figure{Name: "bridge-netlink-route-controller", Title: "The Linux route controller and what it programs"}
	const w, gap = 300.0, 60.0
	center := (3*w + 2*gap) / 2
	mgr := f.box(roleAgent, spec{x: center - 160, y: 0, w: 320, h: 64, lines: []Line{name("Bridge Manager")}})
	ctrl := f.filled(roleAgent, spec{x: center - 200, y: 150, w: 400, h: 64, lines: []Line{codeName("NetlinkRouteController")}})
	f.arrow(flow, mgr.bottom(), ctrl.top())
	busY := ctrl.y + ctrl.h + 50
	subs := [][]Line{
		{name("netlink"), body("routes")},
		{name("sysctl"), body("forwarding")},
		{name("nftables"), body("NAT")},
	}
	for i, l := range subs {
		n := f.box(roleSubstrate, spec{x: float64(i) * (w + gap), y: busY + 50, w: w, h: 80, lines: l})
		f.arrow(call, vhv(ctrl.bottom(), n.top(), busY)...)
	}
	return f
}

// bridgeRouteControllersMacOSWindows draws the macOS and Windows route
// controllers, the managers that call them, and what each delegates
// to, for docs/reference/bridge/route-controllers-macos-windows.md.
// The user access manager is not among them: it serves no provider on
// either platform, so it never calls the route controller there.
func bridgeRouteControllersMacOSWindows() *Figure {
	f := &Figure{Name: "bridge-route-controllers-macos-windows", Title: "The macOS and Windows route controllers and what they program"}
	const leafY, leafW, leafGap = 330.0, 180.0, 30.0
	mgrs := []*node{
		f.box(roleAgent, spec{x: 150, y: 0, w: 300, h: 64, lines: []Line{name("Bridge Manager")}}),
		f.box(roleAgent, spec{x: 735, y: 0, w: 300, h: 64, lines: []Line{codeName("SiteToSiteManager")}}),
	}
	leaf := func(i int, r role, label string) *node {
		x := float64(i) * (leafW + leafGap)
		if i >= 3 {
			x += 60
		}
		return f.box(r, spec{x: x, y: leafY, w: leafW, h: 64, lines: []Line{codeName(label)}})
	}
	route := leaf(0, roleSubstrate, "route(8)")
	sysctl := leaf(1, roleSubstrate, "sysctl(8)")
	pf := leaf(2, roleAgent, "PFController")
	ipcfg := leaf(3, roleSubstrate, "winipcfg")
	wfp := leaf(4, roleAgent, "WFPController")

	darwin := f.filled(roleAgent, spec{y: 170, w: 300, h: 64, lines: []Line{codeName("DarwinRouteController")}})
	darwin.x = sysctl.cx() - darwin.w/2
	windows := f.filled(roleAgent, spec{y: 170, w: 300, h: 64, lines: []Line{codeName("WindowsRouteController")}})
	windows.x = (ipcfg.x+wfp.x+wfp.w)/2 - windows.w/2

	busY := 117.0
	for _, m := range mgrs {
		for _, c := range []*node{darwin, windows} {
			f.arrow(flow, vhv(m.bottom(), c.top(), busY)...)
		}
	}
	// Each arrow leaves its controller on its own stem, so a call and a
	// delegation never share a segment.
	leafBus := darwin.y + darwin.h + 48
	f.arrow(call, vhv(darwin.bottomAt(darwin.x+50), route.top(), leafBus)...)
	f.arrow(call, darwin.bottomAt(sysctl.cx()), sysctl.top())
	f.arrow(flow, vhv(darwin.bottomAt(darwin.x+darwin.w-50), pf.top(), leafBus)...)
	f.arrow(call, windows.bottomAt(ipcfg.cx()), ipcfg.top())
	f.arrow(flow, windows.bottomAt(wfp.cx()), wfp.top())
	return f
}

// bridgePublicIngress draws how a bridge routes a public TCP
// connection to a target node over the mesh, and which handlers feed
// its listeners and certificates, for
// docs/reference/bridge/public-ingress.md.
func bridgePublicIngress() *Figure {
	f := &Figure{Name: "bridge-public-ingress", Title: "How a bridge routes a public connection to a target node"}
	const lsnX, lsnW, yA, yB, gap = 60.0, 160.0, 210.0, 390.0, 64.0
	clients := f.actor(spec{x: -20, y: 0, w: 360, h: 64, lines: []Line{name("Public internet clients")}})
	fr := f.frame(roleSubstrate, 30, 130, 1046, 0, "", "Bridge node", "one listener per listen port")

	plain := f.box(roleAgent, spec{x: lsnX, y: yA, w: lsnW, h: 70, lines: []Line{codeName(":2222"), body("plain port")}})
	sni := f.box(roleAgent, spec{x: lsnX, y: yB - 35, w: lsnW, h: 70, lines: []Line{codeName(":443"), body("SNI port")}})
	f.arrow(call, vh(clients.bottomAt(0), plain.left())...)
	f.arrow(call, vh(clients.bottomAt(0), sni.left())...)
	f.labelRight(pt{0, 97}, body("TCP to"), code("<bridge>:<listen_port>"))

	peek := f.state(stateNormal, spec{x: lsnX + lsnW + 40, y: yB - 40, w: 266, h: 80, lines: []Line{
		brgSub("peek the ClientHello,"), brgSub("match the server name"),
	}})
	modeX := peek.x + peek.w + gap
	pass := f.state(stateNormal, spec{x: modeX, y: yB - 95, w: 240, h: 80, lines: []Line{
		brgSub("passthrough"), body("replay the peeked bytes"),
	}})
	term := f.state(stateNormal, spec{x: modeX, y: yB + 15, w: 240, h: 80, lines: []Line{
		brgSub("terminate, acme"), body("end TLS at the bridge"),
	}})
	dial := f.state(stateNormal, spec{x: modeX + 240 + gap, y: yB - 40, w: 150, h: 80, lines: []Line{
		brgSub("dial target"), body("over plexd0"),
	}})
	f.arrow(flow, sni.right(), peek.left())
	f.arrow(flow, hvh(peek.right(), pass.left(), modeX-gap/2)...)
	f.arrow(flow, hvh(peek.right(), term.left(), modeX-gap/2)...)
	f.arrow(flow, hvh(pass.right(), dial.left(), dial.x-gap/2)...)
	f.arrow(flow, hvh(term.right(), dial.left(), dial.x-gap/2)...)
	f.arrow(flow, hv(plain.right(), dial.top())...)
	f.label(pt{(plain.x + plain.w + dial.cx()) / 2, plain.cy()}, body("forward without reading"))

	const colX, colW, tgtX, tgtW, rowH = lsnX, 330.0, lsnX + 390, 300.0, 70.0
	rowY := term.y + term.h + 80
	reconcile := f.box(roleAgent, spec{x: colX, y: rowY, w: colW, h: rowH, lines: []Line{codeName("IngressReconcileHandler")}})
	apply := f.box(roleAgent, spec{x: tgtX, y: rowY, w: tgtW, h: rowH, lines: []Line{codeName("IngressManager.Apply")}})
	f.arrow(flow, reconcile.right(), apply.left())
	tableY := rowY - 40
	f.arrow(flow, vhv(apply.top(), sni.bottom(), tableY)...)
	f.label(pt{(sni.cx() + apply.cx()) / 2, tableY}, body("ingressTable per port, swapped in place"))

	secrets := f.box(roleAgent, spec{x: colX, y: rowY + rowH + 30, w: colW, h: rowH, lines: []Line{codeName("IngressSecretInventoryHandler")}})
	termCerts := f.box(roleSecret, spec{x: tgtX, y: secrets.y, w: tgtW, h: rowH, lines: []Line{name("terminate certs")}})
	f.arrow(secretFlow, secrets.right(), termCerts.left())
	acme := f.box(roleAgent, spec{x: colX, y: secrets.y + rowH + 30, w: colW, h: rowH, lines: []Line{codeName("ACMEManager")}})
	acmeCerts := f.box(roleSecret, spec{x: tgtX, y: acme.y, w: tgtW, h: rowH, lines: []Line{name("acme certs"), body("and the challenges on :443")}})
	f.arrow(secretFlow, acme.right(), acmeCerts.left())
	fr.h = acme.y + acme.h + 30 - fr.y

	target := f.box(roleAgent, spec{y: fr.y + fr.h + 70, w: 350, h: 70, lines: []Line{
		name("Target node"), code("<target_address>:<target_port>"),
	}})
	target.x = fr.x + fr.w - target.w
	f.arrow(call, dial.bottom(), target.topAt(dial.cx()))
	return f
}

// bridgeACMESNIRouting draws how a bridge routes a TLS connection on an
// SNI port by its ClientHello, answers an ACME challenge, and where
// ACMEManager keeps its account, for docs/reference/bridge/acme-sni.md.
func bridgeACMESNIRouting() *Figure {
	f := &Figure{Name: "bridge-acme-sni-routing", Title: "How a bridge routes a TLS connection by its server name"}
	const mainX, mainW, sideX = 60.0, 480.0, 590.0
	clients := f.actor(spec{x: 60, y: 0, w: 340, h: 76, lines: []Line{name("Public internet clients"), body("HTTPS / TLS")}})
	ca := f.box(roleExternal, spec{x: 640, y: 0, w: 260, h: 76, lines: []Line{name("ACME CA"), body("TLS-ALPN-01")}})
	fr := f.frame(roleSubstrate, 30, 150, 1040, 0, "", "Bridge node", "")

	lsn := f.box(roleAgent, spec{x: mainX, y: 230, w: mainW, h: 70, lines: []Line{
		codeName("IngressManager"), body("one listener per SNI port (:443)"),
	}})
	f.arrow(call, clients.bottomAt(230), lsn.topAt(230))
	f.arrow(call, vhv(ca.bottomAt(700), lsn.topAt(430), 113)...)
	f.text(330, 176, "center", body("TLS ClientHello"))

	acme := f.box(roleAgent, spec{x: sideX, y: 220, w: 230, h: 90, lines: []Line{
		codeName("ACMEManager"), body("one autocert.Manager"), body("per account"),
	}})
	f.arrow(call, acme.topAt(800), ca.bottomAt(800))
	f.labelRight(pt{800, 107}, body("HTTPS to the block's"), code("directory_url"))
	cache := f.store(roleStore, spec{x: 870, y: 216, w: 180, h: 98, lines: []Line{name("DirCache"), code("<data_dir>/acme")}})
	f.arrow(secretFlow, acme.right(), pt{cache.x, acme.cy()})

	peek := f.state(stateNormal, spec{x: mainX, y: 370, w: mainW, h: 120, lines: []Line{
		codeName("peekClientHello"), body("crypto/tls parses the hello, at most"), body("16 KiB and 5 s, nothing is answered;"),
		body("it returns the server name and the offered ALPN"),
	}})
	f.arrow(flow, lsn.bottom(), peek.top())
	challenge := f.state(stateNormal, spec{x: 800, y: 0, w: 250, h: 80, lines: []Line{brgSub("answer the challenge,"), body("then close")}})
	challenge.y = peek.cy() - challenge.h/2
	f.arrow(flow, peek.right(), challenge.left())
	f.label(pt{(peek.x + peek.w + challenge.x) / 2, peek.cy()}, body("on :443, ALPN exactly"), body("acme-tls/1 for a host"), body("of an acme rule"))

	match := f.state(stateNormal, spec{x: mainX, y: peek.y + peek.h + 60, w: mainW, h: 90, lines: []Line{
		codeName("ingressTable.match(server name)"), body("exact host first, then a wildcard of one label"),
	}})
	f.arrow(flow, peek.bottom(), match.top())

	const outW, outH, outGap = 300.0, 110.0, 40.0
	outY := match.y + match.h + 90
	busY := match.y + match.h + 45
	pass := f.state(stateNormal, spec{x: mainX, y: outY, w: outW, h: outH, lines: []Line{
		brgSub("passthrough rule"), body("dial the target, replay"), body("the peeked bytes,"), body("copy both ways"),
	}})
	term := f.state(stateNormal, spec{x: mainX + outW + outGap, y: outY, w: outW, h: outH, lines: []Line{
		brgSub("terminate or acme rule"), body("TLS handshake at the bridge,"), body("dial the target,"), body("copy the plaintext"),
	}})
	closed := f.state(stateFailed, spec{x: mainX + 2*(outW+outGap), y: outY, w: outW, h: outH, lines: []Line{
		brgSub("no rule, no server name,"), brgSub("a rule with a reason,"), brgSub("or no certificate"), body("close the connection"),
	}})
	for _, n := range []*node{pass, term} {
		f.arrow(flow, vhv(match.bottom(), n.top(), busY)...)
	}
	// The refusal leaves on its own side, so its red never covers the
	// stem the two rules share.
	f.arrow(refuse, hv(match.right(), closed.top())...)
	fr.h = outY + outH + 30 - fr.y
	return f
}
