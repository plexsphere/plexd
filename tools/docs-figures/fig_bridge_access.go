package main

// bridgeAccessFigures are the bridge- figures of user access, site-to-site VPN and the VPN and tunnel providers.
var bridgeAccessFigures = []func() *Figure{
	bridgeUserAccessDataFlow,
	bridgeSiteToSiteDataFlow,
	bridgeVpnProvidersDataFlow,
	bridgeTunnelProvidersDataFlow,
}

// The four data-flow figures share one layout, so they read as a
// family: the outside source above the bridge node, the interface it
// arrives on at the top left of the node, the mesh interface at the
// top right, the mesh peers outside on the right, the parts of plexd
// that run the entry interface stacked under it, and whatever drives
// them in the right column.
const (
	accLeftX   = 30.0  // left column inside the bridge node frame
	accLeftW   = 280.0 // width of the left column
	accRightX  = 460.0 // right column inside the frame
	accRightW  = 300.0 // width of the right column
	accFrameW  = 790.0 // width of the bridge node frame
	accOutX    = 890.0 // column outside the frame, on the right
	accOutW    = 200.0 // width of the outside column
	accFrameY  = 150.0 // top of the frame
	accRowH    = 64.0  // height of a box in a row under the interfaces
	accRowGap  = 40.0  // gap between two rows
	accEntryX  = 210.0 // where the outside traffic enters the entry interface
	accSourceW = 320.0 // width of the outside source
)

// accSpec is what one figure of the family puts into the shared
// layout.
type accSpec struct {
	// user draws the source as a user or device; otherwise it is an
	// external system.
	user      bool
	source    []Line
	transport []Line
	entry     []Line
	link      []Line
	// stack lists the parts of plexd under the entry interface, top
	// down. The first one creates the entry interface; a relation
	// joins each to the next.
	stack [][]Line
	// fromFirst joins every part of the stack to the first one instead
	// of to the one above it. The relation to the third part runs
	// round the left of the second.
	fromFirst bool
}

// accLayout holds the parts of the shared layout a figure attaches
// its own parts to.
type accLayout struct {
	frame *node
	entry *node
	mesh  *node
	stack []*node
}

// accRow returns the top of row i under the interfaces.
func (l *accLayout) accRow(i int) float64 {
	return l.entry.y + l.entry.h + 60 + float64(i)*(accRowH+accRowGap)
}

// accClose ends the frame 30 pixels under the lowest of the given
// boxes.
func (l *accLayout) accClose(lowest ...*node) {
	bottom := 0.0
	for _, n := range lowest {
		bottom = max(bottom, n.y+n.h)
	}
	l.frame.h = bottom + 30 - l.frame.y
}

// accDataFlow draws the shared layout: the source, the bridge node
// with its entry and mesh interfaces, the mesh peers, the traffic
// between them, and the stack of plexd parts under the entry
// interface.
func accDataFlow(f *Figure, s accSpec) *accLayout {
	l := &accLayout{}
	l.frame = f.frame(roleSubstrate, 0, accFrameY, accFrameW, 0, "", "Bridge node", "")
	src := spec{x: accEntryX - accSourceW/2, y: 0, w: accSourceW, lines: s.source}
	var source *node
	if s.user {
		source = f.actor(src)
	} else {
		source = f.box(roleExternal, src)
	}

	l.entry = f.box(roleSubstrate, spec{x: accLeftX, y: accFrameY + 70, w: accLeftW, lines: s.entry})
	l.mesh = f.box(roleSubstrate, spec{x: accRightX, y: l.entry.y, w: accRightW, lines: []Line{
		name("Mesh WireGuard"), name("interface"), code("plexd0"),
	}})
	h := max(l.entry.h, l.mesh.h)
	l.entry.h, l.mesh.h = h, h
	peers := f.box(roleAgent, spec{x: accOutX, w: accOutW, lines: []Line{name("Mesh peers"), code("10.42.0.0/16")}})
	peers.y = l.mesh.cy() - peers.h/2

	f.arrow(both, pt{accEntryX, source.y + source.h}, l.entry.topAt(accEntryX))
	f.labelRight(pt{accEntryX, (source.y + source.h + accFrameY) / 2}, s.transport...)
	f.arrow(both, l.entry.right(), l.mesh.left())
	f.label(mid(l.entry.right(), l.mesh.left()), s.link...)
	f.arrow(both, l.mesh.right(), peers.left())

	for i, lines := range s.stack {
		n := f.box(roleAgent, spec{x: accLeftX, y: l.accRow(i), w: accLeftW, h: accRowH, lines: lines})
		switch {
		case i == 0:
			f.arrow(creates, n.top(), l.entry.bottom())
		case s.fromFirst && i > 1:
			first := l.stack[0]
			f.arrow(relation, hvh(first.left(), n.left(), accLeftX-15)...)
		default:
			f.arrow(relation, l.stack[i-1].bottom(), n.top())
		}
		l.stack = append(l.stack, n)
	}
	return l
}

// accReconcile draws how the control plane drives a bridge feature
// that has no SSE handler of its own: the bridge_config_updated event
// only triggers a reconcile, and the reconciler hands the desired
// bridge state it pulled to the feature's reconcile handler. The
// event, the reconcile and the handler fill the right column; the
// control plane sits outside the frame.
func accReconcile(f *Figure, l *accLayout, handler string) *node {
	ev := f.box(roleEvent, spec{x: accRightX, y: l.accRow(0), w: accRightW, h: accRowH, lines: []Line{
		codeName("bridge_config_updated"),
	}})
	rec := f.box(roleAgent, spec{x: accRightX, y: l.accRow(1), w: accRightW, h: accRowH, lines: []Line{name("reconcile")}})
	// The handler sits 20 pixels lower than its row, so the label of
	// the arrow into it has room.
	hd := f.box(roleAgent, spec{x: accRightX, y: l.accRow(2) + 20, w: accRightW, h: accRowH, lines: []Line{codeName(handler)}})
	f.arrow(flow, ev.bottom(), rec.top())
	f.arrow(flow, rec.bottom(), hd.top())
	f.labelLeft(mid(rec.bottom(), hd.top()), body("desired bridge state"))
	cp := f.box(roleCore, spec{x: accOutX, y: ev.y, w: accOutW, h: accRowH, lines: []Line{name("Control plane")}})
	f.arrow(publish, cp.left(), ev.right())
	f.label(pt{(accFrameW + accOutX) / 2, ev.cy()}, body("SSE"))
	return hd
}

// bridgeUserAccessDataFlow draws the data flow of a wireguard user
// access provider for docs/reference/bridge/user-access-integration.md
// (Data Flow): the devices reach plexd0 through the provider's
// interface and the source rewrite, the manager serves the pulled
// block, and the reporter sends the state of each provider.
func bridgeUserAccessDataFlow() *Figure {
	f := &Figure{Name: "bridge-user-access-data-flow", Title: "Data flow of user access through a bridge node"}
	l := accDataFlow(f, accSpec{
		user:      true,
		source:    []Line{name("Devices"), body("of a wireguard provider")},
		transport: []Line{body("WireGuard, UDP listen_port")},
		entry:     []Line{name("Provider WireGuard"), name("interface"), code("wg-ua-a0a0a0e1"), body("10.99.0.1/24")},
		link:      []Line{body("forwarding,"), body("source rewrite")},
		stack: [][]Line{
			{codeName("AccessController"), body("interface and devices")},
			{codeName("UserAccessManager"), body("one entry per provider")},
			{codeName("InterfaceKeyStore"), code("<data_dir>/user-access")},
		},
	})
	hd := accReconcile(f, l, "UserAccessReconcileHandler")
	mgr := l.stack[1]

	// The handler hands the block to the manager through the gap
	// between the two columns. The manager's entries reach the reporter
	// round the left of the stack and under it, so the two paths never
	// meet.
	applyX := (accLeftX + accLeftW + accRightX) / 2
	f.arrow(flow, hvh(hd.left(), mgr.right(), applyX)...)
	f.label(pt{(accLeftX + accLeftW + applyX) / 2, mgr.cy()}, code("Apply()"))
	rep := f.box(roleAgent, spec{x: accRightX, y: l.accRow(3) + 20, w: accRightW, h: accRowH, lines: []Line{
		codeName("UserAccessStatusReporter"),
	}})
	f.arrow(flow, hvh(mgr.left(), rep.left(), accLeftX-15)...)

	// The reporter sends to the control plane box accReconcile drew in
	// the outside column.
	cpBottom := pt{accOutX + accOutW/2, l.accRow(0) + accRowH}
	f.arrow(call, hv(rep.right(), cpBottom)...)
	f.label(pt{(accRightX + accRightW + cpBottom.X) / 2, rep.cy()}, body("status report"))
	l.accClose(rep, l.stack[len(l.stack)-1])
	return f
}

// bridgeSiteToSiteDataFlow draws the data flow of a site-to-site
// tunnel for docs/reference/bridge/site-to-site-vpn.md (Data Flow).
func bridgeSiteToSiteDataFlow() *Figure {
	f := &Figure{Name: "bridge-site-to-site-data-flow", Title: "Data flow of a site-to-site tunnel through a bridge node"}
	l := accDataFlow(f, accSpec{
		source:    []Line{name("External network"), body("remote site")},
		transport: []Line{body("WireGuard tunnel (UDP)")},
		entry:     []Line{name("S2S WireGuard"), name("interfaces"), code("wg-s2s-{id}"), body("ports 51823, …")},
		link:      []Line{body("route")},
		stack: [][]Line{
			{codeName("VPNController"), body("WireGuard operations")},
			{codeName("RouteController"), body("OS routing operations")},
		},
	})
	hd := accReconcile(f, l, "SiteToSiteReconcileHandler")
	l.accClose(hd, l.stack[len(l.stack)-1])
	return f
}

// bridgeVpnProvidersDataFlow draws the data flow of a tailscale or
// netbird user access provider for
// docs/reference/bridge/vpn-providers.md (Data Flow): the vendor's
// users reach plexd0 through the client's interface and the source
// rewrite, and the manager starts the client with the key the Secret
// fetch returns.
func bridgeVpnProvidersDataFlow() *Figure {
	f := &Figure{Name: "bridge-vpn-providers-data-flow", Title: "Data flow of user access through a VPN provider"}
	l := accDataFlow(f, accSpec{
		user:      true,
		source:    []Line{name("Tailscale or NetBird users"), body("of the vendor's network")},
		transport: []Line{body("vendor overlay network")},
		entry:     []Line{name("Client interface"), code("tailscale0, wt0, …")},
		link:      []Line{body("forwarding,"), body("source rewrite")},
		stack: [][]Line{
			{codeName("UserAccessClient"), body("Tailscale, NetBird")},
			{codeName("CommandExecutor"), body("tailscale, netbird CLI")},
		},
	})
	client := l.stack[0]
	mgr := f.box(roleAgent, spec{x: accRightX, y: client.y, w: accRightW, h: accRowH, lines: []Line{codeName("UserAccessManager")}})
	f.arrow(flow, mgr.left(), client.right())
	f.label(mid(client.right(), mgr.left()), code("Start()"), code("Stop()"))

	// The join key comes from the Secret the provider names, fetched
	// from the control plane in the version the inventory lists.
	fetch := f.box(roleAgent, spec{x: accRightX, y: l.accRow(1), w: accRightW, h: accRowH, lines: []Line{
		codeName("nodeSecretFetcher"), body("the Secret's value"),
	}})
	f.arrow(secretFlow, fetch.top(), mgr.bottom())
	f.labelRight(mid(fetch.top(), mgr.bottom()), body("join key"))
	cp := f.box(roleCore, spec{x: accOutX, y: fetch.y, w: accOutW, h: accRowH, lines: []Line{name("Control plane")}})
	f.arrow(call, fetch.right(), cp.left())
	f.label(mid(fetch.right(), cp.left()), body("fetch"))
	l.accClose(fetch, l.stack[len(l.stack)-1])
	return f
}

// bridgeTunnelProvidersDataFlow draws the data flow of a site-to-site
// tunnel through a tunnel provider for
// docs/reference/bridge/tunnel-providers.md (Data Flow).
func bridgeTunnelProvidersDataFlow() *Figure {
	f := &Figure{Name: "bridge-tunnel-providers-data-flow", Title: "Data flow of a site-to-site tunnel through a tunnel provider"}
	l := accDataFlow(f, accSpec{
		source:    []Line{name("External network"), body("remote site")},
		transport: []Line{body("IPsec or OpenVPN tunnel")},
		entry:     []Line{name("IPsec / OpenVPN"), name("tunnels"), code("ipsec-{id}, tun-{id}")},
		link:      []Line{body("route")},
		stack: [][]Line{
			{codeName("TunnelProvider"), body("IPsec, OpenVPN")},
			{codeName("CommandExecutor"), body("CLI invocations")},
			{codeName("RouteController"), body("OS routing operations")},
		},
		fromFirst: true,
	})
	prov := l.stack[0]
	mgr := f.box(roleAgent, spec{x: accRightX, y: prov.y, w: accRightW, lines: []Line{
		codeName("SiteToSiteManager"), body("delegates when"), code(`tunnel.ProviderType != ""`), code(`&& != "wireguard"`),
	}})
	f.arrow(flow, mgr.leftAt(prov.cy()), prov.right())
	l.accClose(mgr, l.stack[len(l.stack)-1])
	return f
}
