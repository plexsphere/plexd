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
	// peers labels the mesh peers outside the frame; nil gives their
	// name and the mesh prefix alone.
	peers []Line
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
	peerLines := s.peers
	if peerLines == nil {
		peerLines = []Line{name("Mesh peers"), code("10.42.0.0/16")}
	}
	peers := f.box(roleAgent, spec{x: accOutX, w: accOutW, lines: peerLines})
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

// s2sPeers labels the mesh peers of the two site-to-site figures: every
// node routes the networks behind a bridge's tunnels, which its pull
// lists as the bridge's routed_subnets, through the bridge.
var s2sPeers = []Line{name("Mesh peers"), code("10.42.0.0/16"), body("route the site's"), body("networks through"), body("the bridge")}

// s2sLinks are the routes, the forwarding and the source rewrite the
// site-to-site manager sets up between a tunnel's link and plexd0.
var s2sLinks = []Line{body("routes,"), body("forwarding,"), body("source rewrite")}

// bridgeSiteToSiteDataFlow draws the data flow of the site-to-site
// tunnels for docs/reference/bridge/site-to-site-vpn.md (Data Flow):
// the remote site reaches plexd0 through the link of its tunnel, the
// manager routes the tunnel's allowed_subnets into the link and
// rewrites the source of what the link forwards into the mesh, and the
// mesh peers route the site's networks through the bridge. The
// reconcile handler and the pull handler feed the manager, and the
// reporter sends the state of each tunnel.
func bridgeSiteToSiteDataFlow() *Figure {
	f := &Figure{Name: "bridge-site-to-site-data-flow", Title: "Data flow of site-to-site tunnels through a bridge node"}
	l := accDataFlow(f, accSpec{
		source:    []Line{name("Remote site"), code("allowed_subnets")},
		transport: []Line{body("WireGuard, IPsec or OpenVPN")},
		entry:     []Line{name("Tunnel links"), code("wg-s2s-a0a0a0e1"), code("xf-s2s-a0a0a0e2"), code("ov-s2s-a0a0a0e3")},
		link:      s2sLinks,
		peers:     s2sPeers,
		stack: [][]Line{
			{codeName("VPNController"), body("one link per tunnel")},
			{codeName("SiteToSiteManager"), body("one entry per tunnel")},
		},
	})
	hd := accReconcile(f, l, "SiteToSiteReconcileHandler")
	mgr := l.stack[1]

	// What the manager drives hangs off its left side, a little narrower
	// than the column, so the path to the reporter runs down the free
	// strip on their right.
	const partW = 252.0
	busX := accLeftX - 15
	var parts []*node
	for i, lines := range [][]Line{
		{codeName("InterfaceKeyStore"), code("<data_dir>/site-to-site")},
		{codeName("RouteController,"), codeName("MeshSourceRewriter")},
		{codeName("TunnelProvider"), body("ipsec, openvpn")},
	} {
		n := f.box(roleAgent, spec{x: accLeftX, y: l.accRow(i + 2), w: partW, h: accRowH, lines: lines})
		f.arrow(relation, hvh(mgr.left(), n.left(), busX)...)
		parts = append(parts, n)
	}

	// The reconcile handler hands the block to the manager through the
	// gap between the two columns, as in the user access figure. The pull
	// handler runs on every successful pull and enters the manager lower,
	// on a path left of the first, so the two never cross.
	applyX := (accLeftX + accLeftW + accRightX) / 2
	f.arrow(flow, hvh(hd.left(), mgr.right(), applyX)...)
	f.label(pt{(accLeftX + accLeftW + applyX) / 2, mgr.cy()}, code("Apply()"))
	pull := f.box(roleAgent, spec{x: accRightX, y: l.accRow(3) + 20, w: accRightW, h: accRowH, lines: []Line{
		codeName("SiteToSitePullHandler"), body("secret inventory, retry"),
	}})
	rec := pt{accRightX + accRightW, l.accRow(1) + accRowH/2}
	f.arrow(flow, hvh(rec, pull.right(), accRightX+accRightW+15)...)
	f.arrow(flow, hvh(pull.left(), mgr.rightAt(mgr.cy()+20), applyX-40)...)

	// The manager's entries reach the reporter down the strip right of
	// the parts it drives.
	rep := f.box(roleAgent, spec{x: accRightX, y: l.accRow(4) + 20, w: accRightW, h: accRowH, lines: []Line{
		codeName("SiteToSiteStatusReporter"),
	}})
	stripX := accLeftX + partW + 10
	f.arrow(flow, vh(mgr.bottomAt(stripX), rep.left())...)

	// The reporter sends to the control plane box accReconcile drew in
	// the outside column.
	cpBottom := pt{accOutX + accOutW/2, l.accRow(0) + accRowH}
	f.arrow(call, hv(rep.right(), cpBottom)...)
	f.label(pt{(accRightX + accRightW + cpBottom.X) / 2, rep.cy()}, body("status report"))
	l.accClose(rep, parts[len(parts)-1])
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

// bridgeTunnelProvidersDataFlow draws the data flow of an ipsec or
// openvpn site-to-site tunnel for
// docs/reference/bridge/tunnel-providers.md (Data Flow): the manager
// creates the tunnel's link through the VPNController and hands the
// tunnel with its key to the provider, which writes the daemon's files
// and runs its commands through the CommandExecutor.
func bridgeTunnelProvidersDataFlow() *Figure {
	f := &Figure{Name: "bridge-tunnel-providers-data-flow", Title: "Data flow of a site-to-site tunnel through a tunnel provider"}
	l := accDataFlow(f, accSpec{
		source:    []Line{name("Remote site"), body("IKEv2 or OpenVPN peer")},
		transport: []Line{body("IPsec (IKEv2) or OpenVPN")},
		entry:     []Line{name("xfrm interface"), name("or tun device"), code("xf-s2s-a0a0a0e2"), code("ov-s2s-a0a0a0e3")},
		link:      s2sLinks,
		peers:     s2sPeers,
		stack: [][]Line{
			{codeName("VPNController"), body("xfrm interface, tun device")},
			{codeName("SiteToSiteManager"), body("one entry per tunnel")},
		},
	})
	mgr := l.stack[1]

	// The tunnel's key travels with the call into the provider.
	prov := f.box(roleAgent, spec{x: accRightX, y: mgr.y, w: accRightW, h: accRowH, lines: []Line{
		codeName("IPsecProvider"), codeName("OpenVPNProvider"),
	}})
	f.arrow(secretFlow, mgr.right(), prov.left())
	f.label(mid(mgr.right(), prov.left()), code("CreateTunnel()"), body("with the key"))

	exec := f.box(roleAgent, spec{x: accRightX, y: l.accRow(2), w: accRightW, h: accRowH, lines: []Line{
		codeName("CommandExecutor"), body("swanctl, openvpn"),
	}})
	f.arrow(flow, prov.bottom(), exec.top())
	daemons := f.box(roleExternal, spec{x: accRightX, y: l.accRow(3), w: accRightW, lines: []Line{
		name("strongSwan, OpenVPN"), body("the host's charon,"), body("one openvpn per tunnel"),
	}})
	f.arrow(flow, exec.bottom(), daemons.top())

	// The provider writes the daemon's files, the key among them, under
	// the run directory, left of the column, so the path leaves the
	// provider below the call that comes in.
	files := f.store(roleSecret, spec{x: accLeftX, y: l.accRow(2), w: accLeftW, lines: []Line{
		name("Tunnel files, 0600"), code("/var/run/plexd/swanctl"), code("/run/plexd/tunnels"),
	}})
	writeX := (accLeftX + accLeftW + accRightX) / 2
	f.arrow(secretFlow, hvh(prov.leftAt(prov.cy()+20), files.right(), writeX)...)
	l.accClose(daemons, files)
	return f
}
