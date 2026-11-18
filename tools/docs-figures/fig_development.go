package main

// developmentFigures are the development- figures of the development reference pages.
var developmentFigures = []func() *Figure{
	developmentDockerTopology,
	developmentKubernetesTopology,
	developmentSystemdTopology,
}

// devSameHeight gives every box the height of the highest of them, so
// a row of boxes lines up top and bottom.
func devSameHeight(ns ...*node) {
	h := 0.0
	for _, n := range ns {
		h = max(h, n.h)
	}
	for _, n := range ns {
		n.h = h
	}
}

// developmentDockerTopology draws the three compose services of the
// Docker end-to-end test on their network, for
// docs/reference/development/docker-e2e-test.md (Service Topology).
func developmentDockerTopology() *Figure {
	f := &Figure{Name: "development-docker-topology", Title: "Services of the Docker end-to-end test"}
	net := f.frame(roleNeutral, 0, 0, 0, 0, "", "e2e-net", "Docker bridge network")
	const y, w, gap = 70.0, 260.0, 110.0
	mock := f.box(roleCore, spec{x: 30, y: y, w: w, lines: []Line{
		name("mock-api"), code(":8080 (HTTP)"), code(":8443 (TLS)"), code("/v1/health"),
	}})
	plexd := f.box(roleAgent, spec{x: mock.x + w + gap, y: y, w: w, lines: []Line{
		name("plexd"), body("the agent"), code("depends_on: mock-api"),
	}})
	peer := f.box(roleSubstrate, spec{x: plexd.x + w + gap, y: y, w: w, lines: []Line{
		name("meshpeer"), code("wg0"), code("10.99.0.3"),
	}})
	devSameHeight(mock, plexd, peer)
	f.arrow(call, plexd.left(), mock.right())
	f.arrow(both, plexd.right(), peer.left())
	f.label(mid(plexd.right(), peer.left()), body("WireGuard"))
	f.labelUnder(mid(plexd.right(), peer.left()), code(":51820"))
	net.w = peer.x + peer.w + 30
	net.h = peer.y + peer.h + 30
	return f
}

// developmentKubernetesTopology draws the kind cluster of the
// Kubernetes end-to-end test and the port-forward the test script
// polls through, for docs/reference/development/kubernetes-e2e-test.md
// (Cluster Topology).
func developmentKubernetesTopology() *Figure {
	f := &Figure{Name: "development-kubernetes-topology", Title: "The kind cluster of the Kubernetes end-to-end test"}
	cluster := f.frame(roleSubstrate, 0, 0, 0, 0, "", "kind cluster", "plexd-e2e")
	const y, w = 70.0, 340.0
	mock := f.box(roleCore, spec{x: 40, y: y, w: w, lines: []Line{
		name("mock-api"), body("Deployment"), code(":8080 (HTTP)"), code(":8443 (TLS)"),
	}})
	plexd := f.box(roleAgent, spec{x: mock.x + w + 280, y: y, w: w, lines: []Line{
		name("plexd DaemonSet"), body("host network"), body("1 pod per node"),
	}})
	devSameHeight(mock, plexd)
	f.arrow(call, plexd.left(), mock.right())
	svc := f.box(roleCore, spec{x: mock.x, y: mock.y + mock.h + 50, w: w, lines: []Line{
		name("ClusterIP Service"), code("mock-api.plexd-e2e:8080, :8443"),
	}})
	f.arrow(relation, mock.bottom(), svc.top())
	cluster.w = plexd.x + plexd.w + 40
	cluster.h = svc.y + svc.h + 30

	poll := f.actor(spec{x: mock.x, y: cluster.y + cluster.h + 110, w: w, lines: []Line{
		name("test script"), code("localhost:18080/test/assertions"),
	}})
	f.arrow(flow, svc.bottom(), poll.top())
	f.labelRight(pt{svc.cx(), (cluster.y + cluster.h + poll.y) / 2}, body("port-forward :18080"))
	return f
}

// developmentSystemdTopology draws the seven containers of the systemd
// end-to-end test on their network, for
// docs/reference/development/systemd-e2e-test.md (Container Topology).
func developmentSystemdTopology() *Figure {
	f := &Figure{Name: "development-systemd-topology", Title: "Containers of the systemd end-to-end test"}
	net := f.frame(roleNeutral, 0, 0, 0, 0, "", "plexd-systemd-e2e", "Docker network")
	const y = 70.0
	mock := f.box(roleCore, spec{x: 30, y: y + 30, w: 200, lines: []Line{
		name("mock-api"), code(":8080 (HTTP)"), code(":8443 (TLS)"), code("/v1/health"),
	}})
	host := f.frame(roleSubstrate, 330, y, 330, 0, "", "systemd container", "")
	f.text(host.x+16, host.y+48, "left", body("Ubuntu 24.04, systemd PID 1"))
	// plexd.service is tall enough that the WireGuard tunnels of the
	// user access phase leave it below the calls of the other phases.
	plexd := f.box(roleAgent, spec{x: host.x + 30, y: host.y + 88, w: host.w - 60, h: 108, lines: []Line{
		codeName("plexd.service"), body("managed by systemd"),
	}})
	host.h = plexd.y + plexd.h + 24 - host.y
	target := f.box(roleSubstrate, spec{x: host.x + host.w + 150, y: mock.y, w: 250, lines: []Line{
		name("ingress target"), code(":9441-9443 (TLS)"), code(":9022 (banner)"), body("openssl, nc"),
	}})
	top := plexd.cy() - 20
	mock.y = top - mock.h/2
	target.y = top - target.h/2

	f.arrow(call, plexd.leftAt(top), mock.rightAt(top))
	up, down := top-14, top+14
	f.arrow(call, plexd.rightAt(up), target.leftAt(up))
	f.label(pt{(host.x + host.w + target.x) / 2, up}, body("rule targets"))
	f.arrow(call, target.leftAt(down), plexd.rightAt(down))
	f.labelUnder(pt{(host.x + host.w + target.x) / 2, down}, body("probes"))

	pebble := f.box(roleExternal, spec{x: host.x + 20, y: host.y + host.h + 120, w: host.w - 40, lines: []Line{
		name("pebble"), code(":14000 (ACME, HTTPS)"), body("Let's Encrypt test CA"),
	}})
	acme, alpn := plexd.cx()-70, plexd.cx()+70
	f.arrow(call, plexd.bottomAt(acme), pebble.topAt(acme))
	f.labelLeft(pt{acme, (plexd.y + plexd.h + pebble.y) / 2}, body("ACME"))
	f.arrow(call, pebble.topAt(alpn), plexd.bottomAt(alpn))
	f.labelRight(pt{alpn, (plexd.y + plexd.h + pebble.y) / 2}, body("TLS-ALPN-01 on :443"))

	// The user access phase: the device reaches the mesh node through
	// a wireguard provider of the bridge, and the mesh node is the
	// fixture's peer ...a0b2 on plexd0. Both tunnels leave plexd.service
	// on one row and turn down the gaps beside the systemd container.
	device := f.actor(spec{x: mock.x, y: pebble.y, w: mock.w, lines: []Line{
		name("device"), code("wg0 10.77.0.2"), body("nc probe"),
	}})
	meshNode := f.box(roleSubstrate, spec{x: target.x, y: pebble.y, w: target.w, lines: []Line{
		name("mesh node"), code("wg0 10.99.0.3"), code(":7101 (nc -l)"),
	}})
	wg := plexd.y + plexd.h - 14
	left, right := (mock.x+mock.w+host.x)/2, target.x-25
	f.arrow(both, plexd.leftAt(wg), pt{left, wg}, pt{left, device.cy()}, device.right())
	f.labelLeft(pt{left, (wg + device.cy()) / 2}, body("WireGuard"), code(":51900 (wg-ua-…)"))
	f.arrow(both, plexd.rightAt(wg), pt{right, wg}, pt{right, meshNode.cy()}, meshNode.left())
	f.labelRight(pt{right, (wg + meshNode.cy()) / 2}, body("WireGuard"), code("plexd0 :51820"))

	// The site-to-site phase: the site is the remote end of a wireguard
	// tunnel of the bridge. Its tunnel leaves plexd.service below the
	// mesh node's and turns down a lane inside the mesh node's, so the
	// two never cross.
	site := f.box(roleExternal, spec{x: target.x, y: meshNode.y + meshNode.h + 50, w: target.w, lines: []Line{
		name("site"), code("wg0 10.40.0.1/16"), code(":7201 (nc -l)"),
	}})
	s2s, inner := wg+8, right-24
	f.arrow(both, plexd.rightAt(s2s), pt{inner, s2s}, pt{inner, site.cy()}, site.left())
	f.labelLeft(pt{inner, (meshNode.y + meshNode.h + site.cy()) / 2}, body("WireGuard"), code(":51930 (wg-s2s-…)"))

	net.w = target.x + target.w + 30
	net.h = max(pebble.y+pebble.h, device.y+device.h, site.y+site.h) + 30
	return f
}
