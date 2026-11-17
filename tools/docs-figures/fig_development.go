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

// developmentSystemdTopology draws the four containers of the systemd
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
	plexd := f.box(roleAgent, spec{x: host.x + 30, y: host.y + 88, w: host.w - 60, lines: []Line{
		codeName("plexd.service"), body("managed by systemd"),
	}})
	host.h = plexd.y + plexd.h + 24 - host.y
	target := f.box(roleSubstrate, spec{x: host.x + host.w + 150, y: mock.y, w: 250, lines: []Line{
		name("ingress target"), code(":9441-9443 (TLS)"), code(":9022 (banner)"), body("openssl, nc"),
	}})
	mock.y = plexd.cy() - mock.h/2
	target.y = plexd.cy() - target.h/2

	f.arrow(call, plexd.left(), mock.rightAt(plexd.cy()))
	up, down := plexd.cy()-14, plexd.cy()+14
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

	net.w = target.x + target.w + 30
	net.h = pebble.y + pebble.h + 30
	return f
}
