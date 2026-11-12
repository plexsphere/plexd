//go:build linux

package policy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// inTestNetns runs fn on the test's own goroutine, locked to its thread and
// that thread moved into a fresh network namespace, so whatever fn does to
// nftables lands in that namespace and goes with it rather than into the
// host's ruleset, which may hold a live plexd's tables. Running fn on the test
// goroutine keeps t.Fatal and t.Skip inside fn legal; the namespace is left
// in a deferred call, which runs on that path too. Goroutines fn starts run on
// other threads and so in the original namespace.
//
// A process that may not create a namespace, an unprivileged one, runs fn in
// place: without CAP_NET_ADMIN every nftables call fails with the permission
// error the unprivileged assertions expect. A process that holds
// CAP_NET_ADMIN but may not create a namespace would change the host's
// ruleset in place, so the test is skipped there.
func inTestNetns(t *testing.T, fn func()) {
	t.Helper()

	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("open this thread's network namespace: %v", err)
	}
	// unshare(2) rather than netns.New, which also opens the new namespace:
	// nothing needs a handle to it, and a failed open would leave the thread
	// inside it with no way to tell.
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		// The thread is still where it was.
		_ = orig.Close()
		runtime.UnlockOSThread()
		admin, capErr := holdsNetAdmin()
		if capErr != nil {
			t.Fatalf("read this thread's capabilities: %v", capErr)
		}
		if admin {
			t.Skipf("cannot create a network namespace (%v) but holds CAP_NET_ADMIN: the test would change this host's nftables ruleset", err)
		}
		fn()
		return
	}
	defer func() {
		err := netns.Set(orig)
		_ = orig.Close()
		if err != nil {
			// The goroutine stays locked, and the runtime ends a thread whose
			// goroutine exits locked, so nothing else runs in the namespace.
			t.Errorf("return to the original network namespace: %v", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	fn()
}

// holdsNetAdmin reports whether the calling thread has CAP_NET_ADMIN in its
// effective set.
func holdsNetAdmin() (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, err
	}
	return data[0].Effective&(1<<unix.CAP_NET_ADMIN) != 0, nil
}

// onLockedThread runs fn on a new goroutine locked to its own thread and waits
// for its result. The goroutine never unlocks: the runtime ends the thread
// with it, so a thread fn moved into another namespace runs nothing else.
func onLockedThread(fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		errc <- fn()
	}()
	return <-errc
}

// realNetns is a network namespace TestNftablesController_Real created. It
// goes away with its last handle, link end and socket.
type realNetns struct {
	name string
	ns   netns.NsHandle
	nl   *netlink.Handle
}

// newRealNetns creates a network namespace on a thread of its own, so no
// thread of the test runs in it afterwards, and a netlink handle bound to it.
func newRealNetns(t *testing.T, name string) *realNetns {
	t.Helper()

	n := &realNetns{name: name}
	if err := onLockedThread(func() error {
		var err error
		n.ns, err = netns.New()
		return err
	}); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	t.Cleanup(func() { _ = n.ns.Close() })

	// Links, addresses, routes and neighbours are all rtnetlink; asking for
	// the handle's other default families would need their modules too.
	h, err := netlink.NewHandleAt(n.ns, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("open a netlink handle in namespace %s: %v", name, err)
	}
	n.nl = h
	t.Cleanup(h.Close)
	return n
}

// do runs fn on a thread inside the namespace: the sockets fn opens, netlink
// ones included, belong to it.
func (n *realNetns) do(fn func() error) error {
	return onLockedThread(func() error {
		if err := netns.Set(n.ns); err != nil {
			return fmt.Errorf("enter namespace %s: %w", n.name, err)
		}
		return fn()
	})
}

func (n *realNetns) link(t *testing.T, name string) netlink.Link {
	t.Helper()
	link, err := n.nl.LinkByName(name)
	if err != nil {
		t.Fatalf("namespace %s: link %s: %v", n.name, name, err)
	}
	return link
}

func (n *realNetns) up(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := n.nl.LinkSetUp(n.link(t, name)); err != nil {
			t.Fatalf("namespace %s: set %s up: %v", n.name, name, err)
		}
	}
}

func (n *realNetns) addAddr(t *testing.T, name, cidr string) {
	t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	if addr.IP.To4() == nil {
		// Duplicate address detection would hold the address back for a
		// second or more, and nothing else on the link claims it.
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := n.nl.AddrAdd(n.link(t, name), addr); err != nil {
		t.Fatalf("namespace %s: add %s to %s: %v", n.name, cidr, name, err)
	}
}

func (n *realNetns) addRoute(t *testing.T, name, dst, gw string) {
	t.Helper()
	route := &netlink.Route{
		LinkIndex: n.link(t, name).Attrs().Index,
		Gw:        net.ParseIP(gw),
	}
	if dst != "" {
		_, ipNet, err := net.ParseCIDR(dst)
		if err != nil {
			t.Fatalf("parse %s: %v", dst, err)
		}
		route.Dst = ipNet
	}
	if err := n.nl.RouteAdd(route); err != nil {
		t.Fatalf("namespace %s: route %q via %s: %v", n.name, dst, gw, err)
	}
}

// addNeighbor enters a permanent IPv6 neighbour, so the address is reached
// without neighbour discovery.
func (n *realNetns) addNeighbor(t *testing.T, name, ip string, mac net.HardwareAddr) {
	t.Helper()
	if err := n.nl.NeighSet(&netlink.Neigh{
		LinkIndex:    n.link(t, name).Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP(ip),
		HardwareAddr: mac,
	}); err != nil {
		t.Fatalf("namespace %s: neighbour %s on %s: %v", n.name, ip, name, err)
	}
}

// realListener accepts TCP connections in a namespace and hands them over.
type realListener struct {
	ln    net.Listener
	conns chan net.Conn
}

// listen opens a TCP listener inside the namespace. It accepts until the
// test ends.
func (n *realNetns) listen(t *testing.T, addr string) *realListener {
	t.Helper()

	var ln net.Listener
	if err := n.do(func() error {
		var err error
		ln, err = net.Listen("tcp", addr)
		return err
	}); err != nil {
		t.Fatalf("namespace %s: listen on %s: %v", n.name, addr, err)
	}

	l := &realListener{ln: ln, conns: make(chan net.Conn, 16)}
	go func() {
		defer close(l.conns)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.conns <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for c := range l.conns {
			_ = c.Close()
		}
	})
	return l
}

// accepted returns the connection l accepted from client.
func (l *realListener) accepted(t *testing.T, client net.Conn) net.Conn {
	t.Helper()

	want := client.LocalAddr().(*net.TCPAddr)
	timeout := time.After(5 * time.Second)
	for {
		select {
		case c, ok := <-l.conns:
			if !ok {
				t.Fatalf("listener %s closed before it accepted %s", l.ln.Addr(), want)
			}
			if got := c.RemoteAddr().(*net.TCPAddr); got.IP.Equal(want.IP) && got.Port == want.Port {
				t.Cleanup(func() { _ = c.Close() })
				return c
			}
			_ = c.Close()
		case <-timeout:
			t.Fatalf("listener %s did not accept %s within 5 s", l.ln.Addr(), want)
		}
	}
}

// dial opens a TCP connection from inside the namespace.
func (n *realNetns) dial(addr string, timeout time.Duration) (net.Conn, error) {
	var c net.Conn
	err := n.do(func() error {
		var err error
		c, err = net.DialTimeout("tcp", addr, timeout)
		return err
	})
	return c, err
}

// connects reports whether a connection from the namespace to addr comes up.
func (n *realNetns) connects(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := n.dial(addr, 5*time.Second)
	if err != nil {
		t.Errorf("%s could not connect to %s: %v", n.name, addr, err)
		return nil
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// timesOut checks that a connection from the namespace to addr, where a
// listener runs, times out: its SYN was dropped rather than refused.
func (n *realNetns) timesOut(t *testing.T, addr string) {
	t.Helper()
	c, err := n.dial(addr, 2*time.Second)
	if err == nil {
		_ = c.Close()
		t.Errorf("%s connected to %s, want the connection attempt dropped", n.name, addr)
		return
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("%s dialing %s: %v, want a timeout", n.name, addr, err)
	}
}

// blocked checks that a connection from the namespace to addr, where a
// listener runs, never comes up. A SYN the peer drops times the connection
// out. A SYN the namespace's own output chain drops times it out too, or
// fails it with EPERM. A refused connection means the SYN reached the peer,
// so it fails the check.
func (n *realNetns) blocked(t *testing.T, addr string) {
	t.Helper()
	c, err := n.dial(addr, 2*time.Second)
	if err == nil {
		_ = c.Close()
		t.Errorf("%s connected to %s, want the connection attempt dropped", n.name, addr)
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("%s dialing %s: %v, want a timeout or EPERM", n.name, addr, err)
	}
}

// listenUDP binds a UDP socket inside the namespace. It closes when the test
// ends.
func (n *realNetns) listenUDP(t *testing.T, addr string) net.PacketConn {
	t.Helper()

	var pc net.PacketConn
	if err := n.do(func() error {
		var err error
		pc, err = net.ListenPacket("udp", addr)
		return err
	}); err != nil {
		t.Fatalf("namespace %s: listen on udp %s: %v", n.name, addr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// TestNftablesController_Real drives the kernel's nf_tables and connection
// tracking. It builds three network namespaces: a peer P whose eth0 is joined
// to the node N's plexd0 by a veth pair, as a mesh peer is joined over
// WireGuard, and an external host E behind N's lan0. Every link is created
// inside those namespaces through netlink handles bound to them, never in the
// host's namespace, which may run a live plexd0, and the controller runs on
// a thread inside N.
//
// N's chains filter what arrives on plexd0, delivered to N or forwarded
// through it, and what N's own sockets send over plexd0. What N forwards out
// of plexd0, from E, is not filtered on its way out.
func TestNftablesController_Real(t *testing.T) {
	// The gate is a variable rather than the effective uid alone, as for
	// TestPFController_Real: sudo go test ./... on a developer's machine
	// should not create namespaces and load rules unasked.
	if os.Getenv("PLEXD_TEST_REAL_NFTABLES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_NFTABLES=1 to load real nftables rules in test network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating network namespaces and loading nftables rules needs root; run with sudo")
	}

	p := newRealNetns(t, "P")
	n := newRealNetns(t, "N")
	e := newRealNetns(t, "E")

	// P eth0 <-> N plexd0, and N lan0 <-> E eth0. Each veth is created in N
	// with its peer end placed straight into the other namespace.
	for _, pair := range []struct {
		name, peerName string
		peer           *realNetns
	}{
		{"plexd0", "eth0", p},
		{"lan0", "eth0", e},
	} {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = pair.name
		veth := netlink.NewVeth(attrs)
		veth.PeerName = pair.peerName
		veth.PeerNamespace = netlink.NsFd(pair.peer.ns)
		if err := n.nl.LinkAdd(veth); err != nil {
			t.Fatalf("namespace N: add veth %s with peer %s in %s: %v", pair.name, pair.peerName, pair.peer.name, err)
		}
	}

	p.up(t, "lo", "eth0")
	n.up(t, "lo", "plexd0", "lan0")
	e.up(t, "lo", "eth0")

	p.addAddr(t, "eth0", "10.99.0.2/24")
	p.addAddr(t, "eth0", "fd00:99::2/64")
	n.addAddr(t, "plexd0", "10.99.0.1/24")
	n.addAddr(t, "plexd0", "fd00:99::1/64")
	n.addAddr(t, "lan0", "192.0.2.1/24")
	e.addAddr(t, "eth0", "192.0.2.2/24")

	p.addRoute(t, "eth0", "192.0.2.0/24", "10.99.0.1")
	e.addRoute(t, "eth0", "", "192.0.2.1")

	// plexd0 is a WireGuard device in production and needs no neighbour
	// discovery. The veth standing in for it does, and N's default deny would
	// drop P's neighbour solicitations and advertisements at the input hook,
	// since the kernel leaves them untracked, so both ends know each other's
	// IPv6 neighbour up front. ARP is not IP and passes the inet table.
	p.addNeighbor(t, "eth0", "fd00:99::1", n.link(t, "plexd0").Attrs().HardwareAddr)
	n.addNeighbor(t, "plexd0", "fd00:99::2", p.link(t, "eth0").Attrs().HardwareAddr)

	if err := n.do(func() error {
		return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	}); err != nil {
		t.Fatalf("namespace N: enable IPv4 forwarding: %v", err)
	}

	n7001 := n.listen(t, ":7001")
	n.listen(t, ":7002")
	e.listen(t, "192.0.2.2:8001")
	e.listen(t, "192.0.2.2:8002")
	p9001 := p.listen(t, "10.99.0.2:9001")
	p.listen(t, "10.99.0.2:9002")
	p.listen(t, "10.99.0.2:9003")
	pUDP9 := p.listenUDP(t, "10.99.0.2:9")
	pUDP10 := p.listenUDP(t, "10.99.0.2:10")

	const chain = DefaultChainName

	// A plexd before the inet table leaves table ip plexd behind when it
	// crashes, its forward chain ending in a drop of everything from plexd0.
	if err := n.do(func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: tableName})
		legacy := conn.AddChain(&nftables.Chain{
			Name:     chain,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		})
		exprs := ifaceMatchExprs("plexd0", dirIn)
		exprs = append(exprs, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
		conn.AddRule(&nftables.Rule{Table: table, Chain: legacy, Exprs: exprs})
		return conn.Flush()
	}); err != nil {
		t.Fatalf("namespace N: create the legacy table ip plexd: %v", err)
	}
	t.Log("the legacy table ip plexd drops what P forwards through N")
	p.timesOut(t, "192.0.2.2:8001")

	ctrl := NewNftablesController(testLogger())
	if err := n.do(ctrl.Probe); err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}
	if err := n.do(func() error { return ctrl.EnsureChain(chain) }); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}

	t.Log("EnsureChain replaced table ip plexd with table inet plexd and its three chains")
	var ipTables []*nftables.Table
	var inetChains []*nftables.Chain
	if err := n.do(func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		if ipTables, err = conn.ListTablesOfFamily(nftables.TableFamilyIPv4); err != nil {
			return err
		}
		inetChains, err = conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
		return err
	}); err != nil {
		t.Fatalf("namespace N: list tables and chains: %v", err)
	}
	for _, table := range ipTables {
		if table.Name == tableName {
			t.Errorf("table ip %s is still there after EnsureChain", tableName)
		}
	}
	hooks := make(map[string]nftables.ChainHook)
	for _, ch := range inetChains {
		if ch.Table.Name == tableName && ch.Hooknum != nil {
			hooks[ch.Name] = *ch.Hooknum
		}
	}
	inputName, forwardName, outputName := chainNames(chain)
	if hook, ok := hooks[inputName]; !ok || hook != *nftables.ChainHookInput {
		t.Errorf("chain inet %s %s: hook %v, present %v; want the input hook", tableName, inputName, hook, ok)
	}
	if hook, ok := hooks[forwardName]; !ok || hook != *nftables.ChainHookForward {
		t.Errorf("chain inet %s %s: hook %v, present %v; want the forward hook", tableName, forwardName, hook, ok)
	}
	if hook, ok := hooks[outputName]; !ok || hook != *nftables.ChainHookOutput {
		t.Errorf("chain inet %s %s: hook %v, present %v; want the output hook", tableName, outputName, hook, ok)
	}

	// The ruleset the engine builds for these rules on plexd0: allows, then
	// the address-less default deny. allowOut9001 is N's own copy of a rule
	// from N to P, the one the control plane compiles for the source node.
	allow7001v4 := FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.0/24", DstIP: "10.99.0.1/32", Port: 7001, Protocol: "tcp", Action: "allow"}
	allow7001v6 := FirewallRule{Interface: "plexd0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::1/128", Port: 7001, Protocol: "tcp", Action: "allow"}
	allow8001 := FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.2/32", DstIP: "192.0.2.0/24", Port: 8001, Protocol: "tcp", Action: "allow"}
	allowOut9001 := FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.1/32", DstIP: "10.99.0.2/32", Port: 9001, Protocol: "tcp", Action: "allow"}
	deny := FirewallRule{Interface: "plexd0", Action: "deny"}
	apply := func(rules ...FirewallRule) {
		t.Helper()
		if err := n.do(func() error { return ctrl.ApplyRules(chain, rules) }); err != nil {
			t.Fatalf("ApplyRules() error = %v, want nil", err)
		}
	}
	apply(allow7001v4, allow7001v6, allow8001, allowOut9001, deny)

	t.Log("P reaches what the rules allow on N over both families, and nothing else; N's replies leave through the output chain")
	p.connects(t, "10.99.0.1:7001")
	p.connects(t, "[fd00:99::1]:7001")
	p.timesOut(t, "10.99.0.1:7002")
	p.timesOut(t, "[fd00:99::1]:7002")

	t.Log("P reaches what the rules allow on E through N, and nothing else")
	p.connects(t, "192.0.2.2:8001")
	p.timesOut(t, "192.0.2.2:8002")

	t.Log("N reaches what the rules allow on P, and nothing else")
	n.connects(t, "10.99.0.2:9001")
	n.blocked(t, "10.99.0.2:9003")

	t.Log("what E opens to P through N is not filtered on its way out of plexd0")
	e.connects(t, "10.99.0.2:9002")

	// Two kinds of traffic leave plexd0 from N with a source that is not
	// N's mesh address, and masquerade gives them that address only at
	// postrouting, after the output chain. kube-proxy DNATs a host-network
	// connection to a Service onto its endpoint at the output hook's nat
	// chain; N plays that with 10.96.0.10, routed via lan0, DNATed onto P's
	// 9003. IPVS sends a Pod's packet through the output hook with the Pod's
	// address as source; N plays that with a socket bound to its lan0
	// address 192.0.2.1 that connects to P's 9003 straight through plexd0.
	// No rule allows 9003, and both connections still come up.
	t.Log("connections that leave plexd0 with a foreign source and are masqueraded onto N's mesh address are not filtered")
	n.addRoute(t, "lan0", "10.96.0.0/12", "192.0.2.2")
	if err := n.do(func() error { return addServiceNAT("10.96.0.10", "10.99.0.2", 9003, "plexd0") }); err != nil {
		t.Fatalf("namespace N: add the service nat table: %v", err)
	}
	n.connects(t, "10.96.0.10:9003")
	var bound net.Conn
	if err := n.do(func() error {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, Timeout: 5 * time.Second}
		var err error
		bound, err = d.Dial("tcp", "10.99.0.2:9003")
		return err
	}); err != nil {
		t.Errorf("N could not connect from 192.0.2.1 to 10.99.0.2:9003 through plexd0: %v", err)
	} else {
		_ = bound.Close()
	}
	if err := n.do(func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		conn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: serviceNATTable})
		return conn.Flush()
	}); err != nil {
		t.Fatalf("namespace N: delete the service nat table: %v", err)
	}

	t.Log("N sends UDP to P's port 9, the relay probe's, without a rule, and nothing to port 10")
	sendUDP := func(addr string) error {
		return n.do(func() error {
			c, err := net.Dial("udp", addr)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			_, err = c.Write([]byte("u"))
			return err
		})
	}
	dgram := make([]byte, 16)
	if err := sendUDP("10.99.0.2:9"); err != nil {
		t.Errorf("N send to udp 10.99.0.2:9: %v", err)
	}
	if err := pUDP9.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if nr, from, err := pUDP9.ReadFrom(dgram); err != nil {
		t.Errorf("P read on udp port 9: %v, want N's datagram within 2 s", err)
	} else if string(dgram[:nr]) != "u" {
		t.Errorf("P read %q from %s on udp port 9, want \"u\"", dgram[:nr], from)
	}
	if err := sendUDP("10.99.0.2:10"); err != nil {
		t.Logf("N send to udp 10.99.0.2:10: %v", err)
	}
	if err := pUDP10.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if nr, from, err := pUDP10.ReadFrom(dgram); err == nil {
		t.Errorf("P read %q from %s on udp port 10, want nothing within 2 s", dgram[:nr], from)
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Errorf("P read on udp port 10: %v, want a timeout", err)
		}
	}

	t.Log("a revoked rule cuts an established connection at its next packet")
	client := p.connects(t, "10.99.0.1:7001")
	if client == nil {
		t.FailNow()
	}
	server := n7001.accepted(t, client)
	buf := make([]byte, 1)
	if _, err := client.Write([]byte("a")); err != nil {
		t.Fatalf("P write before the revoke: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(buf); err != nil || buf[0] != 'a' {
		t.Fatalf("N read before the revoke: %q, %v; want \"a\"", buf, err)
	}
	apply(allow8001, deny)
	if _, err := client.Write([]byte("b")); err != nil {
		t.Fatalf("P write after the revoke: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if nr, err := server.Read(buf); nr > 0 {
		t.Errorf("N read %q after the 7001 rule was revoked, want nothing within 2 s", buf[:nr])
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Errorf("N read after the revoke: %v, want a timeout", err)
		}
	}

	t.Log("a revoked rule cuts an established connection N opened at its next packet")
	apply(allow7001v4, allow7001v6, allow8001, allowOut9001, deny)
	out := n.connects(t, "10.99.0.2:9001")
	if out == nil {
		t.FailNow()
	}
	peer := p9001.accepted(t, out)
	if _, err := out.Write([]byte("a")); err != nil {
		t.Fatalf("N write before the revoke: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(buf); err != nil || buf[0] != 'a' {
		t.Fatalf("P read before the revoke: %q, %v; want \"a\"", buf, err)
	}
	apply(allow7001v4, allow7001v6, allow8001, deny)
	if _, err := out.Write([]byte("b")); err != nil {
		t.Logf("N write after the revoke: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if nr, err := peer.Read(buf); nr > 0 {
		t.Errorf("P read %q after the 9001 rule was revoked, want nothing within 2 s", buf[:nr])
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Errorf("P read after the revoke: %v, want a timeout", err)
		}
	}

	// Every rule add is echoed back on the batch's netlink socket, which the
	// default buffers cannot hold for a ruleset of a few dozen rules written
	// into three chains (applyBufferBytes).
	t.Log("a ruleset of 1000 policy rules applies in one batch and is enforced")
	large := make([]FirewallRule, 0, 1002)
	for i := range 1000 {
		large = append(large, FirewallRule{
			Interface: "plexd0", SrcIP: fmt.Sprintf("10.98.%d.%d/32", i/250, i%250+1), DstIP: "10.99.0.1/32",
			Port: 5432, Protocol: "tcp", Action: "allow",
		})
	}
	apply(append(large, allow7001v4, deny)...)
	p.connects(t, "10.99.0.1:7001")
	p.timesOut(t, "10.99.0.1:7002")

	t.Log("N reaches its own mesh address under the default deny alone")
	apply(deny)
	n.connects(t, "10.99.0.1:7002")

	t.Log("FlushChain empties all three chains: input, forward and output traffic pass again")
	if err := n.do(func() error { return ctrl.FlushChain(chain) }); err != nil {
		t.Fatalf("FlushChain() error = %v, want nil", err)
	}
	p.connects(t, "10.99.0.1:7002")
	p.connects(t, "192.0.2.2:8002")
	n.connects(t, "10.99.0.2:9003")

	t.Log("DeleteChain removes all three chains, and a second call is a no-op")
	apply(deny)
	p.timesOut(t, "192.0.2.2:8002")
	if err := n.do(func() error { return ctrl.DeleteChain(chain) }); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	if err := n.do(func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		inetChains, err = conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
		return err
	}); err != nil {
		t.Fatalf("namespace N: list chains: %v", err)
	}
	for _, ch := range inetChains {
		if ch.Table.Name == tableName && (ch.Name == inputName || ch.Name == forwardName || ch.Name == outputName) {
			t.Errorf("chain inet %s %s is still there after DeleteChain", tableName, ch.Name)
		}
	}
	p.connects(t, "10.99.0.1:7002")
	p.connects(t, "192.0.2.2:8002")
	n.connects(t, "10.99.0.2:9003")
	if err := n.do(func() error { return ctrl.DeleteChain(chain) }); err != nil {
		t.Errorf("second DeleteChain() error = %v, want nil", err)
	}

	// A plexd before the output chain left its input and forward chains
	// behind. Teardown flushes before it deletes, so FlushChain has to act on
	// the two that exist rather than fail on the missing third.
	t.Log("FlushChain and DeleteChain act on the chains that exist, and FlushChain of an unknown chain is a no-op")
	if err := n.do(func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: tableName})
		input, forward, _ := baseChains(table, chain)
		conn.AddChain(input)
		conn.AddChain(forward)
		return conn.Flush()
	}); err != nil {
		t.Fatalf("namespace N: create the input and forward chains alone: %v", err)
	}
	if err := n.do(func() error { return ctrl.FlushChain(chain) }); err != nil {
		t.Errorf("FlushChain() of the input and forward chains alone error = %v, want nil", err)
	}
	if err := n.do(func() error { return ctrl.DeleteChain(chain) }); err != nil {
		t.Errorf("DeleteChain() of the input and forward chains alone error = %v, want nil", err)
	}
	if err := n.do(func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		inetChains, err = conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
		return err
	}); err != nil {
		t.Fatalf("namespace N: list chains: %v", err)
	}
	for _, ch := range inetChains {
		if ch.Table.Name == tableName && (ch.Name == inputName || ch.Name == forwardName) {
			t.Errorf("chain inet %s %s is still there after DeleteChain", tableName, ch.Name)
		}
	}
	if err := n.do(func() error { return ctrl.FlushChain("plexd-test-unknown") }); err != nil {
		t.Errorf("FlushChain() of an unknown chain error = %v, want nil", err)
	}
}

// serviceNATTable is the IPv4 nat table addServiceNAT creates.
const serviceNATTable = "plexd-test-service-nat"

// addServiceNAT adds what kube-proxy and a masquerading CNI do for a
// host-network connection to a Service whose endpoint sits behind the mesh:
// at the output hook, before the filter chains, TCP to service:port is DNATed
// to endpoint:port, and at postrouting what leaves through meshIface is
// masqueraded onto that interface's address.
func addServiceNAT(service, endpoint string, port uint16, meshIface string) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: serviceNATTable})
	out := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})
	conn.AddRule(&nftables.Rule{Table: table, Chain: out, Exprs: []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.ParseIP(service).To4()},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes(port)},
		&expr.Immediate{Register: 1, Data: net.ParseIP(endpoint).To4()},
		&expr.Immediate{Register: 2, Data: portBytes(port)},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2},
	}})
	post := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	conn.AddRule(&nftables.Rule{Table: table, Chain: post, Exprs: append(ifaceMatchExprs(meshIface, dirOut), &expr.Masq{})})
	return conn.Flush()
}
