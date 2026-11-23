//go:build linux

package meshdns

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/plexsphere/plexd/internal/nettest"
)

// realWait is how long the real test waits for a reply, both for one that
// has to come and for one that must not.
const realWait = 2 * time.Second

// realQueryName is the name every query of the real test asks for. The
// server holds no records, so it answers each query it accepts with REFUSED.
const realQueryName = "plexd-realtest.example."

// realListenUDP opens a UDP socket on addr inside n. The test's cleanup
// closes it.
func realListenUDP(t *testing.T, n *nettest.Netns, addr netip.AddrPort) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	if err := n.Do(func() error {
		var err error
		conn, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
		return err
	}); err != nil {
		t.Fatalf("namespace %s: listen udp %s: %v", n.Name, addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// realReceive returns the first datagram conn receives within realWait, or
// nil when none arrives.
func realReceive(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(realWait)); err != nil {
		t.Fatalf("SetReadDeadline() = %v, want nil", err)
	}
	buf := make([]byte, maxMessageSize)
	n, err := conn.Read(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil
	}
	if err != nil {
		t.Fatalf("read on %s: %v", conn.LocalAddr(), err)
	}
	return buf[:n]
}

// realForge sends pkt, an IPv4 packet with a header of its own, from a raw
// socket inside n to dst. IPPROTO_RAW implies IP_HDRINCL, so the kernel keeps
// the source address pkt names.
func realForge(t *testing.T, n *nettest.Netns, dst netip.Addr, pkt []byte) {
	t.Helper()
	if err := n.Do(func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			return fmt.Errorf("open a raw socket: %w", err)
		}
		defer func() { _ = unix.Close(fd) }()
		return unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Addr: dst.As4()})
	}); err != nil {
		t.Fatalf("namespace %s: send a forged datagram to %s: %v", n.Name, dst, err)
	}
}

// TestServer_RealAnswersNoOtherNetwork proves on a real kernel that the mesh
// DNS resolver answers no query that reaches the node's mesh IP over another
// network, although its sockets are bound to the mesh IP alone and not to
// the mesh interface. It runs the real Server in the namespaces
// nettest.NewMeshLAN builds: the node N holds the mesh IP 10.98.0.1 on
// nt-mesh and 192.0.2.1 on nt-lan, a veth to a host L on another network. L
// holds 192.0.2.2 and, on its loopback, the mesh address 10.98.0.3, and it
// routes the mesh IP through N. So what L sends to the resolver arrives on
// nt-lan. The server holds no records and answers every query it accepts
// with REFUSED, so any reply shows that a query got through.
//
// A query that N sends from its own mesh IP gets a reply. The source rule
// drops L's own address and every mesh source but the node's: a UDP query
// from either source gets no reply, and a TCP connection from either ends
// without a byte. While accept_local and route_localnet are 0 in N, and
// rp_filter is 0 too, the kernel drops as a martian a datagram that L forges
// with the node's mesh IP or 127.0.0.1 as its source, so neither reaches the
// resolver. The controls come last: with accept_local=1 the datagram forged
// with the node's mesh IP reaches the resolver, and the answer goes to the
// node itself. With route_localnet=1 as well, the datagram forged with
// 127.0.0.1 does the same. The test sets those sysctls itself, so a later
// change to the source rule fails here, and so does a kernel that treats
// these sources differently while accept_local and route_localnet are 0. It
// cannot see a node that sets accept_local=1.
func TestServer_RealAnswersNoOtherNetwork(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to run against real network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}

	lan := nettest.NewMeshLAN(t)
	// A new namespace may inherit other values from the host, so the test
	// sets each knob the kernel's source checks read on nt-lan.
	for _, key := range []string{
		"conf.all.rp_filter",
		"conf." + nettest.LANLink + ".rp_filter",
		"conf.all.accept_local",
		"conf." + nettest.LANLink + ".accept_local",
		"conf.all.route_localnet",
		"conf." + nettest.LANLink + ".route_localnet",
	} {
		lan.Node.Sysctl(t, key, "0")
	}

	meshIP := netip.MustParseAddr(nettest.NodeMeshIP)

	// The node holds a socket on each source address L forges. A reply to a
	// forged query goes to the forged source, so it would arrive at the
	// socket on that address. The test opens them first, so no socket that
	// binds the mesh IP on port 0 later gets port 40000 from the kernel.
	forgedMesh := netip.AddrPortFrom(meshIP, 40000)
	forgedLoopback := netip.MustParseAddrPort("127.0.0.1:40000")
	sockets := map[netip.AddrPort]*net.UDPConn{
		forgedMesh:     realListenUDP(t, lan.Node, forgedMesh),
		forgedLoopback: realListenUDP(t, lan.Node, forgedLoopback),
	}

	s := NewServer(netip.AddrPortFrom(meshIP, 0), slog.New(slog.DiscardHandler))
	if err := lan.Node.Do(s.Listen); err != nil {
		t.Fatalf("Listen() in namespace %s = %v, want nil", lan.Node.Name, err)
	}
	t.Cleanup(serve(t, s))
	server := s.Addr()

	// The node itself reaches the resolver from its mesh IP.
	node := realListenUDP(t, lan.Node, netip.AddrPortFrom(meshIP, 0))
	if _, err := node.WriteToUDPAddrPort(newQuery(t, 1, realQueryName, dnsmessage.TypeA), server); err != nil {
		t.Fatalf("send the node's query to %s: %v", server, err)
	}
	got := realReceive(t, node)
	if got == nil {
		t.Fatalf("the node's query from %s got no reply within %v, want REFUSED: the silences below would prove nothing", node.LocalAddr(), realWait)
	}
	if m := parseResponse(t, got); m.ID != 1 || m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("the node's query got ID %d, RCode %v, want ID 1, RCode %v", m.ID, m.RCode, dnsmessage.RCodeRefused)
	}

	// L's own address and a mesh source other than the node's get nothing,
	// over UDP and over TCP.
	for i, src := range []netip.Addr{
		netip.MustParseAddr(nettest.LANHostIP),
		netip.MustParseAddr(nettest.LANMeshSource),
	} {
		id := uint16(2 + i)
		conn := realListenUDP(t, lan.LANHost, netip.AddrPortFrom(src, 0))
		if _, err := conn.WriteToUDPAddrPort(newQuery(t, id, realQueryName, dnsmessage.TypeA), server); err != nil {
			t.Fatalf("send L's query from %s to %s: %v", src, server, err)
		}
		if got := realReceive(t, conn); got != nil {
			t.Errorf("L's UDP query from %s through %s got %x, want no reply within %v: the source rule drops it", src, nettest.LANLink, got, realWait)
		}

		// The server closes a connection from a source it does not answer
		// as soon as it accepts it. The client writes nothing first, because
		// a close with unread data in it would reset the connection.
		var tcp net.Conn
		if err := lan.LANHost.Do(func() error {
			d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: src.AsSlice()}}
			var err error
			tcp, err = d.Dial("tcp", server.String())
			return err
		}); err != nil {
			t.Fatalf("L's TCP dial from %s to %s = %v, want a connection: the listener is not bound to an interface", src, server, err)
		}
		t.Cleanup(func() { _ = tcp.Close() })
		waitClosed(t, tcp)
	}

	// L forges a datagram from each address the node holds a socket on.
	for i, src := range []netip.AddrPort{forgedMesh, forgedLoopback} {
		id := uint16(4 + i)
		realForge(t, lan.LANHost, meshIP, nettest.UDPDatagram(src, server, newQuery(t, id, realQueryName, dnsmessage.TypeA)))
		if got := realReceive(t, sockets[src]); got != nil {
			t.Errorf("a datagram L forged from %s through %s drew %x at the node's socket on %s, want nothing within %v: the kernel drops a local or loopback source that arrives on %s while accept_local and route_localnet are 0", src, nettest.LANLink, got, src, realWait, nettest.LANLink)
		}
	}

	// Control: with accept_local=1 the kernel no longer drops the node's
	// own mesh IP as a source that arrives on nt-lan, and the resolver
	// answers the node itself.
	lan.Node.Sysctl(t, "conf.all.accept_local", "1")
	lan.Node.Sysctl(t, "conf."+nettest.LANLink+".accept_local", "1")
	realForge(t, lan.LANHost, meshIP, nettest.UDPDatagram(forgedMesh, server, newQuery(t, 6, realQueryName, dnsmessage.TypeA)))
	got = realReceive(t, sockets[forgedMesh])
	if got == nil {
		t.Fatalf("with accept_local=1 a datagram L forged from %s drew no reply at the node's socket within %v, want REFUSED: the control shows nothing, so the silences above prove nothing", forgedMesh, realWait)
	}
	if m := parseResponse(t, got); m.ID != 6 || m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("with accept_local=1 the forged query got ID %d, RCode %v, want ID 6, RCode %v", m.ID, m.RCode, dnsmessage.RCodeRefused)
	}

	// Control: with route_localnet=1 as well the kernel no longer drops
	// 127.0.0.1 as a source that arrives on nt-lan, and the resolver, which
	// admits a loopback source, answers the node itself.
	lan.Node.Sysctl(t, "conf.all.route_localnet", "1")
	lan.Node.Sysctl(t, "conf."+nettest.LANLink+".route_localnet", "1")
	realForge(t, lan.LANHost, meshIP, nettest.UDPDatagram(forgedLoopback, server, newQuery(t, 7, realQueryName, dnsmessage.TypeA)))
	got = realReceive(t, sockets[forgedLoopback])
	if got == nil {
		t.Fatalf("with accept_local=1 and route_localnet=1 a datagram L forged from %s drew no reply at the node's socket within %v, want REFUSED: the control shows nothing, so the silences above prove nothing", forgedLoopback, realWait)
	}
	if m := parseResponse(t, got); m.ID != 7 || m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("with accept_local=1 and route_localnet=1 the forged query got ID %d, RCode %v, want ID 7, RCode %v", m.ID, m.RCode, dnsmessage.RCodeRefused)
	}
}
