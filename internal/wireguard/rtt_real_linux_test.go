//go:build linux

package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// rttRealNetns is a network namespace TestRTTProbe_RealAnswersOnlyTheMeshInterface
// created. It goes away with its last handle, link end and socket.
type rttRealNetns struct {
	name string
	ns   netns.NsHandle
	nl   *netlink.Handle
}

// rttOnLockedThread runs fn on a new goroutine locked to its own thread and
// waits for its result. The goroutine never unlocks, so the runtime ends the
// thread with it and a thread fn moved into a namespace runs nothing else.
func rttOnLockedThread(fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		errc <- fn()
	}()
	return <-errc
}

func newRTTRealNetns(t *testing.T, name string) *rttRealNetns {
	t.Helper()
	n := &rttRealNetns{name: name}
	if err := rttOnLockedThread(func() error {
		var err error
		n.ns, err = netns.New()
		return err
	}); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	t.Cleanup(func() { _ = n.ns.Close() })
	h, err := netlink.NewHandleAt(n.ns, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("open a netlink handle in namespace %s: %v", name, err)
	}
	n.nl = h
	t.Cleanup(h.Close)
	return n
}

// do runs fn on a thread inside the namespace, so the sockets fn opens belong
// to it.
func (n *rttRealNetns) do(fn func() error) error {
	return rttOnLockedThread(func() error {
		if err := netns.Set(n.ns); err != nil {
			return fmt.Errorf("enter namespace %s: %w", n.name, err)
		}
		return fn()
	})
}

func (n *rttRealNetns) link(t *testing.T, name string) netlink.Link {
	t.Helper()
	link, err := n.nl.LinkByName(name)
	if err != nil {
		t.Fatalf("namespace %s: link %s: %v", n.name, name, err)
	}
	return link
}

func (n *rttRealNetns) addr(t *testing.T, name, cidr string) {
	t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	link := n.link(t, name)
	if err := n.nl.AddrAdd(link, addr); err != nil {
		t.Fatalf("namespace %s: add %s to %s: %v", n.name, cidr, name, err)
	}
	if err := n.nl.LinkSetUp(link); err != nil {
		t.Fatalf("namespace %s: set %s up: %v", n.name, name, err)
	}
}

func (n *rttRealNetns) route(t *testing.T, name, dst, gw string) {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(dst)
	if err != nil {
		t.Fatalf("parse %s: %v", dst, err)
	}
	if err := n.nl.RouteAdd(&netlink.Route{
		LinkIndex: n.link(t, name).Attrs().Index,
		Dst:       ipNet,
		Gw:        net.ParseIP(gw),
	}); err != nil {
		t.Fatalf("namespace %s: route %s via %s: %v", n.name, dst, gw, err)
	}
}

// rttVeth creates a veth pair with one end in each namespace.
func rttVeth(t *testing.T, a *rttRealNetns, aName string, b *rttRealNetns, bName string) {
	t.Helper()
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: aName},
		PeerName:      bName,
		PeerNamespace: netlink.NsFd(b.ns),
	}
	if err := a.nl.LinkAdd(veth); err != nil {
		t.Fatalf("add veth %s-%s: %v", aName, bName, err)
	}
}

// rttAsk sends a round-trip request from a socket on from, inside namespace
// n, to to, and returns what comes back within 2 s, or nil when nothing does.
func rttAsk(t *testing.T, n *rttRealNetns, from, to netip.AddrPort) []byte {
	t.Helper()
	var got []byte
	if err := n.do(func() error {
		conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(from))
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.WriteTo(rttDatagram(rttKindRequest, [8]byte{'r', 'e', 'a', 'l', 't', 'e', 's', 't'}), net.UDPAddrFromAddrPort(to)); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		buf := make([]byte, 64)
		size, _, err := conn.ReadFrom(buf)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}
		if err != nil {
			return err
		}
		got = buf[:size]
		return nil
	}); err != nil {
		t.Fatalf("namespace %s: ask %s from %s: %v", n.name, to, from, err)
	}
	return got
}

// TestRTTProbe_RealAnswersOnlyTheMeshInterface proves on a real kernel that
// the default listen binds the probe socket to the mesh interface. The node N
// holds the mesh IP 10.98.0.1/24 on rtt-mesh, a veth to the peer P
// (10.98.0.2), and 192.0.2.1/24 on rtt-lan, a veth to a host L on another
// network. L holds the mesh address 10.98.0.3 on its loopback and routes the
// mesh IP through N, and N routes 10.98.0.3 back to L, so a request L sends
// from a mesh source arrives on rtt-lan and an answer to it would return to L.
//
// A socket bound to the mesh IP alone answers L, which the first subtest shows
// as the control: Linux delivers a datagram for any local address on whichever
// interface it arrives. listenRTT's socket answers P over the mesh interface
// and leaves L's request unanswered.
func TestRTTProbe_RealAnswersOnlyTheMeshInterface(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to run against real network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}

	n := newRTTRealNetns(t, "node")
	p := newRTTRealNetns(t, "peer")
	l := newRTTRealNetns(t, "lan-host")
	rttVeth(t, n, "rtt-mesh", p, "rtt-peer")
	rttVeth(t, n, "rtt-lan", l, "rtt-host")
	n.addr(t, "rtt-mesh", "10.98.0.1/24")
	n.addr(t, "rtt-lan", "192.0.2.1/24")
	p.addr(t, "rtt-peer", "10.98.0.2/24")
	l.addr(t, "rtt-host", "192.0.2.2/24")
	l.addr(t, "lo", "10.98.0.3/32")
	l.route(t, "rtt-host", "10.98.0.1/32", "192.0.2.1")
	n.route(t, "rtt-lan", "10.98.0.3/32", "192.0.2.2")

	meshIP := netip.MustParseAddr("10.98.0.1")
	node := netip.AddrPortFrom(meshIP, RTTProbePort)
	fromPeer := netip.MustParseAddrPort("10.98.0.2:0")
	fromLAN := netip.MustParseAddrPort("10.98.0.3:0")

	// start opens a manager's socket inside N with listen; the test's cleanup
	// closes it, so the next subtest finds the port free.
	start := func(t *testing.T, listen func(*Manager) func() (net.PacketConn, error)) {
		t.Helper()
		mgr := NewManager(nil, Config{InterfaceName: "rtt-mesh"}, discardLogger())
		mgr.meshIP = meshIP
		mgr.meshPrefix = netip.MustParsePrefix("10.98.0.0/24")
		mgr.rttListen = listen(mgr)
		s := &rttSocket{}
		var opened bool
		if err := n.do(func() error {
			opened = mgr.rttOpen(s)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !opened {
			t.Fatal("the probe socket did not open")
		}
		t.Cleanup(s.close)
	}
	isReply := func(b []byte) bool {
		want := rttDatagram(rttKindReply, [8]byte{'r', 'e', 'a', 'l', 't', 'e', 's', 't'})
		return bytes.Equal(b, want)
	}

	t.Run("a socket bound to the mesh IP alone answers the other network", func(t *testing.T) {
		start(t, func(*Manager) func() (net.PacketConn, error) {
			return func() (net.PacketConn, error) {
				return net.ListenUDP("udp4", net.UDPAddrFromAddrPort(node))
			}
		})
		if got := rttAsk(t, l, fromLAN, node); !isReply(got) {
			t.Fatalf("L's request from %s through rtt-lan got %x, want the reply: the control shows nothing, so the next subtest would prove nothing", fromLAN, got)
		}
	})

	t.Run("listenRTT answers the mesh interface only", func(t *testing.T) {
		start(t, func(m *Manager) func() (net.PacketConn, error) { return m.listenRTT })
		if got := rttAsk(t, p, fromPeer, node); !isReply(got) {
			t.Errorf("P's request over rtt-mesh got %x, want the reply", got)
		}
		if got := rttAsk(t, l, fromLAN, node); got != nil {
			t.Errorf("L's request from %s through rtt-lan got %x, want no answer: the socket is bound to rtt-mesh", fromLAN, got)
		}
	})
}
