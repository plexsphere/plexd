//go:build darwin

package tunnel

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/nettest"
)

// awaited is what one UTUN.Await returned.
type awaited struct {
	packet nettest.Packet
	ok     bool
}

// awaitAsync runs u.Await(wait, match) on a goroutine of its own and returns
// a channel that carries its result. The goroutine ends once Await returned,
// at the latest after wait.
func awaitAsync(u *nettest.UTUN, wait time.Duration, match func(nettest.Packet) bool) <-chan awaited {
	ch := make(chan awaited, 1)
	go func() {
		p, ok := u.Await(wait, match)
		ch <- awaited{packet: p, ok: ok}
	}()
	return ch
}

// TestSession_RealUTUN proves with packets through two utuns the test owns
// what binding a tcp session listener to the mesh interface does on a Mac
// that forwards. The mesh utun carries the mesh IP 10.255.241.1/24, and the
// other utun carries 10.255.242.1/24 and stands for another network the Mac
// is attached to. A segment enters a utun when the test writes it into the
// utun and leaves when the test reads it from the utun. Every SYN uses a
// source port of its own, so no check sees the answer to an earlier one.
//
// macOS takes a segment for an address of the host that arrives on another
// interface only while it forwards, so the test switches forwarding on, as a
// macOS bridge does. A listener bound to the mesh IP alone then answers a SYN
// from the other network out of the other utun, which the first subtest
// shows as the control. IP_BOUND_IF does not filter what the listener
// receives: it confines what the listener sends to the mesh utun. Bound to
// the mesh utun, the listener answers a peer's SYN there as before. A SYN
// from the other network's own address draws no segment out of either utun.
// A SYN with a mesh source that arrives on the other utun draws a SYN-ACK out
// of the mesh utun only, so such a client completes a handshake only if it
// can read what the node sends into the mesh.
func TestSession_RealUTUN(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to run against real utun devices")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create utun devices and switch forwarding on")
	}

	// Called before the utuns exist, so they are closed before forwarding is
	// restored.
	nettest.EnableForwarding(t)
	mesh := nettest.NewUTUN(t, "10.255.241.1/24", "10.255.241.0/24")
	other := nettest.NewUTUN(t, "10.255.242.1/24", "10.255.242.0/24")
	meshIP := netip.MustParseAddr("10.255.241.1")

	// start opens a session's listener on the mesh IP, bound to iface, and
	// returns its address; the test's cleanup closes it. The target is never
	// dialed: no handshake here completes.
	start := func(t *testing.T, iface string) netip.AddrPort {
		t.Helper()
		s := NewSession("sess-real-utun", "127.0.0.1", 9, meshIP.String(), time.Now().Add(5*time.Minute), discardLogger())
		s.MeshInterface = iface
		addr, err := s.Start(context.Background())
		if err != nil {
			t.Fatalf("start the session on %s with MeshInterface %q: %v", meshIP, iface, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		listen, err := netip.ParseAddrPort(addr)
		if err != nil {
			t.Fatalf("parse the session's address %q: %v", addr, err)
		}
		if listen.Addr() != meshIP {
			t.Fatalf("session listens on %s, want the mesh IP %s", listen, meshIP)
		}
		return listen
	}
	syn := func(src, listen netip.AddrPort, seq uint32) []byte {
		return nettest.TCPSegment(src, listen, seq, 0, nettest.FlagSYN)
	}
	// segmentTo matches any TCP segment from the listener to src.
	segmentTo := func(listen, src netip.AddrPort) func(nettest.Packet) bool {
		return func(p nettest.Packet) bool {
			return p.Proto == nettest.ProtoTCP &&
				p.Src == listen.Addr() && p.SrcPort == listen.Port() &&
				p.Dst == src.Addr() && p.DstPort == src.Port()
		}
	}
	// synAckTo matches a SYN-ACK from the listener to src.
	synAckTo := func(listen, src netip.AddrPort) func(nettest.Packet) bool {
		to := segmentTo(listen, src)
		return func(p nettest.Packet) bool {
			return to(p) && p.Flags&(nettest.FlagSYN|nettest.FlagACK) == nettest.FlagSYN|nettest.FlagACK
		}
	}

	t.Run("a listener bound to the mesh IP alone answers the other network", func(t *testing.T) {
		listen := start(t, "")
		src := netip.MustParseAddrPort("10.255.242.2:40001")
		other.Inject(t, syn(src, listen, 1000))
		if _, ok := other.Await(3*time.Second, synAckTo(listen, src)); !ok {
			t.Fatalf("a SYN from %s into %s drew no SYN-ACK out of %s within 3 s, want one: the control shows nothing, so the next subtest would prove nothing", src, other.Name(), other.Name())
		}
	})

	t.Run("a listener bound to the mesh utun answers into the mesh only", func(t *testing.T) {
		listen := start(t, mesh.Name())

		peer := netip.MustParseAddrPort("10.255.241.2:40002")
		mesh.Inject(t, syn(peer, listen, 2000))
		if _, ok := mesh.Await(3*time.Second, synAckTo(listen, peer)); !ok {
			t.Errorf("a peer's SYN from %s into %s drew no SYN-ACK out of %s within 3 s, want one", peer, mesh.Name(), mesh.Name())
		}

		foreign := netip.MustParseAddrPort("10.255.242.2:40003")
		other.Inject(t, syn(foreign, listen, 3000))
		onMesh := awaitAsync(mesh, 2*time.Second, segmentTo(listen, foreign))
		onOther := awaitAsync(other, 2*time.Second, segmentTo(listen, foreign))
		if r := <-onMesh; r.ok {
			t.Errorf("a SYN from %s into %s drew %v out of %s, want no segment: the listener is bound to %s", foreign, other.Name(), r.packet, mesh.Name(), mesh.Name())
		}
		if r := <-onOther; r.ok {
			t.Errorf("a SYN from %s into %s drew %v out of %s, want no segment: the listener is bound to %s", foreign, other.Name(), r.packet, other.Name(), mesh.Name())
		}

		forged := netip.MustParseAddrPort("10.255.241.3:40004")
		other.Inject(t, syn(forged, listen, 4000))
		onMesh = awaitAsync(mesh, 3*time.Second, synAckTo(listen, forged))
		onOther = awaitAsync(other, 2*time.Second, segmentTo(listen, forged))
		if r := <-onMesh; !r.ok {
			t.Errorf("a SYN from the mesh source %s into %s drew no SYN-ACK out of %s within 3 s, want one: IP_BOUND_IF confines what the listener sends", forged, other.Name(), mesh.Name())
		}
		if r := <-onOther; r.ok {
			t.Errorf("a SYN from the mesh source %s into %s drew %v out of %s, want no segment: the listener is bound to %s", forged, other.Name(), r.packet, other.Name(), mesh.Name())
		}
	})
}
