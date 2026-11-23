//go:build darwin

package wireguard

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/ifbind"
	"github.com/plexsphere/plexd/internal/nettest"
)

// TestRTTProbe_RealUTUN proves on a real macOS kernel that listenRTT's socket
// answers only what arrives on the mesh utun. With forwarding on, as a macOS
// bridge sets it, the test owns two utuns: the mesh utun carries the mesh IP
// 10.255.239.1/24, and the other utun carries 10.255.240.1/24 and stands for
// another network. It writes probe requests into each and watches both for
// the reply.
//
// The first subtest is the control: a socket bound to the mesh utun with
// IP_BOUND_IF alone answers a request with the mesh source 10.255.239.3 that
// arrives on the other utun, and the reply leaves through the mesh utun. The
// option confines only what the socket sends. The second subtest shows that
// listenRTT's socket answers a peer's request on the mesh utun and draws no
// reply out of either utun for a request from the same forged source on the
// other utun, because rttMeshOnly drops what did not arrive on the mesh utun.
func TestRTTProbe_RealUTUN(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to run against real utun devices")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create utun devices and switch forwarding on")
	}

	nettest.EnableForwarding(t)
	mesh := nettest.NewUTUN(t, "10.255.239.1/24", "10.255.239.0/24")
	other := nettest.NewUTUN(t, "10.255.240.1/24", "10.255.240.0/24")

	meshIP := netip.MustParseAddr("10.255.239.1")
	node := netip.AddrPortFrom(meshIP, RTTProbePort)
	fromPeer := netip.AddrPortFrom(netip.MustParseAddr("10.255.239.2"), RTTProbePort)
	forged := netip.AddrPortFrom(netip.MustParseAddr("10.255.239.3"), RTTProbePort)

	// start opens a manager's socket with listen; the test's cleanup closes
	// it, so the next subtest finds the port free.
	start := func(t *testing.T, listen func(*Manager) func() (net.PacketConn, error)) {
		t.Helper()
		mgr := NewManager(nil, Config{InterfaceName: mesh.Name()}, discardLogger())
		mgr.meshIP = meshIP
		mgr.meshPrefix = netip.MustParsePrefix("10.255.239.0/24")
		mgr.rttListen = listen(mgr)
		s := &rttSocket{}
		if !mgr.rttOpen(s) {
			t.Fatal("the probe socket did not open")
		}
		t.Cleanup(s.close)
	}
	// ask writes a request from src with nonce into u and returns a match
	// for its reply: a UDP packet from the node's probe port to src that
	// carries the reply to nonce.
	ask := func(t *testing.T, u *nettest.UTUN, src netip.AddrPort, nonce [8]byte) func(nettest.Packet) bool {
		t.Helper()
		u.Inject(t, nettest.UDPDatagram(src, node, rttDatagram(rttKindRequest, nonce)))
		want := rttDatagram(rttKindReply, nonce)
		return func(p nettest.Packet) bool {
			return p.Proto == nettest.ProtoUDP &&
				p.Src == node.Addr() && p.SrcPort == node.Port() &&
				p.Dst == src.Addr() && p.DstPort == src.Port() &&
				bytes.Equal(p.Payload, want)
		}
	}

	t.Run("a socket bound with IP_BOUND_IF alone answers the other network", func(t *testing.T) {
		start(t, func(*Manager) func() (net.PacketConn, error) {
			return func() (net.PacketConn, error) {
				lc := net.ListenConfig{Control: ifbind.Control(mesh.Name())}
				return lc.ListenPacket(context.Background(), "udp4", node.String())
			}
		})
		isReply := ask(t, other, forged, [8]byte{'c', 'o', 'n', 't', 'r', 'o', 'l', '1'})
		if _, ok := mesh.Await(3*time.Second, isReply); !ok {
			t.Fatalf("the request from %s written into %s drew no reply out of %s within 3 s, want the reply: the control shows nothing, so the next subtest would prove nothing",
				forged, other.Name(), mesh.Name())
		}
	})

	t.Run("listenRTT answers the mesh utun only", func(t *testing.T) {
		start(t, func(m *Manager) func() (net.PacketConn, error) { return m.listenRTT })

		isReply := ask(t, mesh, fromPeer, [8]byte{'p', 'e', 'e', 'r', 'r', 'e', 'q', '1'})
		if _, ok := mesh.Await(3*time.Second, isReply); !ok {
			t.Errorf("the peer's request from %s written into %s drew no reply out of %s within 3 s, want the reply", fromPeer, mesh.Name(), mesh.Name())
		}

		// Both utuns are watched at once, each for the whole 2 s, so a reply
		// out of either one is seen.
		isReply = ask(t, other, forged, [8]byte{'f', 'o', 'r', 'g', 'e', 'd', 'r', '1'})
		utuns := []*nettest.UTUN{mesh, other}
		replies := make([]nettest.Packet, len(utuns))
		answered := make([]bool, len(utuns))
		var wg sync.WaitGroup
		for i, u := range utuns {
			wg.Go(func() { replies[i], answered[i] = u.Await(2*time.Second, isReply) })
		}
		wg.Wait()
		for i, u := range utuns {
			if answered[i] {
				t.Errorf("the request from %s written into %s drew %s out of %s, want no reply: listenRTT's socket takes only what arrives on %s",
					forged, other.Name(), replies[i], u.Name(), mesh.Name())
			}
		}
	})
}
