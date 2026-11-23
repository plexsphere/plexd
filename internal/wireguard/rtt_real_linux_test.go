//go:build linux

package wireguard

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/nettest"
)

// rttAsk sends a round-trip request from a socket on from, inside namespace
// n, to to, and returns what comes back within 2 s, or nil when nothing does.
func rttAsk(t *testing.T, n *nettest.Netns, from, to netip.AddrPort) []byte {
	t.Helper()
	var got []byte
	if err := n.Do(func() error {
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
		t.Fatalf("namespace %s: ask %s from %s: %v", n.Name, to, from, err)
	}
	return got
}

// TestRTTProbe_RealAnswersOnlyTheMeshInterface proves on a real kernel that
// the default listen binds the probe socket to the mesh interface. It runs in
// the namespaces nettest.NewMeshLAN builds: the node N holds the mesh IP
// 10.98.0.1/24 on nt-mesh, a veth to the peer P (10.98.0.2), and
// 192.0.2.1/24 on nt-lan, a veth to a host L on another network. L sends its
// request from the mesh address 10.98.0.3 on its loopback and routes the mesh
// IP through N, and N routes 10.98.0.3 back to L, so the request arrives on
// nt-lan and an answer to it would return to L.
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

	lan := nettest.NewMeshLAN(t)

	meshIP := netip.MustParseAddr(nettest.NodeMeshIP)
	node := netip.AddrPortFrom(meshIP, RTTProbePort)
	fromPeer := netip.AddrPortFrom(netip.MustParseAddr(nettest.PeerMeshIP), 0)
	fromLAN := netip.AddrPortFrom(netip.MustParseAddr(nettest.LANMeshSource), 0)

	// start opens a manager's socket inside N with listen; the test's cleanup
	// closes it, so the next subtest finds the port free.
	start := func(t *testing.T, listen func(*Manager) func() (net.PacketConn, error)) {
		t.Helper()
		mgr := NewManager(nil, Config{InterfaceName: nettest.MeshLink}, discardLogger())
		mgr.meshIP = meshIP
		mgr.meshPrefix = netip.MustParsePrefix(nettest.MeshPrefix)
		mgr.rttListen = listen(mgr)
		s := &rttSocket{}
		var opened bool
		if err := lan.Node.Do(func() error {
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
		if got := rttAsk(t, lan.LANHost, fromLAN, node); !isReply(got) {
			t.Fatalf("L's request from %s through nt-lan got %x, want the reply: the control shows nothing, so the next subtest would prove nothing", fromLAN, got)
		}
	})

	t.Run("listenRTT answers the mesh interface only", func(t *testing.T) {
		start(t, func(m *Manager) func() (net.PacketConn, error) { return m.listenRTT })
		if got := rttAsk(t, lan.Peer, fromPeer, node); !isReply(got) {
			t.Errorf("P's request over nt-mesh got %x, want the reply", got)
		}
		if got := rttAsk(t, lan.LANHost, fromLAN, node); got != nil {
			t.Errorf("L's request from %s through nt-lan got %x, want no answer: the socket is bound to nt-mesh", fromLAN, got)
		}
	})
}
