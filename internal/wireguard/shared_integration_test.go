package wireguard_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// sharedMovedLine is what a node logs when it moves a shared subnet to
// another bridge.
const sharedMovedLine = "wireguard: shared subnet moved"

// peerDirect returns n as the mesh peer of its partner, dialed on its direct
// endpoint alone (see direct), with no relay.
func (n *meshNode) peerDirect() api.Peer {
	return api.Peer{
		ID:         n.id,
		PublicKey:  n.key.PublicKey().String(),
		MeshIP:     n.ip.String(),
		AllowedIPs: []string{netip.PrefixFrom(n.ip, 32).String()},
		Endpoint:   n.direct(),
		Endpoints:  []string{n.direct()},
	}
}

// requirePingArrives writes one ping from from to dst into from's TUN and
// fails the test unless a packet for dst arrives on at's TUN within within.
// What at received before the ping is dropped first, and so is every other
// packet that arrives meanwhile: from's discard probes arrive on at's TUN
// too.
func requirePingArrives(t *testing.T, from, at *meshNode, dst netip.Addr, within time.Duration) {
	t.Helper()
	for drained := false; !drained; {
		select {
		case <-at.received:
		default:
			drained = true
		}
	}

	expired := time.After(within)
	select {
	case from.tun.Outbound <- tuntest.Ping(dst, from.ip):
	case <-expired:
		t.Fatalf("%s: the device did not read the ping to %s within %v", from.id, dst, within)
	}
	sent := time.Now()
	for {
		select {
		case p := <-at.received:
			if len(p) >= 20 && p[0]>>4 == 4 && netip.AddrFrom4([4]byte(p[16:20])) == dst {
				t.Logf("the ping from %s to %s arrived on %s after %v", from.id, dst, at.id, time.Since(sent).Round(time.Millisecond))
				return
			}
		case <-expired:
			t.Fatalf("the ping from %s to %s did not arrive on %s within %v", from.id, dst, at.id, within)
		}
	}
}

// TestSharedSubnetIntegration_DeadBridgeMovesTheSubnetToTheStandby proves
// "node N with bridges A and B on wireguard-go, 5 s held, the discard probe
// written into the TUN. Read no moved line over 20 idle seconds, a packet to
// 10.20.0.9 on A's TUN, then remove N from A's device with RemovePeerByID and
// read moved to B within 20 s and the next packet on B's TUN".
//
// All three nodes run the production keepalive of 25 s (plan decision 5). At
// the harness's 1 s, A's own keepalives would keep N's counter moving, and
// the idle check would prove nothing. At 25 s, only a bridge's WireGuard
// answering N's discard probes, within its 10 s KeepaliveTimeout, keeps the
// bridge alive inside the window. No round-trip probe runs, so no bridge is
// proven and the window is 14 s, detectSilence of the 15 s floor.
//
// The pull reaches N through the reconcile handler and carries only what the
// shared subnets need (plan decision 6): the handler refuses the loopback
// endpoints the bridges are dialed on, so AddPeer added them before.
//
// Both sides of a pair start a handshake when AddPeer writes the peer, and
// when the two collide, wireguard-go drops the data of the pair's first
// session until its retry handshake 15 s later (measured here: N's counter
// for the bridge stood still for 15 s while N's probes went missing). The
// watch would then rightly find that path dead. So the test sends the pull
// only once pings cross both pairs both ways, and the watch's window starts
// with the pull on paths that carry traffic.
func TestSharedSubnetIntegration_DeadBridgeMovesTheSubnetToTheStandby(t *testing.T) {
	t.Parallel()
	const subnet = "10.20.0.0/16"
	site := netip.MustParseAddr("10.20.0.9")

	n := newMeshNodeKeepalive(t, "node-n", "10.99.0.1", wireguard.DefaultPersistentKeepalive)
	a := newMeshNodeKeepalive(t, "node-a", "10.99.0.2", wireguard.DefaultPersistentKeepalive)
	b := newMeshNodeKeepalive(t, "node-b", "10.99.0.3", wireguard.DefaultPersistentKeepalive)

	for _, bridge := range []*meshNode{a, b} {
		if err := bridge.mgr.AddPeer(n.peerDirect()); err != nil {
			t.Fatalf("%s: AddPeer(%s): %v", bridge.id, n.id, err)
		}
	}
	for _, bridge := range []*meshNode{a, b} {
		if err := n.mgr.AddPeer(bridge.peerDirect()); err != nil {
			t.Fatalf("%s: AddPeer(%s): %v", n.id, bridge.id, err)
		}
	}
	if d, changed := n.mgr.SetFailureDetection(5 * time.Second); d != 5*time.Second || !changed {
		t.Fatalf("%s: SetFailureDetection(5s) = %v, %t, want 5s, true", n.id, d, changed)
	}
	n.mgr.SetRelayProbe(n.sendProbe)
	n.startSelection()
	pingBoth(t, n, a, 1, 30*time.Second)
	pingBoth(t, n, b, 1, 30*time.Second)

	desired := &api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{NodeID: a.id, PublicKey: a.key.PublicKey().String(), RoutedSubnets: []string{subnet}},
			{NodeID: b.id, PublicKey: b.key.PublicKey().String()},
		},
		SharedSubnets: []api.NodeStateSharedSubnet{{Subnet: subnet, Bridges: []string{a.id, b.id}}},
	}
	if err := wireguard.ReconcileHandler(n.mgr, nil)(context.Background(), desired, reconcile.StateDiff{}); err != nil {
		t.Fatalf("%s: reconcile handler: %v", n.id, err)
	}
	if !logged(n.logs.String(), "wireguard: shared subnet assigned", "subnet="+subnet, "bridge="+a.id) {
		t.Fatalf(`%s: no "wireguard: shared subnet assigned" line with bridge=%s`, n.id, a.id)
	}

	// Idle: nothing crosses but N's probes, the bridges' answers to them and
	// the 25 s keepalives.
	if waitFor(20*time.Second, func() bool { return logged(n.logs.String(), sharedMovedLine) }) {
		t.Fatalf("%s: logged %q while both bridges sat idle and alive", n.id, sharedMovedLine)
	}
	requirePingArrives(t, n, a, site, 5*time.Second)

	if err := a.mgr.RemovePeerByID(n.id); err != nil {
		t.Fatalf("%s: RemovePeerByID(%s): %v", a.id, n.id, err)
	}
	removedAt := time.Now()
	moved := []string{"subnet=" + subnet, "from=" + a.id, "to=" + b.id, "reason=bridge_dead", "window=14s"}
	if !waitFor(20*time.Second, func() bool { return logged(n.logs.String(), sharedMovedLine, moved...) }) {
		t.Fatalf("%s: no %q line with %v within 20s of %s dropping it", n.id, sharedMovedLine, moved, a.id)
	}
	t.Logf("%s moved %s to %s %v after %s dropped it", n.id, subnet, b.id, time.Since(removedAt).Round(time.Millisecond), a.id)

	requirePingArrives(t, n, b, site, 5*time.Second)
}
