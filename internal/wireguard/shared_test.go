package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Shared subnets: validation and assignment
// ---------------------------------------------------------------------------

// sharedSubnet10_20 is the shared subnet most tests hand to the bridges.
const sharedSubnet10_20 = "10.20.0.0/16"

// sharedHarness is a manager set up in testMesh on a statsController, with a
// mockRouter recording into the same calls, its reconcile handler, and the
// buffer its log goes to.
type sharedHarness struct {
	t       *testing.T
	ctrl    *statsController
	mgr     *Manager
	logs    *bytes.Buffer
	handler reconcile.ReconcileHandler
}

func newSharedHarness(t *testing.T) *sharedHarness {
	t.Helper()
	h := &sharedHarness{t: t, ctrl: &statsController{}, logs: &bytes.Buffer{}}
	h.mgr = setupMeshManager(t, h.ctrl, slogTextLogger(h.logs))
	h.mgr.SetPeerRouter(&mockRouter{ctrl: &h.ctrl.mockController})
	h.handler = ReconcileHandler(h.mgr, nil)
	return h
}

// pull runs the handler on a pull whose peers are peers and whose
// shared_subnets block is entries, with diff as the reconciler computed it.
func (h *sharedHarness) pull(peers []api.SnapshotPeer, entries []api.NodeStateSharedSubnet, diff reconcile.StateDiff) error {
	desired := &api.NodeStateSnapshot{Peers: peers, SharedSubnets: entries}
	return h.handler(context.Background(), desired, diff)
}

// mustPull is pull for a run that must succeed.
func (h *sharedHarness) mustPull(peers []api.SnapshotPeer, entries []api.NodeStateSharedSubnet, diff reconcile.StateDiff) {
	h.t.Helper()
	if err := h.pull(peers, entries, diff); err != nil {
		h.t.Fatalf("handler: %v", err)
	}
}

// reset forgets the calls and the log lines recorded so far.
func (h *sharedHarness) reset() {
	h.ctrl.mu.Lock()
	h.ctrl.calls = nil
	h.ctrl.mu.Unlock()
	h.logs.Reset()
}

// writes returns the device writes recorded since the last reset, in order:
// "add <peer> <allowed IPs>" for an AddPeer and "remove <peer>" for a
// RemovePeer, the peer named by its key (see sharedPeerName).
func (h *sharedHarness) writes() []string {
	h.ctrl.mu.Lock()
	defer h.ctrl.mu.Unlock()
	var writes []string
	for _, c := range h.ctrl.calls {
		switch c.Method {
		case "AddPeer":
			cfg := c.Args[1].(PeerConfig)
			writes = append(writes, fmt.Sprintf("add %s %v", sharedPeerName(cfg.PublicKey), cfg.AllowedIPs))
		case "RemovePeer":
			writes = append(writes, "remove "+sharedPeerName(c.Args[1].([]byte)))
		}
	}
	return writes
}

// requireWrites fails the test unless the device writes since the last reset
// are want.
func (h *sharedHarness) requireWrites(want ...string) {
	h.t.Helper()
	if got := h.writes(); !slices.Equal(got, want) {
		h.t.Errorf("device writes = %q, want %q", got, want)
	}
}

// holder returns the holder the manager records for subnet, "" when it holds
// no such shared subnet.
func (h *sharedHarness) holder(subnet string) string {
	h.mgr.mu.Lock()
	defer h.mgr.mu.Unlock()
	if s, ok := h.mgr.shared[subnet]; ok {
		return s.holder
	}
	return ""
}

// requireHolder fails the test unless the holder of subnet is want.
func (h *sharedHarness) requireHolder(subnet, want string) {
	h.t.Helper()
	if got := h.holder(subnet); got != want {
		h.t.Errorf("holder of %s = %q, want %q", subnet, got, want)
	}
}

// sharedPeerName names a test peer by its key: peer-a, peer-b and peer-c
// for the keys of bridgeA, bridgeB and bridgeC, and key-<byte> otherwise.
func sharedPeerName(key []byte) string {
	switch key[0] {
	case 0x0a:
		return "peer-a"
	case 0x0b:
		return "peer-b"
	case 0x0c:
		return "peer-c"
	}
	return fmt.Sprintf("key-%02x", key[0])
}

// bridgeA, bridgeB and bridgeC return the bridges of the tests, peers of
// testMesh without endpoints whose routed_subnets are subnets.
func bridgeA(subnets ...string) api.SnapshotPeer {
	return routedPeer("peer-a", "10.99.0.2", 0x0a, subnets...)
}

func bridgeB(subnets ...string) api.SnapshotPeer {
	return routedPeer("peer-b", "10.99.0.3", 0x0b, subnets...)
}

func bridgeC(subnets ...string) api.SnapshotPeer {
	return routedPeer("peer-c", "10.99.0.4", 0x0c, subnets...)
}

// sharedEntry returns a shared_subnets entry for subnet with bridges.
func sharedEntry(subnet string, bridges ...string) api.NodeStateSharedSubnet {
	return api.NodeStateSharedSubnet{Subnet: subnet, Bridges: bridges}
}

// entries returns its arguments as a shared_subnets block.
func entries(e ...api.NodeStateSharedSubnet) []api.NodeStateSharedSubnet {
	return e
}

// sharedSubnetLines are the seven log lines the shared subnets add.
var sharedSubnetLines = []string{
	"wireguard: shared subnet not programmed",
	"wireguard: shared subnet assigned",
	"wireguard: shared subnet moved",
	"wireguard: shared subnet released",
	"wireguard: shared subnet move failed",
	"wireguard: shared subnet has no live bridge",
	"wireguard: bridge probe send failed",
}

// TestSharedSubnets_EntryPutsTheSubnetOnTheFirstBridge proves "Apply an entry
// 10.20.0.0/16 with bridges A and B while A's routed_subnets lists the
// subnet, and read it in A's allowed IPs alone, one AddRoute, and the
// assigned line with bridge A".
func TestSharedSubnets_EntryPutsTheSubnetOnTheFirstBridge(t *testing.T) {
	h := newSharedHarness(t)
	a, b := bridgeA(sharedSubnet10_20), bridgeB()
	peers := []api.SnapshotPeer{a, b}

	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b")),
		reconcile.StateDiff{PeersToAdd: peers})

	h.requireWrites(
		"add peer-a [10.99.0.2/32 10.20.0.0/16]",
		"add peer-b [10.99.0.3/32]",
	)
	if got, want := routeCalls(&h.ctrl.mockController), []string{"AddRoute 10.20.0.0/16 plexd0"}; !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
	requireLogLine(t, h.logs.String(), "wireguard: shared subnet assigned",
		"level=INFO", "component=wireguard", "subnet=10.20.0.0/16", "bridge=peer-a", "bridges=2")
	h.requireHolder(sharedSubnet10_20, "peer-a")
}

// TestSharedSubnets_NilAndEmptyBlockChangeNothing proves "Apply a pull with
// nil and with empty shared_subnets and read the device writes of
// TestReconcileHandler_RoutesRoutedSubnets unchanged and none of the seven
// new wireguard: log lines": it runs that test's three pulls with a nil
// desired, as the test does, and again with a desired whose block is nil and
// one whose block is [], and compares every recorded call.
func TestSharedSubnets_NilAndEmptyBlockChangeNothing(t *testing.T) {
	// run applies the pulls of TestReconcileHandler_RoutesRoutedSubnets and
	// returns the calls ctrl recorded and the log. desired builds the
	// snapshot the handler gets from the pull's peers.
	run := func(t *testing.T, desired func(peers ...api.SnapshotPeer) *api.NodeStateSnapshot) ([]mockCall, string) {
		t.Helper()
		var logs bytes.Buffer
		ctrl := &mockController{}
		mgr := setupMeshManager(t, ctrl, slogTextLogger(&logs))
		mgr.SetPeerRouter(&mockRouter{ctrl: ctrl})
		handler := ReconcileHandler(mgr, nil)
		ctx := context.Background()

		peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
		if err := handler(ctx, desired(peer), reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
			t.Fatalf("add: %v", err)
		}
		if err := handler(ctx, desired(peer), reconcile.StateDiff{}); err != nil {
			t.Fatalf("unchanged: %v", err)
		}
		peer.RoutedSubnets = nil
		if err := handler(ctx, desired(peer), reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{peer}}); err != nil {
			t.Fatalf("update: %v", err)
		}
		ctrl.mu.Lock()
		defer ctrl.mu.Unlock()
		return slices.Clone(ctrl.calls), logs.String()
	}

	wantCalls, _ := run(t, func(...api.SnapshotPeer) *api.NodeStateSnapshot { return nil })
	if n := len(addPeerConfigs(t, &mockController{calls: wantCalls})); n != 2 {
		t.Fatalf("AddPeer calls with a nil desired = %d, want the add and the update", n)
	}
	if got, want := routeCalls(&mockController{calls: wantCalls}), []string{"AddRoute 10.20.0.0/16 plexd0", "RemoveRoute 10.20.0.0/16 plexd0"}; !slices.Equal(got, want) {
		t.Fatalf("route calls with a nil desired = %v, want %v", got, want)
	}

	for name, block := range map[string][]api.NodeStateSharedSubnet{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			calls, out := run(t, func(peers ...api.SnapshotPeer) *api.NodeStateSnapshot {
				return &api.NodeStateSnapshot{Peers: peers, SharedSubnets: block}
			})
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Errorf("calls with a %s block:\n%v\nwant the calls with a nil desired:\n%v", name, calls, wantCalls)
			}
			for _, msg := range sharedSubnetLines {
				if lines := logLines(out, msg); len(lines) > 0 {
					t.Errorf("a %s block logged %q:\n%s", name, msg, strings.Join(lines, "\n"))
				}
			}
		})
	}
}

// TestSharedSubnets_ReorderedBridgesKeepTheHolder proves "Apply bridges B, A
// while A holds the subnet and read no device write and no moved line".
//
// It then plants B's record listing the subnet as well, as a failed repair
// write of syncSharedSubnets leaves it, and applies the pull again: the
// recorded holder wins over the first bridge whose record lists the subnet,
// and the step rewrites A before it writes B without the subnet.
func TestSharedSubnets_ReorderedBridgesKeepTheHolder(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(sharedSubnet10_20), bridgeB()}
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b")),
		reconcile.StateDiff{PeersToAdd: peers})
	h.requireHolder(sharedSubnet10_20, "peer-a")

	reordered := entries(sharedEntry(sharedSubnet10_20, "peer-b", "peer-a"))
	h.reset()
	h.mustPull(peers, reordered, reconcile.StateDiff{})

	h.requireWrites()
	if lines := logLines(h.logs.String(), "wireguard: shared subnet moved"); len(lines) > 0 {
		t.Errorf("reordered bridges logged a move:\n%s", strings.Join(lines, "\n"))
	}
	h.requireHolder(sharedSubnet10_20, "peer-a")

	h.mgr.mu.Lock()
	b := h.mgr.dial["peer-b"]
	b.peer.RoutedSubnets = []string{sharedSubnet10_20}
	b.peer.AllowedIPs = []string{"10.99.0.3/32", sharedSubnet10_20}
	h.mgr.mu.Unlock()
	h.reset()
	h.mustPull(peers, reordered, reconcile.StateDiff{})

	h.requireWrites(
		"add peer-a [10.99.0.2/32 10.20.0.0/16]",
		"add peer-b [10.99.0.3/32]",
	)
	if lines := logLines(h.logs.String(), "wireguard: shared subnet moved"); len(lines) > 0 {
		t.Errorf("a second record listing the subnet moved it:\n%s", strings.Join(lines, "\n"))
	}
	h.requireHolder(sharedSubnet10_20, "peer-a")
}

// TestSharedSubnets_PullWithoutTheHolderMovesTheSubnet proves "Apply bridges
// B, C while A holds the subnet and read the subnet on B, A written without
// it, and moved with reason=pull". B is written first, so the device never
// holds the subnet on no bridge, and the route stays.
func TestSharedSubnets_PullWithoutTheHolderMovesTheSubnet(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(sharedSubnet10_20), bridgeB(), bridgeC()}
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b")),
		reconcile.StateDiff{PeersToAdd: peers})
	h.requireHolder(sharedSubnet10_20, "peer-a")

	h.reset()
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-b", "peer-c")), reconcile.StateDiff{})

	h.requireWrites(
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
		"add peer-a [10.99.0.2/32]",
	)
	requireLogLine(t, h.logs.String(), "wireguard: shared subnet moved",
		"level=INFO", "component=wireguard", "subnet=10.20.0.0/16", "from=peer-a", "to=peer-b", "reason=pull")
	if got := routeCalls(&h.ctrl.mockController); len(got) != 0 {
		t.Errorf("route calls = %v, want none: the union of the routed subnets is unchanged", got)
	}
	h.requireHolder(sharedSubnet10_20, "peer-b")
	for _, cfg := range addPeerConfigs(t, &h.ctrl.mockController) {
		if cfg.Endpoint != "" {
			t.Errorf("a shared subnet write carries endpoint %q, want none so the device keeps its own", cfg.Endpoint)
		}
	}
}

// TestSharedSubnets_RemovedEntryReturnsTheSubnetToItsRoutedSubnetsPeer
// proves "Remove the entry while B holds the subnet and A's routed_subnets
// lists it, with both peer entries unchanged, and read A written with the
// subnet, B without it, and the released line".
func TestSharedSubnets_RemovedEntryReturnsTheSubnetToItsRoutedSubnetsPeer(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(sharedSubnet10_20), bridgeB()}
	// No peer is written yet when the entry is taken, so the first bridge,
	// B, holds the subnet although A's routed_subnets list it.
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-b", "peer-a")),
		reconcile.StateDiff{PeersToAdd: peers})
	h.requireWrites(
		"add peer-a [10.99.0.2/32]",
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
	)
	h.requireHolder(sharedSubnet10_20, "peer-b")

	h.reset()
	h.mustPull(peers, nil, reconcile.StateDiff{})

	h.requireWrites(
		"add peer-a [10.99.0.2/32 10.20.0.0/16]",
		"add peer-b [10.99.0.3/32]",
	)
	requireLogLine(t, h.logs.String(), "wireguard: shared subnet released",
		"level=INFO", "component=wireguard", "subnet=10.20.0.0/16", "bridge=peer-b")
	h.requireHolder(sharedSubnet10_20, "")
}

// TestSharedSubnets_InvalidEntriesAreNotProgrammed proves "Apply entries
// with the subnets 10.20.0.1/16, fd00::/64, x, one that overlaps the mesh
// prefix, one inside a local network and a repeated one, and read not
// programmed with invalid, overlaps_mesh, inside_local_network and
// duplicate, and each subnet on the peer whose routed_subnets lists it".
// Every skipped entry names B, which gets none of the subnets.
func TestSharedSubnets_InvalidEntriesAreNotProgrammed(t *testing.T) {
	h := newSharedHarness(t)
	h.mgr.SetLocalPrefixes(func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
	})
	peers := []api.SnapshotPeer{bridgeA("10.20.0.0/16", "10.30.0.0/16"), bridgeB("10.40.0.0/16")}

	h.mustPull(peers, entries(
		sharedEntry("10.20.0.1/16", "peer-b"),
		sharedEntry("fd00::/64", "peer-b"),
		sharedEntry("x", "peer-b"),
		sharedEntry("10.99.0.0/25", "peer-b"),
		sharedEntry("192.168.1.0/24", "peer-b"),
		sharedEntry("10.30.0.0/16", "peer-a", "peer-b"),
		sharedEntry("10.30.0.0/16", "peer-b"),
	), reconcile.StateDiff{PeersToAdd: peers})

	out := h.logs.String()
	for _, skip := range []struct{ subnet, reason string }{
		{"10.20.0.1/16", "invalid"},
		{"fd00::/64", "invalid"},
		{"x", "invalid"},
		{"10.99.0.0/25", "overlaps_mesh"},
		{"192.168.1.0/24", "inside_local_network"},
		{"10.30.0.0/16", "duplicate"},
	} {
		requireLogLine(t, out, "wireguard: shared subnet not programmed",
			"level=WARN", "component=wireguard", "subnet="+skip.subnet, "reason="+skip.reason)
	}
	if n := len(logLines(out, "wireguard: shared subnet not programmed")); n != 6 {
		t.Errorf("not programmed lines = %d, want 6:\n%s", n, out)
	}
	if n := len(logLines(out, "wireguard: shared subnet assigned")); n != 1 {
		t.Errorf("assigned lines = %d, want 1 for the first 10.30.0.0/16 entry:\n%s", n, out)
	}

	h.requireWrites(
		"add peer-a [10.99.0.2/32 10.20.0.0/16 10.30.0.0/16]",
		"add peer-b [10.99.0.3/32 10.40.0.0/16]",
	)
	h.mgr.mu.Lock()
	held := slices.Sorted(maps.Keys(h.mgr.shared))
	h.mgr.mu.Unlock()
	if want := []string{"10.30.0.0/16"}; !slices.Equal(held, want) {
		t.Errorf("shared subnets = %v, want %v", held, want)
	}
	h.requireHolder("10.30.0.0/16", "peer-a")
}

// TestSharedSubnets_EntryWithoutAPeerOfThePullIsNotProgrammed proves "Apply
// an entry with empty bridges and one whose bridges name no peer of the
// pull, and read not programmed with no_bridge". The subnet of the first
// stays on A, whose routed_subnets list it.
func TestSharedSubnets_EntryWithoutAPeerOfThePullIsNotProgrammed(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(sharedSubnet10_20), bridgeB()}

	h.mustPull(peers, entries(
		sharedEntry(sharedSubnet10_20),
		sharedEntry("10.21.0.0/16", "peer-gone", "peer-unknown"),
	), reconcile.StateDiff{PeersToAdd: peers})

	out := h.logs.String()
	for _, subnet := range []string{sharedSubnet10_20, "10.21.0.0/16"} {
		requireLogLine(t, out, "wireguard: shared subnet not programmed",
			"level=WARN", "component=wireguard", "subnet="+subnet, "reason=no_bridge")
	}
	if lines := logLines(out, "wireguard: shared subnet assigned"); len(lines) > 0 {
		t.Errorf("an entry without a bridge was assigned:\n%s", strings.Join(lines, "\n"))
	}
	h.requireWrites(
		"add peer-a [10.99.0.2/32 10.20.0.0/16]",
		"add peer-b [10.99.0.3/32]",
	)
	h.requireHolder(sharedSubnet10_20, "")
	h.requireHolder("10.21.0.0/16", "")
}

// TestSharedSubnets_KeepsTheFirstEightBridges proves "Apply an entry with ten
// bridges and read the first eight in the manager's entry". A second entry
// opens its list with an unknown and a repeated ID, and still keeps eight
// bridges: the cap counts after the drops.
func TestSharedSubnets_KeepsTheFirstEightBridges(t *testing.T) {
	h := newSharedHarness(t)
	var peers []api.SnapshotPeer
	var ids []string
	for i := range 10 {
		id := fmt.Sprintf("peer-%d", i)
		ids = append(ids, id)
		peers = append(peers, routedPeer(id, fmt.Sprintf("10.99.0.%d", 10+i), byte(0x10+i)))
	}
	padded := append([]string{"peer-gone", ids[0], ids[0]}, ids[1:]...)

	h.mustPull(peers, entries(
		sharedEntry(sharedSubnet10_20, ids...),
		sharedEntry("10.30.0.0/16", padded...),
	), reconcile.StateDiff{PeersToAdd: peers})

	h.mgr.mu.Lock()
	defer h.mgr.mu.Unlock()
	for _, subnet := range []string{sharedSubnet10_20, "10.30.0.0/16"} {
		s, ok := h.mgr.shared[subnet]
		if !ok {
			t.Fatalf("no shared subnet %s", subnet)
		}
		if want := ids[:api.MaxSharedSubnetBridges]; !slices.Equal(s.bridges, want) {
			t.Errorf("bridges of %s = %v, want %v", subnet, s.bridges, want)
		}
		if s.holder != ids[0] {
			t.Errorf("holder of %s = %q, want %q", subnet, s.holder, ids[0])
		}
	}
	requireLogLine(t, h.logs.String(), "wireguard: shared subnet assigned",
		"subnet=10.20.0.0/16", "bridge=peer-0", "bridges=8")
}

// TestSharedSubnets_NilDesiredKeepsTheHolder proves "Call the handler with a
// nil desired while a subnet is held and read the holder unchanged and no
// write".
func TestSharedSubnets_NilDesiredKeepsTheHolder(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(), bridgeB(sharedSubnet10_20)}
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b")),
		reconcile.StateDiff{PeersToAdd: peers})
	h.requireHolder(sharedSubnet10_20, "peer-a")

	h.reset()
	if err := h.handler(context.Background(), nil, reconcile.StateDiff{}); err != nil {
		t.Fatalf("handler with a nil desired: %v", err)
	}

	if n := callCount(&h.ctrl.mockController); n != 0 {
		t.Errorf("calls with a nil desired = %d, want none", n)
	}
	for _, msg := range sharedSubnetLines {
		if lines := logLines(h.logs.String(), msg); len(lines) > 0 {
			t.Errorf("a nil desired logged %q:\n%s", msg, strings.Join(lines, "\n"))
		}
	}
	h.requireHolder(sharedSubnet10_20, "peer-a")
}

// TestSharedSubnets_FailedSyncWriteIsTriedAgain proves "Fail the AddPeer of
// syncSharedSubnets with an injected error and read it through errors.Is
// under wireguard: write routed subnets of peer from the handler; run the
// handler again and read one write and the same holder".
func TestSharedSubnets_FailedSyncWriteIsTriedAgain(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(), bridgeB()}
	h.mustPull(peers, nil, reconcile.StateDiff{PeersToAdd: peers})

	// The pull only adds the entry, so no peer entry changed and the one
	// write is the shared subnet step's.
	block := entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	addErr := errors.New("netlink: device busy")
	h.reset()
	h.ctrl.mu.Lock()
	h.ctrl.addPeerErr = addErr
	h.ctrl.mu.Unlock()

	err := h.pull(peers, block, reconcile.StateDiff{})
	if !errors.Is(err, addErr) {
		t.Fatalf("handler = %v, want it to wrap %v", err, addErr)
	}
	if want := "wireguard: write routed subnets of peer peer-a: "; !strings.Contains(err.Error(), want) {
		t.Errorf("handler error = %q, want it to contain %q", err, want)
	}
	requireLogLine(t, h.logs.String(), "reconcile: update peer failed",
		"level=ERROR", "component=wireguard", "peer_id=peer-a")
	h.mgr.mu.Lock()
	recorded := h.mgr.dial["peer-a"].peer
	h.mgr.mu.Unlock()
	if recorded.RoutedSubnets != nil || !slices.Equal(recorded.AllowedIPs, []string{"10.99.0.2/32"}) {
		t.Errorf("record after the failed write = %v %v, want it as it was", recorded.RoutedSubnets, recorded.AllowedIPs)
	}
	h.requireHolder(sharedSubnet10_20, "peer-a")

	h.reset()
	h.ctrl.mu.Lock()
	h.ctrl.addPeerErr = nil
	h.ctrl.mu.Unlock()
	h.mustPull(peers, block, reconcile.StateDiff{})

	h.requireWrites("add peer-a [10.99.0.2/32 10.20.0.0/16]")
	h.requireHolder(sharedSubnet10_20, "peer-a")
	for _, msg := range []string{"wireguard: shared subnet assigned", "wireguard: shared subnet moved"} {
		if lines := logLines(h.logs.String(), msg); len(lines) > 0 {
			t.Errorf("the run applied again logged %q:\n%s", msg, strings.Join(lines, "\n"))
		}
	}
}

// TestSharedSubnets_PSKWriteAndKeyRotationKeepTheSubnet proves "Call
// SetPeerPSK for the holder and read the subnet in the write; rotate the
// holder's public key and read the subnet on the new device peer".
func TestSharedSubnets_PSKWriteAndKeyRotationKeepTheSubnet(t *testing.T) {
	h := newSharedHarness(t)
	a, b := bridgeA(sharedSubnet10_20), bridgeB()
	block := entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.mustPull([]api.SnapshotPeer{a, b}, block, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{a, b}})

	h.reset()
	psk := bytes.Repeat([]byte{0x42}, 32)
	if err := h.mgr.SetPeerPSK("peer-a", a.PublicKey, psk); err != nil {
		t.Fatalf("SetPeerPSK: %v", err)
	}
	cfgs := addPeerConfigs(t, &h.ctrl.mockController)
	if len(cfgs) != 1 {
		t.Fatalf("AddPeer calls of the PSK write = %d, want 1", len(cfgs))
	}
	if want := []string{"10.99.0.2/32", sharedSubnet10_20}; !slices.Equal(cfgs[0].AllowedIPs, want) || !bytes.Equal(cfgs[0].PSK, psk) {
		t.Errorf("PSK write = %v with PSK %x, want %v with the PSK", cfgs[0].AllowedIPs, cfgs[0].PSK, want)
	}

	h.reset()
	rotated := routedPeer("peer-a", "10.99.0.2", 0x1a, sharedSubnet10_20)
	h.mustPull([]api.SnapshotPeer{rotated, b}, block, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{rotated}})

	h.requireWrites(
		"remove peer-a",
		"add key-1a [10.99.0.2/32 10.20.0.0/16]",
	)
	h.requireHolder(sharedSubnet10_20, "peer-a")
}

// TestSyncSharedSubnets_LeavesARecordOfAnotherKeyAlone rotates A's key in
// the pull that assigns it a shared subnet, and fails the removal of the old
// device peer, so UpdatePeer leaves A's record on the old key. The step must
// not write the subnet to the old key's device peer; the rotation applied
// again writes it to the new one.
func TestSyncSharedSubnets_LeavesARecordOfAnotherKeyAlone(t *testing.T) {
	h := newSharedHarness(t)
	b := bridgeB()
	h.mustPull([]api.SnapshotPeer{bridgeA(), b}, nil,
		reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{bridgeA(), b}})

	rotated := routedPeer("peer-a", "10.99.0.2", 0x1a)
	peers := []api.SnapshotPeer{rotated, b}
	block := entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	update := reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{rotated}}
	removeErr := errors.New("remove device peer: transient")
	h.reset()
	h.ctrl.mu.Lock()
	h.ctrl.removePeerErr = removeErr
	h.ctrl.mu.Unlock()

	if err := h.pull(peers, block, update); !errors.Is(err, removeErr) {
		t.Fatalf("rotation with a failing removal = %v, want it to wrap %v", err, removeErr)
	}
	h.requireWrites("remove peer-a")
	h.requireHolder(sharedSubnet10_20, "peer-a")

	h.reset()
	h.ctrl.mu.Lock()
	h.ctrl.removePeerErr = nil
	h.ctrl.mu.Unlock()
	h.mustPull(peers, block, update)
	h.requireWrites(
		"remove peer-a",
		"add key-1a [10.99.0.2/32 10.20.0.0/16]",
	)
}

// TestSharedSubnets_MeshPeerStatsNameTheHolder proves "Read
// MeshPeerStat.SharedSubnets sorted on the holder and nil on every other
// peer, and on the new holder after a move". The subnets sort by address,
// 10.4 before 10.20, and then by length.
func TestSharedSubnets_MeshPeerStatsNameTheHolder(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(), bridgeB(), bridgeC()}
	keyA, _ := testKey(0x0a)
	keyB, _ := testKey(0x0b)
	keyC, _ := testKey(0x0c)
	h.ctrl.stats = []PeerStat{{PublicKey: keyC}, {PublicKey: keyA}, {PublicKey: keyB}}

	block := entries(
		sharedEntry("10.30.0.0/16", "peer-a", "peer-b"),
		sharedEntry("10.20.0.0/24", "peer-a"),
		sharedEntry("10.4.0.0/16", "peer-a", "peer-c"),
		sharedEntry("10.20.0.0/16", "peer-a", "peer-b"),
	)
	h.mustPull(peers, block, reconcile.StateDiff{PeersToAdd: peers})

	requireStats := func(want map[string][]string) {
		t.Helper()
		stats, err := h.mgr.MeshPeerStats()
		if err != nil {
			t.Fatalf("MeshPeerStats: %v", err)
		}
		if len(stats) != 3 {
			t.Fatalf("MeshPeerStats() = %+v, want the three peers", stats)
		}
		for _, s := range stats {
			w := want[s.NodeID]
			if !slices.Equal(s.SharedSubnets, w) || (w == nil) != (s.SharedSubnets == nil) {
				t.Errorf("SharedSubnets of %s = %#v, want %#v", s.NodeID, s.SharedSubnets, w)
			}
		}
	}
	requireStats(map[string][]string{
		"peer-a": {"10.4.0.0/16", "10.20.0.0/16", "10.20.0.0/24", "10.30.0.0/16"},
	})

	block[0] = sharedEntry("10.30.0.0/16", "peer-b")
	h.mustPull(peers, block, reconcile.StateDiff{})
	requireStats(map[string][]string{
		"peer-a": {"10.4.0.0/16", "10.20.0.0/16", "10.20.0.0/24"},
		"peer-b": {"10.30.0.0/16"},
	})
}

// keyFailController is a statsController whose AddPeer, after recording the
// call, fails for the keys whose first byte fail maps to an error.
type keyFailController struct {
	*statsController
	fail map[byte]error
}

func (c *keyFailController) AddPeer(iface string, cfg PeerConfig) error {
	if err := c.statsController.AddPeer(iface, cfg); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fail[cfg.PublicKey[0]]
}

// setFail makes AddPeer fail with err for the key whose first byte is key,
// and succeed again for it when err is nil.
func (c *keyFailController) setFail(key byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail == nil {
		c.fail = make(map[byte]error)
	}
	c.fail[key] = err
}

// newKeyFailHarness returns a sharedHarness whose device fails AddPeer for
// the keys the returned controller names.
func newKeyFailHarness(t *testing.T) (*sharedHarness, *keyFailController) {
	t.Helper()
	h := &sharedHarness{t: t, ctrl: &statsController{}, logs: &bytes.Buffer{}}
	kc := &keyFailController{statsController: h.ctrl}
	h.mgr = setupMeshManager(t, kc, slogTextLogger(h.logs))
	h.mgr.SetPeerRouter(&mockRouter{ctrl: &h.ctrl.mockController})
	h.handler = ReconcileHandler(h.mgr, nil)
	return h, kc
}

// TestSyncSharedSubnets_KeepsTheSubnetUntilTheNewHolderHasIt: a pull moves
// the subnet from A to B, and B's write fails. A is not written without the
// subnet, so the device still carries it on A and its route stays, instead
// of carrying it on no peer. The next run writes B with it and then A
// without it.
func TestSyncSharedSubnets_KeepsTheSubnetUntilTheNewHolderHasIt(t *testing.T) {
	h, kc := newKeyFailHarness(t)
	peers := []api.SnapshotPeer{bridgeA(sharedSubnet10_20), bridgeB(), bridgeC()}
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b")),
		reconcile.StateDiff{PeersToAdd: peers})
	h.requireHolder(sharedSubnet10_20, "peer-a")

	addErr := errors.New("netlink: device busy")
	kc.setFail(0x0b, addErr)
	block := entries(sharedEntry(sharedSubnet10_20, "peer-b", "peer-c"))
	h.reset()
	err := h.pull(peers, block, reconcile.StateDiff{})
	if !errors.Is(err, addErr) {
		t.Fatalf("handler = %v, want it to wrap %v", err, addErr)
	}
	if want := "wireguard: write routed subnets of peer peer-b: "; !strings.Contains(err.Error(), want) {
		t.Errorf("handler error = %q, want it to contain %q", err, want)
	}
	h.requireWrites("add peer-b [10.99.0.3/32 10.20.0.0/16]")
	h.requireHolder(sharedSubnet10_20, "peer-b")
	if calls := routeCalls(&h.ctrl.mockController); slices.Contains(calls, "RemoveRoute 10.20.0.0/16 plexd0") {
		t.Errorf("route calls = %v, want the route kept while peer-a carries the subnet", calls)
	}

	kc.setFail(0x0b, nil)
	h.reset()
	h.mustPull(peers, block, reconcile.StateDiff{})
	h.requireWrites(
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
		"add peer-a [10.99.0.2/32]",
	)
}

// TestSyncSharedSubnets_NarrowsARecordThePullNoLongerLists: the pull drops
// the holder A, and its removal fails, so A stays on the device and in the
// manager. The step writes the new holder B with the subnet and then A
// without it, so endpoint selection, which writes A as recorded, cannot put
// the prefix back on A.
func TestSyncSharedSubnets_NarrowsARecordThePullNoLongerLists(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(sharedSubnet10_20), bridgeB()}
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b")),
		reconcile.StateDiff{PeersToAdd: peers})

	removeErr := errors.New("netlink: device busy")
	h.ctrl.mu.Lock()
	h.ctrl.removePeerErr = removeErr
	h.ctrl.mu.Unlock()
	h.reset()
	left := []api.SnapshotPeer{bridgeB()}
	err := h.pull(left, entries(sharedEntry(sharedSubnet10_20, "peer-b")),
		reconcile.StateDiff{PeersToRemove: []string{"peer-a"}})
	if !errors.Is(err, removeErr) {
		t.Fatalf("handler = %v, want it to wrap %v", err, removeErr)
	}
	h.requireWrites(
		"remove peer-a",
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
		"add peer-a [10.99.0.2/32]",
	)
	h.mgr.mu.Lock()
	recorded := h.mgr.dial["peer-a"].peer.RoutedSubnets
	h.mgr.mu.Unlock()
	if recorded != nil {
		t.Errorf("record of peer-a = %v, want no routed subnet", recorded)
	}
}

// TestSharedSubnets_FailedUpdateIsNotHalfApplied: an update the handler
// refuses, here for a mesh_ip that is not IPv4, leaves the peer as it was.
// The shared subnet step does not write the routed subnet the refused entry
// adds onto the recorded peer.
func TestSharedSubnets_FailedUpdateIsNotHalfApplied(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(), bridgeB()}
	h.mustPull(peers, nil, reconcile.StateDiff{PeersToAdd: peers})

	bad := bridgeA("10.30.0.0/16")
	bad.MeshIP = "fd00::2"
	h.reset()
	if err := h.pull([]api.SnapshotPeer{bad, bridgeB()}, nil,
		reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{bad}}); err == nil {
		t.Fatal("handler = nil, want the refused update's error")
	}
	h.requireWrites()
	if calls := routeCalls(&h.ctrl.mockController); len(calls) != 0 {
		t.Errorf("route calls = %v, want none for a refused update", calls)
	}
}

// TestSyncSharedSubnets_RewritesTheHolderAnotherRecordLists plants the
// records a move between snapshotPeer and UpdatePeer leaves (plan decision
// 1): the move wrote B with the subnet and made it the holder, and the
// update then wrote A back with it, so the device gave the prefix to A. The
// step writes B first, though its record already lists the subnet, and then
// A without it. A second run writes nothing.
func TestSyncSharedSubnets_RewritesTheHolderAnotherRecordLists(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(sharedSubnet10_20), bridgeB()}
	h.mustPull(peers, entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b")),
		reconcile.StateDiff{PeersToAdd: peers})
	h.requireHolder(sharedSubnet10_20, "peer-a")

	h.mgr.mu.Lock()
	h.mgr.shared[sharedSubnet10_20].holder = "peer-b"
	b := h.mgr.dial["peer-b"]
	b.peer.RoutedSubnets = []string{sharedSubnet10_20}
	b.peer.AllowedIPs = []string{"10.99.0.3/32", sharedSubnet10_20}
	if got := h.mgr.dial["peer-a"].peer.RoutedSubnets; !slices.Equal(got, []string{sharedSubnet10_20}) {
		h.mgr.mu.Unlock()
		t.Fatalf("record of peer-a = %v, want it to list the subnet", got)
	}
	h.mgr.mu.Unlock()

	h.reset()
	if err := h.mgr.syncSharedSubnets(peers, testMesh, nil); err != nil {
		t.Fatalf("syncSharedSubnets: %v", err)
	}
	h.requireWrites(
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
		"add peer-a [10.99.0.2/32]",
	)

	h.reset()
	if err := h.mgr.syncSharedSubnets(peers, testMesh, nil); err != nil {
		t.Fatalf("syncSharedSubnets again: %v", err)
	}
	h.requireWrites()
}
