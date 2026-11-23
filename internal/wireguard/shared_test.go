package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

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

// ---------------------------------------------------------------------------
// Shared subnets: the bridge watch
// ---------------------------------------------------------------------------

// The messages of the bridge watch's lines.
const (
	movedMsg      = "wireguard: shared subnet moved"
	noLiveMsg     = "wireguard: shared subnet has no live bridge"
	moveFailedMsg = "wireguard: shared subnet move failed"
	sendFailedMsg = "wireguard: bridge probe send failed"
)

// The mesh IPs of bridgeA, bridgeB and bridgeC.
const (
	meshA = "10.99.0.2"
	meshB = "10.99.0.3"
	meshC = "10.99.0.4"
)

// watchHandshake is the handshake the device reports for a bridge unless a
// test sets another: the fake clock's start, which stays fresh for 180 s.
var watchHandshake = selectionStart

// movesEveryPass is a receive counter that moves on every pass a second or
// more apart.
func movesEveryPass(after time.Duration) uint64 { return 100 + uint64(after/time.Second) }

// watchHarness is a sharedHarness on newSelectionManager's fake clock, for
// the bridge watch. Its manager's mesh prefix is testMesh and its relay probe
// is probe. A pass reports to the manager each bridge rx holds a counter for,
// with that counter, its handshake and its device endpoint.
type watchHarness struct {
	*sharedHarness
	clock *fakeClock
	probe *fakeProbe

	// peers are the bridges as a pull carries them, in the order add added
	// them.
	peers []api.SnapshotPeer
	// rx gives the receive counter the device reports for a bridge at a pass
	// at selectionStart plus after. The device does not report a bridge
	// without one.
	rx map[string]func(after time.Duration) uint64
	// handshake is the LastHandshake the device reports for a bridge,
	// watchHandshake for one without an entry.
	handshake map[string]time.Time
	// via is the device endpoint the device reports for each bridge.
	via map[string]netip.AddrPort
}

// newWatchHarness returns a watchHarness whose manager holds the
// failure-detection time d, none for 0, and tracks peers as bridges on a
// direct endpoint (see add).
func newWatchHarness(t *testing.T, d time.Duration, peers ...api.SnapshotPeer) *watchHarness {
	t.Helper()
	logs := &bytes.Buffer{}
	mgr, ctrl, clock := newSelectionManager(Config{}, logs)
	mgr.meshPrefix = testMesh
	h := &watchHarness{
		sharedHarness: &sharedHarness{t: t, ctrl: ctrl, mgr: mgr, logs: logs, handler: ReconcileHandler(mgr, nil)},
		clock:         clock,
		probe:         &fakeProbe{},
		rx:            make(map[string]func(time.Duration) uint64),
		handshake:     make(map[string]time.Time),
		via:           make(map[string]netip.AddrPort),
	}
	if d > 0 {
		if _, changed := mgr.SetFailureDetection(d); !changed {
			t.Fatalf("SetFailureDetection(%v) changed nothing", d)
		}
	}
	mgr.SetRelayProbe(h.probe.send)
	for _, p := range peers {
		h.add(p, nil)
	}
	return h
}

// add makes p a peer the manager tracks, as a pull that predates the shared
// subnets wrote it: directEndpoint as its one endpoint, and its
// routed_subnets as its routed subnets. mutate, when not nil, edits the peer
// before it is added.
func (h *watchHarness) add(p api.SnapshotPeer, mutate func(*api.Peer)) {
	h.t.Helper()
	peer := api.Peer{
		ID:            p.NodeID,
		PublicKey:     p.PublicKey,
		MeshIP:        p.MeshIP,
		AllowedIPs:    peerAllowedIPs(netip.MustParseAddr(p.MeshIP), p.RoutedSubnets),
		RoutedSubnets: p.RoutedSubnets,
		Endpoint:      directEndpoint.String(),
		Endpoints:     []string{directEndpoint.String()},
	}
	if mutate != nil {
		mutate(&peer)
	}
	if err := h.mgr.AddPeer(peer); err != nil {
		h.t.Fatalf("AddPeer(%s): %v", p.NodeID, err)
	}
	h.peers = append(h.peers, p)
	h.via[p.NodeID] = netip.MustParseAddrPort(peer.Endpoint)
}

// share applies a pull's shared_subnets block at selectionStart plus after,
// with the bridges as the pull's peers, as the reconcile handler's two steps
// apply it.
func (h *watchHarness) share(after time.Duration, block ...api.NodeStateSharedSubnet) {
	h.t.Helper()
	h.clock.Set(selectionStart.Add(after))
	h.mgr.setSharedSubnets(block, h.peers, testMesh, nil)
	if err := h.mgr.syncSharedSubnets(h.peers, testMesh, nil); err != nil {
		h.t.Fatalf("syncSharedSubnets: %v", err)
	}
}

// pass runs a selection pass at selectionStart plus after.
func (h *watchHarness) pass(after time.Duration) error {
	h.t.Helper()
	var stats []PeerStat
	for _, p := range h.peers {
		rx, ok := h.rx[p.NodeID]
		if !ok {
			continue
		}
		key, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil || len(key) != 32 {
			h.t.Fatalf("public key of %s: %q", p.NodeID, p.PublicKey)
		}
		handshake, ok := h.handshake[p.NodeID]
		if !ok {
			handshake = watchHandshake
		}
		stats = append(stats, PeerStat{
			PublicKey:     [32]byte(key),
			Endpoint:      h.via[p.NodeID],
			LastHandshake: handshake,
			RxBytes:       rx(after),
		})
	}
	h.ctrl.stats = stats
	h.clock.Set(selectionStart.Add(after))
	return h.mgr.selectEndpoints()
}

// mustPass is pass for a pass that must succeed.
func (h *watchHarness) mustPass(after time.Duration) {
	h.t.Helper()
	if err := h.pass(after); err != nil {
		h.t.Fatalf("selectEndpoints at %v: %v", after, err)
	}
}

// passes runs a pass at from and every second after it, up to and including
// until.
func (h *watchHarness) passes(from, until time.Duration) {
	h.t.Helper()
	for after := from; after <= until; after += time.Second {
		h.mustPass(after)
	}
}

// lines returns how many lines with msg were logged since the last reset.
func (h *watchHarness) lines(msg string) int {
	return len(logLines(h.logs.String(), msg))
}

// requireNoMove fails the test unless no bridge_dead move was logged since
// the last reset and the holder of the subnet is still holder.
func (h *watchHarness) requireNoMove(when, holder string) {
	h.t.Helper()
	if lines := logLines(h.logs.String(), movedMsg); len(lines) > 0 {
		h.t.Fatalf("%s: logged a move:\n%s", when, strings.Join(lines, "\n"))
	}
	h.requireHolder(sharedSubnet10_20, holder)
}

// openEcho gives the round-trip probe a fake socket, which the bridge watch
// writes its requests on, and returns it.
func (h *watchHarness) openEcho() *fakeRTTConn {
	conn := newFakeRTTConn()
	h.mgr.rtt.mu.Lock()
	defer h.mgr.rtt.mu.Unlock()
	h.mgr.rtt.conn = conn
	return conn
}

// prove gives the peer id a round-trip time, as an answered probe leaves it.
func (h *watchHarness) prove(id string) {
	h.mgr.rtt.mu.Lock()
	defer h.mgr.rtt.mu.Unlock()
	h.mgr.rtt.entry(id).value = 3 * time.Millisecond
}

// dialState returns a copy of the dial state of id, read under mu.
func (h *watchHarness) dialState(id string) dialState {
	h.t.Helper()
	h.mgr.mu.Lock()
	defer h.mgr.mu.Unlock()
	st, ok := h.mgr.dial[id]
	if !ok {
		h.t.Fatalf("no dial state for %s", id)
	}
	return *st
}

// probesTo returns how many relay probes p sent to meshIP.
func probesTo(p *fakeProbe, meshIP string) int {
	ip := netip.MustParseAddr(meshIP)
	n := 0
	for _, sent := range p.sent {
		if sent == ip {
			n++
		}
	}
	return n
}

// requestsTo returns the datagrams conn carried to UDP port RTTProbePort of
// meshIP.
func requestsTo(conn *fakeRTTConn, meshIP string) [][]byte {
	to := netip.AddrPortFrom(netip.MustParseAddr(meshIP), RTTProbePort).String()
	var datagrams [][]byte
	for _, w := range conn.sent() {
		if w.to.String() == to {
			datagrams = append(datagrams, w.b)
		}
	}
	return datagrams
}

// TestWatchBridges_DeadHolderMovesOneWindowAfterItsLastPacket proves "Hold
// 15 s, stop the holder's RxBytes while the standby's move, and read no move
// 13 s after the last change and moved with reason=bridge_dead, window=14s
// and both peer IDs on the first pass at 14 s or later", and "Read
// MeshPeerStat.SharedSubnets ... on the new holder after a move" for a
// bridge_dead move. Neither bridge answers a round-trip probe, so each gets
// the discard probe on every pass. The move writes B with the subnet before
// A without it, each without an endpoint, so the device keeps its own.
func TestWatchBridges_DeadHolderMovesOneWindowAfterItsLastPacket(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
	h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.requireHolder(sharedSubnet10_20, "peer-a")
	h.rx["peer-a"] = movesUntil(10 * time.Second)
	h.rx["peer-b"] = movesEveryPass
	h.reset()

	h.passes(time.Second, 23*time.Second)
	h.requireNoMove("13 s after A's last packet", "peer-a")
	h.requireWrites()

	h.mustPass(24 * time.Second)
	requireLogLine(t, h.logs.String(), movedMsg, "level=INFO", "component=wireguard", "subnet=10.20.0.0/16",
		"from=peer-a", "to=peer-b", "reason=bridge_dead", "silent_for=14s", "window=14s")
	h.requireHolder(sharedSubnet10_20, "peer-b")
	h.requireWrites(
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
		"add peer-a [10.99.0.2/32]",
	)
	for _, cfg := range addPeerConfigs(t, &h.ctrl.mockController) {
		if cfg.Endpoint != "" {
			t.Errorf("a move write carries endpoint %q, want none so the device keeps its own", cfg.Endpoint)
		}
	}
	if a, b := probesTo(h.probe, meshA), probesTo(h.probe, meshB); a != 24 || b != 24 {
		t.Errorf("discard probes over 24 passes: A %d, B %d, want 24 each", a, b)
	}

	stats, err := h.mgr.MeshPeerStats()
	if err != nil {
		t.Fatalf("MeshPeerStats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("MeshPeerStats() = %+v, want the two bridges", stats)
	}
	for _, s := range stats {
		var want []string
		if s.NodeID == "peer-b" {
			want = []string{sharedSubnet10_20}
		}
		if !slices.Equal(s.SharedSubnets, want) || (want == nil) != (s.SharedSubnets == nil) {
			t.Errorf("SharedSubnets of %s after the move = %#v, want %#v", s.NodeID, s.SharedSubnets, want)
		}
	}

	h.passes(25*time.Second, 40*time.Second)
	if n := h.lines(movedMsg); n != 1 {
		t.Errorf("moved lines after 16 more passes = %d, want 1: B is alive", n)
	}
	h.requireHolder(sharedSubnet10_20, "peer-b")
}

// TestWatchBridges_RoundTripTimeDecidesTheWindow proves "Hold 5 s with RTT
// zero on the holder and read no move before 14 s; with RTT above zero and an
// echo socket, read the move after 4 s, a 16-byte PXRT request written to the
// socket on each pass, and no call of the discard probe for that peer", and
// "Hold 5 s with RTT above zero and no echo socket and read window=14s and
// the discard probe". A's last packet arrives at the pass at 10 s.
func TestWatchBridges_RoundTripTimeDecidesTheWindow(t *testing.T) {
	setup := func(t *testing.T, echo, rtt bool) (*watchHarness, *fakeRTTConn) {
		t.Helper()
		h := newWatchHarness(t, 5*time.Second, bridgeA(), bridgeB())
		var conn *fakeRTTConn
		if echo {
			conn = h.openEcho()
		}
		if rtt {
			h.prove("peer-a")
		}
		h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
		h.rx["peer-a"] = movesUntil(10 * time.Second)
		h.rx["peer-b"] = movesEveryPass
		h.reset()
		return h, conn
	}

	t.Run("RTT zero with an echo socket", func(t *testing.T) {
		h, conn := setup(t, true, false)
		h.passes(time.Second, 23*time.Second)
		h.requireNoMove("13 s after A's last packet", "peer-a")
		h.mustPass(24 * time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead",
			"silent_for=14s", "window=14s")
		if n := probesTo(h.probe, meshA); n != 24 {
			t.Errorf("discard probes to A over 24 passes = %d, want 24", n)
		}
		if n := len(requestsTo(conn, meshA)); n != 0 {
			t.Errorf("round-trip requests to A = %d, want none without a round-trip time", n)
		}
	})

	t.Run("RTT above zero with an echo socket", func(t *testing.T) {
		h, conn := setup(t, true, true)
		nonces := make(map[string]bool)
		for after := time.Second; after <= 14*time.Second; after += time.Second {
			h.mustPass(after)
			requests := requestsTo(conn, meshA)
			if want := int(after / time.Second); len(requests) != want {
				t.Fatalf("round-trip requests to A after the pass at %v = %d, want %d, one per pass", after, len(requests), want)
			}
			b := requests[len(requests)-1]
			if len(b) != 16 || string(b[:4]) != "PXRT" || b[4] != rttVersion || b[5] != rttKindRequest || b[6] != 0 || b[7] != 0 {
				t.Fatalf("request at %v = %x, want a 16-byte PXRT request", after, b)
			}
			nonces[string(b[8:])] = true
			if after == 13*time.Second {
				h.requireNoMove("3 s after A's last packet", "peer-a")
			}
		}
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead",
			"silent_for=4s", "window=4s")
		h.requireHolder(sharedSubnet10_20, "peer-b")
		if len(nonces) != 14 {
			t.Errorf("distinct nonces over 14 requests = %d, want 14", len(nonces))
		}
		if n := probesTo(h.probe, meshA); n != 0 {
			t.Errorf("discard probes to A = %d, want none to a proven bridge", n)
		}
		if n := probesTo(h.probe, meshB); n != 14 {
			t.Errorf("discard probes to B, which holds no round-trip time, = %d, want 14", n)
		}
	})

	t.Run("RTT above zero without an echo socket", func(t *testing.T) {
		h, _ := setup(t, false, true)
		h.passes(time.Second, 23*time.Second)
		h.requireNoMove("13 s after A's last packet", "peer-a")
		h.mustPass(24 * time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead",
			"silent_for=14s", "window=14s")
		if n := probesTo(h.probe, meshA); n != 24 {
			t.Errorf("discard probes to A over 24 passes = %d, want 24", n)
		}
	})
}

// TestWatchBridges_RelayedBridgeGetsOneProbePerPass proves "Watch a relayed
// bridge and read one discard probe per pass, not two": watchRelay probes the
// relayed holder, and the watch sends it none of its own. The pass that turns
// A connected runs no watchRelay, so A's probes start with the pass after it.
func TestWatchBridges_RelayedBridgeGetsOneProbePerPass(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second)
	relay := relayOrder[1]
	h.add(bridgeA(), func(p *api.Peer) {
		p.Endpoint = relay
		p.Endpoints = []string{relay}
		p.Fallbacks = []string{relay}
	})
	h.add(bridgeB(), nil)
	h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.rx["peer-a"] = movesEveryPass
	h.rx["peer-b"] = movesEveryPass

	h.mustPass(time.Second)
	if st := h.dialState("peer-a"); !st.connected || !st.relayed {
		t.Fatalf("A after the first pass: connected %v, relayed %v, want both", st.connected, st.relayed)
	}
	if n := probesTo(h.probe, meshA); n != 0 {
		t.Fatalf("probes to A after the pass that turned it connected = %d, want 0", n)
	}
	for after := 2 * time.Second; after <= 20*time.Second; after += time.Second {
		h.mustPass(after)
		if got, want := probesTo(h.probe, meshA), int(after/time.Second)-1; got != want {
			t.Fatalf("probes to the relayed A after the pass at %v = %d, want %d, one per pass", after, got, want)
		}
	}
	if n := probesTo(h.probe, meshB); n != 20 {
		t.Errorf("probes to B over 20 passes = %d, want 20", n)
	}
	h.requireNoMove("over 20 passes", "peer-a")
}

// TestWatchBridges_NoLiveBridgeIsLoggedOnce proves "Stop every bridge and
// read the subnet unmoved and has no live bridge once over 30 passes; revive
// and stop the holder again and read the line a second time". Both bridges'
// last packets arrive at the pass at 5 s; A's come back at 51 s to 53 s.
func TestWatchBridges_NoLiveBridgeIsLoggedOnce(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
	h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.rx["peer-a"] = func(after time.Duration) uint64 {
		if after < 51*time.Second {
			return movesUntil(5 * time.Second)(after)
		}
		return 1000 + movesUntil(53*time.Second)(after)
	}
	h.rx["peer-b"] = movesUntil(5 * time.Second)
	h.reset()

	h.passes(time.Second, 18*time.Second)
	if n := h.lines(noLiveMsg); n != 0 {
		t.Fatalf("no live bridge lines 13 s after the last packets = %d, want 0", n)
	}
	h.mustPass(19 * time.Second)
	requireLogLine(t, h.logs.String(), noLiveMsg, "level=WARN", "component=wireguard", "subnet=10.20.0.0/16",
		"bridge=peer-a", "silent_for=14s", "window=14s")

	h.passes(20*time.Second, 50*time.Second)
	if n := h.lines(noLiveMsg); n != 1 {
		t.Errorf("no live bridge lines over the 32 passes from 19 s to 50 s = %d, want 1", n)
	}
	h.requireNoMove("with every bridge dead", "peer-a")
	h.requireWrites()

	h.passes(51*time.Second, 66*time.Second)
	if n := h.lines(noLiveMsg); n != 1 {
		t.Fatalf("no live bridge lines 13 s after A's return = %d, want 1", n)
	}
	h.mustPass(67 * time.Second)
	if n := h.lines(noLiveMsg); n != 2 {
		t.Fatalf("no live bridge lines once A stopped again = %d, want 2", n)
	}
	h.requireNoMove("with every bridge dead again", "peer-a")
	h.requireWrites()
}

// TestWatchBridges_ReturningBridgeStaysStandby proves "Revive the old holder
// after a move and read the subnet on the new holder after 60 more passes and
// after a pull that lists the old holder first". A's last packet arrives at
// the pass at 5 s, the move follows at 19 s, and A's counter moves again on
// every pass from 20 s on.
func TestWatchBridges_ReturningBridgeStaysStandby(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
	block := entries(sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.share(0, block...)
	h.rx["peer-a"] = func(after time.Duration) uint64 {
		if after < 20*time.Second {
			return movesUntil(5 * time.Second)(after)
		}
		return 1000 + movesEveryPass(after)
	}
	h.rx["peer-b"] = movesEveryPass

	h.passes(time.Second, 19*time.Second)
	requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead")
	h.requireHolder(sharedSubnet10_20, "peer-b")

	h.reset()
	h.passes(20*time.Second, 79*time.Second)
	h.requireNoMove("over 60 passes with A alive again", "peer-b")
	h.requireWrites()
	if at := h.dialState("peer-a").aliveAt; !at.Equal(selectionStart.Add(79 * time.Second)) {
		t.Fatalf("A's path last alive at %v, want the pass at 79 s: the test needs A back", at)
	}

	h.clock.Set(selectionStart.Add(80 * time.Second))
	h.mustPull(h.peers, block, reconcile.StateDiff{})
	h.requireNoMove("after a pull that lists A first", "peer-b")
	h.requireWrites()

	h.passes(81*time.Second, 100*time.Second)
	h.requireNoMove("20 passes after the pull", "peer-b")
	h.requireWrites()
}

// TestWatchBridges_MovesToTheNextLiveBridgeWrappingAround proves "Hold
// bridges A, B, C with the subnet on C, stop C and B, and read the move to
// A". C holds the subnet because its routed_subnets list it. A second case
// moves the subnet from A past the dead B to C.
func TestWatchBridges_MovesToTheNextLiveBridgeWrappingAround(t *testing.T) {
	t.Run("from the last bridge to the first", func(t *testing.T) {
		h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB(), bridgeC(sharedSubnet10_20))
		h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b", "peer-c"))
		h.requireHolder(sharedSubnet10_20, "peer-c")
		h.rx["peer-a"] = movesEveryPass
		h.rx["peer-b"] = movesUntil(5 * time.Second)
		h.rx["peer-c"] = movesUntil(5 * time.Second)
		h.reset()

		h.passes(time.Second, 19*time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-c", "to=peer-a", "reason=bridge_dead")
		h.requireHolder(sharedSubnet10_20, "peer-a")
		h.requireWrites(
			"add peer-a [10.99.0.2/32 10.20.0.0/16]",
			"add peer-c [10.99.0.4/32]",
		)
	})

	t.Run("past a dead bridge", func(t *testing.T) {
		h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB(), bridgeC())
		h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b", "peer-c"))
		h.requireHolder(sharedSubnet10_20, "peer-a")
		h.rx["peer-a"] = movesUntil(5 * time.Second)
		h.rx["peer-b"] = movesUntil(5 * time.Second)
		h.rx["peer-c"] = movesEveryPass
		h.reset()

		h.passes(time.Second, 19*time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-c", "reason=bridge_dead")
		h.requireHolder(sharedSubnet10_20, "peer-c")
	})
}

// TestWatchBridges_FailedMoveIsTriedOnTheNextPass proves "Fail the first
// write of a move with an injected error and read move failed, the holder
// unchanged, and the error through errors.Is under wireguard: move shared
// subnet from selectEndpoints; read the move on the next pass".
func TestWatchBridges_FailedMoveIsTriedOnTheNextPass(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
	h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.rx["peer-a"] = movesUntil(5 * time.Second)
	h.rx["peer-b"] = movesEveryPass
	h.passes(time.Second, 18*time.Second)

	addErr := errors.New("add-refused")
	h.reset()
	h.ctrl.mu.Lock()
	h.ctrl.addPeerErr = addErr
	h.ctrl.mu.Unlock()
	err := h.pass(19 * time.Second)
	if !errors.Is(err, addErr) {
		t.Fatalf("selectEndpoints = %v, want it to wrap %v", err, addErr)
	}
	if want := "wireguard: move shared subnet 10.20.0.0/16 to peer peer-b: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("selectEndpoints error = %q, want it to start with %q", err, want)
	}
	requireLogLine(t, h.logs.String(), moveFailedMsg, "level=WARN", "component=wireguard", "subnet=10.20.0.0/16",
		"from=peer-a", "to=peer-b", "error=add-refused")
	h.requireNoMove("after the failed write", "peer-a")
	h.requireWrites("add peer-b [10.99.0.3/32 10.20.0.0/16]")
	if b := h.dialState("peer-b").peer; b.RoutedSubnets != nil || !slices.Equal(b.AllowedIPs, []string{"10.99.0.3/32"}) {
		t.Errorf("record of B after the failed write = %v %v, want it as it was", b.RoutedSubnets, b.AllowedIPs)
	}

	h.reset()
	h.ctrl.mu.Lock()
	h.ctrl.addPeerErr = nil
	h.ctrl.mu.Unlock()
	h.mustPass(20 * time.Second)
	requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead", "silent_for=15s")
	h.requireHolder(sharedSubnet10_20, "peer-b")
	h.requireWrites(
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
		"add peer-a [10.99.0.2/32]",
	)
}

// TestMoveSharedSubnet_FailedSecondWriteRecordsTheMove proves "Fail the
// second write of a move and read move failed, the new holder recorded, and
// nil from moveSharedSubnet". Each bridge has a routed subnet of its own and
// B holds a second shared subnet, so the writes show a peer's routed subnets
// as its own, in order, followed by the shared subnets it holds, sorted.
func TestMoveSharedSubnet_FailedSecondWriteRecordsTheMove(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA("10.50.0.0/16"), bridgeB("10.40.0.0/16"))
	h.share(0,
		sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"),
		sharedEntry("10.30.0.0/16", "peer-b", "peer-a"),
	)
	h.requireHolder(sharedSubnet10_20, "peer-a")
	h.requireHolder("10.30.0.0/16", "peer-b")

	addErr := errors.New("add-refused")
	h.mgr.ctrl = &addHookController{statsController: h.ctrl, onAdd: func(cfg PeerConfig) {
		if sharedPeerName(cfg.PublicKey) == "peer-b" {
			h.ctrl.mu.Lock()
			h.ctrl.addPeerErr = addErr
			h.ctrl.mu.Unlock()
		}
	}}
	h.reset()
	movedAt := selectionStart.Add(30 * time.Second)
	h.mgr.mu.Lock()
	h.mgr.shared[sharedSubnet10_20].stuck = true
	err := h.mgr.moveSharedSubnet(sharedSubnet10_20, "peer-a", "peer-b", movedAt)
	s := *h.mgr.shared[sharedSubnet10_20]
	h.mgr.mu.Unlock()

	if err != nil {
		t.Fatalf("moveSharedSubnet with a failed second write = %v, want nil", err)
	}
	h.requireWrites(
		"add peer-b [10.99.0.3/32 10.40.0.0/16 10.20.0.0/16 10.30.0.0/16]",
		"add peer-a [10.99.0.2/32 10.50.0.0/16]",
	)
	requireLogLine(t, h.logs.String(), moveFailedMsg, "level=WARN", "component=wireguard", "subnet=10.20.0.0/16",
		"from=peer-a", "to=peer-b", "error=add-refused")
	if s.holder != "peer-b" || !s.since.Equal(movedAt) || s.stuck {
		t.Errorf("record of the subnet = holder %q since %v stuck %v, want peer-b since %v, not stuck", s.holder, s.since, s.stuck, movedAt)
	}
	if a := h.dialState("peer-a").peer; !slices.Equal(a.RoutedSubnets, []string{"10.50.0.0/16"}) ||
		!slices.Equal(a.AllowedIPs, []string{"10.99.0.2/32", "10.50.0.0/16"}) {
		t.Errorf("record of A = %v %v, want it without the subnet the device moved off it", a.RoutedSubnets, a.AllowedIPs)
	}
	if b := h.dialState("peer-b").peer; !slices.Equal(b.RoutedSubnets, []string{"10.40.0.0/16", sharedSubnet10_20, "10.30.0.0/16"}) {
		t.Errorf("routed subnets of B = %v, want its own followed by the two it holds", b.RoutedSubnets)
	}
	if n := h.lines(movedMsg); n != 0 {
		t.Errorf("moved lines = %d, want none: the caller logs the move", n)
	}
}

// TestWatchBridges_StatsReadErrorChangesNothing proves "Return an error from
// the stats read, and ErrPeerStatsUnsupported, and read it unchanged from
// selectEndpoints with no probe sent and no holder changed". The holder A is
// dead for the time at the failing pass, and B gets round-trip requests.
func TestWatchBridges_StatsReadErrorChangesNothing(t *testing.T) {
	setup := func(t *testing.T) (*watchHarness, *fakeRTTConn) {
		t.Helper()
		h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
		conn := h.openEcho()
		h.prove("peer-b")
		h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
		h.rx["peer-a"] = movesUntil(5 * time.Second)
		h.rx["peer-b"] = movesEveryPass
		h.passes(time.Second, 18*time.Second)
		h.reset()
		return h, conn
	}
	requireUntouched := func(t *testing.T, h *watchHarness, conn *fakeRTTConn, probes, requests int) {
		t.Helper()
		if n := len(h.probe.sent); n != probes {
			t.Errorf("probes = %d, want the %d sent before the failing pass", n, probes)
		}
		if n := len(conn.sent()); n != requests {
			t.Errorf("round-trip requests = %d, want the %d written before the failing pass", n, requests)
		}
		h.requireNoMove("after the failing pass", "peer-a")
		h.requireWrites()
	}

	t.Run("read error", func(t *testing.T) {
		h, conn := setup(t)
		probes, requests := len(h.probe.sent), len(conn.sent())
		readErr := errors.New("dump-failed")
		h.ctrl.err = readErr
		err := h.pass(19 * time.Second)
		if !errors.Is(err, readErr) || err.Error() != "wireguard: mesh peer stats: dump-failed" {
			t.Fatalf("selectEndpoints = %v, want MeshPeerStats' error wireguard: mesh peer stats: dump-failed unchanged", err)
		}
		requireUntouched(t, h, conn, probes, requests)

		h.ctrl.err = nil
		h.mustPass(20 * time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead")
	})

	t.Run("ErrPeerStatsUnsupported", func(t *testing.T) {
		h, conn := setup(t)
		probes, requests := len(h.probe.sent), len(conn.sent())
		h.mgr.ctrl = &h.ctrl.mockController
		if err := h.pass(19 * time.Second); err != ErrPeerStatsUnsupported {
			t.Fatalf("selectEndpoints = %v, want ErrPeerStatsUnsupported unchanged", err)
		}
		requireUntouched(t, h, conn, probes, requests)
	})
}

// TestWatchBridges_FailedProbeSendIsNoVerdict proves "Fail the probe send and
// read bridge probe send failed at Debug and no move while the sends fail",
// for the discard probe and for the round-trip request. Once the sends go out
// again, the move follows one window after the last failed one.
func TestWatchBridges_FailedProbeSendIsNoVerdict(t *testing.T) {
	// failedFor returns the send failed lines for peer-a, and fails the test
	// unless each is at Debug and names err.
	failedFor := func(t *testing.T, h *watchHarness, err string) int {
		t.Helper()
		n := 0
		for _, line := range logLines(h.logs.String(), sendFailedMsg) {
			if !strings.Contains(line, "peer_id=peer-a") {
				continue
			}
			words := strings.Fields(line)
			for _, f := range []string{"level=DEBUG", "component=wireguard", "error=" + err} {
				if !slices.Contains(words, f) {
					t.Errorf("send failed line %q lacks %s", line, f)
				}
			}
			n++
		}
		return n
	}

	t.Run("discard probe", func(t *testing.T) {
		h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
		h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
		h.rx["peer-a"] = movesUntil(5 * time.Second)
		h.rx["peer-b"] = movesEveryPass
		h.probe.err = errors.New("probe-refused")
		h.reset()

		h.passes(time.Second, 60*time.Second)
		h.requireNoMove("over 60 passes of failed sends", "peer-a")
		if n := failedFor(t, h, "probe-refused"); n != 60 {
			t.Errorf("send failed lines for A over 60 passes = %d, want 60", n)
		}

		h.probe.err = nil
		h.passes(61*time.Second, 73*time.Second)
		h.requireNoMove("13 s after the last failed send", "peer-a")
		h.mustPass(74 * time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead", "silent_for=14s")
	})

	t.Run("round-trip request", func(t *testing.T) {
		h := newWatchHarness(t, 5*time.Second, bridgeA(), bridgeB())
		conn := h.openEcho()
		h.prove("peer-a")
		to := netip.AddrPortFrom(netip.MustParseAddr(meshA), RTTProbePort).String()
		conn.failWritesTo(to, errors.New("sendto-refused"))
		h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
		h.rx["peer-a"] = movesUntil(5 * time.Second)
		h.rx["peer-b"] = movesEveryPass
		h.reset()

		h.passes(time.Second, 30*time.Second)
		h.requireNoMove("over 30 passes of failed writes", "peer-a")
		if n := failedFor(t, h, "sendto-refused"); n != 30 {
			t.Errorf("send failed lines for A over 30 passes = %d, want 30", n)
		}

		conn.failWritesTo(to, nil)
		h.passes(31*time.Second, 33*time.Second)
		h.requireNoMove("3 s after the last failed write", "peer-a")
		h.mustPass(34 * time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead",
			"silent_for=4s", "window=4s")
	})

	// watchRelay sends the probe of a relayed bridge and logs its failure;
	// the watch reads that the last one never left.
	t.Run("relayed bridge", func(t *testing.T) {
		h := newWatchHarness(t, 15*time.Second)
		relay := relayOrder[1]
		h.add(bridgeA(), func(p *api.Peer) {
			p.Endpoint = relay
			p.Endpoints = []string{relay}
			p.Fallbacks = []string{relay}
		})
		h.add(bridgeB(), nil)
		h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
		h.rx["peer-a"] = movesUntil(5 * time.Second)
		h.rx["peer-b"] = movesEveryPass
		h.probe.err = errors.New("probe-refused")
		h.reset()

		h.passes(time.Second, 60*time.Second)
		h.requireNoMove("over 60 passes of failed relay probes", "peer-a")
		if n := failedFor(t, h, "probe-refused"); n != 0 {
			t.Errorf("bridge probe send failed lines for the relayed A = %d, want none: watchRelay sent its probes", n)
		}
		requireLogLine(t, h.logs.String(), "wireguard: relay probe send failed", "peer_id=peer-a")

		h.probe.err = nil
		h.passes(61*time.Second, 73*time.Second)
		h.requireNoMove("13 s after the last failed relay probe", "peer-a")
		h.mustPass(74 * time.Second)
		requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead", "silent_for=14s")
	})
}

// TestWatchBridges_NoFailureDetectionTimeMovesNothing proves "Hold no
// failure-detection time and read no probe and no move after the holder's
// handshake went stale". B rekeys at 150 s and stays connected; A's
// handshake goes stale at 180 s.
func TestWatchBridges_NoFailureDetectionTimeMovesNothing(t *testing.T) {
	h := newWatchHarness(t, 0, bridgeA(), bridgeB())
	h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.rx["peer-a"] = movesUntil(5 * time.Second)
	h.rx["peer-b"] = movesEveryPass
	h.reset()

	for after := EndpointSelectionInterval; after <= 300*time.Second; after += EndpointSelectionInterval {
		if after >= 150*time.Second {
			h.handshake["peer-b"] = selectionStart.Add(150 * time.Second)
		}
		h.mustPass(after)
	}
	if st := h.dialState("peer-a"); st.connected {
		t.Fatalf("A still connected at 300 s, want its handshake stale")
	}
	if st := h.dialState("peer-b"); !st.connected {
		t.Fatalf("B not connected at 300 s, want it connected")
	}
	if len(h.probe.sent) != 0 {
		t.Errorf("probes = %v, want none without a failure-detection time", h.probe.sent)
	}
	h.requireNoMove("without a failure-detection time", "peer-a")
	for _, msg := range sharedSubnetLines {
		if lines := logLines(h.logs.String(), msg); len(lines) > 0 {
			t.Errorf("without a failure-detection time logged %q:\n%s", msg, strings.Join(lines, "\n"))
		}
	}
	h.requireWrites()
}

// TestWatchBridges_EntryForALongSilentPeerWaitsOneWindow proves "Add an
// entry for a peer whose RxBytes last moved an hour ago and read no move
// before one window after the pull". A has been connected for an hour, with
// a counter that never moved and a handshake its rekeys keep fresh. The pull
// restarts its window. The first pass after the pull reads a counter the
// watch had not read before, which counts as alive, so the move follows one
// window after that pass.
func TestWatchBridges_EntryForALongSilentPeerWaitsOneWindow(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
	h.rx["peer-a"] = still
	h.rx["peer-b"] = movesEveryPass
	for after := time.Minute; after <= time.Hour; after += time.Minute {
		h.handshake["peer-a"] = selectionStart.Add(after - 30*time.Second)
		h.handshake["peer-b"] = selectionStart.Add(after - 30*time.Second)
		h.mustPass(after)
	}

	h.share(time.Hour, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.requireHolder(sharedSubnet10_20, "peer-a")
	h.reset()
	h.passes(time.Hour+time.Second, time.Hour+14*time.Second)
	h.requireNoMove("14 s after the pull", "peer-a")
	h.mustPass(time.Hour + 15*time.Second)
	requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead",
		"silent_for=14s", "window=14s")
}

// TestWatchBridges_FailureDetectionChangeRestartsTheWindow proves "Change the
// failure-detection time and read no move before one window of the new
// value". A answers round-trip probes, so its window is 14 s under 15 s and
// 4 s under 5 s. Its last packet arrives at the pass at 5 s, and the change
// to 5 s comes at 15 s.
func TestWatchBridges_FailureDetectionChangeRestartsTheWindow(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
	h.openEcho()
	h.prove("peer-a")
	h.share(0, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	h.rx["peer-a"] = movesUntil(5 * time.Second)
	h.rx["peer-b"] = movesEveryPass

	h.passes(time.Second, 15*time.Second)
	h.requireNoMove("10 s after A's last packet under 15 s", "peer-a")
	if d, changed := h.mgr.SetFailureDetection(5 * time.Second); d != 5*time.Second || !changed {
		t.Fatalf("SetFailureDetection(5s) = %v, %v, want 5s, true", d, changed)
	}

	// Silent for 11 s at 16 s: past the 4 s window of 5 s, had the change not
	// restarted it.
	h.passes(16*time.Second, 18*time.Second)
	h.requireNoMove("3 s after the change", "peer-a")
	h.mustPass(19 * time.Second)
	requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=bridge_dead",
		"silent_for=4s", "window=4s")
}

// TestWatchBridges_FirstBridgeThatNeverConnectsLosesTheSubnet proves "Assign
// a subnet to a first bridge that never connects beside a live standby and
// read the move one window after the assignment". The device never reports
// A. A second case takes A's dial state away after the assignment: a holder
// without one counts from the assignment too, and the move writes B alone.
func TestWatchBridges_FirstBridgeThatNeverConnectsLosesTheSubnet(t *testing.T) {
	for _, tt := range []struct {
		name      string
		dialState bool
		writes    []string
	}{
		{"never connected", true, []string{"add peer-b [10.99.0.3/32 10.20.0.0/16]", "add peer-a [10.99.0.2/32]"}},
		{"without a dial state", false, []string{"add peer-b [10.99.0.3/32 10.20.0.0/16]"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB())
			h.rx["peer-b"] = movesEveryPass
			h.mustPass(time.Second)
			h.share(2*time.Second, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
			h.requireHolder(sharedSubnet10_20, "peer-a")
			if !tt.dialState {
				h.mgr.mu.Lock()
				delete(h.mgr.dial, "peer-a")
				h.mgr.mu.Unlock()
			}
			h.reset()

			h.passes(3*time.Second, 15*time.Second)
			h.requireNoMove("13 s after the assignment", "peer-a")
			h.mustPass(16 * time.Second)
			requireLogLine(t, h.logs.String(), movedMsg, "level=INFO", "from=peer-a", "to=peer-b",
				"reason=bridge_dead", "silent_for=14s", "window=14s")
			h.requireHolder(sharedSubnet10_20, "peer-b")
			h.requireWrites(tt.writes...)
		})
	}
}

// TestSetSharedSubnets_RestartsTheWatchOfJoiningBridgesAndNewHolders pins
// which bridges a pull restarts the window of: a bridge that joins the
// watched peers, the holder of a new subnet, and the bridge a pull moves a
// subnet to. A bridge that was watched already and gets no subnet, and one
// that leaves the watched peers, keep theirs.
func TestSetSharedSubnets_RestartsTheWatchOfJoiningBridgesAndNewHolders(t *testing.T) {
	h := newWatchHarness(t, 15*time.Second, bridgeA(), bridgeB(), bridgeC())
	old := selectionStart.Add(-time.Hour)
	plant := func() {
		h.mgr.mu.Lock()
		defer h.mgr.mu.Unlock()
		for _, st := range h.mgr.dial {
			st.aliveAt, st.echoAt = old, old
		}
	}
	// requireWatch fails the test unless each bridge of want has its window
	// restarted at the time want names, or kept for old.
	requireWatch := func(when string, want map[string]time.Time) {
		t.Helper()
		for id, at := range want {
			st := h.dialState(id)
			if at.Equal(old) {
				if !st.aliveAt.Equal(old) || !st.echoAt.Equal(old) {
					t.Errorf("%s: window of %s restarted (aliveAt %v, echoAt %v), want it kept", when, id, st.aliveAt, st.echoAt)
				}
				continue
			}
			if !st.aliveAt.Equal(at) || !st.echoAt.IsZero() {
				t.Errorf("%s: %s has aliveAt %v and echoAt %v, want %v and zero", when, id, st.aliveAt, st.echoAt, at)
			}
		}
	}

	plant()
	h.share(time.Second, sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"))
	first := selectionStart.Add(time.Second)
	requireWatch("the first entry", map[string]time.Time{"peer-a": first, "peer-b": first, "peer-c": old})

	plant()
	h.share(2*time.Second,
		sharedEntry(sharedSubnet10_20, "peer-a", "peer-b"),
		sharedEntry("10.30.0.0/16", "peer-c", "peer-b"),
	)
	requireWatch("a second entry", map[string]time.Time{"peer-a": old, "peer-b": old, "peer-c": selectionStart.Add(2 * time.Second)})

	plant()
	h.reset()
	h.share(3*time.Second,
		sharedEntry(sharedSubnet10_20, "peer-b", "peer-c"),
		sharedEntry("10.30.0.0/16", "peer-c", "peer-b"),
	)
	requireLogLine(t, h.logs.String(), movedMsg, "from=peer-a", "to=peer-b", "reason=pull")
	requireWatch("a pull that moves the subnet", map[string]time.Time{"peer-a": old, "peer-b": selectionStart.Add(3 * time.Second), "peer-c": old})
}

// TestMoveSharedSubnet_AddsAndRemovesOnlyTheMovedSubnet plants what a move
// between snapshotPeer and UpdatePeer leaves (plan decision 1): 10.20.0.0/16
// went to B, and the update wrote A back with it. A move of 10.30.0.0/16 off
// A to C then writes C with it and A without it alone, so A keeps
// 10.20.0.0/16, which the device gave it; a move that dropped every shared
// subnet A does not hold would take that prefix off the device altogether.
// The shared subnet step then writes B first and A without 10.20.0.0/16.
func TestMoveSharedSubnet_AddsAndRemovesOnlyTheMovedSubnet(t *testing.T) {
	h := newSharedHarness(t)
	peers := []api.SnapshotPeer{bridgeA(), bridgeB(), bridgeC()}
	h.mustPull(peers, entries(
		sharedEntry("10.20.0.0/16", "peer-a", "peer-b"),
		sharedEntry("10.30.0.0/16", "peer-a", "peer-c"),
	), reconcile.StateDiff{PeersToAdd: peers})

	h.mgr.mu.Lock()
	h.mgr.shared["10.20.0.0/16"].holder = "peer-b"
	b := h.mgr.dial["peer-b"]
	b.peer.RoutedSubnets = []string{"10.20.0.0/16"}
	b.peer.AllowedIPs = []string{"10.99.0.3/32", "10.20.0.0/16"}
	h.mgr.mu.Unlock()

	h.reset()
	h.mgr.mu.Lock()
	err := h.mgr.moveSharedSubnet("10.30.0.0/16", "peer-a", "peer-c", h.mgr.now())
	h.mgr.mu.Unlock()
	if err != nil {
		t.Fatalf("moveSharedSubnet: %v", err)
	}
	h.requireWrites(
		"add peer-c [10.99.0.4/32 10.30.0.0/16]",
		"add peer-a [10.99.0.2/32 10.20.0.0/16]",
	)
	h.requireHolder("10.30.0.0/16", "peer-c")

	h.reset()
	if err := h.mgr.syncSharedSubnets(peers, testMesh, nil); err != nil {
		t.Fatalf("syncSharedSubnets: %v", err)
	}
	h.requireWrites(
		"add peer-b [10.99.0.3/32 10.20.0.0/16]",
		"add peer-a [10.99.0.2/32]",
	)
}
