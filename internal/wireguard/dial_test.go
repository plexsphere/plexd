package wireguard

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// dialOrder
// ---------------------------------------------------------------------------

func TestDialOrder_WithoutCandidates(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		fallback string
		want     []string
	}{
		{"nothing to dial", "", "", nil},
		{"only a fallback", "", "203.0.113.1:51820", []string{"203.0.113.1:51820"}},
		{"endpoint and fallback", "198.51.100.7:51820", "203.0.113.1:51820", []string{"198.51.100.7:51820", "203.0.113.1:51820"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := api.SnapshotPeer{Endpoint: tt.endpoint, FallbackEndpoint: tt.fallback}
			order, dropped := dialOrder(p, nil, testMesh)
			if !slices.Equal(order, tt.want) || dropped != 0 {
				t.Errorf("dialOrder() = (%v, %d), want (%v, 0)", order, dropped, tt.want)
			}
		})
	}
}

func TestDialOrder_OnLinkCandidatesFirst(t *testing.T) {
	p := api.SnapshotPeer{
		EndpointCandidates: []string{"10.0.0.5:51820", "172.31.4.9:51820"},
		Endpoint:           "198.51.100.7:51820",
		FallbackEndpoint:   "203.0.113.1:51820",
	}
	local := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	order, dropped := dialOrder(p, local, testMesh)

	want := []string{"10.0.0.5:51820", "198.51.100.7:51820", "172.31.4.9:51820", "203.0.113.1:51820"}
	if !slices.Equal(order, want) || dropped != 0 {
		t.Errorf("dialOrder() = (%v, %d), want (%v, 0)", order, dropped, want)
	}
}

// Without a usable local prefix nothing is on-link, so every candidate goes
// after the direct endpoint. A host /32 says nothing about its neighbours.
func TestDialOrder_NoUsableLocalPrefix(t *testing.T) {
	p := api.SnapshotPeer{
		EndpointCandidates: []string{"10.0.0.5:51820", "172.31.4.9:51820"},
		Endpoint:           "198.51.100.7:51820",
		FallbackEndpoint:   "203.0.113.1:51820",
	}
	want := []string{"198.51.100.7:51820", "10.0.0.5:51820", "172.31.4.9:51820", "203.0.113.1:51820"}

	for _, tt := range []struct {
		name  string
		local []netip.Prefix
	}{
		{"nil local", nil},
		{"host prefix", []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			order, _ := dialOrder(p, tt.local, testMesh)
			if !slices.Equal(order, want) {
				t.Errorf("dialOrder() = %v, want %v", order, want)
			}
		})
	}
}

func TestDialOrder_DropsUnusableCandidates(t *testing.T) {
	unusable := []string{
		"not-an-endpoint",
		"10.0.0.5:0",
		"127.0.0.1:51820",
		"0.0.0.0:51820",
		"224.0.0.1:51820",
		"169.254.1.1:51820",
		"[fe80::1%eth0]:51820",
		"10.99.0.4:51820", // inside testMesh
	}
	for _, c := range unusable {
		t.Run(c, func(t *testing.T) {
			p := api.SnapshotPeer{EndpointCandidates: []string{c}, FallbackEndpoint: "203.0.113.1:51820"}
			order, dropped := dialOrder(p, nil, testMesh)
			if want := []string{"203.0.113.1:51820"}; !slices.Equal(order, want) || dropped != 1 {
				t.Errorf("dialOrder() = (%v, %d), want (%v, 1)", order, dropped, want)
			}
		})
	}
}

func TestDialOrder_CanonicalizesAndDeduplicates(t *testing.T) {
	p := api.SnapshotPeer{
		EndpointCandidates: []string{"[::ffff:10.0.0.5]:51820", "198.51.100.7:51820"},
		Endpoint:           "198.51.100.7:51820",
	}
	order, dropped := dialOrder(p, nil, testMesh)
	// The candidate equal to the direct endpoint keeps its first position,
	// which is the direct endpoint's, ahead of the off-link candidates.
	want := []string{"198.51.100.7:51820", "10.0.0.5:51820"}
	if !slices.Equal(order, want) || dropped != 0 {
		t.Errorf("dialOrder() = (%v, %d), want (%v, 0)", order, dropped, want)
	}
}

// ---------------------------------------------------------------------------
// ReconcileHandler and the dial order
// ---------------------------------------------------------------------------

func TestReconcileHandler_HandsTheManagerTheDialOrder(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	mgr.SetLocalPrefixes(func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, nil
	})
	handler := ReconcileHandler(mgr, nil)

	peer := snapshotPeer("peer-1", "10.99.0.2", "203.0.113.1:51820")
	peer.Endpoint = "198.51.100.7:51820"
	peer.EndpointCandidates = []string{"172.31.4.9:51820", "10.0.0.5:51820"}
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	want := []string{"10.0.0.5:51820", "198.51.100.7:51820", "172.31.4.9:51820", "203.0.113.1:51820"}
	st := mgr.dial["peer-1"]
	if st == nil {
		t.Fatal("no dial state for peer-1 after the add")
	}
	if !slices.Equal(st.peer.Endpoints, want) {
		t.Errorf("Endpoints = %v, want %v", st.peer.Endpoints, want)
	}
	if st.peer.Endpoint != want[0] {
		t.Errorf("Endpoint = %q, want the first entry %q", st.peer.Endpoint, want[0])
	}
	if cfgs := addPeerConfigs(t, ctrl); len(cfgs) != 1 || cfgs[0].Endpoint != want[0] {
		t.Errorf("AddPeer configs = %+v, want one programming %q", cfgs, want[0])
	}
}

func TestReconcileHandler_PrefixErrorOrdersEveryCandidateOffLink(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, slogTextLogger(&logs))
	mgr.SetLocalPrefixes(func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, errors.New("netlink: dump interrupted")
	})
	handler := ReconcileHandler(mgr, nil)

	peer := snapshotPeer("peer-1", "10.99.0.2", "203.0.113.1:51820")
	peer.Endpoint = "198.51.100.7:51820"
	peer.EndpointCandidates = []string{"10.0.0.5:51820"}
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	want := []string{"198.51.100.7:51820", "10.0.0.5:51820", "203.0.113.1:51820"}
	if got := mgr.dial["peer-1"].peer.Endpoints; !slices.Equal(got, want) {
		t.Errorf("Endpoints = %v, want %v with every candidate off-link", got, want)
	}
	out := logs.String()
	for _, want := range []string{
		"read local prefixes failed, ordering every candidate as off-link",
		"level=WARN",
		"netlink: dump interrupted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
}

func TestReconcileHandler_LogsDroppedCandidates(t *testing.T) {
	var logs bytes.Buffer
	mgr := setupMeshManager(t, &mockController{}, slogTextLogger(&logs))
	handler := ReconcileHandler(mgr, nil)

	peer := snapshotPeer("peer-1", "10.99.0.2", "203.0.113.1:51820")
	peer.EndpointCandidates = []string{"127.0.0.1:51820", "10.99.0.4:51820", "10.0.0.5:51820"}
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	out := logs.String()
	for _, want := range []string{"dropped endpoint candidates", "level=DEBUG", "peer_id=peer-1", "count=2"} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------------------
// Endpoint selection
// ---------------------------------------------------------------------------

// fakeClock is a settable clock for Manager.now, safe for concurrent use.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// selectionStart is the fake clock's time when a test adds its peers.
var selectionStart = time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)

// newSelectionManager returns a manager on a statsController with a fake clock
// at selectionStart, logging into logs.
func newSelectionManager(cfg Config, logs *bytes.Buffer) (*Manager, *statsController, *fakeClock) {
	ctrl := &statsController{}
	mgr := NewManager(ctrl, cfg, slogTextLogger(logs))
	clock := &fakeClock{now: selectionStart}
	mgr.now = clock.Now
	return mgr, ctrl, clock
}

// orderedPeer returns a peer keyed with key whose dial order is order.
func orderedPeer(id, b64Key string, order ...string) api.Peer {
	p := keyedPeer(id, b64Key)
	p.Endpoints = order
	p.Endpoint = ""
	if len(order) > 0 {
		p.Endpoint = order[0]
	}
	return p
}

// handshakeAt returns the device stat of key with a handshake at at.
func handshakeAt(key [32]byte, at time.Time) PeerStat {
	return PeerStat{
		PublicKey:     key,
		Endpoint:      netip.MustParseAddrPort("198.51.100.9:51820"),
		LastHandshake: at,
	}
}

// writtenEndpoints returns the endpoint of every AddPeer call ctrl recorded.
func writtenEndpoints(t *testing.T, ctrl *statsController) []string {
	t.Helper()
	var endpoints []string
	for _, cfg := range addPeerConfigs(t, &ctrl.mockController) {
		endpoints = append(endpoints, cfg.Endpoint)
	}
	return endpoints
}

func mustSelect(t *testing.T, mgr *Manager) {
	t.Helper()
	if err := mgr.selectEndpoints(); err != nil {
		t.Fatalf("selectEndpoints: %v", err)
	}
}

var threeEntries = []string{"10.0.0.5:51820", "198.51.100.7:51820", "203.0.113.1:51820"}

func TestSelectEndpoints_AdvancesWithoutAHandshake(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	_, b64 := testKey(0x0a)
	if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if got := writtenEndpoints(t, ctrl); !slices.Equal(got, threeEntries[:1]) {
		t.Fatalf("AddPeer wrote %v, want the first entry only", got)
	}

	clock.Set(selectionStart.Add(29 * time.Second))
	mustSelect(t, mgr)
	if n := len(writtenEndpoints(t, ctrl)); n != 1 {
		t.Fatalf("writes after 29 s = %d, want none beyond the AddPeer", n)
	}

	clock.Set(selectionStart.Add(30 * time.Second))
	mustSelect(t, mgr)
	clock.Set(selectionStart.Add(60 * time.Second))
	mustSelect(t, mgr)
	clock.Set(selectionStart.Add(90 * time.Second))
	mustSelect(t, mgr)

	want := []string{threeEntries[0], threeEntries[1], threeEntries[2], threeEntries[0]}
	if got := writtenEndpoints(t, ctrl); !slices.Equal(got, want) {
		t.Errorf("written endpoints = %v, want %v", got, want)
	}
	if got := addPeerConfigs(t, &ctrl.mockController)[1].PersistentKeepalive; got != 25 {
		t.Errorf("switch PersistentKeepalive = %d, want 25", got)
	}
	out := logs.String()
	for _, want := range []string{
		"trying next endpoint candidate",
		"peer_id=node-a",
		"endpoint=198.51.100.7:51820 attempt=2 of=3",
		"endpoint=10.0.0.5:51820 attempt=1 of=3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
}

func TestSelectEndpoints_FreshHandshakeHoldsTheEndpoint(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	key, b64 := testKey(0x0a)
	if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	handshake := selectionStart.Add(50 * time.Second)
	ctrl.stats = []PeerStat{handshakeAt(key, handshake)}
	clock.Set(handshake.Add(10 * time.Second))
	mustSelect(t, mgr)
	clock.Set(handshake.Add(100 * time.Second))
	mustSelect(t, mgr)

	if n := len(writtenEndpoints(t, ctrl)); n != 1 {
		t.Fatalf("writes = %d with a fresh handshake, want none beyond the AddPeer", n)
	}
	if n := strings.Count(logs.String(), "wireguard: endpoint selected"); n != 1 {
		t.Errorf("endpoint selected logged %d times across two passes, want once", n)
	}
	if !strings.Contains(logs.String(), "endpoint=198.51.100.9:51820") {
		t.Errorf("endpoint selected does not name the device endpoint:\n%s", logs.String())
	}

	stale := handshake.Add(181 * time.Second)
	clock.Set(stale)
	mustSelect(t, mgr)
	if !strings.Contains(logs.String(), "peer handshake went stale, resuming endpoint selection") {
		t.Errorf("no went stale line:\n%s", logs.String())
	}
	clock.Set(stale.Add(29 * time.Second))
	mustSelect(t, mgr)
	if n := len(writtenEndpoints(t, ctrl)); n != 1 {
		t.Fatalf("writes = %d 29 s after going stale, want none beyond the AddPeer", n)
	}
	clock.Set(stale.Add(30 * time.Second))
	mustSelect(t, mgr)
	if got := writtenEndpoints(t, ctrl); !slices.Equal(got, threeEntries[:2]) {
		t.Errorf("written endpoints = %v, want a switch to the second entry 30 s after going stale", got)
	}
}

func TestUpdatePeer_EndpointSelection(t *testing.T) {
	key, b64 := testKey(0x0a)
	_, rotated := testKey(0x0b)
	newOrder := []string{"172.31.4.9:51820", "203.0.113.1:51820"}

	tests := []struct {
		name      string
		connected bool
		update    api.Peer
		want      string
	}{
		{"connected peer keeps the device endpoint", true, orderedPeer("node-a", b64, newOrder...), ""},
		{"peer that is not connected starts over", false, orderedPeer("node-a", b64, newOrder...), newOrder[0]},
		{"connected peer with a rotated key starts over", true, orderedPeer("node-a", rotated, newOrder...), newOrder[0]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
			if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
				t.Fatalf("AddPeer: %v", err)
			}
			if tt.connected {
				ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}
				clock.Set(selectionStart.Add(time.Second))
				mustSelect(t, mgr)
			}

			if err := mgr.UpdatePeer(tt.update); err != nil {
				t.Fatalf("UpdatePeer: %v", err)
			}
			got := writtenEndpoints(t, ctrl)
			if len(got) != 2 || got[1] != tt.want {
				t.Errorf("written endpoints = %v, want the update to write %q", got, tt.want)
			}
		})
	}
}

// A connected peer that goes stale after an update resumes from the position
// the entry it was last programmed with holds in the new order.
func TestUpdatePeer_ConnectedPeerKeepsItsPosition(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	key, b64 := testKey(0x0a)
	if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	clock.Set(selectionStart.Add(30 * time.Second))
	mustSelect(t, mgr) // now on threeEntries[1]

	handshake := selectionStart.Add(31 * time.Second)
	ctrl.stats = []PeerStat{handshakeAt(key, handshake)}
	clock.Set(handshake)
	mustSelect(t, mgr)

	reordered := []string{"172.31.4.9:51820", threeEntries[1], threeEntries[2]}
	if err := mgr.UpdatePeer(orderedPeer("node-a", b64, reordered...)); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if st := mgr.dial["node-a"]; st.idx != 1 || !st.connected {
		t.Errorf("after the update idx = %d, connected = %v, want 1, true", st.idx, st.connected)
	}
}

func TestSelectEndpoints_NothingToDo(t *testing.T) {
	t.Run("no tracked peers", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, _ := newSelectionManager(Config{}, &logs)
		key, _ := testKey(0x0a)
		ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}
		mustSelect(t, mgr)
		if n := len(writtenEndpoints(t, ctrl)); n != 0 {
			t.Errorf("writes = %d, want none", n)
		}
	})

	t.Run("device reports no peers", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		_, b64 := testKey(0x0a)
		if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		clock.Set(selectionStart.Add(10 * time.Second))
		mustSelect(t, mgr)
		if n := len(writtenEndpoints(t, ctrl)); n != 1 {
			t.Errorf("writes = %d, want none beyond the AddPeer", n)
		}
	})
}

func TestSelectEndpoints_NeverSwitches(t *testing.T) {
	t.Run("one-entry order", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		_, b64 := testKey(0x0a)
		if err := mgr.AddPeer(orderedPeer("node-a", b64, "203.0.113.1:51820")); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		for i := 1; i <= 5; i++ {
			clock.Set(selectionStart.Add(time.Duration(i) * time.Minute))
			mustSelect(t, mgr)
		}
		if n := len(writtenEndpoints(t, ctrl)); n != 1 {
			t.Errorf("writes = %d, want none beyond the AddPeer", n)
		}
	})

	t.Run("caller that sets only Endpoint", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		if err := mgr.AddPeer(testPeer("node-a")); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		clock.Set(selectionStart.Add(time.Minute))
		mustSelect(t, mgr)
		if got := writtenEndpoints(t, ctrl); !slices.Equal(got, []string{"1.2.3.4:51820"}) {
			t.Errorf("written endpoints = %v, want only the AddPeer with Endpoint", got)
		}
	})

	t.Run("removed peer", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		_, b64 := testKey(0x0a)
		if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		if err := mgr.RemovePeerByID("node-a"); err != nil {
			t.Fatalf("RemovePeerByID: %v", err)
		}
		clock.Set(selectionStart.Add(time.Minute))
		mustSelect(t, mgr)
		if n := len(writtenEndpoints(t, ctrl)); n != 1 {
			t.Errorf("writes = %d, want none beyond the AddPeer", n)
		}
	})
}

func TestSelectEndpoints_SwitchFailure(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	_, b64 := testKey(0x0a)
	if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	writeErr := errors.New("netlink: busy")
	ctrl.addPeerErr = writeErr
	clock.Set(selectionStart.Add(30 * time.Second))
	err := mgr.selectEndpoints()
	if !errors.Is(err, writeErr) {
		t.Fatalf("selectEndpoints() = %v, want it to wrap %v", err, writeErr)
	}
	out := logs.String()
	for _, want := range []string{"endpoint switch failed", "level=WARN", "endpoint=198.51.100.7:51820", "netlink: busy"} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}

	ctrl.addPeerErr = nil
	clock.Set(selectionStart.Add(59 * time.Second))
	mustSelect(t, mgr)
	if n := len(writtenEndpoints(t, ctrl)); n != 2 {
		t.Fatalf("writes = %d 29 s after the failed switch, want no retry yet", n)
	}
	clock.Set(selectionStart.Add(60 * time.Second))
	mustSelect(t, mgr)
	// The failed switch left the peer on the first entry, so the retry tries
	// the second entry again.
	want := []string{threeEntries[0], threeEntries[1], threeEntries[1]}
	if got := writtenEndpoints(t, ctrl); !slices.Equal(got, want) {
		t.Errorf("written endpoints = %v, want %v", got, want)
	}
}

func TestSelectEndpoints_StatsError(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	_, b64 := testKey(0x0a)
	if err := mgr.AddPeer(orderedPeer("node-a", b64, threeEntries...)); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	readErr := errors.New("netlink: device busy")
	ctrl.err = readErr
	clock.Set(selectionStart.Add(time.Minute))
	if err := mgr.selectEndpoints(); !errors.Is(err, readErr) {
		t.Fatalf("selectEndpoints() = %v, want it to wrap %v", err, readErr)
	}
	if n := len(writtenEndpoints(t, ctrl)); n != 1 {
		t.Errorf("writes = %d after a stats error, want none beyond the AddPeer", n)
	}
	if st := mgr.dial["node-a"]; st.idx != 0 || !st.programmedAt.Equal(selectionStart) {
		t.Errorf("state after a stats error = idx %d, programmedAt %v, want it untouched", st.idx, st.programmedAt)
	}
}

func TestRunEndpointSelection(t *testing.T) {
	t.Run("controller without peer stats", func(t *testing.T) {
		var logs bytes.Buffer
		mgr := NewManager(&mockController{}, Config{}, slogTextLogger(&logs))
		if err := mgr.RunEndpointSelection(context.Background(), time.Millisecond); err != nil {
			t.Fatalf("RunEndpointSelection() = %v, want nil", err)
		}
		if !strings.Contains(logs.String(), "endpoint selection unavailable, the controller cannot read peer stats") {
			t.Errorf("no unavailable line:\n%s", logs.String())
		}
	})

	t.Run("keepalive off", func(t *testing.T) {
		var logs bytes.Buffer
		zero := time.Duration(0)
		mgr := NewManager(&statsController{}, Config{PersistentKeepalive: &zero}, slogTextLogger(&logs))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// A live context: only the disabled path returns at once.
		if err := mgr.RunEndpointSelection(ctx, time.Millisecond); err != nil {
			t.Fatalf("RunEndpointSelection() = %v, want nil", err)
		}
		if !strings.Contains(logs.String(), "endpoint selection disabled, persistent_keepalive is 0s") {
			t.Errorf("no disabled line:\n%s", logs.String())
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		var logs syncBuffer
		mgr := NewManager(&statsController{}, Config{}, slogTextLogger(&logs))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- mgr.RunEndpointSelection(ctx, time.Millisecond) }()

		time.Sleep(20 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("RunEndpointSelection() = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RunEndpointSelection did not return after its context was cancelled")
		}
		if out := logs.String(); !strings.Contains(out, "endpoint selection started") || !strings.Contains(out, "timeout=30s") {
			t.Errorf("no started line with timeout=30s:\n%s", out)
		}
	})
}

// syncBuffer is a bytes.Buffer safe for a logger writing from one goroutine
// while the test reads from another.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestSelectEndpoints_ConcurrentWithUpdatePeer(t *testing.T) {
	key, b64 := testKey(0x0a)
	ctrl := &statsController{stats: []PeerStat{handshakeAt(key, time.Now())}}
	mgr := NewManager(ctrl, Config{}, discardLogger())
	peer := orderedPeer("node-a", b64, threeEntries...)
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			_ = mgr.selectEndpoints()
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			_ = mgr.UpdatePeer(peer)
		}
	}()
	wg.Wait()
}
