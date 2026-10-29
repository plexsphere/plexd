package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
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

// The control plane lists a peer's peer-observed endpoints, NAT mappings other
// nodes of the Domain completed handshakes over, ahead of its local candidates.
// plexd orders them by the on-link rule like every other candidate.
func TestDialOrder_PeerObservedEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		endpoint   string
		local      []netip.Prefix
		want       []string
	}{
		{
			"off-link mapping at the head",
			[]string{"198.51.100.30:40001", "10.0.0.5:51820", "172.31.4.9:51820"},
			"198.51.100.7:51820",
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			[]string{"10.0.0.5:51820", "198.51.100.7:51820", "198.51.100.30:40001", "172.31.4.9:51820", "203.0.113.1:51820"},
		},
		{
			"mapping on the direct endpoint's address",
			[]string{"198.51.100.7:10482"},
			"198.51.100.7:51820",
			nil,
			[]string{"198.51.100.7:51820", "198.51.100.7:10482", "203.0.113.1:51820"},
		},
		{
			"no direct endpoint",
			[]string{"198.51.100.30:40001", "172.31.4.9:51820"},
			"",
			nil,
			[]string{"198.51.100.30:40001", "172.31.4.9:51820", "203.0.113.1:51820"},
		},
		{
			"mapping on a subnet this node shares",
			[]string{"198.51.100.30:40001", "172.31.4.9:51820"},
			"192.0.2.7:51820",
			[]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			[]string{"198.51.100.30:40001", "192.0.2.7:51820", "172.31.4.9:51820", "203.0.113.1:51820"},
		},
		{
			"IPv6 mapping",
			[]string{"[2001:db8::30]:40001", "10.0.0.5:51820"},
			"198.51.100.7:51820",
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			[]string{"10.0.0.5:51820", "198.51.100.7:51820", "[2001:db8::30]:40001", "203.0.113.1:51820"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := api.SnapshotPeer{
				EndpointCandidates: tt.candidates,
				Endpoint:           tt.endpoint,
				FallbackEndpoint:   "203.0.113.1:51820",
			}
			order, dropped := dialOrder(p, tt.local, testMesh)
			if !slices.Equal(order, tt.want) || dropped != 0 {
				t.Errorf("dialOrder() = (%v, %d), want (%v, 0)", order, dropped, tt.want)
			}
		})
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

// Fallback names the fallback_endpoint only where it ends the dial order, the
// entry endpoint selection holds.
func TestReconcileHandler_SetsTheFallback(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		fallback   string
		wantOrder  []string
		want       string
	}{
		{
			"fallback ends the dial order",
			[]string{"172.31.4.9:51820"},
			"203.0.113.1:51820",
			[]string{"198.51.100.7:51820", "172.31.4.9:51820", "203.0.113.1:51820"},
			"203.0.113.1:51820",
		},
		{
			"fallback keeps a candidate's earlier position",
			[]string{"203.0.113.1:51820", "172.31.4.9:51820"},
			"203.0.113.1:51820",
			[]string{"198.51.100.7:51820", "203.0.113.1:51820", "172.31.4.9:51820"},
			"",
		},
		{
			"no fallback",
			[]string{"172.31.4.9:51820"},
			"",
			[]string{"198.51.100.7:51820", "172.31.4.9:51820"},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := setupMeshManager(t, &mockController{}, discardLogger())
			handler := ReconcileHandler(mgr, nil)

			peer := snapshotPeer("peer-1", "10.99.0.2", tt.fallback)
			peer.Endpoint = "198.51.100.7:51820"
			peer.EndpointCandidates = tt.candidates
			if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
				t.Fatalf("add: %v", err)
			}

			st := mgr.dial["peer-1"]
			if st == nil {
				t.Fatal("no dial state for peer-1 after the add")
			}
			if !slices.Equal(st.peer.Endpoints, tt.wantOrder) {
				t.Fatalf("Endpoints = %v, want %v", st.peer.Endpoints, tt.wantOrder)
			}
			if st.peer.Fallback != tt.want {
				t.Errorf("Fallback = %q, want %q", st.peer.Fallback, tt.want)
			}
		})
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

// A Fallback that ends the dial order is held as long as the entries before
// it took together: two trials in a three-entry order.
func TestSelectEndpoints_HoldsTheFallback(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	_, b64 := testKey(0x0a)
	peer := orderedPeer("node-a", b64, threeEntries...)
	peer.Fallback = threeEntries[2]
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	for _, step := range []struct {
		after time.Duration
		want  []string
	}{
		{30 * time.Second, []string{threeEntries[0], threeEntries[1]}},
		{60 * time.Second, []string{threeEntries[0], threeEntries[1], threeEntries[2]}},
		{90 * time.Second, []string{threeEntries[0], threeEntries[1], threeEntries[2]}},
		{119 * time.Second, []string{threeEntries[0], threeEntries[1], threeEntries[2]}},
		{120 * time.Second, []string{threeEntries[0], threeEntries[1], threeEntries[2], threeEntries[0]}},
	} {
		clock.Set(selectionStart.Add(step.after))
		mustSelect(t, mgr)
		if got := writtenEndpoints(t, ctrl); !slices.Equal(got, step.want) {
			t.Fatalf("written endpoints after %v = %v, want %v", step.after, got, step.want)
		}
	}

	out := logs.String()
	for _, want := range []string{
		"endpoint=198.51.100.7:51820 attempt=2 of=3 trial=30s",
		"endpoint=203.0.113.1:51820 attempt=3 of=3 trial=1m0s",
		"endpoint=10.0.0.5:51820 attempt=1 of=3 trial=30s",
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

	t.Run("relay probe key", func(t *testing.T) {
		for _, withProbe := range []bool{true, false} {
			var logs syncBuffer
			mgr := NewManager(&statsController{}, Config{}, slogTextLogger(&logs))
			if withProbe {
				mgr.SetRelayProbe(func(netip.Addr) error { return nil })
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := mgr.RunEndpointSelection(ctx, time.Millisecond); err != nil {
				t.Fatalf("RunEndpointSelection() = %v, want nil", err)
			}
			want := "relay_probe=false"
			if withProbe {
				want = "relay_probe=true"
			}
			requireLogLine(t, logs.String(), "wireguard: endpoint selection started", want)
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

// ---------------------------------------------------------------------------
// Relayed peers
// ---------------------------------------------------------------------------

// relayOrder is a dial order whose second entry is the peer's Fallback.
var relayOrder = []string{"10.0.0.5:51820", "203.0.113.1:51820"}

const newRelay = "203.0.113.2:51820"

// relayStat returns the device stat of key with a handshake at at, rx bytes
// received, and the relay relayOrder[1] as the endpoint the device reports,
// as for a peer reached over that relay.
func relayStat(key [32]byte, at time.Time, rx uint64) PeerStat {
	s := handshakeAt(key, at)
	s.Endpoint = netip.MustParseAddrPort(relayOrder[1])
	s.RxBytes = rx
	return s
}

// directEndpoint is an endpoint a peer reaches this node from directly.
var directEndpoint = netip.MustParseAddrPort("198.51.100.9:51820")

// relayedManager returns a manager on a fake clock whose peer node-a, ordered
// relayOrder with its Fallback last, was switched to the Fallback at 30 s and
// connected over it at 31 s with 100 bytes received. Its mesh prefix contains
// the peer's mesh IP 10.0.0.2. mutate, when not nil, edits the peer before it
// is added.
func relayedManager(t *testing.T, logs *bytes.Buffer, mutate func(*api.Peer)) (*Manager, *statsController, *fakeClock, [32]byte) {
	t.Helper()
	mgr, ctrl, clock := newSelectionManager(Config{}, logs)
	mgr.meshPrefix = netip.MustParsePrefix("10.0.0.0/24")
	key, b64 := testKey(0x0a)
	peer := orderedPeer("node-a", b64, relayOrder...)
	peer.Fallback = relayOrder[1]
	if mutate != nil {
		mutate(&peer)
	}
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	clock.Set(selectionStart.Add(30 * time.Second))
	mustSelect(t, mgr)

	handshake := selectionStart.Add(31 * time.Second)
	ctrl.stats = []PeerStat{relayStat(key, handshake, 100)}
	clock.Set(handshake)
	mustSelect(t, mgr)
	if st := mgr.dial["node-a"]; !st.connected || !st.relayed {
		t.Fatalf("after the handshake over the Fallback connected = %v, relayed = %v, want both", st.connected, st.relayed)
	}
	return mgr, ctrl, clock, key
}

// relayUpdate returns node-a ordered relayOrder's first entry and fallback,
// with fallback as its Fallback, keyed with b64.
func relayUpdate(b64, fallback string) api.Peer {
	p := orderedPeer("node-a", b64, relayOrder[0], fallback)
	p.Fallback = fallback
	return p
}

// deviceWrites returns the RemovePeer and AddPeer calls ctrl recorded, in
// order, as "remove" and "add <endpoint>".
func deviceWrites(ctrl *statsController) []string {
	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	var writes []string
	for _, c := range ctrl.calls {
		switch c.Method {
		case "RemovePeer":
			writes = append(writes, "remove")
		case "AddPeer":
			writes = append(writes, "add "+c.Args[1].(PeerConfig).Endpoint)
		}
	}
	return writes
}

// passAt runs a selection pass at selectionStart plus after.
func passAt(t *testing.T, mgr *Manager, clock *fakeClock, after time.Duration) {
	t.Helper()
	clock.Set(selectionStart.Add(after))
	mustSelect(t, mgr)
}

// logLines returns the lines of out that carry msg.
func logLines(out, msg string) []string {
	var lines []string
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			lines = append(lines, line)
		}
	}
	return lines
}

// requireLogLine fails t unless one line of out carries msg and every field.
func requireLogLine(t *testing.T, out, msg string, fields ...string) {
	t.Helper()
	for _, line := range logLines(out, msg) {
		words := strings.Fields(line)
		if !slices.ContainsFunc(fields, func(f string) bool { return !slices.Contains(words, f) }) {
			return
		}
	}
	t.Errorf("no %q line with %v in:\n%s", msg, fields, out)
}

// fakeProbe records the mesh IPs a relay probe is sent to and returns err.
type fakeProbe struct {
	sent []netip.Addr
	err  error
}

func (p *fakeProbe) send(ip netip.Addr) error {
	p.sent = append(p.sent, ip)
	return p.err
}

func TestUpdatePeer_NewFallbackMovesARelayedPeerAtOnce(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
	_, b64 := testKey(0x0a)
	psk := bytes.Repeat([]byte{0x5c}, 32)
	update := relayUpdate(b64, newRelay)
	update.PSK = base64.StdEncoding.EncodeToString(psk)

	before := len(deviceWrites(ctrl))
	clock.Set(selectionStart.Add(40 * time.Second))
	if err := mgr.UpdatePeer(update); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}

	if got, want := deviceWrites(ctrl)[before:], []string{"remove", "add " + newRelay}; !slices.Equal(got, want) {
		t.Fatalf("device writes = %v, want %v", got, want)
	}
	if removed := ctrl.callsFor("RemovePeer")[0].Args[1].([]byte); !bytes.Equal(removed, key[:]) {
		t.Errorf("RemovePeer key = %x, want the peer's %x", removed, key)
	}
	cfgs := addPeerConfigs(t, &ctrl.mockController)
	added := cfgs[len(cfgs)-1]
	if added.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %d, want 25", added.PersistentKeepalive)
	}
	if !slices.Equal(added.AllowedIPs, []string{"10.0.0.2/32"}) {
		t.Errorf("AllowedIPs = %v, want [10.0.0.2/32]", added.AllowedIPs)
	}
	if !bytes.Equal(added.PSK, psk) {
		t.Errorf("PSK = %x, want the edge PSK %x", added.PSK, psk)
	}
	st := mgr.dial["node-a"]
	if st.idx != 1 || st.connected || !st.relayed || !st.programmedAt.Equal(selectionStart.Add(40*time.Second)) {
		t.Errorf("state = idx %d, connected %v, relayed %v, programmedAt %v; want 1, false, true, 40 s",
			st.idx, st.connected, st.relayed, st.programmedAt.Sub(selectionStart))
	}
	requireLogLine(t, logs.String(), "wireguard: relay fallback changed, moving to the new relay",
		"peer_id=node-a", "from="+relayOrder[1], "to="+newRelay)
}

func TestUpdatePeer_NewFallbackMovesAPeerInItsRelayHold(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	_, b64 := testKey(0x0a)
	peer := orderedPeer("node-a", b64, relayOrder...)
	peer.Fallback = relayOrder[1]
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	passAt(t, mgr, clock, 30*time.Second)

	clock.Set(selectionStart.Add(40 * time.Second))
	if err := mgr.UpdatePeer(relayUpdate(b64, newRelay)); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	want := []string{"add " + relayOrder[0], "add " + relayOrder[1], "remove", "add " + newRelay}
	if got := deviceWrites(ctrl); !slices.Equal(got, want) {
		t.Fatalf("device writes = %v, want %v", got, want)
	}
	if st := mgr.dial["node-a"]; st.idx != 1 || st.relayed {
		t.Errorf("state = idx %d, relayed %v, want 1, false", st.idx, st.relayed)
	}

	passAt(t, mgr, clock, 69*time.Second)
	if got := deviceWrites(ctrl); len(got) != len(want) {
		t.Fatalf("device writes at 69 s = %v, want none beyond %v", got, want)
	}
	passAt(t, mgr, clock, 70*time.Second)
	if got := deviceWrites(ctrl); got[len(got)-1] != "add "+relayOrder[0] {
		t.Errorf("device writes at 70 s = %v, want the first entry programmed as today", got)
	}
}

func TestUpdatePeer_RelayedPeerKeepsItsRelay(t *testing.T) {
	_, b64 := testKey(0x0a)
	update := orderedPeer("node-a", b64, "172.31.4.9:51820", relayOrder[0], relayOrder[1])
	update.Fallback = relayOrder[1]

	t.Run("connected", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, _, _ := relayedManager(t, &logs, nil)
		before := len(deviceWrites(ctrl))
		if err := mgr.UpdatePeer(update); err != nil {
			t.Fatalf("UpdatePeer: %v", err)
		}
		if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add "}) {
			t.Fatalf("device writes = %v, want one write without an endpoint", got)
		}
		if st := mgr.dial["node-a"]; st.idx != 2 || !st.connected || !st.relayed {
			t.Errorf("state = idx %d, connected %v, relayed %v, want 2, true, true", st.idx, st.connected, st.relayed)
		}
	})

	t.Run("not connected", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
		passAt(t, mgr, clock, 212*time.Second) // stale: the relay is dialed again
		ctrl.stats = []PeerStat{{PublicKey: key}}

		before := len(deviceWrites(ctrl))
		clock.Set(selectionStart.Add(220 * time.Second))
		if err := mgr.UpdatePeer(update); err != nil {
			t.Fatalf("UpdatePeer: %v", err)
		}
		if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add "}) {
			t.Fatalf("device writes = %v, want one write without an endpoint", got)
		}
		st := mgr.dial["node-a"]
		if st.idx != 2 || st.connected || !st.relayed || !st.programmedAt.Equal(selectionStart.Add(212*time.Second)) {
			t.Errorf("state = idx %d, connected %v, relayed %v, programmedAt %v; want 2, false, true, 212 s",
				st.idx, st.connected, st.relayed, st.programmedAt.Sub(selectionStart))
		}

		// The relay's trial in a three-entry order is two trials, 60 s.
		passAt(t, mgr, clock, 240*time.Second)
		passAt(t, mgr, clock, 271*time.Second)
		if got := deviceWrites(ctrl)[before:]; len(got) != 1 {
			t.Fatalf("device writes before the relay's trial ran out = %v, want only the update", got)
		}
		passAt(t, mgr, clock, 272*time.Second)
		if got, want := deviceWrites(ctrl)[before:], []string{"add ", "remove", "add " + relayOrder[1]}; !slices.Equal(got, want) {
			t.Errorf("device writes = %v, want %v", got, want)
		}
		if slices.Contains(deviceWrites(ctrl), "add 172.31.4.9:51820") {
			t.Errorf("a relayed peer was programmed on a direct entry: %v", deviceWrites(ctrl))
		}
	})
}

func TestUpdatePeer_DroppedFallbackEndsTheRelayedState(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, _ := relayedManager(t, &logs, nil)
	_, b64 := testKey(0x0a)

	before := len(deviceWrites(ctrl))
	if err := mgr.UpdatePeer(orderedPeer("node-a", b64, relayOrder[0])); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add "}) {
		t.Fatalf("device writes = %v, want one write without an endpoint", got)
	}
	if st := mgr.dial["node-a"]; st.relayed || !st.connected {
		t.Errorf("state = relayed %v, connected %v, want false, true", st.relayed, st.connected)
	}

	passAt(t, mgr, clock, 212*time.Second)
	requireLogLine(t, logs.String(), "wireguard: peer handshake went stale, resuming endpoint selection", "peer_id=node-a")
	if slices.Contains(deviceWrites(ctrl)[before:], "remove") {
		t.Errorf("device writes = %v, want no RemovePeer", deviceWrites(ctrl)[before:])
	}
}

func TestUpdatePeer_NewFallbackOffTheRelayKeepsTodaysRules(t *testing.T) {
	key, b64 := testKey(0x0a)
	start := func(t *testing.T) (*Manager, *statsController, *fakeClock) {
		t.Helper()
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		peer := orderedPeer("node-a", b64, relayOrder...)
		peer.Fallback = relayOrder[1]
		if err := mgr.AddPeer(peer); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		return mgr, ctrl, clock
	}

	t.Run("connected", func(t *testing.T) {
		mgr, ctrl, clock := start(t)
		ctrl.stats = []PeerStat{relayStat(key, selectionStart.Add(10*time.Second), 100)}
		passAt(t, mgr, clock, 10*time.Second)
		if st := mgr.dial["node-a"]; !st.connected || st.relayed {
			t.Fatalf("connected over a direct entry: connected = %v, relayed = %v, want true, false", st.connected, st.relayed)
		}
		before := len(deviceWrites(ctrl))
		if err := mgr.UpdatePeer(relayUpdate(b64, newRelay)); err != nil {
			t.Fatalf("UpdatePeer: %v", err)
		}
		if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add "}) {
			t.Errorf("device writes = %v, want one write without an endpoint", got)
		}
	})

	t.Run("not connected", func(t *testing.T) {
		mgr, ctrl, clock := start(t)
		clock.Set(selectionStart.Add(10 * time.Second))
		before := len(deviceWrites(ctrl))
		if err := mgr.UpdatePeer(relayUpdate(b64, newRelay)); err != nil {
			t.Fatalf("UpdatePeer: %v", err)
		}
		if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add " + relayOrder[0]}) {
			t.Errorf("device writes = %v, want the new order's first entry", got)
		}
	})
}

func TestUpdatePeer_RotatedKeyWithANewFallbackStartsOver(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, _, _ := relayedManager(t, &logs, nil)
	_, rotated := testKey(0x0b)

	before := len(deviceWrites(ctrl))
	if err := mgr.UpdatePeer(relayUpdate(rotated, newRelay)); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add " + relayOrder[0]}) {
		t.Errorf("device writes = %v, want the new order's first entry", got)
	}
	if mgr.dial["node-a"].relayed {
		t.Error("relayed = true after a key rotation, want false")
	}
}

func TestUpdatePeer_RelayMoveWriteFailures(t *testing.T) {
	_, b64 := testKey(0x0a)

	t.Run("remove fails", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, _, _ := relayedManager(t, &logs, nil)
		removeErr := errors.New("remove refused")
		ctrl.removePeerErr = removeErr

		before := len(deviceWrites(ctrl))
		err := mgr.UpdatePeer(relayUpdate(b64, newRelay))
		if err == nil || !strings.HasPrefix(err.Error(), "wireguard: update peer: remove device peer:") || !errors.Is(err, removeErr) {
			t.Fatalf("UpdatePeer = %v, want wireguard: update peer: remove device peer: wrapping %v", err, removeErr)
		}
		if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"remove"}) {
			t.Errorf("device writes = %v, want the RemovePeer alone", got)
		}
		if st := mgr.dial["node-a"]; st.peer.Fallback != relayOrder[1] || !st.connected {
			t.Errorf("state = Fallback %q, connected %v, want it unchanged", st.peer.Fallback, st.connected)
		}
	})

	t.Run("add fails", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, _, _ := relayedManager(t, &logs, nil)
		addErr := errors.New("add refused")
		ctrl.addPeerErr = addErr

		before := len(deviceWrites(ctrl))
		err := mgr.UpdatePeer(relayUpdate(b64, newRelay))
		if err == nil || !strings.HasPrefix(err.Error(), "wireguard: update peer: add device peer:") || !errors.Is(err, addErr) {
			t.Fatalf("UpdatePeer = %v, want wireguard: update peer: add device peer: wrapping %v", err, addErr)
		}
		if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"remove", "add " + newRelay}) {
			t.Errorf("device writes = %v, want the RemovePeer and the failed AddPeer", got)
		}
		if st := mgr.dial["node-a"]; st.peer.Fallback != relayOrder[1] || !st.connected {
			t.Errorf("state = Fallback %q, connected %v, want it unchanged", st.peer.Fallback, st.connected)
		}
	})
}

func TestSelectEndpoints_MarksAPeerConnectedOverTheRelayRelayed(t *testing.T) {
	var relayed bytes.Buffer
	relayedManager(t, &relayed, nil)
	requireLogLine(t, relayed.String(), "wireguard: endpoint selected", "peer_id=node-a", "relayed=true")

	var direct bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &direct)
	key, b64 := testKey(0x0a)
	peer := orderedPeer("node-a", b64, relayOrder...)
	peer.Fallback = relayOrder[1]
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	ctrl.stats = []PeerStat{relayStat(key, selectionStart.Add(10*time.Second), 100)}
	passAt(t, mgr, clock, 10*time.Second)
	requireLogLine(t, direct.String(), "wireguard: endpoint selected", "peer_id=node-a", "relayed=false")
}

func TestSelectEndpoints_ProbesASilentRelayedPeer(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, _ := relayedManager(t, &logs, nil)
	probe := &fakeProbe{}
	mgr.SetRelayProbe(probe.send)
	before := len(deviceWrites(ctrl))

	passAt(t, mgr, clock, 60*time.Second)
	if len(probe.sent) != 0 {
		t.Fatalf("probes after 29 s of silence = %v, want none", probe.sent)
	}
	passAt(t, mgr, clock, 61*time.Second)
	if want := []netip.Addr{netip.MustParseAddr("10.0.0.2")}; !slices.Equal(probe.sent, want) {
		t.Fatalf("probes after 30 s of silence = %v, want %v", probe.sent, want)
	}
	requireLogLine(t, logs.String(), "wireguard: relayed peer silent, probing",
		"level=DEBUG", "peer_id=node-a", "mesh_ip=10.0.0.2", "silent_for=30s")

	passAt(t, mgr, clock, 66*time.Second)
	if len(probe.sent) != 1 {
		t.Errorf("probes with one outstanding = %v, want one", probe.sent)
	}
	if got := deviceWrites(ctrl)[before:]; len(got) != 0 {
		t.Errorf("device writes = %v, want none", got)
	}
}

func TestSelectEndpoints_AnsweredProbeKeepsTheRelay(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
	probe := &fakeProbe{}
	mgr.SetRelayProbe(probe.send)
	before := len(deviceWrites(ctrl))

	passAt(t, mgr, clock, 61*time.Second)
	ctrl.stats = []PeerStat{relayStat(key, selectionStart.Add(31*time.Second), 132)}
	passAt(t, mgr, clock, 70*time.Second)
	passAt(t, mgr, clock, 76*time.Second)
	if got := deviceWrites(ctrl)[before:]; len(got) != 0 {
		t.Fatalf("device writes after an answered probe = %v, want none", got)
	}
	passAt(t, mgr, clock, 99*time.Second)
	if len(probe.sent) != 1 {
		t.Fatalf("probes 29 s after the answer = %v, want only the first", probe.sent)
	}
	passAt(t, mgr, clock, 100*time.Second)
	if len(probe.sent) != 2 {
		t.Errorf("probes 30 s after the answer = %v, want a second one", probe.sent)
	}
}

func TestSelectEndpoints_UnansweredProbeRedialsTheRelay(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
	probe := &fakeProbe{}
	mgr.SetRelayProbe(probe.send)
	before := len(deviceWrites(ctrl))

	passAt(t, mgr, clock, 61*time.Second)
	passAt(t, mgr, clock, 75*time.Second)
	if got := deviceWrites(ctrl)[before:]; len(got) != 0 {
		t.Fatalf("device writes 14 s after the probe = %v, want none", got)
	}
	passAt(t, mgr, clock, 76*time.Second)
	if got, want := deviceWrites(ctrl)[before:], []string{"remove", "add " + relayOrder[1]}; !slices.Equal(got, want) {
		t.Fatalf("device writes 15 s after the probe = %v, want %v", got, want)
	}
	requireLogLine(t, logs.String(), "wireguard: relayed peer did not answer the probe, dialing the relay again",
		"peer_id=node-a", "endpoint="+relayOrder[1], "silent_for=45s")
	if st := mgr.dial["node-a"]; st.connected || !st.relayed {
		t.Errorf("state = connected %v, relayed %v, want false, true", st.connected, st.relayed)
	}

	// The fresh device peer has no handshake yet.
	ctrl.stats = []PeerStat{{PublicKey: key}}
	passAt(t, mgr, clock, 81*time.Second)
	passAt(t, mgr, clock, 105*time.Second)
	if got := deviceWrites(ctrl)[before:]; len(got) != 2 {
		t.Fatalf("device writes before the relay's trial ran out = %v, want only the re-dial", got)
	}
	passAt(t, mgr, clock, 106*time.Second)
	if got, want := deviceWrites(ctrl)[before:], []string{"remove", "add " + relayOrder[1], "remove", "add " + relayOrder[1]}; !slices.Equal(got, want) {
		t.Fatalf("device writes after the relay's trial = %v, want %v", got, want)
	}
	requireLogLine(t, logs.String(), "wireguard: still no handshake over the relay, dialing it again",
		"peer_id=node-a", "endpoint="+relayOrder[1], "trial=30s")

	for after := 111 * time.Second; after <= 300*time.Second; after += 5 * time.Second {
		passAt(t, mgr, clock, after)
	}
	if slices.Contains(deviceWrites(ctrl)[before:], "add "+relayOrder[0]) {
		t.Errorf("a relayed peer was programmed on a direct entry: %v", deviceWrites(ctrl)[before:])
	}
}

func TestSelectEndpoints_NoProbeWithoutASenderOrOutsideTheMeshPrefix(t *testing.T) {
	passes := func(t *testing.T, mgr *Manager, clock *fakeClock, until time.Duration) {
		t.Helper()
		for after := 36 * time.Second; after <= until; after += 5 * time.Second {
			passAt(t, mgr, clock, after)
		}
	}

	t.Run("no sender", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock, _ := relayedManager(t, &logs, nil)
		before := len(deviceWrites(ctrl))
		passes(t, mgr, clock, 210*time.Second)
		if got := deviceWrites(ctrl)[before:]; len(got) != 0 {
			t.Errorf("device writes before the handshake went stale = %v, want none", got)
		}
	})

	t.Run("direct peer", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		mgr.meshPrefix = netip.MustParsePrefix("10.0.0.0/24")
		key, b64 := testKey(0x0a)
		peer := orderedPeer("node-a", b64, relayOrder...)
		peer.Fallback = relayOrder[1]
		if err := mgr.AddPeer(peer); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		ctrl.stats = []PeerStat{relayStat(key, selectionStart.Add(31*time.Second), 100)}
		passAt(t, mgr, clock, 31*time.Second) // connected on 10.0.0.5:51820
		probe := &fakeProbe{}
		mgr.SetRelayProbe(probe.send)
		passes(t, mgr, clock, 210*time.Second)
		if len(probe.sent) != 0 {
			t.Errorf("probes to a peer connected on a direct entry = %v, want none", probe.sent)
		}
	})

	for _, tc := range []struct {
		name   string
		prefix netip.Prefix
		meshIP string
	}{
		// The host prefix of this node's own mesh IP, as Setup records it for
		// an identity without a usable domain_mesh_cidr.
		{"host prefix", netip.MustParsePrefix("10.0.0.1/32"), ""},
		{"zero prefix", netip.Prefix{}, ""},
		{"unparsable mesh ip", netip.MustParsePrefix("10.0.0.0/24"), "not-an-ip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			mgr, _, clock, _ := relayedManager(t, &logs, func(p *api.Peer) {
				if tc.meshIP != "" {
					p.MeshIP = tc.meshIP
				}
			})
			mgr.meshPrefix = tc.prefix
			probe := &fakeProbe{}
			mgr.SetRelayProbe(probe.send)
			passes(t, mgr, clock, 210*time.Second)
			if len(probe.sent) != 0 {
				t.Errorf("probes = %v, want none", probe.sent)
			}
		})
	}
}

func TestSelectEndpoints_ProbeSendFailure(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
	refused := errors.New("probe refused")
	probe := &fakeProbe{err: refused}
	mgr.SetRelayProbe(probe.send)
	before := len(deviceWrites(ctrl))
	const msg = "wireguard: relay probe send failed"
	countAt := func(level string) int {
		n := 0
		for _, line := range logLines(logs.String(), msg) {
			if strings.Contains(line, "level="+level) {
				n++
			}
		}
		return n
	}

	passAt(t, mgr, clock, 61*time.Second)
	requireLogLine(t, logs.String(), msg, "level=WARN", "peer_id=node-a", "mesh_ip=10.0.0.2")
	if !strings.Contains(logs.String(), `error="probe refused"`) {
		t.Errorf("the send failure does not name its error:\n%s", logs.String())
	}
	passAt(t, mgr, clock, 76*time.Second)
	if got := deviceWrites(ctrl)[before:]; len(got) != 0 {
		t.Fatalf("device writes after a failed send = %v, want none", got)
	}
	passAt(t, mgr, clock, 90*time.Second)
	if len(probe.sent) != 1 {
		t.Fatalf("sends before the silence restarted after the failure ran out = %d, want 1", len(probe.sent))
	}
	passAt(t, mgr, clock, 91*time.Second)
	if len(probe.sent) != 2 || countAt("WARN") != 1 || countAt("DEBUG") != 1 {
		t.Fatalf("after the second failed send: %d sends, %d Warn and %d Debug lines, want 2, 1, 1",
			len(probe.sent), countAt("WARN"), countAt("DEBUG"))
	}

	probe.err = nil
	passAt(t, mgr, clock, 121*time.Second)
	ctrl.stats = []PeerStat{relayStat(key, selectionStart.Add(31*time.Second), 132)}
	passAt(t, mgr, clock, 125*time.Second)
	probe.err = refused
	passAt(t, mgr, clock, 155*time.Second)
	if len(probe.sent) != 4 || countAt("WARN") != 2 {
		t.Errorf("after a success and a new failure: %d sends, %d Warn lines, want 4, 2", len(probe.sent), countAt("WARN"))
	}
}

func TestSelectEndpoints_StaleRelayedPeerRedialsTheRelay(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, _ := relayedManager(t, &logs, nil)
	before := len(deviceWrites(ctrl))

	passAt(t, mgr, clock, 212*time.Second)
	if got, want := deviceWrites(ctrl)[before:], []string{"remove", "add " + relayOrder[1]}; !slices.Equal(got, want) {
		t.Fatalf("device writes when the handshake went stale = %v, want %v", got, want)
	}
	requireLogLine(t, logs.String(), "wireguard: relayed peer handshake went stale, dialing the relay again",
		"peer_id=node-a", "endpoint="+relayOrder[1])
}

func TestSelectEndpoints_RelayRedialFailure(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
	probe := &fakeProbe{}
	mgr.SetRelayProbe(probe.send)
	passAt(t, mgr, clock, 61*time.Second)

	addErr := errors.New("add refused")
	ctrl.addPeerErr = addErr
	clock.Set(selectionStart.Add(76 * time.Second))
	err := mgr.selectEndpoints()
	if err == nil || !strings.Contains(err.Error(), "wireguard: switch endpoint of peer node-a: add device peer:") || !errors.Is(err, addErr) {
		t.Fatalf("selectEndpoints = %v, want wireguard: switch endpoint of peer node-a: add device peer: wrapping %v", err, addErr)
	}
	requireLogLine(t, logs.String(), "wireguard: endpoint switch failed",
		"level=WARN", "peer_id=node-a", "endpoint="+relayOrder[1])
	if st := mgr.dial["node-a"]; st.connected || !st.relayed {
		t.Errorf("state = connected %v, relayed %v, want false, true", st.connected, st.relayed)
	}

	ctrl.addPeerErr = nil
	ctrl.stats = []PeerStat{{PublicKey: key}}
	before := len(deviceWrites(ctrl))
	passAt(t, mgr, clock, 105*time.Second)
	if got := deviceWrites(ctrl)[before:]; len(got) != 0 {
		t.Fatalf("device writes 29 s after the failed re-dial = %v, want none", got)
	}
	passAt(t, mgr, clock, 106*time.Second)
	if got, want := deviceWrites(ctrl)[before:], []string{"remove", "add " + relayOrder[1]}; !slices.Equal(got, want) {
		t.Errorf("device writes one trial after the failed re-dial = %v, want %v", got, want)
	}
}

// A pass reads the device before it takes the mutex. A relay move that lands
// in between replaces the device peer, so the stat the pass read describes the
// old session and must not mark the new device peer connected.
func TestSelectEndpoints_IgnoresAStatReadBeforeAMove(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
	_, b64 := testKey(0x0a)

	clock.Set(selectionStart.Add(40 * time.Second))
	ctrl.onRead = func() {
		ctrl.onRead = nil
		if err := mgr.UpdatePeer(relayUpdate(b64, newRelay)); err != nil {
			t.Errorf("UpdatePeer: %v", err)
		}
	}
	mustSelect(t, mgr)
	if st := mgr.dial["node-a"]; st.connected {
		t.Fatal("the old session's stat marked the moved peer connected")
	}
	if n := len(logLines(logs.String(), "wireguard: endpoint selected")); n != 1 {
		t.Errorf("endpoint selected logged %d times, want once, for the connect at 31 s:\n%s", n, logs.String())
	}

	// The new device peer has no handshake yet, so nothing went stale.
	ctrl.stats = []PeerStat{{PublicKey: key}}
	before := len(deviceWrites(ctrl))
	passAt(t, mgr, clock, 45*time.Second)
	if got := deviceWrites(ctrl)[before:]; len(got) != 0 {
		t.Fatalf("device writes 5 s after the move = %v, want none", got)
	}

	// A handshake over the new relay marks the peer connected.
	moved := relayStat(key, selectionStart.Add(46*time.Second), 10)
	moved.Endpoint = netip.MustParseAddrPort(newRelay)
	ctrl.stats = []PeerStat{moved}
	passAt(t, mgr, clock, 48*time.Second)
	if st := mgr.dial["node-a"]; !st.connected || !st.relayed {
		t.Errorf("after the handshake over the new relay connected = %v, relayed = %v, want both", st.connected, st.relayed)
	}
	requireLogLine(t, logs.String(), "wireguard: endpoint selected", "peer_id=node-a", "endpoint="+newRelay, "relayed=true")
}

// addHookController runs onAdd after each AddPeer it records.
type addHookController struct {
	*statsController
	onAdd func(PeerConfig)
}

func (c *addHookController) AddPeer(iface string, cfg PeerConfig) error {
	err := c.statsController.AddPeer(iface, cfg)
	if c.onAdd != nil {
		c.onAdd(cfg)
	}
	return err
}

// The new device peer starts its handshake inside the write that adds it, so
// the move records the replacement as of a time before that write. A handshake
// that completes before UpdatePeer returns belongs to the new session.
func TestUpdatePeer_MoveStampsTheReplacementBeforeTheWrite(t *testing.T) {
	var logs bytes.Buffer
	stats := &statsController{}
	ctrl := &addHookController{statsController: stats}
	mgr := NewManager(ctrl, Config{}, slogTextLogger(&logs))
	clock := &fakeClock{now: selectionStart}
	mgr.now = clock.Now
	key, b64 := testKey(0x0a)
	peer := orderedPeer("node-a", b64, relayOrder...)
	peer.Fallback = relayOrder[1]
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	passAt(t, mgr, clock, 30*time.Second)
	stats.stats = []PeerStat{relayStat(key, selectionStart.Add(31*time.Second), 100)}
	passAt(t, mgr, clock, 31*time.Second)

	clock.Set(selectionStart.Add(40 * time.Second))
	ctrl.onAdd = func(cfg PeerConfig) {
		if cfg.Endpoint != newRelay {
			return
		}
		// The handshake over the new relay completes during the write, and
		// the goroutine is slow to go on.
		moved := relayStat(key, selectionStart.Add(40*time.Second+20*time.Millisecond), 10)
		moved.Endpoint = netip.MustParseAddrPort(newRelay)
		stats.stats = []PeerStat{moved}
		clock.Set(selectionStart.Add(40*time.Second + 50*time.Millisecond))
	}
	if err := mgr.UpdatePeer(relayUpdate(b64, newRelay)); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	ctrl.onAdd = nil

	passAt(t, mgr, clock, 45*time.Second)
	if st := mgr.dial["node-a"]; !st.connected || !st.relayed {
		t.Errorf("after a handshake over the new relay during the move connected = %v, relayed = %v, want both", st.connected, st.relayed)
	}
}

// A peer is relayed only while the device reports its Fallback as the
// endpoint: a peer that reached this node directly while the relay entry was
// programmed runs on a direct path, which a relay move must not cut.
func TestSelectEndpoints_RelayedFollowsTheDeviceEndpoint(t *testing.T) {
	_, b64 := testKey(0x0a)

	t.Run("connected over a direct path while on the relay entry", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		mgr.meshPrefix = netip.MustParsePrefix("10.0.0.0/24")
		key, _ := testKey(0x0a)
		peer := orderedPeer("node-a", b64, relayOrder...)
		peer.Fallback = relayOrder[1]
		if err := mgr.AddPeer(peer); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		passAt(t, mgr, clock, 30*time.Second)
		direct := relayStat(key, selectionStart.Add(31*time.Second), 100)
		direct.Endpoint = directEndpoint
		ctrl.stats = []PeerStat{direct}
		passAt(t, mgr, clock, 31*time.Second)
		requireLogLine(t, logs.String(), "wireguard: endpoint selected", "peer_id=node-a", "relayed=false")

		probe := &fakeProbe{}
		mgr.SetRelayProbe(probe.send)
		passAt(t, mgr, clock, 61*time.Second)
		passAt(t, mgr, clock, 76*time.Second)
		if len(probe.sent) != 0 {
			t.Errorf("probes to a peer on a direct path = %v, want none", probe.sent)
		}

		before := len(deviceWrites(ctrl))
		if err := mgr.UpdatePeer(relayUpdate(b64, newRelay)); err != nil {
			t.Fatalf("UpdatePeer: %v", err)
		}
		if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add "}) {
			t.Errorf("device writes = %v, want one write without an endpoint, keeping the direct path", got)
		}
	})

	t.Run("roams off the relay while connected", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, ctrl, clock, key := relayedManager(t, &logs, nil)
		probe := &fakeProbe{}
		mgr.SetRelayProbe(probe.send)

		direct := relayStat(key, selectionStart.Add(31*time.Second), 100)
		direct.Endpoint = directEndpoint
		ctrl.stats = []PeerStat{direct}
		passAt(t, mgr, clock, 36*time.Second)
		if mgr.dial["node-a"].relayed {
			t.Fatal("relayed = true while the device reports a direct endpoint, want false")
		}
		passAt(t, mgr, clock, 66*time.Second)
		if len(probe.sent) != 0 {
			t.Fatalf("probes to a peer on a direct path = %v, want none", probe.sent)
		}

		// Back on the relay, the silence window starts at that pass.
		ctrl.stats = []PeerStat{relayStat(key, selectionStart.Add(31*time.Second), 100)}
		passAt(t, mgr, clock, 70*time.Second)
		if !mgr.dial["node-a"].relayed {
			t.Fatal("relayed = false after the device reports the relay again, want true")
		}
		passAt(t, mgr, clock, 99*time.Second)
		if len(probe.sent) != 0 {
			t.Fatalf("probes 29 s after the peer was back on the relay = %v, want none", probe.sent)
		}
		passAt(t, mgr, clock, 100*time.Second)
		if len(probe.sent) != 1 {
			t.Errorf("probes 30 s after the peer was back on the relay = %v, want one", probe.sent)
		}
	})

	t.Run("hostname fallback", func(t *testing.T) {
		var logs bytes.Buffer
		const hostRelay = "relay.example.net:51821"
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		key, _ := testKey(0x0a)
		peer := orderedPeer("node-a", b64, relayOrder[0], hostRelay)
		peer.Fallback = hostRelay
		if err := mgr.AddPeer(peer); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		passAt(t, mgr, clock, 30*time.Second)
		direct := relayStat(key, selectionStart.Add(31*time.Second), 100)
		direct.Endpoint = directEndpoint
		ctrl.stats = []PeerStat{direct}
		passAt(t, mgr, clock, 31*time.Second)
		if !mgr.dial["node-a"].relayed {
			t.Error("relayed = false for a peer on a hostname Fallback, want the programmed entry to decide")
		}
	})
}

func TestUpdatePeer_UnchangedFallbackRestartsAPeerInItsRelayHold(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
	_, b64 := testKey(0x0a)
	peer := orderedPeer("node-a", b64, relayOrder...)
	peer.Fallback = relayOrder[1]
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	passAt(t, mgr, clock, 30*time.Second)

	update := orderedPeer("node-a", b64, "172.31.4.9:51820", relayOrder[0], relayOrder[1])
	update.Fallback = relayOrder[1]
	before := len(deviceWrites(ctrl))
	if err := mgr.UpdatePeer(update); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if got := deviceWrites(ctrl)[before:]; !slices.Equal(got, []string{"add 172.31.4.9:51820"}) {
		t.Errorf("device writes = %v, want the new order's first entry: a peer that never connected over the relay is not relayed", got)
	}
}

func TestSendRelayProbe(t *testing.T) {
	if err := SendRelayProbe(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("SendRelayProbe(127.0.0.1) = %v, want nil", err)
	}
	for _, tc := range []struct {
		addr netip.Addr
		want string
	}{
		{netip.Addr{}, "wireguard: relay probe: mesh ip invalid IP is not IPv4"},
		{netip.MustParseAddr("::1"), "wireguard: relay probe: mesh ip ::1 is not IPv4"},
	} {
		if err := SendRelayProbe(tc.addr); err == nil || err.Error() != tc.want {
			t.Errorf("SendRelayProbe(%v) = %v, want %q", tc.addr, err, tc.want)
		}
	}
}
