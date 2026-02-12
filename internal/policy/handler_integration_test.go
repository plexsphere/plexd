package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// ---------------------------------------------------------------------------
// Integration test infrastructure
// ---------------------------------------------------------------------------

// trackingWGController is a thread-safe mock WGController that records all
// AddPeer/RemovePeer calls for integration assertions.
type trackingWGController struct {
	mu         sync.Mutex
	addPeers   []wireguard.PeerConfig
	removeCalls [][]byte // public keys
	addPeerErr  error
	removePeerErr error
}

func (c *trackingWGController) CreateInterface(string, []byte, int) error { return nil }
func (c *trackingWGController) DeleteInterface(string) error              { return nil }
func (c *trackingWGController) ConfigureAddress(string, string) error     { return nil }
func (c *trackingWGController) SetInterfaceUp(string) error               { return nil }
func (c *trackingWGController) SetMTU(string, int) error                  { return nil }

func (c *trackingWGController) AddPeer(_ string, cfg wireguard.PeerConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addPeers = append(c.addPeers, cfg)
	return c.addPeerErr
}

func (c *trackingWGController) RemovePeer(_ string, publicKey []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeCalls = append(c.removeCalls, publicKey)
	return c.removePeerErr
}

func (c *trackingWGController) addPeerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.addPeers)
}

func (c *trackingWGController) removePeerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.removeCalls)
}

// integrationStateFetcher implements reconcile.StateFetcher for integration tests.
type integrationStateFetcher struct {
	mu    sync.Mutex
	state *api.StateResponse
	err   error

	fetchCount int
	driftCount int
}

func (f *integrationStateFetcher) FetchState(_ context.Context, _ string) (*api.StateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.state, nil
}

func (f *integrationStateFetcher) ReportDrift(_ context.Context, _ string, _ api.DriftReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.driftCount++
	return nil
}

func (f *integrationStateFetcher) setState(state *api.StateResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = state
}

func (f *integrationStateFetcher) getFetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetchCount
}

func integrationPeer(id, meshIP string) api.Peer {
	key := make([]byte, 32)
	copy(key, []byte(id))
	return api.Peer{
		ID:         id,
		PublicKey:  base64.StdEncoding.EncodeToString(key),
		MeshIP:     meshIP,
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{meshIP + "/32"},
	}
}

// waitForCondition polls until cond returns true or timeout expires.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out after %v waiting for condition", timeout)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestIntegration_FullPolicyEnforcementFlow wires a real PolicyEngine, mock
// FirewallController, mock WGController, and real Reconciler. Verifies:
// policies arrive → firewall rules applied → peers filtered → WireGuard updated.
func TestIntegration_FullPolicyEnforcementFlow(t *testing.T) {
	wgCtrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(wgCtrl, wireguard.Config{}, testLogger())
	fwCtrl := &mockFirewallController{}
	engine := NewPolicyEngine(testLogger())
	enforcer := NewEnforcer(engine, fwCtrl, Config{}, testLogger())

	peerB := integrationPeer("peer-b", "10.0.0.2")
	peerC := integrationPeer("peer-c", "10.0.0.3")

	state := &api.StateResponse{
		Peers: []api.Peer{peerB, peerC},
		Policies: []api.Policy{
			{
				ID: "pol-1",
				Rules: []api.PolicyRule{
					{Src: "node-a", Dst: "peer-b", Port: 443, Protocol: "tcp", Action: "allow"},
				},
			},
		},
	}

	fetcher := &integrationStateFetcher{state: state}

	reconciler := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	// Wait for the initial reconciliation cycle.
	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() >= 1 })

	// Firewall rules should be applied.
	if len(fwCtrl.ensureChainCalls) != 1 {
		t.Errorf("EnsureChain calls = %d, want 1", len(fwCtrl.ensureChainCalls))
	}
	if len(fwCtrl.applyRulesCalls) != 1 {
		t.Errorf("ApplyRules calls = %d, want 1", len(fwCtrl.applyRulesCalls))
	}

	// Only peer-b should be added (peer-c not allowed by policy).
	if n := wgCtrl.addPeerCount(); n != 1 {
		t.Errorf("AddPeer calls = %d, want 1 (only peer-b allowed)", n)
	}

	cancel()
	<-done
}

// TestIntegration_PolicyRemovalRevokesAccess verifies that when a policy is
// replaced with one that no longer allows a peer, the peer is removed from WireGuard.
func TestIntegration_PolicyRemovalRevokesAccess(t *testing.T) {
	wgCtrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(wgCtrl, wireguard.Config{}, testLogger())
	fwCtrl := &mockFirewallController{}
	engine := NewPolicyEngine(testLogger())
	enforcer := NewEnforcer(engine, fwCtrl, Config{}, testLogger())

	peerB := integrationPeer("peer-b", "10.0.0.2")

	// Initial state: peer-b allowed.
	state1 := &api.StateResponse{
		Peers: []api.Peer{peerB},
		Policies: []api.Policy{
			{ID: "pol-1", Rules: []api.PolicyRule{{Src: "node-a", Dst: "peer-b", Action: "allow"}}},
		},
	}
	fetcher := &integrationStateFetcher{state: state1}

	reconciler := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: 50 * time.Millisecond}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	// Wait for initial cycle: peer-b should be added.
	waitForCondition(t, 2*time.Second, func() bool { return wgCtrl.addPeerCount() >= 1 })

	// Change state: replace policy with one that doesn't allow peer-b.
	state2 := &api.StateResponse{
		Peers: []api.Peer{peerB},
		Policies: []api.Policy{
			{ID: "pol-2", Rules: []api.PolicyRule{{Src: "node-a", Dst: "peer-x", Action: "allow"}}},
		},
	}
	fetcher.setState(state2)

	// Trigger reconcile and wait for peer-b to be removed.
	reconciler.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool { return wgCtrl.removePeerCount() >= 1 })

	if n := wgCtrl.removePeerCount(); n < 1 {
		t.Errorf("RemovePeer calls = %d, want >= 1", n)
	}

	cancel()
	<-done
}

// TestIntegration_SSEPolicyUpdatedTriggersReconcile verifies that dispatching a
// policy_updated SSE event through a real EventDispatcher calls TriggerReconcile
// on the Reconciler, causing a new reconciliation cycle.
func TestIntegration_SSEPolicyUpdatedTriggersReconcile(t *testing.T) {
	wgCtrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(wgCtrl, wireguard.Config{}, testLogger())
	fwCtrl := &mockFirewallController{}
	engine := NewPolicyEngine(testLogger())
	enforcer := NewEnforcer(engine, fwCtrl, Config{}, testLogger())

	peerB := integrationPeer("peer-b", "10.0.0.2")

	state := &api.StateResponse{
		Peers: []api.Peer{peerB},
		Policies: []api.Policy{
			{ID: "pol-1", Rules: []api.PolicyRule{{Src: "*", Dst: "*", Action: "allow"}}},
		},
	}
	fetcher := &integrationStateFetcher{state: state}

	reconciler := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0"))

	// Register SSE handler via a real EventDispatcher.
	dispatcher := api.NewEventDispatcher(testLogger())
	dispatcher.Register(api.EventPolicyUpdated, HandlePolicyUpdated(reconciler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	// Wait for initial cycle.
	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() >= 1 })
	initialFetch := fetcher.getFetchCount()

	// Dispatch a policy_updated SSE event.
	payload, _ := json.Marshal(map[string]string{"policy_id": "pol-1"})
	envelope := api.SignedEnvelope{
		EventType: api.EventPolicyUpdated,
		EventID:   "evt-sse-1",
		Payload:   payload,
	}
	dispatcher.Dispatch(ctx, envelope)

	// Wait for an additional fetch (triggered reconcile cycle).
	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() > initialFetch })

	if n := fetcher.getFetchCount(); n <= initialFetch {
		t.Errorf("FetchState calls = %d, want > %d (SSE should trigger reconcile)", n, initialFetch)
	}

	cancel()
	<-done
}

// TestIntegration_ConcurrentPolicyAndPeerChangesNoRace exercises concurrent
// policy changes and peer additions to verify no data races. Run with -race.
func TestIntegration_ConcurrentPolicyAndPeerChangesNoRace(t *testing.T) {
	wgCtrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(wgCtrl, wireguard.Config{}, testLogger())
	fwCtrl := &mockFirewallController{}
	engine := NewPolicyEngine(testLogger())
	enforcer := NewEnforcer(engine, fwCtrl, Config{}, testLogger())

	// Cycle counter for switching states.
	var cycle atomic.Int32

	state1 := &api.StateResponse{
		Peers: []api.Peer{
			integrationPeer("peer-b", "10.0.0.2"),
			integrationPeer("peer-c", "10.0.0.3"),
		},
		Policies: []api.Policy{
			{ID: "pol-1", Rules: []api.PolicyRule{{Src: "*", Dst: "*", Action: "allow"}}},
		},
	}
	state2 := &api.StateResponse{
		Peers: []api.Peer{
			integrationPeer("peer-b", "10.0.0.2"),
		},
		Policies: []api.Policy{
			{ID: "pol-2", Rules: []api.PolicyRule{{Src: "node-a", Dst: "peer-b", Action: "allow"}}},
		},
	}

	fetcher := &integrationStateFetcher{state: state1}
	fetcher.mu.Lock()
	origFetch := fetcher.FetchState
	_ = origFetch
	fetcher.mu.Unlock()

	// Override FetchState to alternate between states.
	alternateFetcher := &alternatingStateFetcher{
		states: []*api.StateResponse{state1, state2},
		cycle:  &cycle,
	}

	reconciler := reconcile.NewReconciler(alternateFetcher, reconcile.Config{Interval: 30 * time.Millisecond}, testLogger())
	reconciler.RegisterHandler(ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0"))

	// Register SSE handler.
	dispatcher := api.NewEventDispatcher(testLogger())
	dispatcher.Register(api.EventPolicyUpdated, HandlePolicyUpdated(reconciler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, "node-a") }()

	// Concurrently dispatch SSE events while the reconcile loop runs.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]string{"policy_id": "pol-x"})
			envelope := api.SignedEnvelope{
				EventType: api.EventPolicyUpdated,
				EventID:   "concurrent-evt",
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}()
	}

	// Let the reconcile loop run several cycles.
	time.Sleep(300 * time.Millisecond)

	wg.Wait()
	cancel()
	<-done

	// Test passes if no race is detected. Verify some activity occurred.
	if n := alternateFetcher.getFetchCount(); n < 2 {
		t.Errorf("FetchState calls = %d, want >= 2", n)
	}
}

// alternatingStateFetcher returns different states on each fetch.
type alternatingStateFetcher struct {
	mu         sync.Mutex
	states     []*api.StateResponse
	cycle      *atomic.Int32
	fetchCount int
}

func (f *alternatingStateFetcher) FetchState(_ context.Context, _ string) (*api.StateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCount++
	idx := int(f.cycle.Add(1)-1) % len(f.states)
	return f.states[idx], nil
}

func (f *alternatingStateFetcher) ReportDrift(_ context.Context, _ string, _ api.DriftReport) error {
	return nil
}

func (f *alternatingStateFetcher) getFetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetchCount
}
