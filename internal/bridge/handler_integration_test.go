package bridge

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration test infrastructure
// ---------------------------------------------------------------------------

// integrationStateFetcher implements reconcile.StateFetcher for integration tests.
type integrationStateFetcher struct {
	mu    sync.Mutex
	state *api.StateResponse

	fetchCount int
	driftCount int
}

func (f *integrationStateFetcher) FetchState(_ context.Context, _ string) (*api.StateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCount++
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

// TestBridgeReconcileIntegration_FullFlow wires a bridge Manager with a mock
// RouteController and a real Reconciler. Verifies the full reconciliation
// cycle: state with BridgeConfig → diff computation → bridge handler adds/removes routes.
func TestBridgeReconcileIntegration_FullFlow(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	// Setup bridge (initial routes).
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.reset()

	// Initial state: bridge config with one subnet (already active).
	// Metadata is used to ensure the reconciler detects drift (ComputeDiff
	// does not track BridgeConfig changes — it's handled by the bridge handler
	// whenever any drift is detected).
	state1 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		BridgeConfig: &api.BridgeConfig{
			AccessSubnets: []string{"10.0.0.0/24"},
			EnableNAT:     true,
		},
		Metadata: map[string]string{"version": "1"},
	}
	fetcher := &integrationStateFetcher{state: state1}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(ReconcileHandler(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-a") }()

	// Wait for initial cycle to complete (handler runs after fetch).
	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() >= 1 })
	// Allow handler to finish after fetch.
	time.Sleep(50 * time.Millisecond)

	// No route changes expected — subnet already active.
	if n := len(ctrl.callsFor("AddRoute")); n != 0 {
		t.Errorf("AddRoute calls after initial = %d, want 0", n)
	}

	// Update state: add a new subnet + bump metadata to trigger diff.
	state2 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		BridgeConfig: &api.BridgeConfig{
			AccessSubnets: []string{"10.0.0.0/24", "192.168.1.0/24"},
			EnableNAT:     true,
		},
		Metadata: map[string]string{"version": "2"},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for the handler side-effect, not just the fetch.
	waitForCondition(t, 2*time.Second, func() bool { return len(ctrl.callsFor("AddRoute")) >= 1 })

	addCalls := ctrl.callsFor("AddRoute")
	if len(addCalls) != 1 {
		t.Fatalf("AddRoute calls = %d, want 1", len(addCalls))
	}
	if addCalls[0].Args[0] != "192.168.1.0/24" {
		t.Errorf("AddRoute subnet = %v, want 192.168.1.0/24", addCalls[0].Args[0])
	}
	ctrl.reset()

	// Update state: remove the original subnet + bump metadata.
	state3 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		BridgeConfig: &api.BridgeConfig{
			AccessSubnets: []string{"192.168.1.0/24"},
			EnableNAT:     true,
		},
		Metadata: map[string]string{"version": "3"},
	}
	fetcher.setState(state3)
	rec.TriggerReconcile()

	// Wait for the handler side-effect.
	waitForCondition(t, 2*time.Second, func() bool { return len(ctrl.callsFor("RemoveRoute")) >= 1 })

	removeCalls := ctrl.callsFor("RemoveRoute")
	if len(removeCalls) != 1 {
		t.Fatalf("RemoveRoute calls = %d, want 1", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "10.0.0.0/24" {
		t.Errorf("RemoveRoute subnet = %v, want 10.0.0.0/24", removeCalls[0].Args[0])
	}

	cancel()
	<-done
}

// TestBridgeReconcileIntegration_SetupTeardown verifies that Setup followed
// by Teardown leaves no orphaned routes or forwarding rules. Uses a real
// Reconciler to exercise the full lifecycle.
func TestBridgeReconcileIntegration_SetupTeardown(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "172.16.0.0/16"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	// Setup bridge.
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Verify Setup calls.
	if n := len(ctrl.callsFor("EnableForwarding")); n != 1 {
		t.Errorf("EnableForwarding calls = %d, want 1", n)
	}
	if n := len(ctrl.callsFor("AddRoute")); n != 2 {
		t.Errorf("AddRoute calls = %d, want 2", n)
	}
	if n := len(ctrl.callsFor("AddNATMasquerade")); n != 1 {
		t.Errorf("AddNATMasquerade calls = %d, want 1", n)
	}

	// Run one reconcile cycle to exercise handler with active bridge.
	state := &api.StateResponse{
		BridgeConfig: &api.BridgeConfig{
			AccessSubnets: []string{"10.0.0.0/24", "172.16.0.0/16"},
			EnableNAT:     true,
		},
	}
	fetcher := &integrationStateFetcher{state: state}
	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(ReconcileHandler(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-a") }()

	waitForCondition(t, 2*time.Second, func() bool { return fetcher.getFetchCount() >= 1 })

	cancel()
	<-done

	ctrl.reset()

	// Teardown bridge.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify Teardown calls: all routes removed, NAT removed, forwarding disabled.
	removeCalls := ctrl.callsFor("RemoveRoute")
	if len(removeCalls) != 2 {
		t.Errorf("RemoveRoute calls = %d, want 2", len(removeCalls))
	}
	if n := len(ctrl.callsFor("RemoveNATMasquerade")); n != 1 {
		t.Errorf("RemoveNATMasquerade calls = %d, want 1", n)
	}
	if n := len(ctrl.callsFor("DisableForwarding")); n != 1 {
		t.Errorf("DisableForwarding calls = %d, want 1", n)
	}

	// Bridge should be inactive after teardown.
	if mgr.BridgeStatus() != nil {
		t.Error("BridgeStatus should be nil after teardown")
	}

	// Second teardown should be a no-op.
	ctrl.reset()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
	if n := len(ctrl.callsFor("RemoveRoute")); n != 0 {
		t.Errorf("RemoveRoute calls on second teardown = %d, want 0", n)
	}
}

// TestBridgeReconcileIntegration_ConcurrentNoRace exercises concurrent bridge
// config changes and reconcile triggers to verify no data races. Run with -race.
func TestBridgeReconcileIntegration_ConcurrentNoRace(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var cycle atomic.Int32
	states := []*api.StateResponse{
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			BridgeConfig: &api.BridgeConfig{
				AccessSubnets: []string{"10.0.0.0/24"},
			},
		},
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			BridgeConfig: &api.BridgeConfig{
				AccessSubnets: []string{"10.0.0.0/24", "192.168.1.0/24"},
			},
		},
	}

	fetcher := &alternatingBridgeFetcher{
		states: states,
		cycle:  &cycle,
	}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: 30 * time.Millisecond}, discardLogger())
	rec.RegisterHandler(ReconcileHandler(mgr))

	dispatcher := api.NewEventDispatcher(discardLogger())
	dispatcher.Register(api.EventBridgeConfigUpdated, HandleBridgeConfigUpdated(rec))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-a") }()

	// Concurrently dispatch SSE events while the reconcile loop runs.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			envelope := api.SignedEnvelope{
				EventType: api.EventBridgeConfigUpdated,
				EventID:   "concurrent-evt",
			}
			dispatcher.Dispatch(ctx, envelope)
		}()
	}

	// Let the reconcile loop run several cycles.
	time.Sleep(300 * time.Millisecond)

	wg.Wait()
	cancel()
	<-done

	// Test passes if no race detected. Verify some activity occurred.
	if n := fetcher.getFetchCount(); n < 2 {
		t.Errorf("FetchState calls = %d, want >= 2", n)
	}
}

// alternatingBridgeFetcher returns different states on each fetch for race testing.
type alternatingBridgeFetcher struct {
	mu         sync.Mutex
	states     []*api.StateResponse
	cycle      *atomic.Int32
	fetchCount int
}

func (f *alternatingBridgeFetcher) FetchState(_ context.Context, _ string) (*api.StateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCount++
	idx := int(f.cycle.Add(1)-1) % len(f.states)
	return f.states[idx], nil
}

func (f *alternatingBridgeFetcher) ReportDrift(_ context.Context, _ string, _ api.DriftReport) error {
	return nil
}

func (f *alternatingBridgeFetcher) getFetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetchCount
}
