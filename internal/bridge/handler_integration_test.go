package bridge

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Integration test infrastructure
// ---------------------------------------------------------------------------

// integrationStateFetcher implements reconcile.StateFetcher for integration tests.
type integrationStateFetcher struct {
	mu    sync.Mutex
	state *api.NodeStateSnapshot

	fetchCount int
}

func (f *integrationStateFetcher) FetchState(_ context.Context, _ string) (*api.NodeStateSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCount++
	return f.state, nil
}

func (f *integrationStateFetcher) setState(state *api.NodeStateSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = state
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

// TestBridgeSetupTeardown verifies that Setup programs the local YAML-sourced
// routes and NAT/forwarding rules, and that Teardown removes them all. Bridge
// routes are no longer carried by the desired-state snapshot; they are
// programmed at Setup from local config.
func TestBridgeSetupTeardown(t *testing.T) {
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

	ctrl.reset()

	// Teardown bridge.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify Teardown calls: all routes removed, NAT removed, forwarding disabled.
	if n := len(ctrl.callsFor("RemoveRoute")); n != 2 {
		t.Errorf("RemoveRoute calls = %d, want 2", n)
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
