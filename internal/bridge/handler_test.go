package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// mockReconcileTrigger records TriggerReconcile calls.
type mockReconcileTrigger struct {
	triggered int
}

func (m *mockReconcileTrigger) TriggerReconcile() {
	m.triggered++
}

// ---------------------------------------------------------------------------
// ReconcileHandler tests
// ---------------------------------------------------------------------------

func TestReconcileHandler_NoBridgeChanges(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	// Setup bridge so it has active routes.
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.reset()

	handler := ReconcileHandler(mgr)

	// Desired state has nil BridgeConfig — no bridge changes.
	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk", MeshIP: "10.42.0.2"}},
	}
	diff := reconcile.StateDiff{
		PeersToAdd: []api.Peer{{ID: "p1"}},
	}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// No route modifications should have occurred.
	if n := len(ctrl.callsFor("AddRoute")); n != 0 {
		t.Errorf("AddRoute calls = %d, want 0", n)
	}
	if n := len(ctrl.callsFor("RemoveRoute")); n != 0 {
		t.Errorf("RemoveRoute calls = %d, want 0", n)
	}
}

func TestReconcileHandler_NewSubnets(t *testing.T) {
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
	ctrl.reset()

	handler := ReconcileHandler(mgr)

	// Desired state includes new subnets.
	desired := &api.StateResponse{
		BridgeConfig: &api.BridgeConfig{
			AccessSubnets: []string{"10.0.0.0/24", "192.168.1.0/24"},
			EnableNAT:     true,
		},
	}
	diff := reconcile.StateDiff{
		MetadataChanged: true, // trigger non-empty diff
	}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// New subnet should be added.
	addCalls := ctrl.callsFor("AddRoute")
	if len(addCalls) != 1 {
		t.Fatalf("AddRoute calls = %d, want 1", len(addCalls))
	}
	if addCalls[0].Args[0] != "192.168.1.0/24" {
		t.Errorf("AddRoute subnet = %v, want 192.168.1.0/24", addCalls[0].Args[0])
	}
}

func TestReconcileHandler_RemovedSubnets(t *testing.T) {
	ctrl := &mockRouteController{}
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
	}
	mgr := NewManager(ctrl, cfg, discardLogger())

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.reset()

	handler := ReconcileHandler(mgr)

	// Desired state has only one subnet — the other should be removed.
	desired := &api.StateResponse{
		BridgeConfig: &api.BridgeConfig{
			AccessSubnets: []string{"10.0.0.0/24"},
			EnableNAT:     true,
		},
	}
	diff := reconcile.StateDiff{
		MetadataChanged: true,
	}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Stale subnet should be removed.
	removeCalls := ctrl.callsFor("RemoveRoute")
	if len(removeCalls) != 1 {
		t.Fatalf("RemoveRoute calls = %d, want 1", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "192.168.1.0/24" {
		t.Errorf("RemoveRoute subnet = %v, want 192.168.1.0/24", removeCalls[0].Args[0])
	}

	// Existing subnet should NOT be re-added.
	addCalls := ctrl.callsFor("AddRoute")
	if len(addCalls) != 0 {
		t.Errorf("AddRoute calls = %d, want 0", len(addCalls))
	}
}

// ---------------------------------------------------------------------------
// SSE Handler tests
// ---------------------------------------------------------------------------

func TestHandleBridgeConfigUpdated(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleBridgeConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventBridgeConfigUpdated,
		EventID:   "evt-1",
		Payload:   json.RawMessage(`{"access_subnets":["10.0.0.0/24"]}`),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}

func TestHandleBridgeConfigUpdated_MalformedPayload(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleBridgeConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventBridgeConfigUpdated,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	// TriggerReconcile should still be called despite malformed payload.
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}
