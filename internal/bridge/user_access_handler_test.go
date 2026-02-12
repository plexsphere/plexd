package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// peerAssignmentEnvelope builds a SignedEnvelope for a user access peer assignment.
func peerAssignmentEnvelope(t *testing.T, peer api.UserAccessPeer) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(peer)
	if err != nil {
		t.Fatalf("marshal peer: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventUserAccessPeerAssigned,
		EventID:   "evt-assign-" + peer.PublicKey,
		Payload:   payload,
	}
}

// peerRevocationEnvelope builds a SignedEnvelope for a user access peer revocation.
func peerRevocationEnvelope(t *testing.T, publicKey string) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(struct {
		PublicKey string `json:"public_key"`
	}{PublicKey: publicKey})
	if err != nil {
		t.Fatalf("marshal revocation: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventUserAccessPeerRevoked,
		EventID:   "evt-revoke-" + publicKey,
		Payload:   payload,
	}
}

// newTestUserAccessManager creates a UserAccessManager for handler tests with
// mocks and a pre-configured, setup-ready config.
func newTestUserAccessManager(t *testing.T, ctrl *mockAccessController, routes *mockRouteController) *UserAccessManager {
	t.Helper()
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()
	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetAccess()
	routes.reset()
	return mgr
}

// ---------------------------------------------------------------------------
// HandleUserAccessPeerAssigned tests
// ---------------------------------------------------------------------------

func TestHandleUserAccessPeerAssigned_Success(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	handler := HandleUserAccessPeerAssigned(mgr, discardLogger())

	peer := api.UserAccessPeer{
		PublicKey:  "pk-1",
		AllowedIPs: []string{"10.99.0.1/32"},
		PSK:       "psk-1",
		Label:     "alice",
	}
	envelope := peerAssignmentEnvelope(t, peer)

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	configureCalls := ctrl.accessCallsFor("ConfigurePeer")
	if len(configureCalls) != 1 {
		t.Fatalf("expected 1 ConfigurePeer call, got %d", len(configureCalls))
	}
	if configureCalls[0].Args[1] != "pk-1" {
		t.Errorf("ConfigurePeer publicKey = %v, want pk-1", configureCalls[0].Args[1])
	}

	status := mgr.UserAccessStatus()
	if status == nil || status.PeerCount != 1 {
		t.Errorf("PeerCount = %v, want 1", status)
	}
}

func TestHandleUserAccessPeerAssigned_MalformedPayload(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	handler := HandleUserAccessPeerAssigned(mgr, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventUserAccessPeerAssigned,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

func TestHandleUserAccessPeerAssigned_DuplicatePeer(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	handler := HandleUserAccessPeerAssigned(mgr, discardLogger())

	peer := api.UserAccessPeer{
		PublicKey:  "pk-dup",
		AllowedIPs: []string{"10.99.0.1/32"},
		Label:     "alice",
	}
	envelope := peerAssignmentEnvelope(t, peer)

	// First add should succeed.
	if err := handler(context.Background(), envelope); err != nil {
		t.Fatalf("first handler call: %v", err)
	}

	// Second add with same public key should fail.
	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for duplicate peer")
	}
}

// ---------------------------------------------------------------------------
// HandleUserAccessPeerRevoked tests
// ---------------------------------------------------------------------------

func TestHandleUserAccessPeerRevoked_Success(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	assignHandler := HandleUserAccessPeerAssigned(mgr, discardLogger())
	revokeHandler := HandleUserAccessPeerRevoked(mgr, discardLogger())

	// Add a peer first.
	peer := api.UserAccessPeer{
		PublicKey:  "pk-revoke",
		AllowedIPs: []string{"10.99.0.1/32"},
		Label:     "alice",
	}
	if err := assignHandler(context.Background(), peerAssignmentEnvelope(t, peer)); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if mgr.UserAccessStatus().PeerCount != 1 {
		t.Fatalf("PeerCount after assign = %d, want 1", mgr.UserAccessStatus().PeerCount)
	}

	// Revoke the peer.
	envelope := peerRevocationEnvelope(t, "pk-revoke")
	err := revokeHandler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if mgr.UserAccessStatus().PeerCount != 0 {
		t.Errorf("PeerCount after revoke = %d, want 0", mgr.UserAccessStatus().PeerCount)
	}
}

func TestHandleUserAccessPeerRevoked_MalformedPayload(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	handler := HandleUserAccessPeerRevoked(mgr, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventUserAccessPeerRevoked,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

func TestHandleUserAccessPeerRevoked_NonExistent(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	handler := HandleUserAccessPeerRevoked(mgr, discardLogger())

	// Revoking a non-existent peer should be a no-op.
	envelope := peerRevocationEnvelope(t, "nonexistent")
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// HandleUserAccessConfigUpdated tests
// ---------------------------------------------------------------------------

func TestHandleUserAccessConfigUpdated(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleUserAccessConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventUserAccessConfigUpdated,
		EventID:   "evt-1",
		Payload:   json.RawMessage(`{"enabled":true}`),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}

func TestHandleUserAccessConfigUpdated_MalformedPayload(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleUserAccessConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventUserAccessConfigUpdated,
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

// ---------------------------------------------------------------------------
// UserAccessReconcileHandler tests
// ---------------------------------------------------------------------------

func TestUserAccessReconcileHandler_NilConfig(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	handler := UserAccessReconcileHandler(mgr, discardLogger())

	// Desired state has nil UserAccessConfig — no changes.
	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk", MeshIP: "10.42.0.2"}},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if len(ctrl.accessCallsFor("ConfigurePeer")) != 0 {
		t.Error("ConfigurePeer should not be called when UserAccessConfig is nil")
	}
}

func TestUserAccessReconcileHandler_AddMissing(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	handler := UserAccessReconcileHandler(mgr, discardLogger())

	desired := &api.StateResponse{
		UserAccessConfig: &api.UserAccessConfig{
			Enabled:       true,
			InterfaceName: "wg-access",
			ListenPort:    51822,
			Peers: []api.UserAccessPeer{
				{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"},
				{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	configureCalls := ctrl.accessCallsFor("ConfigurePeer")
	if len(configureCalls) != 2 {
		t.Fatalf("expected 2 ConfigurePeer calls, got %d", len(configureCalls))
	}

	if mgr.UserAccessStatus().PeerCount != 2 {
		t.Errorf("PeerCount = %d, want 2", mgr.UserAccessStatus().PeerCount)
	}
}

func TestUserAccessReconcileHandler_RemoveStale(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	// Pre-populate with two peers.
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	ctrl.resetAccess()

	handler := UserAccessReconcileHandler(mgr, discardLogger())

	// Desired state: only pk-1 remains.
	desired := &api.StateResponse{
		UserAccessConfig: &api.UserAccessConfig{
			Enabled:       true,
			InterfaceName: "wg-access",
			ListenPort:    51822,
			Peers: []api.UserAccessPeer{
				{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	removeCalls := ctrl.accessCallsFor("RemovePeer")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemovePeer call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[1] != "pk-2" {
		t.Errorf("RemovePeer publicKey = %v, want pk-2", removeCalls[0].Args[1])
	}

	if mgr.UserAccessStatus().PeerCount != 1 {
		t.Errorf("PeerCount = %d, want 1", mgr.UserAccessStatus().PeerCount)
	}
}

func TestUserAccessReconcileHandler_Mixed(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	mgr := newTestUserAccessManager(t, ctrl, routes)

	// Pre-populate with two peers.
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-keep", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := mgr.AddPeer(api.UserAccessPeer{PublicKey: "pk-stale", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	ctrl.resetAccess()

	handler := UserAccessReconcileHandler(mgr, discardLogger())

	// Desired: keep pk-keep, add pk-new, remove pk-stale.
	desired := &api.StateResponse{
		UserAccessConfig: &api.UserAccessConfig{
			Enabled:       true,
			InterfaceName: "wg-access",
			ListenPort:    51822,
			Peers: []api.UserAccessPeer{
				{PublicKey: "pk-keep", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"},
				{PublicKey: "pk-new", AllowedIPs: []string{"10.99.0.3/32"}, Label: "charlie"},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Verify pk-stale was removed.
	removeCalls := ctrl.accessCallsFor("RemovePeer")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemovePeer call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[1] != "pk-stale" {
		t.Errorf("RemovePeer publicKey = %v, want pk-stale", removeCalls[0].Args[1])
	}

	// Verify pk-new was added.
	configureCalls := ctrl.accessCallsFor("ConfigurePeer")
	if len(configureCalls) != 1 {
		t.Fatalf("expected 1 ConfigurePeer call, got %d", len(configureCalls))
	}
	if configureCalls[0].Args[1] != "pk-new" {
		t.Errorf("ConfigurePeer publicKey = %v, want pk-new", configureCalls[0].Args[1])
	}

	if mgr.UserAccessStatus().PeerCount != 2 {
		t.Errorf("PeerCount = %d, want 2", mgr.UserAccessStatus().PeerCount)
	}
}
