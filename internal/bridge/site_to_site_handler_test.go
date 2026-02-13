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

// tunnelAssignmentEnvelope builds a SignedEnvelope for a site-to-site tunnel assignment.
func tunnelAssignmentEnvelope(t *testing.T, tunnel api.SiteToSiteTunnel) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(tunnel)
	if err != nil {
		t.Fatalf("marshal tunnel: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventSiteToSiteTunnelAssigned,
		EventID:   "evt-assign-" + tunnel.TunnelID,
		Payload:   payload,
	}
}

// tunnelRevocationEnvelope builds a SignedEnvelope for a site-to-site tunnel revocation.
func tunnelRevocationEnvelope(t *testing.T, tunnelID string) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(struct {
		TunnelID string `json:"tunnel_id"`
	}{TunnelID: tunnelID})
	if err != nil {
		t.Fatalf("marshal revocation: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventSiteToSiteTunnelRevoked,
		EventID:   "evt-revoke-" + tunnelID,
		Payload:   payload,
	}
}

// newTestSiteToSiteManager creates a SiteToSiteManager for handler tests with mocks.
func newTestSiteToSiteManager(t *testing.T, vpnCtrl *mockVPNController, routeCtrl *mockRouteController) *SiteToSiteManager {
	t.Helper()
	cfg := Config{
		Enabled:          true,
		AccessInterface:  "eth1",
		AccessSubnets:    []string{"10.0.0.0/24"},
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger())
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()
	return mgr
}

// testTunnel returns a standard tunnel for testing.
func testTunnel(id string) api.SiteToSiteTunnel {
	return api.SiteToSiteTunnel{
		TunnelID:        id,
		RemoteEndpoint:  "203.0.113.1:51820",
		RemotePublicKey: "remote-pub-key-" + id,
		LocalSubnets:    []string{"10.0.0.0/24"},
		RemoteSubnets:   []string{"192.168.1.0/24"},
		InterfaceName:   "wg-s2s-" + id,
		ListenPort:      51823,
	}
}

// ---------------------------------------------------------------------------
// HandleSiteToSiteConfigUpdated tests
// ---------------------------------------------------------------------------

func TestHandleSiteToSiteConfigUpdated(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleSiteToSiteConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventSiteToSiteConfigUpdated,
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

func TestHandleSiteToSiteConfigUpdated_MalformedPayload(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleSiteToSiteConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventSiteToSiteConfigUpdated,
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
// HandleSiteToSiteTunnelAssigned tests
// ---------------------------------------------------------------------------

func TestHandleSiteToSiteTunnelAssigned(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	handler := HandleSiteToSiteTunnelAssigned(mgr, discardLogger())

	tunnel := testTunnel("tun-1")
	envelope := tunnelAssignmentEnvelope(t, tunnel)

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Verify CreateTunnelInterface was called.
	createCalls := vpnCtrl.vpnCallsFor("CreateTunnelInterface")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateTunnelInterface call, got %d", len(createCalls))
	}

	// Verify tunnel is tracked.
	ids := mgr.TunnelIDs()
	if len(ids) != 1 || ids[0] != "tun-1" {
		t.Errorf("TunnelIDs = %v, want [tun-1]", ids)
	}

	status := mgr.SiteToSiteStatus()
	if status == nil || status.TunnelCount != 1 {
		t.Errorf("TunnelCount = %v, want 1", status)
	}
}

func TestHandleSiteToSiteTunnelAssigned_MalformedPayload(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	handler := HandleSiteToSiteTunnelAssigned(mgr, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventSiteToSiteTunnelAssigned,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

// ---------------------------------------------------------------------------
// HandleSiteToSiteTunnelRevoked tests
// ---------------------------------------------------------------------------

func TestHandleSiteToSiteTunnelRevoked(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	// Add a tunnel first.
	tunnel := testTunnel("tun-revoke")
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	if len(mgr.TunnelIDs()) != 1 {
		t.Fatalf("TunnelIDs count after add = %d, want 1", len(mgr.TunnelIDs()))
	}

	handler := HandleSiteToSiteTunnelRevoked(mgr, discardLogger())

	envelope := tunnelRevocationEnvelope(t, "tun-revoke")
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if len(mgr.TunnelIDs()) != 0 {
		t.Errorf("TunnelIDs count after revoke = %d, want 0", len(mgr.TunnelIDs()))
	}
}

func TestHandleSiteToSiteTunnelRevoked_NonExistent(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	handler := HandleSiteToSiteTunnelRevoked(mgr, discardLogger())

	// Revoking a non-existent tunnel should be a no-op.
	envelope := tunnelRevocationEnvelope(t, "nonexistent")
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
}

func TestHandleSiteToSiteTunnelRevoked_MalformedPayload(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	handler := HandleSiteToSiteTunnelRevoked(mgr, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventSiteToSiteTunnelRevoked,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

// ---------------------------------------------------------------------------
// SiteToSiteReconcileHandler tests
// ---------------------------------------------------------------------------

func TestSiteToSiteReconcileHandler_NilConfig(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	handler := SiteToSiteReconcileHandler(mgr, discardLogger())

	// Desired state has nil SiteToSiteConfig — no changes.
	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk", MeshIP: "10.42.0.2"}},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called when SiteToSiteConfig is nil")
	}
}

func TestSiteToSiteReconcileHandler_AddsNewTunnels(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	handler := SiteToSiteReconcileHandler(mgr, discardLogger())

	desired := &api.StateResponse{
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{
				testTunnel("tun-1"),
				testTunnel("tun-2"),
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	createCalls := vpnCtrl.vpnCallsFor("CreateTunnelInterface")
	if len(createCalls) != 2 {
		t.Fatalf("expected 2 CreateTunnelInterface calls, got %d", len(createCalls))
	}

	ids := mgr.TunnelIDs()
	if len(ids) != 2 {
		t.Errorf("TunnelIDs count = %d, want 2", len(ids))
	}
}

func TestSiteToSiteReconcileHandler_RemovesStaleTunnels(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with two tunnels.
	if err := mgr.AddTunnel(testTunnel("tun-1")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	if err := mgr.AddTunnel(testTunnel("tun-2")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	handler := SiteToSiteReconcileHandler(mgr, discardLogger())

	// Desired state: only tun-1 remains.
	desired := &api.StateResponse{
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{
				testTunnel("tun-1"),
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Verify RemoveTunnelInterface was called for tun-2.
	removeCalls := vpnCtrl.vpnCallsFor("RemoveTunnelInterface")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelInterface call, got %d", len(removeCalls))
	}

	ids := mgr.TunnelIDs()
	if len(ids) != 1 {
		t.Fatalf("TunnelIDs count = %d, want 1", len(ids))
	}
	if ids[0] != "tun-1" {
		t.Errorf("remaining tunnel = %v, want tun-1", ids[0])
	}
}

func TestSiteToSiteReconcileHandler_DetectsChangedTunnels(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with a tunnel.
	original := testTunnel("tun-1")
	if err := mgr.AddTunnel(original); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	handler := SiteToSiteReconcileHandler(mgr, discardLogger())

	// Desired state: same tunnel ID but different RemoteEndpoint.
	changed := testTunnel("tun-1")
	changed.RemoteEndpoint = "203.0.113.99:51820"
	desired := &api.StateResponse{
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{changed},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Should have removed the old tunnel and re-added.
	removeCalls := vpnCtrl.vpnCallsFor("RemoveTunnelInterface")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelInterface call for changed tunnel, got %d", len(removeCalls))
	}
	createCalls := vpnCtrl.vpnCallsFor("CreateTunnelInterface")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateTunnelInterface call for changed tunnel, got %d", len(createCalls))
	}

	// Verify the active tunnel has the new config.
	got, ok := mgr.GetTunnel("tun-1")
	if !ok {
		t.Fatal("tun-1 should still be active after change")
	}
	if got.RemoteEndpoint != "203.0.113.99:51820" {
		t.Errorf("RemoteEndpoint = %q, want %q", got.RemoteEndpoint, "203.0.113.99:51820")
	}
}

func TestSiteToSiteReconcileHandler_UnchangedTunnelsUntouched(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with a tunnel.
	tunnel := testTunnel("tun-1")
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	handler := SiteToSiteReconcileHandler(mgr, discardLogger())

	// Desired state: same tunnel, unchanged.
	desired := &api.StateResponse{
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{tunnel},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// No RemoveTunnelInterface or CreateTunnelInterface calls — tunnel is unchanged.
	if len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) != 0 {
		t.Error("RemoveTunnelInterface should not be called for unchanged tunnel")
	}
	if len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called for unchanged tunnel")
	}
}

func TestSiteToSiteReconcileHandler_Mixed(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	mgr := newTestSiteToSiteManager(t, vpnCtrl, routeCtrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with two tunnels.
	if err := mgr.AddTunnel(testTunnel("tun-keep")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	if err := mgr.AddTunnel(testTunnel("tun-stale")); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	handler := SiteToSiteReconcileHandler(mgr, discardLogger())

	// Desired: keep tun-keep, add tun-new, remove tun-stale.
	desired := &api.StateResponse{
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{
				testTunnel("tun-keep"),
				testTunnel("tun-new"),
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Verify tun-stale was removed.
	removeCalls := vpnCtrl.vpnCallsFor("RemoveTunnelInterface")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveTunnelInterface call, got %d", len(removeCalls))
	}

	// Verify tun-new was added.
	createCalls := vpnCtrl.vpnCallsFor("CreateTunnelInterface")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateTunnelInterface call, got %d", len(createCalls))
	}

	ids := mgr.TunnelIDs()
	if len(ids) != 2 {
		t.Fatalf("TunnelIDs count = %d, want 2", len(ids))
	}

	// Verify we have the expected tunnels.
	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[id] = struct{}{}
	}
	if _, ok := idSet["tun-keep"]; !ok {
		t.Error("tun-keep should still be active")
	}
	if _, ok := idSet["tun-new"]; !ok {
		t.Error("tun-new should be active")
	}
	if _, ok := idSet["tun-stale"]; ok {
		t.Error("tun-stale should have been removed")
	}
}
