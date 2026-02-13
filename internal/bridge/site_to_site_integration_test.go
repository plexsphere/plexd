package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration tests — Site-to-Site
// ---------------------------------------------------------------------------

// TestSiteToSiteIntegration_FullLifecycle wires a SiteToSiteManager with mock
// controllers and SSE handlers, verifies Setup → add tunnels via SSE handler →
// reconcile drift → remove tunnels via SSE handler → Teardown.
func TestSiteToSiteIntegration_FullLifecycle(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger())

	// Setup.
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if mgr.SiteToSiteStatus() == nil {
		t.Fatal("should be active after Setup")
	}

	// Wire up SSE handlers.
	assignHandler := HandleSiteToSiteTunnelAssigned(mgr, discardLogger())
	revokeHandler := HandleSiteToSiteTunnelRevoked(mgr, discardLogger())

	// --- Step 1: Add a tunnel via SSE handler and verify tracking ---
	tunnel1 := testTunnel("tun-lifecycle-1")
	envelope1 := tunnelAssignmentEnvelope(t, tunnel1)
	if err := assignHandler(context.Background(), envelope1); err != nil {
		t.Fatalf("assign handler: %v", err)
	}

	ids := mgr.TunnelIDs()
	if len(ids) != 1 || ids[0] != "tun-lifecycle-1" {
		t.Errorf("TunnelIDs = %v, want [tun-lifecycle-1]", ids)
	}
	status := mgr.SiteToSiteStatus()
	if status.TunnelCount != 1 {
		t.Errorf("TunnelCount = %d, want 1", status.TunnelCount)
	}

	// Verify tunnel config is retrievable.
	got, ok := mgr.GetTunnel("tun-lifecycle-1")
	if !ok {
		t.Fatal("GetTunnel should return true for existing tunnel")
	}
	if got.RemoteEndpoint != tunnel1.RemoteEndpoint {
		t.Errorf("RemoteEndpoint = %q, want %q", got.RemoteEndpoint, tunnel1.RemoteEndpoint)
	}

	// Verify VPNController calls.
	createCalls := vpnCtrl.vpnCallsFor("CreateTunnelInterface")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateTunnelInterface call, got %d", len(createCalls))
	}
	configureCalls := vpnCtrl.vpnCallsFor("ConfigureTunnelPeer")
	if len(configureCalls) != 1 {
		t.Fatalf("expected 1 ConfigureTunnelPeer call, got %d", len(configureCalls))
	}
	addRouteCalls := routeCtrl.callsFor("AddRoute")
	if len(addRouteCalls) != 1 {
		t.Fatalf("expected 1 AddRoute call, got %d", len(addRouteCalls))
	}

	// --- Step 2: Add a second tunnel via SSE handler ---
	tunnel2 := testTunnel("tun-lifecycle-2")
	envelope2 := tunnelAssignmentEnvelope(t, tunnel2)
	if err := assignHandler(context.Background(), envelope2); err != nil {
		t.Fatalf("assign handler second: %v", err)
	}
	if len(mgr.TunnelIDs()) != 2 {
		t.Errorf("TunnelIDs count = %d, want 2", len(mgr.TunnelIDs()))
	}

	// --- Step 3: Reconcile with desired state matching current — no changes ---
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	reconcileHandler := SiteToSiteReconcileHandler(mgr, discardLogger())
	desired := &api.StateResponse{
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{tunnel1, tunnel2},
		},
	}
	if err := reconcileHandler(context.Background(), desired, reconcile.StateDiff{}); err != nil {
		t.Fatalf("reconcile handler: %v", err)
	}
	// No changes expected — tunnels already match desired state.
	if len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called for unchanged tunnels")
	}
	if len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) != 0 {
		t.Error("RemoveTunnelInterface should not be called for unchanged tunnels")
	}

	// --- Step 4: Remove first tunnel via SSE handler ---
	revokeEnv := tunnelRevocationEnvelope(t, "tun-lifecycle-1")
	if err := revokeHandler(context.Background(), revokeEnv); err != nil {
		t.Fatalf("revoke handler: %v", err)
	}

	ids = mgr.TunnelIDs()
	if len(ids) != 1 {
		t.Errorf("TunnelIDs after remove = %v, want 1 item", ids)
	}
	status = mgr.SiteToSiteStatus()
	if status.TunnelCount != 1 {
		t.Errorf("TunnelCount after remove = %d, want 1", status.TunnelCount)
	}

	// --- Step 5: Teardown ---
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if mgr.SiteToSiteStatus() != nil {
		t.Error("should be inactive after Teardown")
	}

	// Second teardown is no-op.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

// TestSiteToSiteIntegration_ReconcileDrift wires a SiteToSiteManager with a real
// Reconciler and verifies that reconciliation correctly adds missing tunnels and
// removes stale tunnels.
func TestSiteToSiteIntegration_ReconcileDrift(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger())
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	// Initial state: one tunnel.
	state1 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{
				testTunnel("tun-1"),
			},
		},
		Metadata: map[string]string{"version": "1"},
	}
	fetcher := &integrationStateFetcher{state: state1}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(SiteToSiteReconcileHandler(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-s2s") }()

	// Wait for initial cycle: tun-1 should be added (1 CreateTunnelInterface call).
	waitForCondition(t, 2*time.Second, func() bool {
		return len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) >= 1
	})

	// Update: replace tun-1 with tun-2 and tun-3, bump metadata.
	state2 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{
				testTunnel("tun-2"),
				testTunnel("tun-3"),
			},
		},
		Metadata: map[string]string{"version": "2"},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: 1 RemoveTunnelInterface (tun-1 removed) + 2 more CreateTunnelInterface (tun-2, tun-3 added) = total 3.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) >= 3 &&
			len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) >= 1
	})

	// Update: empty tunnels — all removed.
	state3 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{},
		},
		Metadata: map[string]string{"version": "3"},
	}
	fetcher.setState(state3)
	rec.TriggerReconcile()

	// Wait for 2 more RemoveTunnelInterface calls (tun-2, tun-3 removed) = total 3.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) >= 3
	})

	cancel()
	<-done

	// Clean up.
	_ = mgr.Teardown()
}

// TestSiteToSiteIntegration_ConcurrentAccess exercises concurrent SSE events
// (config updates, tunnel assignments, and tunnel revocations) alongside the
// reconcile loop to verify no data races. Also verifies max tunnels enforcement
// under concurrent load. Run with -race.
func TestSiteToSiteIntegration_ConcurrentAccess(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	cfg := Config{
		Enabled:            true,
		SiteToSiteEnabled:  true,
		MaxSiteToSiteTunnels: 5, // Low limit to exercise max tunnels under concurrent load.
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger())
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var cycle atomic.Int32
	states := []*api.StateResponse{
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			SiteToSiteConfig: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					testTunnel("tun-conc-1"),
				},
			},
		},
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			SiteToSiteConfig: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					testTunnel("tun-conc-1"),
					testTunnel("tun-conc-2"),
				},
			},
		},
	}

	fetcher := &alternatingBridgeFetcher{
		states: states,
		cycle:  &cycle,
	}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: 30 * time.Millisecond}, discardLogger())
	rec.RegisterHandler(SiteToSiteReconcileHandler(mgr, discardLogger()))

	dispatcher := api.NewEventDispatcher(discardLogger())
	dispatcher.Register(api.EventSiteToSiteConfigUpdated, HandleSiteToSiteConfigUpdated(rec))
	dispatcher.Register(api.EventSiteToSiteTunnelAssigned, HandleSiteToSiteTunnelAssigned(mgr, discardLogger()))
	dispatcher.Register(api.EventSiteToSiteTunnelRevoked, HandleSiteToSiteTunnelRevoked(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-s2s") }()

	// Concurrently dispatch SSE events while the reconcile loop runs.
	var wg sync.WaitGroup

	// Config update dispatchers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			envelope := api.SignedEnvelope{
				EventType: api.EventSiteToSiteConfigUpdated,
				EventID:   "concurrent-config-evt",
			}
			dispatcher.Dispatch(ctx, envelope)
		}()
	}

	// Tunnel assignment dispatchers — use unique tunnel IDs per goroutine.
	// With MaxSiteToSiteTunnels=5, some of these will hit the limit and fail
	// (which is expected — errors are handled gracefully by the dispatcher).
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tunnel := testTunnel(fmt.Sprintf("tun-sse-%d", idx))
			payload, _ := json.Marshal(tunnel)
			envelope := api.SignedEnvelope{
				EventType: api.EventSiteToSiteTunnelAssigned,
				EventID:   fmt.Sprintf("assign-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}

	// Tunnel revocation dispatchers — revoke the same tunnel IDs we're adding above.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload, _ := json.Marshal(struct {
				TunnelID string `json:"tunnel_id"`
			}{TunnelID: fmt.Sprintf("tun-sse-%d", idx)})
			envelope := api.SignedEnvelope{
				EventType: api.EventSiteToSiteTunnelRevoked,
				EventID:   fmt.Sprintf("revoke-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}

	// Let the reconcile loop run several cycles.
	time.Sleep(300 * time.Millisecond)

	wg.Wait()
	cancel()
	<-done

	// Verify max tunnels enforcement: active count must never exceed the limit.
	tunnelCount := len(mgr.TunnelIDs())
	if tunnelCount > cfg.MaxSiteToSiteTunnels {
		t.Errorf("active tunnels = %d, exceeds max = %d", tunnelCount, cfg.MaxSiteToSiteTunnels)
	}

	// Clean up.
	_ = mgr.Teardown()

	// Test passes if no race detected. Verify some activity occurred.
	if n := fetcher.getFetchCount(); n < 2 {
		t.Errorf("FetchState calls = %d, want >= 2", n)
	}
}
