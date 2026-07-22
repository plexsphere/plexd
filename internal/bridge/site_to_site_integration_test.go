package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// testTunnel builds a site-to-site tunnel fixture with the given ID.
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
// Integration tests — Site-to-Site
// ---------------------------------------------------------------------------

// TestSiteToSiteIntegration_FullLifecycle wires a SiteToSiteManager with mock
// controllers, verifies Setup → add tunnels via the manager → reconcile drift →
// remove a tunnel via the manager → Teardown.
func TestSiteToSiteIntegration_FullLifecycle(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), nil)

	// Setup.
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if mgr.SiteToSiteStatus() == nil {
		t.Fatal("should be active after Setup")
	}

	// --- Step 1: Add a tunnel via the manager and verify tracking ---
	tunnel1 := testTunnel("tun-lifecycle-1")
	if err := mgr.AddTunnel(tunnel1); err != nil {
		t.Fatalf("add tunnel: %v", err)
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

	// --- Step 2: Add a second tunnel via the manager ---
	tunnel2 := testTunnel("tun-lifecycle-2")
	if err := mgr.AddTunnel(tunnel2); err != nil {
		t.Fatalf("add second tunnel: %v", err)
	}
	if len(mgr.TunnelIDs()) != 2 {
		t.Errorf("TunnelIDs count = %d, want 2", len(mgr.TunnelIDs()))
	}

	// --- Step 3: Reconcile with desired state matching current — no changes ---
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	reconcileHandler := SiteToSiteReconcileHandler(mgr, discardLogger())
	desired := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			SiteToSite: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{tunnel1, tunnel2},
			},
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

	// --- Step 4: Remove the first tunnel via the manager ---
	mgr.RemoveTunnel("tun-lifecycle-1")

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

	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), nil)
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	// Initial state: one tunnel.
	state1 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			SiteToSite: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					testTunnel("tun-1"),
				},
			},
		},
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

	// Update: replace tun-1 with tun-2 and tun-3.
	state2 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			SiteToSite: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					testTunnel("tun-2"),
					testTunnel("tun-3"),
				},
			},
		},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: 1 RemoveTunnelInterface (tun-1 removed) + 2 more CreateTunnelInterface (tun-2, tun-3 added) = total 3.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) >= 3 &&
			len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) >= 1
	})

	// Update: empty tunnels — all removed.
	state3 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			SiteToSite: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{},
			},
		},
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
