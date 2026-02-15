package bridge

// Integration tests — Site-to-Site with TunnelProviders

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
// TestTunnelProviderIntegration_FullLifecycle
// ---------------------------------------------------------------------------

// TestTunnelProviderIntegration_FullLifecycle wires a SiteToSiteManager with a
// mock TunnelProvider ("ipsec") and verifies the full lifecycle: Setup, add
// WireGuard tunnel, add provider tunnel, status, remove both, teardown.
func TestTunnelProviderIntegration_FullLifecycle(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": ipsecProvider,
	}
	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), providers)

	// --- Setup ---
	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if mgr.SiteToSiteStatus() == nil {
		t.Fatal("should be active after Setup")
	}

	// --- Add a WireGuard tunnel (ProviderType="" goes through VPNController) ---
	wgTunnel := testTunnel("tun-wg-1")
	if err := mgr.AddTunnel(wgTunnel); err != nil {
		t.Fatalf("AddTunnel WireGuard: %v", err)
	}

	// Verify VPNController was called for WireGuard tunnel.
	if len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) != 1 {
		t.Errorf("expected 1 CreateTunnelInterface call for WG tunnel, got %d", len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")))
	}

	// --- Add a provider tunnel (ProviderType="ipsec" goes through provider) ---
	ipsecTunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-1",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "shared-secret",
		ProviderType:   "ipsec",
	}
	if err := mgr.AddTunnel(ipsecTunnel); err != nil {
		t.Fatalf("AddTunnel IPsec: %v", err)
	}

	// Verify provider.CreateTunnel was called.
	createCalls := ipsecProvider.callsFor("CreateTunnel")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 provider CreateTunnel call, got %d", len(createCalls))
	}

	// Verify VPNController was NOT called again (still 1 from WG tunnel).
	if len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) != 1 {
		t.Errorf("CreateTunnelInterface should not be called for provider tunnel")
	}

	// --- Status shows TunnelProviderNames and TunnelCount ---
	status := mgr.SiteToSiteStatus()
	if status == nil {
		t.Fatal("SiteToSiteStatus should not be nil when active")
	}
	if len(status.TunnelProviderNames) != 1 || status.TunnelProviderNames[0] != "ipsec" {
		t.Errorf("TunnelProviderNames = %v, want [ipsec]", status.TunnelProviderNames)
	}
	if status.TunnelCount != 2 {
		t.Errorf("TunnelCount = %d, want 2", status.TunnelCount)
	}

	// --- Remove the WireGuard tunnel (goes through VPNController) ---
	vpnCtrl.resetVPN()
	routeCtrl.reset()
	mgr.RemoveTunnel("tun-wg-1")

	if len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) != 1 {
		t.Errorf("expected 1 RemoveTunnelInterface call for WG removal, got %d", len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")))
	}

	// --- Remove the provider tunnel (goes through provider.RemoveTunnel) ---
	mgr.RemoveTunnel("t-ipsec-1")

	removeCalls := ipsecProvider.callsFor("RemoveTunnel")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 provider RemoveTunnel call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "t-ipsec-1" {
		t.Errorf("RemoveTunnel tunnelID = %v, want t-ipsec-1", removeCalls[0].Args[0])
	}

	// No additional VPNController calls for provider tunnel removal.
	if len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) != 1 {
		t.Errorf("RemoveTunnelInterface should not be called for provider tunnel removal")
	}

	// --- Teardown calls provider.Stop() ---
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	stopCalls := ipsecProvider.callsFor("Stop")
	if len(stopCalls) != 1 {
		t.Fatalf("expected 1 provider Stop call, got %d", len(stopCalls))
	}

	// Manager is inactive after teardown.
	if mgr.SiteToSiteStatus() != nil {
		t.Error("should be inactive after Teardown")
	}

	// Second teardown is no-op.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestTunnelProviderIntegration_MixedTunnels
// ---------------------------------------------------------------------------

// TestTunnelProviderIntegration_MixedTunnels wires with both "ipsec" and "openvpn"
// providers and verifies mixed WireGuard + provider tunnels work correctly.
func TestTunnelProviderIntegration_MixedTunnels(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	openvpnProvider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec":   ipsecProvider,
		"openvpn": openvpnProvider,
	}
	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add a WireGuard tunnel.
	wgTunnel := testTunnel("tun-wg-mix")
	if err := mgr.AddTunnel(wgTunnel); err != nil {
		t.Fatalf("AddTunnel WG: %v", err)
	}

	// Add an IPsec tunnel.
	ipsecTunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-mix",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "ipsec-secret",
		ProviderType:   "ipsec",
	}
	if err := mgr.AddTunnel(ipsecTunnel); err != nil {
		t.Fatalf("AddTunnel IPsec: %v", err)
	}

	// Add an OpenVPN tunnel.
	openvpnTunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ovpn-mix",
		RemoteEndpoint: "203.0.113.2:1194",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.2.0.0/24"},
		PSK:            "ovpn-secret",
		ProviderType:   "openvpn",
	}
	if err := mgr.AddTunnel(openvpnTunnel); err != nil {
		t.Fatalf("AddTunnel OpenVPN: %v", err)
	}

	// Status shows sorted TunnelProviderNames and TunnelCount=3.
	status := mgr.SiteToSiteStatus()
	if status == nil {
		t.Fatal("SiteToSiteStatus should not be nil")
	}
	if len(status.TunnelProviderNames) != 2 {
		t.Fatalf("TunnelProviderNames count = %d, want 2", len(status.TunnelProviderNames))
	}
	if status.TunnelProviderNames[0] != "ipsec" {
		t.Errorf("TunnelProviderNames[0] = %q, want %q", status.TunnelProviderNames[0], "ipsec")
	}
	if status.TunnelProviderNames[1] != "openvpn" {
		t.Errorf("TunnelProviderNames[1] = %q, want %q", status.TunnelProviderNames[1], "openvpn")
	}
	if status.TunnelCount != 3 {
		t.Errorf("TunnelCount = %d, want 3", status.TunnelCount)
	}

	// Teardown removes all tunnels and calls Stop() on both providers.
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify provider tunnels were removed via their respective providers.
	ipsecRemoves := ipsecProvider.callsFor("RemoveTunnel")
	if len(ipsecRemoves) != 1 {
		t.Errorf("expected 1 ipsec RemoveTunnel call, got %d", len(ipsecRemoves))
	}
	openvpnRemoves := openvpnProvider.callsFor("RemoveTunnel")
	if len(openvpnRemoves) != 1 {
		t.Errorf("expected 1 openvpn RemoveTunnel call, got %d", len(openvpnRemoves))
	}

	// Verify Stop was called on both providers.
	if len(ipsecProvider.callsFor("Stop")) != 1 {
		t.Errorf("expected 1 ipsec Stop call, got %d", len(ipsecProvider.callsFor("Stop")))
	}
	if len(openvpnProvider.callsFor("Stop")) != 1 {
		t.Errorf("expected 1 openvpn Stop call, got %d", len(openvpnProvider.callsFor("Stop")))
	}

	// Manager is inactive.
	if mgr.SiteToSiteStatus() != nil {
		t.Error("should be inactive after Teardown")
	}
}

// ---------------------------------------------------------------------------
// TestTunnelProviderIntegration_ProviderCreateError
// ---------------------------------------------------------------------------

// TestTunnelProviderIntegration_ProviderCreateError verifies that a provider
// create error prevents the tunnel from being tracked and makes no VPN or
// route controller calls.
func TestTunnelProviderIntegration_ProviderCreateError(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	ipsecProvider.createErr = fmt.Errorf("ipsec daemon unreachable")
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": ipsecProvider,
	}
	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	tunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-fail",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "shared-secret",
		ProviderType:   "ipsec",
	}

	err := mgr.AddTunnel(tunnel)
	if err == nil {
		t.Fatal("AddTunnel should return error when provider.CreateTunnel fails")
	}

	// No tunnel is tracked.
	if len(mgr.TunnelIDs()) != 0 {
		t.Errorf("no tunnel should be tracked after provider create error, got %v", mgr.TunnelIDs())
	}

	// No VPNController calls were made.
	if len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called when provider fails")
	}
	if len(vpnCtrl.vpnCallsFor("ConfigureTunnelPeer")) != 0 {
		t.Error("ConfigureTunnelPeer should not be called when provider fails")
	}

	// No RouteController calls were made.
	if len(routeCtrl.callsFor("EnableForwarding")) != 0 {
		t.Error("EnableForwarding should not be called when provider fails")
	}
	if len(routeCtrl.callsFor("AddRoute")) != 0 {
		t.Error("AddRoute should not be called when provider fails")
	}
}

// ---------------------------------------------------------------------------
// TestTunnelProviderIntegration_TeardownWithProviderError
// ---------------------------------------------------------------------------

// TestTunnelProviderIntegration_TeardownWithProviderError verifies that a
// provider Stop error is aggregated in the teardown error but the manager
// still becomes inactive.
func TestTunnelProviderIntegration_TeardownWithProviderError(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	ipsecProvider.stopErr = fmt.Errorf("ipsec stop failed")
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": ipsecProvider,
	}
	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add a provider tunnel.
	tunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-err",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "shared-secret",
		ProviderType:   "ipsec",
	}
	if err := mgr.AddTunnel(tunnel); err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	// Teardown returns aggregated error due to provider.Stop failure.
	err := mgr.Teardown()
	if err == nil {
		t.Fatal("Teardown should return aggregated error when provider.Stop fails")
	}

	// Despite error, manager is inactive.
	if mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus should be nil after teardown even with errors")
	}

	// provider.RemoveTunnel was called for the active tunnel.
	removeCalls := ipsecProvider.callsFor("RemoveTunnel")
	if len(removeCalls) != 1 {
		t.Fatalf("expected 1 provider RemoveTunnel call, got %d", len(removeCalls))
	}
	if removeCalls[0].Args[0] != "t-ipsec-err" {
		t.Errorf("RemoveTunnel tunnelID = %v, want t-ipsec-err", removeCalls[0].Args[0])
	}
}

// ---------------------------------------------------------------------------
// TestTunnelProviderIntegration_ReconcileWithProviders
// ---------------------------------------------------------------------------

// TestTunnelProviderIntegration_ReconcileWithProviders wires a real Reconciler
// with a provider and verifies that reconciliation correctly delegates to
// VPNController for WireGuard tunnels and to the provider for provider tunnels.
func TestTunnelProviderIntegration_ReconcileWithProviders(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": ipsecProvider,
	}
	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vpnCtrl.resetVPN()
	routeCtrl.reset()

	// Initial state: 1 WireGuard tunnel + 1 IPsec tunnel.
	wgTunnel := testTunnel("tun-wg-rec")
	ipsecTunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-rec",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "shared-secret",
		ProviderType:   "ipsec",
	}

	state1 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{wgTunnel, ipsecTunnel},
		},
		Metadata: map[string]string{"version": "1"},
	}
	fetcher := &integrationStateFetcher{state: state1}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(SiteToSiteReconcileHandler(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-tp") }()

	// Wait for initial cycle: WG tunnel via VPNController, IPsec tunnel via provider.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) >= 1 &&
			len(ipsecProvider.callsFor("CreateTunnel")) >= 1
	})

	// Verify both tunnels are tracked.
	ids := mgr.TunnelIDs()
	if len(ids) != 2 {
		t.Errorf("TunnelIDs count = %d, want 2", len(ids))
	}

	// Update state: remove WG tunnel, add a new IPsec tunnel.
	ipsecTunnel2 := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-rec-2",
		RemoteEndpoint: "203.0.113.2:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.2.0.0/24"},
		PSK:            "shared-secret-2",
		ProviderType:   "ipsec",
	}
	state2 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{ipsecTunnel, ipsecTunnel2},
		},
		Metadata: map[string]string{"version": "2"},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: WG tunnel removed via VPNController, new IPsec tunnel added via provider.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) >= 1 &&
			len(ipsecProvider.callsFor("CreateTunnel")) >= 2
	})

	// Verify provider-managed tunnels stayed through reconciliation.
	_, ok := mgr.GetTunnel("t-ipsec-rec")
	if !ok {
		t.Error("t-ipsec-rec should still be present after reconcile")
	}
	_, ok = mgr.GetTunnel("t-ipsec-rec-2")
	if !ok {
		t.Error("t-ipsec-rec-2 should be present after reconcile")
	}
	_, ok = mgr.GetTunnel("tun-wg-rec")
	if ok {
		t.Error("tun-wg-rec should have been removed after reconcile")
	}

	cancel()
	<-done

	_ = mgr.Teardown()
}

// ---------------------------------------------------------------------------
// TestTunnelProviderIntegration_ConcurrentAccessWithProviders
// ---------------------------------------------------------------------------

// TestTunnelProviderIntegration_ConcurrentAccessWithProviders exercises
// concurrent SSE events with both WireGuard and provider tunnel types alongside
// the reconcile loop to verify no data races. Run with -race.
func TestTunnelProviderIntegration_ConcurrentAccessWithProviders(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	cfg := Config{
		Enabled:              true,
		SiteToSiteEnabled:    true,
		MaxSiteToSiteTunnels: 8,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": ipsecProvider,
	}
	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Build alternating states with a mix of WireGuard and provider tunnels.
	var cycle atomic.Int32
	ipsecTunnelA := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-conc-a",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "secret-a",
		ProviderType:   "ipsec",
	}
	ipsecTunnelB := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-conc-b",
		RemoteEndpoint: "203.0.113.2:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.2.0.0/24"},
		PSK:            "secret-b",
		ProviderType:   "ipsec",
	}

	states := []*api.StateResponse{
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			SiteToSiteConfig: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					testTunnel("tun-conc-wg-1"),
					ipsecTunnelA,
				},
			},
		},
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			SiteToSiteConfig: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					testTunnel("tun-conc-wg-1"),
					testTunnel("tun-conc-wg-2"),
					ipsecTunnelB,
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
	go func() { done <- rec.Run(ctx, "node-tp-conc") }()

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

	// Tunnel assignment dispatchers — mix of WireGuard and provider tunnels.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tunnel := testTunnel(fmt.Sprintf("tun-sse-wg-%d", idx))
			payload, _ := json.Marshal(tunnel)
			envelope := api.SignedEnvelope{
				EventType: api.EventSiteToSiteTunnelAssigned,
				EventID:   fmt.Sprintf("assign-wg-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tunnel := api.SiteToSiteTunnel{
				TunnelID:       fmt.Sprintf("t-ipsec-sse-%d", idx),
				RemoteEndpoint: fmt.Sprintf("203.0.113.%d:500", idx+10),
				LocalSubnets:   []string{"10.0.0.0/24"},
				RemoteSubnets:  []string{fmt.Sprintf("10.%d.0.0/24", idx+10)},
				PSK:            fmt.Sprintf("secret-%d", idx),
				ProviderType:   "ipsec",
			}
			payload, _ := json.Marshal(tunnel)
			envelope := api.SignedEnvelope{
				EventType: api.EventSiteToSiteTunnelAssigned,
				EventID:   fmt.Sprintf("assign-ipsec-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}

	// Tunnel revocation dispatchers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload, _ := json.Marshal(struct {
				TunnelID string `json:"tunnel_id"`
			}{TunnelID: fmt.Sprintf("tun-sse-wg-%d", idx)})
			envelope := api.SignedEnvelope{
				EventType: api.EventSiteToSiteTunnelRevoked,
				EventID:   fmt.Sprintf("revoke-wg-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload, _ := json.Marshal(struct {
				TunnelID string `json:"tunnel_id"`
			}{TunnelID: fmt.Sprintf("t-ipsec-sse-%d", idx)})
			envelope := api.SignedEnvelope{
				EventType: api.EventSiteToSiteTunnelRevoked,
				EventID:   fmt.Sprintf("revoke-ipsec-evt-%d", idx),
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

	// Verify max tunnels enforcement.
	tunnelCount := len(mgr.TunnelIDs())
	if tunnelCount > cfg.MaxSiteToSiteTunnels {
		t.Errorf("active tunnels = %d, exceeds max = %d", tunnelCount, cfg.MaxSiteToSiteTunnels)
	}

	_ = mgr.Teardown()

	// Test passes if no race detected. Verify some activity occurred.
	if n := fetcher.getFetchCount(); n < 2 {
		t.Errorf("FetchState calls = %d, want >= 2", n)
	}
}

// ---------------------------------------------------------------------------
// TestTunnelProviderIntegration_ReconcileChangedProviderTunnel
// ---------------------------------------------------------------------------

// TestTunnelProviderIntegration_ReconcileChangedProviderTunnel verifies that
// reconciliation detects changed tunnel config for provider-managed tunnels
// and removes the old + adds the new via provider calls.
func TestTunnelProviderIntegration_ReconcileChangedProviderTunnel(t *testing.T) {
	vpnCtrl := &mockVPNController{}
	routeCtrl := &mockRouteController{}
	ipsecProvider := newMockTunnelProvider()
	cfg := Config{
		Enabled:           true,
		SiteToSiteEnabled: true,
	}
	cfg.ApplyDefaults()

	providers := map[string]TunnelProvider{
		"ipsec": ipsecProvider,
	}
	mgr := NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg, discardLogger(), providers)

	if err := mgr.Setup("wg0"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Initial state: 1 IPsec tunnel with specific RemoteEndpoint.
	ipsecTunnel := api.SiteToSiteTunnel{
		TunnelID:       "t-ipsec-change",
		RemoteEndpoint: "203.0.113.1:500",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		PSK:            "shared-secret",
		ProviderType:   "ipsec",
	}

	state1 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{ipsecTunnel},
		},
		Metadata: map[string]string{"version": "1"},
	}
	fetcher := &integrationStateFetcher{state: state1}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(SiteToSiteReconcileHandler(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-tp-change") }()

	// Wait for initial reconcile to add the tunnel.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ipsecProvider.callsFor("CreateTunnel")) >= 1
	})

	// Verify tunnel is present.
	got, ok := mgr.GetTunnel("t-ipsec-change")
	if !ok {
		t.Fatal("t-ipsec-change should be present after initial reconcile")
	}
	if got.RemoteEndpoint != "203.0.113.1:500" {
		t.Errorf("RemoteEndpoint = %q, want %q", got.RemoteEndpoint, "203.0.113.1:500")
	}

	// Update state: same TunnelID but different RemoteEndpoint.
	changedTunnel := ipsecTunnel
	changedTunnel.RemoteEndpoint = "203.0.113.99:500"
	state2 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		SiteToSiteConfig: &api.SiteToSiteConfig{
			Enabled: true,
			Tunnels: []api.SiteToSiteTunnel{changedTunnel},
		},
		Metadata: map[string]string{"version": "2"},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for reconcile: remove old + add new via provider calls.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ipsecProvider.callsFor("RemoveTunnel")) >= 1 &&
			len(ipsecProvider.callsFor("CreateTunnel")) >= 2
	})

	// Verify the active tunnel has the new config.
	got, ok = mgr.GetTunnel("t-ipsec-change")
	if !ok {
		t.Fatal("t-ipsec-change should still be present after change reconcile")
	}
	if got.RemoteEndpoint != "203.0.113.99:500" {
		t.Errorf("RemoteEndpoint = %q, want %q", got.RemoteEndpoint, "203.0.113.99:500")
	}

	// Verify NO VPNController calls were made for provider-managed tunnel changes.
	if len(vpnCtrl.vpnCallsFor("CreateTunnelInterface")) != 0 {
		t.Error("CreateTunnelInterface should not be called for provider tunnel changes")
	}
	if len(vpnCtrl.vpnCallsFor("RemoveTunnelInterface")) != 0 {
		t.Error("RemoveTunnelInterface should not be called for provider tunnel changes")
	}

	cancel()
	<-done

	_ = mgr.Teardown()
}
