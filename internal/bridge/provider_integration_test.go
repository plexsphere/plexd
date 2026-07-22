// Integration tests — UserAccess with VPN Provider
package bridge

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// providerTestConfig returns a standard Config for provider integration tests.
func providerTestConfig() Config {
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()
	return cfg
}

// providerCallCount returns the number of times the given method was called on the provider.
func providerCallCount(p *mockUserAccessProvider, method string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		if c == method {
			n++
		}
	}
	return n
}

// TestProviderIntegration_FullLifecycle wires a UserAccessManager with a mock
// provider and exercises Setup → AddPeer → Teardown, verifying provider
// Start/Stop calls and status reporting throughout the lifecycle.
func TestProviderIntegration_FullLifecycle(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	provider := newMockUserAccessProvider("tailscale")
	cfg := providerTestConfig()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger(), provider)

	// Setup.
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Verify provider.Start was called.
	if !provider.hasCalled("Start") {
		t.Error("provider.Start should have been called during Setup")
	}

	// Status should include provider info.
	status := mgr.UserAccessStatus()
	if status == nil {
		t.Fatal("should be active after Setup")
	}
	if status.ProviderName != "tailscale" {
		t.Errorf("ProviderName = %q, want %q", status.ProviderName, "tailscale")
	}
	if status.ProviderStatus != "running" {
		t.Errorf("ProviderStatus = %q, want %q", status.ProviderStatus, "running")
	}

	// Add peers works alongside provider.
	peer1 := api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, PSK: "psk-1", Label: "alice"}
	peer2 := api.UserAccessPeer{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"}
	if err := mgr.AddPeer(peer1); err != nil {
		t.Fatalf("AddPeer 1: %v", err)
	}
	if err := mgr.AddPeer(peer2); err != nil {
		t.Fatalf("AddPeer 2: %v", err)
	}

	status = mgr.UserAccessStatus()
	if status.PeerCount != 2 {
		t.Errorf("PeerCount = %d, want 2", status.PeerCount)
	}

	// Teardown.
	ctrl.resetAccess()
	routes.reset()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify provider.Stop was called.
	if !provider.hasCalled("Stop") {
		t.Error("provider.Stop should have been called during Teardown")
	}

	// Verify WG cleanup.
	if n := len(ctrl.accessCallsFor("RemovePeer")); n != 2 {
		t.Errorf("RemovePeer calls in teardown = %d, want 2 (remaining peers)", n)
	}
	if n := len(routes.callsFor("DisableForwarding")); n != 1 {
		t.Errorf("DisableForwarding calls = %d, want 1", n)
	}
	if n := len(ctrl.accessCallsFor("RemoveInterface")); n != 1 {
		t.Errorf("RemoveInterface calls = %d, want 1", n)
	}

	// After teardown, status is nil.
	if mgr.UserAccessStatus() != nil {
		t.Error("should be inactive after Teardown")
	}

	// Second teardown is no-op.
	ctrl.resetAccess()
	routes.reset()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
	if n := len(ctrl.accessCallsFor("RemoveInterface")); n != 0 {
		t.Errorf("RemoveInterface calls on second teardown = %d, want 0", n)
	}
}

// TestProviderIntegration_SetupProviderError verifies that when the provider's
// Start fails, Setup rolls back the WG interface and forwarding, leaving the
// manager inactive.
func TestProviderIntegration_SetupProviderError(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	provider := newMockUserAccessProvider("tailscale")
	provider.startErr = fmt.Errorf("auth key expired")
	cfg := providerTestConfig()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger(), provider)

	err := mgr.Setup()
	if err == nil {
		t.Fatal("Setup should return error when provider.Start fails")
	}

	// Provider rollback: WG interface and forwarding should be rolled back.
	removeCalls := ctrl.accessCallsFor("RemoveInterface")
	if len(removeCalls) != 1 {
		t.Errorf("expected 1 RemoveInterface rollback call, got %d", len(removeCalls))
	}
	fwdCalls := routes.callsFor("DisableForwarding")
	if len(fwdCalls) != 1 {
		t.Errorf("expected 1 DisableForwarding rollback call, got %d", len(fwdCalls))
	}

	// Manager should be inactive.
	if mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus should be nil after failed setup")
	}
}

// TestProviderIntegration_TeardownProviderStopError verifies that when the
// provider's Stop fails, Teardown returns an aggregated error but still
// completes all WG cleanup (peers removed, forwarding disabled, interface removed).
func TestProviderIntegration_TeardownProviderStopError(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	provider := newMockUserAccessProvider("netbird")
	provider.stopErr = fmt.Errorf("daemon not responding")
	cfg := providerTestConfig()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger(), provider)

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Add a peer.
	peer := api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"}
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	ctrl.resetAccess()
	routes.reset()

	// Teardown returns aggregated error.
	err := mgr.Teardown()
	if err == nil {
		t.Fatal("Teardown should return aggregated error when provider.Stop fails")
	}

	// Despite error, manager should be inactive.
	if mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus should be nil after teardown even with errors")
	}

	// WG cleanup still happens.
	if n := len(ctrl.accessCallsFor("RemovePeer")); n != 1 {
		t.Errorf("RemovePeer calls = %d, want 1 (remaining peer)", n)
	}
	if n := len(routes.callsFor("DisableForwarding")); n != 1 {
		t.Errorf("DisableForwarding calls = %d, want 1", n)
	}
	if n := len(ctrl.accessCallsFor("RemoveInterface")); n != 1 {
		t.Errorf("RemoveInterface calls = %d, want 1", n)
	}
}

// TestProviderIntegration_StatusReporting verifies that UserAccessStatus
// correctly maps provider status to the ProviderStatus string field for all
// three states: running, error, and stopped.
func TestProviderIntegration_StatusReporting(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	provider := newMockUserAccessProvider("tailscale")
	cfg := providerTestConfig()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger(), provider)

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// Running state.
	status := mgr.UserAccessStatus()
	if status == nil {
		t.Fatal("UserAccessStatus should not be nil when active")
	}
	if status.ProviderStatus != "running" {
		t.Errorf("ProviderStatus = %q, want %q", status.ProviderStatus, "running")
	}

	// Error state: set provider status to have Error.
	provider.mu.Lock()
	provider.status = ProviderStatus{Running: false, Error: "connection lost"}
	provider.mu.Unlock()

	status = mgr.UserAccessStatus()
	if status.ProviderStatus != "error" {
		t.Errorf("ProviderStatus = %q, want %q", status.ProviderStatus, "error")
	}

	// Stopped state: Running=false, no Error.
	provider.mu.Lock()
	provider.status = ProviderStatus{Running: false}
	provider.mu.Unlock()

	status = mgr.UserAccessStatus()
	if status.ProviderStatus != "stopped" {
		t.Errorf("ProviderStatus = %q, want %q", status.ProviderStatus, "stopped")
	}
}

// TestProviderIntegration_ReconcileWithProvider wires a UserAccessManager with
// a real Reconciler and a mock provider, and verifies that reconciliation
// correctly adds/removes peers while the provider stays running.
func TestProviderIntegration_ReconcileWithProvider(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	provider := newMockUserAccessProvider("tailscale")
	cfg := providerTestConfig()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger(), provider)
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetAccess()

	// Verify provider started.
	if !provider.hasCalled("Start") {
		t.Fatal("provider.Start should have been called during Setup")
	}
	startCountBefore := providerCallCount(provider, "Start")

	// Initial state: one peer.
	state1 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{
				Enabled:       true,
				InterfaceName: "wg-access",
				ListenPort:    51822,
				Peers: []api.UserAccessPeer{
					{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"},
				},
			},
		},
	}
	fetcher := &integrationStateFetcher{state: state1}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(UserAccessReconcileHandler(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-provider") }()

	// Wait for initial cycle: pk-1 should be added (1 ConfigurePeer call).
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.accessCallsFor("ConfigurePeer")) >= 1
	})

	// Update: replace pk-1 with pk-2 and pk-3.
	state2 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{
				Enabled:       true,
				InterfaceName: "wg-access",
				ListenPort:    51822,
				Peers: []api.UserAccessPeer{
					{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"},
					{PublicKey: "pk-3", AllowedIPs: []string{"10.99.0.3/32"}, Label: "charlie"},
				},
			},
		},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: 1 RemovePeer (pk-1) + 2 more ConfigurePeer (pk-2, pk-3) = total 3 ConfigurePeer.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.accessCallsFor("ConfigurePeer")) >= 3 &&
			len(ctrl.accessCallsFor("RemovePeer")) >= 1
	})

	// Provider stays running through reconciliation.
	status := mgr.UserAccessStatus()
	if status == nil {
		t.Fatal("UserAccessStatus should not be nil during reconcile")
	}
	if status.ProviderStatus != "running" {
		t.Errorf("ProviderStatus = %q, want %q during reconcile", status.ProviderStatus, "running")
	}

	// Verify no extra provider.Start/Stop calls during reconcile.
	startCountAfter := providerCallCount(provider, "Start")
	stopCount := providerCallCount(provider, "Stop")
	if startCountAfter != startCountBefore {
		t.Errorf("extra provider.Start calls during reconcile: before=%d after=%d", startCountBefore, startCountAfter)
	}
	if stopCount != 0 {
		t.Errorf("provider.Stop calls during reconcile = %d, want 0", stopCount)
	}

	cancel()
	<-done
}
