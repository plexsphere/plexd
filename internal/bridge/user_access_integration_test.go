package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration tests — UserAccess
// ---------------------------------------------------------------------------

// TestUserAccessIntegration_FullLifecycle wires a UserAccessManager with mock
// controllers, performs Setup → AddPeer → RemovePeer → Teardown, and verifies
// the complete lifecycle. (Single-goroutine — no race concerns.)
func TestUserAccessIntegration_FullLifecycle(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger(), nil)

	// Setup.
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if mgr.UserAccessStatus() == nil {
		t.Fatal("should be active after Setup")
	}

	// Verify setup calls.
	if n := len(ctrl.accessCallsFor("CreateInterface")); n != 1 {
		t.Errorf("CreateInterface calls = %d, want 1", n)
	}
	if n := len(routes.callsFor("EnableForwarding")); n != 1 {
		t.Errorf("EnableForwarding calls = %d, want 1", n)
	}

	// Add peers.
	peer1 := api.UserAccessPeer{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, PSK: "psk-1", Label: "alice"}
	peer2 := api.UserAccessPeer{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"}
	if err := mgr.AddPeer(peer1); err != nil {
		t.Fatalf("AddPeer 1: %v", err)
	}
	if err := mgr.AddPeer(peer2); err != nil {
		t.Fatalf("AddPeer 2: %v", err)
	}

	status := mgr.UserAccessStatus()
	if status.PeerCount != 2 {
		t.Errorf("PeerCount = %d, want 2", status.PeerCount)
	}

	// Remove one peer.
	mgr.RemovePeer("pk-1")
	status = mgr.UserAccessStatus()
	if status.PeerCount != 1 {
		t.Errorf("PeerCount after remove = %d, want 1", status.PeerCount)
	}

	// Teardown.
	ctrl.resetAccess()
	routes.reset()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Verify teardown calls.
	if n := len(ctrl.accessCallsFor("RemovePeer")); n != 1 {
		t.Errorf("RemovePeer calls in teardown = %d, want 1 (remaining peer)", n)
	}
	if n := len(routes.callsFor("DisableForwarding")); n != 1 {
		t.Errorf("DisableForwarding calls = %d, want 1", n)
	}
	if n := len(ctrl.accessCallsFor("RemoveInterface")); n != 1 {
		t.Errorf("RemoveInterface calls = %d, want 1", n)
	}

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

// TestUserAccessIntegration_ReconcileDrift wires a UserAccessManager with a
// real Reconciler and verifies that reconciliation correctly adds missing
// peers and removes stale peers.
//
// We observe state through the mock controller (accessCallsFor) rather than
// the UserAccessManager to keep assertions independent of reconcile timing.
func TestUserAccessIntegration_ReconcileDrift(t *testing.T) {
	ctrl := &mockAccessController{}
	routes := &mockRouteController{}
	cfg := Config{
		Enabled:                 true,
		AccessInterface:         "eth1",
		AccessSubnets:           []string{"10.0.0.0/24"},
		UserAccessEnabled:       true,
		UserAccessInterfaceName: "wg-access",
		UserAccessListenPort:    51822,
	}
	cfg.ApplyDefaults()

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger(), nil)
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetAccess()

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
	go func() { done <- rec.Run(ctx, "node-access") }()

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

	// Update: empty peers — all removed.
	state3 := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{
				Enabled:       true,
				InterfaceName: "wg-access",
				ListenPort:    51822,
				Peers:         []api.UserAccessPeer{},
			},
		},
	}
	fetcher.setState(state3)
	rec.TriggerReconcile()

	// Wait for 2 more RemovePeer calls (pk-2, pk-3) = total 3 RemovePeer.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.accessCallsFor("RemovePeer")) >= 3
	})

	cancel()
	<-done
}
