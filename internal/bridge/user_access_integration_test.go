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

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())

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

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetAccess()

	// Initial state: one peer.
	state1 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		UserAccessConfig: &api.UserAccessConfig{
			Enabled:       true,
			InterfaceName: "wg-access",
			ListenPort:    51822,
			Peers: []api.UserAccessPeer{
				{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"},
			},
		},
		Metadata: map[string]string{"version": "1"},
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

	// Update: replace pk-1 with pk-2 and pk-3, bump metadata.
	state2 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		UserAccessConfig: &api.UserAccessConfig{
			Enabled:       true,
			InterfaceName: "wg-access",
			ListenPort:    51822,
			Peers: []api.UserAccessPeer{
				{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"},
				{PublicKey: "pk-3", AllowedIPs: []string{"10.99.0.3/32"}, Label: "charlie"},
			},
		},
		Metadata: map[string]string{"version": "2"},
	}
	fetcher.setState(state2)
	rec.TriggerReconcile()

	// Wait for: 1 RemovePeer (pk-1) + 2 more ConfigurePeer (pk-2, pk-3) = total 3 ConfigurePeer.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.accessCallsFor("ConfigurePeer")) >= 3 &&
			len(ctrl.accessCallsFor("RemovePeer")) >= 1
	})

	// Update: empty peers — all removed.
	state3 := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
		UserAccessConfig: &api.UserAccessConfig{
			Enabled:       true,
			InterfaceName: "wg-access",
			ListenPort:    51822,
			Peers:         []api.UserAccessPeer{},
		},
		Metadata: map[string]string{"version": "3"},
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

// TestUserAccessIntegration_ConcurrentAccess exercises concurrent SSE events
// (config updates, peer assignments, and peer revocations) alongside the
// reconcile loop to verify no data races. Run with -race.
func TestUserAccessIntegration_ConcurrentAccess(t *testing.T) {
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

	mgr := NewUserAccessManager(ctrl, routes, cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var cycle atomic.Int32
	states := []*api.StateResponse{
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			UserAccessConfig: &api.UserAccessConfig{
				Enabled:       true,
				InterfaceName: "wg-access",
				ListenPort:    51822,
				Peers: []api.UserAccessPeer{
					{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"},
				},
			},
		},
		{
			Peers: []api.Peer{{ID: "p1", PublicKey: "pk1", MeshIP: "10.42.0.2"}},
			UserAccessConfig: &api.UserAccessConfig{
				Enabled:       true,
				InterfaceName: "wg-access",
				ListenPort:    51822,
				Peers: []api.UserAccessPeer{
					{PublicKey: "pk-1", AllowedIPs: []string{"10.99.0.1/32"}, Label: "alice"},
					{PublicKey: "pk-2", AllowedIPs: []string{"10.99.0.2/32"}, Label: "bob"},
				},
			},
		},
	}

	fetcher := &alternatingBridgeFetcher{
		states: states,
		cycle:  &cycle,
	}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: 30 * time.Millisecond}, discardLogger())
	rec.RegisterHandler(UserAccessReconcileHandler(mgr, discardLogger()))

	dispatcher := api.NewEventDispatcher(discardLogger())
	dispatcher.Register(api.EventUserAccessConfigUpdated, HandleUserAccessConfigUpdated(rec))
	dispatcher.Register(api.EventUserAccessPeerAssigned, HandleUserAccessPeerAssigned(mgr, discardLogger()))
	dispatcher.Register(api.EventUserAccessPeerRevoked, HandleUserAccessPeerRevoked(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-access") }()

	// Concurrently dispatch SSE events while the reconcile loop runs.
	// Mix config updates, peer assignments, and peer revocations to
	// exercise concurrent AddPeer/RemovePeer against the reconcile loop.
	var wg sync.WaitGroup

	// Config update dispatchers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			envelope := api.SignedEnvelope{
				EventType: api.EventUserAccessConfigUpdated,
				EventID:   "concurrent-config-evt",
			}
			dispatcher.Dispatch(ctx, envelope)
		}()
	}

	// Peer assignment dispatchers — use unique keys per goroutine to avoid
	// deterministic "already exists" errors conflicting with the test.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peer := api.UserAccessPeer{
				PublicKey:  fmt.Sprintf("pk-sse-%d", idx),
				AllowedIPs: []string{fmt.Sprintf("10.99.1.%d/32", idx)},
				Label:      fmt.Sprintf("sse-peer-%d", idx),
			}
			payload, _ := json.Marshal(peer)
			envelope := api.SignedEnvelope{
				EventType: api.EventUserAccessPeerAssigned,
				EventID:   fmt.Sprintf("assign-evt-%d", idx),
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}(i)
	}

	// Peer revocation dispatchers — revoke the same keys we're adding above.
	// Some will be no-ops (peer not yet added), which is fine — the point is
	// concurrent access.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload, _ := json.Marshal(struct {
				PublicKey string `json:"public_key"`
			}{PublicKey: fmt.Sprintf("pk-sse-%d", idx)})
			envelope := api.SignedEnvelope{
				EventType: api.EventUserAccessPeerRevoked,
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

	// Test passes if no race detected. Verify some activity occurred.
	if n := fetcher.getFetchCount(); n < 2 {
		t.Errorf("FetchState calls = %d, want >= 2", n)
	}
}
