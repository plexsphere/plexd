package bridge

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration tests — UserAccess
// ---------------------------------------------------------------------------

// runUserAccessReconciler runs a real Reconciler that pulls state from
// fetcher, with the user access pull and reconcile handlers of mgr, until the
// test ends.
func runUserAccessReconciler(t *testing.T, fetcher *integrationStateFetcher, mgr *UserAccessManager) *reconcile.Reconciler {
	t.Helper()
	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterDispatchHandler(UserAccessPullHandler(mgr))
	rec.RegisterHandler(UserAccessReconcileHandler(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-access") }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return rec
}

// userAccessState returns a pull whose bridge block lists providers, with
// inventory as its secret inventory.
func userAccessState(inventory []api.NodeStateSecret, providers ...api.UserAccessProvider) *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{
		Bridge:  &api.BridgeSnapshot{UserAccess: &api.UserAccessConfig{Enabled: true, Providers: providers}},
		Secrets: &inventory,
	}
}

// TestUserAccessIntegration_ReconcileDrift wires a UserAccessManager with a
// real Reconciler and verifies that successive pulls bring a wireguard
// provider up, diff its devices, and tear it down with its key once the pull
// no longer lists it.
//
// We observe state through the mock controller rather than the manager to
// keep assertions independent of reconcile timing.
func TestUserAccessIntegration_ReconcileDrift(t *testing.T) {
	fx := newUAFixture(t, nil)
	fetcher := &integrationStateFetcher{state: userAccessState(nil, wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", alice))}
	rec := runUserAccessReconciler(t, fetcher, fx.mgr)

	// The first pull brings the provider up with alice.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(fx.access.accessCallsFor("ConfigurePeer")) >= 1
	})
	if got := len(fx.access.accessCallsFor("CreateInterface")); got != 1 {
		t.Fatalf("CreateInterface calls = %d, want 1", got)
	}

	// alice is replaced by bob and carol: one RemovePeer and two more
	// ConfigurePeer calls, on the same interface.
	fetcher.setState(userAccessState(nil, wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", bob, carol)))
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return len(fx.access.accessCallsFor("ConfigurePeer")) >= 3 &&
			len(fx.access.accessCallsFor("RemovePeer")) >= 1
	})
	if got := len(fx.access.accessCallsFor("CreateInterface")); got != 1 {
		t.Errorf("CreateInterface calls = %d after a device change, want still 1", got)
	}

	// A pull without the provider removes its interface and its key.
	fetcher.setState(&api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{}})
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return len(fx.access.accessCallsFor("RemoveInterface")) >= 1
	})
	waitForCondition(t, 2*time.Second, func() bool {
		return len(fx.keyFiles(t)) == 0
	})
	if c := fx.rewriter.callsFor("RemoveMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != uaIface1 {
		t.Errorf("RemoveMeshSourceRewrite calls = %+v, want %s", c, uaIface1)
	}
}

// TestUserAccessIntegration_RetriesOnEveryPull wires the manager with a real
// Reconciler and verifies that a provider down for a taken port and a vendor
// provider whose Secret the inventory did not list come up on later pulls
// whose bridge block did not change, once their next attempt is due.
func TestUserAccessIntegration_RetriesOnEveryPull(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.access.createInterfaceErrFor = map[string]error{uaIface1: ErrListenPortInUse}
	fx.secrets.set("ts-join", 1, "tskey")
	providers := []api.UserAccessProvider{fieldTeam, vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")}
	fetcher := &integrationStateFetcher{state: userAccessState(nil, providers...)}
	rec := runUserAccessReconciler(t, fetcher, fx.mgr)

	waitForCondition(t, 2*time.Second, func() bool {
		return len(providerIDs(fx.mgr)) == 2
	})
	requireDown(t, fx.mgr, uaID1, UserAccessReasonBindFailed)
	requireDown(t, fx.mgr, uaID2, UserAccessReasonAuthSecretNotListed)

	// The port is free and the inventory lists the Secret; the bridge block
	// is the same.
	fx.access.mu.Lock()
	fx.access.createInterfaceErrFor = nil
	fx.access.mu.Unlock()
	fetcher.setState(userAccessState(inventoryOf("ts-join", 1), providers...))
	fx.clock.Add(5 * time.Second)
	rec.TriggerReconcile()

	waitForCondition(t, 2*time.Second, func() bool {
		info := fx.mgr.UserAccessStatus()
		if info == nil || len(info.Providers) != 2 {
			return false
		}
		return info.Providers[0].Health == api.UserAccessHealthUp && info.Providers[1].Health == api.UserAccessHealthUp
	})
	if got := fx.secrets.fetches(); !slices.Equal(got, []certVersion{{"ts-join", 1}}) {
		t.Errorf("fetches = %v, want the listed version once", got)
	}
}
