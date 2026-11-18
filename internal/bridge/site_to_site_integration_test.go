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
// Integration tests — SiteToSite
// ---------------------------------------------------------------------------

// runSiteToSiteReconciler runs a real Reconciler that pulls state from
// fetcher, with the site-to-site pull and reconcile handlers of mgr, until
// the test ends.
func runSiteToSiteReconciler(t *testing.T, fetcher *integrationStateFetcher, mgr *SiteToSiteManager) *reconcile.Reconciler {
	t.Helper()
	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterDispatchHandler(SiteToSitePullHandler(mgr))
	rec.RegisterHandler(SiteToSiteReconcileHandler(mgr, discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-bridge") }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return rec
}

// siteToSiteState returns a pull whose bridge block lists tunnels, with
// inventory as its secret inventory.
func siteToSiteState(inventory []api.NodeStateSecret, tunnels ...api.SiteToSiteTunnel) *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{
		Bridge:  &api.BridgeSnapshot{SiteToSite: &api.SiteToSiteConfig{Enabled: true, Tunnels: tunnels}},
		Secrets: &inventory,
	}
}

// tunnelHealth returns the health of the tunnel with id, "" while the
// manager reports none. Like tunnelIDs it reads what the manager holds, so
// polling it runs no provider command among those a test checks.
func tunnelHealth(mgr *SiteToSiteManager, id string) string {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if !mgr.active {
		return ""
	}
	for _, t := range mgr.tunnels {
		switch {
		case !t.settled || t.entry.ID != id:
		case t.up:
			return api.SiteToSiteHealthUp
		default:
			return api.SiteToSiteHealthDown
		}
	}
	return ""
}

// TestSiteToSiteIntegration_ReconcileDrift wires a SiteToSiteManager with a
// real Reconciler and verifies that successive pulls bring a wireguard
// tunnel up, rebuild it with its key when its subnets change, and tear it
// down with its key once the pull no longer lists it.
//
// We observe state through the mock controllers rather than the manager to
// keep assertions independent of reconcile timing.
func TestSiteToSiteIntegration_ReconcileDrift(t *testing.T) {
	fx := buildS2SFixture(t, nil)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	fetcher := &integrationStateFetcher{state: siteToSiteState(s2sInventory(), branchBerlin)}
	rec := runSiteToSiteReconciler(t, fetcher, fx.mgr)

	// The first pull brings the tunnel up.
	waitForCondition(t, 2*time.Second, func() bool {
		return tunnelHealth(fx.mgr, s2sID1) == api.SiteToSiteHealthUp
	})
	key := fx.storedKey(t, s2sID1)

	// Reordered subnets rebuild the tunnel with the same key.
	reordered := branchBerlin
	reordered.AllowedSubnets = []string{"10.21.0.0/16", "10.20.0.0/16"}
	fetcher.setState(siteToSiteState(s2sInventory(), reordered))
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return len(fx.vpn.vpnCallsFor("CreateTunnelInterface")) >= 2 && tunnelHealth(fx.mgr, s2sID1) == api.SiteToSiteHealthUp
	})
	for _, c := range fx.vpn.vpnCallsFor("CreateTunnelInterface") {
		if !slices.Equal(c.Args[1].([]byte), key) {
			t.Error("the rebuilt interface has another key")
		}
	}

	// A pull without the tunnel removes its link, its routes and its key.
	fetcher.setState(&api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{}})
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return len(fx.vpn.vpnCallsFor("RemoveTunnelInterface")) >= 2 && len(fx.keyFiles(t)) == 0
	})
	if got := routeCalls(fx.routes, "RemoveRoute"); len(got) != 4 {
		t.Errorf("RemoveRoute calls = %q, want two per teardown", got)
	}
	if got := tunnelIDs(fx.mgr); len(got) != 0 {
		t.Errorf("tunnels = %q, want none", got)
	}
}

// TestSiteToSiteIntegration_RetriesOnEveryPull wires the manager with a real
// Reconciler and verifies that a tunnel down for a taken port and one whose
// Secret the inventory did not list come up on a later pull whose bridge
// block did not change, once their next attempt is due.
func TestSiteToSiteIntegration_RetriesOnEveryPull(t *testing.T) {
	fx := buildS2SFixture(t, nil)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	fx.vpn.set(func(m *mockVPNController) {
		m.createErrFor = map[string]error{s2sWGIface: ErrListenPortInUse}
	})
	fetcher := &integrationStateFetcher{state: siteToSiteState(inventoryOf("branch-berlin-psk", 1), branchBerlin, dcEast)}
	rec := runSiteToSiteReconciler(t, fetcher, fx.mgr)

	waitForCondition(t, 2*time.Second, func() bool {
		return len(tunnelIDs(fx.mgr)) == 2
	})
	requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonBindFailed)
	requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretNotListed)

	// The port is free and the inventory lists the Secret; the bridge block
	// is the same.
	fx.vpn.set(func(m *mockVPNController) { m.createErrFor = nil })
	fetcher.setState(siteToSiteState(s2sInventory(), branchBerlin, dcEast))
	fx.clock.Add(5 * time.Second)
	rec.TriggerReconcile()

	waitForCondition(t, 2*time.Second, func() bool {
		return tunnelHealth(fx.mgr, s2sID1) == api.SiteToSiteHealthUp && tunnelHealth(fx.mgr, s2sID2) == api.SiteToSiteHealthUp
	})
	if got := fx.ipsec.createCalls(); len(got) != 1 {
		t.Errorf("ipsec CreateTunnel calls = %d, want 1", len(got))
	}
}
