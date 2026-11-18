package bridge

import (
	"context"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// RelayReconcileHandler returns a reconcile.ReconcileHandler that runs the
// relay the desired bridge.relay block asks for and records on status the
// state each snapshot leaves the relay in, for the RelayStatusReporter to send.
// relay is nil when local consent, bridge.relay_enabled, is off. status must
// not be nil.
//
// A nil Bridge or Relay child, or Enabled false, stops a running relay and
// records stopped, also when relay is nil or not running, so a relay whose
// last bind failed reads stopped once the pull disables it. With Enabled true
// the relay is configured on ListenPort with the snapshot's peers, so a bind
// failure fails the reconcile cycle and the next pull retries it. The status
// then comes from Relay.Bound: running on the bound port while the relay runs,
// bind_failed on ListenPort when Configure failed on a valid port, and stopped
// otherwise. With Enabled true and no relay, the handler only warns and records
// not_consented. A nil snapshot records nothing.
func RelayReconcileHandler(relay *Relay, status *RelayStatusTracker, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot, _ reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var block *api.RelayConfig
		if desired.Bridge != nil {
			block = desired.Bridge.Relay
		}
		if block == nil || !block.Enabled {
			if relay != nil && relay.Running() {
				if err := relay.Stop(); err != nil {
					return err
				}
				logger.Info("relay disabled by the control plane", "component", "bridge")
			}
			status.Set(RelayStatus{State: api.RelayStateStopped})
			return nil
		}
		if relay == nil {
			logger.Warn("relay: the control plane enables the relay, but bridge.relay_enabled is false",
				"component", "bridge",
				"listen_port", block.ListenPort,
			)
			status.Set(RelayStatus{State: api.RelayStateNotConsented})
			return nil
		}

		err := relay.Configure(block.ListenPort, desired.Peers)
		// Configure stops a relay on another port before it binds, so a bind
		// failure leaves the relay stopped and it reads bind_failed on the
		// pulled port. An out-of-range port fails before anything changes: a
		// relay running on its old port keeps reading running there, and one
		// that was not running reads stopped, because the contract refuses
		// bind_failed without a valid port.
		port, boundAt, running := relay.Bound()
		switch {
		case running:
			status.Set(RelayStatus{State: api.RelayStateRunning, ListenPort: port, BoundAt: boundAt})
		case err != nil && block.ListenPort >= 1 && block.ListenPort <= 65535:
			status.Set(RelayStatus{State: api.RelayStateBindFailed, ListenPort: block.ListenPort})
		default:
			status.Set(RelayStatus{State: api.RelayStateStopped})
		}
		return err
	}
}

// IngressSecretInventoryHandler returns a reconcile.DispatchHandler that hands
// the secret inventory of every successful pull to the ingress manager, which
// loads, replaces or drops the certificates of its terminate rules. A pull
// whose only change is the secrets block reports no drift, so no reconcile
// handler would see a rotation. A nil Secrets block, a control plane that did
// not say this time, keeps the inventory the manager holds. Dispatch handlers
// run before the reconcile handlers, so a cycle that brings a new rule and its
// Secret hands the inventory over first.
func IngressSecretInventoryHandler(mgr *IngressManager) reconcile.DispatchHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot) {
		if desired == nil || desired.Secrets == nil {
			return
		}
		mgr.SyncSecretInventory(ctx, *desired.Secrets)
	}
}

// IngressReconcileHandler returns a reconcile.ReconcileHandler that serves the
// desired bridge.ingress block whole, its acme member included, when the block
// enables public ingress. mgr is nil when the node opts out of public ingress,
// bridge.ingress_enabled: false. A nil snapshot changes nothing.
//
// With a manager, a block with Enabled true is applied. A nil Bridge or nil
// Ingress child applies the zero block, which closes every listener, and so
// does a block with Enabled false, which is also what a block without the
// member decodes to. A block with Enabled false that carries rules is logged
// as a Warn naming how many before the zero block is applied. A failed bind
// fails the reconcile cycle, so the reconciler keeps its snapshot and the next
// pull tries the bind again.
//
// Without a manager the handler touches nothing and returns nil. A block with
// Enabled true and at least one rule is logged as a Warn naming how many rules
// the local opt-out leaves unserved.
//
// Both Warn lines are logged only when diff.BridgeChanged is set: the
// reconciler invokes every handler on any drift, peers and policy included,
// and an ungated Warn would repeat on each such cycle. Each is logged once per
// change of the pulled bridge block, which includes the first pull after every
// start, since the reconciler's snapshot starts empty. A cycle that fails
// keeps the old snapshot, so the next pull logs it again. Applying the zero
// block is not gated.
func IngressReconcileHandler(mgr *IngressManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var pulled *api.IngressConfig
		if desired.Bridge != nil {
			pulled = desired.Bridge.Ingress
		}
		var rules int
		if pulled != nil {
			rules = len(pulled.Rules)
		}

		if mgr == nil {
			if pulled != nil && pulled.Enabled && rules > 0 && diff.BridgeChanged {
				logger.Warn("ingress: the control plane enables public ingress, but bridge.ingress_enabled is false",
					"component", "bridge",
					"rules", rules,
				)
			}
			return nil
		}

		// The zero block closes every listener.
		var block api.IngressConfig
		switch {
		case pulled != nil && pulled.Enabled:
			block = *pulled
		case rules > 0 && diff.BridgeChanged:
			logger.Warn("ingress: the state pull carries rules but does not enable public ingress, closing every listener",
				"component", "bridge",
				"rules", rules,
			)
		}

		if err := mgr.Apply(ctx, block); err != nil {
			logger.Error("ingress reconcile: apply failed",
				"component", "bridge",
				"error", err,
			)
			return err
		}
		return nil
	}
}

// UserAccessPullHandler returns a reconcile.DispatchHandler that runs on every
// successful pull. It hands the pull's secret inventory to the user access
// manager, which brings up again each provider that is down for a reason a
// retry can cure and whose next attempt is due. A pull whose only change is
// the secrets block reports no drift, so no reconcile handler would see a
// Secret the inventory newly lists, and a provider whose port was taken needs
// a retry whatever drifted. A nil Secrets block, a control plane that did not
// say this time, keeps the inventory the manager holds and only retries.
// Dispatch handlers run before the reconcile handlers, so a cycle that brings
// a new provider and its Secret hands the inventory over first. A nil
// snapshot changes nothing.
func UserAccessPullHandler(mgr *UserAccessManager) reconcile.DispatchHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot) {
		if desired == nil {
			return
		}
		if desired.Secrets == nil {
			mgr.Retry(ctx)
			return
		}
		mgr.SyncSecretInventory(ctx, *desired.Secrets)
	}
}

// UserAccessReconcileHandler returns a reconcile.ReconcileHandler that serves
// the desired bridge.user_access block whole. mgr is nil when the node opts
// out of user access, bridge.user_access_enabled: false. A nil snapshot
// changes nothing, and the handler returns nil in every case: a provider that
// is down is retried by UserAccessPullHandler, so one broken provider never
// makes the reconciler apply the whole snapshot again.
//
// With a manager, the pulled block is applied as it is, and a nil Bridge or
// nil UserAccess child applies the zero block, which tears every provider
// down and deletes every key file. The manager serves providers only when the
// block's Enabled is true.
//
// Without a manager the handler touches nothing. A block with Enabled true
// and at least one provider is logged as a Warn naming how many providers the
// local opt-out leaves unserved, only when diff.BridgeChanged is set: the
// reconciler invokes every handler on any drift, and an ungated Warn would
// repeat on each peer or policy change. It is logged once per change of the
// pulled bridge block, which includes the first pull after every start.
func UserAccessReconcileHandler(mgr *UserAccessManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var pulled *api.UserAccessConfig
		if desired.Bridge != nil {
			pulled = desired.Bridge.UserAccess
		}

		if mgr == nil {
			if pulled != nil && pulled.Enabled && len(pulled.Providers) > 0 && diff.BridgeChanged {
				logger.Warn("user access: the control plane enables user access, but bridge.user_access_enabled is false",
					"component", "bridge",
					"providers", len(pulled.Providers),
				)
			}
			return nil
		}

		// The zero block tears every provider down.
		var block api.UserAccessConfig
		if pulled != nil {
			block = *pulled
		}
		mgr.Apply(ctx, block)
		return nil
	}
}

// SiteToSitePullHandler returns a reconcile.DispatchHandler that runs on every
// successful pull. It hands the pull's secret inventory to the site-to-site
// manager, which rebuilds each tunnel whose Secret the inventory lists at a
// new version and brings up again each tunnel that is down for a reason a
// retry can cure and whose next attempt is due. A pull whose only change is
// the secrets block reports no drift, so no reconcile handler would see a
// rotated Secret, and a tunnel whose port was taken or whose remote host did
// not resolve needs a retry whatever drifted. A nil Secrets block, a control
// plane that did not say this time, keeps the inventory the manager holds and
// only retries. Dispatch handlers run before the reconcile handlers, so a
// cycle that brings a new tunnel and its Secret hands the inventory over
// first. A nil snapshot changes nothing.
func SiteToSitePullHandler(mgr *SiteToSiteManager) reconcile.DispatchHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot) {
		if desired == nil {
			return
		}
		if desired.Secrets == nil {
			mgr.Retry(ctx)
			return
		}
		mgr.SyncSecretInventory(ctx, *desired.Secrets)
	}
}

// SiteToSiteReconcileHandler returns a reconcile.ReconcileHandler that serves
// the desired bridge.site_to_site block whole. mgr is nil when the node opts
// out of site-to-site tunnels, bridge.site_to_site_enabled: false. A nil
// snapshot changes nothing, and the handler returns nil in every case: a
// tunnel that is down is retried by SiteToSitePullHandler, so one broken
// tunnel never makes the reconciler apply the whole snapshot again.
//
// With a manager, the pulled block is applied as it is, and a nil Bridge or
// nil SiteToSite child applies the zero block, which tears every tunnel down
// and deletes every key file. The manager serves tunnels only when the
// block's Enabled is true.
//
// Without a manager the handler touches nothing. A block with Enabled true
// and at least one tunnel is logged as a Warn naming how many tunnels the
// local opt-out leaves unserved, only when diff.BridgeChanged is set: the
// reconciler invokes every handler on any drift, and an ungated Warn would
// repeat on each peer or policy change. It is logged once per change of the
// pulled bridge block, which includes the first pull after every start.
func SiteToSiteReconcileHandler(mgr *SiteToSiteManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var pulled *api.SiteToSiteConfig
		if desired.Bridge != nil {
			pulled = desired.Bridge.SiteToSite
		}

		if mgr == nil {
			if pulled != nil && pulled.Enabled && len(pulled.Tunnels) > 0 && diff.BridgeChanged {
				logger.Warn("site-to-site: the control plane enables site-to-site tunnels, but bridge.site_to_site_enabled is false",
					"component", "bridge",
					"tunnels", len(pulled.Tunnels),
				)
			}
			return nil
		}

		// The zero block tears every tunnel down.
		var block api.SiteToSiteConfig
		if pulled != nil {
			block = *pulled
		}
		mgr.Apply(ctx, block)
		return nil
	}
}
