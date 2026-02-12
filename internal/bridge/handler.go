package bridge

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ReconcileTrigger is satisfied by *reconcile.Reconciler.
type ReconcileTrigger interface {
	TriggerReconcile()
}

// ReconcileHandler returns a reconcile.ReconcileHandler that updates bridge
// routes when the desired BridgeConfig changes. If BridgeConfig is nil in the
// desired state, the handler is a no-op.
func ReconcileHandler(mgr *Manager) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.StateResponse, _ reconcile.StateDiff) error {
		if desired == nil || desired.BridgeConfig == nil {
			return nil
		}
		return mgr.UpdateRoutes(desired.BridgeConfig.AccessSubnets)
	}
}

// HandleBridgeConfigUpdated returns an api.EventHandler that triggers
// reconciliation when a bridge_config_updated SSE event is received.
// Follows the HandlePolicyUpdated pattern: payload is ignored, reconcile
// cycle will fetch the full desired state.
func HandleBridgeConfigUpdated(trigger ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, _ api.SignedEnvelope) error {
		trigger.TriggerReconcile()
		return nil
	}
}
