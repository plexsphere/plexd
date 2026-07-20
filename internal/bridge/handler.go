package bridge

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
)

// ReconcileTrigger is satisfied by *reconcile.Reconciler.
type ReconcileTrigger interface {
	TriggerReconcile()
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
