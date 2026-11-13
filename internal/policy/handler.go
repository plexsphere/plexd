package policy

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ReconcileTrigger is satisfied by *reconcile.Reconciler.
type ReconcileTrigger interface {
	TriggerReconcile()
}

// DispatchHandler returns a reconcile.DispatchHandler that hands the policy
// block of every successful pull to enforcer.Sync, which applies it when it is
// not the installed ruleset and records the outcome for the policy status
// report and the node API.
//
// DECISION: the apply runs on the dispatch seam, on every pull, rather than
// as a reconcile handler behind the differ's PolicyChanged. A reconcile
// handler could not retry a rejected revision: the differ stores the pulled
// block once the cycle completes and never offers its fingerprint again, and
// returning the error instead would hold back every other block of the
// snapshot. On this seam a failed apply never holds anything back, and Sync
// compares the pull with what is installed itself, so a rejected block is
// applied again on the next pull and a pull with policy: null can be recorded
// as applied over the startup baseline. The differ still reports policy drift
// in the cycle log.
func DispatchHandler(enforcer *Enforcer, iface string) reconcile.DispatchHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot) {
		if desired == nil {
			return
		}
		enforcer.Sync(desired.Policy, iface)
	}
}

// HandlePolicyUpdated returns an api.EventHandler that triggers reconciliation
// when a policy_updated SSE event is received.
func HandlePolicyUpdated(trigger ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, _ api.Envelope) error {
		trigger.TriggerReconcile()
		return nil
	}
}
