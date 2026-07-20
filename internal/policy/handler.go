package policy

import (
	"context"
	"errors"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ReconcileTrigger is satisfied by *reconcile.Reconciler.
type ReconcileTrigger interface {
	TriggerReconcile()
}

// ReconcileHandler returns a reconcile.ReconcileHandler that applies the merged
// policy's firewall ruleset when the policy fingerprint changes. It returns nil
// unless diff.PolicyChanged.
//
// The fingerprint short-circuit lives in the differ (PolicyChanged stays false
// on a fingerprint match), so this handler — and its "policy ruleset applied"
// log — never fires for revision-only bumps. That log is emitted only once the
// enforcer confirms the ruleset reached the kernel, so it cannot claim an
// enforcement that a disabled config or a missing firewall backend skipped.
//
// A transient apply failure propagates so the reconciler holds the snapshot back
// and retries next cycle. ErrInvalidRuleset does not: the rejected rules are a
// permanent property of the revision, so propagating it would hold the snapshot
// back and re-run every handler at the reconcile interval forever with no
// chance of the same rules parsing. Such a revision is logged and swallowed so
// the rest of the snapshot converges; the firewall keeps the last successfully
// applied ruleset, which is fail-closed.
func ReconcileHandler(enforcer *Enforcer, iface string) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		if !diff.PolicyChanged {
			return nil
		}

		revisionID, fingerprint, ruleCount := "", "", 0
		if desired.Policy != nil {
			revisionID = desired.Policy.RevisionID
			fingerprint = desired.Policy.Fingerprint
			ruleCount = len(desired.Policy.Rules)
			if fingerprint == "" {
				// The differ treats a missing fingerprint as always-changed, so
				// the chain is flushed and rebuilt every cycle. Name that
				// explicitly — otherwise the churn is indistinguishable from
				// real revisions.
				enforcer.logger.Warn("policy snapshot carries no fingerprint, ruleset rebuilds every cycle",
					"revision_id", revisionID,
				)
			}
		}

		applied, err := enforcer.ApplyFirewallRules(desired.Policy, iface)
		if err != nil {
			if errors.Is(err, ErrInvalidRuleset) {
				enforcer.logger.Error("policy revision rejected, keeping previous ruleset",
					"revision_id", revisionID,
					"fingerprint", fingerprint,
					"error", err,
				)
				return nil
			}
			enforcer.logger.Error("reconcile: apply firewall rules failed", "error", err)
			return err
		}
		if !applied {
			enforcer.logger.Debug("policy enforcement inactive, ruleset not applied",
				"revision_id", revisionID,
				"fingerprint", fingerprint,
			)
			return nil
		}

		enforcer.logger.Info("policy ruleset applied",
			"revision_id", revisionID,
			"fingerprint", fingerprint,
			"rules", ruleCount,
		)
		return nil
	}
}

// HandlePolicyUpdated returns an api.EventHandler that triggers reconciliation
// when a policy_updated SSE event is received.
func HandlePolicyUpdated(trigger ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, _ api.SignedEnvelope) error {
		trigger.TriggerReconcile()
		return nil
	}
}
