package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// HandleIngressRuleAssigned returns an api.EventHandler that adds an ingress
// rule when an ingress_rule_assigned SSE event is received.
func HandleIngressRuleAssigned(mgr *IngressManager, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var rule api.IngressRule
		if err := json.Unmarshal(envelope.Payload, &rule); err != nil {
			logger.Error("ingress_rule_assigned: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: ingress_rule_assigned: parse payload: %w", err)
		}

		if err := mgr.AddRule(rule); err != nil {
			return fmt.Errorf("bridge: ingress_rule_assigned: %w", err)
		}
		return nil
	}
}

// HandleIngressRuleRevoked returns an api.EventHandler that removes an ingress
// rule when an ingress_rule_revoked SSE event is received.
func HandleIngressRuleRevoked(mgr *IngressManager, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var payload struct {
			RuleID string `json:"rule_id"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			logger.Error("ingress_rule_revoked: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: ingress_rule_revoked: parse payload: %w", err)
		}

		mgr.RemoveRule(payload.RuleID)
		return nil
	}
}

// HandleIngressConfigUpdated returns an api.EventHandler that triggers
// reconciliation when an ingress_config_updated SSE event is received.
// Follows the HandleBridgeConfigUpdated pattern: payload is ignored, reconcile
// cycle will fetch the full desired state.
func HandleIngressConfigUpdated(trigger ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, _ api.SignedEnvelope) error {
		trigger.TriggerReconcile()
		return nil
	}
}

// IngressReconcileHandler returns a reconcile.ReconcileHandler that updates
// ingress rules when the desired bridge ingress subtree changes. It diffs the
// desired rules against the currently active rules: adding missing rules,
// removing stale rules, and restarting changed rules (same ID, different
// config). The handler is presence-aware: a nil Bridge or nil Ingress child
// means "not populated", so it reconciles against an empty desired set and
// tears down stale rules.
func IngressReconcileHandler(mgr *IngressManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot, _ reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var rules []api.IngressRule
		if desired.Bridge != nil && desired.Bridge.Ingress != nil {
			rules = desired.Bridge.Ingress.Rules
		}

		// Build desired set for diffing.
		desiredSet := make(map[string]api.IngressRule, len(rules))
		for _, r := range rules {
			desiredSet[r.RuleID] = r
		}

		currentIDs := mgr.RuleIDs()
		currentSet := make(map[string]struct{}, len(currentIDs))
		for _, id := range currentIDs {
			currentSet[id] = struct{}{}
		}

		// Remove stale rules (present locally but not in desired state)
		// and detect changed rules (same ID, different config).
		for _, id := range currentIDs {
			desiredRule, inDesired := desiredSet[id]
			if !inDesired {
				// Stale rule — remove.
				mgr.RemoveRule(id)
				continue
			}
			// Check if the rule config changed (requires restart).
			currentRule, ok := mgr.GetRule(id)
			if ok && currentRule != desiredRule {
				mgr.RemoveRule(id)
				delete(currentSet, id) // mark for re-add below
			}
		}

		// Add missing and changed rules.
		var errs []error
		for _, rule := range rules {
			if _, ok := currentSet[rule.RuleID]; ok {
				continue
			}
			if err := mgr.AddRule(rule); err != nil {
				logger.Error("ingress reconcile: add rule failed",
					"rule_id", rule.RuleID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
}
