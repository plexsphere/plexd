package bridge

import (
	"context"
	"errors"
	"log/slog"
	"reflect"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// RelayReconcileHandler returns a reconcile.ReconcileHandler that reconciles
// relay sessions to match the desired bridge relay subtree. Sessions not in the
// desired state are removed; missing sessions are added. The handler is
// presence-aware: a nil Bridge or nil Relay child means "not populated", so it
// reconciles against an empty desired set and tears down stale sessions.
func RelayReconcileHandler(relay *Relay, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot, _ reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var sessions []api.RelaySessionAssignment
		if desired.Bridge != nil && desired.Bridge.Relay != nil {
			sessions = desired.Bridge.Relay.Sessions
		}

		// Build desired set keyed by SessionID.
		desiredSet := make(map[string]api.RelaySessionAssignment, len(sessions))
		for _, s := range sessions {
			desiredSet[s.SessionID] = s
		}

		// Remove stale sessions.
		currentIDs := relay.SessionIDs()
		for _, id := range currentIDs {
			if _, ok := desiredSet[id]; !ok {
				relay.RemoveSession(id)
			}
		}

		// Add missing sessions.
		currentSet := make(map[string]bool, len(currentIDs))
		for _, id := range currentIDs {
			currentSet[id] = true
		}

		var errs []error
		for id, assignment := range desiredSet {
			if currentSet[id] {
				continue
			}
			if err := relay.AddSession(assignment); err != nil {
				logger.Error("relay reconcile: add session failed",
					"session_id", id,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
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

// UserAccessReconcileHandler returns a reconcile.ReconcileHandler that updates
// user access peers when the desired bridge user-access subtree changes. It
// diffs the desired peers against the currently active peers, adding missing
// and removing stale peers. The handler is presence-aware: a nil Bridge or nil
// UserAccess child means "not populated", so it reconciles against an empty
// desired set and tears down stale peers.
func UserAccessReconcileHandler(mgr *UserAccessManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot, _ reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var peers []api.UserAccessPeer
		if desired.Bridge != nil && desired.Bridge.UserAccess != nil {
			peers = desired.Bridge.UserAccess.Peers
		}

		// Build desired and current sets for diffing.
		desiredSet := make(map[string]api.UserAccessPeer, len(peers))
		for _, p := range peers {
			desiredSet[p.PublicKey] = p
		}

		currentKeys := mgr.PeerPublicKeys()
		currentSet := make(map[string]struct{}, len(currentKeys))
		for _, pk := range currentKeys {
			currentSet[pk] = struct{}{}
		}

		// Remove stale peers (present locally but not in desired state).
		for _, pk := range currentKeys {
			if _, ok := desiredSet[pk]; !ok {
				mgr.RemovePeer(pk)
			}
		}

		// Add missing peers (present in desired state but not locally).
		var errs []error
		for _, peer := range peers {
			if _, ok := currentSet[peer.PublicKey]; ok {
				continue
			}
			if err := mgr.AddPeer(peer); err != nil {
				logger.Error("user access reconcile: add peer failed",
					"public_key", peer.PublicKey,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
}

// SiteToSiteReconcileHandler returns a reconcile.ReconcileHandler that updates
// site-to-site tunnels when the desired bridge site-to-site subtree changes. It
// diffs the desired tunnels against the currently active tunnels: adding missing
// tunnels, removing stale tunnels, and restarting changed tunnels (same ID,
// different config). The handler is presence-aware: a nil Bridge or nil
// SiteToSite child means "not populated", so it reconciles against an empty
// desired set and tears down stale tunnels.
func SiteToSiteReconcileHandler(mgr *SiteToSiteManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot, _ reconcile.StateDiff) error {
		if desired == nil {
			return nil
		}

		var tunnels []api.SiteToSiteTunnel
		if desired.Bridge != nil && desired.Bridge.SiteToSite != nil {
			tunnels = desired.Bridge.SiteToSite.Tunnels
		}

		// Build desired set for diffing.
		desiredSet := make(map[string]api.SiteToSiteTunnel, len(tunnels))
		for _, t := range tunnels {
			desiredSet[t.TunnelID] = t
		}

		currentIDs := mgr.TunnelIDs()
		currentSet := make(map[string]struct{}, len(currentIDs))
		for _, id := range currentIDs {
			currentSet[id] = struct{}{}
		}

		// Remove stale tunnels (present locally but not in desired state)
		// and detect changed tunnels (same ID, different config).
		for _, id := range currentIDs {
			desiredTunnel, inDesired := desiredSet[id]
			if !inDesired {
				// Stale tunnel — remove.
				mgr.RemoveTunnel(id)
				continue
			}
			// Check if the tunnel config changed (requires restart).
			currentTunnel, ok := mgr.GetTunnel(id)
			if ok && !reflect.DeepEqual(currentTunnel, desiredTunnel) {
				mgr.RemoveTunnel(id)
				delete(currentSet, id) // mark for re-add below
			}
		}

		// Add missing and changed tunnels.
		var errs []error
		for _, tunnel := range tunnels {
			if _, ok := currentSet[tunnel.TunnelID]; ok {
				continue
			}
			if err := mgr.AddTunnel(tunnel); err != nil {
				logger.Error("site-to-site reconcile: add tunnel failed",
					"tunnel_id", tunnel.TunnelID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
}
