package policy

import (
	"context"
	"errors"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// ReconcileTrigger is satisfied by *reconcile.Reconciler.
type ReconcileTrigger interface {
	TriggerReconcile()
}

// ReconcileHandler returns a reconcile.ReconcileHandler that enforces network
// policies. When policy or peer drift is detected it:
//  1. Filters peers through the enforcer's policy engine.
//  2. Applies firewall rules via the enforcer.
//  3. Removes peers that are no longer allowed from WireGuard.
//  4. Adds newly allowed peers to WireGuard.
func ReconcileHandler(enforcer *Enforcer, wgMgr *wireguard.Manager, localNodeID, localMeshIP, iface string) reconcile.ReconcileHandler {
	allowedPeers := make(map[string]struct{})

	return func(ctx context.Context, desired *api.StateResponse, diff reconcile.StateDiff) error {
		if !hasPolicyOrPeerChanges(diff) {
			return nil
		}

		// Filter peers through policy engine.
		filtered := enforcer.FilterPeers(desired.Peers, desired.Policies, localNodeID)

		// Build peersByID map for firewall rule IP resolution.
		peersByID := make(map[string]string, len(desired.Peers)+1)
		peersByID[localNodeID] = localMeshIP
		for _, p := range desired.Peers {
			peersByID[p.ID] = p.MeshIP
		}

		var errs []error

		// Apply firewall rules.
		if err := enforcer.ApplyFirewallRules(desired.Policies, localNodeID, iface, peersByID); err != nil {
			enforcer.logger.Error("reconcile: apply firewall rules failed",
				"error", err,
			)
			errs = append(errs, err)
		}

		// Compute new allowed set.
		newAllowed := make(map[string]struct{}, len(filtered))
		filteredByID := make(map[string]api.Peer, len(filtered))
		for _, p := range filtered {
			newAllowed[p.ID] = struct{}{}
			filteredByID[p.ID] = p
		}

		// Remove peers that were allowed but are no longer.
		for peerID := range allowedPeers {
			if _, ok := newAllowed[peerID]; !ok {
				if err := wgMgr.RemovePeerByID(peerID); err != nil {
					enforcer.logger.Error("reconcile: remove disallowed peer failed",
						"peer_id", peerID,
						"error", err,
					)
					errs = append(errs, err)
				}
			}
		}

		// Add newly allowed peers.
		for peerID, peer := range filteredByID {
			if _, ok := allowedPeers[peerID]; !ok {
				if err := wgMgr.AddPeer(peer); err != nil {
					enforcer.logger.Error("reconcile: add allowed peer failed",
						"peer_id", peerID,
						"error", err,
					)
					errs = append(errs, err)
				}
			}
		}

		// Update tracked set.
		allowedPeers = newAllowed

		return errors.Join(errs...)
	}
}

// hasPolicyOrPeerChanges returns true if the diff contains any policy or peer changes.
func hasPolicyOrPeerChanges(diff reconcile.StateDiff) bool {
	return len(diff.PoliciesToAdd) > 0 ||
		len(diff.PoliciesToRemove) > 0 ||
		len(diff.PeersToAdd) > 0 ||
		len(diff.PeersToRemove) > 0 ||
		len(diff.PeersToUpdate) > 0
}

// HandlePolicyUpdated returns an api.EventHandler that triggers reconciliation
// when a policy_updated SSE event is received.
func HandlePolicyUpdated(trigger ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, _ api.SignedEnvelope) error {
		trigger.TriggerReconcile()
		return nil
	}
}
