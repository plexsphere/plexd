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

// HandleUserAccessPeerAssigned returns an api.EventHandler that adds a user
// access peer when a user_access_peer_assigned SSE event is received.
func HandleUserAccessPeerAssigned(mgr *UserAccessManager, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var peer api.UserAccessPeer
		if err := json.Unmarshal(envelope.Payload, &peer); err != nil {
			logger.Error("user_access_peer_assigned: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: user_access_peer_assigned: parse payload: %w", err)
		}

		if err := mgr.AddPeer(peer); err != nil {
			return fmt.Errorf("bridge: user_access_peer_assigned: %w", err)
		}
		return nil
	}
}

// HandleUserAccessPeerRevoked returns an api.EventHandler that removes a user
// access peer when a user_access_peer_revoked SSE event is received.
func HandleUserAccessPeerRevoked(mgr *UserAccessManager, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var payload struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			logger.Error("user_access_peer_revoked: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: user_access_peer_revoked: parse payload: %w", err)
		}

		mgr.RemovePeer(payload.PublicKey)
		return nil
	}
}

// HandleUserAccessConfigUpdated returns an api.EventHandler that triggers
// reconciliation when a user_access_config_updated SSE event is received.
// Follows the HandleBridgeConfigUpdated pattern: payload is ignored, reconcile
// cycle will fetch the full desired state.
func HandleUserAccessConfigUpdated(trigger ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, _ api.SignedEnvelope) error {
		trigger.TriggerReconcile()
		return nil
	}
}

// UserAccessReconcileHandler returns a reconcile.ReconcileHandler that updates
// user access peers when the desired UserAccessConfig changes. It diffs the
// desired peers against the currently active peers, adding missing and removing
// stale peers.
func UserAccessReconcileHandler(mgr *UserAccessManager, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.StateResponse, _ reconcile.StateDiff) error {
		if desired == nil || desired.UserAccessConfig == nil {
			return nil
		}

		// Build desired and current sets for diffing.
		desiredSet := make(map[string]api.UserAccessPeer, len(desired.UserAccessConfig.Peers))
		for _, p := range desired.UserAccessConfig.Peers {
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
		for _, peer := range desired.UserAccessConfig.Peers {
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
