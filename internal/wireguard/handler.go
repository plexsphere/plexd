package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ReconcileHandler returns a reconcile.ReconcileHandler that applies peer
// changes from the StateDiff to the WireGuard interface via the Manager.
// Order: removes first, then updates, then adds.
// Individual failures are logged and collected; an aggregated error is returned.
func ReconcileHandler(mgr *Manager) reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.StateResponse, diff reconcile.StateDiff) error {
		var errs []error

		// 1. Remove peers
		for _, peerID := range diff.PeersToRemove {
			if err := mgr.RemovePeerByID(peerID); err != nil {
				mgr.logger.Error("reconcile: remove peer failed",
					"component", "wireguard",
					"peer_id", peerID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		// 2. Update peers
		for _, peer := range diff.PeersToUpdate {
			if err := mgr.UpdatePeer(peer); err != nil {
				mgr.logger.Error("reconcile: update peer failed",
					"component", "wireguard",
					"peer_id", peer.ID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		// 3. Add peers
		for _, peer := range diff.PeersToAdd {
			if err := mgr.AddPeer(peer); err != nil {
				mgr.logger.Error("reconcile: add peer failed",
					"component", "wireguard",
					"peer_id", peer.ID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
}

// HandlePeerAdded returns an EventHandler for peer_added events.
// It parses the Peer from the envelope payload and adds it via the Manager.
func HandlePeerAdded(mgr *Manager) api.EventHandler {
	return func(ctx context.Context, envelope api.SignedEnvelope) error {
		var peer api.Peer
		if err := json.Unmarshal(envelope.Payload, &peer); err != nil {
			mgr.logger.Error("peer_added: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("wireguard: peer_added: parse payload: %w", err)
		}
		if err := mgr.AddPeer(peer); err != nil {
			return fmt.Errorf("wireguard: peer_added: %w", err)
		}
		return nil
	}
}

// HandlePeerRemoved returns an EventHandler for peer_removed events.
// The payload is expected to be a JSON object with a "peer_id" field.
func HandlePeerRemoved(mgr *Manager) api.EventHandler {
	return func(ctx context.Context, envelope api.SignedEnvelope) error {
		var payload struct {
			PeerID string `json:"peer_id"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			mgr.logger.Error("peer_removed: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("wireguard: peer_removed: parse payload: %w", err)
		}
		if err := mgr.RemovePeerByID(payload.PeerID); err != nil {
			return fmt.Errorf("wireguard: peer_removed: %w", err)
		}
		return nil
	}
}

// HandlePeerKeyRotated returns an EventHandler for peer_key_rotated events.
// The payload is a Peer with the new public key. The old peer is removed
// (resolved via index) and the new one added.
func HandlePeerKeyRotated(mgr *Manager) api.EventHandler {
	return func(ctx context.Context, envelope api.SignedEnvelope) error {
		var peer api.Peer
		if err := json.Unmarshal(envelope.Payload, &peer); err != nil {
			mgr.logger.Error("peer_key_rotated: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("wireguard: peer_key_rotated: parse payload: %w", err)
		}
		// Remove old peer by ID (uses old public key from index)
		if err := mgr.RemovePeerByID(peer.ID); err != nil {
			mgr.logger.Warn("peer_key_rotated: remove old peer failed",
				"component", "wireguard",
				"peer_id", peer.ID,
				"error", err,
			)
			// Continue — still try to add the new key
		}
		// Add with new key
		if err := mgr.AddPeer(peer); err != nil {
			return fmt.Errorf("wireguard: peer_key_rotated: add new peer: %w", err)
		}
		return nil
	}
}

// HandlePeerEndpointChanged returns an EventHandler for peer_endpoint_changed events.
// The payload is a Peer with the updated endpoint.
func HandlePeerEndpointChanged(mgr *Manager) api.EventHandler {
	return func(ctx context.Context, envelope api.SignedEnvelope) error {
		var peer api.Peer
		if err := json.Unmarshal(envelope.Payload, &peer); err != nil {
			mgr.logger.Error("peer_endpoint_changed: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("wireguard: peer_endpoint_changed: parse payload: %w", err)
		}
		if err := mgr.UpdatePeer(peer); err != nil {
			return fmt.Errorf("wireguard: peer_endpoint_changed: %w", err)
		}
		return nil
	}
}
