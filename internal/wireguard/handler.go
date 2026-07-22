package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ReconcileHandler returns a reconcile.ReconcileHandler that applies peer
// changes from the StateDiff to the WireGuard interface via the Manager.
// PeersToRemove are node IDs resolved through the peer index; adds and updates
// are converted from the snapshot shape via peerFromSnapshot.
// Order: removes first, then updates, then adds.
// Individual failures are logged and collected; an aggregated error is returned.
func ReconcileHandler(mgr *Manager) reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		var errs []error

		// 1. Remove peers by node ID.
		for _, nodeID := range diff.PeersToRemove {
			if err := mgr.RemovePeerByID(nodeID); err != nil {
				mgr.logger.Error("reconcile: remove peer failed",
					"component", "wireguard",
					"peer_id", nodeID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		// 2. Update peers.
		for _, peer := range diff.PeersToUpdate {
			p, err := peerFromSnapshot(peer)
			if err != nil {
				mgr.logger.Error("reconcile: update peer failed",
					"component", "wireguard",
					"peer_id", peer.NodeID,
					"error", err,
				)
				errs = append(errs, err)
				continue
			}
			if err := mgr.UpdatePeer(p); err != nil {
				mgr.logger.Error("reconcile: update peer failed",
					"component", "wireguard",
					"peer_id", p.ID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		// 3. Add peers.
		for _, peer := range diff.PeersToAdd {
			p, err := peerFromSnapshot(peer)
			if err != nil {
				mgr.logger.Error("reconcile: add peer failed",
					"component", "wireguard",
					"peer_id", peer.NodeID,
					"error", err,
				)
				errs = append(errs, err)
				continue
			}
			if err := mgr.AddPeer(p); err != nil {
				mgr.logger.Error("reconcile: add peer failed",
					"component", "wireguard",
					"peer_id", p.ID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
}

// peerFromSnapshot converts a reconciliation SnapshotPeer into the WireGuard
// api.Peer. AllowedIPs are derived locally as mesh_ip/32, the fallback endpoint
// is programmed as the peer endpoint (the relay target; direct endpoints keep
// arriving via the untouched peer_endpoint_changed SSE path), and no PSK is
// fabricated.
//
// AllowedIPs is WireGuard's cryptokey routing table — the authorization boundary
// deciding which source addresses a peer key may send from. MeshIP is therefore
// validated as a bare IPv4 address rather than string-concatenated: an IPv6
// mesh_ip would parse as a /32 host route only after masking a 128-bit address
// into a /32 prefix, silently authorizing a huge range through the tunnel.
func peerFromSnapshot(p api.SnapshotPeer) (api.Peer, error) {
	addr, err := netip.ParseAddr(p.MeshIP)
	if err != nil || !addr.Is4() {
		return api.Peer{}, fmt.Errorf("wireguard: peer %s: invalid mesh_ip %q", p.NodeID, p.MeshIP)
	}
	return api.Peer{
		ID:         p.NodeID,
		PublicKey:  p.PublicKey,
		MeshIP:     p.MeshIP,
		Endpoint:   p.FallbackEndpoint,
		AllowedIPs: []string{netip.PrefixFrom(addr, 32).String()},
		PSK:        "",
	}, nil
}

// HandlePeerAdded returns an EventHandler for peer_added events.
// It parses the Peer from the envelope payload and adds it via the Manager.
func HandlePeerAdded(mgr *Manager) api.EventHandler {
	return func(ctx context.Context, envelope api.Envelope) error {
		var peer api.Peer
		if err := json.Unmarshal(envelope.Payload, &peer); err != nil {
			mgr.logger.Error("peer_added: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.ID,
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
	return func(ctx context.Context, envelope api.Envelope) error {
		var payload struct {
			PeerID string `json:"peer_id"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			mgr.logger.Error("peer_removed: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.ID,
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
	return func(ctx context.Context, envelope api.Envelope) error {
		var peer api.Peer
		if err := json.Unmarshal(envelope.Payload, &peer); err != nil {
			mgr.logger.Error("peer_key_rotated: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.ID,
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
	return func(ctx context.Context, envelope api.Envelope) error {
		var peer api.Peer
		if err := json.Unmarshal(envelope.Payload, &peer); err != nil {
			mgr.logger.Error("peer_endpoint_changed: parse payload failed",
				"component", "wireguard",
				"event_id", envelope.ID,
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
