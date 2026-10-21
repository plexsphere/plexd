package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// EdgePSKLookup returns the edge PSK fetched for a peer, keyed by the peer's
// node ID and the public key it was fetched for. A PSK fetched for another key
// belongs to a different device peer, so it is never returned.
type EdgePSKLookup interface {
	Lookup(peerNodeID, publicKey string) ([]byte, bool)
}

// ReconcileHandler returns a reconcile.ReconcileHandler that applies peer
// changes from the StateDiff to the WireGuard interface via the Manager.
// PeersToRemove are node IDs resolved through the peer index; adds and updates
// are converted from the snapshot shape via peerFromSnapshot, with the edge PSK
// psks holds for the peer's current public key. A nil psks programs no PSK.
// Order: removes first, then updates, then adds.
// Individual failures are logged and collected; an aggregated error is returned.
func ReconcileHandler(mgr *Manager, psks EdgePSKLookup) reconcile.ReconcileHandler {
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
			p, err := mgr.snapshotPeer(peer, psks)
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
			p, err := mgr.snapshotPeer(peer, psks)
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

// snapshotPeer converts a snapshot peer with the PSK psks holds for it, and logs
// a direct endpoint it had to refuse.
func (m *Manager) snapshotPeer(p api.SnapshotPeer, psks EdgePSKLookup) (api.Peer, error) {
	var psk []byte
	if psks != nil {
		if key, ok := psks.Lookup(p.NodeID, p.PublicKey); ok {
			psk = key
		}
	}
	peer, err := peerFromSnapshot(p, m.MeshPrefix(), psk)
	if err != nil {
		return api.Peer{}, err
	}
	if _, rejected := ProgrammedEndpoint(p, m.MeshPrefix()); rejected {
		m.logger.Warn("wireguard: peer direct endpoint unusable, programming the relay fallback",
			"component", "wireguard",
			"peer_id", p.NodeID,
			"endpoint", p.Endpoint,
			"fallback", p.FallbackEndpoint,
		)
	}
	return peer, nil
}

// peerFromSnapshot converts a reconciliation SnapshotPeer into the WireGuard
// api.Peer. AllowedIPs are derived locally as mesh_ip/32, the endpoint is the
// one ProgrammedEndpoint picks (the direct endpoint when usable, the relay
// fallback otherwise), and psk, the edge PSK fetched for the peer, is carried
// base64-encoded; a nil psk programs none.
//
// AllowedIPs is WireGuard's cryptokey routing table — the authorization boundary
// deciding which source addresses a peer key may send from. MeshIP is therefore
// validated as a bare IPv4 address rather than string-concatenated: an IPv6
// mesh_ip would parse as a /32 host route only after masking a 128-bit address
// into a /32 prefix, silently authorizing a huge range through the tunnel.
func peerFromSnapshot(p api.SnapshotPeer, mesh netip.Prefix, psk []byte) (api.Peer, error) {
	addr, err := netip.ParseAddr(p.MeshIP)
	if err != nil || !addr.Is4() {
		return api.Peer{}, fmt.Errorf("wireguard: peer %s: invalid mesh_ip %q", p.NodeID, p.MeshIP)
	}
	endpoint, _ := ProgrammedEndpoint(p, mesh)
	var pskB64 string
	if psk != nil {
		pskB64 = base64.StdEncoding.EncodeToString(psk)
	}
	return api.Peer{
		ID:         p.NodeID,
		PublicKey:  p.PublicKey,
		MeshIP:     p.MeshIP,
		Endpoint:   endpoint,
		AllowedIPs: []string{netip.PrefixFrom(addr, 32).String()},
		PSK:        pskB64,
	}, nil
}

// ProgrammedEndpoint returns the endpoint plexd programs for p: its direct
// endpoint when that is usable (see usableDirectEndpoint), otherwise its relay
// fallback, which may be empty. directRejected reports a non-empty direct
// endpoint that was refused, so the caller can say why the relay is in use.
func ProgrammedEndpoint(p api.SnapshotPeer, mesh netip.Prefix) (endpoint string, directRejected bool) {
	if direct, ok := usableDirectEndpoint(p.Endpoint, mesh); ok {
		return direct, false
	}
	return p.FallbackEndpoint, p.Endpoint != ""
}

// usableDirectEndpoint validates a peer's direct endpoint and returns it in
// canonical host:port form, with an IPv4-mapped IPv6 address unmapped.
//
// The endpoint must parse as an address and a non-zero port, carry no zone,
// and name an address that is not unspecified, loopback, multicast or
// link-local. It must also lie outside mesh: an endpoint inside the Domain mesh
// prefix is routed through the mesh interface itself, so WireGuard would send
// the peer's encrypted packets into its own tunnel. A zero mesh skips that
// check. The relay fallback is never validated here: the contract allows a
// hostname there.
func usableDirectEndpoint(endpoint string, mesh netip.Prefix) (string, bool) {
	if endpoint == "" {
		return "", false
	}
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil || ap.Port() == 0 {
		return "", false
	}
	addr := ap.Addr()
	if addr.Zone() != "" {
		return "", false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return "", false
	}
	if mesh.IsValid() && mesh.Contains(addr) {
		return "", false
	}
	return netip.AddrPortFrom(addr, ap.Port()).String(), true
}
