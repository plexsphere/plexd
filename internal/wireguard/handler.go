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
// are converted from the snapshot shape via peerFromSnapshot, with the dial
// order dialOrder builds and the edge PSK psks holds for the peer's current
// public key. A nil psks programs no PSK.
// Order: removes first, then updates, then adds.
// Individual failures are logged and collected; an aggregated error is returned.
//
// The host's interface prefixes and the mesh prefix are read once per call.
// When the prefixes cannot be read, every candidate is ordered as off-link,
// which still tries each of them.
func ReconcileHandler(mgr *Manager, psks EdgePSKLookup) reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		var errs []error

		local, err := mgr.localPrefixes()
		if err != nil {
			mgr.logger.Warn("wireguard: read local prefixes failed, ordering every candidate as off-link",
				"component", "wireguard",
				"error", err,
			)
			local = nil
		}
		mesh := mgr.MeshPrefix()

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
			p, err := mgr.snapshotPeer(peer, psks, local, mesh)
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
			p, err := mgr.snapshotPeer(peer, psks, local, mesh)
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

// snapshotPeer converts a snapshot peer with its dial order and the PSK psks
// holds for it, and logs a direct endpoint and candidates it had to refuse.
func (m *Manager) snapshotPeer(p api.SnapshotPeer, psks EdgePSKLookup, local []netip.Prefix, mesh netip.Prefix) (api.Peer, error) {
	var psk []byte
	if psks != nil {
		if key, ok := psks.Lookup(p.NodeID, p.PublicKey); ok {
			psk = key
		}
	}
	order, dropped := dialOrder(p, local, mesh)
	peer, err := peerFromSnapshot(p, order, psk)
	if err != nil {
		return api.Peer{}, err
	}
	if _, rejected := ProgrammedEndpoint(p, mesh); rejected {
		m.logger.Warn("wireguard: peer direct endpoint unusable, leaving it out of the dial order",
			"component", "wireguard",
			"peer_id", p.NodeID,
			"endpoint", p.Endpoint,
			"fallback", p.FallbackEndpoint,
		)
	}
	if dropped > 0 {
		m.logger.Debug("wireguard: dropped endpoint candidates",
			"component", "wireguard",
			"peer_id", p.NodeID,
			"count", dropped,
		)
	}
	return peer, nil
}

// peerFromSnapshot converts a reconciliation SnapshotPeer into the WireGuard
// api.Peer. AllowedIPs are derived locally as mesh_ip/32, Endpoints is order,
// the dial order endpoint selection tries, and Endpoint its first entry (empty
// for an empty order). Fallback is p's fallback_endpoint when that is the last
// entry of order, which endpoint selection then holds longer than the others,
// and empty otherwise, as when a candidate equal to it holds an earlier
// position. psk, the edge PSK fetched for the peer, is carried base64-encoded;
// a nil psk programs none.
//
// AllowedIPs is WireGuard's cryptokey routing table — the authorization boundary
// deciding which source addresses a peer key may send from. MeshIP is therefore
// validated as a bare IPv4 address rather than string-concatenated: an IPv6
// mesh_ip would parse as a /32 host route only after masking a 128-bit address
// into a /32 prefix, silently authorizing a huge range through the tunnel.
func peerFromSnapshot(p api.SnapshotPeer, order []string, psk []byte) (api.Peer, error) {
	addr, err := netip.ParseAddr(p.MeshIP)
	if err != nil || !addr.Is4() {
		return api.Peer{}, fmt.Errorf("wireguard: peer %s: invalid mesh_ip %q", p.NodeID, p.MeshIP)
	}
	var endpoint, fallback string
	if len(order) > 0 {
		endpoint = order[0]
		if p.FallbackEndpoint != "" && order[len(order)-1] == p.FallbackEndpoint {
			fallback = p.FallbackEndpoint
		}
	}
	var pskB64 string
	if psk != nil {
		pskB64 = base64.StdEncoding.EncodeToString(psk)
	}
	return api.Peer{
		ID:         p.NodeID,
		PublicKey:  p.PublicKey,
		MeshIP:     p.MeshIP,
		Endpoint:   endpoint,
		Endpoints:  order,
		Fallback:   fallback,
		AllowedIPs: []string{netip.PrefixFrom(addr, 32).String()},
		PSK:        pskB64,
	}, nil
}

// ProgrammedEndpoint returns the endpoint the pull gives p without its
// candidates: its direct endpoint when that is usable (see
// usableDirectEndpoint), otherwise its relay fallback, which may be empty.
// directRejected reports a non-empty direct endpoint that was refused, so the
// caller can say why it is left out. The node API's peer list shows this
// endpoint; the device's endpoint is the one endpoint selection settles on.
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
	ap, ok := usableEndpoint(endpoint, mesh)
	if !ok {
		return "", false
	}
	return ap.String(), true
}

// usableEndpoint applies usableDirectEndpoint's rules to endpoint, a direct
// endpoint or a candidate, and returns it parsed, unmapped and without a zone.
func usableEndpoint(endpoint string, mesh netip.Prefix) (netip.AddrPort, bool) {
	if endpoint == "" {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, false
	}
	addr := ap.Addr()
	if addr.Zone() != "" {
		return netip.AddrPort{}, false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return netip.AddrPort{}, false
	}
	if mesh.IsValid() && mesh.Contains(addr) {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, ap.Port()), true
}
