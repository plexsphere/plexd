package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// FailureDetectionDispatchHandler returns a reconcile.DispatchHandler that
// hands the failure-detection time of every successful pull to mgr (see
// Manager.SetFailureDetection). The block is decoded here rather than in
// FetchState, and leniently, as the reachability block is: a malformed tuning
// value must not fail the pull that carries the peers and the policy.
//
// Per pull:
//   - An absent block or a null changes nothing and logs nothing: the node
//     keeps the value of its last pull that carried one.
//   - A block json.Unmarshal refuses, such as a string or a fractional
//     detect_after_seconds, changes nothing and logs wireguard: failure
//     detection block malformed at Warn, once until a block decodes again.
//   - A detect_after_seconds of zero or less, {} included, changes nothing.
//     A value from 1 to 4 applies MinFailureDetection, and one above 180
//     applies MaxFailureDetection. The integer is bounded before it is
//     multiplied by time.Second, so no value overflows a time.Duration.
//     Each logs wireguard: failure detection time out of range at Warn, once
//     per run of the same raw value; a value from 5 to 180 ends the run.
//   - A value in range, clamped or not, goes to SetFailureDetection, which
//     logs the value when it changed.
//
// The state lives in the closure, which only the reconcile goroutine enters,
// so it needs no lock.
func FailureDetectionDispatchHandler(mgr *Manager) reconcile.DispatchHandler {
	const (
		minSeconds = int64(MinFailureDetection / time.Second)
		maxSeconds = int64(MaxFailureDetection / time.Second)
	)
	var (
		malformedLogged bool
		outOfRange      bool  // the last block that decoded held a value out of range
		outOfRangeRaw   int64 // that value, logged once for its run
	)
	return func(_ context.Context, desired *api.NodeStateSnapshot) {
		if desired == nil || len(desired.FailureDetection) == 0 {
			return
		}
		var block *api.NodeStateFailureDetection
		if err := json.Unmarshal(desired.FailureDetection, &block); err != nil {
			if !malformedLogged {
				mgr.logger.Warn("wireguard: failure detection block malformed",
					"component", "wireguard",
					"error", err,
				)
				malformedLogged = true
			}
			return
		}
		// A literal null decodes to a nil block: like an absent key, it says
		// nothing about the value.
		if block == nil {
			return
		}
		malformedLogged = false

		raw := block.DetectAfterSeconds
		seconds := min(max(raw, minSeconds), maxSeconds)
		if raw == seconds {
			outOfRange = false
		} else if !outOfRange || raw != outOfRangeRaw {
			attrs := []any{"component", "wireguard", "detect_after_seconds", raw}
			if raw > 0 {
				attrs = append(attrs, "applied", time.Duration(seconds)*time.Second)
			}
			mgr.logger.Warn("wireguard: failure detection time out of range", attrs...)
			outOfRange, outOfRangeRaw = true, raw
		}
		if raw <= 0 {
			return
		}
		mgr.SetFailureDetection(time.Duration(seconds) * time.Second)
	}
}

// EdgePSKLookup returns the edge PSK fetched for a peer, keyed by the peer's
// node ID and the public key it was fetched for. A PSK fetched for another key
// belongs to a different device peer, so it is never returned.
type EdgePSKLookup interface {
	Lookup(peerNodeID, publicKey string) ([]byte, bool)
}

// ReconcileHandler returns a reconcile.ReconcileHandler that applies peer
// changes from the StateDiff to the WireGuard interface via the Manager.
// PeersToRemove are node IDs resolved through the peer index, and an ID the
// index no longer holds is already gone: a failed handler run leaves the
// reconciler's snapshot as it was, so the next run hands the same removal
// over again, and failing it then would fail every run after. Adds and updates
// are converted from the snapshot shape via peerFromSnapshot, with the dial
// order dialOrder builds, the relays that end it as Fallbacks, and the edge
// PSK psks holds for the peer's current public key. A nil psks programs no
// PSK.
// Order: removes first, then the pull's shared subnets, then updates, then
// adds, then the shared subnet writes, then the peer routes. The shared
// subnets step (see Manager.setSharedSubnets) takes the shared_subnets block
// and picks each subnet's holder before the updates and adds convert a peer,
// so every peer written carries the shared subnets it holds and none it does
// not. A pull can change a holder without changing either peer entry, so the
// shared subnet writes (see Manager.syncSharedSubnets) then write every peer
// on the device whose routed subnets the holders changed. They leave out a
// peer whose update or add failed in the run: a failed write leaves the peer
// as it was, and the next run applies the whole entry. A nil desired skips
// both steps, and the manager keeps the shared subnets it holds. The handler
// ends with syncPeerRoutes, which routes the routed subnets of the peers now
// on the device through the mesh interface and removes the routes no peer
// lists any more.
// Individual failures are logged and collected; an aggregated error is returned.
//
// The host's interface prefixes and the mesh prefix are read once per call.
// When the prefixes cannot be read, every candidate is ordered as off-link,
// which still tries each of them, and no routed subnet is skipped as inside a
// local network.
func ReconcileHandler(mgr *Manager, psks EdgePSKLookup) reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		var errs []error
		// failed holds the node IDs whose update or add failed in this run.
		failed := make(map[string]struct{})

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
			if _, held := mgr.PeerIndex().Lookup(nodeID); !held {
				continue
			}
			if err := mgr.RemovePeerByID(nodeID); err != nil {
				mgr.logger.Error("reconcile: remove peer failed",
					"component", "wireguard",
					"peer_id", nodeID,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		// 2. Take the pull's shared subnets and pick their holders.
		if desired != nil {
			mgr.setSharedSubnets(desired.SharedSubnets, desired.Peers, mesh, local)
		}

		// 3. Update peers.
		for _, peer := range diff.PeersToUpdate {
			p, err := mgr.snapshotPeer(peer, psks, local, mesh)
			if err != nil {
				mgr.logger.Error("reconcile: update peer failed",
					"component", "wireguard",
					"peer_id", peer.NodeID,
					"error", err,
				)
				errs = append(errs, err)
				failed[peer.NodeID] = struct{}{}
				continue
			}
			if err := mgr.UpdatePeer(p); err != nil {
				mgr.logger.Error("reconcile: update peer failed",
					"component", "wireguard",
					"peer_id", p.ID,
					"error", err,
				)
				errs = append(errs, err)
				failed[p.ID] = struct{}{}
			}
		}

		// 4. Add peers.
		for _, peer := range diff.PeersToAdd {
			p, err := mgr.snapshotPeer(peer, psks, local, mesh)
			if err != nil {
				mgr.logger.Error("reconcile: add peer failed",
					"component", "wireguard",
					"peer_id", peer.NodeID,
					"error", err,
				)
				errs = append(errs, err)
				failed[peer.NodeID] = struct{}{}
				continue
			}
			if err := mgr.AddPeer(p); err != nil {
				mgr.logger.Error("reconcile: add peer failed",
					"component", "wireguard",
					"peer_id", p.ID,
					"error", err,
				)
				errs = append(errs, err)
				failed[p.ID] = struct{}{}
			}
		}

		// 5. Write the peers whose routed subnets the holders changed, but
		// not one whose update or add failed above.
		if desired != nil {
			peers := slices.DeleteFunc(slices.Clone(desired.Peers), func(p api.SnapshotPeer) bool {
				_, f := failed[p.NodeID]
				return f
			})
			if err := mgr.syncSharedSubnets(peers, mesh, local); err != nil {
				errs = append(errs, err)
			}
		}

		// 6. Route the peers' routed subnets through the mesh interface.
		if err := mgr.syncPeerRoutes(); err != nil {
			errs = append(errs, err)
		}

		return errors.Join(errs...)
	}
}

// snapshotPeer converts a snapshot peer with its dial order, the PSK psks
// holds for it and the routed subnets routedSubnets gives it: the subnets of
// its routed_subnets usableRoutedSubnets accepts that are no shared subnet,
// followed by the shared subnets it holds. It logs a direct endpoint,
// candidates and routed subnets it had to refuse.
func (m *Manager) snapshotPeer(p api.SnapshotPeer, psks EdgePSKLookup, local []netip.Prefix, mesh netip.Prefix) (api.Peer, error) {
	var psk []byte
	if psks != nil {
		if key, ok := psks.Lookup(p.NodeID, p.PublicKey); ok {
			psk = key
		}
	}
	order, relays, dropped := dialOrder(p, local, mesh)
	routed, skipped := m.routedSubnets(p, mesh, local)
	peer, err := peerFromSnapshot(p, order, order[len(order)-relays:], psk, routed)
	if err != nil {
		return api.Peer{}, err
	}
	for _, s := range skipped {
		m.logger.Warn("wireguard: routed subnet not programmed",
			"component", "wireguard",
			"peer_id", p.NodeID,
			"subnet", s.Subnet,
			"reason", s.Reason,
		)
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
// api.Peer. AllowedIPs are derived locally as mesh_ip/32 followed by routed,
// Endpoints is order, the dial order endpoint selection tries, and Endpoint its
// first entry (empty for an empty order). Fallbacks is fallbacks, the relays
// that end order (see dialOrder), and nil when there are none; endpoint
// selection holds them longer than the others and moves a relayed peer along
// them. psk, the edge PSK fetched for the peer, is carried base64-encoded; a
// nil psk programs none. routed is the list Manager.routedSubnets gives the
// peer, and RoutedSubnets carries it, nil when it is empty.
//
// AllowedIPs is WireGuard's cryptokey routing table — the authorization boundary
// deciding which source addresses a peer key may send from. MeshIP is therefore
// validated as a bare IPv4 address rather than string-concatenated: an IPv6
// mesh_ip would parse as a /32 host route only after masking a 128-bit address
// into a /32 prefix, silently authorizing a huge range through the tunnel. For
// the same reason routed must come from Manager.routedSubnets, whose every
// entry passed the rules of usableRoutedSubnets, which refuse a subnet that
// would widen the range past the networks behind the peer.
func peerFromSnapshot(p api.SnapshotPeer, order, fallbacks []string, psk []byte, routed []string) (api.Peer, error) {
	addr, err := netip.ParseAddr(p.MeshIP)
	if err != nil || !addr.Is4() {
		return api.Peer{}, fmt.Errorf("wireguard: peer %s: invalid mesh_ip %q", p.NodeID, p.MeshIP)
	}
	var endpoint string
	if len(order) > 0 {
		endpoint = order[0]
	}
	if len(fallbacks) == 0 {
		fallbacks = nil
	}
	var pskB64 string
	if psk != nil {
		pskB64 = base64.StdEncoding.EncodeToString(psk)
	}
	var routedSubnets []string
	if len(routed) > 0 {
		routedSubnets = slices.Clone(routed)
	}
	return api.Peer{
		ID:            p.NodeID,
		PublicKey:     p.PublicKey,
		MeshIP:        p.MeshIP,
		Endpoint:      endpoint,
		Endpoints:     order,
		Fallbacks:     fallbacks,
		AllowedIPs:    peerAllowedIPs(addr, routed),
		PSK:           pskB64,
		RoutedSubnets: routedSubnets,
	}, nil
}

// peerAllowedIPs returns the allowed IPs of a peer whose mesh address is addr
// and whose routed subnets are routed: the host /32 of addr followed by
// routed, in its order.
func peerAllowedIPs(addr netip.Addr, routed []string) []string {
	allowed := make([]string, 0, 1+len(routed))
	allowed = append(allowed, netip.PrefixFrom(addr, 32).String())
	return append(allowed, routed...)
}

// The reasons usableRoutedSubnets gives for a routed subnet it skips, as the
// Warn "wireguard: routed subnet not programmed" logs them. setSharedSubnets
// gives them for a shared subnet it skips, as the Warn "wireguard: shared
// subnet not programmed" logs them, beside routedSubnetNoBridge.
const (
	// routedSubnetInvalid: the entry is no IPv4 prefix, or has host bits set.
	routedSubnetInvalid = "invalid"
	// routedSubnetOverlapsMesh: the subnet overlaps the Domain mesh prefix.
	routedSubnetOverlapsMesh = "overlaps_mesh"
	// routedSubnetInsideLocalNetwork: a network of one of this host's
	// interfaces holds the subnet.
	routedSubnetInsideLocalNetwork = "inside_local_network"
	// routedSubnetDuplicate: an earlier entry of the list is the same subnet.
	routedSubnetDuplicate = "duplicate"
)

// skippedSubnet is one entry of a peer's routed_subnets that
// usableRoutedSubnets refused, as the pull carried it, with the reason.
type skippedSubnet struct {
	Subnet, Reason string
}

// usableRoutedSubnets splits a peer's routed_subnets into the subnets this
// node programs, in the list's order and in canonical form, and the ones it
// skips with the reason, the first rule that applies:
//
//   - invalid: netip.ParsePrefix refuses the entry, it is not IPv4, or it has
//     host bits set.
//   - overlaps_mesh: it overlaps mesh, when mesh is valid. 0.0.0.0/0 overlaps
//     every mesh.
//   - inside_local_network: a prefix of local contains its address and is no
//     longer than it, so the subnet lies inside a network of one of this
//     host's interfaces.
//   - duplicate: an earlier entry of the list is the same subnet.
//
// The first two would widen what the peer's key may send from past the
// networks behind it, and the third would route this node's own network, its
// gateway included, into the mesh. Both lists are nil when there is nothing
// to put in them.
func usableRoutedSubnets(subnets []string, mesh netip.Prefix, local []netip.Prefix) (accepted []string, skipped []skippedSubnet) {
	seen := make(map[netip.Prefix]struct{}, len(subnets))
	for _, subnet := range subnets {
		prefix, reason := checkRoutedSubnet(subnet, mesh, local, seen)
		if reason != "" {
			skipped = append(skipped, skippedSubnet{Subnet: subnet, Reason: reason})
			continue
		}
		accepted = append(accepted, prefix.String())
	}
	return accepted, skipped
}

// checkRoutedSubnet applies the rules of usableRoutedSubnets to subnet, one
// entry of a list whose earlier accepted entries seen holds. For an entry it
// accepts, it adds the prefix to seen and returns it with an empty reason;
// for any other, it returns the reason of the first rule that applies.
// setSharedSubnets checks the subnets of the shared_subnets block with it, so
// a shared subnet passes the rules a routed subnet passes.
func checkRoutedSubnet(subnet string, mesh netip.Prefix, local []netip.Prefix, seen map[netip.Prefix]struct{}) (netip.Prefix, string) {
	prefix, err := netip.ParsePrefix(subnet)
	switch {
	case err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked():
		return prefix, routedSubnetInvalid
	case mesh.IsValid() && prefix.Overlaps(mesh):
		return prefix, routedSubnetOverlapsMesh
	case insideLocalNetwork(prefix, local):
		return prefix, routedSubnetInsideLocalNetwork
	}
	if _, dup := seen[prefix]; dup {
		return prefix, routedSubnetDuplicate
	}
	seen[prefix] = struct{}{}
	return prefix, ""
}

// insideLocalNetwork reports whether one prefix of local contains the address
// of subnet and is no longer than subnet, which puts the whole subnet inside
// that network.
func insideLocalNetwork(subnet netip.Prefix, local []netip.Prefix) bool {
	for _, network := range local {
		if network.Bits() <= subnet.Bits() && network.Contains(subnet.Addr()) {
			return true
		}
	}
	return false
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
