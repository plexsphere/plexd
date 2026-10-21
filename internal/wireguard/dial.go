package wireguard

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// EndpointSelectionInterval is how often RunEndpointSelection reads the device
// in plexd up.
const EndpointSelectionInterval = 5 * time.Second

// connectedHandshakeAge is how young a peer's latest handshake must be for the
// peer to count as connected. WireGuard rekeys a session it uses every two
// minutes and refuses one older than 180 s, so a handshake older than that
// says the path no longer carries traffic.
const connectedHandshakeAge = 180 * time.Second

// endpointTrialMargin is added to the keepalive interval to give how long one
// entry of a dial order is tried. The keepalive is what makes WireGuard send
// to a newly programmed endpoint of an idle peer, and the margin leaves the
// handshake that send starts time to complete.
const endpointTrialMargin = 5 * time.Second

// dialState is one peer's endpoint selection: the peer as last written, the
// position in its dial order of the endpoint programmed on the device, when
// that endpoint was programmed or the peer was last seen connected, and
// whether a fresh handshake shows the peer connected.
type dialState struct {
	peer         api.Peer
	idx          int
	programmedAt time.Time
	connected    bool
}

// order returns the peer's dial order: Endpoints, or Endpoint alone for a
// caller that sets only Endpoint.
func (s *dialState) order() []string {
	if len(s.peer.Endpoints) == 0 && s.peer.Endpoint != "" {
		return []string{s.peer.Endpoint}
	}
	return s.peer.Endpoints
}

// endpoint returns the entry at idx, or "" for an empty order.
func (s *dialState) endpoint() string {
	order := s.order()
	if len(order) == 0 {
		return ""
	}
	return order[s.idx]
}

// dialOrder returns the endpoints plexd tries for p, in order: the candidates
// on a subnet this node is also on, then p's direct endpoint when it is usable,
// then the remaining candidates, then the relay fallback. A duplicate keeps its
// first position. dropped counts the candidates refused because they are not
// usable by the rules usableDirectEndpoint applies to the direct endpoint.
//
// A candidate is on-link when an entry of local of the same family contains
// it. A host prefix (/32 or /128) makes nothing on-link: it says nothing about
// the addresses next to it.
func dialOrder(p api.SnapshotPeer, local []netip.Prefix, mesh netip.Prefix) (order []string, dropped int) {
	var onLink, offLink []string
	for _, c := range p.EndpointCandidates {
		ap, ok := usableEndpoint(c, mesh)
		if !ok {
			dropped++
			continue
		}
		if isOnLink(ap.Addr(), local) {
			onLink = append(onLink, ap.String())
		} else {
			offLink = append(offLink, ap.String())
		}
	}

	seen := make(map[string]bool)
	add := func(endpoint string) {
		if endpoint == "" || seen[endpoint] {
			return
		}
		seen[endpoint] = true
		order = append(order, endpoint)
	}
	for _, c := range onLink {
		add(c)
	}
	if direct, ok := usableDirectEndpoint(p.Endpoint, mesh); ok {
		add(direct)
	}
	for _, c := range offLink {
		add(c)
	}
	add(p.FallbackEndpoint)
	return order, dropped
}

// isOnLink reports whether an entry of local of addr's family, shorter than a
// host prefix, contains addr.
func isOnLink(addr netip.Addr, local []netip.Prefix) bool {
	for _, prefix := range local {
		if prefix.Addr().Is4() != addr.Is4() || prefix.Bits() >= addr.BitLen() {
			continue
		}
		if prefix.Masked().Contains(addr) {
			return true
		}
	}
	return false
}

// selectEndpoints runs one pass of endpoint selection over every peer it
// tracks, in node-ID order. A peer whose latest handshake is younger than
// connectedHandshakeAge is connected, and its device endpoint is left alone,
// so WireGuard's roaming stays in effect. A peer that is not connected is
// moved to the next entry of its dial order once the current one has been
// tried for the keepalive interval plus endpointTrialMargin.
//
// The device is read before mu is taken. A read error, ErrPeerStatsUnsupported
// included, is returned unchanged with no state touched. A failed switch is
// logged, leaves the peer on the entry still programmed, and is joined into
// the returned error; its next attempt waits a full trial again.
func (m *Manager) selectEndpoints() error {
	stats, err := m.MeshPeerStats()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	timeout := m.cfg.KeepaliveInterval() + endpointTrialMargin
	fresh := make(map[string]MeshPeerStat, len(stats))
	for _, s := range stats {
		if !s.LastHandshake.IsZero() && now.Sub(s.LastHandshake) < connectedHandshakeAge {
			fresh[s.NodeID] = s
		}
	}

	var errs []error
	for _, nodeID := range slices.Sorted(maps.Keys(m.dial)) {
		st := m.dial[nodeID]
		stat, isFresh := fresh[nodeID]
		switch {
		case isFresh && !st.connected:
			st.connected = true
			var endpoint string
			if stat.Endpoint.IsValid() {
				endpoint = stat.Endpoint.String()
			}
			m.logger.Info("wireguard: endpoint selected",
				"component", "wireguard",
				"peer_id", nodeID,
				"endpoint", endpoint,
			)
			continue
		case isFresh:
			continue
		case st.connected:
			st.connected = false
			st.programmedAt = now
			m.logger.Info("wireguard: peer handshake went stale, resuming endpoint selection",
				"component", "wireguard",
				"peer_id", nodeID,
			)
			continue
		}

		order := st.order()
		if len(order) < 2 || now.Sub(st.programmedAt) < timeout {
			continue
		}
		next := (st.idx + 1) % len(order)
		st.programmedAt = now
		peerCfg, err := m.peerConfig(st.peer, order[next])
		if err == nil {
			err = m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg)
		}
		if err != nil {
			m.logger.Warn("wireguard: endpoint switch failed",
				"component", "wireguard",
				"peer_id", nodeID,
				"endpoint", order[next],
				"error", err,
			)
			errs = append(errs, fmt.Errorf("wireguard: switch endpoint of peer %s: %w", nodeID, err))
			continue
		}
		st.idx = next
		m.logger.Info("wireguard: trying next endpoint candidate",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", order[next],
			"attempt", next+1,
			"of", len(order),
		)
	}
	return errors.Join(errs...)
}

// RunEndpointSelection runs selectEndpoints every interval until ctx is done,
// then returns nil.
//
// It returns nil at once when the keepalive is off: WireGuard starts a
// handshake only when it sends something, so without the keepalive an idle
// peer never tries a newly programmed endpoint and a trial would prove
// nothing. Every peer then keeps the first entry of its dial order. It also
// returns nil, after one pass, when the controller cannot read peer stats.
func (m *Manager) RunEndpointSelection(ctx context.Context, interval time.Duration) error {
	keepalive := m.cfg.KeepaliveInterval()
	if keepalive == 0 {
		m.logger.Info("wireguard: endpoint selection disabled, persistent_keepalive is 0s",
			"component", "wireguard",
		)
		return nil
	}

	m.logger.Info("wireguard: endpoint selection started",
		"component", "wireguard",
		"interval", interval,
		"timeout", keepalive+endpointTrialMargin,
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		err := m.selectEndpoints()
		if errors.Is(err, ErrPeerStatsUnsupported) {
			m.logger.Info("wireguard: endpoint selection unavailable, the controller cannot read peer stats",
				"component", "wireguard",
			)
			return nil
		}
		if err != nil {
			m.logger.Warn("wireguard: endpoint selection pass failed",
				"component", "wireguard",
				"error", err,
			)
		}
	}
}
