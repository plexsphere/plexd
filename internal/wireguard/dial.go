package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
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

// endpointTrialMargin is added to the keepalive interval to give one trial,
// how long an entry of a dial order is tried; the relay fallback that ends an
// order is tried for one trial per entry before it (see dialState.trial). The
// keepalive is what makes WireGuard send to a newly programmed endpoint of an
// idle peer, and the margin leaves the handshake that send starts time to
// complete.
const endpointTrialMargin = 5 * time.Second

// relayProbeTimeout is how long a relayed peer has to answer the relay
// liveness probe (see checkRelay). WireGuard answers a data packet with a
// keepalive within its KeepaliveTimeout, 10 s, when it has nothing else to
// send; its RekeyTimeout, 5 s, on top leaves the answer time to arrive.
const relayProbeTimeout = 15 * time.Second

// relayProbePort is the UDP port SendRelayProbe sends to, the discard port.
// Nothing has to listen there: the peer's WireGuard answers the data packet
// that carries the datagram, whatever the host behind it does with it.
const relayProbePort = 9

// dialState is one peer's endpoint selection: the peer as last written, the
// position in its dial order of the endpoint programmed on the device, when
// that endpoint was programmed or the peer was last seen connected, and
// whether a fresh handshake shows the peer connected.
//
// relayed records that the peer was last seen connected over its relay (see
// relayedOver). A relayed peer stays on its relay: when its connection fails,
// plexd dials the relay again instead of the direct entries before it, which
// already failed. relayed implies onFallback. recreatedAt is when a relay
// re-dial last replaced the device peer; a handshake older than that belongs
// to the session the re-dial dropped. The remaining fields are the relay
// liveness probe's state (see checkRelay).
type dialState struct {
	peer         api.Peer
	idx          int
	programmedAt time.Time
	connected    bool

	relayed      bool
	recreatedAt  time.Time
	rxBytes      uint64    // the device's RxBytes for the peer at the last pass
	rxAt         time.Time // when the silence window started: rxBytes changed, the peer turned connected or came back on the relay, or a probe send failed
	probedAt     time.Time // when the outstanding probe went out, zero when none is
	probeFailing bool      // the last probe send failed
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

// onFallback reports whether the entry programmed is the peer's Fallback, the
// relay.
func (s *dialState) onFallback() bool {
	return s.peer.Fallback != "" && s.endpoint() == s.peer.Fallback
}

// relayedOver reports whether stat shows the peer reached over its relay: the
// entry programmed is its Fallback and, when that Fallback is an address and
// the device reports an endpoint, the device's endpoint is that address. A
// device endpoint elsewhere means WireGuard roamed to a path the peer opened
// directly, which a relay move must not cut and the probe must not judge. A
// hostname Fallback cannot be compared, so the entry programmed decides.
func (s *dialState) relayedOver(stat MeshPeerStat) bool {
	if !s.onFallback() {
		return false
	}
	fallback, err := netip.ParseAddrPort(s.peer.Fallback)
	if err != nil || !stat.Endpoint.IsValid() {
		return true
	}
	unmapped := func(ap netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) }
	return unmapped(stat.Endpoint) == unmapped(fallback)
}

// onRelay records that the peer's relay was just written on a fresh device
// peer (see Manager.redialRelay): the position is the Fallback's, the peer is
// not connected, its timer restarts, and the probe starts over, because the
// new device peer counts its bytes from 0. The Fallback always ends the order
// (see peerFromSnapshot), so its position is found.
func (s *dialState) onRelay(now time.Time) {
	s.idx = max(slices.Index(s.order(), s.peer.Fallback), 0)
	s.connected = false
	s.programmedAt = now
	s.recreatedAt = now
	s.rxBytes = 0
	s.rxAt = now
	s.probedAt = time.Time{}
}

// trial returns how long the entry at idx of the dial order is tried, given
// timeout, one trial. The peer's Fallback, when it is the last entry of an
// order of two or more, is tried for one trial per entry before it, so it is
// held as long as those entries took together. Each of two peers that dial one
// relay then spends at least half its cycle on it, and their relay windows
// overlap or touch. Every other entry is tried for timeout.
func (s *dialState) trial(idx int, timeout time.Duration) time.Duration {
	order := s.order()
	if idx > 0 && idx == len(order)-1 && s.peer.Fallback != "" && order[idx] == s.peer.Fallback {
		return timeout * time.Duration(idx)
	}
	return timeout
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
// tried for its trial (see dialState.trial): the keepalive interval plus
// endpointTrialMargin, or for a Fallback that ends an order of n entries,
// n-1 times that. The switch is logged with the trial of the entry it
// programs.
//
// A relayed peer (see dialState) never moves to another entry. While it is
// connected, checkRelay probes it once it falls silent. When its handshake
// goes stale, or the probe goes unanswered, its relay is dialed again on a
// fresh device peer, and again each time the relay's trial passes without a
// handshake.
//
// The device is read before mu is taken. A read error, ErrPeerStatsUnsupported
// included, is returned unchanged with no state touched. A failed switch is
// logged, leaves the peer on the entry still programmed, and is joined into
// the returned error; its next attempt waits that entry's full trial again.
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
		// The device was read before mu was taken, so UpdatePeer may have
		// replaced the device peer since. A handshake older than that belongs
		// to the dropped session and says nothing about the new one.
		if isFresh && stat.LastHandshake.Before(st.recreatedAt) {
			isFresh = false
		}
		switch {
		case isFresh && !st.connected:
			st.connected = true
			st.relayed = st.relayedOver(stat)
			st.rxBytes = stat.RxBytes
			st.rxAt = now
			st.probedAt = time.Time{}
			st.probeFailing = false
			var endpoint string
			if stat.Endpoint.IsValid() {
				endpoint = stat.Endpoint.String()
			}
			m.logger.Info("wireguard: endpoint selected",
				"component", "wireguard",
				"peer_id", nodeID,
				"endpoint", endpoint,
				"relayed", st.relayed,
			)
			continue
		case isFresh:
			relayed := st.relayedOver(stat)
			if relayed && !st.relayed {
				// Back on the relay: the silence window starts now.
				st.rxBytes = stat.RxBytes
				st.rxAt = now
				st.probedAt = time.Time{}
			}
			st.relayed = relayed
			if relayed {
				if err := m.checkRelay(nodeID, st, stat, now, timeout); err != nil {
					errs = append(errs, err)
				}
			}
			continue
		case st.connected:
			st.connected = false
			st.programmedAt = now
			if st.relayed {
				m.logger.Info("wireguard: relayed peer handshake went stale, dialing the relay again",
					"component", "wireguard",
					"peer_id", nodeID,
					"endpoint", st.peer.Fallback,
				)
				if err := m.redialInPass(nodeID, st, now); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			m.logger.Info("wireguard: peer handshake went stale, resuming endpoint selection",
				"component", "wireguard",
				"peer_id", nodeID,
			)
			continue
		}

		if st.relayed {
			trial := st.trial(st.idx, timeout)
			if now.Sub(st.programmedAt) < trial {
				continue
			}
			m.logger.Info("wireguard: still no handshake over the relay, dialing it again",
				"component", "wireguard",
				"peer_id", nodeID,
				"endpoint", st.peer.Fallback,
				"trial", trial,
			)
			if err := m.redialInPass(nodeID, st, now); err != nil {
				errs = append(errs, err)
			}
			continue
		}

		order := st.order()
		if len(order) < 2 || now.Sub(st.programmedAt) < st.trial(st.idx, timeout) {
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
			"trial", st.trial(next, timeout),
		)
	}
	return errors.Join(errs...)
}

// checkRelay runs the relay liveness probe for a relayed peer whose handshake
// is fresh. A fresh handshake does not prove the relay still forwards: the
// session stays valid for up to 180 s after the relay stopped. Nor does a
// device counter that stands still prove it stopped, because a received
// keepalive restarts WireGuard's own keepalive timer, so on an idle tunnel one
// side can receive nothing until the next rekey. A data packet is different:
// WireGuard answers one with a keepalive within 10 s when it has nothing else
// to send.
//
// So once the peer's RxBytes has not moved for one trial, the probe sends a
// datagram through the tunnel to the peer's mesh IP, and a counter that has
// still not moved relayProbeTimeout later dials the relay again. A failed
// send restarts the silence, so no verdict follows a probe that never left;
// it logs at Warn the first time and at Debug while the sends keep failing.
// No probe goes out without a sender, or to a mesh IP outside the mesh
// prefix: the host would route that datagram past the mesh interface, and its
// silence would read as a dead relay.
//
// DECISION: the probe is sent under mu. One UDP send does not block, and
// sending after the lock is released would need a second locked step to
// record whether it went out.
func (m *Manager) checkRelay(nodeID string, st *dialState, stat MeshPeerStat, now time.Time, timeout time.Duration) error {
	if stat.RxBytes != st.rxBytes {
		st.rxBytes = stat.RxBytes
		st.rxAt = now
		st.probedAt = time.Time{}
		return nil
	}
	if !st.probedAt.IsZero() {
		if now.Sub(st.probedAt) < relayProbeTimeout {
			return nil
		}
		m.logger.Info("wireguard: relayed peer did not answer the probe, dialing the relay again",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", st.peer.Fallback,
			"silent_for", now.Sub(st.rxAt),
		)
		return m.redialInPass(nodeID, st, now)
	}
	if m.sendProbe == nil || now.Sub(st.rxAt) < timeout {
		return nil
	}
	ip, err := netip.ParseAddr(st.peer.MeshIP)
	if err != nil || !m.meshPrefix.Contains(ip) {
		return nil
	}
	if err := m.sendProbe(ip); err != nil {
		level := slog.LevelWarn
		if st.probeFailing {
			level = slog.LevelDebug
		}
		m.logger.Log(context.Background(), level, "wireguard: relay probe send failed",
			"component", "wireguard",
			"peer_id", nodeID,
			"mesh_ip", ip.String(),
			"error", err,
		)
		st.probeFailing = true
		st.rxAt = now
		return nil
	}
	m.logger.Debug("wireguard: relayed peer silent, probing",
		"component", "wireguard",
		"peer_id", nodeID,
		"mesh_ip", ip.String(),
		"silent_for", now.Sub(st.rxAt),
	)
	st.probeFailing = false
	st.probedAt = now
	return nil
}

// redialInPass dials st's relay again on a fresh device peer during a pass. A
// failed attempt is logged and wrapped like a failed switch, and leaves the
// peer not connected with its timer restarted, so the next attempt follows
// one trial of the relay later, unless a fresh handshake on the device peer a
// failed remove left in place marks the peer connected first.
func (m *Manager) redialInPass(nodeID string, st *dialState, now time.Time) error {
	if err := m.redialRelay(st.peer); err != nil {
		m.logger.Warn("wireguard: endpoint switch failed",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", st.peer.Fallback,
			"error", err,
		)
		st.connected = false
		st.programmedAt = now
		return fmt.Errorf("wireguard: switch endpoint of peer %s: %w", nodeID, err)
	}
	st.onRelay(now)
	return nil
}

// SetRelayProbe sets the function endpoint selection sends the relay liveness
// probe with (see checkRelay); plexd up passes SendRelayProbe. Call it before
// RunEndpointSelection, like SetLocalPrefixes. Without it no probe goes out,
// and a relayed peer counts as failed only once its handshake goes stale.
func (m *Manager) SetRelayProbe(send func(meshIP netip.Addr) error) {
	m.sendProbe = send
}

// SendRelayProbe sends the relay liveness probe: one datagram of one zero
// byte to UDP port 9 of meshIP. The host routes it into the mesh interface,
// and WireGuard carries it to the peer as data, which the peer's WireGuard
// answers with a keepalive whether or not anything listens on the port. An
// address that is not IPv4 is refused, because mesh IPs are IPv4.
func SendRelayProbe(meshIP netip.Addr) error {
	if !meshIP.Is4() {
		return fmt.Errorf("wireguard: relay probe: mesh ip %s is not IPv4", meshIP)
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: meshIP.AsSlice(), Port: relayProbePort})
	if err != nil {
		return fmt.Errorf("wireguard: relay probe %s: %w", meshIP, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("wireguard: relay probe %s: %w", meshIP, err)
	}
	return nil
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
		"relay_probe", m.sendProbe != nil,
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
