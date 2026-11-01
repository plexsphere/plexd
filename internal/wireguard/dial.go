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
// how long an entry of a dial order is tried; each relay that ends an order is
// tried for one trial per entry before the first relay (see dialState.trial). The
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
// position in its dial order of the endpoint programmed on the device (after a
// failed relay re-dial, of the relay it tried; see redialInPass), when that
// endpoint was programmed or the peer was last seen connected, and whether a
// fresh handshake shows the peer connected.
//
// relayed records that the peer was last seen connected over one of its
// relays (see relayedOver). A relayed peer stays on its relays: when its
// connection fails, plexd dials the next relay of its set instead of the
// direct entries before them, which already failed. relayed implies
// onFallback. recreatedAt is when a relay re-dial last replaced the device
// peer; a handshake older than that belongs to the session the re-dial
// dropped. handshakeAt tells a new session from the one a pass already saw, so
// a roam that brought no handshake is recognized. A re-dial needs no reset of
// it: the peer is then not connected, and turning connected sets it.
// restoredFor limits a session to one move back (see restoreRelay). The
// remaining fields are the relay liveness probe's state (see checkRelay).
type dialState struct {
	peer         api.Peer
	idx          int
	programmedAt time.Time
	connected    bool

	relayed      bool
	recreatedAt  time.Time
	handshakeAt  time.Time // the peer's LastHandshake at the last pass that found it fresh
	restoredFor  time.Time // the LastHandshake of the session a move back was last written for
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

// onFallback reports whether the entry programmed is one of the peer's
// Fallbacks, a relay.
func (s *dialState) onFallback() bool {
	endpoint := s.endpoint()
	return endpoint != "" && slices.Contains(s.peer.Fallbacks, endpoint)
}

// firstRelay returns the position of the peer's first relay in its dial
// order, or -1 when it has no relay. The Fallbacks end the order whole (see
// dialOrder), so the first relay sits right after the direct entries.
func (s *dialState) firstRelay() int {
	if len(s.peer.Fallbacks) == 0 {
		return -1
	}
	return max(len(s.order())-len(s.peer.Fallbacks), 0)
}

// walk returns the entries a peer that is not relayed cycles through: its
// dial order up to and including its first relay, or the whole order when it
// has no relay. The standby relays are never walked: only a relayed peer
// dials them (see nextRelay).
func (s *dialState) walk() []string {
	order := s.order()
	if first := s.firstRelay(); first >= 0 {
		return order[:min(first+1, len(order))]
	}
	return order
}

// nextRelay returns the relay a relayed peer dials when the one programmed
// fails: the entry of Fallbacks after it, wrapping around to the first after
// the last, or the first when the entry programmed is not a relay. For a set
// of one it is that relay again. It returns "" for a peer without relays,
// which relayed rules out.
func (s *dialState) nextRelay() string {
	relays := s.peer.Fallbacks
	if len(relays) == 0 {
		return ""
	}
	i := slices.Index(relays, s.endpoint())
	if i < 0 {
		return relays[0]
	}
	return relays[(i+1)%len(relays)]
}

// relayedOver reports the relay stat shows the peer reached over, if any. A
// device endpoint equal to a relay that is an address names that relay,
// whatever entry is programmed: WireGuard roams a peer to the address its
// partner's initiation came from, so a peer programmed on a direct entry or on
// another relay can run over this one. A stale packet roams the device the
// same way, so this says where the device sends, not that the session runs
// there; selectEndpoints tells the two apart by the handshake. Without a
// device endpoint, the entry programmed decides. A device endpoint that
// matches no relay means WireGuard roamed to a path the peer opened directly,
// which a relay move must not cut and the probe must not judge, unless the
// entry programmed is a relay and the set holds a hostname, which cannot be
// compared: then the entry programmed decides. An address entry of such a set
// still matches first, so only a device endpoint no entry names gets there.
func (s *dialState) relayedOver(stat MeshPeerStat) (relay string, ok bool) {
	if stat.Endpoint.IsValid() {
		unmapped := func(ap netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) }
		device := unmapped(stat.Endpoint)
		hostname := false
		for _, r := range s.peer.Fallbacks {
			ap, err := netip.ParseAddrPort(r)
			if err != nil {
				hostname = true
				continue
			}
			if unmapped(ap) == device {
				return r, true
			}
		}
		if !hostname {
			return "", false
		}
	}
	if !s.onFallback() {
		return "", false
	}
	return s.endpoint(), true
}

// onRelay records that relay, one of the peer's relays, was just written on a
// fresh device peer (see Manager.redialRelay): the position is the relay's,
// the peer is not connected, its timer restarts, and the probe starts over,
// because the new device peer counts its bytes from 0. The Fallbacks end the
// order (see dialOrder), so the relay's position is found.
func (s *dialState) onRelay(now time.Time, relay string) {
	s.idx = max(slices.Index(s.order(), relay), 0)
	s.connected = false
	s.programmedAt = now
	s.recreatedAt = now
	s.rxBytes = 0
	s.rxAt = now
	s.probedAt = time.Time{}
}

// trial returns how long the entry at idx of the dial order is tried, given
// timeout, one trial. A relay, any entry of the peer's Fallbacks, is tried for
// one trial per entry before the first relay when there are any, so it is held
// as long as those entries took together. Each of two peers that dial one
// relay then spends at least half its walk on it, and their relay windows
// overlap or touch. Every relay of the set gets the same hold, so two relayed
// peers that rotate through the set keep the gap between them. Every other
// entry is tried for timeout.
func (s *dialState) trial(idx int, timeout time.Duration) time.Duration {
	order := s.order()
	if first := s.firstRelay(); first > 0 && idx < len(order) && slices.Contains(s.peer.Fallbacks, order[idx]) {
		return timeout * time.Duration(first)
	}
	return timeout
}

// relaySet returns p's relays in dial order: its fallback_endpoints when the
// pull carries any, otherwise its fallback_endpoint alone, the only relay a
// control plane that predates the set sends, and nil when it has neither.
// fallback_endpoint is not read beside a non-empty fallback_endpoints, whose
// first entry the contract makes it. The entries are not validated, because
// the contract allows a hostname there.
func relaySet(p api.SnapshotPeer) []string {
	if len(p.FallbackEndpoints) > 0 {
		return p.FallbackEndpoints
	}
	if p.FallbackEndpoint != "" {
		return []string{p.FallbackEndpoint}
	}
	return nil
}

// dialOrder returns the endpoints plexd tries for p, in order: the candidates
// on a subnet this node is also on, then p's direct endpoint when it is usable,
// then the remaining candidates, then p's relays (see relaySet). A duplicate
// keeps its first position, except that a candidate or direct endpoint equal
// to a relay is left out: the relays end the order whole and in set order, as
// they do in the other side's order for this node. An empty relay entry is
// skipped. relays counts the entries that end the order as relays, and
// dropped the candidates refused because they are not usable by the rules
// usableDirectEndpoint applies to the direct endpoint.
//
// A candidate is on-link when an entry of local of the same family contains
// it. A host prefix (/32 or /128) makes nothing on-link: it says nothing about
// the addresses next to it.
func dialOrder(p api.SnapshotPeer, local []netip.Prefix, mesh netip.Prefix) (order []string, relays, dropped int) {
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

	set := relaySet(p)
	seen := make(map[string]bool)
	add := func(endpoint string) bool {
		if endpoint == "" || seen[endpoint] {
			return false
		}
		seen[endpoint] = true
		order = append(order, endpoint)
		return true
	}
	addDirect := func(endpoint string) {
		if !slices.Contains(set, endpoint) {
			add(endpoint)
		}
	}
	for _, c := range onLink {
		addDirect(c)
	}
	if direct, ok := usableDirectEndpoint(p.Endpoint, mesh); ok {
		addDirect(direct)
	}
	for _, c := range offLink {
		addDirect(c)
	}
	for _, r := range set {
		if add(r) {
			relays++
		}
	}
	return order, relays, dropped
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
// so WireGuard's roaming stays in effect, with the two exceptions below, a
// re-dial after an unanswered probe and a move back. A peer that is not
// connected is moved to the next entry of its walk (see dialState.walk) once
// the current one has been tried for its trial (see dialState.trial): the
// keepalive interval plus endpointTrialMargin, or for a relay that follows n
// direct entries, n times that. The switch is logged with the trial of the
// entry it programs.
//
// A relayed peer (see dialState) never moves to a direct entry. While it is
// connected, checkRelay probes it once it falls silent. When its handshake
// goes stale, or the probe goes unanswered, the next relay of its set is
// dialed on a fresh device peer, and the next one again each time a relay's
// trial passes without a handshake. A connected relayed peer the device
// reports at another relay of its set follows that relay when a new handshake
// came with the roam. Without one it is moved back to the entry programmed,
// once per session, and a second roam in the session is followed (see
// restoreRelay).
//
// The device is read before mu is taken. A read error, ErrPeerStatsUnsupported
// included, is returned unchanged with no state touched. A failed switch of
// the walk is logged, leaves the peer on the entry still programmed, and is
// joined into the returned error; its next attempt waits that entry's full
// trial again. A failed relay re-dial is logged and joined the same way, but
// moves the peer's position to the relay it tried, so the next attempt, one
// relay hold later, dials the relay after it (see redialInPass). A failed move
// back is logged and joined too, and records nothing, so the next pass writes
// again.
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
			st.handshakeAt = stat.LastHandshake
			relay, relayed := st.relayedOver(stat)
			st.relayed = relayed
			if relayed {
				st.idx = max(slices.Index(st.order(), relay), 0)
			}
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
			relay, relayed := st.relayedOver(stat)
			// The device changes LastHandshake only when a handshake completes,
			// so any change is a new session, even an older value after the
			// wall clock stepped back.
			sameSession := stat.LastHandshake.Equal(st.handshakeAt)
			st.handshakeAt = stat.LastHandshake
			// A relay drops every packet of a session whose handshake it did
			// not forward (see redialRelay), so a roam between relays with no
			// new handshake almost always means a stale packet moved the
			// device, and the session still runs over the entry programmed. A
			// pass that reads the device in the round trip before a partner's
			// initiation completes sees the same thing: its write costs at most
			// a packet, and the next pass follows the new handshake. A position
			// can be wrong too, when the stale packet landed within one pass of
			// the handshake and the pass took its relay for the session's. The
			// partner's next packet then heals the device, and a move back
			// would undo that on every pass until the next handshake. So a
			// session gets one move back, and a second roam falls through to
			// the follow below, which heals the position.
			if sameSession && st.relayed && relayed && relay != st.endpoint() && !stat.LastHandshake.Equal(st.restoredFor) {
				if err := m.restoreRelay(nodeID, st, relay); err != nil {
					errs = append(errs, err)
					continue
				}
				st.restoredFor = stat.LastHandshake
				continue
			}
			if relayed && (!st.relayed || relay != st.endpoint()) {
				// Back on a relay, or on another one after a new handshake or
				// a second roam in the session: the silence window starts now.
				st.idx = max(slices.Index(st.order(), relay), 0)
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
				next := st.nextRelay()
				m.logger.Info("wireguard: relayed peer handshake went stale, dialing the relay again",
					"component", "wireguard",
					"peer_id", nodeID,
					"from", st.endpoint(),
					"endpoint", next,
				)
				if err := m.redialInPass(nodeID, st, next, now); err != nil {
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
			next := st.nextRelay()
			m.logger.Info("wireguard: still no handshake over the relay, dialing it again",
				"component", "wireguard",
				"peer_id", nodeID,
				"from", st.endpoint(),
				"endpoint", next,
				"trial", trial,
			)
			if err := m.redialInPass(nodeID, st, next, now); err != nil {
				errs = append(errs, err)
			}
			continue
		}

		// A peer that lost its relayed mark while on a standby sits beyond its
		// walk, and goes back to the walk's first entry.
		walk := st.walk()
		stranded := st.idx >= len(walk)
		if len(walk) == 0 || (len(walk) < 2 && !stranded) || now.Sub(st.programmedAt) < st.trial(st.idx, timeout) {
			continue
		}
		next := 0
		if !stranded {
			next = (st.idx + 1) % len(walk)
		}
		st.programmedAt = now
		peerCfg, err := m.peerConfig(st.peer, walk[next])
		if err == nil {
			err = m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg)
		}
		if err != nil {
			m.logger.Warn("wireguard: endpoint switch failed",
				"component", "wireguard",
				"peer_id", nodeID,
				"endpoint", walk[next],
				"error", err,
			)
			errs = append(errs, fmt.Errorf("wireguard: switch endpoint of peer %s: %w", nodeID, err))
			continue
		}
		st.idx = next
		m.logger.Info("wireguard: trying next endpoint candidate",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", walk[next],
			"attempt", next+1,
			"of", len(walk),
			"trial", st.trial(next, timeout),
		)
	}
	return errors.Join(errs...)
}

// restoreRelay writes the entry programmed back to the device of a relayed
// peer that roamed, with no new handshake, to roamed, another of its relays.
// It does not remove the device peer: the session over the entry programmed is
// valid, and a re-dial would cut it. The position, connected, relayed and the
// probe's state stay as they are, because the session never left that entry. A
// failed write is logged and wrapped like a failed switch of the walk. Callers
// hold m.mu.
func (m *Manager) restoreRelay(nodeID string, st *dialState, roamed string) error {
	endpoint := st.endpoint()
	peerCfg, err := m.peerConfig(st.peer, endpoint)
	if err == nil {
		err = m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg)
	}
	if err != nil {
		m.logger.Warn("wireguard: endpoint switch failed",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", endpoint,
			"error", err,
		)
		return fmt.Errorf("wireguard: switch endpoint of peer %s: %w", nodeID, err)
	}
	m.logger.Info("wireguard: relayed peer roamed to a relay its session does not run over, moving it back",
		"component", "wireguard",
		"peer_id", nodeID,
		"from", roamed,
		"endpoint", endpoint,
	)
	return nil
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
// still not moved relayProbeTimeout later dials the next relay of the peer's
// set, which is the same relay for a set of one. A failed
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
		next := st.nextRelay()
		m.logger.Info("wireguard: relayed peer did not answer the probe, dialing the relay again",
			"component", "wireguard",
			"peer_id", nodeID,
			"from", st.endpoint(),
			"endpoint", next,
			"silent_for", now.Sub(st.rxAt),
		)
		return m.redialInPass(nodeID, st, next, now)
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

// redialInPass dials relay, one of st's relays, on a fresh device peer during
// a pass. A failed attempt is logged and wrapped like a failed switch. It still
// moves the peer's position to relay and leaves it not connected with its
// timer restarted, so the next attempt, one trial of the relay later, dials
// the relay after it: a relay the device keeps refusing, such as a hostname
// that no longer resolves, must not hold the peer back from the rest of its
// set. A fresh handshake on the device peer a failed remove left in place
// marks the peer connected again first, over the relay it came from (see
// dialState.relayedOver).
func (m *Manager) redialInPass(nodeID string, st *dialState, relay string, now time.Time) error {
	if err := m.redialRelay(st.peer, relay); err != nil {
		m.logger.Warn("wireguard: endpoint switch failed",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", relay,
			"error", err,
		)
		st.idx = max(slices.Index(st.order(), relay), 0)
		st.connected = false
		st.programmedAt = now
		return fmt.Errorf("wireguard: switch endpoint of peer %s: %w", nodeID, err)
	}
	st.onRelay(now, relay)
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
