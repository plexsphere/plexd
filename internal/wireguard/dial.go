package wireguard

import (
	"cmp"
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

// MinFailureDetection and MaxFailureDetection bound the failure-detection
// time SetFailureDetection holds: a positive value outside them is clamped to
// the nearer one. The floor is the control plane's. The ceiling is
// connectedHandshakeAge: past that age the stale-handshake branch re-dials a
// relayed peer whatever the value says.
const (
	MinFailureDetection = 5 * time.Second
	MaxFailureDetection = connectedHandshakeAge
)

// detectPass returns the pass and probe interval under the failure-detection
// time d: d/15 truncated to whole seconds, at least 1 s and at most
// EndpointSelectionInterval.
func detectPass(d time.Duration) time.Duration {
	return min(max((d/15).Truncate(time.Second), time.Second), EndpointSelectionInterval)
}

// detectSilence returns how long a relayed peer may stay silent under the
// failure-detection time d before watchRelay dials the next relay: d less one
// pass, because a pass starts the silence window up to one pass after the
// packet it counts arrived. The bridge watch of shared subnets judges the
// path to a bridge against it too (see watchBridges).
func detectSilence(d time.Duration) time.Duration {
	return d - detectPass(d)
}

// relayProbePort is the UDP port SendRelayProbe sends to, the discard port.
// Nothing has to listen there: the peer's WireGuard answers the data packet
// that carries the datagram, whatever the host behind it does with it. The
// policy backends let the node send to this port over the mesh interface
// without a rule (policy.RelayProbePort), so the probe leaves under any policy.
const relayProbePort = 9

// directRetryTimeout is how long a direct retry tries one direct entry of a
// relayed peer (see Manager.retryDirect). The fresh device peer sends its
// handshake initiation at once and again after WireGuard's RekeyTimeout of
// 5 s, so the window holds two initiations.
const directRetryTimeout = 10 * time.Second

// directRetryMemory is how long a direct entry that left a relayed peer's dial
// order, or failed a direct retry, starts no retry and is left out of one. The
// control plane leaves a peer's direct endpoint out while it has no fresh
// observation and lists only unexpired candidates, so without the memory
// every stale-and-back cycle of a peer's reports would cut its relayed pairs.
// It also keeps a second pull within the window from trying again what the
// first retry just tried.
const directRetryMemory = 10 * time.Minute

// localNetworksInterval is how often, at most, endpoint selection reads the
// local prefixes to find a network that makes a relayed peer's direct entry
// on-link (see Manager.localNetworksChanged). A read every 30 s finds a new
// network soon enough for a pair that would otherwise wait for a restart, on
// every platform and without a watcher for interface changes.
const localNetworksInterval = 30 * time.Second

// dialState is one peer's endpoint selection: the peer as last written, the
// position in its dial order of the endpoint programmed on the device (after a
// failed relay re-dial, of the relay it tried; see redialInPass), when that
// endpoint was programmed or the peer was last seen connected, and whether a
// fresh handshake shows the peer connected.
//
// relayed records that the peer was last seen connected over one of its
// relays (see relayedOver). A relayed peer stays on its relays: when its
// connection fails, plexd dials the next relay of its set instead of the
// direct entries before them, which already failed, until a direct retry
// tries them again (see Manager.retryDirect). relayed implies onFallback.
// recreatedAt is when a re-dial, of a relay or of a direct retry's entry,
// last replaced the device peer; a handshake older than that belongs to the
// session the re-dial dropped. handshakeAt tells a new session from the one a
// pass already saw, so a roam that brought no handshake is recognized. A
// re-dial needs no reset of it: the peer is then not connected, and turning
// connected sets it.
// restoredFor limits a session to one move back (see restoreRelay). The
// probe fields are the relay liveness probe's state (see checkRelay, and
// watchRelay while a failure-detection time is held).
//
// aliveAt, watchRx and echoAt are the bridge watch's state for a bridge of a
// shared subnet (see Manager.watchBridges): the last pass that saw the path
// alive, the device's RxBytes for the peer at the last pass, and when the
// last stimulus went out, zero when none went out since the window last
// restarted (see restartWatch). They stay zero for a peer that was never a
// bridge.
//
// The last three fields are the direct retry's state. retry holds the direct
// entries a running retry tries after the one programmed, in order, and
// retryRelay the relay it dials when no entry answers; retryRelay is
// non-empty exactly while a retry runs. While a retry runs, the peer is not
// connected and not relayed, and idx is the position of the entry tried.
// tried holds the direct entries that left the peer's order or failed a
// retry, with the time, and stays nil until the first one is recorded.
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
	probedAt     time.Time // when the outstanding probe went out, zero when none is; while a failure-detection time is held, when the last probe was sent
	probeFailing bool      // the last probe send failed

	aliveAt time.Time // the bridge watch's last pass that saw the path alive
	watchRx uint64    // the device's RxBytes for the peer at the bridge watch's last pass
	echoAt  time.Time // when the bridge watch's last stimulus went out

	retry      []string
	retryRelay string
	tried      map[string]time.Time
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
// fresh device peer (see Manager.redial): the position is the relay's,
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

// direct returns the peer's direct entries: its dial order before the first
// relay, or the whole order for a peer without relays.
func (s *dialState) direct() []string {
	order := s.order()
	if first := s.firstRelay(); first >= 0 {
		return order[:first]
	}
	return order
}

// retrying reports whether a direct retry runs for the peer.
func (s *dialState) retrying() bool {
	return s.retryRelay != ""
}

// remembered reports whether tried holds entry from less than
// directRetryMemory before now.
func (s *dialState) remembered(entry string, now time.Time) bool {
	at, ok := s.tried[entry]
	return ok && now.Sub(at) < directRetryMemory
}

// remember drops every entry of tried recorded directRetryMemory or more
// before now, then records entry at now.
func (s *dialState) remember(entry string, now time.Time) {
	maps.DeleteFunc(s.tried, func(_ string, at time.Time) bool { return now.Sub(at) >= directRetryMemory })
	if s.tried == nil {
		s.tried = make(map[string]time.Time)
	}
	s.tried[entry] = now
}

// untried returns the direct entries that are not remembered at now, in
// order.
func (s *dialState) untried(now time.Time) []string {
	return slices.DeleteFunc(slices.Clone(s.direct()), func(e string) bool { return s.remembered(e, now) })
}

// triedAfter returns the memory an update to peer leaves st with: st.tried
// without the entries recorded directRetryMemory or more before now, plus
// every direct entry of st that the direct entries of peer no longer hold,
// recorded at now. It returns nil when that is empty.
func triedAfter(st *dialState, peer api.Peer, now time.Time) map[string]time.Time {
	tried := maps.Clone(st.tried)
	maps.DeleteFunc(tried, func(_ string, at time.Time) bool { return now.Sub(at) >= directRetryMemory })
	listed := (&dialState{peer: peer}).direct()
	for _, e := range st.direct() {
		if slices.Contains(listed, e) {
			continue
		}
		if tried == nil {
			tried = make(map[string]time.Time)
		}
		tried[e] = now
	}
	if len(tried) == 0 {
		return nil
	}
	return tried
}

// relayAfter returns the relay a direct retry that an update to peer starts or
// continues ends on: the relay a running retry ends on, or the relay st has
// programmed when none runs, unless the update takes that relay away by the
// rule of relayMoved, which makes it peer's first relay. peer names at least
// one relay, and so does st.peer.
func relayAfter(st *dialState, peer api.Peer) string {
	relay := st.retryRelay
	if relay == "" {
		relay = st.endpoint()
	}
	first := peer.Fallbacks[0]
	if !slices.Contains(peer.Fallbacks, relay) || (first != st.peer.Fallbacks[0] && first != relay) {
		return first
	}
	return relay
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

// onLinkFirst returns entries with those on-link with local (see isOnLink)
// moved to the front, each group in its order. An entry that is not an
// address and port, such as a hostname, is not on-link.
func onLinkFirst(entries []string, local []netip.Prefix) []string {
	var onLink, offLink []string
	for _, e := range entries {
		if ap, err := netip.ParseAddrPort(e); err == nil && isOnLink(ap.Addr(), local) {
			onLink = append(onLink, e)
		} else {
			offLink = append(offLink, e)
		}
	}
	return append(onLink, offLink...)
}

// networksOf returns the networks prefixes name: each prefix shorter than a
// host prefix, masked, sorted by address and then by length, without
// duplicates. A host prefix (/32 or /128) is left out, because it makes
// nothing on-link (see isOnLink). nil and an empty slice give an empty
// result.
func networksOf(prefixes []netip.Prefix) []netip.Prefix {
	nets := []netip.Prefix{}
	for _, p := range prefixes {
		if p.IsValid() && p.Bits() < p.Addr().BitLen() {
			nets = append(nets, p.Masked())
		}
	}
	slices.SortFunc(nets, comparePrefixes)
	return slices.Compact(nets)
}

// comparePrefixes orders two prefixes by address and then by length, the
// order of networksOf and of the shared subnets a peer holds (see
// Manager.sharedHeldLocked).
func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(a.Bits(), b.Bits())
}

// localNetworksChanged reads the local networks through localPrefixes, at
// most once per localNetworksInterval, and reports whether they changed
// since the last successful read, with the networks before and after. It
// compares networks, not addresses (see networksOf), so a new address inside
// a known network is no change. The first successful read is the baseline
// and reports no change. A failed read logs wireguard: read local networks
// failed, at Warn the first time and at Debug while the reads keep failing,
// keeps the networks it had and reports no change; the next read follows one
// interval later. Only the endpoint selection goroutine calls it.
func (m *Manager) localNetworksChanged(now time.Time) (old, cur []netip.Prefix, changed bool) {
	if !m.localAt.IsZero() && now.Sub(m.localAt) < localNetworksInterval {
		return nil, nil, false
	}
	m.localAt = now
	prefixes, err := m.localPrefixes()
	if err != nil {
		level := slog.LevelWarn
		if m.localFailing {
			level = slog.LevelDebug
		}
		m.logger.Log(context.Background(), level, "wireguard: read local networks failed",
			"component", "wireguard",
			"error", err,
		)
		m.localFailing = true
		return nil, nil, false
	}
	m.localFailing = false
	cur = networksOf(prefixes)
	if !m.localKnown {
		m.localKnown = true
		m.localNets = cur
		return nil, nil, false
	}
	if slices.Equal(cur, m.localNets) {
		return nil, nil, false
	}
	m.logger.Debug("wireguard: local networks changed",
		"component", "wireguard",
		"networks", cur,
	)
	old, m.localNets = m.localNets, cur
	return old, cur, true
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
// A relayed peer (see dialState) moves to a direct entry only in a direct
// retry. While it is connected, checkRelay probes it once it falls silent, or,
// while a failure-detection time is held (see SetFailureDetection), watchRelay
// probes it on every pass. When its handshake goes stale, or the probe goes
// unanswered, or under a failure-detection time the peer stays silent past
// it, the next relay of its set is dialed on a fresh device peer, and the
// next one again each time a relay's trial passes without a handshake. A
// connected relayed peer the device reports at another relay of its set
// follows that relay when a new handshake came with the roam. Without one it
// is moved back to the entry programmed, once per session, and a second roam
// in the session is followed (see restoreRelay).
//
// A direct retry (see Manager.retryDirect), which UpdatePeer starts when a
// pull adds a direct entry to a relayed peer, holds each of its entries for
// directRetryTimeout. When that passes without a handshake, the pass writes
// the next entry on a fresh device peer, and after the last one dials the
// relay the retry ends on (see stepRetry). A handshake ends the retry, and
// the device endpoint decides, as for any peer that turns connected, whether
// the peer is relayed. The pass starts a retry too, for a relayed peer or one
// in a retry, when the local networks changed so that a direct entry of the
// peer that is not remembered became on-link (see retryOnLink).
//
// After the peers, the pass watches the bridges of the shared subnets, and
// moves a subnet off a bridge whose path has been dead for the
// failure-detection time to the next live bridge of its entry (see
// watchBridges). A failed move is joined into the returned error.
//
// The device is read before mu is taken. A read error, ErrPeerStatsUnsupported
// included, is returned unchanged with no state touched, no probe sent and no
// subnet moved. The round-trip probe's socket, which the bridge watch writes
// its requests on, is read under the probe's mutex right after the device and
// before mu is taken, so the two mutexes are never held together. The local
// networks are read after the device and before mu is taken, at most once per
// localNetworksInterval (see localNetworksChanged). A failed switch of
// the walk is logged, leaves the peer on the entry still programmed, and is
// joined into the returned error; its next attempt waits that entry's full
// trial again. A failed relay re-dial is logged and joined the same way, but
// moves the peer's position to the relay it tried, so the next attempt, one
// relay hold later, dials the relay after it (see redialInPass). A failed move
// back is logged and joined too, and records nothing, so the next pass writes
// again. A failed write of a retry's entry is logged and joined the same way,
// and moves the position to that entry, so the next step, one window later,
// tries the entry after it.
func (m *Manager) selectEndpoints() error {
	stats, err := m.MeshPeerStats()
	if err != nil {
		return err
	}
	echo := m.rtt.socket()
	old, cur, changed := m.localNetworksChanged(m.now())

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	timeout := m.cfg.KeepaliveInterval() + endpointTrialMargin
	byID := make(map[string]MeshPeerStat, len(stats))
	fresh := make(map[string]MeshPeerStat, len(stats))
	for _, s := range stats {
		byID[s.NodeID] = s
		if !s.LastHandshake.IsZero() && now.Sub(s.LastHandshake) < connectedHandshakeAge {
			fresh[s.NodeID] = s
		}
	}

	var errs []error
	for _, nodeID := range slices.Sorted(maps.Keys(m.dial)) {
		st := m.dial[nodeID]
		if changed && (st.relayed || st.retrying()) {
			attempted, err := m.retryOnLink(nodeID, st, old, cur, now)
			if err != nil {
				errs = append(errs, err)
			}
			if attempted {
				continue
			}
		}
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
			st.retry = nil
			st.retryRelay = ""
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
			// not forward (see redial), so a roam between relays with no
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
				var err error
				if m.detectAfter > 0 {
					err = m.watchRelay(nodeID, st, stat, now)
				} else {
					err = m.checkRelay(nodeID, st, stat, now, timeout)
				}
				if err != nil {
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

		if st.retrying() {
			if err := m.stepRetry(nodeID, st, now); err != nil {
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

	if err := m.watchBridges(byID, echo, now); err != nil {
		errs = append(errs, err)
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

// retryOnLink starts a direct retry for st, a relayed peer or one in a
// retry, when the local networks changed from old to cur so that a direct
// entry of st that is not remembered is on-link with cur and was not with
// old. The retry tries every direct entry that is not remembered, those
// on-link with cur first, each group in the order st holds, and ends on the
// relay a running retry ends on, or on the relay st has programmed. It
// reports whether it wrote. A failed write is logged and wrapped like a
// failed switch and leaves st as it was, and this change starts no retry
// again. Callers hold m.mu.
func (m *Manager) retryOnLink(nodeID string, st *dialState, old, cur []netip.Prefix, now time.Time) (bool, error) {
	newlyOnLink := func(e string) bool {
		ap, err := netip.ParseAddrPort(e)
		return err == nil && isOnLink(ap.Addr(), cur) && !isOnLink(ap.Addr(), old) && !st.remembered(e, now)
	}
	if !slices.ContainsFunc(st.direct(), newlyOnLink) {
		return false, nil
	}
	entries := onLinkFirst(st.untried(now), cur)
	relay := st.retryRelay
	if relay == "" {
		relay = st.endpoint()
	}
	next, err := m.retryDirect(st.peer, entries, relay, st.tried, now)
	if err != nil {
		m.logger.Warn("wireguard: endpoint switch failed",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", entries[0],
			"error", err,
		)
		return true, fmt.Errorf("wireguard: switch endpoint of peer %s: %w", nodeID, err)
	}
	m.dial[nodeID] = next
	m.logger.Info("wireguard: trying the direct endpoints again",
		"component", "wireguard",
		"peer_id", nodeID,
		"reason", "local_networks",
		"endpoint", entries[0],
		"entries", len(entries),
		"relay", relay,
	)
	return true, nil
}

// stepRetry runs one pass of a direct retry for st (see
// Manager.retryDirect). While the entry programmed has been tried for less
// than directRetryTimeout it does nothing. Then it remembers that entry as
// failed and writes the next entry of the retry on a fresh device peer, or,
// after the last one, dials the relay the retry ends on, which leaves the
// peer relayed and not connected as after any relay re-dial. A failed write
// of an entry is logged and wrapped like a failed switch, and still moves the
// position to that entry and restarts its window, so the step after it, one
// window later, tries the entry after it. Callers hold m.mu.
func (m *Manager) stepRetry(nodeID string, st *dialState, now time.Time) error {
	if now.Sub(st.programmedAt) < directRetryTimeout {
		return nil
	}
	st.remember(st.endpoint(), now)
	if len(st.retry) == 0 {
		relay := st.retryRelay
		st.retryRelay = ""
		st.relayed = true
		m.logger.Info("wireguard: no direct endpoint answered, dialing the relay again",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", relay,
		)
		return m.redialInPass(nodeID, st, relay, now)
	}
	entry := st.retry[0]
	st.retry = st.retry[1:]
	m.logger.Info("wireguard: direct retry, trying the next endpoint",
		"component", "wireguard",
		"peer_id", nodeID,
		"endpoint", entry,
		"remaining", len(st.retry),
	)
	st.idx = max(slices.Index(st.order(), entry), 0)
	st.programmedAt = now
	if err := m.redial(st.peer, entry); err != nil {
		m.logger.Warn("wireguard: endpoint switch failed",
			"component", "wireguard",
			"peer_id", nodeID,
			"endpoint", entry,
			"error", err,
		)
		return fmt.Errorf("wireguard: switch endpoint of peer %s: %w", nodeID, err)
	}
	st.recreatedAt = now
	return nil
}

// checkRelay runs the relay liveness probe for a relayed peer whose handshake
// is fresh, on a node that holds no failure-detection time (see watchRelay
// for one that does). A fresh handshake does not prove the relay still
// forwards: the session stays valid for up to 180 s after the relay stopped.
// Nor does a device counter that stands still prove it stopped, because a
// received keepalive restarts WireGuard's own keepalive timer, so on an idle
// tunnel one side can receive nothing until the next rekey. A data packet is
// different: WireGuard answers one with a keepalive within 10 s when it has
// nothing else to send.
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
		m.probeSendFailed(nodeID, st, ip, err)
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

// watchRelay watches a relayed peer whose handshake is fresh against the
// failure-detection time m holds (see SetFailureDetection), in place of
// checkRelay. It applies these rules in order:
//
//   - RxBytes moved: it records the counter and restarts the silence window,
//     and goes on to the rules below.
//   - No sender, or a mesh IP that does not parse or lies outside the mesh
//     prefix: it returns nil. Without a probe there is no verdict, and the
//     peer counts as failed once its handshake goes stale, as under
//     checkRelay.
//   - Silent for detectSilence of the time or longer: it dials the next relay
//     of the peer's set, which is the same relay for a set of one.
//   - No probe sent yet, or the last one sent half a pass or more ago: it
//     sends the probe.
//
// The probe goes out whether or not the peer is silent. Two nodes that both
// watch the pair this way then count each other's probes on every pass,
// where a probe sent only into silence would leave one side waiting for its
// partner's WireGuard to answer within its 10 s KeepaliveTimeout. A peer that
// sends nothing on its own answers a probe per pass at most 10 s plus one
// pass apart, which stays inside the silence window from 15 s up. The half
// pass keeps a pass that runs a few milliseconds early from skipping its
// probe, and holds a caller that ticks faster than detectPass to two probes
// per pass. A sent probe logs nothing. A failed send logs as under
// checkRelay and restarts the silence window, so no verdict follows a probe
// that never left. Callers hold m.mu; the probe is sent under it for the
// reason checkRelay gives.
func (m *Manager) watchRelay(nodeID string, st *dialState, stat MeshPeerStat, now time.Time) error {
	d := m.detectAfter
	if stat.RxBytes != st.rxBytes {
		st.rxBytes = stat.RxBytes
		st.rxAt = now
	}
	if m.sendProbe == nil {
		return nil
	}
	ip, err := netip.ParseAddr(st.peer.MeshIP)
	if err != nil || !m.meshPrefix.Contains(ip) {
		return nil
	}
	if silent := now.Sub(st.rxAt); silent >= detectSilence(d) {
		next := st.nextRelay()
		m.logger.Info("wireguard: relayed peer silent past the failure detection time, dialing the relay again",
			"component", "wireguard",
			"peer_id", nodeID,
			"from", st.endpoint(),
			"endpoint", next,
			"silent_for", silent,
			"detect_after", d,
		)
		return m.redialInPass(nodeID, st, next, now)
	}
	if !st.probedAt.IsZero() && now.Sub(st.probedAt) < detectPass(d)/2 {
		return nil
	}
	if err := m.sendProbe(ip); err != nil {
		m.probeSendFailed(nodeID, st, ip, err)
		st.rxAt = now
		st.probedAt = now
		return nil
	}
	st.probeFailing = false
	st.probedAt = now
	return nil
}

// probeSendFailed logs a relay probe to ip that the sender refused with err,
// at Warn the first time and at Debug while the sends keep failing, and
// records that the last send failed.
func (m *Manager) probeSendFailed(nodeID string, st *dialState, ip netip.Addr, err error) {
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
	if err := m.redial(st.peer, relay); err != nil {
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
// probe with (see checkRelay, and watchRelay under a failure-detection time);
// plexd up passes SendRelayProbe. Call it before RunEndpointSelection, like
// SetLocalPrefixes. Without it no probe goes out, and a relayed peer counts as
// failed only once its handshake goes stale, whatever failure-detection time
// is held. The bridge watch of shared subnets sends the same probe to a
// bridge that answers no round-trip probe (see watchBridges); without a
// sender, the path to such a bridge counts as dead only once its handshake
// goes stale.
func (m *Manager) SetRelayProbe(send func(meshIP netip.Addr) error) {
	m.sendProbe = send
}

// SetFailureDetection sets the failure-detection time, how long a relayed
// peer may stay silent before endpoint selection dials the next relay of its
// set (see watchRelay), and how long the path to the bridge of a shared
// subnet may stay dead before endpoint selection moves the subnet to the next
// live bridge of its entry (see watchBridges). It returns the value in force
// and whether it changed. A value of zero or less is ignored, and any other
// is clamped to MinFailureDetection and MaxFailureDetection. While a value is
// held, each pass watches relayed peers with watchRelay instead of
// checkRelay, and the bridges of the shared subnets with watchBridges, and
// RunEndpointSelection runs a pass every detectPass of the value, or at its
// own interval when that is shorter (see passInterval). While none is held,
// no bridge is watched and no subnet moves on its own.
//
// A change restarts the silence window of every relayed peer and the window
// of every bridge of a shared subnet, so no peer is judged against a window
// it did not start under, and logs wireguard: failure detection time set with
// the new value, the previous one (0s when none was held) and the pass
// interval it gives. The value is not persisted: the first pull after a start
// delivers it again.
func (m *Manager) SetFailureDetection(detectAfter time.Duration) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if detectAfter <= 0 {
		return m.detectAfter, false
	}
	detectAfter = min(max(detectAfter, MinFailureDetection), MaxFailureDetection)
	if detectAfter == m.detectAfter {
		return detectAfter, false
	}
	previous := m.detectAfter
	m.detectAfter = detectAfter
	now := m.now()
	for _, st := range m.dial {
		if st.relayed {
			st.rxAt = now
			st.probedAt = time.Time{}
			st.probeFailing = false
		}
	}
	for id := range m.watchedLocked() {
		if st, ok := m.dial[id]; ok {
			st.restartWatch(now)
		}
	}
	m.logger.Info("wireguard: failure detection time set",
		"component", "wireguard",
		"detect_after", detectAfter,
		"previous", previous,
		"pass", detectPass(detectAfter),
	)
	return detectAfter, true
}

// FailureDetection returns the failure-detection time m holds, and false while
// it holds none.
func (m *Manager) FailureDetection() (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.detectAfter, m.detectAfter > 0
}

// passInterval returns the interval RunEndpointSelection, started with
// interval, runs its passes at: interval while no failure-detection time is
// held, and the shorter of interval and detectPass of the time otherwise.
func (m *Manager) passInterval(interval time.Duration) time.Duration {
	d, held := m.FailureDetection()
	if !held {
		return interval
	}
	return min(interval, detectPass(d))
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
// then returns nil. While a failure-detection time is held, a pass runs every
// passInterval instead. The loop reads it after every pass and resets its
// ticker when it changed, so a new value takes effect at most one pass of the
// old interval late.
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

	pass := m.passInterval(interval)
	ticker := time.NewTicker(pass)
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
		if next := m.passInterval(interval); next != pass {
			pass = next
			ticker.Reset(pass)
		}
	}
}
