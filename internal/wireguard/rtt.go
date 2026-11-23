package wireguard

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/ifbind"
)

// RTTProbePort is the UDP port of the round-trip probe. Every plexd holds one
// socket on this port of its mesh address, which sends the node's probes and
// answers its peers' probes, so a probe and its answer both travel from this
// port to this port. It lies above 1023, so plexd binds it without
// CAP_NET_BIND_SERVICE, and below 32768, outside Linux's ephemeral range and
// the mesh ports of the mesh source rewrite. The policy backends pass UDP to
// this port over the mesh interface without a rule (policy.RTTProbePort), so
// a probe and its answer pass under any policy. The backends cannot import
// this package, so TestRTTProbePortIsPolicyExempt keeps the two constants in
// step.
const RTTProbePort = 7911

// DefaultRTTProbeInterval is the interval RunRTTProbe runs a round at when it
// is given none, the default heartbeat interval.
const DefaultRTTProbeInterval = 30 * time.Second

// rttProbeTimeout is how long a probe's answer may take: a later answer does
// not count.
const rttProbeTimeout = 5 * time.Second

// rttProbeGap is the wait between two sends of one round, so a round to many
// peers does not send its probes in one burst.
const rttProbeGap = 5 * time.Millisecond

// rttMaxUnanswered is how many probes in a row a peer may leave unanswered
// before its value is dropped.
//
// DECISION: a node reports the latest value it measured and keeps it through
// two unanswered probes, instead of the minimum over a window of probes. One
// probe per interval gives a window too few samples to smooth anything, and
// the latest value follows a path that got slower at once. A single lost
// datagram then does not clear the value the control plane stores, and a peer
// that stopped answering loses its value after three intervals.
const rttMaxUnanswered = 3

// The round-trip probe's datagram is rttDatagramLen bytes: bytes 0 to 3 the
// ASCII magic rttMagic, byte 4 the version rttVersion, byte 5 the kind
// (rttKindRequest or rttKindReply), bytes 6 and 7 zero, and bytes 8 to 15 a
// nonce from crypto/rand.
const (
	rttDatagramLen = 16
	rttMagic       = "PXRT"
	rttVersion     = 1
	rttKindRequest = 1
	rttKindReply   = 2
)

// rttMaxReadErrors is how many reads in a row may fail before the reader
// closes the socket. The next round then listens again.
const rttMaxReadErrors = 10

// rttReadBufferLen is the size of the reader's buffer. It holds the largest
// UDP payload, so a datagram of any length reads whole and is dropped by its
// length. Windows fails a read whose datagram does not fit the buffer
// (WSAEMSGSIZE), and a smaller buffer would count every longer datagram
// toward rttMaxReadErrors there.
const rttReadBufferLen = 1 << 16

// rttTable is the round-trip probe's state, per node ID. Its mutex is never
// held together with Manager.mu: a round copies what it needs out of the dial
// states under Manager.mu and releases it before it touches the table.
//
// Only the RunRTTProbe goroutine adds and deletes entries. The reader changes
// the fields of entries that exist and MeshPeerStats reads them, both under
// mu, so the round may keep a pointer to an entry across a release of mu.
type rttTable struct {
	mu sync.Mutex
	// peers is the state of each peer the last round took.
	peers map[string]*rttEntry
	// byIP maps the mesh IP of each peer the last round took to its node ID,
	// for the reader to find the peer a reply comes from.
	byIP map[netip.Addr]string
}

// rttEntry is one peer's round-trip probe state.
type rttEntry struct {
	// value is the latest round-trip time measured, zero when the peer holds
	// none, and over the device endpoint it was measured over.
	value time.Duration
	over  netip.AddrPort
	// unanswered is how many probes in a row went unanswered.
	unanswered int
	// probe is the outstanding probe, the zero rttProbe when none is.
	probe rttProbe
	// sendFailing records that the last send to the peer failed.
	sendFailing bool
}

// rttProbe is an outstanding probe: its nonce, the instant it was sent, the
// device endpoint at that instant, and the mesh IP it went to. sent is false
// in the zero rttProbe, which stands for none.
type rttProbe struct {
	sent     bool
	nonce    [8]byte
	sentAt   time.Time
	endpoint netip.AddrPort
	meshIP   netip.Addr
}

// entry returns the entry of nodeID, adding an empty one when there is none.
// Callers hold t.mu.
func (t *rttTable) entry(nodeID string) *rttEntry {
	if t.peers == nil {
		t.peers = make(map[string]*rttEntry)
	}
	e, ok := t.peers[nodeID]
	if !ok {
		e = &rttEntry{}
		t.peers[nodeID] = e
	}
	return e
}

// miss counts one unanswered probe and drops the value once rttMaxUnanswered
// probes in a row went unanswered.
func (e *rttEntry) miss() {
	e.unanswered++
	if e.unanswered >= rttMaxUnanswered {
		e.value = 0
	}
}

// value returns the value nodeID holds, zero when it holds none. Callers hold
// t.mu.
func (t *rttTable) value(nodeID string) time.Duration {
	if e, ok := t.peers[nodeID]; ok {
		return e.value
	}
	return 0
}

// retain deletes the entry of every node ID that is not among targets and
// rebuilds the mesh IP index from targets.
func (t *rttTable) retain(targets []rttTarget) {
	t.mu.Lock()
	defer t.mu.Unlock()
	taken := make(map[string]struct{}, len(targets))
	t.byIP = make(map[netip.Addr]string, len(targets))
	for _, tg := range targets {
		taken[tg.nodeID] = struct{}{}
		t.byIP[tg.meshIP] = tg.nodeID
	}
	for nodeID := range t.peers {
		if _, ok := taken[nodeID]; !ok {
			delete(t.peers, nodeID)
		}
	}
}

// listenFailed records a round that could not listen: it counts one
// unanswered probe for every peer that holds a value. A probe still
// outstanding from the socket that went away stays recorded, so the first
// round that sends again counts it as well (see rttSend).
func (t *rttTable) listenFailed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.peers {
		if e.value > 0 {
			e.miss()
		}
	}
}

// answered records a reply from src that carries nonce, received at the
// instant at. It counts only when a probe to the peer with mesh IP src is
// outstanding, carries nonce and was sent at most rttProbeTimeout before at.
// The value is then at less the send instant, at least 1 ns, so an answered
// probe always leaves a value even under a clock that did not advance between
// the two. It is measured over the endpoint at the send, and the reply clears
// the outstanding probe and the unanswered count. Any other reply changes
// nothing.
func (t *rttTable) answered(src netip.Addr, nonce [8]byte, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	nodeID, ok := t.byIP[src]
	if !ok {
		return
	}
	e, ok := t.peers[nodeID]
	if !ok || !e.probe.sent || e.probe.meshIP != src || e.probe.nonce != nonce {
		return
	}
	rtt := at.Sub(e.probe.sentAt)
	if rtt > rttProbeTimeout {
		return
	}
	e.value = max(rtt, time.Nanosecond)
	e.over = e.probe.endpoint
	e.probe = rttProbe{}
	e.unanswered = 0
}

// rttTarget is a peer a round probes: its node ID, its mesh IP and the device
// endpoint the read reported.
type rttTarget struct {
	nodeID   string
	meshIP   netip.Addr
	endpoint netip.AddrPort
}

// rttSocket is the probe socket a RunRTTProbe run holds. Only that run's
// goroutine touches it.
type rttSocket struct {
	// conn is the socket, nil while none is held.
	conn net.PacketConn
	// done is closed when the reader on conn ended.
	done chan struct{}
	// listenFailing records that the last listen failed.
	listenFailing bool
}

// close closes the socket and waits for its reader to end. It does nothing
// while no socket is held.
func (s *rttSocket) close() {
	if s.conn == nil {
		return
	}
	_ = s.conn.Close()
	<-s.done
	s.conn, s.done = nil, nil
}

// listenRTT is the default rttListen: it listens on UDP port RTTProbePort of
// the node's mesh IP, as Setup stored it, on a socket bound to the mesh
// interface (ifbind.Control). A mesh IP that is not IPv4, the zero
// address included, is refused, so the socket is never bound to the wildcard
// address.
//
// DECISION: the socket is bound to the mesh interface as well as to the mesh
// IP (author, 2026-11-23, #218). Linux and macOS deliver a datagram for any
// address of the host on whichever interface it arrives, so a host on another
// network that routes the mesh IP through the node and spoofs a mesh source
// would otherwise draw an answer into the tunnel, which the output chain
// passes as a reply. Windows receives on the strong host model by default and
// needs no option.
func (m *Manager) listenRTT() (net.PacketConn, error) {
	if !m.meshIP.Is4() {
		return nil, fmt.Errorf("wireguard: rtt probe: mesh ip %s is not IPv4", m.meshIP)
	}
	lc := net.ListenConfig{Control: ifbind.Control(m.OSInterfaceName())}
	return lc.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(m.meshIP, RTTProbePort).String())
}

// rttProbeAddr is the default rttAddr: UDP port RTTProbePort of meshIP.
func rttProbeAddr(meshIP netip.Addr) net.Addr {
	return &net.UDPAddr{IP: meshIP.AsSlice(), Port: RTTProbePort}
}

// RunRTTProbe measures the round-trip time to each mesh peer through the
// tunnel until ctx is done, and then closes its socket, waits for the reader
// and returns nil. MeshPeerStats reports the values as MeshPeerStat.RTT. A
// non-positive interval is replaced with DefaultRTTProbeInterval. The first
// round runs half an interval after the start and one round runs per interval
// after that, so a round's answers are in before the handshake report that
// follows when interval is the heartbeat interval. A round that outlasts the
// interval delays the next one. It also returns nil, with the socket closed,
// when the controller cannot read peer stats.
//
// A round, in order (see rttRound):
//  1. Listens when it holds no socket, none yet or one whose reader ended (see
//     rttRead). A failure logs wireguard: rtt probe listen failed, at Warn the
//     first time and at Debug while it keeps failing. The round then sends
//     nothing, counts one unanswered probe for every peer that holds a value,
//     and ends.
//  2. Reads MeshPeerStats. ErrPeerStatsUnsupported logs wireguard: rtt probe
//     unavailable, the controller cannot read peer stats at Info and ends the
//     probe. Any other error logs wireguard: rtt probe round failed at Warn
//     and ends the round with every value as it was.
//  3. Takes each peer whose handshake is younger than connectedHandshakeAge,
//     whose dial state exists, and whose mesh IP is an IPv4 address inside the
//     mesh prefix other than the node's own. The entry of every other peer is
//     deleted, so a peer that comes back starts without a value.
//  4. Sends a probe to each taken peer in node ID order, rttProbeGap apart
//     (see rttSend).
//
// One probe per peer is outstanding at a time, and a new one replaces it. A
// node whose identity carries no usable domain_mesh_cidr holds a host /32 as
// its mesh prefix, so it probes nobody and answers nobody. Relay liveness
// (checkRelay, watchRelay) is unaffected; an answer moves RxBytes like any
// other packet.
//
// DECISION: one probe per peer per interval. The value travels once per
// heartbeat interval with the handshake report, so more probes would measure
// what nobody reads. At the default interval that costs a node two 108-byte
// packets per peer every 30 s, its probe and its answer to the peer's probe (a
// 16-byte datagram is an 80-byte WireGuard message), about 0.6 MB a day per
// peer.
func (m *Manager) RunRTTProbe(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultRTTProbeInterval
	}
	m.logger.Info("wireguard: rtt probe started",
		"component", "wireguard",
		"interval", interval,
		"port", RTTProbePort,
	)

	var s rttSocket
	defer s.close()

	first := time.NewTimer(interval / 2)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-first.C:
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if !m.rttRound(ctx, &s) {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

// rttRound runs one round of the round-trip probe on s, the steps
// RunRTTProbe lists, and reports whether the probe goes on: it returns false
// when the controller cannot read peer stats, and RunRTTProbe then closes the
// socket. A done ctx ends the round between two sends.
func (m *Manager) rttRound(ctx context.Context, s *rttSocket) bool {
	if !m.rttOpen(s) {
		m.rtt.listenFailed()
		return true
	}

	stats, err := m.MeshPeerStats()
	if errors.Is(err, ErrPeerStatsUnsupported) {
		m.logger.Info("wireguard: rtt probe unavailable, the controller cannot read peer stats",
			"component", "wireguard",
		)
		return false
	}
	if err != nil {
		m.logger.Warn("wireguard: rtt probe round failed",
			"component", "wireguard",
			"error", err,
		)
		return true
	}

	targets := m.rttTargets(stats)
	m.rtt.retain(targets)

	for i, tg := range targets {
		m.rttSend(ctx, s.conn, tg)
		if i == len(targets)-1 {
			break
		}
		gap := time.NewTimer(rttProbeGap)
		select {
		case <-ctx.Done():
			gap.Stop()
			return true
		case <-gap.C:
		}
	}
	return true
}

// rttOpen listens when s holds no socket, or holds one whose reader ended,
// and starts a reader on the new socket. It reports whether s holds a socket.
// A failed listen logs wireguard: rtt probe listen failed, at Warn the first
// time and at Debug while it keeps failing; a success resets that.
func (m *Manager) rttOpen(s *rttSocket) bool {
	if s.conn != nil {
		select {
		case <-s.done:
			// The reader closed the socket after rttMaxReadErrors failed
			// reads in a row.
			s.conn, s.done = nil, nil
		default:
			return true
		}
	}

	conn, err := m.rttListen()
	if err != nil {
		level := slog.LevelWarn
		if s.listenFailing {
			level = slog.LevelDebug
		}
		m.logger.Log(context.Background(), level, "wireguard: rtt probe listen failed",
			"component", "wireguard",
			"address", netip.AddrPortFrom(m.meshIP, RTTProbePort).String(),
			"error", err,
		)
		s.listenFailing = true
		return false
	}
	s.listenFailing = false
	s.conn = conn
	s.done = make(chan struct{})
	go m.rttRead(conn, s.done)
	return true
}

// rttTargets returns the peers of stats a round probes, in the order of
// stats: each whose LastHandshake is non-zero and younger than
// connectedHandshakeAge, whose dial state exists, and whose dial state's
// MeshIP parses as an IPv4 address inside the mesh prefix other than the
// node's own mesh IP. It reads the dial states under m.mu and touches no
// table.
func (m *Manager) rttTargets(stats []MeshPeerStat) []rttTarget {
	now := m.now()
	var targets []rttTarget
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range stats {
		if s.LastHandshake.IsZero() || now.Sub(s.LastHandshake) >= connectedHandshakeAge {
			continue
		}
		st, ok := m.dial[s.NodeID]
		if !ok {
			continue
		}
		ip, err := netip.ParseAddr(st.peer.MeshIP)
		if err != nil || !ip.Is4() || !m.meshPrefix.Contains(ip) || ip == m.meshIP {
			continue
		}
		targets = append(targets, rttTarget{nodeID: s.NodeID, meshIP: ip, endpoint: s.Endpoint})
	}
	return targets
}

// rttSend runs step 4 of a round for one taken peer. It counts the previous
// probe as unanswered when it is still outstanding, drops the value when the
// device endpoint differs from the one the value was measured over, and
// drops it when rttMaxUnanswered probes in a row went unanswered (see
// rttEntry.miss). It then sends a new probe on conn to m.rttAddr of the
// peer's mesh IP. The probe is recorded before the write, so a fast answer
// cannot beat its own record, and its send instant is read right before the
// write. A failed write clears the record, logs wireguard: rtt probe send
// failed, at Warn the first time for the peer and at Debug while its sends
// keep failing, and counts as an unanswered probe.
//
// DECISION: a value is dropped when the device endpoint changes. The endpoint
// names the path the tunnel runs on, a direct address or a relay, so a new
// endpoint is a new path, and the old path's time would rank the new one
// until the next answer.
func (m *Manager) rttSend(ctx context.Context, conn net.PacketConn, tg rttTarget) {
	var nonce [8]byte
	// Read never returns an error: it crashes the program instead.
	_, _ = rand.Read(nonce[:])
	datagram := rttDatagram(rttKindRequest, nonce)
	to := m.rttAddr(tg.meshIP)

	m.rtt.mu.Lock()
	e := m.rtt.entry(tg.nodeID)
	if e.probe.sent {
		e.miss()
	}
	if e.value > 0 && e.over != tg.endpoint {
		e.value = 0
	}
	e.probe = rttProbe{
		sent:     true,
		nonce:    nonce,
		sentAt:   m.now(),
		endpoint: tg.endpoint,
		meshIP:   tg.meshIP,
	}
	m.rtt.mu.Unlock()

	_, err := conn.WriteTo(datagram, to)

	m.rtt.mu.Lock()
	failing := e.sendFailing
	e.sendFailing = err != nil
	if err != nil {
		e.probe = rttProbe{}
		e.miss()
	}
	m.rtt.mu.Unlock()
	if err == nil {
		return
	}

	level := slog.LevelWarn
	if failing {
		level = slog.LevelDebug
	}
	m.logger.Log(ctx, level, "wireguard: rtt probe send failed",
		"component", "wireguard",
		"peer_id", tg.nodeID,
		"mesh_ip", tg.meshIP.String(),
		"error", err,
	)
}

// rttDatagram returns a probe datagram of kind carrying nonce.
func rttDatagram(kind byte, nonce [8]byte) []byte {
	b := make([]byte, rttDatagramLen)
	copy(b, rttMagic)
	b[4] = rttVersion
	b[5] = kind
	copy(b[8:], nonce[:])
	return b
}

// rttRead is the reader of one probe socket. It handles each datagram conn
// receives (see rttReceive), reading the receive instant right after the read
// returns, until a read fails with net.ErrClosed. Any other read error logs
// wireguard: rtt probe read failed at Debug and the reader reads on; after
// rttMaxReadErrors in a row, which a good read resets, it closes conn and
// ends. It closes done when it ends.
//
// An ICMP port unreachable for an earlier send is no read error: Linux and
// macOS report none to a socket that is not connected, and on Windows Go
// turns SIO_UDP_CONNRESET and SIO_UDP_NETRESET off on every UDP socket it
// creates (net/fd_windows.go), so no WSAECONNRESET reaches this loop.
func (m *Manager) rttRead(conn net.PacketConn, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, rttReadBufferLen)
	failed := 0
	for {
		n, from, err := conn.ReadFrom(buf)
		at := m.now()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			m.logger.Debug("wireguard: rtt probe read failed",
				"component", "wireguard",
				"error", err,
			)
			failed++
			if failed >= rttMaxReadErrors {
				_ = conn.Close()
				return
			}
			continue
		}
		failed = 0
		m.rttReceive(conn, buf[:n], from, at)
	}
}

// rttReceive handles datagram b that conn received from from at the instant
// at. It drops a datagram that is not rttDatagramLen bytes, carries another
// magic or version or a kind other than a request or a reply, or whose
// source, unmapped, is not an IPv4 address inside the mesh prefix. It answers
// a request with the same bytes as a reply to the request's source address
// and port; a failed write logs wireguard: rtt probe answer failed at Debug.
// A reply goes to the table (see rttTable.answered) and never draws a
// datagram, so two nodes cannot answer each other in a loop.
func (m *Manager) rttReceive(conn net.PacketConn, b []byte, from net.Addr, at time.Time) {
	if len(b) != rttDatagramLen || string(b[:4]) != rttMagic || b[4] != rttVersion {
		return
	}
	kind := b[5]
	if kind != rttKindRequest && kind != rttKindReply {
		return
	}
	udp, ok := from.(*net.UDPAddr)
	if !ok {
		return
	}
	src := udp.AddrPort().Addr().Unmap()
	if !src.Is4() || !m.meshPrefix.Contains(src) {
		return
	}

	if kind == rttKindReply {
		m.rtt.answered(src, [8]byte(b[8:]), at)
		return
	}
	b[5] = rttKindReply
	if _, err := conn.WriteTo(b, from); err != nil {
		m.logger.Debug("wireguard: rtt probe answer failed",
			"component", "wireguard",
			"error", err,
		)
	}
}
