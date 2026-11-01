package bridge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ratelimiter"

	"github.com/plexsphere/plexd/internal/api"
)

const (
	// relayFanoutWindow is how long the source of a pending initiation keeps
	// receiving the initiations the relay cannot place. It is no longer than
	// the 30 s Linux conntrack timeout for an unanswered UDP flow, so the
	// initiator's NAT mapping is still open.
	relayFanoutWindow = 30 * time.Second

	// relayRetryMin is how long after the first held initiation the relay
	// forwards the next one. WireGuard repeats an unanswered initiation after
	// its RekeyTimeout of 5 s plus up to 334 ms of jitter, and a backlog drains
	// in milliseconds, so a backlog ends inside this time and a retry does not.
	// The 1 s margin absorbs network jitter. A retry that arrives earlier stays
	// held, and the one after it passes.
	relayRetryMin = 4 * time.Second

	// relayHoldWindow is how long a hold lasts. Past it, an initiation counts
	// as a first one again. Two retries fit in it at WireGuard's largest
	// jitter, and it ends well before the next 120 s rekey.
	relayHoldWindow = 15 * time.Second

	// relayFanoutMax is the most sources one initiation is fanned out to.
	relayFanoutMax = 8

	// relayIndexTTL is WireGuard's RejectAfterTime: no session outlives it
	// without a new handshake. A session index unused for this long is
	// dropped, and a peer address not seen for this long is no longer fresh.
	relayIndexTTL = 180 * time.Second

	// relaySweepInterval is how often the sweeper deletes expired indices and
	// the pairs left with neither of theirs.
	relaySweepInterval = 30 * time.Second

	// relayMaxIndices caps the index table.
	relayMaxIndices = 1 << 16

	// relayFullWarnInterval is the least time between two "relay: index table
	// full" lines.
	relayFullWarnInterval = time.Minute

	relayBufSize = 65535
)

// relayConn is the part of *net.UDPConn the relay uses, so a test can inject
// read and write errors.
type relayConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	LocalAddr() net.Addr
	Close() error
}

// handshakeLimiter is the part of ratelimiter.Ratelimiter the relay uses.
// Every loopback socket in a test shares one source IP, so tests that send
// more handshake messages than the burst swap it out.
type handshakeLimiter interface {
	Allow(ip netip.Addr) bool
	Close()
}

// relayPeer is a peer the state pull lists: its node ID, the mac1 checker
// keyed to its public key, and the address the relay last attributed one of
// its datagrams to.
type relayPeer struct {
	nodeID  string
	checker *device.CookieChecker
	addr    netip.AddrPort
	seen    time.Time
}

// relayIndex is a WireGuard session index the relay saw. A pending index is
// the sender index of an initiation: partner is the peer whose key verified
// its mac1, and src the initiator's source address, since the initiator is
// not known yet. A session index is one side of a handshake the relay
// forwarded: owner is the peer that chose the index, so datagrams naming it
// as receiver go to owner, and partner is the other side. carried records that
// a transport message named it, which is what shows the handshake completed: a
// device that re-dialed in the meantime drops the response the relay forwarded.
type relayIndex struct {
	pending bool
	owner   *relayPeer
	partner *relayPeer
	src     netip.AddrPort
	used    time.Time
	carried bool
}

// relayPair is two peers the relay forwarded a handshake for: the session
// indices of their latest handshake, and when the relay last started to hold
// an initiation of theirs, zero until it first does. A forwarded retry leaves
// heldAt set, so a forger cannot start a new hold right after each forward. A
// response clears it by replacing the entry.
type relayPair struct {
	indices [2]uint32
	heldAt  time.Time
}

// relayRun is one bound socket and the goroutines serving it.
type relayRun struct {
	conn    relayConn
	port    int
	limiter handshakeLimiter
	boundAt time.Time // when the socket was bound, from Relay.now

	stop       chan struct{} // closed to end the sweeper
	dispatched chan struct{} // closed when the dispatch loop returns
	swept      chan struct{} // closed when the sweeper returns
}

// Relay forwards WireGuard between the peers of a state pull through one UDP
// socket. It works out each datagram's destination from the WireGuard message
// header: an initiation goes to the peer whose public key verifies its mac1,
// every other message by its receiver index. An initiation between two peers
// that hold a session waits for its retry, so a backlog that queued while the
// relay was frozen cannot move them to it (see holdInitiation). It holds no
// private or preshared key, decrypts nothing, and never answers a datagram.
type Relay struct {
	logger *slog.Logger

	// Seams, replaced by tests before the first Configure.
	listen     func(port int) (relayConn, error)
	newLimiter func() handshakeLimiter
	now        func() time.Time
	maxIndices int

	// life serializes Configure and Stop, so a start and a stop never
	// interleave.
	life sync.Mutex

	// mu guards run, peers, indices, pairs and fullWarnedAt.
	mu           sync.Mutex
	run          *relayRun
	peers        map[device.NoisePublicKey]*relayPeer
	indices      map[uint32]*relayIndex
	pairs        map[[2]string]*relayPair
	fullWarnedAt time.Time
}

// NewRelay returns a relay that is not running. It opens no socket; Configure
// starts it.
func NewRelay(logger *slog.Logger) *Relay {
	return &Relay{
		logger:     logger.With("component", "bridge"),
		listen:     listenRelay,
		newLimiter: newHandshakeLimiter,
		now:        time.Now,
		maxIndices: relayMaxIndices,
		peers:      make(map[device.NoisePublicKey]*relayPeer),
		indices:    make(map[uint32]*relayIndex),
		pairs:      make(map[[2]string]*relayPair),
	}
}

// listenRelay binds UDP port on the dual-stack wildcard address.
func listenRelay(port int) (relayConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// newHandshakeLimiter returns wireguard-go's handshake rate limiter, 20
// messages per second per source IP with a burst of 5.
func newHandshakeLimiter() handshakeLimiter {
	l := new(ratelimiter.Ratelimiter)
	l.Init()
	return l
}

// Configure runs the relay on UDP listenPort and forwards among peers. A
// relay running on another port is stopped first; a relay not running is
// started. The peer set is then replaced: a peer whose node ID and public key
// are unchanged keeps its learned address, a new or re-keyed peer starts
// fresh, and a peer no longer listed is deleted with every index that names
// it. A peer with an invalid or a repeated public key is skipped with a Warn.
// A repeated call with the same port and peers changes nothing.
func (r *Relay) Configure(listenPort int, peers []api.SnapshotPeer) error {
	if listenPort < 1 || listenPort > 65535 {
		return fmt.Errorf("bridge: relay: listen_port %d out of range", listenPort)
	}

	r.life.Lock()
	defer r.life.Unlock()

	r.mu.Lock()
	run := r.run
	r.mu.Unlock()
	if run != nil && run.port != listenPort {
		r.stopLocked()
		run = nil
	}
	if run == nil {
		if err := r.start(listenPort); err != nil {
			return err
		}
	}
	r.setPeers(peers)
	return nil
}

// start binds port and starts the dispatch loop and the sweeper. Callers
// hold r.life.
func (r *Relay) start(port int) error {
	conn, err := r.listen(port)
	if err != nil {
		return fmt.Errorf("bridge: relay: listen on :%d: %w", port, err)
	}
	run := &relayRun{
		conn:       conn,
		port:       port,
		limiter:    r.newLimiter(),
		boundAt:    r.now(),
		stop:       make(chan struct{}),
		dispatched: make(chan struct{}),
		swept:      make(chan struct{}),
	}
	r.mu.Lock()
	r.run = run
	r.mu.Unlock()

	go r.dispatchLoop(run)
	go r.sweepLoop(run)

	r.logger.Info("relay started", "listen_port", port)
	return nil
}

// Stop closes the socket, ends the dispatch loop and the sweeper, closes the
// rate limiter and clears all state. Stopping a relay that is not running
// returns nil and logs nothing.
func (r *Relay) Stop() error {
	r.life.Lock()
	defer r.life.Unlock()
	r.stopLocked()
	return nil
}

// stopLocked is Stop for a caller holding r.life. It releases r.mu before it
// waits, because the dispatch loop takes r.mu for every datagram.
func (r *Relay) stopLocked() {
	r.mu.Lock()
	run := r.run
	r.run = nil
	r.mu.Unlock()
	if run == nil {
		return
	}

	// A close error leaves nothing to undo: the dispatch loop ends on the
	// next read either way.
	_ = run.conn.Close()
	close(run.stop)
	<-run.dispatched
	<-run.swept
	// Only now that the dispatch loop is gone: Close panics when called twice,
	// and Allow after Close can panic.
	run.limiter.Close()

	r.mu.Lock()
	r.peers = make(map[device.NoisePublicKey]*relayPeer)
	r.indices = make(map[uint32]*relayIndex)
	r.pairs = make(map[[2]string]*relayPair)
	r.fullWarnedAt = time.Time{}
	r.mu.Unlock()

	r.logger.Info("relay stopped", "listen_port", run.port)
}

// Running reports whether the relay has a socket bound.
func (r *Relay) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.run != nil
}

// Bound returns the port the relay socket is bound on and when it was
// bound. ok is false while the relay is not running.
func (r *Relay) Bound() (port int, at time.Time, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run == nil {
		return 0, time.Time{}, false
	}
	return r.run.port, r.run.boundAt, true
}

// ListenAddr returns the local address of the relay socket, or nil while the
// relay is not running.
func (r *Relay) ListenAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run == nil {
		return nil
	}
	return r.run.conn.LocalAddr()
}

// ActiveCount returns the number of distinct unordered peer pairs among the
// session indices used within relayIndexTTL.
func (r *Relay) ActiveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	pairs := make(map[[2]string]struct{})
	for _, idx := range r.indices {
		if idx.pending || now.Sub(idx.used) >= relayIndexTTL {
			continue
		}
		pairs[pairKey(idx.owner, idx.partner)] = struct{}{}
	}
	return len(pairs)
}

// pairKey returns the key of the unordered pair of a and b: their node IDs in
// sorted order.
func pairKey(a, b *relayPeer) [2]string {
	if a.nodeID > b.nodeID {
		return [2]string{b.nodeID, a.nodeID}
	}
	return [2]string{a.nodeID, b.nodeID}
}

// setPeers replaces the peer set from peers; see Configure.
func (r *Relay) setPeers(peers []api.SnapshotPeer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := make(map[device.NoisePublicKey]*relayPeer, len(peers))
	for _, p := range peers {
		key, ok := decodeRelayKey(p.PublicKey)
		if !ok {
			r.logger.Warn("relay: skipping peer with invalid public key", "peer_id", p.NodeID)
			continue
		}
		if _, dup := next[key]; dup {
			r.logger.Warn("relay: skipping peer with duplicate public key", "peer_id", p.NodeID)
			continue
		}
		if old, ok := r.peers[key]; ok && old.nodeID == p.NodeID {
			next[key] = old
			continue
		}
		peer := &relayPeer{nodeID: p.NodeID, checker: new(device.CookieChecker)}
		peer.checker.Init(key)
		next[key] = peer
	}

	kept := make(map[*relayPeer]bool, len(next))
	for _, p := range next {
		kept[p] = true
	}
	for i, idx := range r.indices {
		if (idx.owner != nil && !kept[idx.owner]) || (idx.partner != nil && !kept[idx.partner]) {
			delete(r.indices, i)
		}
	}
	r.peers = next
}

// decodeRelayKey decodes a public key from standard base64 of 32 bytes.
func decodeRelayKey(s string) (device.NoisePublicKey, bool) {
	var key device.NoisePublicKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != len(key) {
		return key, false
	}
	copy(key[:], b)
	return key, true
}

// dispatchLoop reads datagrams from run's socket into one buffer, works out
// their destinations under r.mu, and writes them after releasing it. It ends
// when the socket is closed.
func (r *Relay) dispatchLoop(run *relayRun) {
	defer close(run.dispatched)

	buf := make([]byte, relayBufSize)
	var dsts []netip.AddrPort
	for {
		n, src, err := run.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			r.logger.Debug("relay: read failed", "error", err)
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		b := buf[:n]

		dsts = r.route(run, b, src, dsts[:0])
		for _, dst := range dsts {
			if _, err := run.conn.WriteToUDPAddrPort(b, dst); err != nil {
				r.logger.Debug("relay: forward failed", "dst", dst.String(), "error", err)
			}
		}
	}
}

// route appends to dsts the addresses b, received from src, is forwarded to,
// and updates the relay's state. A datagram it cannot forward is logged as
// dropped and gets no destination, and so is an initiation it could forward
// but holds for its retry.
func (r *Relay) route(run *relayRun, b []byte, src netip.AddrPort, dsts []netip.AddrPort) []netip.AddrPort {
	msg, ok := parseWGMessage(b)
	if !ok {
		r.drop(src, "not_wireguard")
		return dsts
	}
	if msg.typ == device.MessageInitiationType || msg.typ == device.MessageResponseType {
		if !run.limiter.Allow(src.Addr()) {
			r.drop(src, "rate_limited")
			return dsts
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()

	var reason string
	switch msg.typ {
	case device.MessageInitiationType:
		dsts, reason = r.routeInitiation(b, msg, src, now, dsts)
	case device.MessageResponseType:
		dsts, reason = r.routeResponse(b, msg, src, now, dsts)
	case device.MessageCookieReplyType:
		dsts, reason = r.routeCookieReply(msg, src, dsts)
	default:
		dsts, reason = r.routeTransport(msg, src, now, dsts)
	}
	if reason != "" {
		r.drop(src, reason)
	}
	return dsts
}

// routeInitiation forwards an initiation to the peer T whose key verifies its
// mac1: to T's address when fresh, otherwise to the recent pending initiators
// (see fanout). It records the sender index as pending for T. An initiation
// holdInitiation keeps back is dropped before that, because nothing can answer
// it.
func (r *Relay) routeInitiation(b []byte, msg wgMessage, src netip.AddrPort, now time.Time, dsts []netip.AddrPort) ([]netip.AddrPort, string) {
	target := r.mac1Peer(b, nil)
	if target == nil {
		return dsts, "unknown_target"
	}
	direct := r.fresh(target, now)
	if direct && target.addr == src {
		return dsts, "no_route"
	}
	if r.holdInitiation(target, src, now) {
		return dsts, "held_for_retry"
	}
	if !r.room(msg.sender, now) {
		return dsts, "index_table_full"
	}
	r.indices[msg.sender] = &relayIndex{pending: true, partner: target, src: src, used: now}

	if direct {
		return append(dsts, target.addr), ""
	}
	n := len(dsts)
	dsts = r.fanout(src, now, dsts)
	if len(dsts) == n {
		return dsts, "no_route"
	}
	return dsts, ""
}

// holdInitiation reports whether the relay keeps back an initiation for target
// from src. A relay that resumes after a freeze reads the initiations queued
// on its socket, and a node that accepts one moves its endpoint here, off the
// relay its session now runs over. An initiation's age is encrypted and the
// relay's clock stood still, so only the timing after the resume separates a
// stale initiation from a live one: a backlog drains in milliseconds, and
// WireGuard retries about 5 s later.
//
// So the first initiation of two peers with a live session starts a hold, and
// what follows within relayRetryMin stays held. Until relayHoldWindow ends,
// every later initiation passes, and only then can a new hold start. A forged
// initiation can therefore never hold more than the first relayRetryMin of a
// window, and WireGuard's next retry lands after it. A source that is no peer,
// or two peers with no live session, is first contact and passes at once.
func (r *Relay) holdInitiation(target *relayPeer, src netip.AddrPort, now time.Time) bool {
	var initiator *relayPeer
	for _, p := range r.peers {
		if p != target && p.addr == src {
			initiator = p
			break
		}
	}
	if initiator == nil {
		return false
	}
	pair, ok := r.pairs[pairKey(initiator, target)]
	if !ok || !r.sessionLive(pair, initiator, target, now) {
		return false
	}
	if pair.heldAt.IsZero() || now.Sub(pair.heldAt) >= relayHoldWindow {
		pair.heldAt = now
		return true
	}
	return now.Sub(pair.heldAt) < relayRetryMin
}

// sessionLive reports whether one of pair's indices is a session index of a
// and b that carried a transport message and was used within relayIndexTTL. A
// handshake that carried nothing may not have completed, and holding the next
// attempt would delay a pair that has no session. It checks who owns the index
// because another pair's handshake can overwrite it, and because two peers can
// share a node ID and with it a pair key.
func (r *Relay) sessionLive(pair *relayPair, a, b *relayPeer, now time.Time) bool {
	for _, i := range pair.indices {
		idx, ok := r.indices[i]
		if !ok || idx.pending || !idx.carried || now.Sub(idx.used) >= relayIndexTTL {
			continue
		}
		if (idx.owner == a && idx.partner == b) || (idx.owner == b && idx.partner == a) {
			return true
		}
	}
	return false
}

// routeResponse forwards a response to the source of the pending initiation
// it answers, when its mac1 verifies for a peer I other than that
// initiation's target T. Both addresses are learned from it, both indices
// become session indices, and the pair is recorded with them, which ends a
// hold on it.
func (r *Relay) routeResponse(b []byte, msg wgMessage, src netip.AddrPort, now time.Time, dsts []netip.AddrPort) ([]netip.AddrPort, string) {
	pending, ok := r.indices[msg.receiver]
	if !ok || !pending.pending {
		return dsts, "unknown_index"
	}
	initiator := r.mac1Peer(b, pending.partner)
	if initiator == nil {
		return dsts, "unknown_target"
	}
	if pending.src == src {
		return dsts, "no_route"
	}
	if !r.room(msg.sender, now) {
		return dsts, "index_table_full"
	}
	// The sweep room may run can expire the pending index itself.
	if r.indices[msg.receiver] != pending {
		return dsts, "unknown_index"
	}

	target := pending.partner
	r.learn(target, src, now)
	r.learn(initiator, pending.src, now)
	r.indices[msg.receiver] = &relayIndex{owner: initiator, partner: target, used: now}
	r.indices[msg.sender] = &relayIndex{owner: target, partner: initiator, used: now}
	r.pairs[pairKey(initiator, target)] = &relayPair{indices: [2]uint32{msg.receiver, msg.sender}}
	return append(dsts, pending.src), ""
}

// routeCookieReply forwards a cookie reply to the side that chose its
// receiver index: a pending initiation's source, or a session owner.
func (r *Relay) routeCookieReply(msg wgMessage, src netip.AddrPort, dsts []netip.AddrPort) ([]netip.AddrPort, string) {
	idx, ok := r.indices[msg.receiver]
	if !ok {
		return dsts, "unknown_index"
	}
	dst := idx.src
	if !idx.pending {
		dst = idx.owner.addr
	}
	if !dst.IsValid() || dst == src {
		return dsts, "no_route"
	}
	return append(dsts, dst), ""
}

// routeTransport forwards a transport message to the owner of its receiver
// index, and learns the partner's address from it.
func (r *Relay) routeTransport(msg wgMessage, src netip.AddrPort, now time.Time, dsts []netip.AddrPort) ([]netip.AddrPort, string) {
	idx, ok := r.indices[msg.receiver]
	if !ok || idx.pending {
		return dsts, "unknown_index"
	}
	dst := idx.owner.addr
	if !dst.IsValid() || dst == src {
		return dsts, "no_route"
	}
	r.learn(idx.partner, src, now)
	idx.used = now
	idx.carried = true
	return append(dsts, dst), ""
}

// mac1Peer returns the peer other than exclude whose public key verifies b's
// mac1, or nil. Public keys are unique, so at most one peer verifies.
func (r *Relay) mac1Peer(b []byte, exclude *relayPeer) *relayPeer {
	for _, p := range r.peers {
		if p != exclude && p.checker.CheckMAC1(b) {
			return p
		}
	}
	return nil
}

// fresh reports whether p has an address seen within relayIndexTTL.
func (r *Relay) fresh(p *relayPeer, now time.Time) bool {
	return p.addr.IsValid() && now.Sub(p.seen) < relayIndexTTL
}

// fanout appends the distinct sources of pending indices younger than
// relayFanoutWindow, newest first and at most relayFanoutMax, leaving out src
// and every peer's fresh address. An initiator behind a symmetric NAT is
// reachable only at the mapping its own initiation opened, so the relay sends
// an initiation it cannot place to the initiators waiting on it. Only the real
// target's WireGuard accepts it, because mac1 is keyed to the target's key.
func (r *Relay) fanout(src netip.AddrPort, now time.Time, dsts []netip.AddrPort) []netip.AddrPort {
	known := make(map[netip.AddrPort]bool, len(r.peers))
	for _, p := range r.peers {
		if r.fresh(p, now) {
			known[p.addr] = true
		}
	}
	var waiting []*relayIndex
	for _, idx := range r.indices {
		if idx.pending && now.Sub(idx.used) < relayFanoutWindow && idx.src != src && !known[idx.src] {
			waiting = append(waiting, idx)
		}
	}
	slices.SortFunc(waiting, func(a, b *relayIndex) int { return b.used.Compare(a.used) })

	sent := make(map[netip.AddrPort]bool, relayFanoutMax)
	for _, idx := range waiting {
		if len(sent) == relayFanoutMax {
			break
		}
		if sent[idx.src] {
			continue
		}
		sent[idx.src] = true
		dsts = append(dsts, idx.src)
	}
	return dsts
}

// learn sets p's address to addr and marks it seen. The address is cleared
// from any other peer that held it.
func (r *Relay) learn(p *relayPeer, addr netip.AddrPort, now time.Time) {
	p.seen = now
	if p.addr == addr {
		return
	}
	for _, other := range r.peers {
		if other != p && other.addr == addr {
			other.addr = netip.AddrPort{}
		}
	}
	p.addr = addr
	r.logger.Info("relay: peer address learned", "peer_id", p.nodeID, "address", addr.String())
}

// room reports whether index i can be recorded: it exists already, or the
// table holds fewer than maxIndices. A full table is swept first. A table
// still full is logged at Warn, at most once per relayFullWarnInterval.
func (r *Relay) room(i uint32, now time.Time) bool {
	if _, ok := r.indices[i]; ok || len(r.indices) < r.maxIndices {
		return true
	}
	r.sweepLocked(now)
	if len(r.indices) < r.maxIndices {
		return true
	}
	if r.fullWarnedAt.IsZero() || now.Sub(r.fullWarnedAt) >= relayFullWarnInterval {
		r.fullWarnedAt = now
		r.logger.Warn("relay: index table full", "max_indices", r.maxIndices)
	}
	return false
}

// sweepLoop runs sweep every relaySweepInterval until run stops.
func (r *Relay) sweepLoop(run *relayRun) {
	defer close(run.swept)

	ticker := time.NewTicker(relaySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-run.stop:
			return
		case <-ticker.C:
			r.sweep(r.now())
		}
	}
}

// sweep deletes pending indices older than relayFanoutWindow, session indices
// unused for relayIndexTTL, and pairs with neither of their indices left.
func (r *Relay) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
}

func (r *Relay) sweepLocked(now time.Time) {
	for i, idx := range r.indices {
		ttl := relayIndexTTL
		if idx.pending {
			ttl = relayFanoutWindow
		}
		if now.Sub(idx.used) >= ttl {
			delete(r.indices, i)
		}
	}
	for key, pair := range r.pairs {
		if !r.holdsIndex(key, pair) {
			delete(r.pairs, key)
		}
	}
}

// holdsIndex reports whether one of pair's indices is still a session index of
// the two peers of key. Another pair's handshake can overwrite an index, so
// finding it in indices is not enough, and pairs would outgrow the index table.
func (r *Relay) holdsIndex(key [2]string, pair *relayPair) bool {
	for _, i := range pair.indices {
		if idx, ok := r.indices[i]; ok && !idx.pending && pairKey(idx.owner, idx.partner) == key {
			return true
		}
	}
	return false
}

// drop logs a datagram from src the relay does not forward.
func (r *Relay) drop(src netip.AddrPort, reason string) {
	r.logger.Debug("relay: dropped datagram", "source", src, "reason", reason)
}
