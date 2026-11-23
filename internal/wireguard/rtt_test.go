package wireguard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/registration"
)

// The round-trip probe tests on fake sockets run as the node rttSelf in the
// mesh rttMesh.
var (
	rttMesh = netip.MustParsePrefix("10.0.0.0/24")
	rttSelf = netip.MustParseAddr("10.0.0.1")
)

// errAddrInUse is the listen error of a port another socket holds.
var errAddrInUse = errors.New("listen udp4 10.0.0.1:7911: bind: address already in use")

// fakeRTTConn is an in-memory net.PacketConn. Its reads return what deliver
// and failRead queued, in order. WriteTo records every datagram it accepts
// and fails for an address failWrites names. Close makes every read and
// write fail with net.ErrClosed.
type fakeRTTConn struct {
	reads  chan fakeRead
	closed chan struct{}
	once   sync.Once

	mu         sync.Mutex
	writes     []fakeWrite
	failWrites map[string]error
	reading    int
	barriers   int
}

type fakeRead struct {
	b    []byte
	from net.Addr
	err  error
}

type fakeWrite struct {
	b  []byte
	to net.Addr
}

func newFakeRTTConn() *fakeRTTConn {
	return &fakeRTTConn{
		reads:      make(chan fakeRead, 64),
		closed:     make(chan struct{}),
		failWrites: make(map[string]error),
	}
}

func (c *fakeRTTConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	c.reading++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.reading--
		c.mu.Unlock()
	}()
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case r := <-c.reads:
		if r.err != nil {
			return 0, nil, r.err
		}
		return copy(p, r.b), r.from, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakeRTTConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.failWrites[addr.String()]; err != nil {
		return 0, err
	}
	c.writes = append(c.writes, fakeWrite{b: bytes.Clone(p), to: addr})
	return len(p), nil
}

func (c *fakeRTTConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeRTTConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: rttSelf.AsSlice(), Port: RTTProbePort}
}

func (c *fakeRTTConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeRTTConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeRTTConn) SetWriteDeadline(time.Time) error { return nil }

// deliver queues datagram b from from for a read.
func (c *fakeRTTConn) deliver(b []byte, from net.Addr) {
	c.reads <- fakeRead{b: bytes.Clone(b), from: from}
}

// failRead queues a read that fails with err.
func (c *fakeRTTConn) failRead(err error) {
	c.reads <- fakeRead{err: err}
}

// failWritesTo makes every write to addr fail with err, or succeed again for
// a nil err.
func (c *fakeRTTConn) failWritesTo(addr string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		delete(c.failWrites, addr)
		return
	}
	c.failWrites[addr] = err
}

// sent returns the datagrams written so far.
func (c *fakeRTTConn) sent() []fakeWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.writes)
}

// readers returns how many reads are in progress.
func (c *fakeRTTConn) readers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reading
}

func (c *fakeRTTConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// fakeListen is an rttListen that returns its results in order, and
// errAddrInUse once they are used up.
type fakeListen struct {
	mu      sync.Mutex
	results []listenResult
	calls   int
}

type listenResult struct {
	conn net.PacketConn
	err  error
}

func (l *fakeListen) listen() (net.PacketConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if len(l.results) == 0 {
		return nil, errAddrInUse
	}
	r := l.results[0]
	l.results = l.results[1:]
	if r.err != nil {
		return nil, r.err
	}
	return r.conn, nil
}

func (l *fakeListen) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// rttHarness is a manager under test of the round-trip probe: a
// statsController device, a fake clock at selectionStart, a debug log, the
// node at rttSelf in rttMesh, and the socket its rounds hold, closed when the
// test ends.
type rttHarness struct {
	mgr    *Manager
	ctrl   *statsController
	clock  *fakeClock
	logs   *syncBuffer
	listen *fakeListen
	sock   rttSocket
}

// newRTTHarness returns a harness whose rttListen hands out results in order.
func newRTTHarness(t *testing.T, results ...listenResult) *rttHarness {
	t.Helper()
	h := &rttHarness{
		ctrl:   &statsController{},
		clock:  &fakeClock{now: selectionStart},
		logs:   &syncBuffer{},
		listen: &fakeListen{results: results},
	}
	h.mgr = NewManager(h.ctrl, Config{}, slogTextLogger(h.logs))
	h.mgr.now = h.clock.Now
	h.mgr.meshPrefix = rttMesh
	h.mgr.meshIP = rttSelf
	h.mgr.rttListen = h.listen.listen
	t.Cleanup(h.sock.close)
	return h
}

// on returns a listen result that hands out conn.
func on(conn net.PacketConn) listenResult {
	return listenResult{conn: conn}
}

// round runs one round and fails t when it stops the probe.
func (h *rttHarness) round(t *testing.T) {
	t.Helper()
	if !h.mgr.rttRound(context.Background(), &h.sock) {
		t.Fatal("rttRound stopped the probe")
	}
}

// addMeshPeer adds node id, keyed with key byte b, at meshIP to m and returns
// its device key.
func addMeshPeer(t *testing.T, m *Manager, id string, b byte, meshIP string) [32]byte {
	t.Helper()
	key, b64 := testKey(b)
	p := keyedPeer(id, b64)
	p.MeshIP = meshIP
	if err := m.AddPeer(p); err != nil {
		t.Fatalf("AddPeer(%s): %v", id, err)
	}
	return key
}

// udpAddr returns ip:port as net.ParseIP gives it, the 16-byte form, so the
// reader has to unmap it.
func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

// asKind returns a copy of datagram b with kind as its kind.
func asKind(b []byte, kind byte) []byte {
	c := bytes.Clone(b)
	c[5] = kind
	return c
}

// probeTo returns the one probe among writes that went to meshIP's probe port.
func probeTo(t *testing.T, writes []fakeWrite, meshIP string) fakeWrite {
	t.Helper()
	to := netip.AddrPortFrom(netip.MustParseAddr(meshIP), RTTProbePort).String()
	var found []fakeWrite
	for _, w := range writes {
		if w.to.String() == to {
			found = append(found, w)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d writes to %s, want 1: %v", len(found), to, writes)
	}
	p := found[0]
	if len(p.b) != rttDatagramLen || string(p.b[:4]) != rttMagic || p.b[4] != rttVersion || p.b[5] != rttKindRequest || p.b[6] != 0 || p.b[7] != 0 {
		t.Fatalf("probe to %s = % x, want a 16-byte PXRT version 1 request with bytes 6 and 7 zero", to, p.b)
	}
	return p
}

// answer delivers the reply to probe p from meshIP's probe port.
func answer(conn *fakeRTTConn, p fakeWrite, meshIP string) {
	conn.deliver(asKind(p.b, rttKindReply), udpAddr(meshIP, RTTProbePort))
}

// barrier delivers a request from from to conn and waits for its answer. The
// reader handles datagrams in order, so every datagram delivered before it has
// been handled when barrier returns.
func barrier(t *testing.T, conn *fakeRTTConn, from string) {
	t.Helper()
	conn.mu.Lock()
	conn.barriers++
	n := conn.barriers
	conn.mu.Unlock()
	nonce := [8]byte{'b', 'a', 'r', 'r', 'i', 'e', 'r', byte(n)}
	conn.deliver(rttDatagram(rttKindRequest, nonce), udpAddr(from, RTTProbePort))
	want := rttDatagram(rttKindReply, nonce)
	to := udpAddr(from, RTTProbePort).String()
	waitUntil(t, "the answer to barrier request "+string(nonce[:]), func() bool {
		return slices.ContainsFunc(conn.sent(), func(w fakeWrite) bool {
			return bytes.Equal(w.b, want) && w.to.String() == to
		})
	})
}

// isBarrierAnswer reports whether w answers a barrier request.
func isBarrierAnswer(w fakeWrite) bool {
	return len(w.b) == rttDatagramLen && w.b[5] == rttKindReply && string(w.b[8:15]) == "barrier"
}

// waitUntil polls cond until it holds, and fails t when it does not within
// five seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// statRTT returns the RTT MeshPeerStats reports for nodeID, and fails t when
// the read fails or does not list it.
func statRTT(t *testing.T, m *Manager, nodeID string) time.Duration {
	t.Helper()
	stats, err := m.MeshPeerStats()
	if err != nil {
		t.Fatalf("MeshPeerStats: %v", err)
	}
	i := slices.IndexFunc(stats, func(s MeshPeerStat) bool { return s.NodeID == nodeID })
	if i < 0 {
		t.Fatalf("MeshPeerStats lists no %s: %+v", nodeID, stats)
	}
	return stats[i].RTT
}

// entryOf returns a copy of the table entry of nodeID and whether one exists.
func entryOf(m *Manager, nodeID string) (rttEntry, bool) {
	m.rtt.mu.Lock()
	defer m.rtt.mu.Unlock()
	e, ok := m.rtt.peers[nodeID]
	if !ok {
		return rttEntry{}, false
	}
	return *e, true
}

// unansweredOf returns the unanswered count of nodeID's entry, and fails t
// when there is none.
func unansweredOf(t *testing.T, m *Manager, nodeID string) int {
	t.Helper()
	e, ok := entryOf(m, nodeID)
	if !ok {
		t.Fatalf("no table entry for %s", nodeID)
	}
	return e.unanswered
}

// logCount returns how many lines of out carry msg at level and contain every
// part.
func logCount(out, msg, level string, parts ...string) int {
	n := 0
	for _, line := range logLines(out, msg) {
		if !strings.Contains(line, " level="+level+" ") {
			continue
		}
		if slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(line, p) }) {
			continue
		}
		n++
	}
	return n
}

// listenLoopback returns a UDP socket on 127.0.0.1 with a port the kernel
// picks, closed when the test ends. 127.0.0.1 is the only loopback address
// every CI platform has.
func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen on 127.0.0.1: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// loopbackPeer is the mesh IP every loopback manager gives its peer: the
// replies come from 127.0.0.1, so that has to be the peer's mesh IP.
var loopbackPeer = netip.MustParseAddr("127.0.0.1")

// newLoopbackManager returns a manager at mesh IP self in 127.0.0.0/8, which
// listens on conn and holds peer peerID with key byte b at 127.0.0.1, whose
// probes go to peerAddr. Its device reports a handshake with the peer that is
// fresh on the real clock. sends counts the probes it sends.
func newLoopbackManager(t *testing.T, self, peerID string, b byte, conn net.PacketConn, peerAddr net.Addr, sends *atomic.Int64) (*Manager, *statsController) {
	t.Helper()
	ctrl := &statsController{}
	m := NewManager(ctrl, Config{}, discardLogger())
	m.meshPrefix = netip.MustParsePrefix("127.0.0.0/8")
	m.meshIP = netip.MustParseAddr(self)
	key := addMeshPeer(t, m, peerID, b, loopbackPeer.String())
	ctrl.stats = []PeerStat{{
		PublicKey:     key,
		Endpoint:      netip.MustParseAddrPort("198.51.100.9:51820"),
		LastHandshake: time.Now(),
	}}
	m.rttListen = (&fakeListen{results: []listenResult{on(conn)}}).listen
	m.rttAddr = func(ip netip.Addr) net.Addr {
		if sends != nil {
			sends.Add(1)
		}
		if ip != loopbackPeer {
			t.Errorf("probe to %s, want one to %s", ip, loopbackPeer)
		}
		return peerAddr
	}
	return m, ctrl
}

// ---------------------------------------------------------------------------
// Datagram and reader
// ---------------------------------------------------------------------------

func TestRTTProbe_AnswersARequestAtItsSource(t *testing.T) {
	mgr := NewManager(&statsController{}, Config{}, discardLogger())
	mgr.meshPrefix = netip.MustParsePrefix("127.0.0.0/8")
	mgr.meshIP = netip.MustParseAddr("127.0.0.10")
	server := listenLoopback(t)
	mgr.rttListen = (&fakeListen{results: []listenResult{on(server)}}).listen

	var s rttSocket
	t.Cleanup(s.close)
	if !mgr.rttRound(context.Background(), &s) {
		t.Fatal("rttRound stopped the probe")
	}

	client := listenLoopback(t)
	request := rttDatagram(rttKindRequest, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if _, err := client.WriteTo(request, server.LocalAddr()); err != nil {
		t.Fatalf("send the request: %v", err)
	}
	// The deadline bounds a test that would otherwise hang; it waits for
	// nothing.
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, from, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read the answer at the request's source %s: %v", client.LocalAddr(), err)
	}
	if want := asKind(request, rttKindReply); !bytes.Equal(buf[:n], want) {
		t.Errorf("answer = % x, want % x", buf[:n], want)
	}
	if from.String() != server.LocalAddr().String() {
		t.Errorf("answer from %s, want the probe socket %s", from, server.LocalAddr())
	}
}

func TestRTTProbe_DropsMalformedDatagrams(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	h.ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}
	h.round(t)
	probe := probeTo(t, conn.sent(), "10.0.0.2")

	peer := udpAddr("10.0.0.2", RTTProbePort)
	reply := asKind(probe.b, rttKindReply)
	type datagram struct {
		name string
		b    []byte
		from net.Addr
	}
	var drops []datagram
	// Each malformed shape comes as a request, which an answer would betray,
	// and as a reply to the outstanding probe, which a value would betray.
	for _, base := range []struct {
		kind string
		b    []byte
	}{{"request", probe.b}, {"reply", reply}} {
		short := bytes.Clone(base.b[:15])
		long := append(bytes.Clone(base.b), 0)
		magic := bytes.Clone(base.b)
		copy(magic, "PXRX")
		version := bytes.Clone(base.b)
		version[4] = 2
		drops = append(drops,
			datagram{"15-byte " + base.kind, short, peer},
			datagram{"17-byte " + base.kind, long, peer},
			datagram{"PXRX " + base.kind, magic, peer},
			datagram{"version 2 " + base.kind, version, peer},
			datagram{base.kind + " from an IPv6 source", base.b, udpAddr("fd00::2", RTTProbePort)},
			datagram{base.kind + " from a source that is not UDP", base.b, &net.IPAddr{IP: net.ParseIP("10.0.0.2")}},
		)
	}
	drops = append(drops,
		datagram{"kind 3", asKind(probe.b, 3), peer},
		datagram{"request from outside the mesh prefix", probe.b, udpAddr("10.0.1.2", RTTProbePort)},
	)

	h.clock.Set(selectionStart.Add(3 * time.Millisecond))
	for _, d := range drops {
		conn.deliver(d.b, d.from)
	}
	barrier(t, conn, "10.0.0.2")

	for _, w := range conn.sent() {
		if !bytes.Equal(w.b, probe.b) && !isBarrierAnswer(w) {
			t.Errorf("wrote % x to %s, want no answer to a malformed datagram", w.b, w.to)
		}
	}
	if n := len(conn.sent()); n != 2 {
		t.Errorf("%d writes, want the probe and the barrier's answer", n)
	}
	if got := statRTT(t, h.mgr, "node-a"); got != 0 {
		t.Errorf("RTT = %v after the malformed datagrams, want 0", got)
	}

	// The well-formed reply the malformed ones were made of counts, so the
	// drops above are the reader's checks and not a probe nothing answers.
	answer(conn, probe, "10.0.0.2")
	waitUntil(t, "the value of the well-formed reply", func() bool { return statRTT(t, h.mgr, "node-a") == 3*time.Millisecond })
}

func TestRTTProbe_DropsRepliesThatAnswerNoProbe(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	keyA := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	keyB := addMeshPeer(t, h.mgr, "node-b", 0x0b, "10.0.0.3")
	h.ctrl.stats = []PeerStat{handshakeAt(keyA, selectionStart), handshakeAt(keyB, selectionStart)}
	h.round(t)
	probeA := probeTo(t, conn.sent(), "10.0.0.2")
	probeB := probeTo(t, conn.sent(), "10.0.0.3")

	// node-b answers, so no probe to it is outstanding any more.
	h.clock.Set(selectionStart.Add(2 * time.Millisecond))
	answer(conn, probeB, "10.0.0.3")
	waitUntil(t, "node-b's value", func() bool { return statRTT(t, h.mgr, "node-b") == 2*time.Millisecond })

	h.clock.Set(selectionStart.Add(4 * time.Millisecond))
	otherNonce := asKind(probeA.b, rttKindReply)
	otherNonce[15] ^= 0xff
	conn.deliver(otherNonce, udpAddr("10.0.0.2", RTTProbePort))
	// node-b's reply again, for which no probe is outstanding.
	answer(conn, probeB, "10.0.0.3")
	// node-a's reply from a mesh address no probe went to.
	answer(conn, probeA, "10.0.0.9")
	// node-a's reply, a nanosecond past the timeout.
	h.clock.Set(selectionStart.Add(rttProbeTimeout + time.Nanosecond))
	answer(conn, probeA, "10.0.0.2")
	barrier(t, conn, "10.0.0.9")

	if got := statRTT(t, h.mgr, "node-a"); got != 0 {
		t.Errorf("node-a RTT = %v, want 0: no reply answered its probe", got)
	}
	if got := statRTT(t, h.mgr, "node-b"); got != 2*time.Millisecond {
		t.Errorf("node-b RTT = %v, want the 2ms of its one answer", got)
	}
	sent := conn.sent()
	if len(sent) != 3 || !isBarrierAnswer(sent[2]) {
		t.Errorf("writes = %v, want the two probes and the barrier's answer, no datagram for a reply", sent)
	}

	// The late reply left node-a's probe outstanding, so the next round counts
	// it as unanswered.
	h.round(t)
	if n := unansweredOf(t, h.mgr, "node-a"); n != 1 {
		t.Errorf("node-a unanswered = %d after the next round, want 1", n)
	}
}

func TestRTTProbe_CountsAReplyAtTheTimeout(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	h.ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}
	h.round(t)

	h.clock.Set(selectionStart.Add(rttProbeTimeout))
	answer(conn, probeTo(t, conn.sent(), "10.0.0.2"), "10.0.0.2")
	waitUntil(t, "a value of rttProbeTimeout", func() bool { return statRTT(t, h.mgr, "node-a") == rttProbeTimeout })
}

func TestRTTProbe_AnAnswerAlwaysLeavesAValue(t *testing.T) {
	// Zero means no value, so a reply read at the send instant, as under a
	// clock that did not advance between the two, still leaves one.
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	h.ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}
	h.round(t)

	answer(conn, probeTo(t, conn.sent(), "10.0.0.2"), "10.0.0.2")
	waitUntil(t, "a value of 1ns", func() bool { return statRTT(t, h.mgr, "node-a") == time.Nanosecond })
	if n := unansweredOf(t, h.mgr, "node-a"); n != 0 {
		t.Errorf("unanswered = %d after the answer, want 0", n)
	}
}

func TestRTTProbe_ReadErrors(t *testing.T) {
	readErr := errors.New("wsarecvfrom:connection-reset")

	t.Run("one failed read", func(t *testing.T) {
		conn := newFakeRTTConn()
		h := newRTTHarness(t, on(conn))
		h.round(t)

		conn.failRead(readErr)
		barrier(t, conn, "10.0.0.2")
		if n := logCount(h.logs.String(), "wireguard: rtt probe read failed", "DEBUG", "component=wireguard", "error=wsarecvfrom:connection-reset"); n != 1 {
			t.Errorf("%d read failed lines at Debug with the error, want 1:\n%s", n, h.logs.String())
		}
		if conn.isClosed() {
			t.Error("the socket is closed after one failed read")
		}
	})

	t.Run("a good read resets the count", func(t *testing.T) {
		conn := newFakeRTTConn()
		h := newRTTHarness(t, on(conn))
		h.round(t)

		for range 2 {
			for range rttMaxReadErrors - 1 {
				conn.failRead(readErr)
			}
			barrier(t, conn, "10.0.0.2")
		}
		if conn.isClosed() {
			t.Error("the socket is closed after nine failed reads twice, a good read between them")
		}
	})

	t.Run("ten in a row", func(t *testing.T) {
		first, second := newFakeRTTConn(), newFakeRTTConn()
		h := newRTTHarness(t, on(first), on(second))
		h.round(t)
		done := h.sock.done

		for range rttMaxReadErrors {
			first.failRead(readErr)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the reader did not end after ten failed reads in a row")
		}
		if !first.isClosed() {
			t.Error("the reader ended without closing the socket")
		}
		if n := logCount(h.logs.String(), "wireguard: rtt probe read failed", "DEBUG", "component=wireguard"); n != rttMaxReadErrors {
			t.Errorf("%d read failed lines, want %d", n, rttMaxReadErrors)
		}

		h.round(t)
		if n := h.listen.callCount(); n != 2 {
			t.Fatalf("listen calls = %d, want a second listen in the next round", n)
		}
		if h.sock.conn != second {
			t.Fatal("the round holds another socket than the one it listened on")
		}
		barrier(t, second, "10.0.0.2")
	})
}

func TestRTTProbe_AnswerWriteFails(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	h.round(t)

	conn.failWritesTo("10.0.0.2:7911", errors.New("sendto:network-unreachable"))
	conn.deliver(rttDatagram(rttKindRequest, [8]byte{9}), udpAddr("10.0.0.2", RTTProbePort))
	waitUntil(t, "the answer failed line", func() bool {
		return logCount(h.logs.String(), "wireguard: rtt probe answer failed", "DEBUG", "component=wireguard", "error=sendto:network-unreachable") == 1
	})

	// The reader goes on: it answers the next request.
	conn.failWritesTo("10.0.0.2:7911", nil)
	barrier(t, conn, "10.0.0.2")
	if conn.isClosed() {
		t.Error("the socket is closed after a failed answer")
	}
}

// ---------------------------------------------------------------------------
// Round and value
// ---------------------------------------------------------------------------

func TestRTTProbe_TwoManagersMeasureEachOther(t *testing.T) {
	connA, connB := listenLoopback(t), listenLoopback(t)
	a, _ := newLoopbackManager(t, "127.0.0.10", "node-b", 0x0b, connA, connB.LocalAddr(), nil)
	b, _ := newLoopbackManager(t, "127.0.0.11", "node-a", 0x0a, connB, connA.LocalAddr(), nil)
	var sa, sb rttSocket
	t.Cleanup(sa.close)
	t.Cleanup(sb.close)

	// Each socket is bound before either round, so a probe that arrives
	// before the other's reader runs waits in the socket.
	if !a.rttRound(context.Background(), &sa) || !b.rttRound(context.Background(), &sb) {
		t.Fatal("rttRound stopped the probe")
	}
	waitUntil(t, "a value on both managers", func() bool {
		return statRTT(t, a, "node-b") > 0 && statRTT(t, b, "node-a") > 0
	})
}

func TestRTTProbe_RoundWithoutPeers(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))

	before, err := h.mgr.MeshPeerStats()
	if err != nil {
		t.Fatalf("MeshPeerStats: %v", err)
	}
	h.round(t)
	after, err := h.mgr.MeshPeerStats()
	if err != nil {
		t.Fatalf("MeshPeerStats: %v", err)
	}

	if sent := conn.sent(); len(sent) != 0 {
		t.Errorf("writes = %v, want none", sent)
	}
	if after == nil || len(after) != 0 {
		t.Errorf("MeshPeerStats() = %#v after the round, want an empty non-nil slice", after)
	}
	assertMeshPeerStats(t, after, before)
}

func TestRTTProbe_SendsNoProbeToAPeerItDoesNotTake(t *testing.T) {
	_, b64X := testKey(0x0e)
	for _, tc := range []struct {
		name string
		// add puts node-x on h and returns its device stat.
		add func(t *testing.T, h *rttHarness) PeerStat
	}{
		{"zero LastHandshake", func(t *testing.T, h *rttHarness) PeerStat {
			key := addMeshPeer(t, h.mgr, "node-x", 0x0e, "10.0.0.7")
			return handshakeAt(key, time.Time{})
		}},
		{"handshake older than 180s", func(t *testing.T, h *rttHarness) PeerStat {
			key := addMeshPeer(t, h.mgr, "node-x", 0x0e, "10.0.0.7")
			return handshakeAt(key, selectionStart.Add(-connectedHandshakeAge-time.Second))
		}},
		{"handshake exactly 180s old", func(t *testing.T, h *rttHarness) PeerStat {
			key := addMeshPeer(t, h.mgr, "node-x", 0x0e, "10.0.0.7")
			return handshakeAt(key, selectionStart.Add(-connectedHandshakeAge))
		}},
		{"no dial state", func(t *testing.T, h *rttHarness) PeerStat {
			key, _ := testKey(0x0e)
			h.mgr.peers.Add("node-x", b64X)
			return handshakeAt(key, selectionStart)
		}},
		{"MeshIP that does not parse", func(t *testing.T, h *rttHarness) PeerStat {
			key := addMeshPeer(t, h.mgr, "node-x", 0x0e, "not-an-ip")
			return handshakeAt(key, selectionStart)
		}},
		{"IPv6 MeshIP", func(t *testing.T, h *rttHarness) PeerStat {
			key := addMeshPeer(t, h.mgr, "node-x", 0x0e, "fd00::7")
			return handshakeAt(key, selectionStart)
		}},
		{"MeshIP outside the mesh prefix", func(t *testing.T, h *rttHarness) PeerStat {
			key := addMeshPeer(t, h.mgr, "node-x", 0x0e, "10.0.1.7")
			return handshakeAt(key, selectionStart)
		}},
		{"the node's own MeshIP", func(t *testing.T, h *rttHarness) PeerStat {
			key := addMeshPeer(t, h.mgr, "node-x", 0x0e, rttSelf.String())
			return handshakeAt(key, selectionStart)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newFakeRTTConn()
			h := newRTTHarness(t, on(conn))
			// node-ok is a peer the round takes, so the round demonstrably
			// sends.
			keyOK := addMeshPeer(t, h.mgr, "node-ok", 0x0a, "10.0.0.5")
			h.ctrl.stats = []PeerStat{handshakeAt(keyOK, selectionStart), tc.add(t, h)}
			h.round(t)

			sent := conn.sent()
			if len(sent) != 1 {
				t.Fatalf("writes = %v, want only node-ok's probe", sent)
			}
			probeTo(t, sent, "10.0.0.5")
			if _, ok := entryOf(h.mgr, "node-x"); ok {
				t.Error("node-x has a table entry, want none for a peer the round does not take")
			}
		})
	}
}

func TestRTTProbe_KeepsAValueThroughTwoUnansweredProbes(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	at := selectionStart
	round := func() {
		t.Helper()
		h.ctrl.stats = []PeerStat{handshakeAt(key, at)}
		h.clock.Set(at)
		h.round(t)
	}

	round()
	h.clock.Set(at.Add(7 * time.Millisecond))
	answer(conn, conn.sent()[0], "10.0.0.2")
	waitUntil(t, "the first value", func() bool { return statRTT(t, h.mgr, "node-a") == 7*time.Millisecond })

	// Step 4 counts a probe as unanswered at the round after the one that
	// sent it. Round 2 sends a probe that goes unanswered, as do rounds 3 and
	// 4, so "unchanged after the first and the second round and zero after
	// the third" are the rounds that count the first, the second and the third
	// unanswered probe: rounds 3, 4 and 5.
	at = at.Add(30 * time.Second)
	round()
	if got, n := statRTT(t, h.mgr, "node-a"), unansweredOf(t, h.mgr, "node-a"); got != 7*time.Millisecond || n != 0 {
		t.Fatalf("after round 2: RTT = %v, unanswered = %d, want 7ms and 0", got, n)
	}
	for i, want := range []time.Duration{7 * time.Millisecond, 7 * time.Millisecond, 0} {
		at = at.Add(30 * time.Second)
		round()
		got, n := statRTT(t, h.mgr, "node-a"), unansweredOf(t, h.mgr, "node-a")
		if got != want || n != i+1 {
			t.Errorf("after the round that counts unanswered probe %d: RTT = %v, unanswered = %d, want %v and %d", i+1, got, n, want, i+1)
		}
	}

	sent := conn.sent()
	if len(sent) != 5 {
		t.Fatalf("%d probes, want one per round", len(sent))
	}
	h.clock.Set(at.Add(9 * time.Millisecond))
	answer(conn, sent[4], "10.0.0.2")
	waitUntil(t, "a value again", func() bool { return statRTT(t, h.mgr, "node-a") == 9*time.Millisecond })
	if n := unansweredOf(t, h.mgr, "node-a"); n != 0 {
		t.Errorf("unanswered = %d after the answer, want 0", n)
	}
}

func TestRTTProbe_DropsTheValueWhenTheEndpointChanges(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	h.ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}
	h.round(t)
	h.clock.Set(selectionStart.Add(7 * time.Millisecond))
	answer(conn, conn.sent()[0], "10.0.0.2")
	waitUntil(t, "the first value", func() bool { return statRTT(t, h.mgr, "node-a") == 7*time.Millisecond })

	moved := handshakeAt(key, selectionStart)
	moved.Endpoint = netip.MustParseAddrPort("203.0.113.7:51820")
	h.ctrl.stats = []PeerStat{moved}
	h.clock.Set(selectionStart.Add(30 * time.Second))
	h.round(t)
	if got := statRTT(t, h.mgr, "node-a"); got != 0 {
		t.Fatalf("RTT = %v after the round that saw the new endpoint, want 0", got)
	}

	h.clock.Set(selectionStart.Add(30*time.Second + 4*time.Millisecond))
	answer(conn, conn.sent()[1], "10.0.0.2")
	waitUntil(t, "the value over the new endpoint", func() bool { return statRTT(t, h.mgr, "node-a") == 4*time.Millisecond })

	// The value was measured over the new endpoint, so a round that sees it
	// again keeps the value.
	h.clock.Set(selectionStart.Add(60 * time.Second))
	h.round(t)
	if got := statRTT(t, h.mgr, "node-a"); got != 4*time.Millisecond {
		t.Errorf("RTT = %v after a round on the same endpoint, want 4ms", got)
	}
}

func TestRTTProbe_DeletesTheEntryOfAPeerItNoLongerTakes(t *testing.T) {
	for _, tc := range []struct {
		name string
		gone func(key [32]byte) []PeerStat
	}{
		{"removed from the device read", func([32]byte) []PeerStat { return nil }},
		{"handshake gone stale", func(key [32]byte) []PeerStat {
			return []PeerStat{handshakeAt(key, selectionStart.Add(-connectedHandshakeAge))}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newFakeRTTConn()
			h := newRTTHarness(t, on(conn))
			key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
			fresh := []PeerStat{handshakeAt(key, selectionStart)}
			h.ctrl.stats = fresh
			h.round(t)
			h.clock.Set(selectionStart.Add(7 * time.Millisecond))
			answer(conn, conn.sent()[0], "10.0.0.2")
			waitUntil(t, "the first value", func() bool { return statRTT(t, h.mgr, "node-a") == 7*time.Millisecond })

			h.ctrl.stats = tc.gone(key)
			h.round(t)
			if _, ok := entryOf(h.mgr, "node-a"); ok {
				t.Fatal("node-a's entry is still there after a round that did not take it")
			}

			// node-a comes back under the same node ID without a value.
			h.ctrl.stats = fresh
			if got := statRTT(t, h.mgr, "node-a"); got != 0 {
				t.Errorf("RTT = %v when the peer comes back, want 0", got)
			}
			h.round(t)
			e, ok := entryOf(h.mgr, "node-a")
			if !ok || e.value != 0 || e.unanswered != 0 || !e.probe.sent {
				t.Errorf("entry after the next round = %+v (exists %v), want a new one without a value, with one probe outstanding", e, ok)
			}
		})
	}
}

func TestRTTProbe_ListenFails(t *testing.T) {
	first, second := newFakeRTTConn(), newFakeRTTConn()
	h := newRTTHarness(t, on(first), listenResult{err: errAddrInUse}, listenResult{err: errAddrInUse}, listenResult{err: errAddrInUse}, on(second))
	key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	h.ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}

	h.round(t)
	h.clock.Set(selectionStart.Add(7 * time.Millisecond))
	answer(first, first.sent()[0], "10.0.0.2")
	waitUntil(t, "the first value", func() bool { return statRTT(t, h.mgr, "node-a") == 7*time.Millisecond })
	// A second probe is outstanding when the socket goes away.
	h.round(t)
	for range rttMaxReadErrors {
		first.failRead(errors.New("read:failed"))
	}
	select {
	case <-h.sock.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader did not end after ten failed reads in a row")
	}

	const msg = "wireguard: rtt probe listen failed"
	fields := []string{"component=wireguard", "address=10.0.0.1:7911", `error="listen udp4 10.0.0.1:7911: bind: address already in use"`}
	for i, want := range []struct {
		rtt         time.Duration
		warn, debug int
	}{
		{7 * time.Millisecond, 1, 0},
		{7 * time.Millisecond, 1, 1},
		{0, 1, 2},
	} {
		h.round(t)
		logs := h.logs.String()
		warn, debug := logCount(logs, msg, "WARN", fields...), logCount(logs, msg, "DEBUG", fields...)
		got, n := statRTT(t, h.mgr, "node-a"), unansweredOf(t, h.mgr, "node-a")
		if got != want.rtt || n != i+1 || warn != want.warn || debug != want.debug {
			t.Errorf("after failing round %d: RTT = %v, unanswered = %d, %d Warn and %d Debug lines; want %v, %d, %d and %d:\n%s",
				i+1, got, n, warn, debug, want.rtt, i+1, want.warn, want.debug, logs)
		}
	}
	if n := len(first.sent()); n != 2 {
		t.Errorf("%d writes on the first socket, want its two probes and none while the listen failed", n)
	}

	h.round(t)
	probeTo(t, second.sent(), "10.0.0.2")
	// The probe that was outstanding when the socket went away was never
	// answered either: the failed rounds left it recorded, and the round that
	// listens again counts it as step 4 counts any outstanding probe.
	if n := unansweredOf(t, h.mgr, "node-a"); n != rttMaxUnanswered+1 {
		t.Errorf("unanswered = %d after the listen came back, want %d", n, rttMaxUnanswered+1)
	}
	if n := logCount(h.logs.String(), msg, "WARN"); n != 1 {
		t.Errorf("%d Warn listen failed lines in all, want 1", n)
	}
}

func TestRTTProbe_ControllerCannotReadPeerStats(t *testing.T) {
	logs := &syncBuffer{}
	conn := newFakeRTTConn()
	mgr := NewManager(&mockController{}, Config{}, slogTextLogger(logs))
	mgr.meshPrefix = rttMesh
	mgr.meshIP = rttSelf
	mgr.rttListen = (&fakeListen{results: []listenResult{on(conn)}}).listen

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.RunRTTProbe(ctx, 10*time.Millisecond); err != nil {
		t.Fatalf("RunRTTProbe() = %v, want nil", err)
	}
	if ctx.Err() != nil {
		t.Fatal("RunRTTProbe returned only when its context ended, want it to return on its own")
	}
	if n := logCount(logs.String(), "wireguard: rtt probe unavailable, the controller cannot read peer stats", "INFO", "component=wireguard"); n != 1 {
		t.Errorf("%d unavailable lines at Info, want 1:\n%s", n, logs.String())
	}
	if !conn.isClosed() || conn.readers() != 0 {
		t.Errorf("socket closed = %v, reads in progress = %d, want the socket closed and no reader", conn.isClosed(), conn.readers())
	}
}

func TestRTTProbe_RoundFailsOnAReadError(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	keyA := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	keyB := addMeshPeer(t, h.mgr, "node-b", 0x0b, "10.0.0.3")
	h.ctrl.stats = []PeerStat{handshakeAt(keyA, selectionStart), handshakeAt(keyB, selectionStart)}
	h.round(t)
	h.clock.Set(selectionStart.Add(7 * time.Millisecond))
	answer(conn, probeTo(t, conn.sent(), "10.0.0.2"), "10.0.0.2")
	waitUntil(t, "node-a's value", func() bool { return statRTT(t, h.mgr, "node-a") == 7*time.Millisecond })
	beforeA, _ := entryOf(h.mgr, "node-a")
	beforeB, _ := entryOf(h.mgr, "node-b")

	h.ctrl.err = errors.New("netlink:busy")
	h.round(t)
	h.ctrl.err = nil

	if n := logCount(h.logs.String(), "wireguard: rtt probe round failed", "WARN", "component=wireguard", `error="wireguard: mesh peer stats: netlink:busy"`); n != 1 {
		t.Errorf("%d round failed lines at Warn with the error, want 1:\n%s", n, h.logs.String())
	}
	if n := len(conn.sent()); n != 2 {
		t.Errorf("%d writes, want the first round's two probes and none from the failed round", n)
	}
	afterA, _ := entryOf(h.mgr, "node-a")
	afterB, _ := entryOf(h.mgr, "node-b")
	if afterA != beforeA || afterB != beforeB {
		t.Errorf("entries after the failed round = %+v, %+v; want them as they were, %+v, %+v", afterA, afterB, beforeA, beforeB)
	}
	if got := statRTT(t, h.mgr, "node-a"); got != 7*time.Millisecond {
		t.Errorf("node-a RTT = %v, want the 7ms it held", got)
	}
}

func TestRTTProbe_SendFails(t *testing.T) {
	conn := newFakeRTTConn()
	h := newRTTHarness(t, on(conn))
	keyA := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
	keyB := addMeshPeer(t, h.mgr, "node-b", 0x0b, "10.0.0.3")
	h.ctrl.stats = []PeerStat{handshakeAt(keyA, selectionStart), handshakeAt(keyB, selectionStart)}

	const msg = "wireguard: rtt probe send failed"
	sendErr := errors.New("sendto:no-route")
	fieldsA := []string{"component=wireguard", "peer_id=node-a", "mesh_ip=10.0.0.2", "error=sendto:no-route"}
	fieldsB := []string{"component=wireguard", "peer_id=node-b", "mesh_ip=10.0.0.3", "error=sendto:no-route"}
	check := func(step string, warnA, debugA, unansweredA, warnB, debugB int) {
		t.Helper()
		logs := h.logs.String()
		got := []int{
			logCount(logs, msg, "WARN", fieldsA...), logCount(logs, msg, "DEBUG", fieldsA...), unansweredOf(t, h.mgr, "node-a"),
			logCount(logs, msg, "WARN", fieldsB...), logCount(logs, msg, "DEBUG", fieldsB...),
		}
		want := []int{warnA, debugA, unansweredA, warnB, debugB}
		if !slices.Equal(got, want) {
			t.Errorf("%s: node-a Warn, Debug, unanswered and node-b Warn, Debug = %v, want %v:\n%s", step, got, want, logs)
		}
	}

	conn.failWritesTo("10.0.0.2:7911", sendErr)
	h.round(t)
	check("first failed send", 1, 0, 1, 0, 0)
	if e, _ := entryOf(h.mgr, "node-a"); e.probe.sent {
		t.Error("the failed send left its probe outstanding")
	}
	probeTo(t, conn.sent(), "10.0.0.3")

	h.round(t)
	check("second failed send", 1, 1, 2, 0, 0)

	// node-b's first failure is its own first, whatever node-a's state.
	conn.failWritesTo("10.0.0.3:7911", sendErr)
	h.round(t)
	check("third failed send of node-a, first of node-b", 1, 2, 3, 1, 0)

	// A send that goes out resets the failing state, so the next failure is
	// logged at Warn again.
	conn.failWritesTo("10.0.0.2:7911", nil)
	h.round(t)
	check("a send that went out", 1, 2, 3, 1, 1)
	conn.failWritesTo("10.0.0.2:7911", sendErr)
	h.round(t)
	// The probe that went out is still outstanding and counts too.
	check("a failed send after one that went out", 2, 2, 5, 1, 2)
}

func TestRTTProbe_RunRTTProbe(t *testing.T) {
	t.Run("interval 0", func(t *testing.T) {
		h := newRTTHarness(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errc := make(chan error, 1)
		go func() { errc <- h.mgr.RunRTTProbe(ctx, 0) }()

		waitUntil(t, "the started line", func() bool {
			return logCount(h.logs.String(), "wireguard: rtt probe started", "INFO", "component=wireguard", "interval=30s", "port=7911") == 1
		})
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("RunRTTProbe() = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RunRTTProbe did not return after its context ended")
		}
		// The first round of a 30 s interval runs after 15 s.
		if n := h.listen.callCount(); n != 0 {
			t.Errorf("listen calls = %d, want none before the first round", n)
		}
	})

	t.Run("cancel closes the socket", func(t *testing.T) {
		conn := newFakeRTTConn()
		h := newRTTHarness(t, on(conn))
		key := addMeshPeer(t, h.mgr, "node-a", 0x0a, "10.0.0.2")
		h.ctrl.stats = []PeerStat{handshakeAt(key, selectionStart)}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errc := make(chan error, 1)
		go func() { errc <- h.mgr.RunRTTProbe(ctx, 10*time.Millisecond) }()

		waitUntil(t, "two rounds", func() bool { return len(conn.sent()) >= 2 })
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("RunRTTProbe() = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RunRTTProbe did not return after its context ended")
		}
		if !conn.isClosed() || conn.readers() != 0 {
			t.Errorf("socket closed = %v, reads in progress = %d, want the socket closed and no reader", conn.isClosed(), conn.readers())
		}
		if n := h.listen.callCount(); n != 1 {
			t.Errorf("listen calls = %d, want one socket for every round", n)
		}
	})
}

func TestRTTProbe_MeshPeerStatsWhileRoundsRun(t *testing.T) {
	var sendsA, sendsB atomic.Int64
	connA, connB := listenLoopback(t), listenLoopback(t)
	a, _ := newLoopbackManager(t, "127.0.0.10", "node-b", 0x0b, connA, connB.LocalAddr(), &sendsA)
	b, _ := newLoopbackManager(t, "127.0.0.11", "node-a", 0x0a, connB, connA.LocalAddr(), &sendsB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for _, m := range []*Manager{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.RunRTTProbe(ctx, 5*time.Millisecond); err != nil {
				t.Errorf("RunRTTProbe() = %v, want nil", err)
			}
		}()
	}

	waitUntil(t, "values on both managers after several rounds", func() bool {
		return statRTT(t, a, "node-b") > 0 && statRTT(t, b, "node-a") > 0 && sendsA.Load() >= 5 && sendsB.Load() >= 5
	})
	cancel()
	wg.Wait()
}

func TestRTTProbePortIsPolicyExempt(t *testing.T) {
	// The policy backends pass the probe's port ahead of the policy rules.
	// They cannot import this package, so this test keeps the two constants in
	// step: a probe to a port the backends do not pass would be dropped under
	// any policy without a rule for it.
	if RTTProbePort != policy.RTTProbePort {
		t.Errorf("RTTProbePort = %d, want policy.RTTProbePort %d", RTTProbePort, policy.RTTProbePort)
	}
}

func TestRTTProbe_DefaultListenRefusesAMeshIPThatIsNotIPv4(t *testing.T) {
	for _, tc := range []struct {
		ip   netip.Addr
		want string
	}{
		{netip.Addr{}, "wireguard: rtt probe: mesh ip invalid IP is not IPv4"},
		{netip.MustParseAddr("fd00::1"), "wireguard: rtt probe: mesh ip fd00::1 is not IPv4"},
	} {
		mgr := NewManager(&statsController{}, Config{}, discardLogger())
		mgr.meshIP = tc.ip
		conn, err := mgr.rttListen()
		if conn != nil {
			_ = conn.Close()
			t.Errorf("rttListen() with mesh ip %v listened on %s, want no socket", tc.ip, conn.LocalAddr())
		}
		if err == nil || err.Error() != tc.want {
			t.Errorf("rttListen() with mesh ip %v = %v, want %q", tc.ip, err, tc.want)
		}
	}
}

func TestRTTProbe_DefaultAddrIsTheProbePortOfTheMeshIP(t *testing.T) {
	mgr := NewManager(&statsController{}, Config{}, discardLogger())
	addr, ok := mgr.rttAddr(netip.MustParseAddr("10.0.0.2")).(*net.UDPAddr)
	if !ok || addr.String() != "10.0.0.2:7911" {
		t.Errorf("rttAddr(10.0.0.2) = %v, want the UDP address 10.0.0.2:7911", addr)
	}
}

func TestManager_Setup_StoresTheMeshIP(t *testing.T) {
	for _, tc := range []struct {
		meshIP string
		want   netip.Addr
	}{
		{"10.0.0.1", netip.MustParseAddr("10.0.0.1")},
		{"not-an-ip", netip.Addr{}},
	} {
		mgr := NewManager(&mockController{}, Config{}, discardLogger())
		identity := &registration.NodeIdentity{NodeID: "node-1", MeshIP: tc.meshIP, PrivateKey: make([]byte, 32)}
		if err := mgr.Setup(context.Background(), identity); err != nil {
			t.Fatalf("Setup(%s): %v", tc.meshIP, err)
		}
		if mgr.meshIP != tc.want {
			t.Errorf("meshIP after Setup(%s) = %v, want %v", tc.meshIP, mgr.meshIP, tc.want)
		}
	}
}
