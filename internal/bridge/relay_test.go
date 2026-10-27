package bridge

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// relayLog is a debug-level log sink that is safe to read while the relay's
// goroutines write to it.
type relayLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *relayLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *relayLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *relayLog) count(substr string) int {
	return strings.Count(l.String(), substr)
}

// waitFor waits up to 2 s for substr to appear n times in the log.
func (l *relayLog) waitFor(t *testing.T, substr string, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for l.count(substr) < n {
		if time.Now().After(deadline) {
			t.Fatalf("log has %d of %d %q:\n%s", l.count(substr), n, substr, l.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newRelayLogger() (*slog.Logger, *relayLog) {
	logs := &relayLog{}
	return slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), logs
}

// loopbackRelayListen binds 127.0.0.1 on an ephemeral port, whatever port it
// is asked for. Sending to the wildcard address works on Linux only.
func loopbackRelayListen(int) (relayConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// allowAll is a handshakeLimiter that limits nothing. Every test socket shares
// 127.0.0.1, so wireguard-go's burst of 5 would cap a test's handshakes.
type allowAll struct{}

func (allowAll) Allow(netip.Addr) bool { return true }
func (allowAll) Close()                {}

// relayClock is a settable clock for Relay.now.
type relayClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *relayClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *relayClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var relayStart = time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)

// testRelay returns a relay on a loopback socket with a settable clock and no
// rate limit, not yet configured. Its Stop runs on cleanup.
func testRelay(t *testing.T) (*Relay, *relayLog, *relayClock) {
	t.Helper()
	logger, logs := newRelayLogger()
	r := NewRelay(logger)
	clock := &relayClock{now: relayStart}
	r.listen = loopbackRelayListen
	r.newLimiter = func() handshakeLimiter { return allowAll{} }
	r.now = clock.Now
	t.Cleanup(func() { _ = r.Stop() })
	return r, logs, clock
}

// wgPeer is a peer of the relay: a node ID, a public key, and a loopback
// socket standing in for its WireGuard. gen builds the mac1 of messages
// addressed to this peer.
type wgPeer struct {
	id   string
	key  device.NoisePublicKey
	conn *net.UDPConn
	gen  *device.CookieGenerator
}

func newWGPeer(t *testing.T, id string, seed byte) *wgPeer {
	t.Helper()
	p := &wgPeer{id: id, gen: new(device.CookieGenerator)}
	for i := range p.key {
		p.key[i] = seed + byte(i)
	}
	p.gen.Init(p.key)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	p.conn = conn
	return p
}

func (p *wgPeer) snapshot() api.SnapshotPeer {
	return api.SnapshotPeer{NodeID: p.id, PublicKey: base64.StdEncoding.EncodeToString(p.key[:])}
}

func (p *wgPeer) addr() netip.AddrPort {
	return p.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func snapshotPeers(peers ...*wgPeer) []api.SnapshotPeer {
	out := make([]api.SnapshotPeer, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.snapshot())
	}
	return out
}

// initiationFor returns a handshake initiation with sender index sender whose
// mac1 is keyed to to's public key.
func initiationFor(sender uint32, to *wgPeer) []byte {
	msg := wgDatagram(device.MessageInitiationType, device.MessageInitiationSize, sender, 0)
	msg[20] = byte(sender) // vary the body, so two initiations never compare equal
	to.gen.AddMacs(msg)
	return msg
}

// responseFor returns a handshake response from sender to receiver whose mac1
// is keyed to to's public key.
func responseFor(sender, receiver uint32, to *wgPeer) []byte {
	msg := wgDatagram(device.MessageResponseType, device.MessageResponseSize, sender, receiver)
	to.gen.AddMacs(msg)
	return msg
}

// transportTo returns a transport message for receiver carrying a counter.
func transportTo(receiver uint32, counter uint64) []byte {
	msg := wgDatagram(device.MessageTransportType, device.MessageTransportSize+16, receiver, 0)
	binary.LittleEndian.PutUint64(msg[8:16], counter)
	return msg
}

// relayAddr returns the address a test socket sends to the relay on:
// 127.0.0.1 and the relay's port. A relay on the wildcard address is reached
// on 127.0.0.1, because only Linux routes a datagram sent to the wildcard.
func relayAddr(t *testing.T, r *Relay) *net.UDPAddr {
	t.Helper()
	addr, ok := r.ListenAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		t.Fatalf("relay ListenAddr = %v, want a *net.UDPAddr", r.ListenAddr())
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port}
}

func send(t *testing.T, from *net.UDPConn, r *Relay, b []byte) {
	t.Helper()
	if _, err := from.WriteToUDP(b, relayAddr(t, r)); err != nil {
		t.Fatalf("send to relay: %v", err)
	}
}

// recv returns the next datagram conn reads within 2 s.
func recv(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read on %s: %v", conn.LocalAddr(), err)
	}
	return buf[:n]
}

func expectRecv(t *testing.T, to *wgPeer, want []byte) {
	t.Helper()
	if got := recv(t, to.conn); !bytes.Equal(got, want) {
		t.Fatalf("%s received %x, want %x", to.id, got, want)
	}
}

// receives reports whether conn reads a datagram equal to want within d,
// skipping any other datagram.
func receives(conn *net.UDPConn, want []byte, d time.Duration) bool {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(d)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return false
		}
		if bytes.Equal(buf[:n], want) {
			return true
		}
	}
}

// expectNothing checks that conn reads no datagram within 300 ms.
func expectNothing(t *testing.T, name string, conn *net.UDPConn) {
	t.Helper()
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatalf("%s received %x, want nothing", name, buf[:n])
	}
}

// waitIndex waits until the relay holds index i, pending or not as asked.
func waitIndex(t *testing.T, r *Relay, i uint32, pending bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		idx, ok := r.indices[i]
		done := ok && idx.pending == pending
		r.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay never recorded index %d (pending=%v)", i, pending)
		}
		time.Sleep(time.Millisecond)
	}
}

// handshake completes a first contact between a and b through r, which must
// already list both: a's initiation for b waits as pending, b's initiation
// for a is fanned out to a, and a's response reaches b. aIdx is a's session
// index and bIdx b's.
func handshake(t *testing.T, r *Relay, a, b *wgPeer, aIdx, bIdx uint32) {
	t.Helper()
	send(t, a.conn, r, initiationFor(aIdx+1_000_000, b))
	waitIndex(t, r, aIdx+1_000_000, true)

	init := initiationFor(bIdx, a)
	send(t, b.conn, r, init)
	expectRecv(t, a, init)

	resp := responseFor(aIdx, bIdx, b)
	send(t, a.conn, r, resp)
	expectRecv(t, b, resp)
}

// setAddr gives the relay's peer nodeID the fresh address addr, as a
// completed handshake would, without spending handshakes on it.
func setAddr(r *Relay, nodeID string, addr netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.peers {
		if p.nodeID == nodeID {
			p.addr, p.seen = addr, r.now()
		}
	}
}

func mustConfigure(t *testing.T, r *Relay, peers ...*wgPeer) {
	t.Helper()
	if err := r.Configure(51821, snapshotPeers(peers...)); err != nil {
		t.Fatalf("Configure: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Forwarding
// ---------------------------------------------------------------------------

func TestRelay_ForwardsAFirstContactAndTransport(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	x := newWGPeer(t, "node-x", 0x30)
	mustConfigure(t, r, a, b, x)

	// A's initiation for B: B has no address and nobody else waits, so it
	// goes nowhere and A waits as pending.
	send(t, a.conn, r, initiationFor(1, b))
	expectNothing(t, "B", b.conn)
	expectNothing(t, "A", a.conn)
	expectNothing(t, "X", x.conn)

	// B's initiation for A reaches A, the only pending initiator.
	init := initiationFor(2, a)
	send(t, b.conn, r, init)
	expectRecv(t, a, init)
	expectNothing(t, "X", x.conn)

	// A's response to B's index, mac1 for B, reaches B.
	resp := responseFor(3, 2, b)
	send(t, a.conn, r, resp)
	expectRecv(t, b, resp)

	// Transport now flows by receiver index both ways.
	toA := transportTo(3, 1)
	send(t, b.conn, r, toA)
	expectRecv(t, a, toA)
	toB := transportTo(2, 1)
	send(t, a.conn, r, toB)
	expectRecv(t, b, toB)

	// A roams to A2: its transport teaches the relay the new address.
	a2 := newWGPeer(t, "node-a", 0x10)
	toB = transportTo(2, 2)
	send(t, a2.conn, r, toB)
	expectRecv(t, b, toB)
	toA = transportTo(3, 2)
	send(t, b.conn, r, toA)
	expectRecv(t, a2, toA)
	expectNothing(t, "A", a.conn)
	logs.waitFor(t, fmt.Sprintf("peer_id=node-a address=%s", a2.addr()), 1)
	if !strings.Contains(logs.String(), `msg="relay: peer address learned"`) {
		t.Errorf("no peer address learned line:\n%s", logs.String())
	}
}

func TestRelay_FanoutReachesTheEightNewestInitiators(t *testing.T) {
	r, _, clock := testRelay(t)
	z := newWGPeer(t, "node-z", 0xf0) // a peer that never sends
	peers := []*wgPeer{z}
	var waiting []*wgPeer
	for i := range 10 {
		p := newWGPeer(t, fmt.Sprintf("node-%d", i), byte(i*8))
		waiting = append(waiting, p)
		peers = append(peers, p)
	}
	eleventh := newWGPeer(t, "node-11", 0xa0)
	peers = append(peers, eleventh)
	mustConfigure(t, r, peers...)

	for i, p := range waiting {
		clock.Add(time.Second)
		send(t, p.conn, r, initiationFor(uint32(100+i), z))
		waitIndex(t, r, uint32(100+i), true)
	}

	init := initiationFor(200, waiting[5])
	send(t, eleventh.conn, r, init)
	for i, p := range waiting {
		got := receives(p.conn, init, 300*time.Millisecond)
		if want := i >= 2; got != want {
			t.Errorf("initiator %d (of 10, oldest first) received the fan-out = %v, want %v", i, got, want)
		}
	}
}

func TestRelay_FanoutSkipsInitiatorsOlderThanTheWindow(t *testing.T) {
	r, _, clock := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	d := newWGPeer(t, "node-d", 0x40)
	z := newWGPeer(t, "node-z", 0xf0)
	mustConfigure(t, r, a, b, c, d, z)

	send(t, a.conn, r, initiationFor(1, z))
	waitIndex(t, r, 1, true)

	// Within the window A still gets initiations the relay cannot place.
	clock.Add(29 * time.Second)
	early := initiationFor(2, z)
	send(t, c.conn, r, early)
	if !receives(a.conn, early, 2*time.Second) {
		t.Fatal("A did not receive an initiation 29 s after its own")
	}

	// A pending index must be younger than the window: at exactly 30 s A is out.
	clock.Add(time.Second)
	edge := initiationFor(4, z)
	send(t, d.conn, r, edge)
	if !receives(c.conn, edge, 2*time.Second) {
		t.Fatal("C, pending for 1 s, did not receive the initiation")
	}
	if receives(a.conn, edge, 300*time.Millisecond) {
		t.Error("A received an initiation exactly 30 s after its own")
	}

	clock.Add(time.Second) // 31 s after A's initiation
	late := initiationFor(3, z)
	send(t, b.conn, r, late)
	if receives(a.conn, late, 300*time.Millisecond) {
		t.Error("A received an initiation 31 s after its own")
	}
	if !receives(c.conn, late, 2*time.Second) {
		t.Error("C, pending for 2 s, did not receive the initiation")
	}
}

func TestRelay_NeverSendsBackToTheSource(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)
	base := logs.count("reason=no_route") // the handshake's first initiation

	// A sends to its own index.
	send(t, a.conn, r, transportTo(3, 1))
	expectNothing(t, "A", a.conn)
	expectNothing(t, "B", b.conn)
	logs.waitFor(t, "reason=no_route", base+1)

	// It changed no address: both directions still work.
	toB := transportTo(2, 2)
	send(t, a.conn, r, toB)
	expectRecv(t, b, toB)
	toA := transportTo(3, 2)
	send(t, b.conn, r, toA)
	expectRecv(t, a, toA)
}

func TestRelay_DropsWhatItCannotRoute(t *testing.T) {
	t.Run("not wireguard", func(t *testing.T) {
		r, logs, _ := testRelay(t)
		a := newWGPeer(t, "node-a", 0x10)
		mustConfigure(t, r, a)
		send(t, a.conn, r, []byte("hello"))
		logs.waitFor(t, "reason=not_wireguard", 1)
		expectNothing(t, "sender", a.conn)
		if !strings.Contains(logs.String(), fmt.Sprintf(`msg="relay: dropped datagram" component=bridge source=%s`, a.addr())) {
			t.Errorf("drop line does not name the source:\n%s", logs.String())
		}
	})
	t.Run("response to an unseen index", func(t *testing.T) {
		r, logs, _ := testRelay(t)
		a := newWGPeer(t, "node-a", 0x10)
		b := newWGPeer(t, "node-b", 0x20)
		mustConfigure(t, r, a, b)
		send(t, a.conn, r, responseFor(5, 4242, b))
		logs.waitFor(t, "reason=unknown_index", 1)
		expectNothing(t, "B", b.conn)
	})
	t.Run("response keyed to the initiation's own target", func(t *testing.T) {
		r, logs, _ := testRelay(t)
		a := newWGPeer(t, "node-a", 0x10)
		b := newWGPeer(t, "node-b", 0x20)
		mustConfigure(t, r, a, b)
		send(t, a.conn, r, initiationFor(1, b))
		waitIndex(t, r, 1, true)
		send(t, b.conn, r, responseFor(2, 1, b))
		logs.waitFor(t, "reason=unknown_target", 1)
		expectNothing(t, "A", a.conn)
	})
	t.Run("transport to an unseen index", func(t *testing.T) {
		r, logs, _ := testRelay(t)
		a := newWGPeer(t, "node-a", 0x10)
		mustConfigure(t, r, a)
		send(t, a.conn, r, transportTo(77, 1))
		logs.waitFor(t, "reason=unknown_index", 1)
	})
}

func TestRelay_RateLimitsHandshakesPerSourceIP(t *testing.T) {
	logger, logs := newRelayLogger()
	r := NewRelay(logger) // wireguard-go's limiter, real time
	r.listen = loopbackRelayListen
	t.Cleanup(func() { _ = r.Stop() })
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)

	setAddr(r, "node-b", b.addr())

	const sent = 50
	start := time.Now()
	for i := range sent {
		send(t, a.conn, r, initiationFor(uint32(1000+i), b))
	}
	// elapsed ends at the last arrival: the limiter cannot have refilled a
	// token for a datagram after it arrived.
	received := 0
	var elapsed time.Duration
	buf := make([]byte, 2048)
	for {
		_ = b.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, _, err := b.conn.ReadFromUDP(buf); err != nil {
			break
		}
		received++
		elapsed = time.Since(start)
	}

	if limit := 5 + int(20*elapsed.Seconds()); received > limit || received == 0 {
		t.Errorf("B received %d of %d initiations in %v, want 1 to %d", received, sent, elapsed, limit)
	}
	logs.waitFor(t, "reason=rate_limited", sent-received)
	if n := logs.count("reason=rate_limited"); n != sent-received {
		t.Errorf("rate_limited drops = %d, want %d", n, sent-received)
	}
}

func TestRelay_IndexTableFull(t *testing.T) {
	r, logs, clock := testRelay(t)
	r.maxIndices = 2
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	d := newWGPeer(t, "node-d", 0x40)
	z := newWGPeer(t, "node-z", 0xf0)
	mustConfigure(t, r, a, b, c, d, z)

	send(t, a.conn, r, initiationFor(1, z))
	waitIndex(t, r, 1, true)
	clock.Add(time.Second)
	send(t, b.conn, r, initiationFor(2, z))
	waitIndex(t, r, 2, true)
	_ = receives(a.conn, nil, 100*time.Millisecond) // drain B's fan-out to A

	clock.Add(time.Second)
	third := initiationFor(3, z)
	send(t, c.conn, r, third)
	logs.waitFor(t, "reason=index_table_full", 1)
	clock.Add(time.Second)
	send(t, d.conn, r, initiationFor(4, z))
	logs.waitFor(t, "reason=index_table_full", 2)

	if n := logs.count(`msg="relay: index table full"`); n != 1 {
		t.Errorf("index table full logged %d times for two drops within a minute, want once:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), `level=WARN msg="relay: index table full"`) {
		t.Errorf("index table full is not a Warn:\n%s", logs.String())
	}
	if receives(a.conn, third, 300*time.Millisecond) {
		t.Error("a dropped initiation was still fanned out")
	}
}

func TestRelay_ActiveCount(t *testing.T) {
	r, _, clock := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)

	if n := r.ActiveCount(); n != 0 {
		t.Fatalf("ActiveCount before any handshake = %d, want 0", n)
	}
	handshake(t, r, a, b, 3, 2)
	if n := r.ActiveCount(); n != 1 {
		t.Fatalf("ActiveCount after one handshake = %d, want 1", n)
	}

	// A second handshake of the same pair: B's address is fresh now, so the
	// initiation goes straight to B.
	init := initiationFor(12, b)
	send(t, a.conn, r, init)
	expectRecv(t, b, init)
	resp := responseFor(13, 12, a)
	send(t, b.conn, r, resp)
	expectRecv(t, a, resp)
	if n := r.ActiveCount(); n != 1 {
		t.Fatalf("ActiveCount after a second handshake of the pair = %d, want 1", n)
	}

	clock.Add(181 * time.Second)
	r.sweep(clock.Now())
	if n := r.ActiveCount(); n != 0 {
		t.Errorf("ActiveCount 181 s later = %d, want 0", n)
	}
}

func TestRelay_ForwardsCookieReplies(t *testing.T) {
	r, _, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	// A cookie reply to a pending initiation goes to the initiation's source.
	init := initiationFor(20, b)
	send(t, a.conn, r, init)
	expectRecv(t, b, init)
	cookie := wgDatagram(device.MessageCookieReplyType, device.MessageCookieReplySize, 20, 0)
	send(t, b.conn, r, cookie)
	expectRecv(t, a, cookie)

	// One naming a session index goes to the index's owner, B for index 2.
	cookie = wgDatagram(device.MessageCookieReplyType, device.MessageCookieReplySize, 2, 0)
	cookie[63] = 1
	send(t, a.conn, r, cookie)
	expectRecv(t, b, cookie)
}

func TestRelay_RateLimitsOnlyHandshakes(t *testing.T) {
	logger, logs := newRelayLogger()
	r := NewRelay(logger) // wireguard-go's limiter, real time
	r.listen = loopbackRelayListen
	t.Cleanup(func() { _ = r.Stop() })
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2) // three of the burst of five

	const sent = 50
	for i := range sent {
		send(t, a.conn, r, transportTo(2, uint64(i)))
	}
	for i := range sent {
		if got := recv(t, b.conn); !bytes.Equal(got, transportTo(2, uint64(i))) {
			t.Fatalf("transport %d: B received %x", i, got)
		}
	}
	if n := logs.count("reason=rate_limited"); n != 0 {
		t.Fatalf("%d transport datagrams were rate limited, want none", n)
	}

	// Responses spend the same budget as initiations.
	for i := range 10 {
		send(t, a.conn, r, responseFor(uint32(60+i), 4242, b))
	}
	logs.waitFor(t, "reason=rate_limited", 1)
}

func TestRelay_StaleAddressIsNotUsed(t *testing.T) {
	r, _, clock := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	// Both come back on new mappings after their addresses went stale.
	clock.Add(181 * time.Second)
	a2 := newWGPeer(t, "node-a", 0x10)
	b2 := newWGPeer(t, "node-b", 0x20)
	initB := initiationFor(30, b)
	send(t, a2.conn, r, initB)
	waitIndex(t, r, 30, true)
	initA := initiationFor(31, a)
	send(t, b2.conn, r, initA)
	if !receives(a2.conn, initA, 2*time.Second) {
		t.Error("B2's initiation did not fan out to A2")
	}
	if receives(b.conn, initB, 300*time.Millisecond) || receives(a.conn, initA, 300*time.Millisecond) {
		t.Error("an initiation went to a stale address")
	}
}

func TestRelay_LearnsAnAddressOnce(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	const line = `msg="relay: peer address learned"`
	before := logs.count(line)
	for i := range 10 {
		toB := transportTo(2, uint64(i))
		send(t, a.conn, r, toB)
		expectRecv(t, b, toB)
	}
	if n := logs.count(line); n != before {
		t.Errorf("%d learned lines for 10 transports from an unchanged address, want none", n-before)
	}
}

func TestRelay_LearningAnAddressTakesItFromItsLastHolder(t *testing.T) {
	r, _, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	mustConfigure(t, r, a, b, c)
	handshake(t, r, a, b, 3, 2)
	setAddr(r, "node-c", c.addr())

	// A's NAT reuses the public port C had: A's transport arrives from it.
	toB := transportTo(2, 1)
	send(t, c.conn, r, toB)
	expectRecv(t, b, toB)

	// C no longer has that address, so B's initiation for C is not sent there.
	init := initiationFor(40, c)
	send(t, b.conn, r, init)
	if receives(c.conn, init, 300*time.Millisecond) {
		t.Error("an initiation for C went to the address A took over")
	}
}

func TestRelay_FanoutLeavesOutConnectedPeers(t *testing.T) {
	r, _, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	d := newWGPeer(t, "node-d", 0x40)
	z := newWGPeer(t, "node-z", 0xf0)
	mustConfigure(t, r, a, b, c, d, z)
	// A's first initiation stays pending at A's address, which is fresh now.
	handshake(t, r, a, b, 3, 2)

	// C waits under two indices at one address.
	send(t, c.conn, r, initiationFor(41, z))
	waitIndex(t, r, 41, true)
	send(t, c.conn, r, initiationFor(42, z))
	waitIndex(t, r, 42, true)

	init := initiationFor(43, z)
	send(t, d.conn, r, init)
	expectRecv(t, c, init)
	expectNothing(t, "C, a second time", c.conn)
	if receives(a.conn, init, 300*time.Millisecond) {
		t.Error("the fan-out reached A, whose address is fresh")
	}
}

func TestRelay_NeverAnswersAHandshake(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)
	base := logs.count("reason=no_route") // the handshake's first initiation

	// An initiation keyed to A, from A's own fresh address.
	send(t, a.conn, r, initiationFor(50, a))
	expectNothing(t, "A", a.conn)
	logs.waitFor(t, "reason=no_route", base+1)

	// A response from the source of the initiation it answers.
	init := initiationFor(51, b)
	send(t, a.conn, r, init)
	expectRecv(t, b, init)
	send(t, a.conn, r, responseFor(52, 51, a))
	expectNothing(t, "A", a.conn)
	logs.waitFor(t, "reason=no_route", base+2)
}

func TestRelay_SweepExpiresIndices(t *testing.T) {
	r, _, clock := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2) // A's first initiation stays pending as 1000003

	has := func(i uint32) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, ok := r.indices[i]
		return ok
	}

	clock.Add(31 * time.Second)
	r.sweep(clock.Now())
	if has(1_000_003) || !has(2) || !has(3) {
		t.Fatalf("after 31 s: pending held = %v, sessions held = %v %v; want only the sessions", has(1_000_003), has(2), has(3))
	}

	// Traffic keeps a session alive past relayIndexTTL from its handshake.
	clock.Add(120 * time.Second)
	for _, step := range []struct {
		from, to *wgPeer
		index    uint32
	}{{a, b, 2}, {b, a, 3}} {
		msg := transportTo(step.index, 1)
		send(t, step.from.conn, r, msg)
		expectRecv(t, step.to, msg)
	}
	clock.Add(60 * time.Second)
	r.sweep(clock.Now())
	if !has(2) || !has(3) || r.ActiveCount() != 1 {
		t.Fatalf("211 s after the handshake, 60 s after traffic: sessions held = %v %v, ActiveCount = %d", has(2), has(3), r.ActiveCount())
	}
}

func TestRelay_FullTableIsSweptFirst(t *testing.T) {
	r, logs, clock := testRelay(t)
	r.maxIndices = 2
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	z := newWGPeer(t, "node-z", 0xf0)
	mustConfigure(t, r, a, b, c, z)

	send(t, a.conn, r, initiationFor(1, z))
	waitIndex(t, r, 1, true)
	send(t, b.conn, r, initiationFor(2, z))
	waitIndex(t, r, 2, true)

	// Both pending indices are past the window, and no sweeper tick ran.
	clock.Add(31 * time.Second)
	send(t, c.conn, r, initiationFor(3, z))
	waitIndex(t, r, 3, true)
	if n := logs.count("index_table_full"); n != 0 {
		t.Errorf("a table of expired indices refused a new one (%d lines)", n)
	}
}

func TestRelay_ResponseToAnIndexTheSweepExpired(t *testing.T) {
	r, logs, clock := testRelay(t)
	r.maxIndices = 2
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	z := newWGPeer(t, "node-z", 0xf0)
	mustConfigure(t, r, a, b, c, z)

	send(t, a.conn, r, initiationFor(1, b))
	waitIndex(t, r, 1, true)
	clock.Add(20 * time.Second)
	send(t, c.conn, r, initiationFor(2, z))
	waitIndex(t, r, 2, true)
	_ = receives(a.conn, nil, 100*time.Millisecond) // drain C's fan-out to A

	// The response needs room for B's index; the sweep that makes it expires
	// the 31 s old initiation the response answers.
	clock.Add(11 * time.Second)
	send(t, b.conn, r, responseFor(5, 1, a))
	logs.waitFor(t, "reason=unknown_index", 1)
	expectNothing(t, "A", a.conn)
}

func TestRelay_StopForgetsEverything(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	mustConfigure(t, r, a, b)
	send(t, b.conn, r, transportTo(3, 1))
	logs.waitFor(t, "reason=unknown_index", 1)
	expectNothing(t, "A", a.conn)

	// No address survived either: an initiation for B waits as pending.
	init := initiationFor(60, b)
	send(t, a.conn, r, init)
	if receives(b.conn, init, 300*time.Millisecond) {
		t.Error("an initiation went to an address learned before Stop")
	}
}

func TestRelay_ConfigureKeysPeersByNodeIDAndKey(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	// B's key now belongs to node-c: a fresh entry, so B's sessions go.
	moved := b.snapshot()
	moved.NodeID = "node-c"
	if err := r.Configure(51821, []api.SnapshotPeer{a.snapshot(), moved}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	send(t, a.conn, r, transportTo(2, 1))
	logs.waitFor(t, "reason=unknown_index", 1)
	expectNothing(t, "B", b.conn)
}

func TestRelay_UnmapsSourcesOnTheDualStackSocket(t *testing.T) {
	logger, logs := newRelayLogger()
	r := NewRelay(logger) // the production listen: UDP on the dual-stack wildcard
	r.newLimiter = func() handshakeLimiter { return allowAll{} }
	t.Cleanup(func() { _ = r.Stop() })
	probe, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("probe for a free port: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	if err := r.Configure(port, snapshotPeers(a, b)); err != nil {
		t.Fatalf("Configure(%d): %v", port, err)
	}
	handshake(t, r, a, b, 3, 2)

	out := logs.String()
	if want := fmt.Sprintf("peer_id=node-a address=%s", a.addr()); !strings.Contains(out, want) {
		t.Errorf("log lacks %q, the IPv4 source unmapped:\n%s", want, out)
	}
	if strings.Contains(out, "::ffff:") {
		t.Errorf("an IPv4-mapped address reached the relay's state:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Read and write errors
// ---------------------------------------------------------------------------

type fakeRead struct {
	b   []byte
	src netip.AddrPort
	err error
}

type fakeWrite struct {
	b   []byte
	dst netip.AddrPort
}

// fakeRelayConn is a relayConn whose reads the test feeds and whose writes it
// records, with injectable errors.
type fakeRelayConn struct {
	reads     chan fakeRead
	writes    chan fakeWrite
	mu        sync.Mutex
	writeErrs []error
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeRelayConn() *fakeRelayConn {
	return &fakeRelayConn{
		reads:  make(chan fakeRead),
		writes: make(chan fakeWrite, 16),
		closed: make(chan struct{}),
	}
}

func (c *fakeRelayConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	select {
	case r := <-c.reads:
		if r.err != nil {
			return 0, netip.AddrPort{}, r.err
		}
		return copy(b, r.b), r.src, nil
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *fakeRelayConn) WriteToUDPAddrPort(b []byte, dst netip.AddrPort) (int, error) {
	c.mu.Lock()
	var err error
	if len(c.writeErrs) > 0 {
		err, c.writeErrs = c.writeErrs[0], c.writeErrs[1:]
	}
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	c.writes <- fakeWrite{b: bytes.Clone(b), dst: dst}
	return len(b), nil
}

func (c *fakeRelayConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51821}
}

func (c *fakeRelayConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeRelayConn) feed(t *testing.T, r fakeRead) {
	t.Helper()
	select {
	case c.reads <- r:
	case <-time.After(2 * time.Second):
		t.Fatal("the dispatch loop did not read")
	}
}

func (c *fakeRelayConn) written(t *testing.T) fakeWrite {
	t.Helper()
	select {
	case w := <-c.writes:
		return w
	case <-time.After(2 * time.Second):
		t.Fatal("the relay forwarded nothing")
		return fakeWrite{}
	}
}

// fakeConnRelay returns a relay running on a fakeRelayConn whose peer "node-b"
// has the fresh address bAddr, so an initiation for b is forwarded there.
func fakeConnRelay(t *testing.T, b *wgPeer, bAddr netip.AddrPort) (*Relay, *fakeRelayConn, *relayLog) {
	t.Helper()
	r, logs, _ := testRelay(t)
	conn := newFakeRelayConn()
	r.listen = func(int) (relayConn, error) { return conn, nil }
	if err := r.Configure(51821, snapshotPeers(b)); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	setAddr(r, b.id, bAddr)
	return r, conn, logs
}

func TestRelay_ReadErrors(t *testing.T) {
	b := newWGPeer(t, "node-b", 0x20)
	bAddr := netip.MustParseAddrPort("198.51.100.2:40000")
	src := netip.MustParseAddrPort("198.51.100.1:40000")
	r, conn, logs := fakeConnRelay(t, b, bAddr)

	conn.feed(t, fakeRead{err: errors.New("connection reset by peer")})
	init := initiationFor(1, b)
	conn.feed(t, fakeRead{b: init, src: src})
	if w := conn.written(t); w.dst != bAddr || !bytes.Equal(w.b, init) {
		t.Errorf("forwarded %x to %s, want the initiation to %s", w.b, w.dst, bAddr)
	}
	if !strings.Contains(logs.String(), `level=DEBUG msg="relay: read failed" component=bridge error="connection reset by peer"`) {
		t.Errorf("no read failed line at Debug:\n%s", logs.String())
	}

	r.mu.Lock()
	run := r.run
	r.mu.Unlock()
	conn.feed(t, fakeRead{err: &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}})
	select {
	case <-run.dispatched:
	case <-time.After(2 * time.Second):
		t.Fatal("the dispatch loop did not end on net.ErrClosed")
	}
}

func TestRelay_WriteErrors(t *testing.T) {
	b := newWGPeer(t, "node-b", 0x20)
	bAddr := netip.MustParseAddrPort("198.51.100.2:40000")
	src := netip.MustParseAddrPort("198.51.100.1:40000")
	_, conn, logs := fakeConnRelay(t, b, bAddr)

	conn.mu.Lock()
	conn.writeErrs = []error{errors.New("no buffer space available")}
	conn.mu.Unlock()
	conn.feed(t, fakeRead{b: initiationFor(1, b), src: src})
	logs.waitFor(t, `msg="relay: forward failed"`, 1)
	if want := fmt.Sprintf(`dst=%s error="no buffer space available"`, bAddr); !strings.Contains(logs.String(), want) {
		t.Errorf("forward failed line lacks %q:\n%s", want, logs.String())
	}

	next := initiationFor(2, b)
	conn.feed(t, fakeRead{b: next, src: src})
	if w := conn.written(t); !bytes.Equal(w.b, next) {
		t.Errorf("forwarded %x after the failed write, want the next initiation", w.b)
	}
}

// ---------------------------------------------------------------------------
// Configure and Stop
// ---------------------------------------------------------------------------

// countingListen wraps loopbackRelayListen, counting calls and keeping every
// socket it bound.
type countingListen struct {
	mu    sync.Mutex
	conns []*net.UDPConn
}

func (c *countingListen) listen(port int) (relayConn, error) {
	conn, err := loopbackRelayListen(port)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns = append(c.conns, conn.(*net.UDPConn))
	return conn, nil
}

func (c *countingListen) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

func TestRelay_ConfigureRejectsAnOutOfRangePort(t *testing.T) {
	r, _, _ := testRelay(t)
	seam := &countingListen{}
	r.listen = seam.listen
	a := newWGPeer(t, "node-a", 0x10)
	for _, port := range []int{0, 65536} {
		err := r.Configure(port, snapshotPeers(a))
		want := fmt.Sprintf("bridge: relay: listen_port %d out of range", port)
		if err == nil || err.Error() != want {
			t.Errorf("Configure(%d) = %v, want %q", port, err, want)
		}
	}
	if seam.calls() != 0 || r.Running() {
		t.Errorf("listen called %d times, Running = %v; want no bind", seam.calls(), r.Running())
	}
}

func TestRelay_ConfigureRebindsOnlyForANewPort(t *testing.T) {
	r, logs, _ := testRelay(t)
	seam := &countingListen{}
	r.listen = seam.listen
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	peers := snapshotPeers(a, b)

	if err := r.Configure(51821, peers); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	first := r.ListenAddr().String()
	if err := r.Configure(51821, peers); err != nil {
		t.Fatalf("second Configure: %v", err)
	}
	if seam.calls() != 1 || r.ListenAddr().String() != first {
		t.Fatalf("after a repeated Configure: listen calls = %d, ListenAddr = %s; want 1 and %s", seam.calls(), r.ListenAddr(), first)
	}

	if err := r.Configure(51822, peers); err != nil {
		t.Fatalf("Configure on a new port: %v", err)
	}
	if seam.calls() != 2 {
		t.Errorf("listen calls = %d after a new port, want 2", seam.calls())
	}
	out := logs.String()
	stopped := strings.Index(out, `msg="relay stopped"`)
	started := strings.Index(out, `msg="relay started" component=bridge listen_port=51822`)
	if stopped < 0 || started < stopped {
		t.Errorf("want relay stopped, then relay started with listen_port=51822:\n%s", out)
	}
	if _, err := seam.conns[0].WriteToUDP([]byte("x"), a.conn.LocalAddr().(*net.UDPAddr)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("old socket write = %v, want net.ErrClosed", err)
	}
}

func TestRelay_ConfigureWithoutPeers(t *testing.T) {
	r, logs, _ := testRelay(t)
	if err := r.Configure(51821, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if !r.Running() {
		t.Fatal("Running = false after Configure")
	}
	a := newWGPeer(t, "node-a", 0x10)
	send(t, a.conn, r, initiationFor(1, a))
	logs.waitFor(t, "reason=unknown_target", 1)
}

func TestRelay_ConfigureSkipsInvalidAndDuplicateKeys(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	dup := a.snapshot()
	dup.NodeID = "node-dup"
	peers := []api.SnapshotPeer{
		{NodeID: "node-bad", PublicKey: "not-base64"},
		a.snapshot(),
		{NodeID: "node-short", PublicKey: base64.StdEncoding.EncodeToString([]byte("too short"))},
		dup,
		b.snapshot(),
	}
	if err := r.Configure(51821, peers); err != nil {
		t.Fatalf("Configure = %v, want nil", err)
	}
	out := logs.String()
	for _, want := range []string{
		`level=WARN msg="relay: skipping peer with invalid public key" component=bridge peer_id=node-bad`,
		`level=WARN msg="relay: skipping peer with invalid public key" component=bridge peer_id=node-short`,
		`level=WARN msg="relay: skipping peer with duplicate public key" component=bridge peer_id=node-dup`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	handshake(t, r, a, b, 3, 2)
	// The first node ID listing a key keeps it.
	out = logs.String()
	if !strings.Contains(out, "peer_id=node-a address=") || strings.Contains(out, "peer_id=node-dup address=") {
		t.Errorf("A's address was learned for the wrong node ID:\n%s", out)
	}
}

func TestRelay_ConfigureKeepsWhatStillHolds(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	mustConfigure(t, r, a, b, c)
	handshake(t, r, a, b, 3, 2)

	// Same node IDs and keys: the session and both addresses survive.
	mustConfigure(t, r, a, b, c)
	toA := transportTo(3, 1)
	send(t, b.conn, r, toA)
	expectRecv(t, a, toA)

	// B leaves: every index naming it goes, and A's index with it.
	mustConfigure(t, r, a, c)
	send(t, b.conn, r, transportTo(3, 2))
	logs.waitFor(t, "reason=unknown_index", 1)
	expectNothing(t, "A", a.conn)
}

func TestRelay_ConfigureForgetsARekeyedPeer(t *testing.T) {
	r, logs, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	rekeyed := newWGPeer(t, "node-b", 0x60)
	mustConfigure(t, r, a, rekeyed)
	send(t, a.conn, r, transportTo(2, 1))
	logs.waitFor(t, "reason=unknown_index", 1)
	expectNothing(t, "B", b.conn)
}

func TestRelay_ConfigureBindsTheWildcardAddress(t *testing.T) {
	logger, _ := newRelayLogger()
	r := NewRelay(logger)
	t.Cleanup(func() { _ = r.Stop() })

	probe, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("probe for a free port: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	if err := r.Configure(port, nil); err != nil {
		t.Fatalf("Configure(%d): %v", port, err)
	}
	addr, ok := r.ListenAddr().(*net.UDPAddr)
	if !ok || addr.Port != port || !addr.IP.IsUnspecified() {
		t.Errorf("ListenAddr = %s, want the wildcard address on port %d", addr, port)
	}
}

func TestRelay_StopIsIdempotent(t *testing.T) {
	logger, logs := newRelayLogger()
	r := NewRelay(logger) // the real limiter, so goleak sees its goroutine end
	r.listen = loopbackRelayListen

	if err := r.Stop(); err != nil {
		t.Fatalf("Stop on a relay that never ran = %v, want nil", err)
	}
	if err := r.Configure(51821, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	// Spend a handshake so the limiter's cleanup goroutine is running.
	a := newWGPeer(t, "node-a", 0x10)
	send(t, a.conn, r, initiationFor(1, a))
	logs.waitFor(t, "reason=unknown_target", 1)

	for i := range 2 {
		if err := r.Stop(); err != nil {
			t.Fatalf("Stop #%d = %v, want nil", i+1, err)
		}
	}
	if r.Running() || r.ListenAddr() != nil {
		t.Errorf("after Stop: Running = %v, ListenAddr = %v", r.Running(), r.ListenAddr())
	}
	if n := logs.count(`msg="relay stopped"`); n != 1 {
		t.Errorf("relay stopped logged %d times, want once", n)
	}
}

// ---------------------------------------------------------------------------
// RelayReconcileHandler
// ---------------------------------------------------------------------------

func relaySnapshot(block *api.RelayConfig, peers ...api.SnapshotPeer) *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{Peers: peers, Bridge: &api.BridgeSnapshot{Relay: block}}
}

func runHandler(t *testing.T, h reconcile.ReconcileHandler, desired *api.NodeStateSnapshot) error {
	t.Helper()
	return h(t.Context(), desired, reconcile.StateDiff{BridgeChanged: true})
}

func TestRelayReconcileHandler_NilSnapshot(t *testing.T) {
	r, _, _ := testRelay(t)
	if err := r.Configure(51821, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	h := RelayReconcileHandler(r, discardLogger())
	if err := runHandler(t, h, nil); err != nil {
		t.Fatalf("handler(nil) = %v, want nil", err)
	}
	if !r.Running() {
		t.Error("a nil snapshot stopped the relay")
	}
}

func TestRelayReconcileHandler_DisabledStopsTheRelay(t *testing.T) {
	tests := []struct {
		name    string
		desired *api.NodeStateSnapshot
	}{
		{"bridge null", &api.NodeStateSnapshot{}},
		{"relay null", relaySnapshot(nil)},
		{"enabled false", relaySnapshot(&api.RelayConfig{Enabled: false, ListenPort: 51821, Assignments: []api.RelayAssignment{}})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _, _ := testRelay(t)
			logger, logs := newRelayLogger()
			h := RelayReconcileHandler(r, logger)
			if err := runHandler(t, h, relaySnapshot(&api.RelayConfig{Enabled: true, ListenPort: 51821})); err != nil {
				t.Fatalf("enable: %v", err)
			}
			if !r.Running() {
				t.Fatal("relay not running after an enabled block")
			}

			if err := runHandler(t, h, tt.desired); err != nil {
				t.Fatalf("handler = %v, want nil", err)
			}
			if r.Running() {
				t.Error("relay still running")
			}
			const line = `level=INFO msg="relay disabled by the control plane"`
			if n := logs.count(line); n != 1 {
				t.Errorf("%q logged %d times, want once:\n%s", line, n, logs.String())
			}

			if err := runHandler(t, h, tt.desired); err != nil {
				t.Fatalf("second handler = %v, want nil", err)
			}
			if n := logs.count(line); n != 1 {
				t.Errorf("a second disabled snapshot logged again (%d lines)", n)
			}
		})
	}
}

func TestRelayReconcileHandler_NoLocalConsent(t *testing.T) {
	logger, logs := newRelayLogger()
	h := RelayReconcileHandler(nil, logger)
	if err := runHandler(t, h, relaySnapshot(&api.RelayConfig{Enabled: true, ListenPort: 51821})); err != nil {
		t.Fatalf("handler = %v, want nil", err)
	}
	want := `level=WARN msg="relay: the control plane enables the relay, but bridge.relay_enabled is false" component=bridge listen_port=51821`
	if !strings.Contains(logs.String(), want) {
		t.Errorf("log lacks %q:\n%s", want, logs.String())
	}
	if err := runHandler(t, h, relaySnapshot(nil)); err != nil {
		t.Errorf("disabled block with no relay = %v, want nil", err)
	}
}

func TestRelayReconcileHandler_BindFailure(t *testing.T) {
	r, _, _ := testRelay(t)
	r.listen = func(int) (relayConn, error) {
		return nil, &net.OpError{Op: "listen", Net: "udp", Err: syscall.EADDRINUSE}
	}
	h := RelayReconcileHandler(r, discardLogger())
	err := runHandler(t, h, relaySnapshot(&api.RelayConfig{Enabled: true, ListenPort: 51821}))
	if err == nil || !strings.HasPrefix(err.Error(), "bridge: relay: listen on :51821: ") {
		t.Fatalf("handler = %v, want the listen error", err)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("errors.Is(%v, EADDRINUSE) = false", err)
	}
	if r.Running() {
		t.Error("Running = true after a failed bind")
	}
}

func TestRelayReconcileHandler_ConfiguresThePulledPeers(t *testing.T) {
	r, _, _ := testRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	h := RelayReconcileHandler(r, discardLogger())
	block := &api.RelayConfig{Enabled: true, ListenPort: 51821}
	if err := runHandler(t, h, relaySnapshot(block, snapshotPeers(a, b)...)); err != nil {
		t.Fatalf("handler: %v", err)
	}
	handshake(t, r, a, b, 3, 2)
}
