package meshdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/plexsphere/plexd/internal/api"
)

// fakeQuery is one query a fake resolver received, with the replies it sent
// back.
type fakeQuery struct {
	// network is "udp" or "tcp".
	network string
	msg     []byte
	replies [][]byte
}

// fakeResolver stands in for a forward resolver: a DNS server on UDP and TCP
// of one port of 127.0.0.1 that the kernel picked. It sends back what its
// answer function returns for each query, in order, and records every query.
// While it holds, it keeps the replies back until release, so a test decides
// when a resolver answers. It runs until the test ends, and the cleanup waits
// for its goroutines.
type fakeResolver struct {
	addr netip.AddrPort
	udp  *net.UDPConn
	tcp  *net.TCPListener
	wg   sync.WaitGroup

	mu      sync.Mutex
	answer  func(query []byte) [][]byte
	queries []fakeQuery
	// holding keeps the replies back; held sends each one kept.
	holding bool
	held    []func()
	conns   map[net.Conn]struct{}
	// closed is set by close, so a connection accepted while the fake
	// closes is closed at once rather than served.
	closed bool
	// arrived is closed and replaced with each query, so a test waits for a
	// query rather than for a while.
	arrived chan struct{}
}

// newFakeResolver starts a fake resolver that answers with answer.
func newFakeResolver(t *testing.T, answer func(query []byte) [][]byte) *fakeResolver {
	t.Helper()
	f := &fakeResolver{answer: answer, conns: make(map[net.Conn]struct{}), arrived: make(chan struct{})}
	for range listenAttempts {
		udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
		if err != nil {
			t.Fatalf("fake resolver: listen udp: %v", err)
		}
		addr := udp.LocalAddr().(*net.UDPAddr).AddrPort()
		tcp, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
		if err != nil {
			_ = udp.Close()
			continue
		}
		f.addr, f.udp, f.tcp = addr, udp, tcp
		break
	}
	if f.udp == nil {
		t.Fatalf("fake resolver: no port free for UDP and TCP in %d attempts", listenAttempts)
	}
	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()
	t.Cleanup(f.close)
	return f
}

func (f *fakeResolver) serveUDP() {
	defer f.wg.Done()
	buf := make([]byte, maxMessageSize)
	for {
		n, src, err := f.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		replies := f.receive("udp", slices.Clone(buf[:n]))
		f.deliver(func() {
			for _, r := range replies {
				_, _ = f.udp.WriteToUDPAddrPort(r, src)
			}
		})
	}
}

func (f *fakeResolver) serveTCP() {
	defer f.wg.Done()
	for {
		conn, err := f.tcp.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			_ = conn.Close()
			return
		}
		f.conns[conn] = struct{}{}
		f.mu.Unlock()
		f.wg.Go(func() {
			defer func() {
				f.mu.Lock()
				delete(f.conns, conn)
				f.mu.Unlock()
				_ = conn.Close()
			}()
			for {
				msg, err := readFrameNoDeadline(conn)
				if err != nil {
					return
				}
				replies := f.receive("tcp", msg)
				f.deliver(func() {
					for _, r := range replies {
						if err := writeFrame(conn, r); err != nil {
							return
						}
					}
				})
			}
		})
	}
}

// readFrameNoDeadline reads one length-framed message from conn, waiting as
// long as it takes: the fake's connections end when the client or the
// cleanup closes them.
func readFrameNoDeadline(conn net.Conn) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// receive records msg and returns the replies to it.
func (f *fakeResolver) receive(network string, msg []byte) [][]byte {
	f.mu.Lock()
	answer := f.answer
	f.mu.Unlock()
	replies := answer(msg)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, fakeQuery{network: network, msg: msg, replies: replies})
	close(f.arrived)
	f.arrived = make(chan struct{})
	return replies
}

// deliver sends the replies of one query, or keeps them back while the fake
// holds.
func (f *fakeResolver) deliver(send func()) {
	f.mu.Lock()
	if f.holding {
		f.held = append(f.held, send)
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()
	send()
}

// hold keeps the replies to the queries to come back until release.
func (f *fakeResolver) hold() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holding = true
}

// release sends every reply kept back, in the order the queries arrived, and
// stops holding.
func (f *fakeResolver) release() {
	f.mu.Lock()
	held := f.held
	f.held, f.holding = nil, false
	f.mu.Unlock()
	for _, send := range held {
		send()
	}
}

// close stops the fake and waits for its goroutines.
func (f *fakeResolver) close() {
	_ = f.udp.Close()
	_ = f.tcp.Close()
	f.mu.Lock()
	f.closed = true
	for conn := range f.conns {
		_ = conn.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

// setAnswer replaces the answer function for the queries to come.
func (f *fakeResolver) setAnswer(answer func(query []byte) [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

// received returns a copy of the queries so far.
func (f *fakeResolver) received() []fakeQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.queries)
}

// count returns how many queries arrived so far.
func (f *fakeResolver) count() int {
	return len(f.received())
}

// waitQueries fails the test unless the fake has received n queries within
// ioTimeout.
func (f *fakeResolver) waitQueries(t *testing.T, n int) {
	t.Helper()
	timeout := time.After(ioTimeout)
	for {
		f.mu.Lock()
		got, arrived := len(f.queries), f.arrived
		f.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-arrived:
		case <-timeout:
			t.Fatalf("fake resolver %s received %d queries within %v, want %d", f.addr, got, ioTimeout, n)
		}
	}
}

// packReply packs a reply to query: the query's ID, opcode, RD bit and
// question, QR and RA set, then the changes edit makes to the header and the
// question, and the records answers adds to the answer section. A query that
// does not parse, or a reply that does not pack, gets nil, which the fake
// sends as an empty datagram or frame that matches no query.
func packReply(query []byte, edit func(*dnsmessage.Header, *dnsmessage.Question), answers func(*dnsmessage.Builder, dnsmessage.Question) error) []byte {
	var p dnsmessage.Parser
	qh, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	h := dnsmessage.Header{ID: qh.ID, Response: true, OpCode: qh.OpCode, RecursionDesired: qh.RecursionDesired, RecursionAvailable: true}
	if edit != nil {
		edit(&h, &q)
	}
	b := dnsmessage.NewBuilder(nil, h)
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return nil
	}
	if answers != nil && answers(&b, q) != nil {
		return nil
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

// aRecords adds an A record of each of addrs, owned by the question's name
// with a TTL of 60, which tells a relayed record from one of the server's.
func aRecords(addrs ...string) func(*dnsmessage.Builder, dnsmessage.Question) error {
	return func(b *dnsmessage.Builder, q dnsmessage.Question) error {
		for _, a := range addrs {
			rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
			if err := b.AResource(rh, dnsmessage.AResource{A: netip.MustParseAddr(a).As4()}); err != nil {
				return err
			}
		}
		return nil
	}
}

// answerA answers every query with NOERROR and an A record of each of addrs.
func answerA(addrs ...string) func([]byte) [][]byte {
	return func(query []byte) [][]byte {
		return [][]byte{packReply(query, nil, aRecords(addrs...))}
	}
}

// answerRCode answers every query with rcode and no record.
func answerRCode(rcode dnsmessage.RCode) func([]byte) [][]byte {
	return func(query []byte) [][]byte {
		return [][]byte{packReply(query, func(h *dnsmessage.Header, _ *dnsmessage.Question) { h.RCode = rcode }, nil)}
	}
}

// silent answers nothing, like a resolver that is down or a packet filter
// that drops the query.
func silent([]byte) [][]byte { return nil }

// routeFakes returns an upstream target that sends a query to each address of
// fakes to that fake resolver, and fails the test for any other address.
func routeFakes(t *testing.T, fakes map[string]*fakeResolver) func(netip.Addr) netip.AddrPort {
	m := make(map[netip.Addr]netip.AddrPort, len(fakes))
	for a, f := range fakes {
		m[netip.MustParseAddr(a)] = f.addr
	}
	return func(a netip.Addr) netip.AddrPort {
		if ap, ok := m[a]; ok {
			return ap
		}
		t.Errorf("query sent to %v, which no fake resolver stands in for", a)
		return netip.AddrPort{}
	}
}

// fakeClock is the upstream's clock in the tests, which moves only when a
// test moves it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestUpstream returns an upstream that sends the queries for each address
// of fakes to that fake, runs on a fake clock, and logs to the returned log.
func newTestUpstream(t *testing.T, fakes map[string]*fakeResolver) (*upstream, *fakeClock, *debugLog) {
	t.Helper()
	logs := &debugLog{}
	clock := newFakeClock()
	u := newUpstream(slog.New(logs))
	u.target = routeFakes(t, fakes)
	u.now = clock.now
	return u, clock, logs
}

// testZone is the zone the upstream tests forward for, as Route would name
// it.
const testZone = "corp.example.com"

// fwdQuery is the query of a client for host.corp.example.com A, with the
// client's ID 0x5ec1.
func fwdQuery(t *testing.T) []byte {
	t.Helper()
	return newQuery(t, 0x5ec1, "host.corp.example.com.", dnsmessage.TypeA)
}

// wantRelayed fails the test unless reply is sent with the ID of query: the
// same bytes but for the first two, which carry the client's ID.
func wantRelayed(t *testing.T, reply, sent, query []byte) {
	t.Helper()
	if len(reply) < 2 || len(sent) < 2 {
		t.Fatalf("reply of %d bytes and sent reply of %d bytes, want a message each", len(reply), len(sent))
	}
	if got, want := binary.BigEndian.Uint16(reply), binary.BigEndian.Uint16(query); got != want {
		t.Errorf("reply ID = %#x, want the client's %#x", got, want)
	}
	if !slices.Equal(reply[2:], sent[2:]) {
		t.Errorf("reply after the ID = %x, want the resolver's %x", reply[2:], sent[2:])
	}
}

// wantSentAsQuery fails the test unless got is query with an ID of its own.
func wantSentAsQuery(t *testing.T, got fakeQuery, network string, query []byte) {
	t.Helper()
	if got.network != network {
		t.Errorf("query arrived over %s, want %s", got.network, network)
	}
	if len(got.msg) != len(query) || !slices.Equal(got.msg[2:], query[2:]) {
		t.Errorf("query sent = %x, want %x but for the ID", got.msg, query)
	}
	if len(got.msg) >= 2 && binary.BigEndian.Uint16(got.msg) == binary.BigEndian.Uint16(query) {
		t.Errorf("query sent with the client's ID %#x, want one of its own", binary.BigEndian.Uint16(query))
	}
}

// wantError fails the test unless err wraps target and names the zone the
// exchange forwarded for.
func wantError(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Errorf("exchange() = %v, want an error wrapping %v", err, target)
	}
	if prefix := "meshdns: forward to " + testZone + ": "; err == nil || !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("exchange() = %v, want an error starting with %q", err, prefix)
	}
}

func TestNewUpstream_Defaults(t *testing.T) {
	u := newUpstream(slog.New(slog.DiscardHandler))
	if u.timeout != 4*time.Second {
		t.Errorf("timeout = %v, want 4s", u.timeout)
	}
	if resolverRetry != 30*time.Second {
		t.Errorf("resolverRetry = %v, want 30s", resolverRetry)
	}
	for _, tc := range []struct{ resolver, want string }{
		{"192.0.2.1", "192.0.2.1:53"},
		{"2001:db8::53", "[2001:db8::53]:53"},
	} {
		if got := u.target(netip.MustParseAddr(tc.resolver)); got != netip.MustParseAddrPort(tc.want) {
			t.Errorf("target(%s) = %v, want %s", tc.resolver, got, tc.want)
		}
	}
	if before, now := time.Now(), u.now(); now.Before(before) || now.Sub(before) > time.Minute {
		t.Errorf("now() = %v, want the wall clock near %v", now, before)
	}
}

func TestUpstream_UDP(t *testing.T) {
	fake := newFakeResolver(t, answerA("198.51.100.53"))
	u, _, _ := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": fake})
	query := fwdQuery(t)

	reply, err := u.exchange(context.Background(), addrs("192.0.2.1"), testZone, query, false)
	if err != nil {
		t.Fatalf("exchange() = %v, want nil", err)
	}
	got := fake.received()
	if len(got) != 1 {
		t.Fatalf("fake received %d queries, want 1", len(got))
	}
	wantSentAsQuery(t, got[0], "udp", query)
	wantRelayed(t, reply, got[0].replies[0], query)
}

func TestUpstream_IgnoresOtherReplies(t *testing.T) {
	matching := func(query []byte) []byte { return packReply(query, nil, aRecords("198.51.100.53")) }
	fake := newFakeResolver(t, func(query []byte) [][]byte {
		return [][]byte{
			query[:5],
			packReply(query, func(h *dnsmessage.Header, _ *dnsmessage.Question) { h.ID++ }, aRecords("192.0.2.66")),
			packReply(query, func(h *dnsmessage.Header, _ *dnsmessage.Question) { h.Response = false }, aRecords("192.0.2.66")),
			packReply(query, func(_ *dnsmessage.Header, q *dnsmessage.Question) { q.Name = dnsmessage.MustNewName("other.example.") }, aRecords("192.0.2.66")),
			packReply(query, func(_ *dnsmessage.Header, q *dnsmessage.Question) { q.Type = dnsmessage.TypeAAAA }, nil),
			packReply(query, func(_ *dnsmessage.Header, q *dnsmessage.Question) { q.Class = dnsmessage.ClassCHAOS }, nil),
			// The question's name in another case is the same name.
			packReply(query, func(_ *dnsmessage.Header, q *dnsmessage.Question) {
				q.Name = dnsmessage.MustNewName("HOST.Corp.Example.COM.")
			}, aRecords("198.51.100.53")),
			matching(query),
		}
	})
	u, _, _ := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": fake})
	query := fwdQuery(t)

	for _, tcp := range []bool{false, true} {
		reply, err := u.exchange(context.Background(), addrs("192.0.2.1"), testZone, query, tcp)
		if err != nil {
			t.Fatalf("exchange(tcp=%v) = %v, want nil", tcp, err)
		}
		got := fake.received()
		sent := got[len(got)-1].replies
		// The first reply that matches is taken: the one that spells the
		// name in another case.
		wantRelayed(t, reply, sent[6], query)
	}
}

func TestUpstream_TCP(t *testing.T) {
	fake := newFakeResolver(t, answerA("198.51.100.53"))
	u, _, _ := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": fake})
	query := fwdQuery(t)

	reply, err := u.exchange(context.Background(), addrs("192.0.2.1"), testZone, query, true)
	if err != nil {
		t.Fatalf("exchange() = %v, want nil", err)
	}
	got := fake.received()
	if len(got) != 1 {
		t.Fatalf("fake received %d queries, want 1", len(got))
	}
	wantSentAsQuery(t, got[0], "tcp", query)
	wantRelayed(t, reply, got[0].replies[0], query)
}

// A reply with TC set ends the exchange like any other and is relayed as it
// is, so the client asks again over TCP.
func TestUpstream_RelaysTruncated(t *testing.T) {
	fake := newFakeResolver(t, func(query []byte) [][]byte {
		return [][]byte{packReply(query, func(h *dnsmessage.Header, _ *dnsmessage.Question) { h.Truncated = true }, nil)}
	})
	u, _, _ := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": fake})
	query := fwdQuery(t)

	reply, err := u.exchange(context.Background(), addrs("192.0.2.1"), testZone, query, false)
	if err != nil {
		t.Fatalf("exchange() = %v, want nil", err)
	}
	wantRelayed(t, reply, fake.received()[0].replies[0], query)
	if m := parseResponse(t, reply); !m.Truncated {
		t.Errorf("TC = false, want the resolver's TC relayed")
	}
}

func TestUpstream_DeadFirstResolver(t *testing.T) {
	dead := newFakeResolver(t, silent)
	live := newFakeResolver(t, answerA("198.51.100.53"))
	u, clock, logs := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": dead, "192.0.2.2": live})
	resolvers := addrs("192.0.2.1", "192.0.2.2")
	query := fwdQuery(t)

	start := time.Now()
	reply, err := u.exchange(context.Background(), resolvers, testZone, query, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("exchange() = %v, want the second resolver's reply", err)
	}
	if elapsed >= forwardTimeout {
		t.Errorf("exchange took %v, want less than %v", elapsed, forwardTimeout)
	}
	if dead.count() != 1 || live.count() != 1 {
		t.Fatalf("queries to the first and second resolver = %d, %d, want 1, 1", dead.count(), live.count())
	}
	wantRelayed(t, reply, live.received()[0].replies[0], query)
	wantDown(t, u, "192.0.2.1")

	// The next exchange asks the second resolver first, and it answers.
	if _, err := u.exchange(context.Background(), resolvers, testZone, query, false); err != nil {
		t.Fatalf("second exchange() = %v, want nil", err)
	}
	if dead.count() != 1 || live.count() != 2 {
		t.Errorf("after the second exchange: queries to the first and second resolver = %d, %d, want 1, 2", dead.count(), live.count())
	}

	// After resolverRetry the first is asked first again; it answers now.
	dead.setAnswer(answerA("198.51.100.54"))
	clock.advance(resolverRetry)
	reply, err = u.exchange(context.Background(), resolvers, testZone, query, false)
	if err != nil {
		t.Fatalf("third exchange() = %v, want nil", err)
	}
	if dead.count() != 2 || live.count() != 2 {
		t.Errorf("after the third exchange: queries to the first and second resolver = %d, %d, want 2, 2", dead.count(), live.count())
	}
	wantRelayed(t, reply, dead.received()[1].replies[0], query)
	wantDown(t, u)

	warns := logs.find("mesh dns resolver does not answer")
	if len(warns) != 1 {
		t.Fatalf("%d lines say the resolver does not answer, want 1", len(warns))
	}
	if warns[0].Level != slog.LevelWarn {
		t.Errorf("logged at %v, want %v", warns[0].Level, slog.LevelWarn)
	}
	for k, want := range map[string]string{"resolver": "192.0.2.1", "zone": testZone, "error": context.DeadlineExceeded.Error()} {
		if got := recordAttr(warns[0], k).String(); got != want {
			t.Errorf("resolver does not answer has %s=%q, want %q", k, got, want)
		}
	}
	infos := logs.find("mesh dns resolver answers again")
	if len(infos) != 1 {
		t.Fatalf("%d lines say the resolver answers again, want 1", len(infos))
	}
	if infos[0].Level != slog.LevelInfo {
		t.Errorf("logged at %v, want %v", infos[0].Level, slog.LevelInfo)
	}
	if got := recordAttr(infos[0], "resolver").String(); got != "192.0.2.1" {
		t.Errorf("resolver answers again has resolver=%q, want %q", got, "192.0.2.1")
	}
}

// wantDown fails the test unless exactly the resolvers named carry a mark.
func wantDown(t *testing.T, u *upstream, resolvers ...string) {
	t.Helper()
	u.mu.Lock()
	var got []string
	for r := range u.down {
		got = append(got, r.String())
	}
	u.mu.Unlock()
	slices.Sort(got)
	slices.Sort(resolvers)
	if !slices.Equal(got, resolvers) {
		t.Errorf("resolvers marked down = %q, want %q", got, resolvers)
	}
}

func TestUpstream_NoResolverAnswers(t *testing.T) {
	first := newFakeResolver(t, silent)
	second := newFakeResolver(t, silent)
	u, _, logs := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": first, "192.0.2.2": second})

	start := time.Now()
	reply, err := u.exchange(context.Background(), addrs("192.0.2.1", "192.0.2.2"), testZone, fwdQuery(t), false)
	elapsed := time.Since(start)

	if reply != nil {
		t.Errorf("exchange() returned a reply of %d bytes, want none", len(reply))
	}
	wantError(t, err, context.DeadlineExceeded)
	// The exchange has 4 seconds in all; a second on top covers the
	// scheduling of a loaded test host.
	if elapsed > forwardTimeout+time.Second {
		t.Errorf("exchange took %v, want at most %v", elapsed, forwardTimeout)
	}
	if first.count() != 1 || second.count() != 1 {
		t.Errorf("queries to the first and second resolver = %d, %d, want 1, 1", first.count(), second.count())
	}
	wantDown(t, u, "192.0.2.1", "192.0.2.2")
	if got := len(logs.find("mesh dns resolver does not answer")); got != 2 {
		t.Errorf("%d lines say a resolver does not answer, want 2", got)
	}
}

// Nothing listens on the port, so the dial is refused. Windows retries a
// refused connect for about two seconds before it reports it, so the test
// keeps the full timeout.
func TestUpstream_TCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free TCP port: %v", err)
	}
	closed := ln.Addr().(*net.TCPAddr).AddrPort()
	_ = ln.Close()
	u, _, logs := newTestUpstream(t, nil)
	u.target = func(netip.Addr) netip.AddrPort { return closed }

	_, err = u.exchange(context.Background(), addrs("192.0.2.1"), testZone, fwdQuery(t), true)

	wantError(t, err, errConnRefused)
	wantDown(t, u, "192.0.2.1")
	warns := logs.find("mesh dns resolver does not answer")
	if len(warns) != 1 {
		t.Fatalf("%d lines say the resolver does not answer, want 1", len(warns))
	}
	if logged, _ := recordAttr(warns[0], "error").Any().(error); !errors.Is(logged, errConnRefused) {
		t.Errorf("resolver does not answer has error=%v, want the refused dial", logged)
	}
}

func TestUpstream_Cancel(t *testing.T) {
	fake := newFakeResolver(t, silent)
	u, _, logs := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": fake})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	query := fwdQuery(t)

	type result struct {
		reply []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		reply, err := u.exchange(ctx, addrs("192.0.2.1"), testZone, query, false)
		done <- result{reply, err}
	}()
	fake.waitQueries(t, 1)

	cancel()
	cancelled := time.Now()
	select {
	case r := <-done:
		// The attempt had the whole 4 seconds, so a return within one
		// second of the cancel is the cancel's doing.
		if waited := time.Since(cancelled); waited > time.Second {
			t.Errorf("exchange returned %v after the cancel, want at once", waited)
		}
		if r.reply != nil {
			t.Errorf("exchange() returned a reply of %d bytes, want none", len(r.reply))
		}
		wantError(t, r.err, context.Canceled)
	case <-time.After(ioTimeout):
		t.Fatalf("exchange did not return within %v of the cancel", ioTimeout)
	}
	// The resolver did nothing wrong: plexd stopped asking.
	wantDown(t, u)
	if got := len(logs.find("mesh dns resolver does not answer")); got != 0 {
		t.Errorf("%d lines say the resolver does not answer, want none", got)
	}

	// A context that already ended sends nothing.
	if _, err := u.exchange(ctx, addrs("192.0.2.1"), testZone, query, false); !errors.Is(err, context.Canceled) {
		t.Errorf("exchange() with an ended context = %v, want an error wrapping %v", err, context.Canceled)
	}
	if got := fake.count(); got != 1 {
		t.Errorf("fake received %d queries, want 1", got)
	}
}

func TestUpstream_NoResolvers(t *testing.T) {
	u, _, _ := newTestUpstream(t, nil)
	u.target = func(a netip.Addr) netip.AddrPort {
		t.Errorf("target(%v) called, want nothing sent", a)
		return netip.AddrPort{}
	}
	for _, resolvers := range [][]netip.Addr{nil, {}} {
		_, err := u.exchange(context.Background(), resolvers, testZone, fwdQuery(t), false)
		wantError(t, err, errNoResolver)
		if want := "meshdns: forward to " + testZone + ": no resolver"; err == nil || err.Error() != want {
			t.Errorf("exchange() = %v, want %q", err, want)
		}
	}
}

func TestUpstream_ServfailAndRefused(t *testing.T) {
	tests := []struct {
		name          string
		first, second dnsmessage.RCode
		// fromSecond says whether the reply returned is the second's.
		fromSecond bool
	}{
		{"SERVFAIL then NOERROR", dnsmessage.RCodeServerFailure, dnsmessage.RCodeSuccess, true},
		{"REFUSED then NXDOMAIN", dnsmessage.RCodeRefused, dnsmessage.RCodeNameError, true},
		{"SERVFAIL then REFUSED", dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused, true},
		{"SERVFAIL from both", dnsmessage.RCodeServerFailure, dnsmessage.RCodeServerFailure, true},
		{"NXDOMAIN first", dnsmessage.RCodeNameError, dnsmessage.RCodeSuccess, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first := newFakeResolver(t, answerRCode(tc.first))
			second := newFakeResolver(t, answerRCode(tc.second))
			u, _, logs := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": first, "192.0.2.2": second})
			query := fwdQuery(t)

			reply, err := u.exchange(context.Background(), addrs("192.0.2.1", "192.0.2.2"), testZone, query, false)
			if err != nil {
				t.Fatalf("exchange() = %v, want a reply", err)
			}
			wantSecond := 0
			from, want := first, tc.first
			if tc.fromSecond {
				wantSecond = 1
				from, want = second, tc.second
			}
			if first.count() != 1 || second.count() != wantSecond {
				t.Errorf("queries to the first and second resolver = %d, %d, want 1, %d", first.count(), second.count(), wantSecond)
			}
			wantRelayed(t, reply, from.received()[0].replies[0], query)
			if m := parseResponse(t, reply); m.RCode != want {
				t.Errorf("RCode = %v, want %v", m.RCode, want)
			}
			// Every resolver answered, so none is marked.
			wantDown(t, u)
			if got := len(logs.find("mesh dns resolver does not answer")); got != 0 {
				t.Errorf("%d lines say a resolver does not answer, want none", got)
			}
		})
	}
}

func TestUpstream_LogsMarkOnce(t *testing.T) {
	fake := newFakeResolver(t, silent)
	u, clock, logs := newTestUpstream(t, map[string]*fakeResolver{"192.0.2.1": fake})
	// The resolver stays silent; nothing here is about the length of the
	// wait, so an attempt gives up sooner.
	u.timeout = 200 * time.Millisecond
	ask := func() error {
		_, err := u.exchange(context.Background(), addrs("192.0.2.1"), testZone, fwdQuery(t), false)
		return err
	}
	counts := func(t *testing.T, warns, infos int) {
		t.Helper()
		if got := len(logs.find("mesh dns resolver does not answer")); got != warns {
			t.Errorf("%d lines say the resolver does not answer, want %d", got, warns)
		}
		if got := len(logs.find("mesh dns resolver answers again")); got != infos {
			t.Errorf("%d lines say the resolver answers again, want %d", got, infos)
		}
	}

	for range 3 {
		if err := ask(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("exchange() = %v, want an error wrapping %v", err, context.DeadlineExceeded)
		}
	}
	counts(t, 1, 0)

	// The mark runs out while the resolver is still down. It is asked in its
	// turn again and fails again, which renews the mark without a new line.
	clock.advance(resolverRetry + time.Second)
	if err := ask(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exchange() after the mark ran out = %v, want an error wrapping %v", err, context.DeadlineExceeded)
	}
	if got := fake.count(); got != 4 {
		t.Fatalf("the resolver received %d queries, want 4: the one after the mark ran out did not reach it", got)
	}
	counts(t, 1, 0)
	u.mu.Lock()
	until := u.down[netip.MustParseAddr("192.0.2.1")]
	u.mu.Unlock()
	if want := clock.now().Add(resolverRetry); !until.Equal(want) {
		t.Errorf("mark after the failed retry runs until %v, want %v", until, want)
	}

	fake.setAnswer(answerA("198.51.100.53"))
	for range 2 {
		if err := ask(); err != nil {
			t.Fatalf("exchange() = %v, want nil", err)
		}
	}
	counts(t, 1, 1)

	// Down again after it answered: a new mark, so a new line.
	fake.setAnswer(silent)
	if err := ask(); err == nil {
		t.Fatalf("exchange() = nil, want an error")
	}
	counts(t, 2, 1)
}

func TestUpstream_Prune(t *testing.T) {
	u, clock, _ := newTestUpstream(t, nil)
	mark := func(rs ...string) {
		for _, r := range rs {
			u.down[netip.MustParseAddr(r)] = clock.now().Add(resolverRetry)
		}
	}
	keep := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{fwdZone(testZone, "192.0.2.1")},
		CatchAll:     []string{"192.0.2.3"},
	}, nil)

	mark("192.0.2.1", "192.0.2.2", "192.0.2.3")
	u.prune(keep)
	wantDown(t, u, "192.0.2.1", "192.0.2.3")

	u.prune(nil)
	wantDown(t, u)
}
