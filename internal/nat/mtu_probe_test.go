package nat

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// fakeSTUN configures a loopback STUN server for the ProbePathMTU tests. The
// zero value answers every well-formed Binding Request with a success
// response.
type fakeSTUN struct {
	// maxRequest is the largest request, in bytes, the server answers. A
	// larger one is dropped, as a router on a smaller path drops a DF packet.
	// 0 answers every size.
	maxRequest int
	// dropBaseline drops the unpadded 20-byte request and answers the padded
	// ones, as a path that loses one datagram of the round.
	dropBaseline bool
	// errorResponse answers with a Binding error response (0x0111), as a
	// server without RFC 5780 answers the PADDING attribute.
	errorResponse bool
	// foreignTransaction answers with a transaction ID the request did not
	// carry.
	foreignTransaction bool
	// foreignFirst sends a datagram too short to be STUN and an answer to
	// another transaction ahead of every answer, as stray datagrams can reach
	// a probe socket before its own answer does.
	foreignFirst bool
	// silent never answers.
	silent bool
	// received, when set, records every datagram the server receives.
	received *receivedRequests
}

// receivedRequests records the datagrams a fakeSTUN received, so a test can
// check what ProbePathMTU put on the wire.
type receivedRequests struct {
	mu   sync.Mutex
	reqs [][]byte
}

func (r *receivedRequests) add(req []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, slices.Clone(req))
}

// all returns the datagrams received so far.
func (r *receivedRequests) all() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqs)
}

// start serves f on a loopback port until the test ends and returns the
// server's address.
func (f fakeSTUN) start(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if f.received != nil {
				f.received.add(buf[:n])
			}
			for _, resp := range f.answer(buf[:n]) {
				_, _ = conn.WriteTo(resp, from)
			}
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})

	return conn.LocalAddr().String()
}

// answer returns the datagrams the server sends back for req, in order, or
// nil when it drops req. Only a well-formed Binding Request is answered, so a
// padded request whose declared length disagrees with its size goes
// unanswered, as it would at a real server.
func (f fakeSTUN) answer(req []byte) [][]byte {
	if f.silent || (f.maxRequest > 0 && len(req) > f.maxRequest) || (f.dropBaseline && len(req) == 20) {
		return nil
	}
	if len(req) < 20 ||
		binary.BigEndian.Uint16(req[0:2]) != stunBindingRequest ||
		int(binary.BigEndian.Uint16(req[2:4])) != len(req)-20 ||
		binary.BigEndian.Uint32(req[4:8]) != stunMagicCookie {
		return nil
	}

	txID := [12]byte(req[8:20])
	var replies [][]byte
	if f.foreignFirst {
		other := txID
		other[0] ^= 0xFF
		replies = append(replies,
			[]byte{0x01, 0x01, 0x00, 0x00},
			buildUDPTestResponse(other, net.IPv4(203, 0, 113, 5), 54321))
	}
	if f.foreignTransaction {
		txID[0] ^= 0xFF
	}
	if f.errorResponse {
		return append(replies, buildTestResponse(stunBindingErrorResponse, txID, nil))
	}
	return append(replies, buildUDPTestResponse(txID, net.IPv4(203, 0, 113, 5), 54321))
}

// runProbe calls ProbePathMTU and returns its result and how long it took.
// It fails the test when a goroutine the call started is still running after
// it returned: every probe, socket deadline and AfterFunc must be done by
// then.
func runProbe(t *testing.T, ctx context.Context, servers []string, timeout time.Duration) (int, time.Duration, error) {
	t.Helper()

	running := goleak.IgnoreCurrent()
	start := time.Now()
	got, err := ProbePathMTU(ctx, servers, timeout)
	elapsed := time.Since(start)
	goleak.VerifyNone(t, running)

	return got, elapsed, err
}

func TestMTUProbeSizes(t *testing.T) {
	// Ethernet (1500), PPPoE (1492), DS-Lite (1460) and DS-Lite over PPPoE
	// (1452), with steps in between, down to 1360.
	want := []int{1500, 1492, 1480, 1472, 1460, 1452, 1440, 1428, 1420, 1400, 1380, 1360}
	if !slices.Equal(MTUProbeSizes, want) {
		t.Errorf("MTUProbeSizes = %v, want %v", MTUProbeSizes, want)
	}
}

func TestProbePathMTU_BlackHoleAboveLimit(t *testing.T) {
	// A 1424-byte request is a 1452-byte IPv4 packet: DS-Lite over PPPoE.
	addr := fakeSTUN{maxRequest: 1424}.start(t)

	got, _, err := runProbe(t, context.Background(), []string{addr}, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1452 {
		t.Errorf("ProbePathMTU() = %d, want 1452", got)
	}
}

func TestProbePathMTU_AllSizes(t *testing.T) {
	addr := fakeSTUN{}.start(t)

	const timeout = 2 * time.Second
	got, elapsed, err := runProbe(t, context.Background(), []string{addr}, timeout)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1500 {
		t.Errorf("ProbePathMTU() = %d, want 1500", got)
	}
	// Every probe was answered, so the round must end with the last answer
	// rather than wait out its timeout.
	if elapsed >= timeout {
		t.Errorf("ProbePathMTU() took %v, want it to return before the %v timeout", elapsed, timeout)
	}
}

func TestProbePathMTU_RequestSizes(t *testing.T) {
	received := &receivedRequests{}
	addr := fakeSTUN{received: received}.start(t)

	// Every probe is answered, so the server has received every request by
	// the time the round ends.
	if _, _, err := runProbe(t, context.Background(), []string{addr}, 2*time.Second); err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}

	var got []int
	for _, req := range received.all() {
		got = append(got, len(req))
	}
	slices.Sort(got)
	// The unpadded baseline, and every ladder entry less the 28 bytes of IPv4
	// and UDP header, so each request leaves the host as an IPv4 packet of
	// exactly its entry's size.
	want := []int{20, 1332, 1352, 1372, 1392, 1400, 1412, 1424, 1432, 1444, 1452, 1464, 1472}
	if !slices.Equal(got, want) {
		t.Errorf("request sizes = %v, want %v", got, want)
	}
}

func TestProbePathMTU_TransactionIDs(t *testing.T) {
	received := &receivedRequests{}
	addr := fakeSTUN{received: received}.start(t)

	if _, _, err := runProbe(t, context.Background(), []string{addr}, 2*time.Second); err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}

	// A fresh random ID per probe is what keeps an off-path sender from
	// answering for the server.
	reqs := received.all()
	if len(reqs) != 13 {
		t.Fatalf("server received %d requests, want 13 (the baseline and the 12 ladder sizes)", len(reqs))
	}
	seen := make(map[[12]byte]bool)
	for _, req := range reqs {
		txID := [12]byte(req[8:20])
		if txID == ([12]byte{}) {
			t.Errorf("the %d-byte request carries the zero transaction ID", len(req))
		}
		if seen[txID] {
			t.Errorf("transaction ID %x is carried by more than one request", txID)
		}
		seen[txID] = true
	}
}

func TestProbePathMTU_DontFragmentOnEveryProbe(t *testing.T) {
	// Not parallel: probeControl is package state.
	var (
		mu    sync.Mutex
		calls int
		errs  []error
	)
	// The wrapper runs the default control, not setDontFragment itself, and
	// reads the option back, so a default that sets nothing fails here too.
	old := probeControl
	t.Cleanup(func() { probeControl = old })
	probeControl = func(network, address string, c syscall.RawConn) error {
		err := old(network, address, c)
		if err == nil {
			var got, want int
			got, want, err = dontFragmentOption(c)
			if err == nil && got != want {
				err = fmt.Errorf("don't-fragment option = %d, want %d", got, want)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		calls++
		if err != nil {
			errs = append(errs, err)
		}
		return err
	}

	addr := fakeSTUN{}.start(t)
	got, _, err := runProbe(t, context.Background(), []string{addr}, 2*time.Second)

	mu.Lock()
	defer mu.Unlock()
	if calls != 13 {
		t.Errorf("don't-fragment control ran on %d probe sockets, want 13 (the baseline and the 12 ladder sizes)", calls)
	}
	for _, dfErr := range errs {
		t.Errorf("probe socket without don't-fragment: %v", dfErr)
	}
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1500 {
		t.Errorf("ProbePathMTU() = %d, want 1500", got)
	}
}

func TestProbePathMTU_ErrorResponseCounts(t *testing.T) {
	addr := fakeSTUN{errorResponse: true}.start(t)

	got, _, err := runProbe(t, context.Background(), []string{addr}, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1500 {
		t.Errorf("ProbePathMTU() = %d, want 1500", got)
	}
}

func TestProbePathMTU_BaselineOnly(t *testing.T) {
	addr := fakeSTUN{maxRequest: 20}.start(t)

	got, _, err := runProbe(t, context.Background(), []string{addr}, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 48 {
		t.Errorf("ProbePathMTU() = %d, want 48 (the unpadded baseline)", got)
	}
}

func TestProbePathMTU_BaselineLost(t *testing.T) {
	// The baseline is lost and the padded probes up to 1452 are answered:
	// the ladder's answers stand without it.
	addr := fakeSTUN{dropBaseline: true, maxRequest: 1424}.start(t)

	got, _, err := runProbe(t, context.Background(), []string{addr}, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1452 {
		t.Errorf("ProbePathMTU() = %d, want 1452 (the largest ladder answer)", got)
	}
}

func TestProbePathMTU_MaxOverServers(t *testing.T) {
	limited := fakeSTUN{maxRequest: 1424}.start(t)
	full := fakeSTUN{}.start(t)

	// The larger answer must win wherever its server is listed.
	tests := []struct {
		name    string
		servers []string
	}{
		{"limited first", []string{limited, full}},
		{"full first", []string{full, limited}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := runProbe(t, context.Background(), tt.servers, 300*time.Millisecond)
			if err != nil {
				t.Fatalf("ProbePathMTU() error = %v, want nil", err)
			}
			if got != 1500 {
				t.Errorf("ProbePathMTU() = %d, want 1500 (the larger server's answer)", got)
			}
		})
	}
}

func TestProbePathMTU_OneServerDown(t *testing.T) {
	closed, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	down := closed.LocalAddr().String()
	if err := closed.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	limited := fakeSTUN{maxRequest: 1424}.start(t)

	got, _, err := runProbe(t, context.Background(), []string{down, limited}, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1452 {
		t.Errorf("ProbePathMTU() = %d, want 1452", got)
	}
}

func TestProbePathMTU_IgnoresForeignTransaction(t *testing.T) {
	addr := fakeSTUN{foreignTransaction: true}.start(t)

	got, _, err := runProbe(t, context.Background(), []string{addr}, 300*time.Millisecond)
	if !errors.Is(err, ErrMTUProbeInconclusive) {
		t.Fatalf("ProbePathMTU() error = %v, want ErrMTUProbeInconclusive", err)
	}
	if got != 0 {
		t.Errorf("ProbePathMTU() = %d, want 0", got)
	}
}

func TestProbePathMTU_SkipsForeignDatagrams(t *testing.T) {
	// Every answer comes after a datagram too short to be STUN and an answer
	// to another transaction: each probe must read past both to its own.
	addr := fakeSTUN{foreignFirst: true}.start(t)

	got, _, err := runProbe(t, context.Background(), []string{addr}, 2*time.Second)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1500 {
		t.Errorf("ProbePathMTU() = %d, want 1500", got)
	}
}

func TestProbePathMTU_NoAnswer(t *testing.T) {
	addr := fakeSTUN{silent: true}.start(t)

	got, elapsed, err := runProbe(t, context.Background(), []string{addr}, 300*time.Millisecond)
	if elapsed >= time.Second {
		t.Errorf("ProbePathMTU() took %v, want under 1s with a 300ms timeout", elapsed)
	}
	if !errors.Is(err, ErrMTUProbeInconclusive) {
		t.Fatalf("ProbePathMTU() error = %v, want ErrMTUProbeInconclusive", err)
	}
	// The read error names the address too, so only the prefix shows that
	// ProbePathMTU named the server.
	if want := ErrMTUProbeInconclusive.Error() + ": " + addr + ": "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ProbePathMTU() error = %q, want it to start with %q", err, want)
	}
	if got != 0 {
		t.Errorf("ProbePathMTU() = %d, want 0", got)
	}
}

func TestProbePathMTU_EmptyServers(t *testing.T) {
	tests := []struct {
		name    string
		servers []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, elapsed, err := runProbe(t, context.Background(), tt.servers, 10*time.Second)
			// Exactly the sentinel: there is no per-server reason to wrap.
			if err != ErrMTUProbeInconclusive {
				t.Errorf("ProbePathMTU() error = %v, want exactly ErrMTUProbeInconclusive", err)
			}
			if got != 0 {
				t.Errorf("ProbePathMTU() = %d, want 0", got)
			}
			if elapsed >= 100*time.Millisecond {
				t.Errorf("ProbePathMTU() took %v, want it to return immediately", elapsed)
			}
		})
	}
}

func TestProbePathMTU_ResolveError(t *testing.T) {
	got, _, err := runProbe(t, context.Background(), []string{"no-port-here"}, 300*time.Millisecond)
	if !errors.Is(err, ErrMTUProbeInconclusive) {
		t.Fatalf("ProbePathMTU() error = %v, want ErrMTUProbeInconclusive", err)
	}
	// The SplitHostPort error names the server too, so only the prefix shows
	// that ProbePathMTU named it.
	if want := ErrMTUProbeInconclusive.Error() + ": no-port-here: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ProbePathMTU() error = %q, want it to start with %q", err, want)
	}
	if got != 0 {
		t.Errorf("ProbePathMTU() = %d, want 0", got)
	}
}

func TestProbePathMTU_ResolvesHostNameToIPv4(t *testing.T) {
	// Not parallel: lookupNetIP is package state.
	addr := fakeSTUN{}.start(t)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}

	var (
		mu       sync.Mutex
		networks []string
	)
	old := lookupNetIP
	t.Cleanup(func() { lookupNetIP = old })
	lookupNetIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		mu.Lock()
		networks = append(networks, network)
		mu.Unlock()
		if host != "stun.invalid" {
			return nil, fmt.Errorf("lookup %s: no such host", host)
		}
		// The form the system resolver gives a hosts-file entry in.
		return []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, nil
	}

	got, _, err := runProbe(t, context.Background(), []string{net.JoinHostPort("stun.invalid", port)}, 2*time.Second)
	if err != nil {
		t.Fatalf("ProbePathMTU() error = %v, want nil", err)
	}
	if got != 1500 {
		t.Errorf("ProbePathMTU() = %d, want 1500", got)
	}

	mu.Lock()
	defer mu.Unlock()
	// The probe sockets dial udp4, so an IPv6 address would be no use.
	if want := []string{"ip4"}; !slices.Equal(networks, want) {
		t.Errorf("lookup networks = %q, want %q", networks, want)
	}
}

func TestProbePathMTU_ResolveBoundedByRound(t *testing.T) {
	// Not parallel: lookupNetIP is package state.
	var (
		mu        sync.Mutex
		lookupCtx context.Context
	)
	old := lookupNetIP
	t.Cleanup(func() { lookupNetIP = old })
	// A nameserver that never answers: the lookup returns when its context is
	// done. The 2s bound only keeps a lookup whose context is never done from
	// holding the test.
	lookupNetIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		mu.Lock()
		lookupCtx = ctx
		mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
			return nil, errors.New("nameserver never answered")
		}
	}

	const server = "stun.invalid:3478"
	got, elapsed, err := runProbe(t, context.Background(), []string{server}, 300*time.Millisecond)
	if elapsed >= time.Second {
		t.Errorf("ProbePathMTU() took %v, want under 1s with a 300ms timeout", elapsed)
	}
	if !errors.Is(err, ErrMTUProbeInconclusive) {
		t.Fatalf("ProbePathMTU() error = %v, want ErrMTUProbeInconclusive", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ProbePathMTU() error = %v, want it to wrap the lookup's context.DeadlineExceeded", err)
	}
	if want := ErrMTUProbeInconclusive.Error() + ": " + server + ": "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ProbePathMTU() error = %q, want it to start with %q", err, want)
	}
	if got != 0 {
		t.Errorf("ProbePathMTU() = %d, want 0", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if lookupCtx == nil || lookupCtx.Err() == nil {
		t.Errorf("lookup context not done after the round, want the round's context")
	}
}

func TestProbePathMTU_ContextCanceled(t *testing.T) {
	tests := []struct {
		name   string
		server fakeSTUN
	}{
		// Nothing has been answered when the cancel comes.
		{"nothing answered", fakeSTUN{silent: true}},
		// The baseline and the sizes up to 1452 are answered within the
		// first round trip, long before the cancel, and the larger ones are
		// still pending: the answers must not win over the cancel.
		{"answered up to 1452", fakeSTUN{maxRequest: 1424}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := tt.server.start(t)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timer := time.AfterFunc(100*time.Millisecond, cancel)
			defer timer.Stop()

			got, elapsed, err := runProbe(t, ctx, []string{addr}, 10*time.Second)
			if elapsed >= time.Second {
				t.Errorf("ProbePathMTU() took %v, want under 1s after a cancel at 100ms", elapsed)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("ProbePathMTU() error = %v, want context.Canceled", err)
			}
			if got != 0 {
				t.Errorf("ProbePathMTU() = %d, want 0", got)
			}
		})
	}
}
