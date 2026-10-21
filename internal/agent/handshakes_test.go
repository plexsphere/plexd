package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// The composition root hands the reporter the control-plane client and the
// WireGuard manager; these assertions keep the two seams satisfiable by them.
var (
	_ HandshakeReportClient = (*api.ControlPlane)(nil)
	_ MeshPeerStatsSource   = (*wireguard.Manager)(nil)
)

const (
	testHandshakeNodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1"
	testPeerA           = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1"
	testPeerB           = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2"
	testPeerC           = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b3"
)

var testObservedAt = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeHandshakeClient records every report it is handed and answers the n-th
// with errs[n] when that is set, and with resp (or a receipt recording every
// entry) otherwise.
type fakeHandshakeClient struct {
	mu       sync.Mutex
	nodeIDs  []string
	requests []api.HandshakeReportRequest
	errs     []error
	resp     *api.HandshakeReportResponse
}

func (c *fakeHandshakeClient) ReportHandshakes(_ context.Context, nodeID string, req api.HandshakeReportRequest) (*api.HandshakeReportResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	idx := len(c.requests)
	// The reporter must not touch a body after sending it, but a copy keeps
	// the recorded body independent of the caller's slice either way.
	req.Peers = slices.Clone(req.Peers)
	c.nodeIDs = append(c.nodeIDs, nodeID)
	c.requests = append(c.requests, req)

	if idx < len(c.errs) && c.errs[idx] != nil {
		return nil, c.errs[idx]
	}
	if c.resp != nil {
		return c.resp, nil
	}
	return &api.HandshakeReportResponse{AcceptedAt: req.ObservedAt, Recorded: len(req.Peers)}, nil
}

func (c *fakeHandshakeClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *fakeHandshakeClient) recorded() ([]string, []api.HandshakeReportRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.nodeIDs), slices.Clone(c.requests)
}

// fakeStatsSource answers the n-th read with errs[n] when that is set, and
// with a copy of stats otherwise.
type fakeStatsSource struct {
	mu    sync.Mutex
	reads int
	stats []wireguard.MeshPeerStat
	errs  []error
}

func (s *fakeStatsSource) MeshPeerStats() ([]wireguard.MeshPeerStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.reads
	s.reads++
	if idx < len(s.errs) && s.errs[idx] != nil {
		return nil, s.errs[idx]
	}
	return slices.Clone(s.stats), nil
}

func (s *fakeStatsSource) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// steppingClock returns next on each reading and then advances it by step, so
// every report a ticking reporter sends carries a distinct, predictable
// observed_at without the test having to synchronize with the ticks.
type steppingClock struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
}

func (c *steppingClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.next
	c.next = c.next.Add(c.step)
	return t
}

// lockedBuffer is a log sink the reporter goroutine may write while the test
// reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newDebugLogger() (*slog.Logger, *lockedBuffer) {
	buf := &lockedBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// countLogLines returns how many lines of logs carry msg as their message.
func countLogLines(logs, msg string) int {
	n := 0
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			n++
		}
	}
	return n
}

// logLine returns the line of logs carrying msg as its message, failing the
// test unless exactly one line does.
func logLine(t *testing.T, logs, msg string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("log lines with msg %q = %d, want 1; logs:\n%s", msg, len(found), logs)
	}
	return found[0]
}

// newFixedClockReporter builds a reporter whose clock always reads
// testObservedAt, for tests that drive reportOnce directly.
func newFixedClockReporter(client HandshakeReportClient, source MeshPeerStatsSource, logger *slog.Logger) *HandshakeReporter {
	r := NewHandshakeReporter(time.Hour, testHandshakeNodeID, client, source, logger)
	r.now = func() time.Time { return testObservedAt }
	return r
}

// startReporter runs r.Run in a goroutine and returns a stop function that
// cancels it and waits for Run to return nil. The stop is also registered as a
// cleanup, so a failed assertion does not leave the goroutine to goleak.
func startReporter(t *testing.T, r *HandshakeReporter) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run() = %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("Run did not return within 5s of the context being cancelled")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func meshPeer(nodeID, endpoint string, lastHandshake time.Time) wireguard.MeshPeerStat {
	var ep netip.AddrPort
	if endpoint != "" {
		ep = netip.MustParseAddrPort(endpoint)
	}
	return wireguard.MeshPeerStat{NodeID: nodeID, Endpoint: ep, LastHandshake: lastHandshake}
}

// ---------------------------------------------------------------------------
// buildHandshakeReport
// ---------------------------------------------------------------------------

func TestBuildHandshakeReport_AgesAndEndpointsSortedByAge(t *testing.T) {
	stats := []wireguard.MeshPeerStat{
		meshPeer(testPeerB, "[2001:db8::7]:51820", testObservedAt.Add(-130*time.Second)),
		meshPeer(testPeerA, "198.51.100.7:51820", testObservedAt.Add(-5*time.Second)),
	}

	req, skipped, truncated := buildHandshakeReport(testObservedAt, stats)

	if !req.ObservedAt.Equal(testObservedAt) {
		t.Errorf("ObservedAt = %v, want %v", req.ObservedAt, testObservedAt)
	}
	want := []api.HandshakeReportPeer{
		{PeerNodeID: testPeerA, LastHandshakeAgeSeconds: 5, Endpoint: "198.51.100.7:51820"},
		{PeerNodeID: testPeerB, LastHandshakeAgeSeconds: 130, Endpoint: "[2001:db8::7]:51820"},
	}
	if !slices.Equal(req.Peers, want) {
		t.Errorf("Peers = %+v, want %+v", req.Peers, want)
	}
	if skipped != 0 || truncated != 0 {
		t.Errorf("skipped, truncated = %d, %d, want 0, 0", skipped, truncated)
	}
}

func TestBuildHandshakeReport_NothingToReport(t *testing.T) {
	tests := []struct {
		name  string
		stats []wireguard.MeshPeerStat
	}{
		{name: "nil stats", stats: nil},
		{name: "empty stats", stats: []wireguard.MeshPeerStat{}},
		{
			// A peer with no handshake is left out before any other rule
			// applies, so even an id that would be skipped is not counted.
			name: "no handshake on any peer",
			stats: []wireguard.MeshPeerStat{
				meshPeer(testPeerA, "198.51.100.7:51820", time.Time{}),
				meshPeer(testPeerB, "", time.Time{}),
				meshPeer("peer-1", "198.51.100.9:51820", time.Time{}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, skipped, truncated := buildHandshakeReport(testObservedAt, tt.stats)
			if req.Peers == nil {
				t.Fatal("Peers = nil, want a non-nil empty slice")
			}
			if len(req.Peers) != 0 {
				t.Errorf("Peers = %+v, want empty", req.Peers)
			}
			if skipped != 0 || truncated != 0 {
				t.Errorf("skipped, truncated = %d, %d, want 0, 0", skipped, truncated)
			}
		})
	}
}

func TestBuildHandshakeReport_Normalization(t *testing.T) {
	tests := []struct {
		name          string
		endpoint      netip.AddrPort
		lastHandshake time.Time
		wantEndpoint  string
		wantAge       int32
	}{
		{
			name:          "IPv4-mapped IPv6 address is unmapped",
			endpoint:      netip.AddrPortFrom(netip.MustParseAddr("::ffff:198.51.100.7"), 51820),
			lastHandshake: testObservedAt.Add(-5 * time.Second),
			wantEndpoint:  "198.51.100.7:51820",
			wantAge:       5,
		},
		{
			name:          "IPv6 zone is stripped",
			endpoint:      netip.MustParseAddrPort("[fe80::1%eth0]:51820"),
			lastHandshake: testObservedAt.Add(-5 * time.Second),
			wantEndpoint:  "[fe80::1]:51820",
			wantAge:       5,
		},
		{
			name:          "age is floored to whole seconds",
			endpoint:      netip.MustParseAddrPort("198.51.100.7:51820"),
			lastHandshake: testObservedAt.Add(-4900 * time.Millisecond),
			wantEndpoint:  "198.51.100.7:51820",
			wantAge:       4,
		},
		{
			name:          "handshake after observedAt is clamped to 0",
			endpoint:      netip.MustParseAddrPort("198.51.100.7:51820"),
			lastHandshake: testObservedAt.Add(3 * time.Second),
			wantEndpoint:  "198.51.100.7:51820",
			wantAge:       0,
		},
		{
			name:          "age beyond int32 is clamped to its maximum",
			endpoint:      netip.MustParseAddrPort("198.51.100.7:51820"),
			lastHandshake: testObservedAt.AddDate(-70, 0, 0),
			wantEndpoint:  "198.51.100.7:51820",
			wantAge:       2147483647,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := []wireguard.MeshPeerStat{{NodeID: testPeerA, Endpoint: tt.endpoint, LastHandshake: tt.lastHandshake}}

			req, skipped, _ := buildHandshakeReport(testObservedAt, stats)

			want := []api.HandshakeReportPeer{{PeerNodeID: testPeerA, LastHandshakeAgeSeconds: tt.wantAge, Endpoint: tt.wantEndpoint}}
			if !slices.Equal(req.Peers, want) {
				t.Errorf("Peers = %+v, want %+v", req.Peers, want)
			}
			if skipped != 0 {
				t.Errorf("skipped = %d, want 0", skipped)
			}
		})
	}
}

func TestBuildHandshakeReport_SkipsEntriesTheContractRefuses(t *testing.T) {
	handshake := testObservedAt.Add(-7 * time.Second)
	tests := []struct {
		name string
		stat wireguard.MeshPeerStat
	}{
		{name: "invalid endpoint", stat: wireguard.MeshPeerStat{NodeID: testPeerB, LastHandshake: handshake}},
		{name: "port 0", stat: meshPeer(testPeerB, "198.51.100.8:0", handshake)},
		{name: "unspecified IPv4 address", stat: meshPeer(testPeerB, "0.0.0.0:51820", handshake)},
		{name: "unspecified IPv6 address", stat: meshPeer(testPeerB, "[::]:51820", handshake)},
		{name: "IPv4-mapped unspecified address", stat: meshPeer(testPeerB, "[::ffff:0.0.0.0]:51820", handshake)},
		{name: "node ID that is not a UUID", stat: meshPeer("peer-1", "198.51.100.8:51820", handshake)},
		{name: "empty node ID", stat: meshPeer("", "198.51.100.8:51820", handshake)},
		{name: "all-zero UUID", stat: meshPeer("00000000-0000-0000-0000-000000000000", "198.51.100.8:51820", handshake)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := []wireguard.MeshPeerStat{
				tt.stat,
				meshPeer(testPeerA, "198.51.100.7:51820", testObservedAt.Add(-5*time.Second)),
			}

			req, skipped, truncated := buildHandshakeReport(testObservedAt, stats)

			want := []api.HandshakeReportPeer{{PeerNodeID: testPeerA, LastHandshakeAgeSeconds: 5, Endpoint: "198.51.100.7:51820"}}
			if !slices.Equal(req.Peers, want) {
				t.Errorf("Peers = %+v, want only the valid peer %+v", req.Peers, want)
			}
			if skipped != 1 {
				t.Errorf("skipped = %d, want 1", skipped)
			}
			if truncated != 0 {
				t.Errorf("truncated = %d, want 0", truncated)
			}
		})
	}
}

func TestBuildHandshakeReport_RepeatedNodeIDKeepsSmallerAge(t *testing.T) {
	older := meshPeer(testPeerA, "198.51.100.7:51820", testObservedAt.Add(-30*time.Second))
	newer := meshPeer(testPeerA, "203.0.113.9:51820", testObservedAt.Add(-10*time.Second))
	want := []api.HandshakeReportPeer{{PeerNodeID: testPeerA, LastHandshakeAgeSeconds: 10, Endpoint: "203.0.113.9:51820"}}

	tests := []struct {
		name  string
		stats []wireguard.MeshPeerStat
	}{
		{name: "older first", stats: []wireguard.MeshPeerStat{older, newer}},
		{name: "newer first", stats: []wireguard.MeshPeerStat{newer, older}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, skipped, truncated := buildHandshakeReport(testObservedAt, tt.stats)
			if !slices.Equal(req.Peers, want) {
				t.Errorf("Peers = %+v, want %+v", req.Peers, want)
			}
			if skipped != 0 || truncated != 0 {
				t.Errorf("skipped, truncated = %d, %d, want 0, 0", skipped, truncated)
			}
		})
	}
}

func TestBuildHandshakeReport_EqualAgesSortByPeerNodeID(t *testing.T) {
	handshake := testObservedAt.Add(-9 * time.Second)
	stats := []wireguard.MeshPeerStat{
		meshPeer(testPeerC, "198.51.100.3:51820", handshake),
		meshPeer(testPeerA, "198.51.100.1:51820", handshake),
		meshPeer(testPeerB, "198.51.100.2:51820", handshake),
	}

	req, _, _ := buildHandshakeReport(testObservedAt, stats)

	got := make([]string, 0, len(req.Peers))
	for _, p := range req.Peers {
		got = append(got, p.PeerNodeID)
	}
	if want := []string{testPeerA, testPeerB, testPeerC}; !slices.Equal(got, want) {
		t.Errorf("PeerNodeID order = %v, want %v", got, want)
	}
}

func TestBuildHandshakeReport_TruncatesToTheMostRecent(t *testing.T) {
	const total = 4100
	// Oldest first, so keeping the first MaxHandshakeReportPeers entries of
	// the input would keep exactly the wrong ones.
	stats := make([]wireguard.MeshPeerStat, 0, total)
	for age := total - 1; age >= 0; age-- {
		stats = append(stats, meshPeer(
			fmt.Sprintf("0190a8b8-a0c0-7a0a-8a0a-%012x", age+1),
			"198.51.100.7:51820",
			testObservedAt.Add(-time.Duration(age)*time.Second),
		))
	}

	req, skipped, truncated := buildHandshakeReport(testObservedAt, stats)

	if len(req.Peers) != api.MaxHandshakeReportPeers {
		t.Fatalf("len(Peers) = %d, want %d", len(req.Peers), api.MaxHandshakeReportPeers)
	}
	if truncated != 4 {
		t.Errorf("truncated = %d, want 4", truncated)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	for i, p := range req.Peers {
		if p.LastHandshakeAgeSeconds != int32(i) {
			t.Fatalf("Peers[%d] age = %d, want %d (the most recent handshakes, by age)", i, p.LastHandshakeAgeSeconds, i)
		}
	}
}

// ---------------------------------------------------------------------------
// Construction and Run
// ---------------------------------------------------------------------------

func TestNewHandshakeReporter_NonPositiveIntervalRunsAtDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			client := &fakeHandshakeClient{}
			source := &fakeStatsSource{}
			logger, logs := newDebugLogger()

			r := NewHandshakeReporter(interval, testHandshakeNodeID, client, source, logger)
			if r.interval != 30*time.Second {
				t.Errorf("interval = %v, want 30s", r.interval)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := r.Run(ctx); err != nil {
				t.Fatalf("Run() = %v, want nil", err)
			}

			line := logLine(t, logs.String(), "agent: handshake report: started")
			if !strings.Contains(line, "interval=30s") {
				t.Errorf("started log = %q, want interval=30s", line)
			}
			if got := client.calls(); got != 0 {
				t.Errorf("reports = %d, want 0", got)
			}
		})
	}
}

func TestHandshakeReporter_RunSendsNothingAtStart(t *testing.T) {
	client := &fakeHandshakeClient{}
	source := &fakeStatsSource{stats: []wireguard.MeshPeerStat{
		meshPeer(testPeerA, "198.51.100.7:51820", testObservedAt.Add(-5*time.Second)),
	}}
	logger, logs := newDebugLogger()
	r := NewHandshakeReporter(time.Hour, testHandshakeNodeID, client, source, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}

	if got := client.calls(); got != 0 {
		t.Errorf("reports = %d, want 0 before the first tick", got)
	}
	if got := source.readCount(); got != 0 {
		t.Errorf("device reads = %d, want 0 before the first tick", got)
	}
	line := logLine(t, logs.String(), "agent: handshake report: started")
	for _, want := range []string{"level=INFO", "component=handshake-report", "interval=1h0m0s"} {
		if !strings.Contains(line, want) {
			t.Errorf("started log = %q, want it to contain %q", line, want)
		}
	}
}

func TestHandshakeReporter_RunReportsEveryTickWithAFreshBody(t *testing.T) {
	// The clock reads in a non-UTC zone to prove observed_at is sent as UTC.
	start := time.Date(2026, 10, 21, 14, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	const step = 10 * time.Second
	clock := &steppingClock{next: start, step: step}

	client := &fakeHandshakeClient{}
	source := &fakeStatsSource{stats: []wireguard.MeshPeerStat{
		meshPeer(testPeerA, "198.51.100.7:51820", start.Add(-5*time.Second)),
	}}
	r := NewHandshakeReporter(10*time.Millisecond, testHandshakeNodeID, client, source, testLogger())
	r.now = clock.now

	stop := startReporter(t, r)
	waitFor(t, 5*time.Second, func() bool { return client.calls() >= 2 })
	stop()

	nodeIDs, reqs := client.recorded()
	if len(reqs) < 2 {
		t.Fatalf("reports = %d, want >= 2", len(reqs))
	}
	if reads := source.readCount(); reads != len(reqs) {
		t.Errorf("device reads = %d, reports = %d, want one report per read", reads, len(reqs))
	}
	for k, req := range reqs {
		if nodeIDs[k] != testHandshakeNodeID {
			t.Errorf("report %d nodeID = %q, want %q", k, nodeIDs[k], testHandshakeNodeID)
		}
		wantObservedAt := start.Add(time.Duration(k) * step)
		if !req.ObservedAt.Equal(wantObservedAt) {
			t.Errorf("report %d ObservedAt = %v, want the clock's reading %v", k, req.ObservedAt, wantObservedAt)
		}
		if req.ObservedAt.Location() != time.UTC {
			t.Errorf("report %d ObservedAt location = %v, want UTC", k, req.ObservedAt.Location())
		}
		want := []api.HandshakeReportPeer{{
			PeerNodeID:              testPeerA,
			LastHandshakeAgeSeconds: int32(5 + 10*k),
			Endpoint:                "198.51.100.7:51820",
		}}
		if !slices.Equal(req.Peers, want) {
			t.Errorf("report %d Peers = %+v, want %+v", k, req.Peers, want)
		}
	}
	if reqs[0].ObservedAt.Equal(reqs[1].ObservedAt) {
		t.Errorf("two ticks sent the same observed_at %v, want a fresh one per tick", reqs[0].ObservedAt)
	}
	if reqs[0].Peers[0].LastHandshakeAgeSeconds == reqs[1].Peers[0].LastHandshakeAgeSeconds {
		t.Errorf("two ticks sent the same age %d, want a fresh one per tick", reqs[0].Peers[0].LastHandshakeAgeSeconds)
	}
}

func TestHandshakeReporter_RunReturnsNilAfterCancel(t *testing.T) {
	client := &fakeHandshakeClient{}
	r := NewHandshakeReporter(time.Hour, testHandshakeNodeID, client, &fakeStatsSource{}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestHandshakeReporter_SourceErrorSkipsTheTick(t *testing.T) {
	clock := &steppingClock{next: testObservedAt, step: 10 * time.Second}
	client := &fakeHandshakeClient{}
	source := &fakeStatsSource{
		stats: []wireguard.MeshPeerStat{
			meshPeer(testPeerA, "198.51.100.7:51820", testObservedAt.Add(-5*time.Second)),
		},
		errs: []error{errors.New("netlink: device busy")},
	}
	logger, logs := newDebugLogger()
	r := NewHandshakeReporter(10*time.Millisecond, testHandshakeNodeID, client, source, logger)
	r.now = clock.now

	stop := startReporter(t, r)
	waitFor(t, 5*time.Second, func() bool { return client.calls() >= 1 })
	stop()

	// Every read but the failed first one produced exactly one report.
	_, reqs := client.recorded()
	if reads := source.readCount(); reads != len(reqs)+1 {
		t.Errorf("device reads = %d, reports = %d, want the failed read to send nothing", reads, len(reqs))
	}
	// The failed tick did not read the clock either, so the next tick's body
	// carries the first reading.
	if !reqs[0].ObservedAt.Equal(testObservedAt) {
		t.Errorf("first report ObservedAt = %v, want %v", reqs[0].ObservedAt, testObservedAt)
	}
	line := logLine(t, logs.String(), "agent: handshake report: read peer stats failed")
	for _, want := range []string{"level=WARN", `error="netlink: device busy"`} {
		if !strings.Contains(line, want) {
			t.Errorf("read failure log = %q, want it to contain %q", line, want)
		}
	}
}

// ---------------------------------------------------------------------------
// reportOnce
// ---------------------------------------------------------------------------

func TestHandshakeReporter_NotServedLoggedOnTransitions(t *testing.T) {
	const (
		notServedMsg = "agent: handshake report: control plane does not accept handshake reports, retrying every interval"
		recoveredMsg = "agent: handshake report: control plane accepts handshake reports"
	)
	tests := []struct {
		name     string
		err      *api.APIError
		wantAttr string
	}{
		{name: "404 without code", err: &api.APIError{StatusCode: 404}, wantAttr: `status=404 code=""`},
		{name: "404 with code", err: &api.APIError{StatusCode: 404, Code: "not_found"}, wantAttr: "status=404 code=not_found"},
		{
			name:     "501 handshakes_not_provisioned",
			err:      &api.APIError{StatusCode: 501, Code: "handshakes_not_provisioned"},
			wantAttr: "status=501 code=handshakes_not_provisioned",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeHandshakeClient{errs: []error{tt.err, tt.err, tt.err}}
			logger, logs := newDebugLogger()
			r := newFixedClockReporter(client, &fakeStatsSource{}, logger)
			ctx := context.Background()

			for range 3 {
				r.reportOnce(ctx)
			}
			got := logs.String()
			if n := client.calls(); n != 3 {
				t.Errorf("reports = %d after three refused ticks, want 3 (one per tick)", n)
			}
			line := logLine(t, got, notServedMsg)
			for _, want := range []string{"level=INFO", tt.wantAttr} {
				if !strings.Contains(line, want) {
					t.Errorf("not-served log = %q, want it to contain %q", line, want)
				}
			}
			if n := countLogLines(got, recoveredMsg); n != 0 {
				t.Errorf("recovery logged %d times before any report was accepted, want 0", n)
			}
			if strings.Contains(got, "send failed") {
				t.Errorf("a not-served answer was logged as a send failure:\n%s", got)
			}

			r.reportOnce(ctx)
			r.reportOnce(ctx)
			got = logs.String()
			if n := countLogLines(got, notServedMsg); n != 1 {
				t.Errorf("not-served logged %d times, want 1", n)
			}
			line = logLine(t, got, recoveredMsg)
			if !strings.Contains(line, "level=INFO") {
				t.Errorf("recovery log = %q, want level=INFO", line)
			}
			if r.notServed {
				t.Error("notServed still set after an accepted report")
			}
		})
	}
}

func TestHandshakeReporter_SendErrorsAreNotRetriedWithinTheTick(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantLevel string
		wantMsg   string
	}{
		{
			name:      "400 handshake_clock_skew",
			err:       &api.APIError{StatusCode: 400, Code: "handshake_clock_skew"},
			wantLevel: "level=ERROR",
			wantMsg:   "agent: handshake report: rejected for clock skew, synchronize the system clock via NTP",
		},
		{
			name:      "500",
			err:       &api.APIError{StatusCode: 500},
			wantLevel: "level=WARN",
			wantMsg:   "agent: handshake report: send failed",
		},
		{
			name:      "501 for another surface",
			err:       &api.APIError{StatusCode: 501, Code: "observability_ingest_not_provisioned"},
			wantLevel: "level=WARN",
			wantMsg:   "agent: handshake report: send failed",
		},
		{
			name:      "transport error",
			err:       errors.New("dial tcp: connection refused"),
			wantLevel: "level=WARN",
			wantMsg:   "agent: handshake report: send failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeHandshakeClient{errs: []error{tt.err}}
			source := &fakeStatsSource{}
			logger, logs := newDebugLogger()
			r := newFixedClockReporter(client, source, logger)

			r.reportOnce(context.Background())

			if n := client.calls(); n != 1 {
				t.Errorf("reports = %d within one tick, want 1 (no retry)", n)
			}
			if n := source.readCount(); n != 1 {
				t.Errorf("device reads = %d within one tick, want 1", n)
			}
			got := logs.String()
			line := logLine(t, got, tt.wantMsg)
			if !strings.Contains(line, tt.wantLevel) {
				t.Errorf("log = %q, want %s", line, tt.wantLevel)
			}
			if !strings.Contains(line, "error=") {
				t.Errorf("log = %q, want the error attached", line)
			}
			if strings.Contains(got, "does not accept handshake reports") {
				t.Errorf("a failure was logged as not served:\n%s", got)
			}
			if r.notServed {
				t.Error("notServed set by a failure that is not a not-served answer")
			}
		})
	}
}

func TestHandshakeReporter_CancelledSendIsNotLogged(t *testing.T) {
	client := &fakeHandshakeClient{errs: []error{context.Canceled}}
	logger, logs := newDebugLogger()
	r := newFixedClockReporter(client, &fakeStatsSource{}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.reportOnce(ctx)

	if got := logs.String(); got != "" {
		t.Errorf("logs = %q, want nothing for a send cut short by shutdown", got)
	}
}

func TestHandshakeReporter_AcceptedAndSkippedLoggedAtDebug(t *testing.T) {
	client := &fakeHandshakeClient{resp: &api.HandshakeReportResponse{
		AcceptedAt: testObservedAt.Add(time.Second),
		Recorded:   1,
		Ignored:    1,
	}}
	source := &fakeStatsSource{stats: []wireguard.MeshPeerStat{
		meshPeer(testPeerA, "198.51.100.7:51820", testObservedAt.Add(-5*time.Second)),
		meshPeer(testPeerB, "198.51.100.8:51820", testObservedAt.Add(-6*time.Second)),
		meshPeer("peer-1", "198.51.100.9:51820", testObservedAt.Add(-7*time.Second)),
	}}
	logger, logs := newDebugLogger()
	r := newFixedClockReporter(client, source, logger)

	r.reportOnce(context.Background())

	got := logs.String()
	skippedLine := logLine(t, got, "agent: handshake report: skipped peers")
	for _, want := range []string{"level=DEBUG", "count=1"} {
		if !strings.Contains(skippedLine, want) {
			t.Errorf("skipped log = %q, want it to contain %q", skippedLine, want)
		}
	}
	acceptedLine := logLine(t, got, "agent: handshake report: accepted")
	for _, want := range []string{"level=DEBUG", "sent=2", "recorded=1", "ignored=1", "accepted_at=2026-10-21T12:00:01"} {
		if !strings.Contains(acceptedLine, want) {
			t.Errorf("accepted log = %q, want it to contain %q", acceptedLine, want)
		}
	}
	if strings.Contains(got, "more peers than the contract allows") {
		t.Errorf("truncation logged for a report within the limit:\n%s", got)
	}
}

func TestHandshakeReporter_TruncationLoggedAtWarn(t *testing.T) {
	const total = 4100
	stats := make([]wireguard.MeshPeerStat, 0, total)
	for i := range total {
		stats = append(stats, meshPeer(
			fmt.Sprintf("0190a8b8-a0c0-7a0a-8a0a-%012x", i+1),
			"198.51.100.7:51820",
			testObservedAt.Add(-time.Duration(i)*time.Second),
		))
	}
	client := &fakeHandshakeClient{}
	logger, logs := newDebugLogger()
	r := newFixedClockReporter(client, &fakeStatsSource{stats: stats}, logger)

	r.reportOnce(context.Background())

	_, reqs := client.recorded()
	if len(reqs) != 1 {
		t.Fatalf("reports = %d, want 1", len(reqs))
	}
	if n := len(reqs[0].Peers); n != api.MaxHandshakeReportPeers {
		t.Errorf("sent %d peers, want %d", n, api.MaxHandshakeReportPeers)
	}
	got := logs.String()
	line := logLine(t, got, "agent: handshake report: more peers than the contract allows, reporting the most recent")
	for _, want := range []string{"level=WARN", "peers=4100", "max=4096"} {
		if !strings.Contains(line, want) {
			t.Errorf("truncation log = %q, want it to contain %q", line, want)
		}
	}
	if n := countLogLines(got, "agent: handshake report: skipped peers"); n != 0 {
		t.Errorf("skipped peers logged %d times with nothing skipped, want 0", n)
	}
}
