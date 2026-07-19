package nat

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func newTestDiscoverer(client *mockSTUNClient, servers []string, localPort int) *Discoverer {
	cfg := Config{
		Enabled:           true,
		STUNServers:       servers,
		RefreshInterval:   60 * time.Second,
		Timeout:           5 * time.Second,
		MinReportInterval: DefaultMinReportInterval,
	}
	return NewDiscoverer(client, cfg, localPort, discardLogger())
}

func TestDiscover_ClassifiesFullCone(t *testing.T) {
	addr := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NATType != NATFullCone {
		t.Errorf("expected NATFullCone, got %s", result.NATType)
	}
	if result.Endpoint != "203.0.113.1:12345" {
		t.Errorf("unexpected endpoint: %s", result.Endpoint)
	}
}

func TestDiscover_ClassifiesSymmetric(t *testing.T) {
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}},
			"stun2:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 54321}},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NATType != NATSymmetric {
		t.Errorf("expected NATSymmetric, got %s", result.NATType)
	}
}

func TestDiscover_ClassifiesNone(t *testing.T) {
	// The mapped port matching the local port is what marks "no NAT"; the IP
	// must still be routable to be publishable as an endpoint.
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(198, 51, 100, 7), Port: 51820}},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478"}, 51820)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NATType != NATNone {
		t.Errorf("expected NATNone, got %s", result.NATType)
	}
}

func TestDiscover_ClassifiesUnknownOnPartialFailure(t *testing.T) {
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}},
			"stun2:3478": {Err: errors.New("timeout")},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NATType != NATUnknown {
		t.Errorf("expected NATUnknown, got %s", result.NATType)
	}
	if result.Endpoint != "203.0.113.1:12345" {
		t.Errorf("unexpected endpoint: %s", result.Endpoint)
	}
}

func TestDiscover_FallbackToSecondServer(t *testing.T) {
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Err: errors.New("connection refused")},
			"stun2:3478": {Addr: MappedAddress{IP: net.IPv4(198, 51, 100, 5), Port: 9999}},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Endpoint != "198.51.100.5:9999" {
		t.Errorf("unexpected endpoint: %s", result.Endpoint)
	}
}

// A STUN response is unauthenticated, so a hostile server or an on-path
// attacker can name any address. Publishing one would point every peer's
// WireGuard handshake at it, so a non-routable address must be treated like
// a failed binding rather than becoming the node's endpoint.
func TestDiscover_RejectsNonRoutableMappedAddress(t *testing.T) {
	poisoned := []struct {
		name string
		addr MappedAddress
	}{
		{"loopback", MappedAddress{IP: net.IPv4(127, 0, 0, 1), Port: 12345}},
		{"unspecified", MappedAddress{IP: net.IPv4zero, Port: 12345}},
		{"link_local", MappedAddress{IP: net.IPv4(169, 254, 1, 1), Port: 12345}},
		{"zero_port", MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 0}},
	}

	for _, tt := range poisoned {
		t.Run(tt.name+"_falls_back_to_next_server", func(t *testing.T) {
			client := &mockSTUNClient{
				results: map[string]mockBindResult{
					"hostile:3478": {Addr: tt.addr},
					"stun2:3478":   {Addr: MappedAddress{IP: net.IPv4(198, 51, 100, 5), Port: 9999}},
				},
			}
			d := newTestDiscoverer(client, []string{"hostile:3478", "stun2:3478"}, 51820)

			result, err := d.Discover(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Endpoint != "198.51.100.5:9999" {
				t.Errorf("endpoint = %q, want the routable address from the second server", result.Endpoint)
			}
		})

		t.Run(tt.name+"_alone_fails_discovery", func(t *testing.T) {
			client := &mockSTUNClient{
				results: map[string]mockBindResult{
					"hostile:3478": {Addr: tt.addr},
				},
			}
			d := newTestDiscoverer(client, []string{"hostile:3478"}, 51820)

			if _, err := d.Discover(context.Background()); err == nil {
				t.Fatal("expected discovery to fail, got nil error")
			}
			if d.LastResult() != nil {
				t.Errorf("LastResult = %+v, want nil; a rejected address must not reach the heartbeat", d.LastResult())
			}
		})
	}
}

func TestDiscover_AllServersFail(t *testing.T) {
	client := &mockSTUNClient{
		defaultErr: errors.New("all failed"),
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	_, err := d.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	expected := "nat: discover: all STUN servers failed"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

func TestDiscover_UsesConfiguredListenPort(t *testing.T) {
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478"}, 44444)

	_, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := client.allCalls()
	if len(calls) == 0 {
		t.Fatal("expected at least one Bind call")
	}
	for _, c := range calls {
		if c.LocalPort != 44444 {
			t.Errorf("expected localPort 44444, got %d", c.LocalPort)
		}
	}
}

func TestDiscover_ContextCancelledDuringSTUN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478"}, 51820)

	_, err := d.Discover(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestLastResult_BeforeDiscovery(t *testing.T) {
	client := &mockSTUNClient{}
	d := newTestDiscoverer(client, []string{"stun1:3478"}, 51820)

	if d.LastResult() != nil {
		t.Error("expected nil LastResult before any Discover call")
	}
}

func TestLastResult_AfterDiscovery(t *testing.T) {
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}},
			"stun2:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	_, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info := d.LastResult()
	if info == nil {
		t.Fatal("expected non-nil LastResult after Discover")
	}
	if info.PublicEndpoint != "203.0.113.1:12345" {
		t.Errorf("unexpected PublicEndpoint: %s", info.PublicEndpoint)
	}
	if info.Type != string(NATFullCone) {
		t.Errorf("unexpected Type: %s", info.Type)
	}
}

func TestLastResult_ConcurrentAccess(t *testing.T) {
	addr := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = d.Discover(context.Background())
		}()
		go func() {
			defer wg.Done()
			_ = d.LastResult()
		}()
	}
	wg.Wait()
}

// sequenceMockSTUN returns different results on successive Bind calls to a given server.
// results is consumed in order; the last entry repeats for any further calls.
type sequenceMockSTUN struct {
	mu      sync.Mutex
	results []mockBindResult
	idx     int
	calls   []mockBindCall
}

func (s *sequenceMockSTUN) Bind(ctx context.Context, serverAddr string, localPort int) (MappedAddress, error) {
	s.mu.Lock()
	s.calls = append(s.calls, mockBindCall{ServerAddr: serverAddr, LocalPort: localPort})
	i := s.idx
	if i < len(s.results)-1 {
		s.idx++
	}
	r := s.results[i]
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return MappedAddress{}, err
	}
	return r.Addr, r.Err
}

func (s *sequenceMockSTUN) totalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func TestRun_InitialDiscoveryAndReport(t *testing.T) {
	addr := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}
	reporter := &mockReporter{response: &api.EndpointResponse{}}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: time.Hour, // large interval so we only get initial discovery
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, "node-1") }()

	// Wait for the reporter to be called.
	deadline := time.After(2 * time.Second)
	for {
		reporter.mu.Lock()
		n := len(reporter.calls)
		reporter.mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for report call")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.calls) < 1 {
		t.Fatal("expected at least 1 report call")
	}
	call := reporter.calls[0]
	if call.Report.Endpoint != "203.0.113.1:12345" {
		t.Errorf("expected endpoint 203.0.113.1:12345, got %s", call.Report.Endpoint)
	}
	if call.Report.NATType != string(NATFullCone) {
		t.Errorf("expected nat type full_cone, got %s", call.Report.NATType)
	}
}

func TestRun_RefreshesAtInterval(t *testing.T) {
	addr := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	client := &sequenceMockSTUN{
		results: []mockBindResult{
			{Addr: addr},
		},
	}

	reporter := &mockReporter{response: &api.EndpointResponse{}}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_ = d.Run(ctx, reporter, "node-1")

	// Initial discover + at least 1 refresh means >= 2 bind calls.
	calls := client.totalCalls()
	if calls < 2 {
		t.Errorf("expected at least 2 Bind calls (initial + refresh), got %d", calls)
	}
}

func TestRun_LogsEndpointChange(t *testing.T) {
	addrA := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	addrB := MappedAddress{IP: net.IPv4(198, 51, 100, 2), Port: 54321}

	client := &sequenceMockSTUN{
		results: []mockBindResult{
			{Addr: addrA}, // initial discovery
			{Addr: addrB}, // first refresh — different endpoint
		},
	}

	reporter := &mockReporter{response: &api.EndpointResponse{}}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, "node-1") }()

	// Wait until reporter has been called at least twice (initial + refresh with new endpoint).
	deadline := time.After(2 * time.Second)
	for {
		reporter.mu.Lock()
		n := len(reporter.calls)
		reporter.mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for second report call")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	<-done

	reporter.mu.Lock()
	defer reporter.mu.Unlock()

	if reporter.calls[0].Report.Endpoint != "203.0.113.1:12345" {
		t.Errorf("first report: expected 203.0.113.1:12345, got %s", reporter.calls[0].Report.Endpoint)
	}
	if reporter.calls[1].Report.Endpoint != "198.51.100.2:54321" {
		t.Errorf("second report: expected 198.51.100.2:54321, got %s", reporter.calls[1].Report.Endpoint)
	}
}

func TestRun_ContinuesOnRefreshFailure(t *testing.T) {
	addrA := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	addrC := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}

	client := &sequenceMockSTUN{
		results: []mockBindResult{
			{Addr: addrA},                            // initial — success
			{Err: errors.New("stun server timeout")}, // first refresh — fail
			{Addr: addrC},                            // second refresh — success
		},
	}

	reporter := &mockReporter{response: &api.EndpointResponse{}}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, "node-1") }()

	// Wait for at least 2 report calls: initial + third discovery (second refresh succeeds).
	deadline := time.After(2 * time.Second)
	for {
		reporter.mu.Lock()
		n := len(reporter.calls)
		reporter.mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for reports after refresh failure")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	<-done

	reporter.mu.Lock()
	defer reporter.mu.Unlock()

	if len(reporter.calls) < 2 {
		t.Fatalf("expected at least 2 report calls, got %d", len(reporter.calls))
	}
	// The second report should correspond to addrC (the third discovery, since second failed).
	if reporter.calls[1].Report.Endpoint != "203.0.113.1:12345" {
		t.Errorf("expected endpoint 203.0.113.1:12345, got %s", reporter.calls[1].Report.Endpoint)
	}
}

func TestRun_StopsOnContextCancellation(t *testing.T) {
	addr := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}
	reporter := &mockReporter{response: &api.EndpointResponse{}}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, "node-1") }()

	// Let it run briefly, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func TestRun_ReturnsErrorOnInitialDiscoveryFailure(t *testing.T) {
	client := &mockSTUNClient{
		defaultErr: errors.New("all servers unreachable"),
	}
	reporter := &mockReporter{response: &api.EndpointResponse{}}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	err := d.Run(context.Background(), reporter, "node-1")
	if err == nil {
		t.Fatal("expected error from initial discovery failure, got nil")
	}

	// Verify reporter was never called.
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.calls) != 0 {
		t.Errorf("expected 0 report calls, got %d", len(reporter.calls))
	}
}

// A control plane that keeps rejecting the endpoint leaves the node
// unreachable for peers behind symmetric NAT while every other health signal
// stays green. The condition must not stay a quiet per-cycle Warn forever.
func TestReportEndpoint_EscalatesConsecutiveRejections(t *testing.T) {
	var buf bytes.Buffer
	d := &Discoverer{
		cfg:    Config{RefreshInterval: time.Minute, MinReportInterval: 10 * time.Second},
		logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	reporter := &mockReporter{}
	result := &DiscoveryResult{Endpoint: "203.0.113.1:12345", NATType: NATFullCone}

	for i := 1; i <= endpointRejectionEscalation; i++ {
		reporter.errs = append(reporter.errs, &api.APIError{StatusCode: 404, Code: "endpoint_peer_not_found"})
	}

	for i := 1; i < endpointRejectionEscalation; i++ {
		buf.Reset()
		d.reportEndpoint(context.Background(), reporter, "node-1", result)
		if got := buf.String(); !strings.Contains(got, "level=WARN") {
			t.Errorf("rejection %d logged %q, want WARN", i, got)
		}
	}

	buf.Reset()
	d.reportEndpoint(context.Background(), reporter, "node-1", result)
	logged := buf.String()
	if !strings.Contains(logged, "level=ERROR") {
		t.Errorf("rejection %d logged %q, want ERROR escalation", endpointRejectionEscalation, logged)
	}
	if !strings.Contains(logged, "consecutive_rejections=3") {
		t.Errorf("log %q, want it to carry consecutive_rejections=3", logged)
	}

	// A successful report clears the streak.
	reporter.response = &api.EndpointResponse{}
	d.reportEndpoint(context.Background(), reporter, "node-1", result)
	if d.rejections != 0 {
		t.Errorf("rejections = %d after success, want 0", d.rejections)
	}
}

func TestNextDelay(t *testing.T) {
	tests := []struct {
		name              string
		minReportInterval time.Duration
		offset            time.Duration // staleAfter relative to now
		zero              bool          // when true, pass the zero time
		want              time.Duration
		wantWarn          bool
	}{
		{name: "deadline far ahead capped at refresh interval", minReportInterval: 10 * time.Second, offset: 5 * time.Minute, want: 60 * time.Second},
		{name: "deadline near margin floored at minimum", minReportInterval: 10 * time.Second, offset: 40 * time.Second, want: 10 * time.Second, wantWarn: true},
		{name: "zero deadline falls back to refresh interval", minReportInterval: 10 * time.Second, zero: true, want: 60 * time.Second},
		{name: "deadline inside margin floored at minimum", minReportInterval: 10 * time.Second, offset: 20 * time.Second, want: 10 * time.Second, wantWarn: true},
		// An operator who raises the floor caps how far a short server-side
		// TTL can accelerate the STUN and report loop.
		{name: "configured floor bounds a short deadline", minReportInterval: 45 * time.Second, offset: 40 * time.Second, want: 45 * time.Second, wantWarn: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			d := &Discoverer{
				cfg:    Config{RefreshInterval: 60 * time.Second, MinReportInterval: tt.minReportInterval},
				logger: slog.New(slog.NewTextHandler(&buf, nil)),
			}

			var staleAfter time.Time
			if !tt.zero {
				staleAfter = time.Now().Add(tt.offset)
			}
			got := d.nextDelay(staleAfter)
			// Allow for tiny elapsed time between computing staleAfter and the
			// call; the result never exceeds want.
			if got > tt.want || got < tt.want-time.Second {
				t.Errorf("nextDelay = %v, want within [%v, %v]", got, tt.want-time.Second, tt.want)
			}
			// A server-shortened cadence must be visible to the operator.
			if gotWarn := strings.Contains(buf.String(), "level=WARN"); gotWarn != tt.wantWarn {
				t.Errorf("warn logged = %v, want %v (log: %s)", gotWarn, tt.wantWarn, buf.String())
			}
		})
	}
}
