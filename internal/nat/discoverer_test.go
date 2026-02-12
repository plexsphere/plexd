package nat

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func newTestDiscoverer(client *mockSTUNClient, servers []string, localPort int) *Discoverer {
	cfg := Config{
		Enabled:         true,
		STUNServers:     servers,
		RefreshInterval: 60 * time.Second,
		Timeout:         5 * time.Second,
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
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(127, 0, 0, 1), Port: 51820}},
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
	updater := &mockUpdater{}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: time.Hour, // large interval so we only get initial discovery
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, updater, "node-1") }()

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
	if call.Report.PublicEndpoint != "203.0.113.1:12345" {
		t.Errorf("expected endpoint 203.0.113.1:12345, got %s", call.Report.PublicEndpoint)
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
	updater := &mockUpdater{}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_ = d.Run(ctx, reporter, updater, "node-1")

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
	updater := &mockUpdater{}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, updater, "node-1") }()

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

	if reporter.calls[0].Report.PublicEndpoint != "203.0.113.1:12345" {
		t.Errorf("first report: expected 203.0.113.1:12345, got %s", reporter.calls[0].Report.PublicEndpoint)
	}
	if reporter.calls[1].Report.PublicEndpoint != "198.51.100.2:54321" {
		t.Errorf("second report: expected 198.51.100.2:54321, got %s", reporter.calls[1].Report.PublicEndpoint)
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
	updater := &mockUpdater{}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, updater, "node-1") }()

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
	if reporter.calls[1].Report.PublicEndpoint != "203.0.113.1:12345" {
		t.Errorf("expected endpoint 203.0.113.1:12345, got %s", reporter.calls[1].Report.PublicEndpoint)
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
	updater := &mockUpdater{}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, reporter, updater, "node-1") }()

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
	updater := &mockUpdater{}

	cfg := Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	d := NewDiscoverer(client, cfg, 51820, discardLogger())

	err := d.Run(context.Background(), reporter, updater, "node-1")
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
