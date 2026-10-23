package nat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// newLoggingDiscoverer is newTestDiscoverer, advertising port 51820, with its
// log written to logs.
func newLoggingDiscoverer(client *mockSTUNClient, servers []string, logs *syncBuffer) *Discoverer {
	d := newTestDiscoverer(client, servers, 51820)
	d.logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return d
}

// translatesPortsMsg is the Warn Discover logs on the way into PortTranslated.
const translatesPortsMsg = "NAT translates ports, the published endpoint assumes the WireGuard listen port is forwarded"

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
	if result.Endpoint != "203.0.113.1:51820" {
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
	if result.PortMapping != PortTranslated {
		t.Errorf("PortMapping = %q, want %q", result.PortMapping, PortTranslated)
	}
}

func TestDiscover_ClassifiesNone(t *testing.T) {
	// The mapped port matching the STUN source port is what marks "no NAT";
	// the IP must still be routable to be publishable as an endpoint.
	// stun2 maps to another port and must never be asked: one binding that
	// kept the port settles both the classification and the port mapping.
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(198, 51, 100, 7), Port: mockEphemeralPort}},
			"stun2:3478": {Addr: MappedAddress{IP: net.IPv4(198, 51, 100, 7), Port: 10482}},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 51820)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NATType != NATNone {
		t.Errorf("expected NATNone, got %s", result.NATType)
	}
	if result.PortMapping != PortPreserved {
		t.Errorf("PortMapping = %q, want %q", result.PortMapping, PortPreserved)
	}
	if result.Endpoint != "198.51.100.7:51820" {
		t.Errorf("unexpected endpoint: %s", result.Endpoint)
	}
	calls := client.allCalls()
	if len(calls) != 1 || calls[0].ServerAddr != "stun1:3478" {
		t.Errorf("Bind calls = %+v, want exactly one, to stun1:3478", calls)
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
	if result.PortMapping != PortTranslated {
		t.Errorf("PortMapping = %q, want %q", result.PortMapping, PortTranslated)
	}
	if result.Endpoint != "203.0.113.1:51820" {
		t.Errorf("unexpected endpoint: %s", result.Endpoint)
	}
}

// The lab case: the router maps the STUN socket to a port of its own and
// both servers see the same mapping. The mapping is endpoint-independent, so
// nat_type stays full_cone, and the published endpoint keeps the listen port,
// which only a port forward makes reachable, so the port mapping says the
// endpoint is an assumption. A node behind such a forward reports the same.
func TestDiscover_PortTranslatingFullConeKeepsListenPort(t *testing.T) {
	addr := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 10482}
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
		t.Errorf("NATType = %s, want %s", result.NATType, NATFullCone)
	}
	if result.PortMapping != PortTranslated {
		t.Errorf("PortMapping = %q, want %q", result.PortMapping, PortTranslated)
	}
	if result.Endpoint != "203.0.113.1:51820" {
		t.Errorf("Endpoint = %s, want 203.0.113.1:51820", result.Endpoint)
	}
}

// With no STUN server configured there is no binding, so there is nothing
// to classify, store or warn about.
func TestDiscover_NoSTUNServers(t *testing.T) {
	logs := &syncBuffer{}
	d := newLoggingDiscoverer(&mockSTUNClient{}, []string{}, logs)

	_, err := d.Discover(context.Background())
	if err == nil || err.Error() != "nat: discover: all STUN servers failed" {
		t.Fatalf("err = %v, want %q", err, "nat: discover: all STUN servers failed")
	}
	if got := d.LastResult(); got != nil {
		t.Errorf("LastResult() = %+v, want nil", got)
	}
	if lines := logLines(logs, translatesPortsMsg); len(lines) != 0 {
		t.Errorf("logged %d %q lines, want none: %v", len(lines), translatesPortsMsg, lines)
	}
}

// A cycle in which every binding fails keeps the earlier result. It is no
// way out of PortTranslated either, so the translated cycle after it does
// not warn again.
func TestDiscover_FailedCycleKeepsLastResult(t *testing.T) {
	translated := map[string]mockBindResult{
		"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 10482}},
		"stun2:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 10482}},
	}
	client := &mockSTUNClient{results: translated}
	logs := &syncBuffer{}
	d := newLoggingDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, logs)

	if _, err := d.Discover(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}

	client.mu.Lock()
	client.results = map[string]mockBindResult{
		"stun1:3478": {Err: context.DeadlineExceeded},
		"stun2:3478": {Err: context.DeadlineExceeded},
	}
	client.mu.Unlock()

	_, err := d.Discover(context.Background())
	if err == nil || err.Error() != "nat: discover: all STUN servers failed" {
		t.Fatalf("failed cycle: err = %v, want %q", err, "nat: discover: all STUN servers failed")
	}
	last := d.LastResult()
	if last == nil || last.PortMapping != PortTranslated || last.Endpoint != "203.0.113.1:51820" {
		t.Fatalf("LastResult() = %+v, want the first cycle's 203.0.113.1:51820 with %q", last, PortTranslated)
	}
	if lines := logLines(logs, translatesPortsMsg); len(lines) != 1 {
		t.Errorf("after the failed cycle: %d %q lines, want 1: %v", len(lines), translatesPortsMsg, lines)
	}

	client.mu.Lock()
	client.results = translated
	client.mu.Unlock()

	if _, err := d.Discover(context.Background()); err != nil {
		t.Fatalf("third cycle: %v", err)
	}
	if lines := logLines(logs, translatesPortsMsg); len(lines) != 1 {
		t.Errorf("after the third cycle: %d %q lines, want 1: %v", len(lines), translatesPortsMsg, lines)
	}
}

// Every discovery names its port mapping on the endpoint discovered line,
// so the log shows whether the published endpoint was observed or assumed.
// A first discovery with a translated port warns whatever the mapping's
// classification, and one that kept the port never warns.
func TestDiscover_LogsPortMapping(t *testing.T) {
	translated := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 10482}
	kept := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: mockEphemeralPort}
	tests := []struct {
		name        string
		results     map[string]mockBindResult
		wantNATType NATType
		want        PortMapping
		wantWarns   int
	}{
		{
			name:        "full cone",
			results:     map[string]mockBindResult{"stun1:3478": {Addr: translated}, "stun2:3478": {Addr: translated}},
			wantNATType: NATFullCone, want: PortTranslated, wantWarns: 1,
		},
		{
			// The second binding keeps the source port, but only the first
			// binding settles the port mapping.
			name:        "symmetric, second binding keeps the port",
			results:     map[string]mockBindResult{"stun1:3478": {Addr: translated}, "stun2:3478": {Addr: kept}},
			wantNATType: NATSymmetric, want: PortTranslated, wantWarns: 1,
		},
		{
			name:        "unknown",
			results:     map[string]mockBindResult{"stun1:3478": {Addr: translated}, "stun2:3478": {Err: errors.New("timeout")}},
			wantNATType: NATUnknown, want: PortTranslated, wantWarns: 1,
		},
		{
			name:        "port preserved",
			results:     map[string]mockBindResult{"stun1:3478": {Addr: kept}, "stun2:3478": {Addr: translated}},
			wantNATType: NATNone, want: PortPreserved, wantWarns: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &syncBuffer{}
			d := newLoggingDiscoverer(&mockSTUNClient{results: tt.results}, []string{"stun1:3478", "stun2:3478"}, logs)

			result, err := d.Discover(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.NATType != tt.wantNATType || result.PortMapping != tt.want {
				t.Fatalf("result = %s/%q, want %s/%q", result.NATType, result.PortMapping, tt.wantNATType, tt.want)
			}

			lines := logLines(logs, "endpoint discovered")
			if len(lines) != 1 {
				t.Fatalf("endpoint discovered lines = %d, want 1; logs:\n%s", len(lines), logs.String())
			}
			if want := "port_mapping=" + string(tt.want); !strings.Contains(lines[0], want) {
				t.Errorf("endpoint discovered line %q, want it to contain %q", lines[0], want)
			}

			warns := logLines(logs, translatesPortsMsg)
			if len(warns) != tt.wantWarns {
				t.Fatalf("%q lines = %d, want %d; logs:\n%s", translatesPortsMsg, len(warns), tt.wantWarns, logs.String())
			}
			for _, w := range warns {
				if want := "nat_type=" + string(tt.wantNATType); !strings.Contains(w, want) {
					t.Errorf("Warn line %q, want it to contain %q", w, want)
				}
			}
		})
	}
}

// The Warn names an assumption that a port forward makes true, so it fires
// on the way into translated, the first discovery included, and not on
// every refresh cycle a port-forwarded node runs.
func TestDiscover_WarnsOnTransitionIntoTranslated(t *testing.T) {
	translated := map[string]mockBindResult{
		"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 10482}},
		"stun2:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 10482}},
	}
	// The mock sends from mockEphemeralPort, so mapping back to it is a
	// preserved port.
	preserved := map[string]mockBindResult{
		"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: mockEphemeralPort}},
	}
	cycles := []struct {
		results   map[string]mockBindResult
		want      PortMapping
		wantWarns int // Warn lines logged so far
	}{
		{results: translated, want: PortTranslated, wantWarns: 1},
		{results: translated, want: PortTranslated, wantWarns: 1},
		{results: translated, want: PortTranslated, wantWarns: 1},
		{results: preserved, want: PortPreserved, wantWarns: 1},
		{results: translated, want: PortTranslated, wantWarns: 2},
	}

	client := &mockSTUNClient{}
	logs := &syncBuffer{}
	d := newLoggingDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, logs)

	for i, c := range cycles {
		client.mu.Lock()
		client.results = c.results
		client.mu.Unlock()

		result, err := d.Discover(context.Background())
		if err != nil {
			t.Fatalf("cycle %d: %v", i+1, err)
		}
		if result.PortMapping != c.want {
			t.Fatalf("cycle %d: PortMapping = %q, want %q", i+1, result.PortMapping, c.want)
		}
		if lines := logLines(logs, translatesPortsMsg); len(lines) != c.wantWarns {
			t.Fatalf("after cycle %d: %d %q lines, want %d: %v", i+1, len(lines), translatesPortsMsg, c.wantWarns, lines)
		}
	}

	for _, line := range logLines(logs, translatesPortsMsg) {
		for _, want := range []string{"level=WARN", "component=nat", "endpoint=203.0.113.1:51820", "nat_type=full_cone", "stun_port=40000", "mapped_port=10482"} {
			if !strings.Contains(line, want) {
				t.Errorf("Warn line %q, want it to contain %q", line, want)
			}
		}
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
	if result.Endpoint != "198.51.100.5:51820" {
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
			if result.Endpoint != "198.51.100.5:51820" {
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

// The kernel WireGuard socket owns the listen port, so STUN must never bind
// it: the first binding lets the OS pick an ephemeral port, later bindings
// in the same cycle reuse that port, and the listen port appears only in the
// published endpoint.
func TestDiscover_EphemeralSourcePortAdvertisesListenPort(t *testing.T) {
	addr := MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	client := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}
	d := newTestDiscoverer(client, []string{"stun1:3478", "stun2:3478"}, 44444)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := client.allCalls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 Bind calls, got %d", len(calls))
	}
	if calls[0].LocalPort != 0 {
		t.Errorf("first Bind localPort = %d, want 0 (ephemeral, never the WireGuard listen port)", calls[0].LocalPort)
	}
	if calls[1].LocalPort != mockEphemeralPort {
		t.Errorf("second Bind localPort = %d, want %d (reuse the cycle's ephemeral port)", calls[1].LocalPort, mockEphemeralPort)
	}
	if result.Endpoint != "203.0.113.1:44444" {
		t.Errorf("endpoint = %q, want the mapped IP with the advertised listen port", result.Endpoint)
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
	if info.Endpoint != "203.0.113.1:51820" {
		t.Errorf("unexpected Endpoint: %s", info.Endpoint)
	}
	if info.NATType != NATFullCone {
		t.Errorf("unexpected NATType: %s", info.NATType)
	}
	if info.PortMapping != PortTranslated {
		t.Errorf("PortMapping = %q, want %q", info.PortMapping, PortTranslated)
	}

	// The next cycle's port mapping replaces it.
	client.mu.Lock()
	client.results = map[string]mockBindResult{
		"stun1:3478": {Addr: MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: mockEphemeralPort}},
	}
	client.mu.Unlock()
	if _, err := d.Discover(context.Background()); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if got := d.LastResult().PortMapping; got != PortPreserved {
		t.Errorf("PortMapping after the second cycle = %q, want %q", got, PortPreserved)
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

func (s *sequenceMockSTUN) Bind(ctx context.Context, serverAddr string, localPort int) (MappedAddress, int, error) {
	s.mu.Lock()
	s.calls = append(s.calls, mockBindCall{ServerAddr: serverAddr, LocalPort: localPort})
	i := s.idx
	if i < len(s.results)-1 {
		s.idx++
	}
	r := s.results[i]
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return MappedAddress{}, 0, err
	}
	usedPort := localPort
	if usedPort == 0 {
		usedPort = mockEphemeralPort
	}
	return r.Addr, usedPort, r.Err
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
	if call.Report.Endpoint != "203.0.113.1:51820" {
		t.Errorf("expected endpoint 203.0.113.1:51820, got %s", call.Report.Endpoint)
	}
	if call.Report.NATType != string(NATFullCone) {
		t.Errorf("expected nat type full_cone, got %s", call.Report.NATType)
	}
	// The mock maps the probe to port 12345 while it left from 40000.
	if call.Report.PortMapping != string(PortTranslated) {
		t.Errorf("port mapping = %q, want %q", call.Report.PortMapping, PortTranslated)
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

	if reporter.calls[0].Report.Endpoint != "203.0.113.1:51820" {
		t.Errorf("first report: expected 203.0.113.1:51820, got %s", reporter.calls[0].Report.Endpoint)
	}
	if reporter.calls[1].Report.Endpoint != "198.51.100.2:51820" {
		t.Errorf("second report: expected 198.51.100.2:51820, got %s", reporter.calls[1].Report.Endpoint)
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
	if reporter.calls[1].Report.Endpoint != "203.0.113.1:51820" {
		t.Errorf("expected endpoint 203.0.113.1:51820, got %s", reporter.calls[1].Report.Endpoint)
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

// While the heartbeat has parked the agent, every report fails locally with
// api.ErrCredentialRefused. The heartbeat names the cause once, so the
// discoverer logs the failure at Debug instead of a Warn per cycle.
func TestReportEndpoint_RefusedCredentialLoggedAtDebug(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantLevel string
	}{
		{name: "refused credential", err: fmt.Errorf("x: %w", api.ErrCredentialRefused), wantLevel: "level=DEBUG"},
		{name: "other error", err: errors.New("boom"), wantLevel: "level=WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			d := &Discoverer{
				cfg:    Config{RefreshInterval: time.Minute, MinReportInterval: 10 * time.Second},
				logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}
			reporter := &mockReporter{errs: []error{tt.err}}
			result := &DiscoveryResult{Endpoint: "203.0.113.1:12345", NATType: NATFullCone}

			d.reportEndpoint(context.Background(), reporter, "node-1", result)

			logged := buf.String()
			if n := strings.Count(logged, `msg="endpoint report failed"`); n != 1 {
				t.Fatalf("endpoint report failed lines = %d, want 1; logs:\n%s", n, logged)
			}
			for _, want := range []string{tt.wantLevel, "component=nat", "error="} {
				if !strings.Contains(logged, want) {
					t.Errorf("log %q, want it to contain %q", logged, want)
				}
			}
			if tt.wantLevel == "level=DEBUG" && (strings.Contains(logged, "level=WARN") || strings.Contains(logged, "level=ERROR")) {
				t.Errorf("log %q, want nothing at Warn or above for a refused credential", logged)
			}
		})
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
