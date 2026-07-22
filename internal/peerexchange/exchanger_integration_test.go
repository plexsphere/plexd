package peerexchange

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nat"
)

// ---------------------------------------------------------------------------
// Integration test helpers
// ---------------------------------------------------------------------------

// sequenceSTUNClient returns different results on successive Bind calls.
// The results slice is consumed in order; the last entry repeats for further calls.
type sequenceSTUNClient struct {
	mu      sync.Mutex
	results []mockBindResult
	idx     int
	calls   int
}

func (s *sequenceSTUNClient) Bind(ctx context.Context, serverAddr string, localPort int) (nat.MappedAddress, int, error) {
	s.mu.Lock()
	s.calls++
	i := s.idx
	if i < len(s.results)-1 {
		s.idx++
	}
	r := s.results[i]
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nat.MappedAddress{}, 0, err
	}
	usedPort := localPort
	if usedPort == 0 {
		usedPort = 40000 // stands in for the OS's ephemeral choice
	}
	return r.Addr, usedPort, r.Err
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestIntegration_FullEndpointExchangeFlow wires together a real nat.Discoverer
// (with mock STUN) and an httptest server simulating the control plane.
// Verifies the flow: STUN discovery → endpoint reported to control plane →
// LastResult populated.
func TestIntegration_FullEndpointExchangeFlow(t *testing.T) {
	addr := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	stunClient := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}

	var reportReceived atomic.Bool
	now := time.Now().UTC()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.EndpointRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify the endpoint contract body was reported correctly.
		if req.Endpoint != "203.0.113.1:51820" {
			t.Errorf("reported endpoint = %q, want %q", req.Endpoint, "203.0.113.1:51820")
		}
		if req.NATType != "full_cone" {
			t.Errorf("reported NAT type = %q, want %q", req.NATType, "full_cone")
		}
		if req.ReportedAt.IsZero() {
			t.Error("reported_at is zero, want a fresh timestamp")
		}
		reportReceived.Store(true)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			AcceptedAt: now,
			StaleAfter: now.Add(5 * time.Minute),
		})
	}))
	defer ts.Close()

	logger := discardLogger()

	natCfg := nat.Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: time.Hour,
		Timeout:         5 * time.Second,
	}
	discoverer := nat.NewDiscoverer(stunClient, natCfg, 51820, logger)

	cpClient := newTestControlPlane(t, ts)

	cfg := Config{}
	cfg.Config = natCfg
	exchanger := NewExchanger(discoverer, cpClient, cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- exchanger.Run(ctx, "node-1") }()

	// Wait for the endpoint report to reach the control plane.
	waitFor(t, 2*time.Second, func() bool { return reportReceived.Load() })

	cancel()
	<-done

	if !reportReceived.Load() {
		t.Error("endpoint report was never received by the control plane")
	}

	// Verify LastResult is populated.
	info := exchanger.LastResult()
	if info == nil {
		t.Fatal("LastResult = nil after full exchange flow")
	}
	if info.Endpoint != "203.0.113.1:51820" {
		t.Errorf("LastResult.Endpoint = %q, want %q", info.Endpoint, "203.0.113.1:51820")
	}
}

// TestIntegration_EndpointChangeDuringRefreshLoop verifies that when the STUN
// endpoint changes between refresh cycles, the new endpoint is reported and
// peer updates from the response are applied.
func TestIntegration_EndpointChangeDuringRefreshLoop(t *testing.T) {
	addrA := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	addrB := nat.MappedAddress{IP: net.IPv4(198, 51, 100, 9), Port: 54321}

	stunClient := &sequenceSTUNClient{
		results: []mockBindResult{
			{Addr: addrA}, // initial discovery
			{Addr: addrB}, // first refresh — different endpoint
		},
	}

	var mu sync.Mutex
	var reportedEndpoints []string
	now := time.Now().UTC()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.EndpointRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		reportedEndpoints = append(reportedEndpoints, req.Endpoint)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			AcceptedAt: now,
			StaleAfter: now.Add(5 * time.Minute),
		})
	}))
	defer ts.Close()

	logger := discardLogger()

	natCfg := nat.Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478"},
		RefreshInterval: 50 * time.Millisecond,
		Timeout:         5 * time.Second,
	}
	discoverer := nat.NewDiscoverer(stunClient, natCfg, 51820, logger)
	cpClient := newTestControlPlane(t, ts)

	cfg := Config{}
	cfg.Config = natCfg
	exchanger := NewExchanger(discoverer, cpClient, cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- exchanger.Run(ctx, "node-1") }()

	// Wait for at least 2 reports (initial + refresh with the changed endpoint).
	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		n := len(reportedEndpoints)
		mu.Unlock()
		return n >= 2
	})

	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()

	if len(reportedEndpoints) < 2 {
		t.Fatalf("expected at least 2 reported endpoints, got %d", len(reportedEndpoints))
	}
	if reportedEndpoints[0] != "203.0.113.1:51820" {
		t.Errorf("first reported endpoint = %q, want %q", reportedEndpoints[0], "203.0.113.1:51820")
	}
	if reportedEndpoints[1] != "198.51.100.9:51820" {
		t.Errorf("second reported endpoint = %q, want %q", reportedEndpoints[1], "198.51.100.9:51820")
	}
}

// waitFor polls condition until it returns true or timeout expires.
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if condition() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out after %v waiting for condition", timeout)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}
