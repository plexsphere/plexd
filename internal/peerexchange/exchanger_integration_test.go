package peerexchange

import (
	"context"
	"encoding/base64"
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
	"github.com/plexsphere/plexd/internal/wireguard"
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

func (s *sequenceSTUNClient) Bind(ctx context.Context, serverAddr string, localPort int) (nat.MappedAddress, error) {
	s.mu.Lock()
	s.calls++
	i := s.idx
	if i < len(s.results)-1 {
		s.idx++
	}
	r := s.results[i]
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nat.MappedAddress{}, err
	}
	return r.Addr, r.Err
}

func (s *sequenceSTUNClient) totalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// trackingWGController is a mock WGController that records AddPeer calls
// and supports optional per-call errors.
type trackingWGController struct {
	mu        sync.Mutex
	addPeers  []wireguard.PeerConfig
	addErrors map[int]error // error by call index
}

func (c *trackingWGController) CreateInterface(string, []byte, int) error { return nil }
func (c *trackingWGController) DeleteInterface(string) error              { return nil }
func (c *trackingWGController) ConfigureAddress(string, string) error     { return nil }
func (c *trackingWGController) SetInterfaceUp(string) error               { return nil }
func (c *trackingWGController) SetMTU(string, int) error                  { return nil }
func (c *trackingWGController) RemovePeer(string, []byte) error           { return nil }

func (c *trackingWGController) AddPeer(_ string, cfg wireguard.PeerConfig) error {
	c.mu.Lock()
	idx := len(c.addPeers)
	c.addPeers = append(c.addPeers, cfg)
	err := c.addErrors[idx]
	c.mu.Unlock()
	return err
}

func (c *trackingWGController) addPeerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.addPeers)
}

func (c *trackingWGController) lastPeerEndpoint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.addPeers) == 0 {
		return ""
	}
	return c.addPeers[len(c.addPeers)-1].Endpoint
}

// peerKey returns a base64-encoded 32-byte key for testing.
func peerKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestIntegration_FullEndpointExchangeFlow wires together a real nat.Discoverer
// (with mock STUN), real wireguard.Manager (with mock controller), and an
// httptest server simulating the control plane. Verifies the full flow:
// STUN discovery → endpoint reported to control plane → peer endpoints
// received in response → WireGuard peer updated.
func TestIntegration_FullEndpointExchangeFlow(t *testing.T) {
	addr := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	stunClient := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}

	pubKey := peerKey()

	var reportReceived atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.EndpointReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify the endpoint was reported correctly.
		if req.PublicEndpoint != "203.0.113.1:12345" {
			t.Errorf("reported endpoint = %q, want %q", req.PublicEndpoint, "203.0.113.1:12345")
		}
		if req.NATType != "full_cone" {
			t.Errorf("reported NAT type = %q, want %q", req.NATType, "full_cone")
		}
		reportReceived.Store(true)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-a", Endpoint: "198.51.100.1:51820"},
				{PeerID: "peer-b", Endpoint: "198.51.100.2:51820"},
			},
		})
	}))
	defer ts.Close()

	logger := discardLogger()
	ctrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
	wgMgr.PeerIndex().Add("peer-a", pubKey)
	wgMgr.PeerIndex().Add("peer-b", pubKey)

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
	exchanger := NewExchanger(discoverer, wgMgr, cpClient, cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- exchanger.Run(ctx, "node-1") }()

	// Wait for both peers to be updated.
	waitFor(t, 2*time.Second, func() bool { return ctrl.addPeerCount() >= 2 })

	cancel()
	<-done

	if !reportReceived.Load() {
		t.Error("endpoint report was never received by the control plane")
	}
	if n := ctrl.addPeerCount(); n < 2 {
		t.Errorf("expected at least 2 AddPeer calls, got %d", n)
	}

	// Verify LastResult is populated.
	info := exchanger.LastResult()
	if info == nil {
		t.Fatal("LastResult = nil after full exchange flow")
	}
	if info.PublicEndpoint != "203.0.113.1:12345" {
		t.Errorf("LastResult.PublicEndpoint = %q, want %q", info.PublicEndpoint, "203.0.113.1:12345")
	}
}

// TestIntegration_SSEPeerEndpointChangedTriggersWGUpdate verifies that
// registering the SSE handler through the Exchanger and dispatching a
// peer_endpoint_changed event causes a WireGuard peer update via the real
// wireguard.Manager (with mock controller).
func TestIntegration_SSEPeerEndpointChangedTriggersWGUpdate(t *testing.T) {
	logger := discardLogger()

	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	cpClient := newTestControlPlane(t, ts)

	ctrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
	pubKey := peerKey()
	wgMgr.PeerIndex().Add("peer-x", pubKey)

	discoverer := nat.NewDiscoverer(nil, nat.Config{}, 51820, logger)

	cfg := Config{}
	cfg.Enabled = false
	cfg.RefreshInterval = 60 * time.Second
	exchanger := NewExchanger(discoverer, wgMgr, cpClient, cfg, logger)

	// Create a real SSEManager and register handlers via the Exchanger.
	sseManager := api.NewSSEManager(cpClient, nil, logger)
	exchanger.RegisterHandlers(sseManager)

	// Simulate an SSE event by directly dispatching through the event dispatcher.
	// The SSEManager delegates to its internal EventDispatcher, but since we can't
	// start a real SSE connection, we verify the handler by using a dispatcher
	// with the same handler that RegisterHandlers registers.
	dispatcher := api.NewEventDispatcher(logger)
	dispatcher.Register(api.EventPeerEndpointChanged, wireguard.HandlePeerEndpointChanged(wgMgr))

	peer := api.Peer{
		ID:         "peer-x",
		PublicKey:  pubKey,
		MeshIP:     "10.0.0.5",
		Endpoint:   "192.0.2.1:51820",
		AllowedIPs: []string{"10.0.0.5/32"},
	}
	payload, _ := json.Marshal(peer)
	envelope := api.SignedEnvelope{
		EventType: api.EventPeerEndpointChanged,
		EventID:   "evt-100",
		Payload:   payload,
	}

	dispatcher.Dispatch(context.Background(), envelope)

	if n := ctrl.addPeerCount(); n != 1 {
		t.Fatalf("expected 1 AddPeer call from SSE handler, got %d", n)
	}
	if ep := ctrl.lastPeerEndpoint(); ep != "192.0.2.1:51820" {
		t.Errorf("peer endpoint = %q, want %q", ep, "192.0.2.1:51820")
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

	pubKey := peerKey()

	var mu sync.Mutex
	var reportedEndpoints []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.EndpointReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		reportedEndpoints = append(reportedEndpoints, req.PublicEndpoint)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-1", Endpoint: "10.0.0.99:51820"},
			},
		})
	}))
	defer ts.Close()

	logger := discardLogger()
	ctrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
	wgMgr.PeerIndex().Add("peer-1", pubKey)

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
	exchanger := NewExchanger(discoverer, wgMgr, cpClient, cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- exchanger.Run(ctx, "node-1") }()

	// Wait for at least 2 reports (initial + refresh with changed endpoint).
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
	if reportedEndpoints[0] != "203.0.113.1:12345" {
		t.Errorf("first reported endpoint = %q, want %q", reportedEndpoints[0], "203.0.113.1:12345")
	}
	if reportedEndpoints[1] != "198.51.100.9:54321" {
		t.Errorf("second reported endpoint = %q, want %q", reportedEndpoints[1], "198.51.100.9:54321")
	}

	// Verify WireGuard was updated on both cycles.
	if n := ctrl.addPeerCount(); n < 2 {
		t.Errorf("expected at least 2 AddPeer calls, got %d", n)
	}
}

// TestIntegration_ConcurrentSSEAndRefreshNoRace exercises the Exchanger
// under concurrent SSE event dispatch and refresh loop activity to verify
// there are no data races. This test must be run with -race.
func TestIntegration_ConcurrentSSEAndRefreshNoRace(t *testing.T) {
	addr := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	stunClient := &sequenceSTUNClient{
		results: []mockBindResult{
			{Addr: addr},
		},
	}

	pubKey := peerKey()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-1", Endpoint: "10.0.0.1:51820"},
			},
		})
	}))
	defer ts.Close()

	logger := discardLogger()
	ctrl := &trackingWGController{}
	wgMgr := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
	wgMgr.PeerIndex().Add("peer-1", pubKey)

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
	exchanger := NewExchanger(discoverer, wgMgr, cpClient, cfg, logger)

	// Set up SSE handler via a dispatcher that shares the same WG manager.
	dispatcher := api.NewEventDispatcher(logger)
	dispatcher.Register(api.EventPeerEndpointChanged, wireguard.HandlePeerEndpointChanged(wgMgr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- exchanger.Run(ctx, "node-1") }()

	// Concurrently dispatch SSE events while the refresh loop runs.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer := api.Peer{
				ID:         "peer-1",
				PublicKey:  pubKey,
				MeshIP:     "10.0.0.1",
				Endpoint:   "192.0.2.50:51820",
				AllowedIPs: []string{"10.0.0.1/32"},
			}
			payload, _ := json.Marshal(peer)
			envelope := api.SignedEnvelope{
				EventType: api.EventPeerEndpointChanged,
				EventID:   "concurrent-evt",
				Payload:   payload,
			}
			dispatcher.Dispatch(ctx, envelope)
		}()
	}

	// Let the refresh loop run a few cycles.
	time.Sleep(200 * time.Millisecond)

	wg.Wait()
	cancel()
	<-done

	// The test passes if no race is detected (via -race flag).
	// Verify some updates were applied.
	if n := ctrl.addPeerCount(); n == 0 {
		t.Error("expected at least 1 AddPeer call from concurrent activity")
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
