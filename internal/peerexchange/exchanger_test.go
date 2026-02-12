package peerexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nat"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

// mockSTUNClient is a test double for nat.STUNClient.
type mockSTUNClient struct {
	mu         sync.Mutex
	calls      []mockBindCall
	results    map[string]mockBindResult
	defaultErr error
}

type mockBindCall struct {
	ServerAddr string
	LocalPort  int
}

type mockBindResult struct {
	Addr nat.MappedAddress
	Err  error
}

func (m *mockSTUNClient) Bind(ctx context.Context, serverAddr string, localPort int) (nat.MappedAddress, error) {
	m.mu.Lock()
	m.calls = append(m.calls, mockBindCall{ServerAddr: serverAddr, LocalPort: localPort})
	results := m.results
	defaultErr := m.defaultErr
	m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nat.MappedAddress{}, err
	}

	if results != nil {
		if r, ok := results[serverAddr]; ok {
			return r.Addr, r.Err
		}
	}
	return nat.MappedAddress{}, defaultErr
}

// mockWGController is a test double for wireguard.WGController.
type mockWGController struct {
	mu    sync.Mutex
	peers []wireguard.PeerConfig
	calls []mockWGCall
}

type mockWGCall struct {
	Method string
	Args   []interface{}
}

func (m *mockWGController) CreateInterface(name string, privateKey []byte, listenPort int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockWGCall{Method: "CreateInterface", Args: []interface{}{name, privateKey, listenPort}})
	m.mu.Unlock()
	return nil
}

func (m *mockWGController) DeleteInterface(name string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockWGCall{Method: "DeleteInterface", Args: []interface{}{name}})
	m.mu.Unlock()
	return nil
}

func (m *mockWGController) ConfigureAddress(name string, address string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockWGCall{Method: "ConfigureAddress", Args: []interface{}{name, address}})
	m.mu.Unlock()
	return nil
}

func (m *mockWGController) SetInterfaceUp(name string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockWGCall{Method: "SetInterfaceUp", Args: []interface{}{name}})
	m.mu.Unlock()
	return nil
}

func (m *mockWGController) SetMTU(name string, mtu int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockWGCall{Method: "SetMTU", Args: []interface{}{name, mtu}})
	m.mu.Unlock()
	return nil
}

func (m *mockWGController) AddPeer(iface string, cfg wireguard.PeerConfig) error {
	m.mu.Lock()
	m.peers = append(m.peers, cfg)
	m.calls = append(m.calls, mockWGCall{Method: "AddPeer", Args: []interface{}{iface, cfg}})
	m.mu.Unlock()
	return nil
}

func (m *mockWGController) RemovePeer(iface string, publicKey []byte) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockWGCall{Method: "RemovePeer", Args: []interface{}{iface, publicKey}})
	m.mu.Unlock()
	return nil
}

func (m *mockWGController) addPeerCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.Method == "AddPeer" {
			n++
		}
	}
	return n
}

// newTestControlPlane creates a ControlPlane pointing at the given test server.
func newTestControlPlane(t *testing.T, ts *httptest.Server) *api.ControlPlane {
	t.Helper()
	cfg := api.Config{BaseURL: ts.URL}
	cp, err := api.NewControlPlane(cfg, "test", discardLogger())
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	return cp
}

// newTestExchanger constructs an Exchanger with the provided mock STUN client,
// httptest server for the control plane, and a mock WG controller.
func newTestExchanger(t *testing.T, stunClient nat.STUNClient, ts *httptest.Server, ctrl *mockWGController) *Exchanger {
	t.Helper()
	logger := discardLogger()

	natCfg := nat.Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: time.Hour, // large so we only see initial discovery
		Timeout:         5 * time.Second,
	}
	discoverer := nat.NewDiscoverer(stunClient, natCfg, 51820, logger)
	wgManager := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
	cpClient := newTestControlPlane(t, ts)

	cfg := Config{}
	cfg.Enabled = true
	cfg.STUNServers = natCfg.STUNServers
	cfg.RefreshInterval = natCfg.RefreshInterval
	cfg.Timeout = natCfg.Timeout

	return NewExchanger(discoverer, wgManager, cpClient, cfg, logger)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestExchanger_Run_NATDisabled(t *testing.T) {
	logger := discardLogger()
	discoverer := nat.NewDiscoverer(nil, nat.Config{}, 51820, logger)
	wgManager := wireguard.NewManager(&mockWGController{}, wireguard.Config{}, logger)

	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	cpClient := newTestControlPlane(t, ts)

	cfg := Config{}
	cfg.Enabled = false
	// Set a non-zero field so ApplyDefaults does not override Enabled to true.
	cfg.RefreshInterval = 60 * time.Second

	e := NewExchanger(discoverer, wgManager, cpClient, cfg, logger)

	err := e.Run(context.Background(), "node-1")
	if err != nil {
		t.Fatalf("Run() = %v, want nil for disabled NAT", err)
	}
}

func TestExchanger_Run_InitialDiscoveryAndReport(t *testing.T) {
	addr := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	stunClient := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}

	peerPubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}

		var req api.EndpointReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.PublicEndpoint != "203.0.113.1:12345" {
			t.Errorf("PublicEndpoint = %q, want %q", req.PublicEndpoint, "203.0.113.1:12345")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-1", Endpoint: "5.6.7.8:51820"},
			},
		})
	}))
	defer ts.Close()

	ctrl := &mockWGController{}
	e := newTestExchanger(t, stunClient, ts, ctrl)

	// Pre-populate the WG manager's peer index so UpdatePeer can resolve the key.
	e.wgManager.PeerIndex().Add("peer-1", peerPubKey)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx, "node-1") }()

	// Wait for WG AddPeer call (from UpdatePeer via reportAndApply).
	waitFor(t, 2*time.Second, func() bool { return ctrl.addPeerCalls() >= 1 })

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context.Canceled", err)
	}
}

func TestExchanger_Run_ContextCancellation(t *testing.T) {
	addr := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	stunClient := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{})
	}))
	defer ts.Close()

	ctrl := &mockWGController{}
	e := newTestExchanger(t, stunClient, ts, ctrl)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx, "node-1") }()

	// Let it start, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func TestExchanger_RegisterHandlers(t *testing.T) {
	tests := []struct {
		name       string
		natEnabled bool
	}{
		{"NATEnabled", true},
		// RegisterHandlers must work even when NAT is disabled, because
		// inbound peer endpoint updates still need to be processed via SSE.
		{"NATDisabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := discardLogger()

			ts := httptest.NewServer(http.NotFoundHandler())
			defer ts.Close()
			cpClient := newTestControlPlane(t, ts)

			ctrl := &mockWGController{}
			wgManager := wireguard.NewManager(ctrl, wireguard.Config{}, logger)
			discoverer := nat.NewDiscoverer(nil, nat.Config{}, 51820, logger)

			cfg := Config{}
			if !tt.natEnabled {
				cfg.Enabled = false
				cfg.RefreshInterval = 60 * time.Second
			}
			e := NewExchanger(discoverer, wgManager, cpClient, cfg, logger)

			sseManager := api.NewSSEManager(cpClient, nil, logger)
			e.RegisterHandlers(sseManager)

			// Verify the handler works by creating a dispatcher and dispatching an event.
			dispatcher := api.NewEventDispatcher(logger)
			dispatcher.Register(api.EventPeerEndpointChanged, wireguard.HandlePeerEndpointChanged(wgManager))

			peerPubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
			wgManager.PeerIndex().Add("peer-1", peerPubKey)

			peer := api.Peer{
				ID:         "peer-1",
				PublicKey:  peerPubKey,
				MeshIP:     "10.0.0.2",
				Endpoint:   "9.8.7.6:51820",
				AllowedIPs: []string{"10.0.0.2/32"},
			}
			payload, _ := json.Marshal(peer)
			envelope := api.SignedEnvelope{
				EventType: api.EventPeerEndpointChanged,
				EventID:   "evt-1",
				Payload:   payload,
			}

			dispatcher.Dispatch(context.Background(), envelope)

			if n := ctrl.addPeerCalls(); n != 1 {
				t.Errorf("expected 1 AddPeer call, got %d", n)
			}
		})
	}
}

func TestExchanger_LastResult(t *testing.T) {
	addr := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	stunClient := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}

	logger := discardLogger()
	natCfg := nat.Config{
		Enabled:         true,
		STUNServers:     []string{"stun1:3478", "stun2:3478"},
		RefreshInterval: time.Hour,
		Timeout:         5 * time.Second,
	}
	discoverer := nat.NewDiscoverer(stunClient, natCfg, 51820, logger)

	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	cpClient := newTestControlPlane(t, ts)

	wgManager := wireguard.NewManager(&mockWGController{}, wireguard.Config{}, logger)

	cfg := Config{}
	cfg.Enabled = true
	e := NewExchanger(discoverer, wgManager, cpClient, cfg, logger)

	// Before discovery, LastResult should be nil.
	if e.LastResult() != nil {
		t.Error("expected nil LastResult before discovery")
	}

	// Trigger a discovery.
	_, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	info := e.LastResult()
	if info == nil {
		t.Fatal("expected non-nil LastResult after discovery")
	}
	if info.PublicEndpoint != "203.0.113.1:12345" {
		t.Errorf("PublicEndpoint = %q, want %q", info.PublicEndpoint, "203.0.113.1:12345")
	}
	if info.Type != "full_cone" {
		t.Errorf("Type = %q, want %q", info.Type, "full_cone")
	}
}

func TestExchanger_EndpointReporterAdapter(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v1/nodes/node-1/endpoint" {
			t.Errorf("path = %s, want /v1/nodes/node-1/endpoint", r.URL.Path)
		}

		var req api.EndpointReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.PublicEndpoint != "1.2.3.4:51820" {
			t.Errorf("PublicEndpoint = %q, want %q", req.PublicEndpoint, "1.2.3.4:51820")
		}
		if req.NATType != "full_cone" {
			t.Errorf("NATType = %q, want %q", req.NATType, "full_cone")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-1", Endpoint: "5.6.7.8:51820"},
			},
		})
	}))
	defer ts.Close()

	cpClient := newTestControlPlane(t, ts)
	reporter := &controlPlaneReporter{client: cpClient}

	resp, err := reporter.ReportEndpoint(context.Background(), "node-1", api.EndpointReport{
		PublicEndpoint: "1.2.3.4:51820",
		NATType:        "full_cone",
	})
	if err != nil {
		t.Fatalf("ReportEndpoint: %v", err)
	}
	if len(resp.PeerEndpoints) != 1 {
		t.Fatalf("len(PeerEndpoints) = %d, want 1", len(resp.PeerEndpoints))
	}
	if resp.PeerEndpoints[0].PeerID != "peer-1" {
		t.Errorf("PeerID = %q, want %q", resp.PeerEndpoints[0].PeerID, "peer-1")
	}
	if resp.PeerEndpoints[0].Endpoint != "5.6.7.8:51820" {
		t.Errorf("Endpoint = %q, want %q", resp.PeerEndpoints[0].Endpoint, "5.6.7.8:51820")
	}
}

func TestExchanger_Run_SkipsEmptyPeerEndpoint(t *testing.T) {
	addr := nat.MappedAddress{IP: net.IPv4(203, 0, 113, 1), Port: 12345}
	stunClient := &mockSTUNClient{
		results: map[string]mockBindResult{
			"stun1:3478": {Addr: addr},
			"stun2:3478": {Addr: addr},
		},
	}

	peerPubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-empty", Endpoint: ""},           // should be skipped
				{PeerID: "peer-valid", Endpoint: "1.2.3.4:51820"}, // should be applied
			},
		})
	}))
	defer ts.Close()

	ctrl := &mockWGController{}
	e := newTestExchanger(t, stunClient, ts, ctrl)

	// Pre-populate peer index for both peers.
	e.wgManager.PeerIndex().Add("peer-empty", peerPubKey)
	e.wgManager.PeerIndex().Add("peer-valid", peerPubKey)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx, "node-1") }()

	// Wait for exactly 1 AddPeer call (peer-valid only, peer-empty skipped).
	waitFor(t, 2*time.Second, func() bool { return ctrl.addPeerCalls() >= 1 })

	// Give a small window to ensure no extra calls arrive.
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	// Only peer-valid should have triggered an AddPeer call.
	if n := ctrl.addPeerCalls(); n != 1 {
		t.Errorf("expected 1 AddPeer call (peer-valid only), got %d", n)
	}
}
