// Package mockapi provides a mock Central API server for end-to-end testing.
// It returns fixture responses for each endpoint and tracks call counters
// that can be queried via the GET /test/assertions endpoint.
package mockapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// AssertionCounters holds call counters for each tracked endpoint.
type AssertionCounters struct {
	RegisterCount          int64 `json:"registration_count"`
	HeartbeatCount         int64 `json:"heartbeat_count"`
	StateCount             int64 `json:"state_count"`
	MetadataCount          int64 `json:"metadata_count"`
	DeregisterCount        int64 `json:"deregister_count"`
	KeyRotateCount         int64 `json:"key_rotate_count"`
	CapabilitiesCount      int64 `json:"capabilities_count"`
	EndpointCount          int64 `json:"endpoint_count"`
	DriftCount             int64 `json:"drift_count"`
	SecretsCount           int64 `json:"secrets_count"`
	ReportCount            int64 `json:"report_count"`
	ExecutionAckCount      int64 `json:"execution_ack_count"`
	ExecutionResultCount   int64 `json:"execution_result_count"`
	MetricsCount           int64 `json:"metrics_count"`
	LogsCount              int64 `json:"logs_count"`
	AuditCount             int64 `json:"audit_count"`
	ArtifactCount          int64 `json:"artifact_count"`
	TunnelReadyCount       int64 `json:"tunnel_ready_count"`
	TunnelClosedCount      int64 `json:"tunnel_closed_count"`
	IntegrityViolationCount int64 `json:"integrity_violation_count"`
	InjectEventCount        int64 `json:"inject_event_count"`
}

// DefaultKeepAliveInterval is the default interval between SSE keep-alive comments.
const DefaultKeepAliveInterval = 15 * time.Second

// Server is a mock Central API server that returns fixture data.
type Server struct {
	// KeepAliveInterval controls the SSE keep-alive comment interval.
	// Defaults to DefaultKeepAliveInterval (15s). Set before calling Handler().
	KeepAliveInterval time.Duration

	registerCount          atomic.Int64
	heartbeatCount         atomic.Int64
	stateCount             atomic.Int64
	metadataCount          atomic.Int64
	deregisterCount        atomic.Int64
	keyRotateCount         atomic.Int64
	capabilitiesCount      atomic.Int64
	endpointCount          atomic.Int64
	driftCount             atomic.Int64
	secretsCount           atomic.Int64
	reportCount            atomic.Int64
	executionAckCount      atomic.Int64
	executionResultCount   atomic.Int64
	metricsCount           atomic.Int64
	logsCount              atomic.Int64
	auditCount             atomic.Int64
	artifactCount          atomic.Int64
	tunnelReadyCount       atomic.Int64
	tunnelClosedCount      atomic.Int64
	integrityViolationCount atomic.Int64
	injectEventCount        atomic.Int64

	sseClients sync.Map // map[uint64]chan api.SignedEnvelope

	stateFixture   api.StateResponse
	stateFixtureMu sync.RWMutex

	lastRequests   map[string][]byte
	lastRequestsMu sync.RWMutex

	sseClientID atomic.Uint64

	mux *http.ServeMux
}

// New creates a new mock API server with all routes registered.
func New() *Server {
	s := &Server{
		KeepAliveInterval: DefaultKeepAliveInterval,
		lastRequests:      make(map[string][]byte),
		mux:               http.NewServeMux(),
		stateFixture: api.StateResponse{
			Peers: fixturePeers,
			Policies: []api.Policy{
				{
					ID: "policy-001",
					Rules: []api.PolicyRule{
						{
							Src:      "10.99.0.0/24",
							Dst:      "10.99.0.0/24",
							Port:     0,
							Protocol: "any",
							Action:   "allow",
						},
						{
							Src:      "10.99.0.0/24",
							Dst:      "0.0.0.0/0",
							Port:     443,
							Protocol: "tcp",
							Action:   "allow",
						},
					},
				},
			},
			SigningKeys: &api.SigningKeys{
				Current:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Previous: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
			},
			Metadata: map[string]string{
				"environment": "e2e-test",
				"region":      "mock-region-1",
			},
			BridgeConfig: &api.BridgeConfig{
				AccessSubnets:    []string{"192.168.100.0/24"},
				EnableNAT:        true,
				EnableForwarding: true,
			},
			RelayConfig: &api.RelayConfig{
				Sessions: []api.RelaySessionAssignment{
					{
						SessionID:     "relay-sess-001",
						PeerAID:       "peer-001",
						PeerAEndpoint: "203.0.113.1:51820",
						PeerBID:       "peer-003",
						PeerBEndpoint: "203.0.113.3:51820",
						ExpiresAt:     time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
					},
				},
			},
			UserAccessConfig: &api.UserAccessConfig{
				Enabled:       true,
				InterfaceName: "wg-access0",
				ListenPort:    51821,
				Peers: []api.UserAccessPeer{
					{
						PublicKey:  "ua-pub-key-001",
						AllowedIPs: []string{"10.100.0.1/32"},
						Label:      "admin-laptop",
					},
				},
			},
			IngressConfig: &api.IngressConfig{
				Enabled: true,
				Rules: []api.IngressRule{
					{
						RuleID:     "ingress-001",
						ListenPort: 443,
						TargetAddr: "10.99.0.2:8443",
						Mode:       "tcp",
					},
				},
			},
			SiteToSiteConfig: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					{
						TunnelID:        "s2s-001",
						RemoteEndpoint:  "198.51.100.1:51820",
						RemotePublicKey: "s2s-remote-pub-key-001",
						LocalSubnets:    []string{"10.99.0.0/24"},
						RemoteSubnets:   []string{"172.16.0.0/16"},
						InterfaceName:   "wg-s2s0",
						ListenPort:      51822,
					},
				},
			},
			Data: []api.DataEntry{
				{
					Key:         "app/config",
					ContentType: "application/json",
					Payload:     json.RawMessage(`{"log_level":"info","max_conns":100}`),
					Version:     1,
					UpdatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					Key:         "certs/ca",
					ContentType: "application/x-pem-file",
					Payload:     json.RawMessage(`"-----BEGIN CERTIFICATE-----\nmock-ca-cert\n-----END CERTIFICATE-----"`),
					Version:     2,
					UpdatedAt:   time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
				},
			},
			SecretRefs: []api.SecretRef{
				{Key: "db-password", Version: 1},
				{Key: "tls-private-key", Version: 3},
			},
		},
	}
	s.registerRoutes()
	return s
}

// Handler returns the http.Handler for use with httptest or a real listener.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Assertions returns a snapshot of the current call counters.
func (s *Server) Assertions() AssertionCounters {
	return AssertionCounters{
		RegisterCount:          s.registerCount.Load(),
		HeartbeatCount:         s.heartbeatCount.Load(),
		StateCount:             s.stateCount.Load(),
		MetadataCount:          s.metadataCount.Load(),
		DeregisterCount:        s.deregisterCount.Load(),
		KeyRotateCount:         s.keyRotateCount.Load(),
		CapabilitiesCount:      s.capabilitiesCount.Load(),
		EndpointCount:          s.endpointCount.Load(),
		DriftCount:             s.driftCount.Load(),
		SecretsCount:           s.secretsCount.Load(),
		ReportCount:            s.reportCount.Load(),
		ExecutionAckCount:      s.executionAckCount.Load(),
		ExecutionResultCount:   s.executionResultCount.Load(),
		MetricsCount:           s.metricsCount.Load(),
		LogsCount:              s.logsCount.Load(),
		AuditCount:             s.auditCount.Load(),
		ArtifactCount:          s.artifactCount.Load(),
		TunnelReadyCount:       s.tunnelReadyCount.Load(),
		TunnelClosedCount:      s.tunnelClosedCount.Load(),
		IntegrityViolationCount: s.integrityViolationCount.Load(),
		InjectEventCount:        s.injectEventCount.Load(),
	}
}

// fixturePeers is the shared peer fixture used by both register and state handlers.
var fixturePeers = []api.Peer{
	{
		ID:         "peer-001",
		PublicKey:  "wg-pub-key-peer-001",
		MeshIP:     "10.99.0.2",
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"10.99.0.2/32"},
		PSK:        "mock-psk-001",
	},
	{
		ID:         "peer-002",
		PublicKey:  "wg-pub-key-peer-002",
		MeshIP:     "10.99.0.3",
		Endpoint:   "203.0.113.2:51820",
		AllowedIPs: []string{"10.99.0.3/32"},
		PSK:        "mock-psk-002",
	},
}

func (s *Server) registerRoutes() {
	// Existing endpoints.
	s.mux.HandleFunc("GET /v1/ping", s.handlePing)
	s.mux.HandleFunc("POST /v1/register", s.handleRegister)
	s.mux.HandleFunc("POST /v1/nodes/{id}/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("GET /v1/nodes/{id}/state", s.handleState)
	s.mux.HandleFunc("GET /v1/nodes/{id}/metadata", s.handleMetadata)
	s.mux.HandleFunc("GET /v1/nodes/{id}/events", s.handleEvents)
	s.mux.HandleFunc("GET /test/assertions", s.handleAssertions)

	// New endpoints.
	s.mux.HandleFunc("POST /v1/nodes/{id}/deregister", s.handleDeregister)
	s.mux.HandleFunc("POST /v1/keys/rotate", s.handleKeyRotate)
	s.mux.HandleFunc("PUT /v1/nodes/{id}/capabilities", s.handleCapabilities)
	s.mux.HandleFunc("PUT /v1/nodes/{id}/endpoint", s.handleEndpoint)
	s.mux.HandleFunc("POST /v1/nodes/{id}/drift", s.handleDrift)
	s.mux.HandleFunc("GET /v1/nodes/{id}/secrets/{key}", s.handleSecrets)
	s.mux.HandleFunc("POST /v1/nodes/{id}/report", s.handleReport)
	s.mux.HandleFunc("POST /v1/nodes/{id}/executions/{eid}/ack", s.handleExecutionAck)
	s.mux.HandleFunc("POST /v1/nodes/{id}/executions/{eid}/result", s.handleExecutionResult)
	s.mux.HandleFunc("POST /v1/nodes/{id}/metrics", s.handleMetrics)
	s.mux.HandleFunc("POST /v1/nodes/{id}/logs", s.handleLogs)
	s.mux.HandleFunc("POST /v1/nodes/{id}/audit", s.handleAudit)
	s.mux.HandleFunc("GET /v1/artifacts/plexd/{version}/{os}/{arch}", s.handleArtifact)
	s.mux.HandleFunc("POST /v1/nodes/{id}/tunnels/{sid}/ready", s.handleTunnelReady)
	s.mux.HandleFunc("POST /v1/nodes/{id}/tunnels/{sid}/closed", s.handleTunnelClosed)
	s.mux.HandleFunc("POST /v1/nodes/{id}/integrity/violations", s.handleIntegrityViolation)

	// Test control endpoints.
	s.mux.HandleFunc("PUT /test/state", s.handleSetState)
	s.mux.HandleFunc("POST /test/configure-state", s.handleSetState)
	s.mux.HandleFunc("POST /test/inject-event", s.handleInjectEvent)
	s.mux.HandleFunc("GET /test/last-request/{endpoint}", s.handleLastRequest)

	// Method-not-allowed fallbacks.
	s.mux.HandleFunc("/v1/ping", methodNotAllowed)
	s.mux.HandleFunc("/v1/register", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/heartbeat", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/deregister", methodNotAllowed)
	s.mux.HandleFunc("/v1/keys/rotate", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/capabilities", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/endpoint", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/drift", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/secrets/{key}", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/report", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/executions/{eid}/ack", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/executions/{eid}/result", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/metrics", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/logs", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/audit", methodNotAllowed)
	s.mux.HandleFunc("/v1/artifacts/plexd/{version}/{os}/{arch}", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/tunnels/{sid}/ready", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/tunnels/{sid}/closed", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/integrity/violations", methodNotAllowed)
	s.mux.HandleFunc("/test/state", methodNotAllowed)
	s.mux.HandleFunc("/test/configure-state", methodNotAllowed)
	s.mux.HandleFunc("/test/inject-event", methodNotAllowed)
}

// captureBody reads the full request body, stores the raw bytes in lastRequests
// under the given endpoint name, and returns the bytes for further processing.
func (s *Server) captureBody(endpoint string, r *http.Request) ([]byte, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	s.lastRequestsMu.Lock()
	s.lastRequests[endpoint] = data
	s.lastRequestsMu.Unlock()
	return data, nil
}

// decodeBody captures the request body for the given endpoint and JSON-decodes
// it into v. Returns false and writes a 400 response if either step fails.
func (s *Server) decodeBody(w http.ResponseWriter, r *http.Request, endpoint string, v any) bool {
	data, err := s.captureBody(endpoint, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return false
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return false
	}
	return true
}

// LastRequestBody returns the last captured request body for the given endpoint.
func (s *Server) LastRequestBody(endpoint string) ([]byte, bool) {
	s.lastRequestsMu.RLock()
	defer s.lastRequestsMu.RUnlock()
	data, ok := s.lastRequests[endpoint]
	return data, ok
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handlePing handles GET /v1/ping (REQ-001).
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct{}{})
}

// handleRegister handles POST /v1/register (REQ-002).
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req api.RegisterRequest
	if !s.decodeBody(w, r, "register", &req) {
		return
	}

	s.registerCount.Add(1)

	resp := api.RegisterResponse{
		NodeID:          "node-mock-001",
		MeshIP:          "10.99.0.1",
		SigningPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		NodeSecretKey:   "mock-node-secret-key-abc123",
		Peers:           fixturePeers,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHeartbeat handles POST /v1/nodes/{id}/heartbeat (REQ-003).
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req api.HeartbeatRequest
	if !s.decodeBody(w, r, "heartbeat", &req) {
		return
	}

	s.heartbeatCount.Add(1)

	resp := api.HeartbeatResponse{
		Reconcile:  true,
		RotateKeys: false,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleState handles GET /v1/nodes/{id}/state (REQ-004).
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.stateCount.Add(1)
	writeJSON(w, http.StatusOK, s.GetState())
}

// handleMetadata handles GET /v1/nodes/{id}/metadata (REQ-005).
func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	s.metadataCount.Add(1)

	meta := map[string]string{
		"environment": "e2e-test",
		"region":      "mock-region-1",
		"role":        "worker",
		"version":     "1.0.0-mock",
	}
	writeJSON(w, http.StatusOK, meta)
}

// handleEvents handles GET /v1/nodes/{id}/events (REQ-006).
// Sends a single SSE event then sends keep-alive comments at KeepAliveInterval
// until the client disconnects.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	nodeID := r.PathValue("id")
	envelope := api.SignedEnvelope{
		EventType: api.EventNodeStateUpdated,
		EventID:   "evt-mock-001",
		IssuedAt:  time.Now().UTC(),
		Nonce:     "mock-nonce-001",
		Payload:   json.RawMessage(fmt.Sprintf(`{"node_id":%q}`, nodeID)),
		Signature: "mock-signature-placeholder",
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return
	}

	fmt.Fprintf(w, "id: %s\n", envelope.EventID)
	fmt.Fprintf(w, "event: %s\n", envelope.EventType)
	// Split data across SSE data lines if it contains newlines (it won't for JSON, but be safe).
	for _, line := range strings.Split(string(data), "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
	flusher.Flush()

	// Register this client for broadcast events.
	clientID := s.sseClientID.Add(1)
	clientCh := make(chan api.SignedEnvelope, 16)
	s.sseClients.Store(clientID, clientCh)
	defer s.sseClients.Delete(clientID)

	// Send keep-alive comments at KeepAliveInterval until client disconnects.
	// Also listen for injected events on the client channel.
	ticker := time.NewTicker(s.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n"); err != nil {
				return
			}
			flusher.Flush()
		case env := <-clientCh:
			evtData, err := json.Marshal(env)
			if err != nil {
				return
			}
			fmt.Fprintf(w, "id: %s\n", env.EventID)
			fmt.Fprintf(w, "event: %s\n", env.EventType)
			for _, line := range strings.Split(string(evtData), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
			flusher.Flush()
		}
	}
}

// handleAssertions handles GET /test/assertions (REQ-007).
func (s *Server) handleAssertions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Assertions())
}

// handleDeregister handles POST /v1/nodes/{id}/deregister.
// The client sends a nil body (see endpoints.go), so we only capture for
// test observability — there is no payload to decode.
func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	if _, err := s.captureBody("deregister", r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	s.deregisterCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleKeyRotate handles POST /v1/keys/rotate.
func (s *Server) handleKeyRotate(w http.ResponseWriter, r *http.Request) {
	var req api.KeyRotateRequest
	if !s.decodeBody(w, r, "key_rotate", &req) {
		return
	}
	s.keyRotateCount.Add(1)
	writeJSON(w, http.StatusOK, api.KeyRotateResponse{UpdatedPeers: fixturePeers})
}

// handleCapabilities handles PUT /v1/nodes/{id}/capabilities.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	var req api.CapabilitiesPayload
	if !s.decodeBody(w, r, "capabilities", &req) {
		return
	}
	s.capabilitiesCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleEndpoint handles PUT /v1/nodes/{id}/endpoint.
func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	var req api.EndpointReport
	if !s.decodeBody(w, r, "endpoint", &req) {
		return
	}
	s.endpointCount.Add(1)
	resp := api.EndpointResponse{
		PeerEndpoints: []api.PeerEndpoint{
			{PeerID: "peer-001", Endpoint: "203.0.113.1:51820"},
			{PeerID: "peer-002", Endpoint: "203.0.113.2:51820"},
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDrift handles POST /v1/nodes/{id}/drift.
func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	var req api.DriftReport
	if !s.decodeBody(w, r, "drift", &req) {
		return
	}
	s.driftCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleSecrets handles GET /v1/nodes/{id}/secrets/{key}.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	s.secretsCount.Add(1)
	key := r.PathValue("key")
	resp := api.SecretResponse{
		Key:        key,
		Ciphertext: "bW9jay1jaXBoZXJ0ZXh0",
		Nonce:      "bW9jay1ub25jZQ==",
		Version:    1,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleReport handles POST /v1/nodes/{id}/report.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	var req api.ReportSyncRequest
	if !s.decodeBody(w, r, "report", &req) {
		return
	}
	s.reportCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleExecutionAck handles POST /v1/nodes/{id}/executions/{eid}/ack.
func (s *Server) handleExecutionAck(w http.ResponseWriter, r *http.Request) {
	var req api.ExecutionAck
	if !s.decodeBody(w, r, "execution_ack", &req) {
		return
	}
	s.executionAckCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleExecutionResult handles POST /v1/nodes/{id}/executions/{eid}/result.
func (s *Server) handleExecutionResult(w http.ResponseWriter, r *http.Request) {
	var req api.ExecutionResult
	if !s.decodeBody(w, r, "execution_result", &req) {
		return
	}
	s.executionResultCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleMetrics handles POST /v1/nodes/{id}/metrics.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var req api.MetricBatch
	if !s.decodeBody(w, r, "metrics", &req) {
		return
	}
	s.metricsCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleLogs handles POST /v1/nodes/{id}/logs.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	var req api.LogBatch
	if !s.decodeBody(w, r, "logs", &req) {
		return
	}
	s.logsCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleAudit handles POST /v1/nodes/{id}/audit.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	var req api.AuditBatch
	if !s.decodeBody(w, r, "audit", &req) {
		return
	}
	s.auditCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleArtifact handles GET /v1/artifacts/plexd/{version}/{os}/{arch}.
func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	s.artifactCount.Add(1)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("mock-plexd-binary-v0.0.0")); err != nil {
		slog.Error("handleArtifact: write failed", "error", err)
	}
}

// handleTunnelReady handles POST /v1/nodes/{id}/tunnels/{sid}/ready.
func (s *Server) handleTunnelReady(w http.ResponseWriter, r *http.Request) {
	var req api.TunnelReadyRequest
	if !s.decodeBody(w, r, "tunnel_ready", &req) {
		return
	}
	s.tunnelReadyCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleTunnelClosed handles POST /v1/nodes/{id}/tunnels/{sid}/closed.
func (s *Server) handleTunnelClosed(w http.ResponseWriter, r *http.Request) {
	var req api.TunnelClosedRequest
	if !s.decodeBody(w, r, "tunnel_closed", &req) {
		return
	}
	s.tunnelClosedCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleIntegrityViolation handles POST /v1/nodes/{id}/integrity/violations.
func (s *Server) handleIntegrityViolation(w http.ResponseWriter, r *http.Request) {
	var req api.IntegrityViolationReport
	if !s.decodeBody(w, r, "integrity_violation", &req) {
		return
	}
	s.integrityViolationCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// SetState updates the mutable state fixture returned by GET /v1/nodes/{id}/state.
func (s *Server) SetState(state api.StateResponse) {
	s.stateFixtureMu.Lock()
	s.stateFixture = state
	s.stateFixtureMu.Unlock()
}

// GetState returns a copy of the current state fixture.
func (s *Server) GetState() api.StateResponse {
	s.stateFixtureMu.RLock()
	state := s.stateFixture
	s.stateFixtureMu.RUnlock()
	// Deep-copy the Metadata map so callers cannot mutate server state.
	if state.Metadata != nil {
		cp := make(map[string]string, len(state.Metadata))
		for k, v := range state.Metadata {
			cp[k] = v
		}
		state.Metadata = cp
	}
	return state
}

// handleSetState handles PUT /test/state and POST /test/configure-state.
func (s *Server) handleSetState(w http.ResponseWriter, r *http.Request) {
	var state api.StateResponse
	if !s.decodeBody(w, r, "configure_state", &state) {
		return
	}
	s.SetState(state)
	w.WriteHeader(http.StatusNoContent)
}

// BroadcastSSE sends an SSE event to all connected SSE clients.
func (s *Server) BroadcastSSE(envelope api.SignedEnvelope) {
	s.sseClients.Range(func(key, value any) bool {
		ch := value.(chan api.SignedEnvelope)
		select {
		case ch <- envelope:
		default:
			// Client channel full, skip to avoid blocking.
		}
		return true
	})
}

// handleInjectEvent handles POST /test/inject-event.
func (s *Server) handleInjectEvent(w http.ResponseWriter, r *http.Request) {
	var envelope api.SignedEnvelope
	if !s.decodeBody(w, r, "inject_event", &envelope) {
		return
	}
	s.injectEventCount.Add(1)
	s.BroadcastSSE(envelope)
	w.WriteHeader(http.StatusNoContent)
}

// handleLastRequest handles GET /test/last-request/{endpoint}.
func (s *Server) handleLastRequest(w http.ResponseWriter, r *http.Request) {
	endpoint := r.PathValue("endpoint")
	s.lastRequestsMu.RLock()
	data, ok := s.lastRequests[endpoint]
	s.lastRequestsMu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no captured request for endpoint"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		slog.Error("handleLastRequest: write failed", "error", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: encode failed", "error", err)
	}
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}
