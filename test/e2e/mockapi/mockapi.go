// Package mockapi provides a mock Central API server for end-to-end testing.
// It returns fixture responses for each endpoint and tracks call counters
// that can be queried via the GET /test/assertions endpoint.
package mockapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// AssertionCounters holds call counters for each tracked endpoint.
type AssertionCounters struct {
	RegisterCount  int64 `json:"registration_count"`
	HeartbeatCount int64 `json:"heartbeat_count"`
	StateCount     int64 `json:"state_count"`
	MetadataCount  int64 `json:"metadata_count"`
}

// DefaultKeepAliveInterval is the default interval between SSE keep-alive comments.
const DefaultKeepAliveInterval = 15 * time.Second

// Server is a mock Central API server that returns fixture data.
type Server struct {
	// KeepAliveInterval controls the SSE keep-alive comment interval.
	// Defaults to DefaultKeepAliveInterval (15s). Set before calling Handler().
	KeepAliveInterval time.Duration

	registerCount  atomic.Int64
	heartbeatCount atomic.Int64
	stateCount     atomic.Int64
	metadataCount  atomic.Int64
	mux            *http.ServeMux
}

// New creates a new mock API server with all routes registered.
func New() *Server {
	s := &Server{
		KeepAliveInterval: DefaultKeepAliveInterval,
		mux:               http.NewServeMux(),
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
		RegisterCount:  s.registerCount.Load(),
		HeartbeatCount: s.heartbeatCount.Load(),
		StateCount:     s.stateCount.Load(),
		MetadataCount:  s.metadataCount.Load(),
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
	s.mux.HandleFunc("GET /v1/ping", s.handlePing)
	s.mux.HandleFunc("POST /v1/register", s.handleRegister)
	s.mux.HandleFunc("POST /v1/nodes/{id}/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("GET /v1/nodes/{id}/state", s.handleState)
	s.mux.HandleFunc("GET /v1/nodes/{id}/metadata", s.handleMetadata)
	s.mux.HandleFunc("GET /v1/nodes/{id}/events", s.handleEvents)
	s.mux.HandleFunc("GET /test/assertions", s.handleAssertions)

	// Method-not-allowed handlers for routes that only accept specific methods.
	s.mux.HandleFunc("/v1/ping", methodNotAllowed)
	s.mux.HandleFunc("/v1/register", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/heartbeat", methodNotAllowed)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
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

	resp := api.StateResponse{
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
		Metadata: map[string]string{
			"environment": "e2e-test",
			"region":      "mock-region-1",
		},
		Data:       []api.DataEntry{},
		SecretRefs: []api.SecretRef{},
	}
	writeJSON(w, http.StatusOK, resp)
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

	// Send keep-alive comments at KeepAliveInterval until client disconnects.
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
		}
	}
}

// handleAssertions handles GET /test/assertions (REQ-007).
func (s *Server) handleAssertions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Assertions())
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
