// Package mockapi provides a mock Central API server for end-to-end testing.
// It returns fixture responses for each endpoint and tracks call counters
// that can be queried via the GET /test/assertions endpoint.
package mockapi

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// AssertionCounters holds call counters for each tracked endpoint.
type AssertionCounters struct {
	RegisterCount           int64 `json:"registration_count"`
	HeartbeatCount          int64 `json:"heartbeat_count"`
	StateCount              int64 `json:"state_count"`
	KeyRotateCount          int64 `json:"key_rotate_count"`
	CapabilitiesCount       int64 `json:"capabilities_count"`
	EndpointCount           int64 `json:"endpoint_count"`
	SecretsCount            int64 `json:"secrets_count"`
	SecretsRateLimitedCount int64 `json:"secrets_rate_limited_count"`
	ReportPutCount          int64 `json:"report_put_count"`
	ReportDeleteCount       int64 `json:"report_delete_count"`
	ExecutionCallbackCount  int64 `json:"execution_callback_count"`
	ExecutionUploadCount    int64 `json:"execution_upload_count"`
	MetricsCount            int64 `json:"metrics_count"`
	LogsCount               int64 `json:"logs_count"`
	AuditCount              int64 `json:"audit_count"`
	SessionActivityCount    int64 `json:"session_activity_count"`
	IntegrityViolationCount int64 `json:"integrity_violation_count"`
	InjectEventCount        int64 `json:"inject_event_count"`
	EventsRequestCount      int64 `json:"events_request_count"`
	LocalMetricsCount       int64 `json:"local_metrics_count"`
	LocalLogsCount          int64 `json:"local_logs_count"`
	LocalAuditCount         int64 `json:"local_audit_count"`
	// UnauthorizedCount counts requests refused by the bearer-envelope gate. A
	// node that presents the wrong credential drives this above zero, which is
	// exactly the defect the suite failed to catch before the gate existed.
	UnauthorizedCount int64 `json:"unauthorized_count"`
}

// DefaultKeepAliveInterval is the default interval between SSE keep-alive comments.
const DefaultKeepAliveInterval = 15 * time.Second

// Server is a mock Central API server that returns fixture data.
type Server struct {
	// KeepAliveInterval controls the SSE keep-alive comment interval.
	// Defaults to DefaultKeepAliveInterval (15s). Set before calling Handler().
	KeepAliveInterval time.Duration

	registerCount           atomic.Int64
	heartbeatCount          atomic.Int64
	stateCount              atomic.Int64
	keyRotateCount          atomic.Int64
	capabilitiesCount       atomic.Int64
	endpointCount           atomic.Int64
	secretsCount            atomic.Int64
	secretCurrentVersion    atomic.Int64
	secretRateLimitNext     atomic.Int64
	secretRetryAfterSeconds atomic.Int64
	secretsRateLimitedCount atomic.Int64
	reportPutCount          atomic.Int64
	reportDeleteCount       atomic.Int64
	executionCallbackCount  atomic.Int64
	executionUploadCount    atomic.Int64
	metricsCount            atomic.Int64
	logsCount               atomic.Int64
	auditCount              atomic.Int64
	sessionActivityCount    atomic.Int64
	integrityViolationCount atomic.Int64
	injectEventCount        atomic.Int64
	eventsRequestCount      atomic.Int64
	localMetricsCount       atomic.Int64
	localLogsCount          atomic.Int64
	localAuditCount         atomic.Int64

	// Signed event stream state (issue #25), all guarded by eventsMu. Every
	// broadcast envelope is assigned a monotonic stream sequence (the first is
	// 1), appended to a bounded ring so a reconnecting client can replay from a
	// Last-Event-ID cursor, and fanned out to the registered live clients. The
	// ring records regardless of connected clients and regardless of descoped
	// mode. eventsMode is "streaming" (default) or "descoped"; flipping to
	// descoped closes every open stream through its done channel.
	eventsMu      sync.Mutex
	eventSeq      uint64
	eventRing     []storedEvent
	eventClients  map[uint64]*sseClient
	eventClientID uint64
	eventsMode    string

	stateFixture   api.NodeStateSnapshot
	stateFixtureMu sync.RWMutex

	heartbeatFixture   api.HeartbeatResponse
	heartbeatFixtureMu sync.RWMutex

	endpointTTL   time.Duration
	endpointTTLMu sync.RWMutex

	// Key-rotation state machine (issue #21), all guarded by keyRotationMu.
	// The control plane arms a pending rotation, the node submits its fresh
	// public key, and the mock answers a receipt (replaying the stored one on
	// an idempotent retry). Completion disarms.
	keyRotationMu       sync.Mutex
	nodePublicKey       string
	rotationArmed       bool
	lastRotationReceipt *api.KeyRotateResponse
	lastRotatedKey      string
	rotationCount       int

	unauthorizedCount atomic.Int64

	lastRequests   map[string][]byte
	lastRequestsMu sync.RWMutex

	signingPrivateKey   ed25519.PrivateKey
	signingPublicKeyB64 string

	nsk                 []byte // 32-byte AES-256-GCM key for secret encryption
	expectedBearerToken string // plaintext bearer token for local endpoint auth

	consumedNonces   map[string]struct{} // key: projectID+"|"+nonce, recorded only on 201
	consumedNoncesMu sync.Mutex

	// Execution callback state machine (issue #22), all guarded by execMu. The
	// node advances an execution through ack/started/terminal callbacks;
	// execStates maps an execution id to its current status (absent means
	// dispatched). A started callback that declares an over-ceiling output mints
	// a one-time presigned upload recorded in execUploads (token-keyed), and
	// execTokenCounter mints distinct upload tokens.
	execMu           sync.Mutex
	execStates       map[string]string
	execUploads      map[string]*execUpload
	execTokenCounter int

	mux *http.ServeMux
}

// New creates a new mock API server with all routes registered.
func New() *Server {
	// Generate a real ed25519 key pair for event signing.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("mockapi: generate signing key: " + err.Error())
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	s := &Server{
		KeepAliveInterval:   DefaultKeepAliveInterval,
		lastRequests:        make(map[string][]byte),
		mux:                 http.NewServeMux(),
		signingPrivateKey:   priv,
		signingPublicKeyB64: pubB64,
		// A deterministic 32-byte key that is deliberately not valid UTF-8, so
		// the suite cannot pass by accident if nsk ever regresses to being
		// emitted as a raw string instead of base64.
		nsk:                 mockNSK,
		expectedBearerToken: "e2e-local-bearer-token",
		consumedNonces:      make(map[string]struct{}),
		execStates:          make(map[string]string),
		execUploads:         make(map[string]*execUpload),
		eventClients:        make(map[uint64]*sseClient),
		eventsMode:          eventsModeStreaming,
		endpointTTL:         5 * time.Minute,
		heartbeatFixture: api.HeartbeatResponse{
			Reconcile:  true,
			RotateKeys: false,
		},
		stateFixture: newStateFixture(),
	}
	s.secretCurrentVersion.Store(1)
	s.secretRetryAfterSeconds.Store(1)
	s.registerRoutes()
	return s
}

// Handler returns the http.Handler for use with httptest or a real listener.
// Every authenticated route is served behind the bearer-envelope gate, so the
// suite exercises the credential contract rather than assuming it.
func (s *Server) Handler() http.Handler {
	return s.requireBearerEnvelope(s.mux)
}

// Assertions returns a snapshot of the current call counters.
func (s *Server) Assertions() AssertionCounters {
	return AssertionCounters{
		RegisterCount:           s.registerCount.Load(),
		HeartbeatCount:          s.heartbeatCount.Load(),
		StateCount:              s.stateCount.Load(),
		KeyRotateCount:          s.keyRotateCount.Load(),
		CapabilitiesCount:       s.capabilitiesCount.Load(),
		EndpointCount:           s.endpointCount.Load(),
		SecretsCount:            s.secretsCount.Load(),
		SecretsRateLimitedCount: s.secretsRateLimitedCount.Load(),
		ReportPutCount:          s.reportPutCount.Load(),
		ReportDeleteCount:       s.reportDeleteCount.Load(),
		ExecutionCallbackCount:  s.executionCallbackCount.Load(),
		ExecutionUploadCount:    s.executionUploadCount.Load(),
		MetricsCount:            s.metricsCount.Load(),
		LogsCount:               s.logsCount.Load(),
		AuditCount:              s.auditCount.Load(),
		SessionActivityCount:    s.sessionActivityCount.Load(),
		IntegrityViolationCount: s.integrityViolationCount.Load(),
		InjectEventCount:        s.injectEventCount.Load(),
		EventsRequestCount:      s.eventsRequestCount.Load(),
		LocalMetricsCount:       s.localMetricsCount.Load(),
		LocalLogsCount:          s.localLogsCount.Load(),
		LocalAuditCount:         s.localAuditCount.Load(),
		UnauthorizedCount:       s.unauthorizedCount.Load(),
	}
}

// newStateFixture builds the desired-state NodeStateSnapshot envelope served by
// GET /v1/nodes/{id}/state. The two peers mirror fixtureRegisterPeers (node_id
// ascending, self excluded) and carry no psk/allowed_ips/endpoint; the merged
// policy fingerprint is derived with policyFingerprint; the bridge subtree
// carries the four child configs; and both state and reports mirror one another
// (the contract splits them for forward compatibility).
func newStateFixture() api.NodeStateSnapshot {
	rules := []api.PolicyRule{
		{Action: "allow", Protocol: "any", SourceCIDR: "10.99.0.0/24", DestinationCIDR: "10.99.0.0/24"},
		{Action: "allow", Protocol: "tcp", SourceCIDR: "10.99.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
	}
	block := func() *api.NodeStateBlock {
		return &api.NodeStateBlock{
			Metadata: []api.StateEntry{
				{Key: "environment", Value: "e2e-test"},
				{Key: "region", Value: "mock-region-1"},
			},
			Data: []api.StateEntry{
				{Key: "app/config", Value: `{"log_level":"info","max_conns":100}`},
				{Key: "certs/ca", Value: "-----BEGIN CERTIFICATE-----\nmock-ca-cert\n-----END CERTIFICATE-----"},
			},
			Reports: []api.StateEntry{},
		}
	}
	return api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{
				NodeID:           "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
				MeshIP:           "10.99.0.2",
				PublicKey:        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
				FallbackEndpoint: "203.0.113.1:51820",
			},
			{
				NodeID:    "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
				MeshIP:    "10.99.0.3",
				PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			},
		},
		// The mock accepts heartbeats but never evaluates them into a projection,
		// so never_reported is the honest verdict — and the one a real control
		// plane serves for a freshly enrolled node.
		Reachability: json.RawMessage(`{"state":"never_reported","changed_at":"2026-01-01T00:00:00Z"}`),
		Policy: &api.PolicySnapshot{
			RevisionID:  "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1",
			Fingerprint: policyFingerprint(rules),
			Rules:       rules,
		},
		Bridge: &api.BridgeSnapshot{
			Relay: &api.RelayConfig{
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
			UserAccess: &api.UserAccessConfig{
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
			Ingress: &api.IngressConfig{
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
			SiteToSite: &api.SiteToSiteConfig{
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
		},
		State:   block(),
		Reports: block(),
	}
}

// policyFingerprint returns the 44-char base64 SHA-256 over the compact-JSON
// encoding of the rules slice. This canonicalization is MOCK-INTERNAL: plexd
// treats the fingerprint as an opaque comparison key and never re-derives it
// from the rules.
func policyFingerprint(rules []api.PolicyRule) string {
	data, err := json.Marshal(rules)
	if err != nil {
		panic("mockapi: marshal policy rules: " + err.Error())
	}
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Register contract fixtures and validators (issue #18).
const (
	mockProjectID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0"
	mockNodeID    = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"
	// mockSigningKeyID is the key id the mock stamps on every signed envelope and
	// returns from register; the agent's verifier selects the signing key by it.
	mockSigningKeyID = "did:web:plexsphere.com#key-e2e"
	// mockAPIVersion is the value stamped in the X-Plexsphere-API-Version header
	// on the events stream, matching the /v1 route prefix the mock serves.
	mockAPIVersion = "v1"

	// eventsModeStreaming serves the event stream normally; eventsModeDescoped
	// makes the events endpoint answer the spec's 501 descope.
	eventsModeStreaming = "streaming"
	eventsModeDescoped  = "descoped"

	// eventRingCap bounds the replay ring: beyond it the oldest entry is dropped.
	eventRingCap = 64
)

var (
	// mockNSK is the fixture NodeSecretKey: 32 bytes of high-bit data that is
	// not valid UTF-8, matching the entropy a real control plane returns.
	mockNSK = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
		0xf8, 0xe9, 0xda, 0xcb, 0xbc, 0xad, 0x9e, 0x8f,
	}
	// pubKeyRe matches a standard-padded base64 X25519 public key (44 chars).
	pubKeyRe = regexp.MustCompile("^[A-Za-z0-9+/]{43}=$")
	// tokenRe matches a bootstrap token and captures its kind (node|bridge).
	tokenRe = regexp.MustCompile("^psb_[a-z]+_[a-z2-7]+_(node|bridge)_[a-z2-7]{20,}$")
	// uuidRe matches a canonical 8-4-4-4-12 hex UUID (any version).
	uuidRe = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
	// sshFingerprintRe matches the capability manifest's optional host-key
	// fingerprint: the literal SHA256: prefix and a base64 body, padded or not.
	sshFingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]+={0,2}$`)
)

// releaseFixtures holds the plexd release binary and its Sigstore bundle served
// by GET /releases/{tag}/{asset}. They are byte-identical copies of the upgrade
// package's verification fixtures, so the e2e upgrade path fetches and verifies
// the same artifacts the unit tests do.
//
//go:embed testdata/fixture.bin testdata/fixture.sigstore.json
var releaseFixtures embed.FS

// fixtureRegisterPeers is the initial peer snapshot returned by the register
// handler. It is deliberately narrow (see api.RegisterPeer).
var fixtureRegisterPeers = []api.RegisterPeer{
	{
		NodeID:           "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
		MeshIP:           "10.99.0.2",
		PublicKey:        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		FallbackEndpoint: "203.0.113.1:51820",
	},
	{
		NodeID:    "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
		MeshIP:    "10.99.0.3",
		PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	},
}

// storedEvent is a broadcast envelope paired with its stream sequence, as held
// in the replay ring and delivered to live clients.
type storedEvent struct {
	seq uint64
	env api.Envelope
}

// sseClient is a registered live event stream. ch carries sequenced envelopes to
// the handler's write loop; done is closed when a descope flip tears the stream
// down.
type sseClient struct {
	ch   chan storedEvent
	done chan struct{}
}

func (s *Server) registerRoutes() {
	// Existing endpoints.
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
	s.mux.HandleFunc("POST /v1/register", s.handleRegister)
	s.mux.HandleFunc("POST /v1/nodes/{id}/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("GET /v1/nodes/{id}/state", s.handleState)
	s.mux.HandleFunc("GET /v1/nodes/{id}/events", s.handleEvents)
	s.mux.HandleFunc("GET /test/assertions", s.handleAssertions)

	// New endpoints.
	s.mux.HandleFunc("POST /v1/keys/rotate", s.handleKeyRotate)
	s.mux.HandleFunc("PUT /v1/nodes/{id}/capabilities", s.handleCapabilities)
	s.mux.HandleFunc("PUT /v1/nodes/{id}/endpoint", s.handleEndpoint)
	s.mux.HandleFunc("GET /v1/nodes/{id}/secrets/{key}", s.handleSecrets)
	s.mux.HandleFunc("PUT /v1/nodes/{id}/state/reports/{key}", s.handlePutStateReport)
	s.mux.HandleFunc("DELETE /v1/nodes/{id}/state/reports/{key}", s.handleDeleteStateReport)
	s.mux.HandleFunc("POST /v1/nodes/{id}/executions/{eid}", s.handleExecutionCallback)
	s.mux.HandleFunc("PUT /exec-output/{eid}", s.handleExecOutputUpload)
	s.mux.HandleFunc("POST /v1/nodes/{id}/metrics", s.handleMetrics)
	s.mux.HandleFunc("POST /v1/nodes/{id}/logs", s.handleLogs)
	s.mux.HandleFunc("POST /v1/nodes/{id}/audit", s.handleAudit)
	s.mux.HandleFunc("POST /v1/nodes/{id}/sessions/{sid}", s.handleSessionActivity)
	s.mux.HandleFunc("POST /v1/nodes/{id}/integrity-violations", s.handleIntegrityViolations)

	// Release channel fixture (outside /v1: this plays the GitHub release host,
	// not the control plane).
	s.mux.HandleFunc("GET /releases/{tag}/{asset}", s.handleReleases)

	// Test control endpoints.
	s.mux.HandleFunc("PUT /test/state", s.handleSetState)
	s.mux.HandleFunc("POST /test/configure-state", s.handleSetState)
	s.mux.HandleFunc("POST /test/configure-heartbeat", s.handleConfigureHeartbeat)
	s.mux.HandleFunc("POST /test/configure-endpoint", s.handleConfigureEndpoint)
	s.mux.HandleFunc("POST /test/configure-secrets", s.handleConfigureSecrets)
	s.mux.HandleFunc("POST /test/configure-events", s.handleConfigureEvents)
	s.mux.HandleFunc("POST /test/inject-event", s.handleInjectEvent)
	s.mux.HandleFunc("GET /test/last-request/{endpoint}", s.handleLastRequest)
	s.mux.HandleFunc("GET /test/bearer", s.handleBearer)

	// Method-not-allowed fallbacks.
	s.mux.HandleFunc("/v1/health", methodNotAllowed)
	s.mux.HandleFunc("/v1/register", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/heartbeat", methodNotAllowed)
	s.mux.HandleFunc("/v1/keys/rotate", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/capabilities", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/endpoint", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/secrets/{key}", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/state/reports/{key}", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/executions/{eid}", methodNotAllowed)
	s.mux.HandleFunc("/exec-output/{eid}", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/metrics", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/logs", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/audit", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/sessions/{sid}", methodNotAllowed)
	s.mux.HandleFunc("/v1/nodes/{id}/integrity-violations", methodNotAllowed)
	s.mux.HandleFunc("/releases/{tag}/{asset}", methodNotAllowed)
	s.mux.HandleFunc("/test/state", methodNotAllowed)
	s.mux.HandleFunc("/test/configure-state", methodNotAllowed)
	s.mux.HandleFunc("/test/configure-heartbeat", methodNotAllowed)
	s.mux.HandleFunc("/test/configure-endpoint", methodNotAllowed)
	s.mux.HandleFunc("/test/configure-secrets", methodNotAllowed)
	s.mux.HandleFunc("/test/configure-events", methodNotAllowed)
	s.mux.HandleFunc("/test/inject-event", methodNotAllowed)
}

// maxCapturedBody bounds how many bytes captureBody keeps per request. The
// mock is published on all interfaces by test/e2e/docker-compose.yml, so the
// decompressed stream must be bounded too: gzip expands arbitrarily.
const maxCapturedBody = 1 << 20

// captureBody reads the request body up to maxCapturedBody, stores the raw
// bytes in lastRequests under the given endpoint name, and returns the bytes
// for further processing. Handles gzip-compressed request bodies transparently.
func (s *Server) captureBody(endpoint string, r *http.Request) ([]byte, error) {
	var reader io.Reader = io.LimitReader(r.Body, maxCapturedBody)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gr, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		reader = io.LimitReader(gr, maxCapturedBody)
	}
	data, err := io.ReadAll(reader)
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

// healthStatus mirrors the control-plane GET /v1/health response shape: an
// overall status plus a list of named component checks.
type healthStatus struct {
	Status string        `json:"status"`
	Checks []healthCheck `json:"checks"`
}

// healthCheck is one component entry in a healthStatus.
type healthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// handleHealth handles GET /v1/health. It is unauthenticated (a readiness probe
// has no credentials) and answers the control-plane HealthStatus shape so the
// harness has a stable, contract-faithful liveness endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthStatus{
		Status: "ok",
		Checks: []healthCheck{{Name: "mock", Status: "ok", Detail: ""}},
	})
}

// handleRegister handles POST /v1/register (REQ-002). It enforces the full
// registration contract from issue #18: success is 201, and every denial is an
// RFC 9457 application/problem+json body mirroring the platform taxonomy. The
// bootstrap token is consumed (its nonce recorded) only on the 201 branch.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	s.registerCount.Add(1)

	// 1. Body decode (400, no code).
	r.Body = http.MaxBytesReader(w, r.Body, maxCapturedBody)
	data, err := s.captureBody("register", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "", "invalid request body")
		return
	}
	var req api.RegisterRequest
	if err := json.Unmarshal(data, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "", "invalid request body")
		return
	}

	// 2. Invariants (422, no code).
	switch {
	case req.BootstrapToken == "":
		writeProblem(w, r, http.StatusUnprocessableEntity, "", "bootstrap_token is required")
		return
	case req.Nonce == "":
		writeProblem(w, r, http.StatusUnprocessableEntity, "", "nonce is required")
		return
	case req.ResourceHandle == "":
		writeProblem(w, r, http.StatusUnprocessableEntity, "", "resource_handle is required")
		return
	case req.ProjectID == "" || req.ProjectID == "00000000-0000-0000-0000-000000000000" || !uuidRe.MatchString(req.ProjectID):
		writeProblem(w, r, http.StatusUnprocessableEntity, "", "project_id must be a non-zero UUID")
		return
	}
	for _, f := range []string{req.ProjectID, req.ResourceHandle, req.BootstrapToken, req.Nonce, req.RequestedResourceID} {
		if len(f) > 4096 {
			writeProblem(w, r, http.StatusUnprocessableEntity, "", "field exceeds maximum length of 4096")
			return
		}
	}

	// 3. Public key (400, public_key_invalid) — shape, then reject the zero key.
	if !pubKeyRe.MatchString(req.PublicKey) {
		writeProblem(w, r, http.StatusBadRequest, "public_key_invalid", "public_key must be 44-char standard base64")
		return
	}
	if raw, err := base64.StdEncoding.DecodeString(req.PublicKey); err == nil && isAllZero(raw) {
		writeProblem(w, r, http.StatusBadRequest, "public_key_invalid", "public_key must not be the zero key")
		return
	}

	// 4. Token (403).
	m := tokenRe.FindStringSubmatch(req.BootstrapToken)
	if m == nil {
		writeProblem(w, r, http.StatusForbidden, "", "bootstrap_token is malformed")
		return
	}
	if m[1] == "bridge" {
		writeProblem(w, r, http.StatusForbidden, "kind_mismatch", "bootstrap_token kind does not match node registration")
		return
	}
	// The random segment is the trailing field after the kind. tokenRe has
	// already anchored the format to exactly four underscores, so index 4 is
	// safe. Token layout: psb_<env>_<project>_<kind>_<random>.
	random := strings.Split(req.BootstrapToken, "_")[4]
	switch {
	case strings.Contains(random, "consumed"):
		writeProblem(w, r, http.StatusForbidden, "token_consumed", "bootstrap_token already consumed")
		return
	case strings.Contains(random, "expired"):
		writeProblem(w, r, http.StatusForbidden, "token_expired", "bootstrap_token expired")
		return
	case strings.Contains(random, "revoked"):
		writeProblem(w, r, http.StatusForbidden, "token_revoked", "bootstrap_token revoked")
		return
	}

	// 5. Project match (403).
	if req.ProjectID != mockProjectID {
		writeProblem(w, r, http.StatusForbidden, "project_mismatch", "project_id does not match the bootstrap token")
		return
	}

	// 6. Nonce replay (403).
	nonceKey := req.ProjectID + "|" + req.Nonce
	s.consumedNoncesMu.Lock()
	_, replayed := s.consumedNonces[nonceKey]
	s.consumedNoncesMu.Unlock()
	if replayed {
		writeProblem(w, r, http.StatusForbidden, "nonce_collision", "nonce has already been used")
		return
	}

	// 7. Resource resolution (404).
	if req.ResourceHandle == "unknown-resource" {
		writeProblem(w, r, http.StatusNotFound, "resource_not_found", "resource handle could not be resolved")
		return
	}

	// 8. Magic handles for allocator/server failures.
	switch req.ResourceHandle {
	case "exhausted-pool":
		writeProblem(w, r, http.StatusServiceUnavailable, "pool_exhausted", "address pool exhausted")
		return
	case "exhausted-subrange":
		writeProblem(w, r, http.StatusServiceUnavailable, "subrange_exhausted", "address subrange exhausted")
		return
	case "contended-allocator":
		writeProblem(w, r, http.StatusServiceUnavailable, "allocator_contention", "allocator contention, retry")
		return
	case "boom-internal":
		writeProblem(w, r, http.StatusInternalServerError, "", "internal server error")
		return
	}

	// 9. Success (201). Claim the nonce only here — the token is never consumed
	// on any error branch. Check-and-set under one lock: the read in step 6 is
	// a fast path, so two concurrent registrations sharing a nonce would
	// otherwise both observe it free and both be granted an identity.
	s.consumedNoncesMu.Lock()
	_, replayed = s.consumedNonces[nonceKey]
	if !replayed {
		s.consumedNonces[nonceKey] = struct{}{}
	}
	s.consumedNoncesMu.Unlock()
	if replayed {
		writeProblem(w, r, http.StatusForbidden, "nonce_collision", "nonce has already been used")
		return
	}

	// Record the node's public key so the keys/rotate handler can recognize an
	// unchanged-key submission (issue #21).
	s.keyRotationMu.Lock()
	s.nodePublicKey = req.PublicKey
	s.keyRotationMu.Unlock()

	resp := api.RegisterResponse{
		NodeID:           mockNodeID,
		MeshIP:           "10.99.0.1",
		SigningPublicKey: s.signingPublicKeyB64,
		SigningKeyID:     mockSigningKeyID,
		// NSK is standard-padded base64 per the register contract; plexd
		// decodes it back into the 32-byte AES-256-GCM key.
		NSK:            base64.StdEncoding.EncodeToString(s.nsk),
		PeerSnapshot:   fixtureRegisterPeers,
		DomainMeshCIDR: "10.99.0.0/24",
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleHeartbeat handles POST /v1/nodes/{id}/heartbeat (REQ-003). It enforces
// the v1 heartbeat contract: strict decoding, a required nat_summary object,
// clock-skew tolerance, and checksum/version shape. The counter increments only
// when every check passes, so invalid requests do not count.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	data, err := s.captureBody("heartbeat", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_heartbeat_request", "invalid request body")
		return
	}

	var req api.HeartbeatRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_heartbeat_request", "heartbeat body is malformed")
		return
	}

	// nat_summary is a required object: reject absent, null, or non-object. This
	// is what proves the agent sends {} rather than null when NAT discovery has
	// not produced a result yet.
	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawFields); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_heartbeat_request", "heartbeat body is malformed")
		return
	}
	if natRaw, ok := rawFields["nat_summary"]; !ok || !isJSONObject(natRaw) {
		writeProblem(w, r, http.StatusBadRequest, "malformed_heartbeat_request", "nat_summary must be a JSON object")
		return
	}

	// Clock skew: client_now must be within 60s of server time either way.
	if skew := time.Since(req.ClientNow); skew > 60*time.Second || skew < -60*time.Second {
		writeProblem(w, r, http.StatusBadRequest, "clock_skew", "client_now is outside the accepted tolerance")
		return
	}

	if !validBinaryChecksum(req.BinaryChecksum) {
		writeProblem(w, r, http.StatusBadRequest, "binary_checksum_empty", "binary_checksum must be 64-char hex or base64 of 32 bytes")
		return
	}
	if strings.TrimSpace(req.BinaryVersion) == "" {
		writeProblem(w, r, http.StatusBadRequest, "binary_version_empty", "binary_version is required")
		return
	}

	s.heartbeatCount.Add(1)

	s.heartbeatFixtureMu.RLock()
	resp := s.heartbeatFixture
	s.heartbeatFixtureMu.RUnlock()
	resp.AcceptedAt = time.Now().UTC()

	// Re-arm the rotation each time we serve rotate_keys=true, mirroring a
	// control plane that keeps signaling while the rotation is pending.
	if resp.RotateKeys {
		s.keyRotationMu.Lock()
		s.rotationArmed = true
		s.keyRotationMu.Unlock()
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleState handles GET /v1/nodes/{id}/state (REQ-004). The executions block
// is served through projectExecutions, so every pull reports the live callback
// status of each entry still awaiting delivery. The sessions block is served
// through projectSessions, so every pull redelivers the sessions that are still
// live.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.stateCount.Add(1)
	state := s.GetState()
	state.Executions = s.projectExecutions(state.Executions)
	served := s.projectSessions(*state.Sessions)
	state.Sessions = &served
	writeJSON(w, http.StatusOK, state)
}

// projectExecutions returns the executions block as served: a freshly allocated
// slice — the fixture is handed out as a shallow copy, so the configured entries
// are never rewritten in place — carrying the live callback status of every entry
// still due for delivery. An entry keeps reappearing on every pull until the node
// drives it to a terminal status through the callback, at which point it drains
// out of the block; an entry whose expires_at is not in the future is no longer
// served, and an entry carrying no expires_at at all is therefore never served.
// The result is never nil, so the block serializes as [] rather than null.
func (s *Server) projectExecutions(configured []api.NodeStateExecution) []api.NodeStateExecution {
	s.execMu.Lock()
	defer s.execMu.Unlock()

	now := time.Now()
	served := make([]api.NodeStateExecution, 0, len(configured))
	for _, exec := range configured {
		if !exec.ExpiresAt.After(now) {
			continue
		}
		if live, tracked := s.execStates[exec.ExecutionID]; tracked {
			if terminalExecStatus(live) {
				continue
			}
			exec.Status = live
		}
		served = append(served, exec)
	}
	return served
}

// projectSessions returns the sessions block as served: a freshly allocated
// slice — the fixture is handed out as a shallow copy, so the configured entries
// are never rewritten in place — carrying every entry whose expires_at is still
// in the future. The block is desired state, so a live entry is redelivered on
// every pull; hard expiry drains it out, and an entry carrying no expires_at at
// all is therefore never served. Revocation is a re-posted fixture without the
// entry. Unlike executions there is no status projection — sessions have no
// callback state machine — so no lock is taken: the fixture copy is already read
// under the fixture lock in GetState and this only filters its argument. The
// result is never nil, so the block serializes as [] rather than null.
func (s *Server) projectSessions(configured []api.NodeStateSession) []api.NodeStateSession {
	now := time.Now()
	served := make([]api.NodeStateSession, 0, len(configured))
	for _, session := range configured {
		if !session.ExpiresAt.After(now) {
			continue
		}
		served = append(served, session)
	}
	return served
}

// handleEvents handles GET /v1/nodes/{id}/events (REQ-006), the pull-only signed
// event stream. It tails from now unless a Last-Event-ID cursor asks to replay
// the buffered envelopes with a higher sequence, keeps the stream live until the
// client disconnects, and honours the descope contract: when descoped it answers
// the spec's 501 without opening a stream. Every request is counted, including
// descoped and 400 answers.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.eventsRequestCount.Add(1)

	// A descoped control plane answers the spec's 501 without opening a stream,
	// ahead of any cursor parsing.
	if s.descoped() {
		writeProblem(w, r, http.StatusNotImplemented, "signed_event_bus_not_provisioned", "signed event bus not provisioned")
		return
	}

	// Parse the Last-Event-ID cursor. An empty or absent header tails from now; a
	// parseable non-negative integer replays the buffered envelopes above it;
	// anything else is a 400 with no stream.
	var cursor uint64
	hasCursor := false
	if raw := r.Header.Get("Last-Event-ID"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			writeProblem(w, r, http.StatusBadRequest, "invalid_cursor", "Last-Event-ID must be a non-negative integer")
			return
		}
		cursor = uint64(n)
		hasCursor = true
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	// Snapshot the replay set and register this client under one lock acquisition
	// so no broadcast can slip between replay and live delivery. Re-check the mode
	// here so a descope that races the request never leaves a stream open.
	s.eventsMu.Lock()
	if s.eventsMode == eventsModeDescoped {
		s.eventsMu.Unlock()
		writeProblem(w, r, http.StatusNotImplemented, "signed_event_bus_not_provisioned", "signed event bus not provisioned")
		return
	}
	var replay []storedEvent
	if hasCursor {
		for _, ev := range s.eventRing {
			if ev.seq > cursor {
				replay = append(replay, ev)
			}
		}
	}
	s.eventClientID++
	clientID := s.eventClientID
	client := &sseClient{ch: make(chan storedEvent, eventRingCap), done: make(chan struct{})}
	s.eventClients[clientID] = client
	s.eventsMu.Unlock()

	defer func() {
		s.eventsMu.Lock()
		delete(s.eventClients, clientID)
		s.eventsMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Plexsphere-API-Version", mockAPIVersion)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	for _, ev := range replay {
		writeSSEEvent(w, ev)
	}
	flusher.Flush()

	// Keep-alive comments at KeepAliveInterval; live envelopes on the client
	// channel; the stream ends on client disconnect or a descope flip.
	ticker := time.NewTicker(s.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-client.done:
			return
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev := <-client.ch:
			writeSSEEvent(w, ev)
			flusher.Flush()
		}
	}
}

// writeSSEEvent writes one storedEvent as an SSE frame: an id line carrying the
// stream sequence, the event type, the marshaled envelope across data lines, and
// a terminating blank line. A marshal failure is logged and the frame skipped.
func writeSSEEvent(w io.Writer, ev storedEvent) {
	data, err := json.Marshal(ev.env)
	if err != nil {
		slog.Error("writeSSEEvent: marshal failed", "error", err)
		return
	}
	fmt.Fprintf(w, "id: %d\n", ev.seq)
	fmt.Fprintf(w, "event: %s\n", ev.env.Type)
	// Split data across SSE data lines if it contains newlines (it won't for
	// compact JSON, but be safe).
	for _, line := range strings.Split(string(data), "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
}

// handleAssertions handles GET /test/assertions (REQ-007).
func (s *Server) handleAssertions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Assertions())
}

// handleKeyRotate handles POST /v1/keys/rotate. It models the v1 rotation
// receipt contract (issue #21): the control plane arms a pending rotation, the
// node submits its fresh public key, and the mock answers a receipt (or replays
// the stored receipt on an idempotent retry). The key_rotate counter advances
// only on a completing rotation — the same precedent as handleEndpoint.
func (s *Server) handleKeyRotate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	data, err := s.captureBody("key_rotate", r)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, r, http.StatusRequestEntityTooLarge, "keys_rotate_body_too_large", "keys/rotate body exceeds 4 KiB")
			return
		}
		writeProblem(w, r, http.StatusBadRequest, "malformed_keys_rotate_request", "invalid request body")
		return
	}

	var req api.KeyRotateRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_keys_rotate_request", "keys/rotate body is malformed")
		return
	}

	// Shape: a 44-char standard-base64 X25519 key that is not the zero key.
	raw, decErr := base64.StdEncoding.DecodeString(req.NewPublicKey)
	if !pubKeyRe.MatchString(req.NewPublicKey) || decErr != nil || isAllZero(raw) {
		writeProblem(w, r, http.StatusUnprocessableEntity, "keys_rotate_public_key_invalid", "new_public_key must be a non-zero 44-char standard base64 X25519 key")
		return
	}

	s.keyRotationMu.Lock()
	defer s.keyRotationMu.Unlock()

	switch {
	case req.NewPublicKey == s.nodePublicKey && req.NewPublicKey == s.lastRotatedKey && s.lastRotationReceipt != nil:
		// Idempotent retry: replay the stored receipt without moving the counter.
		writeJSON(w, http.StatusOK, *s.lastRotationReceipt)
	case req.NewPublicKey == s.nodePublicKey:
		writeProblem(w, r, http.StatusUnprocessableEntity, "keys_rotate_public_key_unchanged", "new_public_key matches the node's current public key")
	case !s.rotationArmed:
		writeProblem(w, r, http.StatusConflict, "keys_rotate_no_pending_rotation", "no pending rotation is armed for this node")
	default:
		s.rotationCount++
		receipt := api.KeyRotateResponse{
			RotationID:     fmt.Sprintf("e2e-rotation-%04d", s.rotationCount),
			KID:            "did:web:plexsphere.com#psk-2026-04",
			WrapKeyVersion: s.rotationCount,
		}
		s.nodePublicKey = req.NewPublicKey
		s.lastRotatedKey = req.NewPublicKey
		s.lastRotationReceipt = &receipt
		s.rotationArmed = false
		s.keyRotateCount.Add(1)
		writeJSON(w, http.StatusOK, receipt)
	}
}

// handleCapabilities handles PUT /v1/nodes/{id}/capabilities, the capability
// manifest. It strict-decodes the contract's envelope and enforces its
// invariants: a non-empty binary_version, a binary_checksum that decodes to
// exactly 32 bytes, a canonical ssh_host_key_fingerprint when present, and
// declared_hooks that are unique, named, and carry a 32-byte digest.
//
// Strictness is the point. The fixture used to decode into whatever shape the
// agent happened to send and count it, so a manifest the real handler refuses
// — the wrong envelope, a hex checksum, or a gzip-encoded body — passed here
// and the capability report was silently dead on every deployed node.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	data, err := s.captureBody("capabilities", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_capabilities_request", "invalid request body")
		return
	}

	var req api.CapabilityManifestRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_capabilities_request",
			"request body is not a valid CapabilityManifestRequest envelope: "+err.Error())
		return
	}

	if strings.TrimSpace(req.BinaryVersion) == "" {
		writeProblem(w, r, http.StatusBadRequest, "binary_version_empty", "binary_version is required")
		return
	}
	if !isBase64Digest(req.BinaryChecksum) {
		writeProblem(w, r, http.StatusBadRequest, "binary_checksum_invalid",
			"binary_checksum must be 32 bytes, standard-padded base64")
		return
	}
	if req.SSHHostKeyFingerprint != "" && !sshFingerprintRe.MatchString(req.SSHHostKeyFingerprint) {
		writeProblem(w, r, http.StatusBadRequest, "ssh_host_key_fingerprint_invalid",
			"ssh_host_key_fingerprint must match SHA256:<base64>")
		return
	}
	if len(req.DeclaredHooks) > maxDeclaredHooks {
		writeProblem(w, r, http.StatusBadRequest, "declared_hooks_too_many",
			fmt.Sprintf("declared_hooks carries %d entries, at most %d are accepted", len(req.DeclaredHooks), maxDeclaredHooks))
		return
	}
	seen := make(map[string]struct{}, len(req.DeclaredHooks))
	for _, h := range req.DeclaredHooks {
		if strings.TrimSpace(h.Name) == "" || !isBase64Digest(h.Checksum) {
			writeProblem(w, r, http.StatusBadRequest, "declared_hook_invalid",
				"each declared hook needs a name and a 32-byte base64 checksum")
			return
		}
		if _, dup := seen[h.Name]; dup {
			writeProblem(w, r, http.StatusBadRequest, "declared_hook_duplicate",
				"declared_hooks names must be unique: "+h.Name)
			return
		}
		seen[h.Name] = struct{}{}
	}

	s.capabilitiesCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// maxDeclaredHooks is the manifest's per-request declared_hooks ceiling.
const maxDeclaredHooks = 128

// isBase64Digest reports whether v is a SHA-256 digest in the wire form the
// manifest carries: exactly 32 bytes, standard-padded base64. Hex is refused —
// it decodes as base64 to 48 bytes, which is the shape that made this check
// worth having.
func isBase64Digest(v string) bool {
	raw, err := base64.StdEncoding.DecodeString(v)
	return err == nil && len(raw) == sha256.Size
}

// handleEndpoint handles PUT /v1/nodes/{id}/endpoint. It enforces the v1
// endpoint contract: a 4 KiB body cap, strict decoding, a closed nat_type enum,
// clock-skew tolerance, and a routable ip:port. The counter increments only
// when every check passes.
func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	data, err := s.captureBody("endpoint", r)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, r, http.StatusRequestEntityTooLarge, "endpoint_body_too_large", "endpoint body exceeds 4 KiB")
			return
		}
		writeProblem(w, r, http.StatusBadRequest, "malformed_endpoint_request", "invalid request body")
		return
	}

	var req api.EndpointRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_endpoint_request", "endpoint body is malformed")
		return
	}

	if !validNATType(req.NATType) {
		writeProblem(w, r, http.StatusBadRequest, "malformed_endpoint_request", "nat_type is outside the accepted enum")
		return
	}

	// Clock skew: reported_at must be within 60s of server time either way.
	if skew := time.Since(req.ReportedAt); skew > 60*time.Second || skew < -60*time.Second {
		writeProblem(w, r, http.StatusBadRequest, "endpoint_clock_skew", "reported_at is outside the accepted tolerance")
		return
	}

	if !routableEndpoint(req.Endpoint) {
		writeProblem(w, r, http.StatusBadRequest, "endpoint_unparseable", "endpoint must be a routable ip:port")
		return
	}

	s.endpointCount.Add(1)

	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, api.EndpointResponse{
		AcceptedAt: now,
		StaleAfter: now.Add(s.getEndpointTTL()),
	})
}

// handleSecrets handles GET /v1/nodes/{id}/secrets/{key}. It validates the key
// against secretKeyRe, honours an optional ?version=N selector bounded by the
// current version, and serves the raw AES-256-GCM envelope as an octet-stream
// body with the version and KID in response headers.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !secretKeyRe.MatchString(key) {
		writeProblem(w, r, http.StatusNotFound, "secret_not_found", "no secret exists for this key")
		return
	}

	// Parse an optional ?version selector. Its grammar is validated before the
	// rate-limit gate, so a malformed selector is always a 400 rather than a 429.
	version := s.secretCurrentVersion.Load()
	var requested int64
	if raw := r.URL.Query().Get("version"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			writeProblem(w, r, http.StatusBadRequest, "invalid_version", "version must be a positive integer")
			return
		}
		requested = int64(v)
	}

	// Armed rate limiting: exactly the next secretRateLimitNext fetches answer a
	// 429. The CompareAndSwap decrement keeps the "exactly N" guarantee under
	// concurrent fetches — two racing goroutines can never both claim the same
	// remaining unit. Retry-After is set before writeProblem writes the status.
	for {
		n := s.secretRateLimitNext.Load()
		if n <= 0 {
			break
		}
		if s.secretRateLimitNext.CompareAndSwap(n, n-1) {
			s.secretsRateLimitedCount.Add(1)
			w.Header().Set("Retry-After", strconv.FormatInt(s.secretRetryAfterSeconds.Load(), 10))
			writeProblem(w, r, http.StatusTooManyRequests, "per_node_rate_limited", "per-node secret fetch rate limit exceeded")
			return
		}
	}

	if requested > 0 {
		if requested > s.secretCurrentVersion.Load() {
			writeProblem(w, r, http.StatusNotFound, "secret_version_not_found", "no such secret version")
			return
		}
		version = requested
	}

	envelope := encryptSecret(s.nsk, s.expectedBearerToken)
	s.secretsCount.Add(1)
	w.Header().Set("X-Plexsphere-Secret-Version", strconv.FormatInt(version, 10))
	w.Header().Set("X-Plexsphere-Secret-KID", mockSecretKID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(envelope); err != nil {
		slog.Error("handleSecrets: write failed", "error", err)
	}
}

// mockSecretKID is the fixture key id served in the X-Plexsphere-Secret-KID
// header of every secret envelope.
const mockSecretKID = "e2e-nsk-kid-1"

// secretKeyRe is a mock-local copy of the control-plane secret name grammar.
// A name outside it is a 404 secret_not_found.
var secretKeyRe = regexp.MustCompile("^[a-z][a-z0-9_-]{0,62}$")

// reportKeyRe is a mock-local copy of the control-plane per-key report grammar:
// a lowercase-leading key of 1..128 chars over [a-z0-9._-]. A key outside it is
// a 400 invalid_report.
var reportKeyRe = regexp.MustCompile("^[a-z][a-z0-9._-]{0,127}$")

// handlePutStateReport handles PUT /v1/nodes/{id}/state/reports/{key}. It
// validates the key against reportKeyRe, strict-decodes the per-key wire body,
// caps the value at 4 KiB, and upserts the entry into both mirrored reports
// buckets. Success is a 200 acknowledgement.
func (s *Server) handlePutStateReport(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !reportKeyRe.MatchString(key) {
		writeProblem(w, r, http.StatusBadRequest, "invalid_report", "report key is outside the accepted grammar")
		return
	}

	data, err := s.captureBody("report", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "invalid_report", "invalid request body")
		return
	}
	var req api.NodeStateReportRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "invalid_report", "report body is malformed")
		return
	}
	if len(req.Value) > 4096 {
		writeProblem(w, r, http.StatusBadRequest, "invalid_report", "report value exceeds the 4096-byte ceiling")
		return
	}

	s.upsertReport(api.StateEntry{Key: key, Value: req.Value, WorkloadTag: req.WorkloadTag})
	s.reportPutCount.Add(1)
	writeJSON(w, http.StatusOK, api.NodeStateReportResponse{AcceptedAt: time.Now().UTC(), Key: key})
}

// handleDeleteStateReport handles DELETE /v1/nodes/{id}/state/reports/{key}. It
// validates the key, removes the entry from both mirrored reports buckets, and
// responds 204; a key with no stored report is a 404 report_not_found.
func (s *Server) handleDeleteStateReport(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !reportKeyRe.MatchString(key) {
		writeProblem(w, r, http.StatusBadRequest, "invalid_report", "report key is outside the accepted grammar")
		return
	}
	if !s.deleteReport(key) {
		writeProblem(w, r, http.StatusNotFound, "report_not_found", "no report exists for this key")
		return
	}
	s.reportDeleteCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// upsertReport inserts or replaces entry in both mirrored reports buckets
// (State.Reports and Reports.Reports) of the stored fixture, keeping each bucket
// sorted by key ascending. Report writes are copy-on-write — each mutated block
// is rebuilt behind a fresh pointer — so a concurrent state read (which aliases
// the previous block through GetState) never observes a half-written slice.
func (s *Server) upsertReport(entry api.StateEntry) {
	s.stateFixtureMu.Lock()
	defer s.stateFixtureMu.Unlock()
	s.stateFixture.State = upsertReportBlock(s.stateFixture.State, entry)
	s.stateFixture.Reports = upsertReportBlock(s.stateFixture.Reports, entry)
}

// upsertReportBlock returns a copy of block with entry upserted into a freshly
// allocated, key-ascending reports bucket. A nil block is initialized.
func upsertReportBlock(block *api.NodeStateBlock, entry api.StateEntry) *api.NodeStateBlock {
	nb := api.NodeStateBlock{Metadata: []api.StateEntry{}, Data: []api.StateEntry{}, Reports: []api.StateEntry{}}
	if block != nil {
		nb = *block
	}
	reports := make([]api.StateEntry, 0, len(nb.Reports)+1)
	replaced := false
	for _, e := range nb.Reports {
		if e.Key == entry.Key {
			reports = append(reports, entry)
			replaced = true
			continue
		}
		reports = append(reports, e)
	}
	if !replaced {
		reports = append(reports, entry)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Key < reports[j].Key })
	nb.Reports = reports
	return &nb
}

// deleteReport removes the entry under key from both mirrored reports buckets of
// the stored fixture, copy-on-write. It reports whether a matching entry existed.
func (s *Server) deleteReport(key string) bool {
	s.stateFixtureMu.Lock()
	defer s.stateFixtureMu.Unlock()
	newState, foundState := deleteReportBlock(s.stateFixture.State, key)
	newReports, foundReports := deleteReportBlock(s.stateFixture.Reports, key)
	if !foundState && !foundReports {
		return false
	}
	s.stateFixture.State = newState
	s.stateFixture.Reports = newReports
	return true
}

// deleteReportBlock returns a copy of block with the entry under key removed from
// a freshly allocated reports bucket, plus whether it existed. A nil block is
// returned unchanged.
func deleteReportBlock(block *api.NodeStateBlock, key string) (*api.NodeStateBlock, bool) {
	if block == nil {
		return block, false
	}
	nb := *block
	reports := make([]api.StateEntry, 0, len(nb.Reports))
	found := false
	for _, e := range nb.Reports {
		if e.Key == key {
			found = true
			continue
		}
		reports = append(reports, e)
	}
	nb.Reports = reports
	return &nb, found
}

// execUpload records a one-time presigned output upload minted by a declaring
// execution callback. key is the object key ("exec-output/{eid}"), declared is
// the byte ceiling the PUT accepts, received flips once the bytes land, and
// data holds the uploaded bytes for the terminal callback's sha256 check.
type execUpload struct {
	key      string
	declared int64
	received bool
	data     []byte
}

// nodeReportableStatus reports whether status is one of the five statuses a node
// may report on an execution callback.
func nodeReportableStatus(status string) bool {
	switch status {
	case api.ExecutionStatusAck, api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded, api.ExecutionStatusFailed, api.ExecutionStatusCancelled:
		return true
	default:
		return false
	}
}

// terminalExecStatus reports whether status is a terminal execution status.
func terminalExecStatus(status string) bool {
	switch status {
	case api.ExecutionStatusSucceeded, api.ExecutionStatusFailed, api.ExecutionStatusCancelled:
		return true
	default:
		return false
	}
}

// legalExecTransition reports whether advancing an execution from its current
// state (cur, with exists=false when the id has never been seen) to next is a
// legal non-terminal transition. Terminal current states are rejected by the
// caller before this is reached. The roster is closed and mirrors the control
// plane: an unseen id accepts only ack, ack advances only to started, and a
// terminal status is reachable only from started — ack→failed and ack→cancelled
// are refused. A started→started self-repeat is legal only when the callback
// declares an output size, which the node knows only once the run has finished.
func legalExecTransition(cur string, exists bool, next string, declaredBytes int64) bool {
	if !exists {
		return next == api.ExecutionStatusAck
	}
	switch cur {
	case api.ExecutionStatusAck:
		return next == api.ExecutionStatusStarted
	case api.ExecutionStatusStarted:
		switch next {
		case api.ExecutionStatusSucceeded, api.ExecutionStatusFailed, api.ExecutionStatusCancelled:
			return true
		case api.ExecutionStatusStarted:
			return declaredBytes > 0
		}
	}
	return false
}

// handleExecutionCallback handles POST /v1/nodes/{id}/executions/{eid}, the v1
// execution status callback. It enforces the node-id guard, a 64 KiB body cap,
// strict decoding to the five node-reportable statuses, the 16 KiB inline
// output ceiling, and the execution state machine — ack, then started, then one
// terminal status — with its 409 taxonomy (execution_already_terminal for a
// callback past a terminal state, invalid_state_transition for any other
// illegal jump, including a terminal that skips started). A started callback that
// declares an over-ceiling output mints a one-time presigned upload URL; a
// terminal callback carrying an object_key is verified against the uploaded
// bytes. Every 200 carries the new status so the client can decode the body.
func (s *Server) handleExecutionCallback(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != mockNodeID {
		writeProblem(w, r, http.StatusForbidden, "nsk_node_mismatch", "node id does not match this node's identity")
		return
	}
	eid := r.PathValue("eid")

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	data, err := s.captureBody("execution_callback", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_execution_callback", "invalid request body")
		return
	}

	var req api.ExecutionCallbackRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_execution_callback", "execution callback body is malformed")
		return
	}
	if !nodeReportableStatus(req.Status) {
		writeProblem(w, r, http.StatusBadRequest, "malformed_execution_callback", "status is outside the node-reportable set")
		return
	}

	// Inline output must base64-decode and stay within the 16 KiB ceiling. This
	// precedes the state machine: an over-ceiling inline is a 413 regardless of
	// whether the transition would otherwise be legal.
	if req.Output != nil && req.Output.Inline != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(req.Output.Inline)
		if decErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "malformed_execution_callback", "inline output is not valid base64")
			return
		}
		if len(decoded) > 16384 {
			writeProblem(w, r, http.StatusRequestEntityTooLarge, "inline_output_too_large", "inline output exceeds the 16 KiB ceiling")
			return
		}
	}

	s.execMu.Lock()
	defer s.execMu.Unlock()

	cur, exists := s.execStates[eid]
	if exists && terminalExecStatus(cur) {
		writeProblem(w, r, http.StatusConflict, "execution_already_terminal", "execution has already reached a terminal state")
		return
	}
	if !legalExecTransition(cur, exists, req.Status, req.DeclaredOutputBytes) {
		writeProblem(w, r, http.StatusConflict, "invalid_state_transition", "illegal execution state transition")
		return
	}

	resp := api.ExecutionCallbackResponse{Status: req.Status}
	switch {
	case req.Status == api.ExecutionStatusStarted && req.DeclaredOutputBytes > 0:
		// Declaring callback: mint a one-time presigned upload. The URL path is
		// the object key, which the node echoes back on the terminal callback.
		s.execTokenCounter++
		token := fmt.Sprintf("exec-upload-%04d", s.execTokenCounter)
		s.execUploads[token] = &execUpload{key: "exec-output/" + eid, declared: req.DeclaredOutputBytes}
		resp.OutputUploadURL = "http://" + r.Host + "/exec-output/" + eid + "?token=" + token
	case req.Output != nil && req.Output.ObjectKey != "":
		// Terminal callback referencing an uploaded output: the upload must exist,
		// have been received, and hash to the declared sha256.
		up := s.findExecUpload(req.Output.ObjectKey)
		if up == nil || !up.received {
			writeProblem(w, r, http.StatusBadRequest, "malformed_execution_callback", "output object_key does not match a received upload")
			return
		}
		sum := sha256.Sum256(up.data)
		if hex.EncodeToString(sum[:]) != req.Output.SHA256 {
			writeProblem(w, r, http.StatusBadRequest, "malformed_execution_callback", "output sha256 does not match the uploaded bytes")
			return
		}
	}

	s.execStates[eid] = req.Status
	s.executionCallbackCount.Add(1)
	writeJSON(w, http.StatusOK, resp)
}

// findExecUpload returns the pending upload whose object key matches key, or nil.
// Callers must hold execMu.
func (s *Server) findExecUpload(key string) *execUpload {
	for _, up := range s.execUploads {
		if up.key == key {
			return up
		}
	}
	return nil
}

// handleExecOutputUpload handles PUT /exec-output/{eid}, the one-time presigned
// output upload minted by a declaring execution callback. The token identifies
// the upload; its recorded key must match the path, it must be unused, and the
// body must fit within the declared size.
func (s *Server) handleExecOutputUpload(w http.ResponseWriter, r *http.Request) {
	eid := r.PathValue("eid")
	token := r.URL.Query().Get("token")

	s.execMu.Lock()
	up, ok := s.execUploads[token]
	if !ok || up.key != "exec-output/"+eid {
		s.execMu.Unlock()
		writeProblem(w, r, http.StatusNotFound, "", "no presigned upload for this token")
		return
	}
	if up.received {
		s.execMu.Unlock()
		writeProblem(w, r, http.StatusConflict, "", "presigned upload URL has already been used")
		return
	}
	declared := up.declared
	s.execMu.Unlock()

	r.Body = http.MaxBytesReader(w, r.Body, declared)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, r, http.StatusRequestEntityTooLarge, "", "upload body exceeds the declared size")
			return
		}
		writeProblem(w, r, http.StatusBadRequest, "", "invalid upload body")
		return
	}

	s.execMu.Lock()
	up.data = data
	up.received = true
	s.execMu.Unlock()

	s.executionUploadCount.Add(1)
	w.WriteHeader(http.StatusOK)
}

// ingestEncodingSupported reports whether enc is a Content-Encoding the platform
// ingest endpoints accept: empty, identity, or gzip.
func ingestEncodingSupported(enc string) bool {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity", "gzip":
		return true
	default:
		return false
	}
}

// checkIngestGates enforces the two header gates shared by the metrics, logs,
// and audit ingest endpoints, in order: a supported Content-Encoding (else 415
// ingest_encoding_unsupported) and a present, RFC 3339 X-Plexsphere-Sent-At
// (else 400 ingest_sent_at_invalid). It writes the problem response and returns
// false on the first failing gate.
func (s *Server) checkIngestGates(w http.ResponseWriter, r *http.Request) bool {
	if !ingestEncodingSupported(r.Header.Get("Content-Encoding")) {
		writeProblem(w, r, http.StatusUnsupportedMediaType, "ingest_encoding_unsupported", "Content-Encoding is not supported")
		return false
	}
	sentAt := r.Header.Get("X-Plexsphere-Sent-At")
	if sentAt == "" {
		writeProblem(w, r, http.StatusBadRequest, "ingest_sent_at_invalid", "X-Plexsphere-Sent-At is required")
		return false
	}
	if _, err := time.Parse(time.RFC3339, sentAt); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ingest_sent_at_invalid", "X-Plexsphere-Sent-At is not an RFC 3339 timestamp")
		return false
	}
	return true
}

// wireMetricGroup reports whether g is inside the closed metric-group enum.
func wireMetricGroup(g string) bool {
	switch g {
	case api.MetricGroupNodeResources, api.MetricGroupTunnelHealth,
		api.MetricGroupPeerLatency, api.MetricGroupAgentStats:
		return true
	default:
		return false
	}
}

// validLogSeverity reports whether sev is inside the closed log-severity enum.
func validLogSeverity(sev string) bool {
	switch sev {
	case "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug":
		return true
	default:
		return false
	}
}

// validAuditSource reports whether src is inside the closed audit-source enum.
// validAuditSource reports whether src is in the audit ingest contract's closed
// set. The set is exactly `auditd` and `k8s`; the fixture used to also admit
// `plexd`, which the contract has never defined, so a batch the real control
// plane refuses whole with 400 ingest_batch_malformed was accepted here.
func validAuditSource(src string) bool {
	switch src {
	case "auditd", "k8s":
		return true
	default:
		return false
	}
}

// handleMetrics handles POST /v1/nodes/{id}/metrics, the v1 metrics ingest. It
// enforces the shared ingest header gates, strict-decodes a non-empty JSON array
// of api.MetricSample, and validates each record's group, name, and timestamp.
// Success is a 202 ingest receipt whose records field is the batch length.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.checkIngestGates(w, r) {
		return
	}
	data, err := s.captureBody("metrics", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "invalid request body")
		return
	}

	var batch []api.MetricSample
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil || len(batch) == 0 {
		writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "metrics batch is malformed or empty")
		return
	}
	for _, m := range batch {
		if !wireMetricGroup(m.Group) || m.Name == "" || m.Timestamp.IsZero() {
			writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "metrics batch has an invalid record")
			return
		}
	}

	s.metricsCount.Add(1)
	writeJSON(w, http.StatusAccepted, api.IngestReceipt{AcceptedAt: time.Now().UTC(), Records: len(batch)})
}

// handleLogs handles POST /v1/nodes/{id}/logs, the v1 logs ingest. It enforces
// the shared ingest header gates, splits the NDJSON body on newlines skipping
// blank lines, strict-decodes each line into api.LogLine, and validates the
// severity, message, and timestamp. A batch with no non-blank lines is
// malformed. Success is a 202 receipt whose records field is the line count.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !s.checkIngestGates(w, r) {
		return
	}
	data, err := s.captureBody("logs", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "invalid request body")
		return
	}

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec api.LogLine
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "logs batch has an undecodable line")
			return
		}
		if !validLogSeverity(rec.Severity) || rec.Message == "" || rec.Timestamp.IsZero() {
			writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "logs batch has an invalid record")
			return
		}
		count++
	}
	if count == 0 {
		writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "logs batch is empty")
		return
	}

	s.logsCount.Add(1)
	writeJSON(w, http.StatusAccepted, api.IngestReceipt{AcceptedAt: time.Now().UTC(), Records: count})
}

// handleAudit handles POST /v1/nodes/{id}/audit, the v1 audit ingest. It mirrors
// handleLogs: shared header gates, NDJSON split skipping blank lines, strict
// decode into api.AuditEvent, and validation of the source, action, outcome, and
// timestamp. Success is a 202 receipt whose records field is the line count.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.checkIngestGates(w, r) {
		return
	}
	data, err := s.captureBody("audit", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "invalid request body")
		return
	}

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec api.AuditEvent
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "audit batch has an undecodable line")
			return
		}
		if !validAuditSource(rec.Source) || rec.Action == "" || rec.Outcome == "" || rec.Timestamp.IsZero() {
			writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "audit batch has an invalid record")
			return
		}
		count++
	}
	if count == 0 {
		writeProblem(w, r, http.StatusBadRequest, "ingest_batch_malformed", "audit batch is empty")
		return
	}

	s.auditCount.Add(1)
	writeJSON(w, http.StatusAccepted, api.IngestReceipt{AcceptedAt: time.Now().UTC(), Records: count})
}

// handleReleases handles GET /releases/{tag}/{asset}, playing the GitHub release
// channel the upgrade fetcher pulls from. Asset matching is arch-agnostic (CI
// runs amd64, Docker Desktop arm64): the asset must be plexd-linux-<arch> (the
// binary) or plexd-linux-<arch>.sigstore.json (the Sigstore bundle); anything
// else is a 404. Tag v9.9.9 serves the valid fixture bundle so verification
// succeeds; v9.9.8 serves a garbage non-JSON bundle so bundle parsing fails
// downstream; any other tag is a 404.
func (s *Server) handleReleases(w http.ResponseWriter, r *http.Request) {
	asset := r.PathValue("asset")
	if !strings.HasPrefix(asset, "plexd-linux-") {
		http.NotFound(w, r)
		return
	}
	isBundle := strings.HasSuffix(asset, ".sigstore.json")

	switch r.PathValue("tag") {
	case "v9.9.9":
		if isBundle {
			writeReleaseFixture(w, "testdata/fixture.sigstore.json", "application/json")
			return
		}
		writeReleaseFixture(w, "testdata/fixture.bin", "application/octet-stream")
	case "v9.9.8":
		if isBundle {
			// A garbage non-JSON bundle so the downstream Sigstore parse fails.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("garbage not a bundle")); err != nil {
				slog.Error("handleReleases: write failed", "error", err)
			}
			return
		}
		writeReleaseFixture(w, "testdata/fixture.bin", "application/octet-stream")
	default:
		http.NotFound(w, r)
	}
}

// writeReleaseFixture serves an embedded release fixture with the given
// Content-Type. A read failure can only mean the embed directive drifted from
// the testdata files, so it is a 500.
func writeReleaseFixture(w http.ResponseWriter, name, contentType string) {
	data, err := releaseFixtures.ReadFile(name)
	if err != nil {
		slog.Error("handleReleases: read fixture failed", "name", name, "error", err)
		http.Error(w, "fixture unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		slog.Error("handleReleases: write failed", "error", err)
	}
}

// validTerminatedBy reports whether v is a recognized TCP termination reason.
func validTerminatedBy(v string) bool {
	switch v {
	case api.TerminatedByTTLExpired, api.TerminatedByIdleTimeout,
		api.TerminatedByPlexdClose, api.TerminatedByOperatorRevoke:
		return true
	default:
		return false
	}
}

// validSessionActivity reports whether req carries exactly one of ssh/k8s/tcp
// and that member satisfies its per-kind rules.
func validSessionActivity(req api.SessionActivityRequest) bool {
	set := 0
	if req.SSH != nil {
		set++
	}
	if req.K8s != nil {
		set++
	}
	if req.TCP != nil {
		set++
	}
	if set != 1 {
		return false
	}

	switch {
	case req.SSH != nil:
		return req.SSH.Command != "" && len(req.SSH.Command) <= 1024
	case req.K8s != nil:
		return req.K8s.Verb != ""
	default:
		if req.TCP.Phase != api.TCPPhaseSessionStarted && req.TCP.Phase != api.TCPPhaseSessionEnded {
			return false
		}
		if req.TCP.TerminatedBy != "" && !validTerminatedBy(req.TCP.TerminatedBy) {
			return false
		}
		return true
	}
}

// handleSessionActivity handles POST /v1/nodes/{id}/sessions/{sid}, the v1
// session activity record. It enforces the node-id guard, a 16 KiB body cap,
// strict decoding, and the one-of ssh/k8s/tcp contract with per-kind
// validation. Success is 204 No Content.
func (s *Server) handleSessionActivity(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != mockNodeID {
		writeProblem(w, r, http.StatusForbidden, "nsk_node_mismatch", "node id does not match this node's identity")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	data, err := s.captureBody("session_activity", r)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_session_activity", "invalid request body")
		return
	}

	var req api.SessionActivityRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_session_activity", "session activity body is malformed")
		return
	}
	if !validSessionActivity(req) {
		writeProblem(w, r, http.StatusBadRequest, "malformed_session_activity", "session activity violates the one-of contract")
		return
	}

	s.sessionActivityCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleIntegrityViolations handles POST /v1/nodes/{id}/integrity-violations. It
// strict-decodes the contract's batch envelope and enforces the invariants the
// real handler runs every entry through: a 1-to-128 entry batch, closed kind and
// detected_by enums, a non-empty artifact_id, 32-byte base64 digests for the two
// checksum kinds, canonical fingerprints for the host-key kind, and the per-kind
// guard that refuses a checksum entry carrying a fingerprint or the reverse.
//
// Strictness is the point, as it is for the capability manifest. The fixture
// used to register the agent's own route and decode the agent's own shape, so
// the agent's reports agreed with the fixture and with nothing else: the real
// endpoint had never seen one. A violation never fires during an e2e run, so
// this handler is the only place the divergence can be caught.
func (s *Server) handleIntegrityViolations(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxIntegrityViolationsBody)
	data, err := s.captureBody("integrity_violations", r)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, r, http.StatusRequestEntityTooLarge, "integrity_violations_body_too_large",
				"request body exceeds the 32768-byte integrity-violations envelope cap")
			return
		}
		writeProblem(w, r, http.StatusBadRequest, "malformed_integrity_violations_request", "invalid request body")
		return
	}

	var req api.IntegrityViolationsRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "malformed_integrity_violations_request",
			"request body is not a valid IntegrityViolationsRequest envelope: "+err.Error())
		return
	}

	if len(req.Violations) == 0 {
		writeProblem(w, r, http.StatusBadRequest, "integrity_violations_empty",
			"the violations array is empty")
		return
	}
	if len(req.Violations) > api.MaxIntegrityViolationsPerBatch {
		writeProblem(w, r, http.StatusBadRequest, "integrity_violations_too_many",
			fmt.Sprintf("the violations array carries %d entries, at most %d are accepted",
				len(req.Violations), api.MaxIntegrityViolationsPerBatch))
		return
	}
	for _, entry := range req.Violations {
		if code, detail := checkIntegrityViolation(entry); code != "" {
			writeProblem(w, r, http.StatusBadRequest, code, detail)
			return
		}
	}

	s.integrityViolationCount.Add(1)
	writeJSON(w, http.StatusOK, api.IntegrityViolationsResponse{
		AcceptedAt:     time.Now().UTC(),
		ViolationCount: len(req.Violations),
	})
}

// maxIntegrityViolationsBody is the contract's 32 KiB cap on the batch envelope.
const maxIntegrityViolationsBody = 32 * 1024

// checkIntegrityViolation validates one batch entry against the contract's
// per-violation invariants, returning the problem code and detail of the first
// one it breaks, or an empty code when the entry is valid.
func checkIntegrityViolation(v api.IntegrityViolationReport) (code, detail string) {
	switch v.Kind {
	case api.IntegrityKindBinaryChecksum, api.IntegrityKindHookChecksum, api.IntegrityKindSSHHostKey:
	default:
		return "integrity_violation_kind_invalid",
			fmt.Sprintf("kind %q is outside {binary_checksum, hook_checksum, ssh_host_key}", v.Kind)
	}

	switch v.DetectedBy {
	case api.IntegrityDetectorStartupScan, api.IntegrityDetectorInotify, api.IntegrityDetectorPreDispatch:
	default:
		return "integrity_violation_detected_by_invalid",
			fmt.Sprintf("detected_by %q is outside {startup_scan, inotify, pre_dispatch}", v.DetectedBy)
	}

	if strings.TrimSpace(v.ArtifactID) == "" {
		return "integrity_violation_artifact_id_empty", "artifact_id is empty or whitespace-only"
	}

	if v.Kind == api.IntegrityKindSSHHostKey {
		if v.ObservedChecksum != "" || v.ExpectedChecksum != "" {
			return "integrity_violation_kind_mismatch", "an ssh_host_key entry must not carry a checksum"
		}
		if !sshFingerprintRe.MatchString(v.ObservedFingerprint) {
			return "integrity_violation_host_key_fingerprint_invalid",
				"observed_fingerprint must match SHA256:<base64>"
		}
		if v.ExpectedFingerprint != "" && !sshFingerprintRe.MatchString(v.ExpectedFingerprint) {
			return "integrity_violation_host_key_fingerprint_invalid",
				"expected_fingerprint must match SHA256:<base64>"
		}
		return "", ""
	}

	if v.ObservedFingerprint != "" || v.ExpectedFingerprint != "" {
		return "integrity_violation_kind_mismatch", "a checksum entry must not carry a fingerprint"
	}
	if !isBase64Digest(v.ObservedChecksum) {
		return "integrity_violation_checksum_invalid",
			"observed_checksum must be 32 bytes, standard-padded base64"
	}
	if v.ExpectedChecksum != "" && !isBase64Digest(v.ExpectedChecksum) {
		return "integrity_violation_checksum_invalid",
			"expected_checksum must be 32 bytes, standard-padded base64"
	}
	return "", ""
}

// SetState updates the mutable state fixture returned by GET /v1/nodes/{id}/state
// and seeds the execution state machine from the configured executions block, so
// an entry configured mid-flight resumes on the callback roster: a configured
// ack or started status seeds that state, while pending seeds nothing and the
// first legal callback for it stays ack. Seeding is skip-if-present — a re-posted
// snapshot must never regress an execution the node has already advanced. The
// two locks are never held at once: execMu is taken only after stateFixtureMu is
// released.
func (s *Server) SetState(state api.NodeStateSnapshot) {
	s.stateFixtureMu.Lock()
	s.stateFixture = state
	s.stateFixtureMu.Unlock()

	s.execMu.Lock()
	defer s.execMu.Unlock()
	for _, exec := range state.Executions {
		if _, tracked := s.execStates[exec.ExecutionID]; tracked {
			continue
		}
		switch exec.Status {
		case api.ExecutionStatusAck, api.ExecutionStatusStarted:
			s.execStates[exec.ExecutionID] = exec.Status
		}
	}
}

// GetState returns the current state fixture with the peers, executions, and
// sessions slices normalized to non-nil so they always serialize as [] rather
// than null. The eight envelope blocks carry no omitempty, so all keys are
// emitted (null for unpopulated blocks).
//
// The result is a SHALLOW copy: the policy, bridge, state, and reports pointers
// and the peers, executions, and sessions backing arrays alias the live fixture.
// Reading is safe — SetState replaces the whole struct under the mutex, so no
// caller observes a half-written fixture — but callers must NOT mutate through
// the returned pointers or slices, which would race the state handler serving a
// concurrent request. Change the fixture with SetState instead.
func (s *Server) GetState() api.NodeStateSnapshot {
	s.stateFixtureMu.RLock()
	state := s.stateFixture
	s.stateFixtureMu.RUnlock()
	if state.Peers == nil {
		state.Peers = []api.SnapshotPeer{}
	}
	if state.Executions == nil {
		state.Executions = []api.NodeStateExecution{}
	}
	if state.Sessions == nil {
		state.Sessions = &[]api.NodeStateSession{}
	}
	return state
}

// handleSetState handles PUT /test/state and POST /test/configure-state.
// Decoding is strict: a misspelled or renamed key anywhere in the envelope is a
// 400, not a 204 that silently stores a zero-valued block. Without this, a typo
// in a caller's "policy" key would leave Policy nil while the caller believes it
// configured a fingerprint.
func (s *Server) handleSetState(w http.ResponseWriter, r *http.Request) {
	data, err := s.captureBody("configure_state", r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	var state api.NodeStateSnapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	s.SetState(state)
	w.WriteHeader(http.StatusNoContent)
}

// SetHeartbeatResponse updates the mutable heartbeat response fixture.
func (s *Server) SetHeartbeatResponse(resp api.HeartbeatResponse) {
	s.heartbeatFixtureMu.Lock()
	s.heartbeatFixture = resp
	s.heartbeatFixtureMu.Unlock()
}

// handleConfigureHeartbeat handles POST /test/configure-heartbeat.
func (s *Server) handleConfigureHeartbeat(w http.ResponseWriter, r *http.Request) {
	var resp api.HeartbeatResponse
	if !s.decodeBody(w, r, "configure_heartbeat", &resp) {
		return
	}
	s.SetHeartbeatResponse(resp)
	if resp.RotateKeys {
		s.keyRotationMu.Lock()
		s.rotationArmed = true
		s.keyRotationMu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetEndpointTTL updates the stale_after TTL applied by the endpoint handler.
func (s *Server) SetEndpointTTL(d time.Duration) {
	s.endpointTTLMu.Lock()
	s.endpointTTL = d
	s.endpointTTLMu.Unlock()
}

// getEndpointTTL returns the current stale_after TTL.
func (s *Server) getEndpointTTL() time.Duration {
	s.endpointTTLMu.RLock()
	defer s.endpointTTLMu.RUnlock()
	return s.endpointTTL
}

// handleConfigureEndpoint handles POST /test/configure-endpoint. It sets the
// endpoint stale_after TTL from {"ttl_seconds": N}; N must be positive.
func (s *Server) handleConfigureEndpoint(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	if !s.decodeBody(w, r, "configure_endpoint", &body) {
		return
	}
	if body.TTLSeconds <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl_seconds must be positive"})
		return
	}
	s.SetEndpointTTL(time.Duration(body.TTLSeconds) * time.Second)
	w.WriteHeader(http.StatusNoContent)
}

// handleConfigureSecrets handles POST /test/configure-secrets. It arms the
// secret handler's served version and rate-limit dials from an optional JSON
// body; each field is applied only when > 0, so a partial body leaves the
// other dials untouched. Decoding is strict: an unknown field is a 400.
func (s *Server) handleConfigureSecrets(w http.ResponseWriter, r *http.Request) {
	data, err := s.captureBody("configure_secrets", r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	var body struct {
		CurrentVersion    int64 `json:"current_version"`
		RateLimitNext     int64 `json:"rate_limit_next"`
		RetryAfterSeconds int64 `json:"retry_after_seconds"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.CurrentVersion > 0 {
		s.secretCurrentVersion.Store(body.CurrentVersion)
	}
	if body.RateLimitNext > 0 {
		s.secretRateLimitNext.Store(body.RateLimitNext)
	}
	if body.RetryAfterSeconds > 0 {
		s.secretRetryAfterSeconds.Store(body.RetryAfterSeconds)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleConfigureEvents handles POST /test/configure-events. It flips the event
// stream between "streaming" (default) and "descoped" from a strict {"mode":...}
// body. Descoping closes every open stream through its done channel and makes the
// events endpoint answer the spec's 501; streaming restores normal service.
// Decoding is strict and the mode is a closed enum: an unknown mode or malformed
// body is a 400.
func (s *Server) handleConfigureEvents(w http.ResponseWriter, r *http.Request) {
	data, err := s.captureBody("configure_events", r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.Mode != eventsModeStreaming && body.Mode != eventsModeDescoped {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be streaming or descoped"})
		return
	}

	s.eventsMu.Lock()
	s.eventsMode = body.Mode
	if body.Mode == eventsModeDescoped {
		for id, c := range s.eventClients {
			close(c.done)
			delete(s.eventClients, id)
		}
	}
	s.eventsMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// descoped reports whether the event stream is currently in descoped mode.
func (s *Server) descoped() bool {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	return s.eventsMode == eventsModeDescoped
}

// BroadcastSSE assigns the next stream sequence to the envelope, records it in
// the replay ring (dropping the oldest beyond eventRingCap), and fans it out to
// every connected client non-blocking. Recording happens even with zero clients
// and while descoped, so a later reconnect can replay from a cursor. A client
// whose channel is full is skipped to avoid blocking the broadcaster.
func (s *Server) BroadcastSSE(envelope api.Envelope) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

	s.eventSeq++
	ev := storedEvent{seq: s.eventSeq, env: envelope}
	if len(s.eventRing) < eventRingCap {
		s.eventRing = append(s.eventRing, ev)
	} else {
		copy(s.eventRing, s.eventRing[1:])
		s.eventRing[eventRingCap-1] = ev
	}

	for _, c := range s.eventClients {
		select {
		case c.ch <- ev:
		default:
			// Client channel full, skip to avoid blocking.
		}
	}
}

// handleInjectEvent handles POST /test/inject-event.
// It sets issued_at to the current time and computes a valid ed25519 signature
// so the agent's verifier accepts the event.
func (s *Server) handleInjectEvent(w http.ResponseWriter, r *http.Request) {
	var envelope api.Envelope
	if !s.decodeBody(w, r, "inject_event", &envelope) {
		return
	}
	if envelope.ID == "" || envelope.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id or type"})
		return
	}

	// Override timestamp and sign the envelope so it passes verification.
	envelope.IssuedAt = time.Now().UTC()
	s.signEnvelope(&envelope)

	// A rotate_keys event arms a pending rotation (issue #21).
	if envelope.Type == api.EventRotateKeys {
		s.keyRotationMu.Lock()
		s.rotationArmed = true
		s.keyRotationMu.Unlock()
	}

	s.injectEventCount.Add(1)
	s.BroadcastSSE(envelope)
	w.WriteHeader(http.StatusNoContent)
}

// signEnvelope stamps the mock's signing key id on the envelope and computes a
// valid ed25519 signature over the shared canonical form (api.CanonicalBytes)
// using the mock API's signing key.
func (s *Server) signEnvelope(envelope *api.Envelope) {
	envelope.KeyID = mockSigningKeyID
	canonical, err := api.CanonicalBytes(*envelope)
	if err != nil {
		panic("mockapi: marshal canonical envelope: " + err.Error())
	}
	sig := ed25519.Sign(s.signingPrivateKey, canonical)
	envelope.Signature = base64.StdEncoding.EncodeToString(sig)
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
// Local Endpoint Handlers (HTTPS :8443)
// ---------------------------------------------------------------------------

// encryptSecret seals plaintext with AES-256-GCM under the given NSK using a
// fresh random 12-byte nonce, returning the raw envelope
// nonce || ciphertext+tag exactly as the control-plane octet-stream body.
func encryptSecret(nsk []byte, plaintext string) []byte {
	block, err := aes.NewCipher(nsk)
	if err != nil {
		panic("mockapi: aes.NewCipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("mockapi: cipher.NewGCM: " + err.Error())
	}
	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		panic("mockapi: rand.Read nonce: " + err.Error())
	}
	return gcm.Seal(nonceBytes, nonceBytes, []byte(plaintext), nil)
}

// BearerEnvelope returns the credential every authenticated route admits, in
// the exact form a client must present it. The e2e scripts fetch it from
// GET /test/bearer so the fixture keeps one source of truth for the node id and
// the nsk, and the `<env>` segment is deliberately not the agent's `plexd`: the
// gate gets its authority from the payload, not from the tag.
func (s *Server) BearerEnvelope() string {
	return "nsk_e2e_" + base64.RawURLEncoding.EncodeToString(bearerPayload(s.nsk))
}

// bearerPayload is the 48 bytes an envelope carries: the node's UUID followed
// by the decoded node secret key.
func bearerPayload(nsk []byte) []byte {
	id, err := hex.DecodeString(strings.ReplaceAll(mockNodeID, "-", ""))
	if err != nil {
		panic("mockapi: decode mock node id: " + err.Error())
	}
	return append(id, nsk...)
}

// requiresBearer reports whether path is an authenticated control-plane route.
// POST /v1/register is `security: []` in the spec and GET /v1/health is the
// probe the compose healthcheck dials, so both are exempt; everything else
// under /v1 is a node route. The /test, /releases and /exec-output surfaces are
// fixture scaffolding and a presigned upload, none of which carry a bearer.
func requiresBearer(path string) bool {
	if !strings.HasPrefix(path, "/v1/") {
		return false
	}
	return path != "/v1/register" && path != "/v1/health"
}

// requireBearerEnvelope refuses any authenticated route whose Authorization
// header is not the NSK bearer envelope
// (`nsk_<env>_<base64url(node_id(16) || nsk(32))>`, unpadded) for this node.
//
// The mock used to admit every credential and check only the node id in the
// path, which is why the whole suite stayed green through two releases in which
// the agent presented the raw nsk and every deployed node answered 401 from the
// control plane (issues #56, #60). A fixture that accepts anything cannot fail
// on the one thing every deployed node depends on.
func (s *Server) requireBearerEnvelope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresBearer(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if detail := s.checkBearerEnvelope(r.Header.Get("Authorization")); detail != "" {
			s.unauthorizedCount.Add(1)
			writeProblem(w, r, http.StatusUnauthorized, "unauthorized", detail)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkBearerEnvelope returns "" when auth carries this node's envelope, and
// otherwise the reason it was refused. The shape check mirrors the control
// plane's: three underscore-separated segments, `nsk` then a non-empty
// environment tag then an unpadded base64url payload of exactly 48 bytes, whose
// halves are the node id and the node secret key.
func (s *Server) checkBearerEnvelope(auth string) string {
	const prefix = "Bearer "
	if auth == "" {
		return "Authorization header is required"
	}
	if !strings.HasPrefix(auth, prefix) {
		return "Authorization must use the Bearer scheme"
	}
	token := strings.TrimPrefix(auth, prefix)

	// SplitN with a limit of 3, not Split: the payload is base64url, whose
	// alphabet includes the underscore, so splitting on every separator tears a
	// valid credential apart. Only the first two underscores delimit segments.
	segments := strings.SplitN(token, "_", 3)
	if len(segments) != 3 || segments[0] != "nsk" || segments[1] == "" {
		return "Authorization Bearer credential must be an NSK envelope"
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return "Authorization Bearer credential must be an NSK envelope: payload is not unpadded base64url"
	}
	want := bearerPayload(s.nsk)
	if len(payload) != len(want) {
		return fmt.Sprintf("Authorization Bearer credential must be an NSK envelope: payload is %d bytes, want %d", len(payload), len(want))
	}
	if !bytes.Equal(payload[:16], want[:16]) {
		return "Authorization Bearer credential names an unknown node"
	}
	if !bytes.Equal(payload[16:], want[16:]) {
		return "Authorization Bearer credential does not match this node's secret key"
	}
	return ""
}

// handleBearer serves GET /test/bearer, the credential the scripts present when
// they drive an authenticated route themselves.
func (s *Server) handleBearer(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"bearer": s.BearerEnvelope()}); err != nil {
		slog.Error("handleBearer: encode failed", "error", err)
	}
}

// validateLocalAuth checks the Authorization header for the expected bearer token.
// Returns true if valid, false (with 401 written) if invalid.
func (s *Server) validateLocalAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	token := auth[len(prefix):]
	if token != s.expectedBearerToken {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

// handleLocalMetrics handles POST /local/metrics on the TLS listener.
func (s *Server) handleLocalMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.validateLocalAuth(w, r) {
		return
	}
	if _, err := s.captureBody("local_metrics", r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.localMetricsCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleLocalLogs handles POST /local/logs on the TLS listener.
func (s *Server) handleLocalLogs(w http.ResponseWriter, r *http.Request) {
	if !s.validateLocalAuth(w, r) {
		return
	}
	if _, err := s.captureBody("local_logs", r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.localLogsCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// handleLocalAudit handles POST /local/audit on the TLS listener.
func (s *Server) handleLocalAudit(w http.ResponseWriter, r *http.Request) {
	if !s.validateLocalAuth(w, r) {
		return
	}
	if _, err := s.captureBody("local_audit", r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.localAuditCount.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

// TLSHandler returns an http.Handler for the local endpoint TLS listener.
// It registers local endpoint routes plus test assertion/last-request routes.
func (s *Server) TLSHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /local/metrics", s.handleLocalMetrics)
	mux.HandleFunc("POST /local/logs", s.handleLocalLogs)
	mux.HandleFunc("POST /local/audit", s.handleLocalAudit)
	mux.HandleFunc("GET /test/assertions", s.handleAssertions)
	mux.HandleFunc("GET /test/last-request/{endpoint}", s.handleLastRequest)
	return mux
}

// GenerateSelfSignedTLSConfig creates a self-signed TLS configuration with an
// ECDSA key and X.509 certificate valid for "mock-api" and "localhost".
func GenerateSelfSignedTLSConfig() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("mockapi: generate ECDSA key: " + err.Error())
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic("mockapi: generate serial number: " + err.Error())
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"plexd-e2e-mock"}},
		DNSNames:     []string{"mock-api", "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic("mockapi: create certificate: " + err.Error())
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic("mockapi: marshal ECDSA key: " + err.Error())
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic("mockapi: load X509 key pair: " + err.Error())
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// NSK returns the server's 32-byte node secret key (for testing).
func (s *Server) NSK() []byte { return s.nsk }

// ExpectedBearerToken returns the expected bearer token (for testing).
func (s *Server) ExpectedBearerToken() string { return s.expectedBearerToken }

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

// writeProblem writes an RFC 9457 application/problem+json error response. The
// type member is a well-known problem URI when code is non-empty, else
// about:blank; the code member is omitted when code is empty. The instance
// member identifies the specific occurrence via the request path. Every problem
// response carries a freshly minted correlation_id member, echoed on the
// X-Correlation-Id header.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		panic("mockapi: rand.Read correlation id: " + err.Error())
	}
	correlationID := hex.EncodeToString(id)
	problem := map[string]any{
		"type":           "about:blank",
		"title":          http.StatusText(status),
		"status":         status,
		"detail":         detail,
		"instance":       r.URL.Path,
		"correlation_id": correlationID,
	}
	if code != "" {
		problem["type"] = "https://api.plexsphere.com/problems/" + code
		problem["code"] = code
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Correlation-Id", correlationID)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(problem); err != nil {
		slog.Error("writeProblem: encode failed", "error", err)
	}
}

// isAllZero reports whether every byte in b is zero.
func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// binaryChecksumHexRe matches a 64-char lowercase hex SHA-256 digest.
var binaryChecksumHexRe = regexp.MustCompile("^[0-9a-f]{64}$")

// validBinaryChecksum accepts either a 64-char lowercase hex digest or the
// 44-char standard-padded base64 encoding of exactly 32 bytes — the two wire
// forms a real control plane tolerates for a SHA-256 binary checksum.
func validBinaryChecksum(cs string) bool {
	if binaryChecksumHexRe.MatchString(cs) {
		return true
	}
	if len(cs) == 44 {
		if raw, err := base64.StdEncoding.DecodeString(cs); err == nil && len(raw) == 32 {
			return true
		}
	}
	return false
}

// isJSONObject reports whether raw is a JSON object ({...}), rejecting null,
// arrays, strings, and numbers.
func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// validNATType reports whether t is inside the closed endpoint nat_type enum.
func validNATType(t string) bool {
	switch t {
	case "full_cone", "restricted", "port_restricted", "symmetric", "unknown":
		return true
	default:
		return false
	}
}

// routableEndpoint reports whether endpoint is a routable ip:port: a numeric
// port in 1..65535 and an IP that is not loopback, link-local (unicast or
// multicast), or unspecified.
func routableEndpoint(endpoint string) bool {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	return true
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}
