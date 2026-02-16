package mockapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/test/e2e/mockapi"
)

func newTestServer(t *testing.T) (*mockapi.Server, *httptest.Server) {
	t.Helper()
	srv := mockapi.New()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// registerBody is a valid JSON body for POST /v1/register.
const registerBody = `{"token":"tok_123","public_key":"pk_abc","hostname":"node-1"}`

// heartbeatBody is a valid JSON body for POST /v1/nodes/{id}/heartbeat.
const heartbeatBody = `{"node_id":"node-1","timestamp":"2025-01-01T00:00:00Z","status":"healthy","uptime":"1h","binary_checksum":"abc123"}`

// Test body constants for new endpoints.
const (
	keyRotateBody          = `{"node_id":"node-1","new_public_key":"new-pk-abc"}`
	capabilitiesBody       = `{"builtin_actions":[],"hooks":[]}`
	endpointBody           = `{"public_endpoint":"203.0.113.10:51820","nat_type":"full_cone"}`
	driftBody              = `{"timestamp":"2025-01-01T00:00:00Z","corrections":[{"type":"tunnel","detail":"recreated"}]}`
	reportBody             = `{"entries":[],"deleted":[]}`
	executionAckBody       = `{"execution_id":"exec-001","status":"accepted","reason":""}`
	executionResultBody    = `{"execution_id":"exec-001","status":"success","exit_code":0,"stdout":"ok","stderr":"","duration":"1s","finished_at":"2025-01-01T00:00:01Z"}`
	metricsBatchBody       = `[{"timestamp":"2025-01-01T00:00:00Z","group":"system","data":{}}]`
	logsBatchBody          = `[{"timestamp":"2025-01-01T00:00:00Z","source":"plexd","unit":"main","message":"started","severity":"info","hostname":"node-1"}]`
	auditBatchBody         = `[{"timestamp":"2025-01-01T00:00:00Z","source":"auditd","event_type":"execve","subject":{},"object":{},"action":"execve","result":"success","hostname":"node-1","raw":""}]`
	tunnelReadyBody        = `{"listen_addr":"127.0.0.1:2222","timestamp":"2025-01-01T00:00:00Z"}`
	tunnelClosedBody       = `{"reason":"client_disconnect","duration":"5m","timestamp":"2025-01-01T00:00:05Z"}`
	integrityViolationBody = `{"type":"binary","path":"/usr/local/bin/plexd","expected_checksum":"abc","actual_checksum":"def","detail":"mismatch","timestamp":"2025-01-01T00:00:00Z"}`
)

// doRequest creates and sends an HTTP request with the given method, url, and body.
func doRequest(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("create %s request: %v", method, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// getAssertions fetches counters from the /test/assertions HTTP endpoint.
func getAssertions(t *testing.T, baseURL string) mockapi.AssertionCounters {
	t.Helper()
	resp, err := http.Get(baseURL + "/test/assertions")
	if err != nil {
		t.Fatalf("GET /test/assertions: %v", err)
	}
	defer resp.Body.Close()
	var a mockapi.AssertionCounters
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		t.Fatalf("decode assertions: %v", err)
	}
	return a
}

// ---------------------------------------------------------------------------
// REQ-001: GET /v1/ping (Task 2.1)
// ---------------------------------------------------------------------------

func TestPing_ReturnsOK(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/ping")
	if err != nil {
		t.Fatalf("GET /v1/ping: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestPing_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Post(ts.URL+"/v1/ping", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /v1/ping: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// REQ-002: POST /v1/register (Task 2.2)
// ---------------------------------------------------------------------------

func TestRegister_ReturnsFixtureAndCounterViaHTTP(t *testing.T) {
	_, ts := newTestServer(t)

	// Call register twice.
	for i := 0; i < 2; i++ {
		resp, err := http.Post(ts.URL+"/v1/register", "application/json", strings.NewReader(registerBody))
		if err != nil {
			t.Fatalf("POST /v1/register #%d: %v", i+1, err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var reg api.RegisterResponse
		if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
			resp.Body.Close()
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()

		// Verify fixture fields on first call.
		if i == 0 {
			if reg.NodeID == "" {
				t.Error("NodeID is empty")
			}
			if reg.MeshIP == "" {
				t.Error("MeshIP is empty")
			}
			if reg.SigningPublicKey == "" {
				t.Error("SigningPublicKey is empty")
			}
			if reg.NodeSecretKey == "" {
				t.Error("NodeSecretKey is empty")
			}
			if len(reg.Peers) != 2 {
				t.Errorf("len(Peers) = %d, want 2", len(reg.Peers))
			}
			for _, p := range reg.Peers {
				if p.ID == "" || p.PublicKey == "" || p.MeshIP == "" || p.Endpoint == "" || p.PSK == "" {
					t.Errorf("peer %q has empty fields", p.ID)
				}
				if len(p.AllowedIPs) == 0 {
					t.Errorf("peer %q has no AllowedIPs", p.ID)
				}
			}
		}
	}

	// Verify registration_count is 2 via /test/assertions HTTP endpoint.
	a := getAssertions(t, ts.URL)
	if a.RegisterCount != 2 {
		t.Errorf("registration_count = %d, want 2", a.RegisterCount)
	}
}

func TestRegister_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Post(ts.URL+"/v1/register", "application/json", strings.NewReader("not-json"))
	if err != nil {
		t.Fatalf("POST /v1/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestRegister_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/register")
	if err != nil {
		t.Fatalf("GET /v1/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// REQ-003: POST /v1/nodes/{id}/heartbeat (Task 2.3)
// ---------------------------------------------------------------------------

func TestHeartbeat_ReturnsReconcileTrueAndCounterIncrements(t *testing.T) {
	_, ts := newTestServer(t)

	// Call heartbeat 3 times.
	for i := 0; i < 3; i++ {
		resp, err := http.Post(ts.URL+"/v1/nodes/node-1/heartbeat", "application/json", strings.NewReader(heartbeatBody))
		if err != nil {
			t.Fatalf("POST heartbeat #%d: %v", i+1, err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var hb api.HeartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
			resp.Body.Close()
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()

		if !hb.Reconcile {
			t.Errorf("call #%d: Reconcile = false, want true", i+1)
		}
		if hb.RotateKeys {
			t.Errorf("call #%d: RotateKeys = true, want false", i+1)
		}
	}

	// Verify heartbeat_count is 3 via /test/assertions.
	a := getAssertions(t, ts.URL)
	if a.HeartbeatCount != 3 {
		t.Errorf("heartbeat_count = %d, want 3", a.HeartbeatCount)
	}
}

func TestHeartbeat_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/heartbeat")
	if err != nil {
		t.Fatalf("GET heartbeat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestHeartbeat_AcceptsAnyNodeID(t *testing.T) {
	_, ts := newTestServer(t)

	for _, id := range []string{"node-1", "node-2", "node-abc"} {
		body := fmt.Sprintf(`{"node_id":"%s","timestamp":"2025-01-01T00:00:00Z","status":"ok","uptime":"1m","binary_checksum":"x"}`, id)
		resp, err := http.Post(ts.URL+"/v1/nodes/"+id+"/heartbeat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST heartbeat %s: %v", id, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("heartbeat %s: status = %d, want %d", id, resp.StatusCode, http.StatusOK)
		}
		resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// REQ-004: GET /v1/nodes/{id}/state (Task 2.4)
// ---------------------------------------------------------------------------

func TestState_ReturnsFixturePeersAndPolicies(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var state api.StateResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verify peers.
	if len(state.Peers) < 2 {
		t.Errorf("len(Peers) = %d, want >= 2", len(state.Peers))
	}
	for _, p := range state.Peers {
		if p.ID == "" || p.PublicKey == "" || p.MeshIP == "" || p.Endpoint == "" || p.PSK == "" {
			t.Errorf("peer %q has empty fields", p.ID)
		}
		if len(p.AllowedIPs) == 0 {
			t.Errorf("peer %q has no AllowedIPs", p.ID)
		}
	}

	// Verify policies.
	if len(state.Policies) < 1 {
		t.Errorf("len(Policies) = %d, want >= 1", len(state.Policies))
	}
	for _, pol := range state.Policies {
		if pol.ID == "" {
			t.Error("policy has empty ID")
		}
		if len(pol.Rules) < 2 {
			t.Errorf("policy %q: len(Rules) = %d, want >= 2", pol.ID, len(pol.Rules))
		}
		for _, r := range pol.Rules {
			if r.Src == "" || r.Dst == "" || r.Protocol == "" || r.Action == "" {
				t.Errorf("policy %q rule has empty fields", pol.ID)
			}
		}
	}

	// Verify Data and SecretRefs are empty slices (not nil).
	if state.Data == nil {
		t.Error("Data is nil, want empty slice")
	} else if len(state.Data) != 0 {
		t.Errorf("len(Data) = %d, want 0", len(state.Data))
	}
	if state.SecretRefs == nil {
		t.Error("SecretRefs is nil, want empty slice")
	} else if len(state.SecretRefs) != 0 {
		t.Errorf("len(SecretRefs) = %d, want 0", len(state.SecretRefs))
	}

	// Verify state_count increments.
	a := getAssertions(t, ts.URL)
	if a.StateCount != 1 {
		t.Errorf("state_count = %d, want 1", a.StateCount)
	}
}

// ---------------------------------------------------------------------------
// REQ-005: GET /v1/nodes/{id}/metadata (Task 2.5)
// ---------------------------------------------------------------------------

func TestMetadata_ReturnsFixtureAndCounterIncrements(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/metadata")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var meta map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verify expected metadata keys.
	for _, key := range []string{"environment", "region", "role"} {
		if _, ok := meta[key]; !ok {
			t.Errorf("metadata missing key %q", key)
		}
	}

	// Verify metadata_count increments.
	a := getAssertions(t, ts.URL)
	if a.MetadataCount != 1 {
		t.Errorf("metadata_count = %d, want 1", a.MetadataCount)
	}
}

// ---------------------------------------------------------------------------
// REQ-006: GET /v1/nodes/{id}/events (Task 2.6)
// ---------------------------------------------------------------------------

func TestEvents_SSEStream(t *testing.T) {
	_, ts := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/nodes/node-1/events", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/event-stream")
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-cache")
	}

	// Read at least one SSE event.
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read SSE: %v", err)
	}
	data := string(buf[:n])

	// Verify SSE format: should contain event type, id, and data fields.
	if !strings.Contains(data, "event:") {
		t.Errorf("expected SSE event field, got: %q", data)
	}
	if !strings.Contains(data, "data:") {
		t.Errorf("expected SSE data field, got: %q", data)
	}
	if !strings.Contains(data, "id:") {
		t.Errorf("expected SSE id field, got: %q", data)
	}
}

func TestEvents_SSEKeepAlive(t *testing.T) {
	srv := mockapi.New()
	srv.KeepAliveInterval = 50 * time.Millisecond // fast interval for testing
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/nodes/node-1/events", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	defer resp.Body.Close()

	// Read initial event + at least one keep-alive comment.
	// With 50ms interval, we should see a keep-alive within 200ms.
	buf := make([]byte, 8192)
	var accumulated string
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			accumulated += string(buf[:n])
		}
		if strings.Contains(accumulated, ": keep-alive") {
			break
		}
		if err != nil {
			t.Fatalf("read SSE: %v (got so far: %q)", err, accumulated)
		}
	}

	if !strings.Contains(accumulated, ": keep-alive") {
		t.Errorf("expected keep-alive comment in SSE stream, got: %q", accumulated)
	}
}

func TestEvents_ClientDisconnect(t *testing.T) {
	_, ts := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/nodes/n1/events", nil)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	resp.Body.Close()

	// If we got here without panicking, disconnect was handled gracefully.
}

// ---------------------------------------------------------------------------
// REQ-007: GET /test/assertions (Task 2.7)
// ---------------------------------------------------------------------------

func TestAssertions_ReturnsCorrectCountsAfterMixedCalls(t *testing.T) {
	_, ts := newTestServer(t)

	// Call register once.
	resp, err := http.Post(ts.URL+"/v1/register", "application/json", strings.NewReader(registerBody))
	if err != nil {
		t.Fatalf("POST register: %v", err)
	}
	resp.Body.Close()

	// Call heartbeat twice.
	for i := 0; i < 2; i++ {
		resp, err := http.Post(ts.URL+"/v1/nodes/n1/heartbeat", "application/json", strings.NewReader(heartbeatBody))
		if err != nil {
			t.Fatalf("POST heartbeat #%d: %v", i+1, err)
		}
		resp.Body.Close()
	}

	// Call state once.
	resp, err = http.Get(ts.URL + "/v1/nodes/n1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	resp.Body.Close()

	// Call metadata once.
	resp, err = http.Get(ts.URL + "/v1/nodes/n1/metadata")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	resp.Body.Close()

	// Call all new endpoints.
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/deregister", "")
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", keyRotateBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/n1/capabilities", capabilitiesBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/n1/endpoint", endpointBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/drift", driftBody)
	resp.Body.Close()
	resp, err = http.Get(ts.URL + "/v1/nodes/n1/secrets/db-password")
	if err != nil {
		t.Fatalf("GET secrets: %v", err)
	}
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/report", reportBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/executions/exec-001/ack", executionAckBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/executions/exec-001/result", executionResultBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/metrics", metricsBatchBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/logs", logsBatchBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/audit", auditBatchBody)
	resp.Body.Close()
	resp, err = http.Get(ts.URL + "/v1/artifacts/plexd/1.0.0/linux/amd64")
	if err != nil {
		t.Fatalf("GET artifact: %v", err)
	}
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/tunnels/sess-001/ready", tunnelReadyBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/tunnels/sess-001/closed", tunnelClosedBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/integrity/violations", integrityViolationBody)
	resp.Body.Close()

	// Verify all counters via /test/assertions.
	a := getAssertions(t, ts.URL)
	if a.RegisterCount != 1 {
		t.Errorf("registration_count = %d, want 1", a.RegisterCount)
	}
	if a.HeartbeatCount != 2 {
		t.Errorf("heartbeat_count = %d, want 2", a.HeartbeatCount)
	}
	if a.StateCount != 1 {
		t.Errorf("state_count = %d, want 1", a.StateCount)
	}
	if a.MetadataCount != 1 {
		t.Errorf("metadata_count = %d, want 1", a.MetadataCount)
	}
	if a.DeregisterCount != 1 {
		t.Errorf("deregister_count = %d, want 1", a.DeregisterCount)
	}
	if a.KeyRotateCount != 1 {
		t.Errorf("key_rotate_count = %d, want 1", a.KeyRotateCount)
	}
	if a.CapabilitiesCount != 1 {
		t.Errorf("capabilities_count = %d, want 1", a.CapabilitiesCount)
	}
	if a.EndpointCount != 1 {
		t.Errorf("endpoint_count = %d, want 1", a.EndpointCount)
	}
	if a.DriftCount != 1 {
		t.Errorf("drift_count = %d, want 1", a.DriftCount)
	}
	if a.SecretsCount != 1 {
		t.Errorf("secrets_count = %d, want 1", a.SecretsCount)
	}
	if a.ReportCount != 1 {
		t.Errorf("report_count = %d, want 1", a.ReportCount)
	}
	if a.ExecutionAckCount != 1 {
		t.Errorf("execution_ack_count = %d, want 1", a.ExecutionAckCount)
	}
	if a.ExecutionResultCount != 1 {
		t.Errorf("execution_result_count = %d, want 1", a.ExecutionResultCount)
	}
	if a.MetricsCount != 1 {
		t.Errorf("metrics_count = %d, want 1", a.MetricsCount)
	}
	if a.LogsCount != 1 {
		t.Errorf("logs_count = %d, want 1", a.LogsCount)
	}
	if a.AuditCount != 1 {
		t.Errorf("audit_count = %d, want 1", a.AuditCount)
	}
	if a.ArtifactCount != 1 {
		t.Errorf("artifact_count = %d, want 1", a.ArtifactCount)
	}
	if a.TunnelReadyCount != 1 {
		t.Errorf("tunnel_ready_count = %d, want 1", a.TunnelReadyCount)
	}
	if a.TunnelClosedCount != 1 {
		t.Errorf("tunnel_closed_count = %d, want 1", a.TunnelClosedCount)
	}
	if a.IntegrityViolationCount != 1 {
		t.Errorf("integrity_violation_count = %d, want 1", a.IntegrityViolationCount)
	}
}

func TestAssertions_InitialZero(t *testing.T) {
	_, ts := newTestServer(t)

	a := getAssertions(t, ts.URL)
	if a.RegisterCount != 0 {
		t.Errorf("registration_count = %d, want 0", a.RegisterCount)
	}
	if a.HeartbeatCount != 0 {
		t.Errorf("heartbeat_count = %d, want 0", a.HeartbeatCount)
	}
	if a.StateCount != 0 {
		t.Errorf("state_count = %d, want 0", a.StateCount)
	}
	if a.MetadataCount != 0 {
		t.Errorf("metadata_count = %d, want 0", a.MetadataCount)
	}
	if a.DeregisterCount != 0 {
		t.Errorf("deregister_count = %d, want 0", a.DeregisterCount)
	}
	if a.KeyRotateCount != 0 {
		t.Errorf("key_rotate_count = %d, want 0", a.KeyRotateCount)
	}
	if a.CapabilitiesCount != 0 {
		t.Errorf("capabilities_count = %d, want 0", a.CapabilitiesCount)
	}
	if a.EndpointCount != 0 {
		t.Errorf("endpoint_count = %d, want 0", a.EndpointCount)
	}
	if a.DriftCount != 0 {
		t.Errorf("drift_count = %d, want 0", a.DriftCount)
	}
	if a.SecretsCount != 0 {
		t.Errorf("secrets_count = %d, want 0", a.SecretsCount)
	}
	if a.ReportCount != 0 {
		t.Errorf("report_count = %d, want 0", a.ReportCount)
	}
	if a.ExecutionAckCount != 0 {
		t.Errorf("execution_ack_count = %d, want 0", a.ExecutionAckCount)
	}
	if a.ExecutionResultCount != 0 {
		t.Errorf("execution_result_count = %d, want 0", a.ExecutionResultCount)
	}
	if a.MetricsCount != 0 {
		t.Errorf("metrics_count = %d, want 0", a.MetricsCount)
	}
	if a.LogsCount != 0 {
		t.Errorf("logs_count = %d, want 0", a.LogsCount)
	}
	if a.AuditCount != 0 {
		t.Errorf("audit_count = %d, want 0", a.AuditCount)
	}
	if a.ArtifactCount != 0 {
		t.Errorf("artifact_count = %d, want 0", a.ArtifactCount)
	}
	if a.TunnelReadyCount != 0 {
		t.Errorf("tunnel_ready_count = %d, want 0", a.TunnelReadyCount)
	}
	if a.TunnelClosedCount != 0 {
		t.Errorf("tunnel_closed_count = %d, want 0", a.TunnelClosedCount)
	}
	if a.IntegrityViolationCount != 0 {
		t.Errorf("integrity_violation_count = %d, want 0", a.IntegrityViolationCount)
	}
}

// ---------------------------------------------------------------------------
// REQ-008: Concurrent counters (Task 2.8)
// ---------------------------------------------------------------------------

func TestConcurrentCounters(t *testing.T) {
	_, ts := newTestServer(t)

	const n = 100

	type endpointDef struct {
		method string
		path   string
		body   string
	}
	endpoints := []endpointDef{
		{http.MethodPost, "/v1/register", registerBody},
		{http.MethodPost, "/v1/nodes/node-1/heartbeat", heartbeatBody},
		{http.MethodGet, "/v1/nodes/node-1/state", ""},
		{http.MethodGet, "/v1/nodes/node-1/metadata", ""},
		{http.MethodPost, "/v1/nodes/node-1/deregister", ""},
		{http.MethodPost, "/v1/keys/rotate", keyRotateBody},
		{http.MethodPut, "/v1/nodes/node-1/capabilities", capabilitiesBody},
		{http.MethodPut, "/v1/nodes/node-1/endpoint", endpointBody},
		{http.MethodPost, "/v1/nodes/node-1/drift", driftBody},
		{http.MethodGet, "/v1/nodes/node-1/secrets/key1", ""},
		{http.MethodPost, "/v1/nodes/node-1/report", reportBody},
		{http.MethodPost, "/v1/nodes/node-1/executions/exec-001/ack", executionAckBody},
		{http.MethodPost, "/v1/nodes/node-1/executions/exec-001/result", executionResultBody},
		{http.MethodPost, "/v1/nodes/node-1/metrics", metricsBatchBody},
		{http.MethodPost, "/v1/nodes/node-1/logs", logsBatchBody},
		{http.MethodPost, "/v1/nodes/node-1/audit", auditBatchBody},
		{http.MethodGet, "/v1/artifacts/plexd/1.0.0/linux/amd64", ""},
		{http.MethodPost, "/v1/nodes/node-1/tunnels/sess-001/ready", tunnelReadyBody},
		{http.MethodPost, "/v1/nodes/node-1/tunnels/sess-001/closed", tunnelClosedBody},
		{http.MethodPost, "/v1/nodes/node-1/integrity/violations", integrityViolationBody},
	}

	var wg sync.WaitGroup
	wg.Add(n * len(endpoints))

	for _, ep := range endpoints {
		for i := 0; i < n; i++ {
			go func(e endpointDef) {
				defer wg.Done()
				var bodyReader io.Reader
				if e.body != "" {
					bodyReader = strings.NewReader(e.body)
				}
				req, err := http.NewRequest(e.method, ts.URL+e.path, bodyReader)
				if err != nil {
					return
				}
				if e.body != "" {
					req.Header.Set("Content-Type", "application/json")
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()
			}(ep)
		}
	}

	wg.Wait()

	a := getAssertions(t, ts.URL)
	if a.RegisterCount != n {
		t.Errorf("registration_count = %d, want %d", a.RegisterCount, n)
	}
	if a.HeartbeatCount != n {
		t.Errorf("heartbeat_count = %d, want %d", a.HeartbeatCount, n)
	}
	if a.StateCount != n {
		t.Errorf("state_count = %d, want %d", a.StateCount, n)
	}
	if a.MetadataCount != n {
		t.Errorf("metadata_count = %d, want %d", a.MetadataCount, n)
	}
	if a.DeregisterCount != n {
		t.Errorf("deregister_count = %d, want %d", a.DeregisterCount, n)
	}
	if a.KeyRotateCount != n {
		t.Errorf("key_rotate_count = %d, want %d", a.KeyRotateCount, n)
	}
	if a.CapabilitiesCount != n {
		t.Errorf("capabilities_count = %d, want %d", a.CapabilitiesCount, n)
	}
	if a.EndpointCount != n {
		t.Errorf("endpoint_count = %d, want %d", a.EndpointCount, n)
	}
	if a.DriftCount != n {
		t.Errorf("drift_count = %d, want %d", a.DriftCount, n)
	}
	if a.SecretsCount != n {
		t.Errorf("secrets_count = %d, want %d", a.SecretsCount, n)
	}
	if a.ReportCount != n {
		t.Errorf("report_count = %d, want %d", a.ReportCount, n)
	}
	if a.ExecutionAckCount != n {
		t.Errorf("execution_ack_count = %d, want %d", a.ExecutionAckCount, n)
	}
	if a.ExecutionResultCount != n {
		t.Errorf("execution_result_count = %d, want %d", a.ExecutionResultCount, n)
	}
	if a.MetricsCount != n {
		t.Errorf("metrics_count = %d, want %d", a.MetricsCount, n)
	}
	if a.LogsCount != n {
		t.Errorf("logs_count = %d, want %d", a.LogsCount, n)
	}
	if a.AuditCount != n {
		t.Errorf("audit_count = %d, want %d", a.AuditCount, n)
	}
	if a.ArtifactCount != n {
		t.Errorf("artifact_count = %d, want %d", a.ArtifactCount, n)
	}
	if a.TunnelReadyCount != n {
		t.Errorf("tunnel_ready_count = %d, want %d", a.TunnelReadyCount, n)
	}
	if a.TunnelClosedCount != n {
		t.Errorf("tunnel_closed_count = %d, want %d", a.TunnelClosedCount, n)
	}
	if a.IntegrityViolationCount != n {
		t.Errorf("integrity_violation_count = %d, want %d", a.IntegrityViolationCount, n)
	}
}

// ---------------------------------------------------------------------------
// Deregister endpoint
// ---------------------------------------------------------------------------

func TestDeregister_Returns204AndCounterIncrements(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/deregister", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.DeregisterCount != 1 {
		t.Errorf("deregister_count = %d, want 1", a.DeregisterCount)
	}
}

func TestDeregister_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/deregister")
	if err != nil {
		t.Fatalf("GET deregister: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Key rotate endpoint
// ---------------------------------------------------------------------------

func TestKeyRotate_ReturnsFixtureAndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", keyRotateBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var kr api.KeyRotateResponse
	if err := json.NewDecoder(resp.Body).Decode(&kr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(kr.UpdatedPeers) != 2 {
		t.Errorf("len(UpdatedPeers) = %d, want 2", len(kr.UpdatedPeers))
	}

	a := getAssertions(t, ts.URL)
	if a.KeyRotateCount != 1 {
		t.Errorf("key_rotate_count = %d, want 1", a.KeyRotateCount)
	}
}

func TestKeyRotate_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestKeyRotate_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/keys/rotate")
	if err != nil {
		t.Fatalf("GET key rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Capabilities endpoint
// ---------------------------------------------------------------------------

func TestCapabilities_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/capabilities", capabilitiesBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.CapabilitiesCount != 1 {
		t.Errorf("capabilities_count = %d, want 1", a.CapabilitiesCount)
	}
}

func TestCapabilities_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/capabilities", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestCapabilities_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/capabilities", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Endpoint (NAT) endpoint
// ---------------------------------------------------------------------------

func TestEndpoint_ReturnsFixtureAndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/endpoint", endpointBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var er api.EndpointResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(er.PeerEndpoints) != 2 {
		t.Errorf("len(PeerEndpoints) = %d, want 2", len(er.PeerEndpoints))
	}

	a := getAssertions(t, ts.URL)
	if a.EndpointCount != 1 {
		t.Errorf("endpoint_count = %d, want 1", a.EndpointCount)
	}
}

func TestEndpoint_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/endpoint", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestEndpoint_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/endpoint", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Drift endpoint
// ---------------------------------------------------------------------------

func TestDrift_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/drift", driftBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.DriftCount != 1 {
		t.Errorf("drift_count = %d, want 1", a.DriftCount)
	}
}

func TestDrift_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/drift", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestDrift_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/drift")
	if err != nil {
		t.Fatalf("GET drift: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Secrets endpoint
// ---------------------------------------------------------------------------

func TestSecrets_ReturnsFixtureWithPathKey(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/secrets/db-password")
	if err != nil {
		t.Fatalf("GET secrets: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var sr api.SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sr.Key != "db-password" {
		t.Errorf("Key = %q, want %q", sr.Key, "db-password")
	}
	if sr.Ciphertext == "" {
		t.Error("Ciphertext is empty")
	}
	if sr.Nonce == "" {
		t.Error("Nonce is empty")
	}
	if sr.Version != 1 {
		t.Errorf("Version = %d, want 1", sr.Version)
	}

	a := getAssertions(t, ts.URL)
	if a.SecretsCount != 1 {
		t.Errorf("secrets_count = %d, want 1", a.SecretsCount)
	}
}

func TestSecrets_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/secrets/db-password", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Report endpoint
// ---------------------------------------------------------------------------

func TestReport_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/report", reportBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.ReportCount != 1 {
		t.Errorf("report_count = %d, want 1", a.ReportCount)
	}
}

func TestReport_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/report", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestReport_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/report")
	if err != nil {
		t.Fatalf("GET report: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Execution ack endpoint
// ---------------------------------------------------------------------------

func TestExecutionAck_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/executions/exec-001/ack", executionAckBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.ExecutionAckCount != 1 {
		t.Errorf("execution_ack_count = %d, want 1", a.ExecutionAckCount)
	}
}

func TestExecutionAck_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/executions/exec-001/ack", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestExecutionAck_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/executions/exec-001/ack")
	if err != nil {
		t.Fatalf("GET execution ack: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Execution result endpoint
// ---------------------------------------------------------------------------

func TestExecutionResult_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/executions/exec-001/result", executionResultBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.ExecutionResultCount != 1 {
		t.Errorf("execution_result_count = %d, want 1", a.ExecutionResultCount)
	}
}

func TestExecutionResult_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/executions/exec-001/result", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestExecutionResult_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/executions/exec-001/result")
	if err != nil {
		t.Fatalf("GET execution result: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Metrics endpoint
// ---------------------------------------------------------------------------

func TestMetrics_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/metrics", metricsBatchBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.MetricsCount != 1 {
		t.Errorf("metrics_count = %d, want 1", a.MetricsCount)
	}
}

func TestMetrics_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/metrics", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestMetrics_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/metrics")
	if err != nil {
		t.Fatalf("GET metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Logs endpoint
// ---------------------------------------------------------------------------

func TestLogs_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/logs", logsBatchBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.LogsCount != 1 {
		t.Errorf("logs_count = %d, want 1", a.LogsCount)
	}
}

func TestLogs_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/logs", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestLogs_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/logs")
	if err != nil {
		t.Fatalf("GET logs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Audit endpoint
// ---------------------------------------------------------------------------

func TestAudit_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/audit", auditBatchBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.AuditCount != 1 {
		t.Errorf("audit_count = %d, want 1", a.AuditCount)
	}
}

func TestAudit_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/audit", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestAudit_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/audit")
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Artifact endpoint
// ---------------------------------------------------------------------------

func TestArtifact_ReturnsBinaryAndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/artifacts/plexd/1.0.0/linux/amd64")
	if err != nil {
		t.Fatalf("GET artifact: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/octet-stream")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Error("artifact body is empty")
	}

	a := getAssertions(t, ts.URL)
	if a.ArtifactCount != 1 {
		t.Errorf("artifact_count = %d, want 1", a.ArtifactCount)
	}
}

func TestArtifact_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/artifacts/plexd/1.0.0/linux/amd64", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Tunnel ready endpoint
// ---------------------------------------------------------------------------

func TestTunnelReady_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/tunnels/sess-001/ready", tunnelReadyBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.TunnelReadyCount != 1 {
		t.Errorf("tunnel_ready_count = %d, want 1", a.TunnelReadyCount)
	}
}

func TestTunnelReady_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/tunnels/sess-001/ready", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestTunnelReady_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/tunnels/sess-001/ready")
	if err != nil {
		t.Fatalf("GET tunnel ready: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Tunnel closed endpoint
// ---------------------------------------------------------------------------

func TestTunnelClosed_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/tunnels/sess-001/closed", tunnelClosedBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.TunnelClosedCount != 1 {
		t.Errorf("tunnel_closed_count = %d, want 1", a.TunnelClosedCount)
	}
}

func TestTunnelClosed_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/tunnels/sess-001/closed", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestTunnelClosed_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/tunnels/sess-001/closed")
	if err != nil {
		t.Fatalf("GET tunnel closed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Integrity violation endpoint
// ---------------------------------------------------------------------------

func TestIntegrityViolation_Returns204AndCounter(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/integrity/violations", integrityViolationBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	a := getAssertions(t, ts.URL)
	if a.IntegrityViolationCount != 1 {
		t.Errorf("integrity_violation_count = %d, want 1", a.IntegrityViolationCount)
	}
}

func TestIntegrityViolation_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/integrity/violations", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestIntegrityViolation_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/integrity/violations")
	if err != nil {
		t.Fatalf("GET integrity violations: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Last request body capture
// ---------------------------------------------------------------------------

func TestLastRequest_Returns404WhenNoCapturedBody(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/test/last-request/drift")
	if err != nil {
		t.Fatalf("GET last-request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestLastRequest_ReturnsCapturedBody(t *testing.T) {
	_, ts := newTestServer(t)

	// Send a drift request to capture the body.
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/drift", driftBody)
	resp.Body.Close()

	// Retrieve the captured body.
	resp, err := http.Get(ts.URL + "/test/last-request/drift")
	if err != nil {
		t.Fatalf("GET last-request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/octet-stream")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != driftBody {
		t.Errorf("captured body = %q, want %q", string(body), driftBody)
	}
}

func TestLastRequestBody_InitiallyEmpty(t *testing.T) {
	srv, _ := newTestServer(t)

	_, ok := srv.LastRequestBody("drift")
	if ok {
		t.Error("expected no captured body initially")
	}
}

func TestLastRequestBody_StoredAfterCapture(t *testing.T) {
	srv, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/drift", driftBody)
	resp.Body.Close()

	data, ok := srv.LastRequestBody("drift")
	if !ok {
		t.Fatal("expected captured body")
	}
	if string(data) != driftBody {
		t.Errorf("captured body = %q, want %q", string(data), driftBody)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestUnknownRoute_Returns404(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/does-not-exist")
	if err != nil {
		t.Fatalf("GET unknown: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHandler_NotNil(t *testing.T) {
	srv := mockapi.New()
	if srv.Handler() == nil {
		t.Error("Handler() returned nil")
	}
}
