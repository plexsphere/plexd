package mockapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// getCapturedBody fetches the last captured request body for the given endpoint
// key via GET /test/last-request/{endpoint} and returns the raw bytes.
func getCapturedBody(t *testing.T, baseURL, endpoint string) []byte {
	t.Helper()
	resp, err := http.Get(baseURL + "/test/last-request/" + endpoint)
	if err != nil {
		t.Fatalf("GET last-request/%s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET last-request/%s status = %d, want %d", endpoint, resp.StatusCode, http.StatusOK)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read last-request/%s body: %v", endpoint, err)
	}
	return data
}

// assertAllCountersEqual checks that every field in the AssertionCounters struct
// equals the expected value. Useful for InitialZero and ConcurrentCounters tests.
func assertAllCountersEqual(t *testing.T, a mockapi.AssertionCounters, want int64) {
	t.Helper()
	v := reflect.ValueOf(a)
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		got := v.Field(i).Int()
		if got != want {
			t.Errorf("%s = %d, want %d", typ.Field(i).Name, got, want)
		}
	}
}

// makeEnvelope creates a SignedEnvelope with the given event type and ID.
func makeEnvelope(eventType, eventID string, payload json.RawMessage) api.SignedEnvelope {
	return api.SignedEnvelope{
		EventType: eventType,
		EventID:   eventID,
		IssuedAt:  time.Now().UTC(),
		Nonce:     "nonce-" + eventID,
		Payload:   payload,
		Signature: "sig-" + eventID,
	}
}

// connectSSE opens an SSE connection to /v1/nodes/{nodeID}/events and returns
// the response. The caller must close resp.Body. The context timeout controls
// the connection lifetime.
func connectSSE(t *testing.T, baseURL, nodeID string, timeout time.Duration) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/nodes/"+nodeID+"/events", nil)
	if err != nil {
		t.Fatalf("create SSE request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	return resp
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

	resp := connectSSE(t, ts.URL, "node-1", 3*time.Second)
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

	resp := connectSSE(t, ts.URL, "node-1", 2*time.Second)
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

	resp := connectSSE(t, ts.URL, "n1", 500*time.Millisecond)
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

	// Inject one SSE event.
	envJSON, _ := json.Marshal(makeEnvelope("test_mixed", "evt-mixed-001", json.RawMessage(`{}`)))
	resp = doRequest(t, http.MethodPost, ts.URL+"/test/inject-event", string(envJSON))
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
	if a.InjectEventCount != 1 {
		t.Errorf("inject_event_count = %d, want 1", a.InjectEventCount)
	}
}

func TestAssertions_InitialZero(t *testing.T) {
	_, ts := newTestServer(t)

	a := getAssertions(t, ts.URL)
	assertAllCountersEqual(t, a, 0)
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
		{http.MethodPost, "/test/inject-event", `{"event_type":"conc","event_id":"e1","nonce":"n","payload":{},"signature":"s"}`},
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
	assertAllCountersEqual(t, a, n)
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

func TestLastRequest_RegisterBodyCaptured(t *testing.T) {
	_, ts := newTestServer(t)

	// Send a register request to capture the body.
	resp, err := http.Post(ts.URL+"/v1/register", "application/json", strings.NewReader(registerBody))
	if err != nil {
		t.Fatalf("POST register: %v", err)
	}
	resp.Body.Close()

	// Retrieve the captured body via the HTTP endpoint.
	resp, err = http.Get(ts.URL + "/test/last-request/register")
	if err != nil {
		t.Fatalf("GET last-request/register: %v", err)
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
	if string(body) != registerBody {
		t.Errorf("captured body = %q, want %q", string(body), registerBody)
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

// ---------------------------------------------------------------------------
// SSE broadcast / inject-event (Task 1.1)
// ---------------------------------------------------------------------------

// readSSEEvent reads the next SSE event from an SSE response body.
// It returns the raw text of the event block (up to and including the blank line).
func readSSEEvent(t *testing.T, body io.Reader, timeout time.Duration) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		var accumulated string
		for {
			n, err := body.Read(buf)
			if n > 0 {
				accumulated += string(buf[:n])
			}
			// An SSE event ends with a double newline.
			if idx := strings.Index(accumulated, "\n\n"); idx >= 0 {
				ch <- accumulated[:idx+2]
				return
			}
			if err != nil {
				ch <- accumulated
				return
			}
		}
	}()
	select {
	case data := <-ch:
		return data
	case <-time.After(timeout):
		t.Fatal("timed out waiting for SSE event")
		return ""
	}
}

func TestInjectEvent_DeliversToConnectedClient(t *testing.T) {
	srv := mockapi.New()
	srv.KeepAliveInterval = 10 * time.Second // long interval so keep-alives don't interfere
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Connect an SSE client.
	resp := connectSSE(t, ts.URL, "node-1", 5*time.Second)
	defer resp.Body.Close()

	// Read the initial event (node_state_updated sent on connect).
	initialEvt := readSSEEvent(t, resp.Body, 3*time.Second)
	if !strings.Contains(initialEvt, "node_state_updated") {
		t.Fatalf("expected initial node_state_updated event, got: %q", initialEvt)
	}

	// Inject an event via POST /test/inject-event.
	envJSON, _ := json.Marshal(makeEnvelope("test_injected", "evt-inject-001", json.RawMessage(`{"action":"test"}`)))
	injectResp := doRequest(t, http.MethodPost, ts.URL+"/test/inject-event", string(envJSON))
	defer injectResp.Body.Close()
	if injectResp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /test/inject-event status = %d, want %d", injectResp.StatusCode, http.StatusNoContent)
	}

	// Read the injected event from the SSE stream.
	injectedEvt := readSSEEvent(t, resp.Body, 3*time.Second)
	if !strings.Contains(injectedEvt, "test_injected") {
		t.Errorf("expected injected event type, got: %q", injectedEvt)
	}
	if !strings.Contains(injectedEvt, "evt-inject-001") {
		t.Errorf("expected injected event ID, got: %q", injectedEvt)
	}
	if !strings.Contains(injectedEvt, `"action":"test"`) {
		t.Errorf("expected injected payload in data, got: %q", injectedEvt)
	}
}

func TestInjectEvent_CounterIncrements(t *testing.T) {
	_, ts := newTestServer(t)

	envJSON, _ := json.Marshal(makeEnvelope("test_counter", "evt-counter-001", json.RawMessage(`{}`)))

	// Inject twice.
	for i := 0; i < 2; i++ {
		resp := doRequest(t, http.MethodPost, ts.URL+"/test/inject-event", string(envJSON))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("inject #%d: status = %d, want %d", i+1, resp.StatusCode, http.StatusNoContent)
		}
	}

	a := getAssertions(t, ts.URL)
	if a.InjectEventCount != 2 {
		t.Errorf("inject_event_count = %d, want 2", a.InjectEventCount)
	}
}

func TestInjectEvent_MultipleClients(t *testing.T) {
	srv := mockapi.New()
	srv.KeepAliveInterval = 10 * time.Second
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Connect two SSE clients.
	clients := make([]*http.Response, 2)
	for i := range clients {
		resp := connectSSE(t, ts.URL, "node-1", 5*time.Second)
		defer resp.Body.Close()
		clients[i] = resp

		// Consume the initial event.
		readSSEEvent(t, resp.Body, 3*time.Second)
	}

	// Inject one event.
	envJSON, _ := json.Marshal(makeEnvelope("multi_test", "evt-multi-001", json.RawMessage(`{"multi":true}`)))
	injectResp := doRequest(t, http.MethodPost, ts.URL+"/test/inject-event", string(envJSON))
	injectResp.Body.Close()

	// Both clients should receive the event.
	for i, c := range clients {
		evt := readSSEEvent(t, c.Body, 3*time.Second)
		if !strings.Contains(evt, "multi_test") {
			t.Errorf("client %d: expected multi_test event, got: %q", i, evt)
		}
		if !strings.Contains(evt, "evt-multi-001") {
			t.Errorf("client %d: expected event ID evt-multi-001, got: %q", i, evt)
		}
	}
}

func TestInjectEvent_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/test/inject-event", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// State enriched fixture tests (Task 1.3)
// ---------------------------------------------------------------------------

func getState(t *testing.T, baseURL string) api.StateResponse {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var state api.StateResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return state
}

func TestState_ReturnsSigningKeys(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.SigningKeys == nil {
		t.Fatal("SigningKeys is nil")
	}
	if state.SigningKeys.Current == "" {
		t.Error("SigningKeys.Current is empty")
	}
	if state.SigningKeys.Previous == "" {
		t.Error("SigningKeys.Previous is empty")
	}
}

func TestState_ReturnsBridgeConfig(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.BridgeConfig == nil {
		t.Fatal("BridgeConfig is nil")
	}
	if len(state.BridgeConfig.AccessSubnets) == 0 {
		t.Error("BridgeConfig.AccessSubnets is empty")
	}
	if !state.BridgeConfig.EnableNAT {
		t.Error("BridgeConfig.EnableNAT = false, want true")
	}
	if !state.BridgeConfig.EnableForwarding {
		t.Error("BridgeConfig.EnableForwarding = false, want true")
	}
}

func TestState_ReturnsRelayConfig(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.RelayConfig == nil {
		t.Fatal("RelayConfig is nil")
	}
	if len(state.RelayConfig.Sessions) != 1 {
		t.Fatalf("len(RelayConfig.Sessions) = %d, want 1", len(state.RelayConfig.Sessions))
	}
	sess := state.RelayConfig.Sessions[0]
	if sess.SessionID == "" {
		t.Error("RelayConfig.Sessions[0].SessionID is empty")
	}
	if sess.PeerAID == "" || sess.PeerBID == "" {
		t.Error("RelayConfig.Sessions[0] has empty peer IDs")
	}
	if sess.PeerAEndpoint == "" || sess.PeerBEndpoint == "" {
		t.Error("RelayConfig.Sessions[0] has empty peer endpoints")
	}
	if sess.ExpiresAt.IsZero() {
		t.Error("RelayConfig.Sessions[0].ExpiresAt is zero")
	}
}

func TestState_ReturnsUserAccessConfig(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.UserAccessConfig == nil {
		t.Fatal("UserAccessConfig is nil")
	}
	if !state.UserAccessConfig.Enabled {
		t.Error("UserAccessConfig.Enabled = false, want true")
	}
	if state.UserAccessConfig.InterfaceName == "" {
		t.Error("UserAccessConfig.InterfaceName is empty")
	}
	if state.UserAccessConfig.ListenPort == 0 {
		t.Error("UserAccessConfig.ListenPort = 0")
	}
	if len(state.UserAccessConfig.Peers) != 1 {
		t.Fatalf("len(UserAccessConfig.Peers) = %d, want 1", len(state.UserAccessConfig.Peers))
	}
	uaPeer := state.UserAccessConfig.Peers[0]
	if uaPeer.PublicKey == "" {
		t.Error("UserAccessConfig.Peers[0].PublicKey is empty")
	}
	if len(uaPeer.AllowedIPs) == 0 {
		t.Error("UserAccessConfig.Peers[0].AllowedIPs is empty")
	}
	if uaPeer.Label == "" {
		t.Error("UserAccessConfig.Peers[0].Label is empty")
	}
}

func TestState_ReturnsIngressConfig(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.IngressConfig == nil {
		t.Fatal("IngressConfig is nil")
	}
	if !state.IngressConfig.Enabled {
		t.Error("IngressConfig.Enabled = false, want true")
	}
	if len(state.IngressConfig.Rules) != 1 {
		t.Fatalf("len(IngressConfig.Rules) = %d, want 1", len(state.IngressConfig.Rules))
	}
	rule := state.IngressConfig.Rules[0]
	if rule.RuleID == "" {
		t.Error("IngressConfig.Rules[0].RuleID is empty")
	}
	if rule.ListenPort == 0 {
		t.Error("IngressConfig.Rules[0].ListenPort = 0")
	}
	if rule.TargetAddr == "" {
		t.Error("IngressConfig.Rules[0].TargetAddr is empty")
	}
	if rule.Mode == "" {
		t.Error("IngressConfig.Rules[0].Mode is empty")
	}
}

func TestState_ReturnsSiteToSiteConfig(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.SiteToSiteConfig == nil {
		t.Fatal("SiteToSiteConfig is nil")
	}
	if !state.SiteToSiteConfig.Enabled {
		t.Error("SiteToSiteConfig.Enabled = false, want true")
	}
	if len(state.SiteToSiteConfig.Tunnels) != 1 {
		t.Fatalf("len(SiteToSiteConfig.Tunnels) = %d, want 1", len(state.SiteToSiteConfig.Tunnels))
	}
	tunnel := state.SiteToSiteConfig.Tunnels[0]
	if tunnel.TunnelID == "" {
		t.Error("SiteToSiteConfig.Tunnels[0].TunnelID is empty")
	}
	if tunnel.RemoteEndpoint == "" {
		t.Error("SiteToSiteConfig.Tunnels[0].RemoteEndpoint is empty")
	}
	if tunnel.RemotePublicKey == "" {
		t.Error("SiteToSiteConfig.Tunnels[0].RemotePublicKey is empty")
	}
	if len(tunnel.LocalSubnets) == 0 {
		t.Error("SiteToSiteConfig.Tunnels[0].LocalSubnets is empty")
	}
	if len(tunnel.RemoteSubnets) == 0 {
		t.Error("SiteToSiteConfig.Tunnels[0].RemoteSubnets is empty")
	}
	if tunnel.InterfaceName == "" {
		t.Error("SiteToSiteConfig.Tunnels[0].InterfaceName is empty")
	}
	if tunnel.ListenPort == 0 {
		t.Error("SiteToSiteConfig.Tunnels[0].ListenPort = 0")
	}
}

func TestState_ReturnsDataEntries(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if len(state.Data) != 2 {
		t.Fatalf("len(Data) = %d, want 2", len(state.Data))
	}

	keys := map[string]bool{}
	for _, d := range state.Data {
		keys[d.Key] = true
		if d.ContentType == "" {
			t.Errorf("Data entry %q has empty ContentType", d.Key)
		}
		if len(d.Payload) == 0 {
			t.Errorf("Data entry %q has empty Payload", d.Key)
		}
		if d.Version == 0 {
			t.Errorf("Data entry %q has Version 0", d.Key)
		}
		if d.UpdatedAt.IsZero() {
			t.Errorf("Data entry %q has zero UpdatedAt", d.Key)
		}
	}
	if !keys["app/config"] {
		t.Error("Data missing key 'app/config'")
	}
	if !keys["certs/ca"] {
		t.Error("Data missing key 'certs/ca'")
	}
}

func TestState_ReturnsSecretRefs(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if len(state.SecretRefs) != 2 {
		t.Fatalf("len(SecretRefs) = %d, want 2", len(state.SecretRefs))
	}

	keys := map[string]bool{}
	for _, sr := range state.SecretRefs {
		keys[sr.Key] = true
		if sr.Version == 0 {
			t.Errorf("SecretRef %q has Version 0", sr.Key)
		}
	}
	if !keys["db-password"] {
		t.Error("SecretRefs missing key 'db-password'")
	}
	if !keys["tls-private-key"] {
		t.Error("SecretRefs missing key 'tls-private-key'")
	}
}

func TestInjectEvent_NoClients_Succeeds(t *testing.T) {
	_, ts := newTestServer(t)

	envJSON, _ := json.Marshal(makeEnvelope("no_clients_test", "evt-noclient-001", json.RawMessage(`{}`)))
	resp := doRequest(t, http.MethodPost, ts.URL+"/test/inject-event", string(envJSON))
	defer resp.Body.Close()

	// Should succeed even with no connected clients.
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestBroadcastSSE_Programmatic(t *testing.T) {
	srv := mockapi.New()
	srv.KeepAliveInterval = 10 * time.Second
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Connect an SSE client.
	resp := connectSSE(t, ts.URL, "node-1", 5*time.Second)
	defer resp.Body.Close()

	// Consume initial event.
	readSSEEvent(t, resp.Body, 3*time.Second)

	// Use the Go API directly instead of the HTTP endpoint.
	srv.BroadcastSSE(makeEnvelope("programmatic_test", "evt-prog-001", json.RawMessage(`{"via":"go_api"}`)))

	// Read the broadcast event.
	evt := readSSEEvent(t, resp.Body, 3*time.Second)
	if !strings.Contains(evt, "programmatic_test") {
		t.Errorf("expected programmatic_test event, got: %q", evt)
	}
	if !strings.Contains(evt, "evt-prog-001") {
		t.Errorf("expected event ID evt-prog-001, got: %q", evt)
	}
}

// ---------------------------------------------------------------------------
// SetState / GetState (Task 1.2)
// ---------------------------------------------------------------------------

func TestSetState_UpdatesStateResponse(t *testing.T) {
	srv, ts := newTestServer(t)

	newState := api.StateResponse{
		Peers: []api.Peer{
			{
				ID:         "peer-new",
				PublicKey:  "new-pub-key",
				MeshIP:     "10.99.1.1",
				Endpoint:   "198.51.100.1:51820",
				AllowedIPs: []string{"10.99.1.1/32"},
				PSK:        "new-psk",
			},
		},
		Policies:   []api.Policy{},
		Metadata:   map[string]string{"env": "updated"},
		Data:       []api.DataEntry{},
		SecretRefs: []api.SecretRef{},
	}
	srv.SetState(newState)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()

	var got api.StateResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(got.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(got.Peers))
	}
	if got.Peers[0].ID != "peer-new" {
		t.Errorf("Peers[0].ID = %q, want %q", got.Peers[0].ID, "peer-new")
	}
	if got.Metadata["env"] != "updated" {
		t.Errorf("Metadata[env] = %q, want %q", got.Metadata["env"], "updated")
	}
}

func TestSetState_ViaHTTP(t *testing.T) {
	_, ts := newTestServer(t)

	newState := api.StateResponse{
		Peers: []api.Peer{
			{
				ID:         "peer-http",
				PublicKey:  "http-pub-key",
				MeshIP:     "10.99.2.1",
				Endpoint:   "198.51.100.2:51820",
				AllowedIPs: []string{"10.99.2.1/32"},
				PSK:        "http-psk",
			},
		},
		Policies:   []api.Policy{},
		Metadata:   map[string]string{"source": "http"},
		Data:       []api.DataEntry{},
		SecretRefs: []api.SecretRef{},
	}
	body, err := json.Marshal(newState)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp := doRequest(t, http.MethodPut, ts.URL+"/test/state", string(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("PUT /test/state status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Now GET state and verify the update.
	getResp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer getResp.Body.Close()

	var got api.StateResponse
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(got.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(got.Peers))
	}
	if got.Peers[0].ID != "peer-http" {
		t.Errorf("Peers[0].ID = %q, want %q", got.Peers[0].ID, "peer-http")
	}
}

func TestSetState_DefaultMatchesOriginal(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()

	var state api.StateResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Check peers match original fixture.
	if len(state.Peers) != 2 {
		t.Fatalf("len(Peers) = %d, want 2", len(state.Peers))
	}
	if state.Peers[0].ID != "peer-001" {
		t.Errorf("Peers[0].ID = %q, want %q", state.Peers[0].ID, "peer-001")
	}
	if state.Peers[1].ID != "peer-002" {
		t.Errorf("Peers[1].ID = %q, want %q", state.Peers[1].ID, "peer-002")
	}

	// Check policies.
	if len(state.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(state.Policies))
	}
	if state.Policies[0].ID != "policy-001" {
		t.Errorf("Policies[0].ID = %q, want %q", state.Policies[0].ID, "policy-001")
	}
	if len(state.Policies[0].Rules) != 2 {
		t.Errorf("len(Rules) = %d, want 2", len(state.Policies[0].Rules))
	}

	// Check metadata.
	if state.Metadata["environment"] != "e2e-test" {
		t.Errorf("Metadata[environment] = %q, want %q", state.Metadata["environment"], "e2e-test")
	}
	if state.Metadata["region"] != "mock-region-1" {
		t.Errorf("Metadata[region] = %q, want %q", state.Metadata["region"], "mock-region-1")
	}

	// Check rich config fields are present (from expanded fixture).
	if state.SigningKeys == nil {
		t.Error("SigningKeys is nil")
	}
	if state.BridgeConfig == nil {
		t.Error("BridgeConfig is nil")
	}
	if state.RelayConfig == nil {
		t.Error("RelayConfig is nil")
	}
	if state.UserAccessConfig == nil {
		t.Error("UserAccessConfig is nil")
	}
	if state.IngressConfig == nil {
		t.Error("IngressConfig is nil")
	}
	if state.SiteToSiteConfig == nil {
		t.Error("SiteToSiteConfig is nil")
	}

	// Data and SecretRefs should have entries.
	if len(state.Data) != 2 {
		t.Errorf("len(Data) = %d, want 2", len(state.Data))
	}
	if len(state.SecretRefs) != 2 {
		t.Errorf("len(SecretRefs) = %d, want 2", len(state.SecretRefs))
	}
}

func TestGetState_ReturnsCopy(t *testing.T) {
	srv, _ := newTestServer(t)

	state1 := srv.GetState()
	state1.Metadata["mutated"] = "yes"

	state2 := srv.GetState()
	if _, ok := state2.Metadata["mutated"]; ok {
		t.Error("GetState returned a reference instead of a copy: mutating the result affected server state")
	}
}

func TestSetState_ConcurrentSafe(t *testing.T) {
	srv, ts := newTestServer(t)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n * 2) // n writers + n readers

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			srv.SetState(api.StateResponse{
				Peers: []api.Peer{
					{ID: fmt.Sprintf("peer-%d", i), PublicKey: "pk", MeshIP: "10.0.0.1",
						Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.0.0.1/32"}, PSK: "psk"},
				},
				Data:       []api.DataEntry{},
				SecretRefs: []api.SecretRef{},
			})
		}(i)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
			if err != nil {
				return
			}
			resp.Body.Close()
		}()
	}

	wg.Wait()
}

func TestSetState_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPut, ts.URL+"/test/state", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestSetState_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/test/state")
	if err != nil {
		t.Fatalf("GET /test/state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// POST /test/configure-state (REQ-003)
// ---------------------------------------------------------------------------

func TestConfigureState_ReplacesActiveFixture(t *testing.T) {
	_, ts := newTestServer(t)

	customState := api.StateResponse{
		Peers: []api.Peer{{
			ID:        "custom-peer",
			PublicKey: "custom-key",
			MeshIP:    "10.0.0.99",
		}},
		Metadata: map[string]string{"env": "custom"},
	}
	body, err := json.Marshal(customState)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", string(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /test/configure-state status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Verify GET /v1/nodes/{id}/state returns the custom state.
	stateResp := doRequest(t, http.MethodGet, ts.URL+"/v1/nodes/node-1/state", "")
	defer stateResp.Body.Close()
	var got api.StateResponse
	if err := json.NewDecoder(stateResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(got.Peers) != 1 || got.Peers[0].ID != "custom-peer" {
		t.Errorf("peers = %v, want 1 peer with ID custom-peer", got.Peers)
	}
	if got.Metadata["env"] != "custom" {
		t.Errorf("metadata[env] = %q, want %q", got.Metadata["env"], "custom")
	}
}

func TestConfigureState_InvalidJSON_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestConfigureState_CounterStillIncrements(t *testing.T) {
	_, ts := newTestServer(t)

	// Configure a custom state.
	customState := api.StateResponse{
		Peers:    []api.Peer{{ID: "p1", PublicKey: "k1", MeshIP: "10.0.0.1"}},
		Metadata: map[string]string{"test": "counter"},
	}
	body, _ := json.Marshal(customState)
	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", string(body))
	resp.Body.Close()

	// Call GET /v1/nodes/{id}/state twice.
	for i := 0; i < 2; i++ {
		r := doRequest(t, http.MethodGet, ts.URL+"/v1/nodes/node-1/state", "")
		r.Body.Close()
	}

	a := getAssertions(t, ts.URL)
	if a.StateCount != 2 {
		t.Errorf("state_count = %d, want 2", a.StateCount)
	}
}

func TestConfigureState_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/test/configure-state")
	if err != nil {
		t.Fatalf("GET /test/configure-state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestConfigureState_CapturesRequestBody(t *testing.T) {
	_, ts := newTestServer(t)

	customState := api.StateResponse{
		Metadata: map[string]string{"capture": "test"},
	}
	body, err := json.Marshal(customState)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", string(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /test/configure-state status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	captured := getCapturedBody(t, ts.URL, "configure_state")
	if string(captured) != string(body) {
		t.Errorf("captured body = %q, want %q", string(captured), string(body))
	}
}

func TestSetState_PutCapturesRequestBody(t *testing.T) {
	_, ts := newTestServer(t)

	customState := api.StateResponse{
		Metadata: map[string]string{"put-capture": "test"},
	}
	body, err := json.Marshal(customState)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp := doRequest(t, http.MethodPut, ts.URL+"/test/state", string(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /test/state status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Both PUT /test/state and POST /test/configure-state share the same capture key.
	captured := getCapturedBody(t, ts.URL, "configure_state")
	if string(captured) != string(body) {
		t.Errorf("captured body = %q, want %q", string(captured), string(body))
	}
}

// ---------------------------------------------------------------------------
// Concurrency: inject-event + configure-state (Task 3.5, REQ-009)
// ---------------------------------------------------------------------------

func TestConcurrent_InjectEventAndConfigureState(t *testing.T) {
	srv := mockapi.New()
	srv.KeepAliveInterval = 10 * time.Second
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Connect an SSE client so BroadcastSSE has a target.
	sseResp := connectSSE(t, ts.URL, "node-1", 10*time.Second)
	defer sseResp.Body.Close()

	// Drain the initial event.
	readSSEEvent(t, sseResp.Body, 3*time.Second)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n * 3) // n inject-event + n configure-state + n state-reads

	// Concurrent inject-event calls.
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			env := api.SignedEnvelope{
				EventType: "concurrent_test",
				EventID:   fmt.Sprintf("evt-conc-%d", i),
				Nonce:     fmt.Sprintf("nonce-conc-%d", i),
				Payload:   json.RawMessage(`{"i":` + fmt.Sprint(i) + `}`),
				Signature: "sig",
			}
			body, _ := json.Marshal(env)
			resp := doRequest(t, http.MethodPost, ts.URL+"/test/inject-event", string(body))
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("inject #%d: status = %d, want %d", i, resp.StatusCode, http.StatusNoContent)
			}
		}(i)
	}

	// Concurrent configure-state calls.
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			state := api.StateResponse{
				Peers: []api.Peer{{
					ID:        fmt.Sprintf("conc-peer-%d", i),
					PublicKey: "pk",
					MeshIP:    fmt.Sprintf("10.0.%d.1", i%256),
				}},
			}
			body, _ := json.Marshal(state)
			resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", string(body))
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("configure-state #%d: status = %d, want %d", i, resp.StatusCode, http.StatusNoContent)
			}
		}(i)
	}

	// Concurrent state reads.
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("state read: status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
		}()
	}

	wg.Wait()

	// All inject-event calls should have been counted.
	a := getAssertions(t, ts.URL)
	if a.InjectEventCount != int64(n) {
		t.Errorf("inject_event_count = %d, want %d", a.InjectEventCount, n)
	}
	// State reads should be at least n (concurrent readers) plus any from configure-state.
	if a.StateCount < int64(n) {
		t.Errorf("state_count = %d, want >= %d", a.StateCount, n)
	}
}

// ---------------------------------------------------------------------------
// POST /test/configure-heartbeat
// ---------------------------------------------------------------------------

func TestConfigureHeartbeat_UpdatesResponse(t *testing.T) {
	_, ts := newTestServer(t)

	// Default heartbeat response should have Reconcile=true, RotateKeys=false.
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/heartbeat", heartbeatBody)
	defer resp.Body.Close()
	var hb api.HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !hb.Reconcile {
		t.Errorf("default Reconcile = false, want true")
	}
	if hb.RotateKeys {
		t.Errorf("default RotateKeys = true, want false")
	}

	// Configure heartbeat to return RotateKeys=true.
	configBody := `{"reconcile":true,"rotate_keys":true}`
	cfgResp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-heartbeat", configBody)
	defer cfgResp.Body.Close()
	if cfgResp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /test/configure-heartbeat status = %d, want %d", cfgResp.StatusCode, http.StatusNoContent)
	}

	// Verify heartbeat response changed.
	resp2 := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/heartbeat", heartbeatBody)
	defer resp2.Body.Close()
	var hb2 api.HeartbeatResponse
	if err := json.NewDecoder(resp2.Body).Decode(&hb2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !hb2.RotateKeys {
		t.Errorf("RotateKeys = false after configure, want true")
	}
	if !hb2.Reconcile {
		t.Errorf("Reconcile = false after configure, want true")
	}
}

func TestConfigureHeartbeat_InvalidBody(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-heartbeat", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /test/configure-heartbeat with invalid body: status = %d, want %d",
			resp.StatusCode, http.StatusBadRequest)
	}
}

func TestConfigureHeartbeat_WrongMethod(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/test/configure-heartbeat")
	if err != nil {
		t.Fatalf("GET /test/configure-heartbeat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /test/configure-heartbeat: status = %d, want %d",
			resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestConfigureHeartbeat_ResetToDefault(t *testing.T) {
	_, ts := newTestServer(t)

	// Set RotateKeys=true.
	cfgResp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-heartbeat",
		`{"reconcile":true,"rotate_keys":true}`)
	defer cfgResp.Body.Close()

	// Reset to default.
	resetResp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-heartbeat",
		`{"reconcile":true,"rotate_keys":false}`)
	defer resetResp.Body.Close()

	// Verify heartbeat is back to default.
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/heartbeat", heartbeatBody)
	defer resp.Body.Close()
	var hb api.HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hb.RotateKeys {
		t.Errorf("RotateKeys = true after reset, want false")
	}
}

func TestConfigureHeartbeat_CapturesRequestBody(t *testing.T) {
	srv, ts := newTestServer(t)

	body := `{"reconcile":false,"rotate_keys":true}`
	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-heartbeat", body)
	defer resp.Body.Close()

	data, ok := srv.LastRequestBody("configure_heartbeat")
	if !ok {
		t.Fatal("no captured configure_heartbeat body")
	}
	if string(data) != body {
		t.Errorf("captured body = %q, want %q", string(data), body)
	}
}
