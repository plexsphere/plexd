package mockapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nodeapi"
	"github.com/plexsphere/plexd/test/e2e/mockapi"
)

func newTestServer(t *testing.T) (*mockapi.Server, *httptest.Server) {
	t.Helper()
	srv := mockapi.New()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// Register contract fixtures (issue #18). These mirror the mock's unexported
// constants; the mock package is imported as an external test package.
const (
	testMockProjectID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0"
	testMockNodeID    = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"
	testNodeToken     = "psb_test_e2eproject_node_aaaaaaaaaaaaaaaaaaaaaa"
	testValidPubKey   = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

// registerBody is a valid new-contract JSON body for POST /v1/register.
const registerBody = `{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"edge-router-01","bootstrap_token":"psb_test_e2eproject_node_aaaaaaaaaaaaaaaaaaaaaa","nonce":"11111111-1111-4111-8111-111111111111","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}`

// nonceCounter yields unique nonces for register tests that need distinct ones.
var nonceCounter atomic.Uint64

// freshNonce returns a unique, canonically-shaped UUID nonce.
func freshNonce() string {
	n := nonceCounter.Add(1)
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", n, n)
}

// validRegisterFields returns a mutable map of valid register request fields,
// including a fresh nonce.
func validRegisterFields() map[string]any {
	return map[string]any{
		"project_id":      testMockProjectID,
		"resource_handle": "edge-router-01",
		"bootstrap_token": testNodeToken,
		"nonce":           freshNonce(),
		"public_key":      testValidPubKey,
	}
}

// validHexChecksum is a shape-valid 64-char lowercase hex SHA-256 digest.
var validHexChecksum = strings.Repeat("ab", 32)

// validHeartbeatBody builds a contract-valid heartbeat request body with a
// fresh client_now so it never trips the mock's clock-skew check. nat_summary
// is an empty object, matching what the agent sends before NAT discovery.
func validHeartbeatBody() string {
	return fmt.Sprintf(
		`{"client_now":%q,"binary_checksum":%q,"binary_version":"1.2.3","nat_summary":{}}`,
		time.Now().UTC().Format(time.RFC3339),
		validHexChecksum,
	)
}

// validEndpointBody builds a contract-valid endpoint request body with a fresh
// reported_at so it never trips the mock's clock-skew check.
func validEndpointBody() string {
	return fmt.Sprintf(
		`{"endpoint":"203.0.113.10:51820","nat_type":"full_cone","reported_at":%q}`,
		time.Now().UTC().Format(time.RFC3339),
	)
}

// Test body constants for new endpoints.
const (
	keyRotateBody          = `{"node_id":"node-1","new_public_key":"new-pk-abc"}`
	capabilitiesBody       = `{"builtin_actions":[],"hooks":[]}`
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

// localCounterFields contains the JSON field names of local endpoint counters
// that are only incremented via the TLS handler (not the main HTTP mux).
var localCounterFields = map[string]bool{
	"LocalMetricsCount": true,
	"LocalLogsCount":    true,
	"LocalAuditCount":   true,
}

// assertAllCountersEqual checks that every field in the AssertionCounters struct
// equals the expected value. Useful for InitialZero and ConcurrentCounters tests.
// Fields in localCounterFields are excluded from this check when want != 0
// because they are only incremented via the TLS handler.
func assertAllCountersEqual(t *testing.T, a mockapi.AssertionCounters, want int64) {
	t.Helper()
	v := reflect.ValueOf(a)
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		name := typ.Field(i).Name
		if want != 0 && localCounterFields[name] {
			continue
		}
		got := v.Field(i).Int()
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
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

	// Call register twice with fresh nonces (each nonce is single-use).
	for i := 0; i < 2; i++ {
		body, err := json.Marshal(validRegisterFields())
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		resp, err := http.Post(ts.URL+"/v1/register", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("POST /v1/register #%d: %v", i+1, err)
		}

		if resp.StatusCode != http.StatusCreated {
			resp.Body.Close()
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
		}

		var reg api.RegisterResponse
		if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
			resp.Body.Close()
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()

		// Verify every response field on the first call.
		if i == 0 {
			if reg.NodeID != testMockNodeID {
				t.Errorf("NodeID = %q, want %q", reg.NodeID, testMockNodeID)
			}
			if reg.MeshIP != "10.99.0.1" {
				t.Errorf("MeshIP = %q, want %q", reg.MeshIP, "10.99.0.1")
			}
			if reg.SigningPublicKey == "" {
				t.Error("SigningPublicKey is empty")
			}
			if reg.SigningKeyID != "did:web:plexsphere.com#key-e2e" {
				t.Errorf("SigningKeyID = %q, want %q", reg.SigningKeyID, "did:web:plexsphere.com#key-e2e")
			}
			if len(reg.NSK) != 44 {
				t.Errorf("len(NSK) = %d, want 44 (standard-padded base64)", len(reg.NSK))
			}
			if reg.DomainMeshCIDR != "10.99.0.0/24" {
				t.Errorf("DomainMeshCIDR = %q, want %q", reg.DomainMeshCIDR, "10.99.0.0/24")
			}
			if len(reg.PeerSnapshot) != 2 {
				t.Fatalf("len(PeerSnapshot) = %d, want 2", len(reg.PeerSnapshot))
			}
			for _, p := range reg.PeerSnapshot {
				if p.NodeID == "" || p.PublicKey == "" || p.MeshIP == "" {
					t.Errorf("peer %q has empty required fields", p.NodeID)
				}
			}
			// The first peer has a fallback endpoint; the second does not.
			if reg.PeerSnapshot[0].FallbackEndpoint == "" {
				t.Error("PeerSnapshot[0].FallbackEndpoint is empty, want set")
			}
			if reg.PeerSnapshot[1].FallbackEndpoint != "" {
				t.Errorf("PeerSnapshot[1].FallbackEndpoint = %q, want empty", reg.PeerSnapshot[1].FallbackEndpoint)
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
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
	}
}

func TestRegister_DenialTaxonomy(t *testing.T) {
	longStr := strings.Repeat("a", 4097)
	// 43 'A' + '=' decodes to 32 zero bytes: a shape-valid but forbidden key.
	zeroKey := strings.Repeat("A", 43) + "="

	tests := []struct {
		name       string
		rawBody    string // used verbatim when non-empty (undecodable body case)
		mutate     func(map[string]any)
		wantStatus int
		wantCode   string // "" means the code member must be absent
	}{
		{name: "invalid_body", rawBody: "not-json", wantStatus: http.StatusBadRequest},
		{name: "empty_bootstrap_token", mutate: func(m map[string]any) { m["bootstrap_token"] = "" }, wantStatus: http.StatusUnprocessableEntity},
		{name: "empty_nonce", mutate: func(m map[string]any) { m["nonce"] = "" }, wantStatus: http.StatusUnprocessableEntity},
		{name: "empty_resource_handle", mutate: func(m map[string]any) { m["resource_handle"] = "" }, wantStatus: http.StatusUnprocessableEntity},
		{name: "zero_project_id", mutate: func(m map[string]any) { m["project_id"] = "00000000-0000-0000-0000-000000000000" }, wantStatus: http.StatusUnprocessableEntity},
		{name: "non_uuid_project_id", mutate: func(m map[string]any) { m["project_id"] = "not-a-uuid" }, wantStatus: http.StatusUnprocessableEntity},
		{name: "field_too_long", mutate: func(m map[string]any) { m["requested_resource_id"] = longStr }, wantStatus: http.StatusUnprocessableEntity},
		{name: "public_key_bad_shape", mutate: func(m map[string]any) { m["public_key"] = "short" }, wantStatus: http.StatusBadRequest, wantCode: "public_key_invalid"},
		{name: "public_key_all_zero", mutate: func(m map[string]any) { m["public_key"] = zeroKey }, wantStatus: http.StatusBadRequest, wantCode: "public_key_invalid"},
		{name: "malformed_token", mutate: func(m map[string]any) { m["bootstrap_token"] = "not-a-psb-token" }, wantStatus: http.StatusForbidden},
		{name: "kind_mismatch", mutate: func(m map[string]any) { m["bootstrap_token"] = "psb_test_e2eproject_bridge_aaaaaaaaaaaaaaaaaaaaaa" }, wantStatus: http.StatusForbidden, wantCode: "kind_mismatch"},
		{name: "token_consumed", mutate: func(m map[string]any) { m["bootstrap_token"] = "psb_test_e2eproject_node_consumedaaaaaaaaaaaaaa" }, wantStatus: http.StatusForbidden, wantCode: "token_consumed"},
		{name: "token_expired", mutate: func(m map[string]any) { m["bootstrap_token"] = "psb_test_e2eproject_node_expiredaaaaaaaaaaaaaaa" }, wantStatus: http.StatusForbidden, wantCode: "token_expired"},
		{name: "token_revoked", mutate: func(m map[string]any) { m["bootstrap_token"] = "psb_test_e2eproject_node_revokedaaaaaaaaaaaaaaa" }, wantStatus: http.StatusForbidden, wantCode: "token_revoked"},
		{name: "project_mismatch", mutate: func(m map[string]any) { m["project_id"] = "11111111-1111-1111-1111-111111111111" }, wantStatus: http.StatusForbidden, wantCode: "project_mismatch"},
		{name: "resource_not_found", mutate: func(m map[string]any) { m["resource_handle"] = "unknown-resource" }, wantStatus: http.StatusNotFound, wantCode: "resource_not_found"},
		{name: "pool_exhausted", mutate: func(m map[string]any) { m["resource_handle"] = "exhausted-pool" }, wantStatus: http.StatusServiceUnavailable, wantCode: "pool_exhausted"},
		{name: "subrange_exhausted", mutate: func(m map[string]any) { m["resource_handle"] = "exhausted-subrange" }, wantStatus: http.StatusServiceUnavailable, wantCode: "subrange_exhausted"},
		{name: "allocator_contention", mutate: func(m map[string]any) { m["resource_handle"] = "contended-allocator" }, wantStatus: http.StatusServiceUnavailable, wantCode: "allocator_contention"},
		{name: "boom_internal", mutate: func(m map[string]any) { m["resource_handle"] = "boom-internal" }, wantStatus: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			body := tt.rawBody
			if body == "" {
				m := validRegisterFields()
				if tt.mutate != nil {
					tt.mutate(m)
				}
				b, err := json.Marshal(m)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				body = string(b)
			}

			resp := doRequest(t, http.MethodPost, ts.URL+"/v1/register", body)
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
			}

			var problem map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			// RFC 9457 required members.
			for _, member := range []string{"type", "title", "status", "detail", "instance"} {
				if _, ok := problem[member]; !ok {
					t.Errorf("problem missing required member %q", member)
				}
			}
			if tt.wantCode == "" {
				if _, ok := problem["code"]; ok {
					t.Errorf("problem should omit code member, got %v", problem["code"])
				}
			} else if problem["code"] != tt.wantCode {
				t.Errorf("code = %v, want %q", problem["code"], tt.wantCode)
			}
		})
	}
}

func TestRegister_NonceCollision(t *testing.T) {
	_, ts := newTestServer(t)

	m := validRegisterFields()
	nonce := freshNonce()
	m["nonce"] = nonce
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// First registration with the nonce succeeds.
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/register", string(body))
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("first register status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp.Body.Close()

	// Replaying the same nonce is rejected with nonce_collision.
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/register", string(body))
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("replay status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	var problem map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	resp.Body.Close()
	if problem["code"] != "nonce_collision" {
		t.Errorf("replay code = %v, want %q", problem["code"], "nonce_collision")
	}

	// A different nonce succeeds again — only the used nonce is blocked.
	m["nonce"] = freshNonce()
	body2, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/register", string(body2))
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("fresh-nonce status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp.Body.Close()
}

func TestRegister_DeniedRequestDoesNotConsumeNonce(t *testing.T) {
	_, ts := newTestServer(t)
	nonce := freshNonce()

	// A 404 denial (unknown resource) must NOT record the nonce.
	m := validRegisterFields()
	m["nonce"] = nonce
	m["resource_handle"] = "unknown-resource"
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/register", string(body))
	if resp.StatusCode != http.StatusNotFound {
		resp.Body.Close()
		t.Fatalf("denied status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()

	// Reusing the same nonce on an otherwise-valid request now succeeds.
	m2 := validRegisterFields()
	m2["nonce"] = nonce
	body2, err := json.Marshal(m2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/register", string(body2))
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("reuse-after-denial status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp.Body.Close()
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
		resp, err := http.Post(ts.URL+"/v1/nodes/node-1/heartbeat", "application/json", strings.NewReader(validHeartbeatBody()))
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

		if hb.AcceptedAt.IsZero() {
			t.Errorf("call #%d: AcceptedAt is zero, want a fresh timestamp", i+1)
		}
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
		resp, err := http.Post(ts.URL+"/v1/nodes/"+id+"/heartbeat", "application/json", strings.NewReader(validHeartbeatBody()))
		if err != nil {
			t.Fatalf("POST heartbeat %s: %v", id, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("heartbeat %s: status = %d, want %d", id, resp.StatusCode, http.StatusOK)
		}
		resp.Body.Close()
	}
}

func TestHeartbeat_DenialTaxonomy(t *testing.T) {
	const path = "/v1/nodes/node-1/heartbeat"
	base64Checksum := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name       string
		mutate     func(map[string]any)
		wantStatus int
		wantCode   string // asserted for rejections (wantStatus != 200)
	}{
		{name: "unknown_field", mutate: func(m map[string]any) { m["surprise"] = "x" }, wantStatus: http.StatusBadRequest, wantCode: "malformed_heartbeat_request"},
		{name: "nat_summary_null", mutate: func(m map[string]any) { m["nat_summary"] = nil }, wantStatus: http.StatusBadRequest, wantCode: "malformed_heartbeat_request"},
		{name: "client_now_ahead", mutate: func(m map[string]any) { m["client_now"] = time.Now().UTC().Add(61 * time.Second).Format(time.RFC3339) }, wantStatus: http.StatusBadRequest, wantCode: "clock_skew"},
		{name: "client_now_behind", mutate: func(m map[string]any) { m["client_now"] = time.Now().UTC().Add(-61 * time.Second).Format(time.RFC3339) }, wantStatus: http.StatusBadRequest, wantCode: "clock_skew"},
		{name: "malformed_checksum", mutate: func(m map[string]any) { m["binary_checksum"] = "zz" }, wantStatus: http.StatusBadRequest, wantCode: "binary_checksum_empty"},
		{name: "blank_version", mutate: func(m map[string]any) { m["binary_version"] = "   " }, wantStatus: http.StatusBadRequest, wantCode: "binary_version_empty"},
		// Both checksum wire forms are accepted.
		{name: "base64_checksum_accepted", mutate: func(m map[string]any) { m["binary_checksum"] = base64Checksum }, wantStatus: http.StatusOK},
		{name: "fully_valid", mutate: nil, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			m := map[string]any{
				"client_now":      time.Now().UTC().Format(time.RFC3339),
				"binary_checksum": validHexChecksum,
				"binary_version":  "1.2.3",
				"nat_summary":     map[string]any{},
			}
			if tt.mutate != nil {
				tt.mutate(m)
			}
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			resp := doRequest(t, http.MethodPost, ts.URL+path, string(body))
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				var hb api.HeartbeatResponse
				if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
					t.Fatalf("decode: %v", err)
				}
				if hb.AcceptedAt.IsZero() {
					t.Error("AcceptedAt is zero, want a fresh timestamp")
				}
				if !hb.Reconcile || hb.RotateKeys {
					t.Errorf("flags = {Reconcile:%v RotateKeys:%v}, want {true false}", hb.Reconcile, hb.RotateKeys)
				}
				return
			}

			if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
			}
			var problem map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			for _, member := range []string{"type", "title", "status", "detail", "instance"} {
				if _, ok := problem[member]; !ok {
					t.Errorf("problem missing required member %q", member)
				}
			}
			if problem["code"] != tt.wantCode {
				t.Errorf("code = %v, want %q", problem["code"], tt.wantCode)
			}
			if problem["instance"] != path {
				t.Errorf("instance = %v, want %q", problem["instance"], path)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// REQ-004: GET /v1/nodes/{id}/state (Task 2.4)
// ---------------------------------------------------------------------------

// policyFingerprint mirrors the mock's MOCK-INTERNAL canonicalization so the
// test can assert the served policy.fingerprint equals base64(sha256(compact
// JSON of the rules)). plexd itself never re-derives it — this is test-only.
func policyFingerprint(t *testing.T, rules []api.PolicyRule) string {
	t.Helper()
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestState_ReturnsPeersAndPolicy(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Capture the raw envelope so we can assert on exact JSON keys.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// All six envelope keys must be present, even when a block is unpopulated.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	for _, key := range []string{"peers", "reachability", "policy", "bridge", "state", "reports"} {
		if _, ok := envelope[key]; !ok {
			t.Errorf("envelope missing key %q", key)
		}
	}

	// The peers JSON must never carry psk/allowed_ips/endpoint.
	for _, forbidden := range []string{`"psk"`, `"allowed_ips"`, `"endpoint"`} {
		if bytes.Contains(envelope["peers"], []byte(forbidden)) {
			t.Errorf("peers JSON must not contain %s: %s", forbidden, envelope["peers"])
		}
	}

	var state api.NodeStateSnapshot
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Peers: exactly two, node_id ascending, with 44-char base64 keys.
	if len(state.Peers) != 2 {
		t.Fatalf("len(Peers) = %d, want 2", len(state.Peers))
	}
	if state.Peers[0].NodeID >= state.Peers[1].NodeID {
		t.Errorf("peers not node_id ascending: %q, %q", state.Peers[0].NodeID, state.Peers[1].NodeID)
	}
	for _, p := range state.Peers {
		if p.NodeID == "" || p.PublicKey == "" || p.MeshIP == "" {
			t.Errorf("peer %q has empty required fields", p.NodeID)
		}
		if len(p.PublicKey) != 44 {
			t.Errorf("peer %q public key len = %d, want 44 (base64)", p.NodeID, len(p.PublicKey))
		}
	}

	// Policy: one merged block; the fingerprint is the base64 SHA-256 of the rules.
	if state.Policy == nil {
		t.Fatal("Policy is nil")
	}
	if len(state.Policy.Rules) != 2 {
		t.Fatalf("len(Policy.Rules) = %d, want 2", len(state.Policy.Rules))
	}
	if want := policyFingerprint(t, state.Policy.Rules); state.Policy.Fingerprint != want {
		t.Errorf("policy.fingerprint = %q, want %q", state.Policy.Fingerprint, want)
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
		resp, err := http.Post(ts.URL+"/v1/nodes/n1/heartbeat", "application/json", strings.NewReader(validHeartbeatBody()))
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
	resp = doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/n1/endpoint", validEndpointBody())
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
		{http.MethodPost, "/v1/nodes/node-1/heartbeat", validHeartbeatBody()},
		{http.MethodGet, "/v1/nodes/node-1/state", ""},
		{http.MethodGet, "/v1/nodes/node-1/metadata", ""},
		{http.MethodPost, "/v1/nodes/node-1/deregister", ""},
		{http.MethodPost, "/v1/keys/rotate", keyRotateBody},
		{http.MethodPut, "/v1/nodes/node-1/capabilities", capabilitiesBody},
		{http.MethodPut, "/v1/nodes/node-1/endpoint", validEndpointBody()},
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

	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/endpoint", validEndpointBody())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var er api.EndpointResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if er.AcceptedAt.IsZero() {
		t.Error("AcceptedAt is zero, want a fresh timestamp")
	}
	if er.StaleAfter.IsZero() {
		t.Error("StaleAfter is zero, want a deadline")
	}
	if !er.StaleAfter.After(er.AcceptedAt) {
		t.Errorf("StaleAfter %v, want after AcceptedAt %v", er.StaleAfter, er.AcceptedAt)
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
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
	}
	var problem map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem["code"] != "malformed_endpoint_request" {
		t.Errorf("code = %v, want %q", problem["code"], "malformed_endpoint_request")
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

func TestEndpoint_DenialTaxonomy(t *testing.T) {
	const path = "/v1/nodes/node-1/endpoint"

	tests := []struct {
		name       string
		mutate     func(map[string]any)
		wantStatus int
		wantCode   string // asserted for rejections (wantStatus != 200)
	}{
		// The oversized body must expand a KNOWN field so strict decoding is not
		// what trips first — the 4 KiB cap is.
		{name: "body_too_large", mutate: func(m map[string]any) { m["endpoint"] = strings.Repeat("a", 5000) }, wantStatus: http.StatusRequestEntityTooLarge, wantCode: "endpoint_body_too_large"},
		{name: "unknown_field", mutate: func(m map[string]any) { m["surprise"] = "x" }, wantStatus: http.StatusBadRequest, wantCode: "malformed_endpoint_request"},
		{name: "nat_type_outside_enum", mutate: func(m map[string]any) { m["nat_type"] = "cone" }, wantStatus: http.StatusBadRequest, wantCode: "malformed_endpoint_request"},
		{name: "reported_at_skew", mutate: func(m map[string]any) { m["reported_at"] = time.Now().UTC().Add(61 * time.Second).Format(time.RFC3339) }, wantStatus: http.StatusBadRequest, wantCode: "endpoint_clock_skew"},
		{name: "loopback_host", mutate: func(m map[string]any) { m["endpoint"] = "127.0.0.1:51820" }, wantStatus: http.StatusBadRequest, wantCode: "endpoint_unparseable"},
		{name: "link_local_host", mutate: func(m map[string]any) { m["endpoint"] = "169.254.10.9:51820" }, wantStatus: http.StatusBadRequest, wantCode: "endpoint_unparseable"},
		{name: "unspecified_host", mutate: func(m map[string]any) { m["endpoint"] = "0.0.0.0:51820" }, wantStatus: http.StatusBadRequest, wantCode: "endpoint_unparseable"},
		{name: "zero_port", mutate: func(m map[string]any) { m["endpoint"] = "203.0.113.5:0" }, wantStatus: http.StatusBadRequest, wantCode: "endpoint_unparseable"},
		{name: "portless", mutate: func(m map[string]any) { m["endpoint"] = "203.0.113.5" }, wantStatus: http.StatusBadRequest, wantCode: "endpoint_unparseable"},
		{name: "valid", mutate: nil, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			m := map[string]any{
				"endpoint":    "203.0.113.10:51820",
				"nat_type":    "full_cone",
				"reported_at": time.Now().UTC().Format(time.RFC3339),
			}
			if tt.mutate != nil {
				tt.mutate(m)
			}
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			resp := doRequest(t, http.MethodPut, ts.URL+path, string(body))
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				var er api.EndpointResponse
				if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
					t.Fatalf("decode: %v", err)
				}
				// Default TTL is 5 minutes.
				if !er.AcceptedAt.Add(5 * time.Minute).Equal(er.StaleAfter) {
					t.Errorf("stale_after = %v, want accepted_at + 5m (%v)", er.StaleAfter, er.AcceptedAt.Add(5*time.Minute))
				}
				return
			}

			if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
			}
			var problem map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			for _, member := range []string{"type", "title", "status", "detail", "instance"} {
				if _, ok := problem[member]; !ok {
					t.Errorf("problem missing required member %q", member)
				}
			}
			if problem["code"] != tt.wantCode {
				t.Errorf("code = %v, want %q", problem["code"], tt.wantCode)
			}
			if problem["instance"] != path {
				t.Errorf("instance = %v, want %q", problem["instance"], path)
			}
		})
	}
}

func TestEndpoint_ConfigureTTL(t *testing.T) {
	_, ts := newTestServer(t)

	// Configure a 40s TTL.
	cfg := doRequest(t, http.MethodPost, ts.URL+"/test/configure-endpoint", `{"ttl_seconds":40}`)
	if cfg.StatusCode != http.StatusNoContent {
		cfg.Body.Close()
		t.Fatalf("configure-endpoint status = %d, want %d", cfg.StatusCode, http.StatusNoContent)
	}
	cfg.Body.Close()

	// A subsequent report reflects the new TTL.
	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/endpoint", validEndpointBody())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("endpoint status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var er api.EndpointResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := er.StaleAfter.Sub(er.AcceptedAt); got != 40*time.Second {
		t.Errorf("stale_after - accepted_at = %v, want %v", got, 40*time.Second)
	}

	// Invalid bodies are rejected with 400.
	for _, body := range []string{`{"ttl_seconds":0}`, "garbage"} {
		bad := doRequest(t, http.MethodPost, ts.URL+"/test/configure-endpoint", body)
		if bad.StatusCode != http.StatusBadRequest {
			bad.Body.Close()
			t.Errorf("configure-endpoint(%q) status = %d, want %d", body, bad.StatusCode, http.StatusBadRequest)
			continue
		}
		bad.Body.Close()
	}

	// Wrong method is rejected with 405.
	wrong, err := http.Get(ts.URL + "/test/configure-endpoint")
	if err != nil {
		t.Fatalf("GET configure-endpoint: %v", err)
	}
	defer wrong.Body.Close()
	if wrong.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET configure-endpoint status = %d, want %d", wrong.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Drift endpoint removed (no POST /v1/nodes/{id}/drift upstream)
// ---------------------------------------------------------------------------

func TestDrift_RouteRemoved_Returns404(t *testing.T) {
	_, ts := newTestServer(t)

	// The drift route no longer exists, so a POST falls through the mux default.
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/drift", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
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

	// Send a capabilities request to capture the body.
	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/capabilities", capabilitiesBody)
	resp.Body.Close()

	// Retrieve the captured body.
	resp, err := http.Get(ts.URL + "/test/last-request/capabilities")
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
	if string(body) != capabilitiesBody {
		t.Errorf("captured body = %q, want %q", string(body), capabilitiesBody)
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

	resp := doRequest(t, http.MethodPut, ts.URL+"/v1/nodes/node-1/capabilities", capabilitiesBody)
	resp.Body.Close()

	data, ok := srv.LastRequestBody("capabilities")
	if !ok {
		t.Fatal("expected captured body")
	}
	if string(data) != capabilitiesBody {
		t.Errorf("captured body = %q, want %q", string(data), capabilitiesBody)
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

func getState(t *testing.T, baseURL string) api.NodeStateSnapshot {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var state api.NodeStateSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return state
}

func TestState_ReturnsBridgeSubtree(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.Bridge == nil {
		t.Fatal("Bridge is nil")
	}
	// The bridge subtree carries the four children.
	if state.Bridge.Relay == nil {
		t.Error("Bridge.Relay is nil")
	}
	if state.Bridge.UserAccess == nil {
		t.Error("Bridge.UserAccess is nil")
	}
	if state.Bridge.Ingress == nil {
		t.Error("Bridge.Ingress is nil")
	}
	if state.Bridge.SiteToSite == nil {
		t.Error("Bridge.SiteToSite is nil")
	}
}

func TestState_ReturnsRelayChild(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.Bridge == nil || state.Bridge.Relay == nil {
		t.Fatal("Bridge.Relay is nil")
	}
	if len(state.Bridge.Relay.Sessions) != 1 {
		t.Fatalf("len(Relay.Sessions) = %d, want 1", len(state.Bridge.Relay.Sessions))
	}
	sess := state.Bridge.Relay.Sessions[0]
	if sess.SessionID == "" {
		t.Error("Relay.Sessions[0].SessionID is empty")
	}
	if sess.PeerAID == "" || sess.PeerBID == "" {
		t.Error("Relay.Sessions[0] has empty peer IDs")
	}
	if sess.PeerAEndpoint == "" || sess.PeerBEndpoint == "" {
		t.Error("Relay.Sessions[0] has empty peer endpoints")
	}
	if sess.ExpiresAt.IsZero() {
		t.Error("Relay.Sessions[0].ExpiresAt is zero")
	}
}

func TestState_ReturnsUserAccessChild(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.Bridge == nil || state.Bridge.UserAccess == nil {
		t.Fatal("Bridge.UserAccess is nil")
	}
	ua := state.Bridge.UserAccess
	if !ua.Enabled {
		t.Error("UserAccess.Enabled = false, want true")
	}
	if ua.InterfaceName == "" {
		t.Error("UserAccess.InterfaceName is empty")
	}
	if ua.ListenPort == 0 {
		t.Error("UserAccess.ListenPort = 0")
	}
	if len(ua.Peers) != 1 {
		t.Fatalf("len(UserAccess.Peers) = %d, want 1", len(ua.Peers))
	}
	uaPeer := ua.Peers[0]
	if uaPeer.PublicKey == "" {
		t.Error("UserAccess.Peers[0].PublicKey is empty")
	}
	if len(uaPeer.AllowedIPs) == 0 {
		t.Error("UserAccess.Peers[0].AllowedIPs is empty")
	}
	if uaPeer.Label == "" {
		t.Error("UserAccess.Peers[0].Label is empty")
	}
}

func TestState_ReturnsIngressChild(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.Bridge == nil || state.Bridge.Ingress == nil {
		t.Fatal("Bridge.Ingress is nil")
	}
	ing := state.Bridge.Ingress
	if !ing.Enabled {
		t.Error("Ingress.Enabled = false, want true")
	}
	if len(ing.Rules) != 1 {
		t.Fatalf("len(Ingress.Rules) = %d, want 1", len(ing.Rules))
	}
	rule := ing.Rules[0]
	if rule.RuleID == "" {
		t.Error("Ingress.Rules[0].RuleID is empty")
	}
	if rule.ListenPort == 0 {
		t.Error("Ingress.Rules[0].ListenPort = 0")
	}
	if rule.TargetAddr == "" {
		t.Error("Ingress.Rules[0].TargetAddr is empty")
	}
	if rule.Mode == "" {
		t.Error("Ingress.Rules[0].Mode is empty")
	}
}

func TestState_ReturnsSiteToSiteChild(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.Bridge == nil || state.Bridge.SiteToSite == nil {
		t.Fatal("Bridge.SiteToSite is nil")
	}
	s2s := state.Bridge.SiteToSite
	if !s2s.Enabled {
		t.Error("SiteToSite.Enabled = false, want true")
	}
	if len(s2s.Tunnels) != 1 {
		t.Fatalf("len(SiteToSite.Tunnels) = %d, want 1", len(s2s.Tunnels))
	}
	tunnel := s2s.Tunnels[0]
	if tunnel.TunnelID == "" {
		t.Error("SiteToSite.Tunnels[0].TunnelID is empty")
	}
	if tunnel.RemoteEndpoint == "" {
		t.Error("SiteToSite.Tunnels[0].RemoteEndpoint is empty")
	}
	if tunnel.RemotePublicKey == "" {
		t.Error("SiteToSite.Tunnels[0].RemotePublicKey is empty")
	}
	if len(tunnel.LocalSubnets) == 0 {
		t.Error("SiteToSite.Tunnels[0].LocalSubnets is empty")
	}
	if len(tunnel.RemoteSubnets) == 0 {
		t.Error("SiteToSite.Tunnels[0].RemoteSubnets is empty")
	}
	if tunnel.InterfaceName == "" {
		t.Error("SiteToSite.Tunnels[0].InterfaceName is empty")
	}
	if tunnel.ListenPort == 0 {
		t.Error("SiteToSite.Tunnels[0].ListenPort = 0")
	}
}

func TestState_ReturnsStateBlockEntries(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.State == nil {
		t.Fatal("State block is nil")
	}
	if len(state.State.Data) != 2 {
		t.Fatalf("len(State.Data) = %d, want 2", len(state.State.Data))
	}

	keys := map[string]bool{}
	for _, d := range state.State.Data {
		keys[d.Key] = true
		if d.Value == "" {
			t.Errorf("State data entry %q has empty Value", d.Key)
		}
	}
	if !keys["app/config"] {
		t.Error("State data missing key 'app/config'")
	}
	if !keys["certs/ca"] {
		t.Error("State data missing key 'certs/ca'")
	}

	// Metadata bucket carries the two entries, key-ascending.
	if len(state.State.Metadata) != 2 {
		t.Fatalf("len(State.Metadata) = %d, want 2", len(state.State.Metadata))
	}
	if state.State.Metadata[0].Key >= state.State.Metadata[1].Key {
		t.Errorf("State.Metadata not key-ascending: %q, %q", state.State.Metadata[0].Key, state.State.Metadata[1].Key)
	}
}

func TestState_ReportsMirrorsState(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	if state.State == nil || state.Reports == nil {
		t.Fatal("State and Reports blocks must both be populated")
	}
	if !reflect.DeepEqual(state.State, state.Reports) {
		t.Errorf("reports block does not mirror state block:\nstate=%+v\nreports=%+v", state.State, state.Reports)
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

func TestSetState_UpdatesSnapshot(t *testing.T) {
	srv, ts := newTestServer(t)

	newState := api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{NodeID: "peer-new", PublicKey: "new-pub-key", MeshIP: "10.99.1.1", FallbackEndpoint: "198.51.100.1:51820"},
		},
		Policy: &api.PolicySnapshot{RevisionID: "rev-x", Fingerprint: "fp-x"},
	}
	srv.SetState(newState)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()

	var got api.NodeStateSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(got.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(got.Peers))
	}
	if got.Peers[0].NodeID != "peer-new" {
		t.Errorf("Peers[0].NodeID = %q, want %q", got.Peers[0].NodeID, "peer-new")
	}
	if got.Policy == nil || got.Policy.Fingerprint != "fp-x" {
		t.Errorf("Policy = %+v, want fingerprint fp-x", got.Policy)
	}
}

func TestSetState_ViaHTTP(t *testing.T) {
	_, ts := newTestServer(t)

	newState := api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{NodeID: "peer-http", PublicKey: "http-pub-key", MeshIP: "10.99.2.1", FallbackEndpoint: "198.51.100.2:51820"},
		},
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

	// Now GET state and verify the update round-tripped.
	getResp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer getResp.Body.Close()

	var got api.NodeStateSnapshot
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(got.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(got.Peers))
	}
	if got.Peers[0].NodeID != "peer-http" {
		t.Errorf("Peers[0].NodeID = %q, want %q", got.Peers[0].NodeID, "peer-http")
	}
}

func TestSetState_DefaultMatchesOriginal(t *testing.T) {
	_, ts := newTestServer(t)
	state := getState(t, ts.URL)

	// Peers mirror the register fixture, node_id ascending.
	if len(state.Peers) != 2 {
		t.Fatalf("len(Peers) = %d, want 2", len(state.Peers))
	}
	if state.Peers[0].NodeID != "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1" {
		t.Errorf("Peers[0].NodeID = %q", state.Peers[0].NodeID)
	}
	if state.Peers[1].NodeID != "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2" {
		t.Errorf("Peers[1].NodeID = %q", state.Peers[1].NodeID)
	}

	// Merged policy with two rules.
	if state.Policy == nil {
		t.Fatal("Policy is nil")
	}
	if len(state.Policy.Rules) != 2 {
		t.Errorf("len(Policy.Rules) = %d, want 2", len(state.Policy.Rules))
	}

	// Bridge subtree and its four children populated.
	if state.Bridge == nil {
		t.Fatal("Bridge is nil")
	}
	if state.Bridge.Relay == nil || state.Bridge.UserAccess == nil || state.Bridge.Ingress == nil || state.Bridge.SiteToSite == nil {
		t.Error("Bridge subtree missing a child")
	}

	// State block metadata and data entries.
	if state.State == nil {
		t.Fatal("State block is nil")
	}
	if len(state.State.Metadata) != 2 {
		t.Errorf("len(State.Metadata) = %d, want 2", len(state.State.Metadata))
	}
	if len(state.State.Data) != 2 {
		t.Errorf("len(State.Data) = %d, want 2", len(state.State.Data))
	}
}

func TestGetState_NormalizesEmptyPeers(t *testing.T) {
	srv, _ := newTestServer(t)

	// A fixture with nil peers must still return a non-nil (empty) slice so it
	// serializes as [] rather than null.
	srv.SetState(api.NodeStateSnapshot{})
	got := srv.GetState()
	if got.Peers == nil {
		t.Error("GetState().Peers is nil, want a non-nil empty slice")
	}
	if len(got.Peers) != 0 {
		t.Errorf("GetState().Peers = %v, want empty", got.Peers)
	}
}

func TestState_EmptyPeersSerializeAsArray(t *testing.T) {
	_, ts := newTestServer(t)

	// configure-state with an envelope carrying nil peers and nil blocks.
	body, err := json.Marshal(api.NodeStateSnapshot{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", string(body))
	resp.Body.Close()

	getResp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer getResp.Body.Close()
	raw, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"peers", "reachability", "policy", "bridge", "state", "reports"} {
		if _, ok := envelope[key]; !ok {
			t.Errorf("envelope missing key %q", key)
		}
	}
	// peers is [] (never null) even when emptied.
	if string(envelope["peers"]) != "[]" {
		t.Errorf("peers = %s, want [] (never null)", envelope["peers"])
	}
	// Unpopulated blocks serialize as null.
	for _, key := range []string{"policy", "bridge", "state", "reports"} {
		if string(envelope[key]) != "null" {
			t.Errorf("%s = %s, want null (unpopulated)", key, envelope[key])
		}
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
			srv.SetState(api.NodeStateSnapshot{
				Peers: []api.SnapshotPeer{
					{NodeID: fmt.Sprintf("peer-%d", i), PublicKey: "pk", MeshIP: "10.0.0.1", FallbackEndpoint: "1.2.3.4:51820"},
				},
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

	customState := api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{{
			NodeID:    "custom-peer",
			PublicKey: "custom-key",
			MeshIP:    "10.0.0.99",
		}},
		Policy: &api.PolicySnapshot{RevisionID: "rev-c", Fingerprint: "fp-c"},
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
	var got api.NodeStateSnapshot
	if err := json.NewDecoder(stateResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(got.Peers) != 1 || got.Peers[0].NodeID != "custom-peer" {
		t.Errorf("peers = %v, want 1 peer with node_id custom-peer", got.Peers)
	}
	if got.Policy == nil || got.Policy.Fingerprint != "fp-c" {
		t.Errorf("policy = %+v, want fingerprint fp-c", got.Policy)
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

func TestConfigureState_UnknownField_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	// A typo in a block key ("policies" for "policy") must not be accepted:
	// otherwise the fixture stores Policy == nil while the caller believes it
	// configured a fingerprint, and every downstream policy assertion becomes
	// indistinguishable from "no policy block at all".
	const typo = `{"peers":[],"reachability":null,"policies":{"revision_id":"rev-c","fingerprint":"fp-c","rules":[]},"bridge":null,"state":null,"reports":null}`

	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", typo)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// The rejected payload must not have replaced the fixture.
	stateResp := doRequest(t, http.MethodGet, ts.URL+"/v1/nodes/node-1/state", "")
	defer stateResp.Body.Close()
	var got api.NodeStateSnapshot
	if err := json.NewDecoder(stateResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if got.Policy == nil {
		t.Error("policy = nil, want the default fixture policy retained")
	}
}

func TestConfigureState_UnknownNestedField_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	// Strictness must reach nested blocks too, so a renamed PolicySnapshot json
	// tag cannot silently degrade the stored fingerprint.
	const typo = `{"peers":[],"reachability":null,"policy":{"revision_id":"rev-c","finger_print":"fp-c","rules":[]},"bridge":null,"state":null,"reports":null}`

	resp := doRequest(t, http.MethodPost, ts.URL+"/test/configure-state", typo)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestConfigureState_CounterStillIncrements(t *testing.T) {
	_, ts := newTestServer(t)

	// Configure a custom state.
	customState := api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{{NodeID: "p1", PublicKey: "k1", MeshIP: "10.0.0.1"}},
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

	customState := api.NodeStateSnapshot{
		Policy: &api.PolicySnapshot{Fingerprint: "capture"},
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

	customState := api.NodeStateSnapshot{
		Policy: &api.PolicySnapshot{Fingerprint: "put-capture"},
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
			state := api.NodeStateSnapshot{
				Peers: []api.SnapshotPeer{{
					NodeID:    fmt.Sprintf("conc-peer-%d", i),
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
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/heartbeat", validHeartbeatBody())
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
	resp2 := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/heartbeat", validHeartbeatBody())
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
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/heartbeat", validHeartbeatBody())
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

// ---------------------------------------------------------------------------
// Local Endpoint Tests
// ---------------------------------------------------------------------------

// newTLSTestServer creates a test server with the TLSHandler for local endpoints.
func newTLSTestServer(t *testing.T) (*mockapi.Server, *httptest.Server) {
	t.Helper()
	srv := mockapi.New()
	ts := httptest.NewTLSServer(srv.TLSHandler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// tlsClient returns an HTTP client that skips TLS verification.
func tlsClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func TestAssertions_IncludesLocalCounters(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/test/assertions")
	if err != nil {
		t.Fatalf("GET /test/assertions: %v", err)
	}
	defer resp.Body.Close()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"local_metrics_count", "local_logs_count", "local_audit_count"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("assertions JSON missing key %q", key)
		}
	}
}

func TestLocalEndpoint_RequiresAuth(t *testing.T) {
	_, ts := newTLSTestServer(t)
	client := tlsClient()

	for _, path := range []string{"/local/metrics", "/local/logs", "/local/audit"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(`[{"test":true}]`))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header.
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST %s without auth: status = %d, want %d", path, resp.StatusCode, http.StatusUnauthorized)
		}
	}
}

func TestLocalEndpoint_AcceptsValidAuth(t *testing.T) {
	srv, ts := newTLSTestServer(t)
	client := tlsClient()
	token := srv.ExpectedBearerToken()

	endpoints := []struct {
		path    string
		counter func() int64
	}{
		{"/local/metrics", func() int64 { return srv.Assertions().LocalMetricsCount }},
		{"/local/logs", func() int64 { return srv.Assertions().LocalLogsCount }},
		{"/local/audit", func() int64 { return srv.Assertions().LocalAuditCount }},
	}

	for _, ep := range endpoints {
		before := ep.counter()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+ep.path, strings.NewReader(`[{"test":true}]`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", ep.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("POST %s with valid auth: status = %d, want %d", ep.path, resp.StatusCode, http.StatusNoContent)
		}
		after := ep.counter()
		if after != before+1 {
			t.Errorf("POST %s: counter = %d, want %d", ep.path, after, before+1)
		}
	}
}

func TestLocalEndpoint_RejectsWrongToken(t *testing.T) {
	srv, ts := newTLSTestServer(t)
	client := tlsClient()

	endpoints := []struct {
		path    string
		counter func() int64
	}{
		{"/local/metrics", func() int64 { return srv.Assertions().LocalMetricsCount }},
		{"/local/logs", func() int64 { return srv.Assertions().LocalLogsCount }},
		{"/local/audit", func() int64 { return srv.Assertions().LocalAuditCount }},
	}

	for _, ep := range endpoints {
		before := ep.counter()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+ep.path, strings.NewReader(`[{"test":true}]`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer wrong-token-value")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", ep.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST %s with wrong token: status = %d, want %d", ep.path, resp.StatusCode, http.StatusUnauthorized)
		}
		after := ep.counter()
		if after != before {
			t.Errorf("POST %s with wrong token: counter changed from %d to %d", ep.path, before, after)
		}
	}
}

func TestHandleSecrets_ReturnsDecryptableResponse(t *testing.T) {
	srv, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/secrets/local-bearer-token")
	if err != nil {
		t.Fatalf("GET secrets: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var secret api.SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		t.Fatalf("decode: %v", err)
	}

	plaintext, err := nodeapi.DecryptSecret(srv.NSK(), secret.Ciphertext, secret.Nonce)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if plaintext != srv.ExpectedBearerToken() {
		t.Errorf("decrypted = %q, want %q", plaintext, srv.ExpectedBearerToken())
	}
}

// nsk must be served in the standard-padded base64 form the register contract
// specifies, decoding to the 32-byte AES-256-GCM key. Serving the raw bytes
// instead would let the suite pass against a shape production never sends.
func TestRegister_ReturnsBase64EncodedNSK(t *testing.T) {
	s, ts := newTestServer(t)

	resp, err := http.Post(ts.URL+"/v1/register", "application/json", strings.NewReader(registerBody))
	if err != nil {
		t.Fatalf("POST /v1/register: %v", err)
	}
	defer resp.Body.Close()

	var reg api.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(reg.NSK) != 44 {
		t.Errorf("len(NSK) = %d, want 44 (standard-padded base64)", len(reg.NSK))
	}
	raw, err := base64.StdEncoding.DecodeString(reg.NSK)
	if err != nil {
		t.Fatalf("nsk is not standard base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded nsk = %d bytes, want 32", len(raw))
	}
	if !bytes.Equal(raw, s.NSK()) {
		t.Errorf("decoded nsk = %x, want %x", raw, s.NSK())
	}
}
