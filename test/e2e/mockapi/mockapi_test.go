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
	"net/url"
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
	keyRotateKey           = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	keyRotateBody          = `{"new_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}`
	capabilitiesBody       = `{"builtin_actions":[],"hooks":[]}`
	reportBody             = `{"value":"cpu ok","workload_tag":"web"}`
	metricsBatchBody       = `[{"group":"node_resources","name":"cpu.load","value":0.5,"timestamp":"2025-01-01T00:00:00Z"}]`
	logsBatchBody          = `{"severity":"info","unit":"main","message":"started","timestamp":"2025-01-01T00:00:00Z"}`
	auditBatchBody         = `{"source":"auditd","action":"execve","outcome":"success","timestamp":"2025-01-01T00:00:00Z"}`
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

// statefulCounterFields contains counters whose value depends on server state
// beyond a simple per-call increment, so they are exempt from the uniform
// non-zero pass in assertAllCountersEqual. KeyRotateCount advances only on a
// completing rotation, which n identical unarmed submissions cannot reach.
// ExecutionUploadCount advances only through the presign-then-PUT leg, which the
// flat fan-out does not drive uniformly.
var statefulCounterFields = map[string]bool{
	"KeyRotateCount":       true,
	"ExecutionUploadCount": true,
}

// assertAllCountersEqual checks that every field in the AssertionCounters struct
// equals the expected value. Useful for InitialZero and ConcurrentCounters tests.
// Fields in localCounterFields and statefulCounterFields are excluded from this
// check when want != 0 (the former are only incremented via the TLS handler; the
// latter never reach a uniform count).
func assertAllCountersEqual(t *testing.T, a mockapi.AssertionCounters, want int64) {
	t.Helper()
	v := reflect.ValueOf(a)
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		name := typ.Field(i).Name
		if want != 0 && (localCounterFields[name] || statefulCounterFields[name]) {
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
	// Arm a pending rotation so the keys/rotate call below completes (the
	// registered key differs from keyRotateBody's fresh key).
	resp = doRequest(t, http.MethodPost, ts.URL+"/test/configure-heartbeat", `{"reconcile":true,"rotate_keys":true}`)
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
	// Exercise both per-key report legs: PUT stores the entry, DELETE removes it.
	reportPath := ts.URL + "/v1/nodes/n1/state/reports/cpu.load"
	resp = doRequest(t, http.MethodPut, reportPath, reportBody)
	resp.Body.Close()
	resp = doRequest(t, http.MethodDelete, reportPath, "")
	resp.Body.Close()
	// Drive one execution through the over-ceiling upload leg: the declaring
	// callback (ack→started→declare) mints a presigned URL, and the PUT stores
	// the bytes. This exercises both the callback and upload routes/counters.
	uploadURL := declareExecUpload(t, ts.URL, "exec-mixed", 4)
	putResp := doRequest(t, http.MethodPut, uploadURL, "abcd")
	putResp.Body.Close()
	resp = doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/metrics", "application/json", metricsBatchBody, nil)
	resp.Body.Close()
	resp = doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/logs", "application/x-ndjson", logsBatchBody, nil)
	resp.Body.Close()
	resp = doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/n1/audit", "application/x-ndjson", auditBatchBody, nil)
	resp.Body.Close()
	resp, err = http.Get(ts.URL + "/v1/artifacts/plexd/1.0.0/linux/amd64")
	if err != nil {
		t.Fatalf("GET artifact: %v", err)
	}
	resp.Body.Close()
	resp = doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/"+testMockNodeID+"/sessions/sess-001", `{"tcp":{"phase":"session_started"}}`)
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
	if a.ReportPutCount != 1 {
		t.Errorf("report_put_count = %d, want 1", a.ReportPutCount)
	}
	if a.ReportDeleteCount != 1 {
		t.Errorf("report_delete_count = %d, want 1", a.ReportDeleteCount)
	}
	if a.ExecutionCallbackCount != 3 {
		t.Errorf("execution_callback_count = %d, want 3", a.ExecutionCallbackCount)
	}
	if a.ExecutionUploadCount != 1 {
		t.Errorf("execution_upload_count = %d, want 1", a.ExecutionUploadCount)
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
	if a.SessionActivityCount != 1 {
		t.Errorf("session_activity_count = %d, want 1", a.SessionActivityCount)
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
		{http.MethodPut, "/v1/nodes/node-1/capabilities", capabilitiesBody},
		{http.MethodPut, "/v1/nodes/node-1/endpoint", validEndpointBody()},
		{http.MethodGet, "/v1/nodes/node-1/secrets/key1", ""},
		{http.MethodPost, "/v1/nodes/node-1/metrics", metricsBatchBody},
		{http.MethodPost, "/v1/nodes/node-1/logs", logsBatchBody},
		{http.MethodPost, "/v1/nodes/node-1/audit", auditBatchBody},
		{http.MethodGet, "/v1/artifacts/plexd/1.0.0/linux/amd64", ""},
		{http.MethodPost, "/v1/nodes/" + testMockNodeID + "/sessions/sess-conc", `{"tcp":{"phase":"session_started"}}`},
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
				// Harmless on non-ingest routes; the metrics/logs/audit ingest
				// gate rejects a missing X-Plexsphere-Sent-At with 400.
				req.Header.Set("X-Plexsphere-Sent-At", time.Now().UTC().Format(time.RFC3339))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()
			}(ep)
		}
	}

	// Report writes need a distinct key per goroutine: each goroutine PUTs then
	// DELETEs its own key so both the put and delete counters reach n without the
	// two racing on a shared key (a delete of a missing key is a 404 that does not
	// count).
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			path := ts.URL + "/v1/nodes/node-1/state/reports/" + fmt.Sprintf("report.conc.%d", i)
			putReq, err := http.NewRequest(http.MethodPut, path, strings.NewReader(reportBody))
			if err != nil {
				return
			}
			putReq.Header.Set("Content-Type", "application/json")
			putResp, err := http.DefaultClient.Do(putReq)
			if err != nil {
				return
			}
			putResp.Body.Close()
			delReq, err := http.NewRequest(http.MethodDelete, path, nil)
			if err != nil {
				return
			}
			delResp, err := http.DefaultClient.Do(delReq)
			if err != nil {
				return
			}
			delResp.Body.Close()
		}(i)
	}

	// Execution callbacks need a distinct execution id per request; concurrent
	// callbacks for one id would fight the state machine. Fire n absent→ack
	// callbacks across n distinct ids so the callback counter reaches n.
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			eid := fmt.Sprintf("exec-conc-%d", i)
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/nodes/"+testMockNodeID+"/executions/"+eid, strings.NewReader(`{"status":"ack"}`))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
		}(i)
	}

	wg.Wait()

	a := getAssertions(t, ts.URL)
	assertAllCountersEqual(t, a, n)

	// KeyRotateCount and ExecutionUploadCount are stateful (see
	// statefulCounterFields) and exempt from the uniform pass above. No
	// keys/rotate calls and no presigned uploads run here, so both stay zero.
	if a.KeyRotateCount != 0 {
		t.Errorf("key_rotate_count = %d, want 0", a.KeyRotateCount)
	}
	if a.ExecutionUploadCount != 0 {
		t.Errorf("execution_upload_count = %d, want 0", a.ExecutionUploadCount)
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

// registerNode performs a successful registration so the mock records the node's
// public key (nodePublicKey), a precondition for the rotation state machine.
func registerNode(t *testing.T, baseURL string) {
	t.Helper()
	resp := doRequest(t, http.MethodPost, baseURL+"/v1/register", registerBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
}

// armRotation arms a pending rotation via the configure-heartbeat fixture.
func armRotation(t *testing.T, baseURL string) {
	t.Helper()
	resp := doRequest(t, http.MethodPost, baseURL+"/test/configure-heartbeat", `{"reconcile":true,"rotate_keys":true}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("configure-heartbeat status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

// rotateBodyForKey builds a keys/rotate request body carrying the given key.
func rotateBodyForKey(key string) string {
	return fmt.Sprintf(`{"new_public_key":%q}`, key)
}

// freshRotateKey returns a valid 44-char standard-base64 X25519 key derived from
// seed. Seed 0 yields the register fixture key, so callers pass seed >= 2 for a
// key distinct from both the registered key and keyRotateKey (seed 1).
func freshRotateKey(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// problemCode decodes an application/problem+json body and returns its code
// member, failing the test if the content type is wrong.
func problemCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
	}
	var problem map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	code, _ := problem["code"].(string)
	return code
}

func TestKeyRotate_CompletionFlow(t *testing.T) {
	_, ts := newTestServer(t)

	registerNode(t, ts.URL)
	armRotation(t, ts.URL)

	// Submit a fresh key: the armed rotation completes with a receipt.
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", keyRotateBody)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var kr api.KeyRotateResponse
	if err := json.NewDecoder(resp.Body).Decode(&kr); err != nil {
		resp.Body.Close()
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if kr.RotationID == "" {
		t.Error("rotation_id is empty")
	}
	if kr.KID == "" {
		t.Error("kid is empty")
	}
	if kr.WrapKeyVersion < 1 {
		t.Errorf("wrap_key_version = %d, want >= 1", kr.WrapKeyVersion)
	}

	// Completion disarms: a second, different fresh key finds no pending rotation.
	resp2 := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", rotateBodyForKey(freshRotateKey(9)))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second rotate status = %d, want %d", resp2.StatusCode, http.StatusConflict)
	}
	if code := problemCode(t, resp2); code != "keys_rotate_no_pending_rotation" {
		t.Errorf("code = %q, want %q", code, "keys_rotate_no_pending_rotation")
	}

	// The counter moved exactly once.
	a := getAssertions(t, ts.URL)
	if a.KeyRotateCount != 1 {
		t.Errorf("key_rotate_count = %d, want 1", a.KeyRotateCount)
	}
}

func TestKeyRotate_IdempotentRetry(t *testing.T) {
	_, ts := newTestServer(t)

	registerNode(t, ts.URL)
	armRotation(t, ts.URL)

	first := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", keyRotateBody)
	var kr1 api.KeyRotateResponse
	if err := json.NewDecoder(first.Body).Decode(&kr1); err != nil {
		first.Body.Close()
		t.Fatalf("decode first: %v", err)
	}
	first.Body.Close()

	// Resubmitting the same key replays the stored receipt without moving the counter.
	second := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", keyRotateBody)
	if second.StatusCode != http.StatusOK {
		second.Body.Close()
		t.Fatalf("retry status = %d, want %d", second.StatusCode, http.StatusOK)
	}
	var kr2 api.KeyRotateResponse
	if err := json.NewDecoder(second.Body).Decode(&kr2); err != nil {
		second.Body.Close()
		t.Fatalf("decode second: %v", err)
	}
	second.Body.Close()

	if kr2.RotationID != kr1.RotationID {
		t.Errorf("retry rotation_id = %q, want identical %q", kr2.RotationID, kr1.RotationID)
	}
	if kr2.WrapKeyVersion != kr1.WrapKeyVersion {
		t.Errorf("retry wrap_key_version = %d, want identical %d", kr2.WrapKeyVersion, kr1.WrapKeyVersion)
	}

	a := getAssertions(t, ts.URL)
	if a.KeyRotateCount != 1 {
		t.Errorf("key_rotate_count = %d, want 1 (retry must not move the counter)", a.KeyRotateCount)
	}
}

func TestKeyRotate_ArmingSources(t *testing.T) {
	tests := []struct {
		name string
		arm  func(t *testing.T, baseURL string)
	}{
		{
			name: "configure_heartbeat_fixture",
			arm:  armRotation,
		},
		{
			name: "served_heartbeat_response",
			arm: func(t *testing.T, baseURL string) {
				// Configure the fixture, then serve one heartbeat carrying
				// rotate_keys=true.
				cfg := doRequest(t, http.MethodPost, baseURL+"/test/configure-heartbeat", `{"reconcile":true,"rotate_keys":true}`)
				cfg.Body.Close()
				hb := doRequest(t, http.MethodPost, baseURL+"/v1/nodes/node-1/heartbeat", validHeartbeatBody())
				hb.Body.Close()
			},
		},
		{
			name: "injected_rotate_keys_event",
			arm: func(t *testing.T, baseURL string) {
				env := makeEnvelope(api.EventRotateKeys, "evt-rotate-001", json.RawMessage(`{}`))
				body, _ := json.Marshal(env)
				resp := doRequest(t, http.MethodPost, baseURL+"/test/inject-event", string(body))
				resp.Body.Close()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)
			registerNode(t, ts.URL)
			tt.arm(t, ts.URL)

			// Armed: the fresh key completes.
			resp := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", keyRotateBody)
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				t.Fatalf("rotate status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			resp.Body.Close()

			// Completion disarms: a second, different fresh key finds no pending rotation.
			resp2 := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", rotateBodyForKey(freshRotateKey(7)))
			defer resp2.Body.Close()
			if resp2.StatusCode != http.StatusConflict {
				t.Fatalf("second rotate status = %d, want %d", resp2.StatusCode, http.StatusConflict)
			}
			if code := problemCode(t, resp2); code != "keys_rotate_no_pending_rotation" {
				t.Errorf("code = %q, want %q", code, "keys_rotate_no_pending_rotation")
			}
		})
	}
}

func TestKeyRotate_DenialTaxonomy(t *testing.T) {
	const path = "/v1/keys/rotate"

	tests := []struct {
		name       string
		setup      func(t *testing.T, baseURL string)
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "invalid_json", body: "not-json", wantStatus: http.StatusBadRequest, wantCode: "malformed_keys_rotate_request"},
		{name: "unknown_field", body: fmt.Sprintf(`{"new_public_key":%q,"node_id":"n1"}`, keyRotateKey), wantStatus: http.StatusBadRequest, wantCode: "malformed_keys_rotate_request"},
		{name: "body_too_large", body: fmt.Sprintf(`{"new_public_key":%q}`, strings.Repeat("a", 5000)), wantStatus: http.StatusRequestEntityTooLarge, wantCode: "keys_rotate_body_too_large"},
		{name: "not_44_char_key", body: `{"new_public_key":"short"}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "keys_rotate_public_key_invalid"},
		{name: "zero_key", body: `{"new_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "keys_rotate_public_key_invalid"},
		{
			name:       "unchanged_key_while_armed",
			setup:      func(t *testing.T, baseURL string) { registerNode(t, baseURL); armRotation(t, baseURL) },
			body:       rotateBodyForKey(testValidPubKey),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "keys_rotate_public_key_unchanged",
		},
		{
			name:       "unarmed_fresh_key",
			setup:      registerNode,
			body:       keyRotateBody,
			wantStatus: http.StatusConflict,
			wantCode:   "keys_rotate_no_pending_rotation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)
			if tt.setup != nil {
				tt.setup(t, ts.URL)
			}

			resp := doRequest(t, http.MethodPost, ts.URL+path, tt.body)
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if code := problemCode(t, resp); code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
		})
	}
}

func TestKeyRotate_InvalidBody_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/keys/rotate", "not-json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if code := problemCode(t, resp); code != "malformed_keys_rotate_request" {
		t.Errorf("code = %q, want %q", code, "malformed_keys_rotate_request")
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
	srv, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/secrets/db-password")
	if err != nil {
		t.Fatalf("GET secrets: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if got := resp.Header.Get("X-Plexsphere-Secret-Version"); got != "1" {
		t.Errorf("X-Plexsphere-Secret-Version = %q, want %q", got, "1")
	}
	if got := resp.Header.Get("X-Plexsphere-Secret-KID"); got != "e2e-nsk-kid-1" {
		t.Errorf("X-Plexsphere-Secret-KID = %q, want %q", got, "e2e-nsk-kid-1")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := resp.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", got, "application/octet-stream")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	plaintext, err := nodeapi.DecryptSecret(srv.NSK(), body)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if plaintext != srv.ExpectedBearerToken() {
		t.Errorf("decrypted = %q, want %q", plaintext, srv.ExpectedBearerToken())
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

func TestSecrets_FreshNoncePerFetch(t *testing.T) {
	_, ts := newTestServer(t)

	get := func() []byte {
		t.Helper()
		resp, err := http.Get(ts.URL + "/v1/nodes/node-1/secrets/db-password")
		if err != nil {
			t.Fatalf("GET secrets: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return body
	}

	if first, second := get(), get(); bytes.Equal(first, second) {
		t.Error("two fetches produced identical envelopes, want a fresh nonce each time")
	}
}

func TestSecrets_KeyOutsideGrammarReturns404(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/secrets/DB-password")
	if err != nil {
		t.Fatalf("GET secrets: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "secret_not_found" {
		t.Errorf("code = %q, want %q", problem.Code, "secret_not_found")
	}
}

func TestSecrets_VersionAboveCurrentReturns404(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/secrets/db-password?version=2")
	if err != nil {
		t.Fatalf("GET secrets: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "secret_version_not_found" {
		t.Errorf("code = %q, want %q", problem.Code, "secret_version_not_found")
	}
}

func TestSecrets_InvalidVersionReturns400(t *testing.T) {
	_, ts := newTestServer(t)

	for _, q := range []string{"version=abc", "version=0"} {
		resp, err := http.Get(ts.URL + "/v1/nodes/node-1/secrets/db-password?" + q)
		if err != nil {
			t.Fatalf("GET secrets ?%s: %v", q, err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("?%s: status = %d, want %d", q, resp.StatusCode, http.StatusBadRequest)
		}
		resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// Per-key state report endpoint
// ---------------------------------------------------------------------------

// putReport issues PUT /v1/nodes/node-1/state/reports/{key} with the given JSON
// body and returns the response.
func putReport(t *testing.T, baseURL, key, body string) *http.Response {
	t.Helper()
	return doRequest(t, http.MethodPut, baseURL+"/v1/nodes/node-1/state/reports/"+key, body)
}

func TestReport_PutStoresSortedInBothBuckets(t *testing.T) {
	_, ts := newTestServer(t)

	// PUT two keys out of order; both mirrored buckets must end up key-ascending.
	resp := putReport(t, ts.URL, "zeta", `{"value":"z","workload_tag":"web"}`)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("PUT zeta status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var ack api.NodeStateReportResponse
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		resp.Body.Close()
		t.Fatalf("decode ack: %v", err)
	}
	resp.Body.Close()
	if ack.Key != "zeta" {
		t.Errorf("ack.Key = %q, want %q", ack.Key, "zeta")
	}
	if ack.AcceptedAt.IsZero() {
		t.Error("ack.AcceptedAt is zero, want a fresh timestamp")
	}

	resp = putReport(t, ts.URL, "alpha", `{"value":"a"}`)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("PUT alpha status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp.Body.Close()

	state := getState(t, ts.URL)
	for name, block := range map[string]*api.NodeStateBlock{"state": state.State, "reports": state.Reports} {
		if block == nil {
			t.Fatalf("%s block is nil", name)
		}
		if len(block.Reports) != 2 {
			t.Fatalf("%s: len(Reports) = %d, want 2", name, len(block.Reports))
		}
		if block.Reports[0].Key != "alpha" || block.Reports[1].Key != "zeta" {
			t.Errorf("%s: Reports not key-ascending: %q, %q", name, block.Reports[0].Key, block.Reports[1].Key)
		}
		if block.Reports[1].WorkloadTag != "web" {
			t.Errorf("%s: zeta WorkloadTag = %q, want %q", name, block.Reports[1].WorkloadTag, "web")
		}
	}

	a := getAssertions(t, ts.URL)
	if a.ReportPutCount != 2 {
		t.Errorf("report_put_count = %d, want 2", a.ReportPutCount)
	}
}

func TestReport_PutReplacesExistingKey(t *testing.T) {
	_, ts := newTestServer(t)

	resp := putReport(t, ts.URL, "cpu", `{"value":"first"}`)
	resp.Body.Close()
	resp = putReport(t, ts.URL, "cpu", `{"value":"second"}`)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("second PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp.Body.Close()

	state := getState(t, ts.URL)
	if len(state.State.Reports) != 1 {
		t.Fatalf("len(State.Reports) = %d, want 1", len(state.State.Reports))
	}
	if got := state.State.Reports[0].Value; got != "second" {
		t.Errorf("Value = %q, want %q", got, "second")
	}
}

func TestReport_PutRejections(t *testing.T) {
	tests := []struct {
		name string
		key  string
		body string
	}{
		{"bad_key", "Bad_Key", `{"value":"x"}`},
		{"oversized_value", "cpu", fmt.Sprintf(`{"value":%q}`, strings.Repeat("a", 4097))},
		{"unknown_field", "cpu", `{"value":"x","surprise":true}`},
		{"malformed_body", "cpu", "not-json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			resp := putReport(t, ts.URL, tt.key, tt.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
			if code := problemCode(t, resp); code != "invalid_report" {
				t.Errorf("code = %q, want %q", code, "invalid_report")
			}

			// A rejected PUT must not advance the counter or store an entry.
			a := getAssertions(t, ts.URL)
			if a.ReportPutCount != 0 {
				t.Errorf("report_put_count = %d, want 0", a.ReportPutCount)
			}
			if state := getState(t, ts.URL); len(state.State.Reports) != 0 {
				t.Errorf("State.Reports len = %d, want 0", len(state.State.Reports))
			}
		})
	}
}

func TestReport_DeleteRemovesFromBothBuckets(t *testing.T) {
	_, ts := newTestServer(t)

	resp := putReport(t, ts.URL, "cpu", `{"value":"x"}`)
	resp.Body.Close()

	resp = doRequest(t, http.MethodDelete, ts.URL+"/v1/nodes/node-1/state/reports/cpu", "")
	if resp.StatusCode != http.StatusNoContent {
		resp.Body.Close()
		t.Fatalf("DELETE status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	resp.Body.Close()

	state := getState(t, ts.URL)
	if len(state.State.Reports) != 0 {
		t.Errorf("State.Reports len = %d, want 0", len(state.State.Reports))
	}
	if len(state.Reports.Reports) != 0 {
		t.Errorf("Reports.Reports len = %d, want 0", len(state.Reports.Reports))
	}

	a := getAssertions(t, ts.URL)
	if a.ReportDeleteCount != 1 {
		t.Errorf("report_delete_count = %d, want 1", a.ReportDeleteCount)
	}
}

func TestReport_DeleteMissingKey_Returns404(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodDelete, ts.URL+"/v1/nodes/node-1/state/reports/ghost", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if code := problemCode(t, resp); code != "report_not_found" {
		t.Errorf("code = %q, want %q", code, "report_not_found")
	}

	a := getAssertions(t, ts.URL)
	if a.ReportDeleteCount != 0 {
		t.Errorf("report_delete_count = %d, want 0", a.ReportDeleteCount)
	}
}

func TestReport_DeleteBadKey_Returns400(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodDelete, ts.URL+"/v1/nodes/node-1/state/reports/Bad_Key", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if code := problemCode(t, resp); code != "invalid_report" {
		t.Errorf("code = %q, want %q", code, "invalid_report")
	}
}

func TestReport_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state/reports/cpu")
	if err != nil {
		t.Fatalf("GET report: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Telemetry ingest endpoints (metrics, logs, audit)
// ---------------------------------------------------------------------------

// doIngest sends body to a platform ingest endpoint with the given content type
// and a fresh RFC 3339 X-Plexsphere-Sent-At header (so the default gates pass).
// A header override with an empty value deletes that header, letting a test drop
// the sent-at or set an unsupported Content-Encoding.
func doIngest(t *testing.T, method, url, contentType, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("create %s request: %v", method, err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Plexsphere-Sent-At", time.Now().UTC().Format(time.RFC3339))
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// assertProblem asserts resp carries the given status and RFC 9457 problem code.
func assertProblem(t *testing.T, resp *http.Response, wantStatus int, wantCode string) {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
	if code := problemCode(t, resp); code != wantCode {
		t.Errorf("code = %q, want %q", code, wantCode)
	}
}

// assertRecords asserts resp is a 202 ingest receipt whose records field equals
// want and whose accepted_at is fresh.
func assertRecords(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	var rcpt api.IngestReceipt
	if err := json.NewDecoder(resp.Body).Decode(&rcpt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if rcpt.Records != want {
		t.Errorf("records = %d, want %d", rcpt.Records, want)
	}
	if rcpt.AcceptedAt.IsZero() {
		t.Error("accepted_at is zero, want a fresh timestamp")
	}
}

// ingestSurface describes one of the three platform ingest endpoints for the
// gate tests shared across metrics, logs, and audit.
type ingestSurface struct {
	name        string
	path        string
	contentType string
	validBody   string
	counter     func(mockapi.AssertionCounters) int64
}

func ingestSurfaces() []ingestSurface {
	return []ingestSurface{
		{"metrics", "/v1/nodes/node-1/metrics", "application/json", metricsBatchBody, func(a mockapi.AssertionCounters) int64 { return a.MetricsCount }},
		{"logs", "/v1/nodes/node-1/logs", "application/x-ndjson", logsBatchBody, func(a mockapi.AssertionCounters) int64 { return a.LogsCount }},
		{"audit", "/v1/nodes/node-1/audit", "application/x-ndjson", auditBatchBody, func(a mockapi.AssertionCounters) int64 { return a.AuditCount }},
	}
}

func TestIngest_ValidBatch_Returns202(t *testing.T) {
	for _, sf := range ingestSurfaces() {
		t.Run(sf.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			resp := doIngest(t, http.MethodPost, ts.URL+sf.path, sf.contentType, sf.validBody, nil)
			defer resp.Body.Close()
			assertRecords(t, resp, 1)

			if got := sf.counter(getAssertions(t, ts.URL)); got != 1 {
				t.Errorf("%s counter = %d, want 1", sf.name, got)
			}
		})
	}
}

// TestIngest_RecordsCountsElements proves records equals the array length for
// metrics and the non-blank line count for logs and audit (blank lines skipped).
func TestIngest_RecordsCountsElements(t *testing.T) {
	_, ts := newTestServer(t)

	metrics := `[{"group":"node_resources","name":"cpu.load","value":0.5,"timestamp":"2025-01-01T00:00:00Z"},` +
		`{"group":"peer_latency","name":"rtt.ms","value":12,"timestamp":"2025-01-01T00:00:01Z"}]`
	resp := doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/metrics", "application/json", metrics, nil)
	assertRecords(t, resp, 2)
	resp.Body.Close()

	logs := `{"severity":"info","message":"a","timestamp":"2025-01-01T00:00:00Z"}` + "\n\n" +
		`{"severity":"err","message":"b","timestamp":"2025-01-01T00:00:01Z"}`
	resp = doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/logs", "application/x-ndjson", logs, nil)
	assertRecords(t, resp, 2)
	resp.Body.Close()

	audit := `{"source":"auditd","action":"execve","outcome":"success","timestamp":"2025-01-01T00:00:00Z"}` + "\n" +
		`{"source":"k8s","action":"create","outcome":"allow","timestamp":"2025-01-01T00:00:01Z"}` + "\n" +
		`{"source":"plexd","action":"start","outcome":"success","timestamp":"2025-01-01T00:00:02Z"}`
	resp = doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/audit", "application/x-ndjson", audit, nil)
	assertRecords(t, resp, 3)
	resp.Body.Close()
}

// TestIngest_HeaderGates exercises the two header gates on all three surfaces:
// an unsupported Content-Encoding is 415 ingest_encoding_unsupported, and a
// missing or unparseable X-Plexsphere-Sent-At is 400 ingest_sent_at_invalid.
func TestIngest_HeaderGates(t *testing.T) {
	gates := []struct {
		name       string
		headers    map[string]string
		wantStatus int
		wantCode   string
	}{
		{"unsupported_encoding", map[string]string{"Content-Encoding": "br"}, http.StatusUnsupportedMediaType, "ingest_encoding_unsupported"},
		{"missing_sent_at", map[string]string{"X-Plexsphere-Sent-At": ""}, http.StatusBadRequest, "ingest_sent_at_invalid"},
		{"unparseable_sent_at", map[string]string{"X-Plexsphere-Sent-At": "not-a-timestamp"}, http.StatusBadRequest, "ingest_sent_at_invalid"},
	}
	for _, sf := range ingestSurfaces() {
		for _, g := range gates {
			t.Run(sf.name+"/"+g.name, func(t *testing.T) {
				_, ts := newTestServer(t)

				resp := doIngest(t, http.MethodPost, ts.URL+sf.path, sf.contentType, sf.validBody, g.headers)
				defer resp.Body.Close()
				assertProblem(t, resp, g.wantStatus, g.wantCode)

				if got := sf.counter(getAssertions(t, ts.URL)); got != 0 {
					t.Errorf("%s counter = %d, want 0", sf.name, got)
				}
			})
		}
	}
}

func TestMetricsIngest_BatchMalformed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty_array", `[]`},
		{"non_array", `{"group":"node_resources"}`},
		{"unknown_field", `[{"group":"node_resources","name":"cpu","value":1,"timestamp":"2025-01-01T00:00:00Z","surprise":true}]`},
		{"bad_group", `[{"group":"system","name":"cpu","value":1,"timestamp":"2025-01-01T00:00:00Z"}]`},
		{"empty_name", `[{"group":"node_resources","name":"","value":1,"timestamp":"2025-01-01T00:00:00Z"}]`},
		{"zero_timestamp", `[{"group":"node_resources","name":"cpu","value":1,"timestamp":"0001-01-01T00:00:00Z"}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			resp := doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/metrics", "application/json", tt.body, nil)
			defer resp.Body.Close()
			assertProblem(t, resp, http.StatusBadRequest, "ingest_batch_malformed")

			if a := getAssertions(t, ts.URL); a.MetricsCount != 0 {
				t.Errorf("metrics_count = %d, want 0", a.MetricsCount)
			}
		})
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

func TestLogsIngest_BatchMalformed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty", ``},
		{"blank_only", "\n   \n"},
		{"undecodable_line", `{not json}`},
		{"unknown_field", `{"severity":"info","message":"x","timestamp":"2025-01-01T00:00:00Z","surprise":1}`},
		{"bad_severity", `{"severity":"loud","message":"x","timestamp":"2025-01-01T00:00:00Z"}`},
		{"empty_message", `{"severity":"info","message":"","timestamp":"2025-01-01T00:00:00Z"}`},
		{"zero_timestamp", `{"severity":"info","message":"x","timestamp":"0001-01-01T00:00:00Z"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			resp := doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/logs", "application/x-ndjson", tt.body, nil)
			defer resp.Body.Close()
			assertProblem(t, resp, http.StatusBadRequest, "ingest_batch_malformed")

			if a := getAssertions(t, ts.URL); a.LogsCount != 0 {
				t.Errorf("logs_count = %d, want 0", a.LogsCount)
			}
		})
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

func TestAuditIngest_BatchMalformed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty", ``},
		{"blank_only", "\n   \n"},
		{"undecodable_line", `{not json}`},
		{"unknown_field", `{"source":"auditd","action":"x","outcome":"ok","timestamp":"2025-01-01T00:00:00Z","surprise":1}`},
		{"bad_source", `{"source":"syslog","action":"x","outcome":"ok","timestamp":"2025-01-01T00:00:00Z"}`},
		{"empty_action", `{"source":"auditd","action":"","outcome":"ok","timestamp":"2025-01-01T00:00:00Z"}`},
		{"empty_outcome", `{"source":"auditd","action":"x","outcome":"","timestamp":"2025-01-01T00:00:00Z"}`},
		{"zero_timestamp", `{"source":"auditd","action":"x","outcome":"ok","timestamp":"0001-01-01T00:00:00Z"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)

			resp := doIngest(t, http.MethodPost, ts.URL+"/v1/nodes/node-1/audit", "application/x-ndjson", tt.body, nil)
			defer resp.Body.Close()
			assertProblem(t, resp, http.StatusBadRequest, "ingest_batch_malformed")

			if a := getAssertions(t, ts.URL); a.AuditCount != 0 {
				t.Errorf("audit_count = %d, want 0", a.AuditCount)
			}
		})
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
// Execution callback endpoint (issue #22)
// ---------------------------------------------------------------------------

// execCallbackURL builds POST /v1/nodes/{mockNode}/executions/{eid}.
func execCallbackURL(baseURL, eid string) string {
	return baseURL + "/v1/nodes/" + testMockNodeID + "/executions/" + eid
}

// postExecCallback posts one execution callback body and returns the response.
func postExecCallback(t *testing.T, baseURL, eid, body string) *http.Response {
	t.Helper()
	return doRequest(t, http.MethodPost, execCallbackURL(baseURL, eid), body)
}

// declareExecUpload drives eid through ack→started→declare and returns the
// one-time presigned upload URL minted by the declaring callback.
func declareExecUpload(t *testing.T, baseURL, eid string, declaredBytes int) string {
	t.Helper()
	for _, body := range []string{`{"status":"ack"}`, `{"status":"started"}`} {
		resp := postExecCallback(t, baseURL, eid, body)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("declareExecUpload %s: setup status = %d, want %d", eid, resp.StatusCode, http.StatusOK)
		}
		resp.Body.Close()
	}
	resp := postExecCallback(t, baseURL, eid, fmt.Sprintf(`{"status":"started","declared_output_bytes":%d}`, declaredBytes))
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("declareExecUpload %s: declare status = %d, want %d", eid, resp.StatusCode, http.StatusOK)
	}
	var cr api.ExecutionCallbackResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		resp.Body.Close()
		t.Fatalf("declareExecUpload %s: decode: %v", eid, err)
	}
	resp.Body.Close()
	if cr.OutputUploadURL == "" {
		t.Fatalf("declareExecUpload %s: output_upload_url is empty", eid)
	}
	return cr.OutputUploadURL
}

func TestExecutionCallback_AckStartedSucceededInline(t *testing.T) {
	_, ts := newTestServer(t)
	const eid = "exec-flow-001"

	steps := []struct {
		body   string
		status string
	}{
		{`{"status":"ack"}`, "ack"},
		{`{"status":"started"}`, "started"},
		{fmt.Sprintf(`{"status":"succeeded","exit_code":0,"output":{"inline":%q}}`, base64.StdEncoding.EncodeToString([]byte("done"))), "succeeded"},
	}
	for _, step := range steps {
		resp := postExecCallback(t, ts.URL, eid, step.body)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("status %q: got %d, want %d", step.status, resp.StatusCode, http.StatusOK)
		}
		var cr api.ExecutionCallbackResponse
		if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
			resp.Body.Close()
			t.Fatalf("decode %q: %v", step.status, err)
		}
		resp.Body.Close()
		if cr.Status != step.status {
			t.Errorf("status = %q, want %q", cr.Status, step.status)
		}
	}

	if a := getAssertions(t, ts.URL); a.ExecutionCallbackCount != 3 {
		t.Errorf("execution_callback_count = %d, want 3", a.ExecutionCallbackCount)
	}

	// The last captured body is the succeeded callback.
	captured := getCapturedBody(t, ts.URL, "execution_callback")
	if !bytes.Contains(captured, []byte(`"succeeded"`)) {
		t.Errorf("captured execution_callback = %s, want the succeeded callback", captured)
	}
}

func TestExecutionCallback_IllegalTransitions(t *testing.T) {
	tests := []struct {
		name  string
		setup []string
		jump  string
	}{
		{"absent_to_started", nil, `{"status":"started"}`},
		{"absent_to_succeeded", nil, `{"status":"succeeded"}`},
		{"ack_to_succeeded", []string{`{"status":"ack"}`}, `{"status":"succeeded"}`},
		{"ack_to_ack", []string{`{"status":"ack"}`}, `{"status":"ack"}`},
		{"started_to_ack", []string{`{"status":"ack"}`, `{"status":"started"}`}, `{"status":"ack"}`},
		{"plain_started_to_started", []string{`{"status":"ack"}`, `{"status":"started"}`}, `{"status":"started"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)
			eid := "exec-" + tt.name
			for i, body := range tt.setup {
				resp := postExecCallback(t, ts.URL, eid, body)
				if resp.StatusCode != http.StatusOK {
					resp.Body.Close()
					t.Fatalf("setup #%d: status = %d, want %d", i, resp.StatusCode, http.StatusOK)
				}
				resp.Body.Close()
			}
			resp := postExecCallback(t, ts.URL, eid, tt.jump)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusConflict {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusConflict)
			}
			if code := problemCode(t, resp); code != "invalid_state_transition" {
				t.Errorf("code = %q, want %q", code, "invalid_state_transition")
			}
		})
	}
}

func TestExecutionCallback_TerminalIsFinal(t *testing.T) {
	tests := []struct {
		name string
		next string
	}{
		{"then_started", `{"status":"started"}`},
		{"then_succeeded", `{"status":"succeeded"}`},
		{"then_failed", `{"status":"failed"}`},
		{"then_ack", `{"status":"ack"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)
			eid := "exec-term-" + tt.name
			// Drive to a terminal state: ack→started→succeeded.
			for _, body := range []string{`{"status":"ack"}`, `{"status":"started"}`, `{"status":"succeeded"}`} {
				resp := postExecCallback(t, ts.URL, eid, body)
				resp.Body.Close()
			}
			resp := postExecCallback(t, ts.URL, eid, tt.next)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusConflict {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusConflict)
			}
			if code := problemCode(t, resp); code != "execution_already_terminal" {
				t.Errorf("code = %q, want %q", code, "execution_already_terminal")
			}
		})
	}
}

func TestExecutionCallback_ForeignNodeID_Returns403(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/foreign-node/executions/exec-1", `{"status":"ack"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if code := problemCode(t, resp); code != "nsk_node_mismatch" {
		t.Errorf("code = %q, want %q", code, "nsk_node_mismatch")
	}
}

func TestExecutionCallback_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(execCallbackURL(ts.URL, "exec-1"))
	if err != nil {
		t.Fatalf("GET execution callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestExecutionCallback_OverCeilingUploadFlow(t *testing.T) {
	_, ts := newTestServer(t)
	const eid = "exec-upload-001"
	output := []byte(strings.Repeat("x", 20000)) // over the 16 KiB inline ceiling
	sum := sha256.Sum256(output)
	sha := fmt.Sprintf("%x", sum[:])

	// ack → started → declare mints the presigned URL.
	uploadURL := declareExecUpload(t, ts.URL, eid, len(output))
	u, err := url.Parse(uploadURL)
	if err != nil {
		t.Fatalf("parse upload url: %v", err)
	}
	if u.Path != "/exec-output/"+eid {
		t.Errorf("upload url path = %q, want %q", u.Path, "/exec-output/"+eid)
	}

	// PUT the bytes → 200, execution_upload_count = 1.
	put := doRequest(t, http.MethodPut, uploadURL, string(output))
	if put.StatusCode != http.StatusOK {
		put.Body.Close()
		t.Fatalf("PUT upload status = %d, want %d", put.StatusCode, http.StatusOK)
	}
	put.Body.Close()
	if a := getAssertions(t, ts.URL); a.ExecutionUploadCount != 1 {
		t.Errorf("execution_upload_count = %d, want 1", a.ExecutionUploadCount)
	}

	// Terminal callback with the matching object_key + sha256 → 200.
	term := postExecCallback(t, ts.URL, eid, fmt.Sprintf(`{"status":"succeeded","output":{"object_key":"exec-output/%s","sha256":%q}}`, eid, sha))
	defer term.Body.Close()
	if term.StatusCode != http.StatusOK {
		t.Fatalf("terminal status = %d, want %d", term.StatusCode, http.StatusOK)
	}
}

func TestExecOutputUpload_Errors(t *testing.T) {
	_, ts := newTestServer(t)
	const eid = "exec-upload-errs"
	output := []byte(strings.Repeat("y", 18000))

	uploadURL := declareExecUpload(t, ts.URL, eid, len(output))

	// Unknown token → 404.
	unknown := doRequest(t, http.MethodPut, ts.URL+"/exec-output/"+eid+"?token=nope", "data")
	if unknown.StatusCode != http.StatusNotFound {
		unknown.Body.Close()
		t.Fatalf("unknown token status = %d, want %d", unknown.StatusCode, http.StatusNotFound)
	}
	unknown.Body.Close()

	// A body larger than declared → 413 (the token stays unused).
	over := doRequest(t, http.MethodPut, uploadURL, string(output)+"z")
	if over.StatusCode != http.StatusRequestEntityTooLarge {
		over.Body.Close()
		t.Fatalf("over-declared status = %d, want %d", over.StatusCode, http.StatusRequestEntityTooLarge)
	}
	over.Body.Close()

	// The first well-sized PUT → 200.
	first := doRequest(t, http.MethodPut, uploadURL, string(output))
	if first.StatusCode != http.StatusOK {
		first.Body.Close()
		t.Fatalf("first PUT status = %d, want %d", first.StatusCode, http.StatusOK)
	}
	first.Body.Close()

	// A second PUT with the same token → 409 (one-time URL).
	second := doRequest(t, http.MethodPut, uploadURL, string(output))
	defer second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second PUT status = %d, want %d", second.StatusCode, http.StatusConflict)
	}
}

func TestExecutionCallback_MalformedAndCeiling(t *testing.T) {
	t.Run("sha256_mismatch", func(t *testing.T) {
		_, ts := newTestServer(t)
		const eid = "exec-mismatch"
		output := []byte(strings.Repeat("z", 20000))

		uploadURL := declareExecUpload(t, ts.URL, eid, len(output))
		put := doRequest(t, http.MethodPut, uploadURL, string(output))
		put.Body.Close()

		wrongSHA := strings.Repeat("00", 32)
		term := postExecCallback(t, ts.URL, eid, fmt.Sprintf(`{"status":"succeeded","output":{"object_key":"exec-output/%s","sha256":%q}}`, eid, wrongSHA))
		defer term.Body.Close()
		if term.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", term.StatusCode, http.StatusBadRequest)
		}
		if code := problemCode(t, term); code != "malformed_execution_callback" {
			t.Errorf("code = %q, want %q", code, "malformed_execution_callback")
		}
	})

	simple := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"unknown_field", `{"status":"ack","surprise":"x"}`, http.StatusBadRequest, "malformed_execution_callback"},
		{"bad_status", `{"status":"bogus"}`, http.StatusBadRequest, "malformed_execution_callback"},
		{"inline_over_ceiling", fmt.Sprintf(`{"status":"succeeded","output":{"inline":%q}}`, base64.StdEncoding.EncodeToString(make([]byte, 16385))), http.StatusRequestEntityTooLarge, "inline_output_too_large"},
	}
	for _, tt := range simple {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)
			resp := postExecCallback(t, ts.URL, "exec-"+tt.name, tt.body)
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if code := problemCode(t, resp); code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Session activity endpoint (issue #22)
// ---------------------------------------------------------------------------

// sessionURL builds POST /v1/nodes/{mockNode}/sessions/{sid}.
func sessionURL(baseURL, sid string) string {
	return baseURL + "/v1/nodes/" + testMockNodeID + "/sessions/" + sid
}

func TestSessionActivity_ValidRows(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"tcp_started", `{"tcp":{"phase":"session_started","target_host":"203.0.113.9","target_port":22}}`},
		{"tcp_ended", `{"tcp":{"phase":"session_ended","bytes_in":0,"bytes_out":0,"terminated_by":"operator_revoke"}}`},
		{"ssh", `{"ssh":{"command":"ls -la","exit_code":0}}`},
		{"k8s", `{"k8s":{"verb":"get","resource_kind":"pods","namespace":"default"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)
			resp := doRequest(t, http.MethodPost, sessionURL(ts.URL, "sess-"+tt.name), tt.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
			if a := getAssertions(t, ts.URL); a.SessionActivityCount != 1 {
				t.Errorf("session_activity_count = %d, want 1", a.SessionActivityCount)
			}
			if captured := getCapturedBody(t, ts.URL, "session_activity"); string(captured) != tt.body {
				t.Errorf("captured session_activity = %q, want %q", captured, tt.body)
			}
		})
	}
}

func TestSessionActivity_Denials(t *testing.T) {
	longCommand := strings.Repeat("a", 1025)
	tests := []struct {
		name string
		body string
	}{
		{"zero_members", `{}`},
		{"two_members", `{"ssh":{"command":"ls"},"k8s":{"verb":"get"}}`},
		{"ssh_missing_command", `{"ssh":{"exit_code":0}}`},
		{"ssh_command_too_long", fmt.Sprintf(`{"ssh":{"command":%q}}`, longCommand)},
		{"k8s_missing_verb", `{"k8s":{"resource_kind":"pods"}}`},
		{"bad_tcp_phase", `{"tcp":{"phase":"session_paused"}}`},
		{"bad_terminated_by", `{"tcp":{"phase":"session_ended","terminated_by":"who_knows"}}`},
		{"unknown_field", `{"tcp":{"phase":"session_started"},"surprise":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ts := newTestServer(t)
			resp := doRequest(t, http.MethodPost, sessionURL(ts.URL, "sess-"+tt.name), tt.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
			if code := problemCode(t, resp); code != "malformed_session_activity" {
				t.Errorf("code = %q, want %q", code, "malformed_session_activity")
			}
		})
	}
}

func TestSessionActivity_ForeignNodeID_Returns403(t *testing.T) {
	_, ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/nodes/foreign-node/sessions/sess-1", `{"tcp":{"phase":"session_started"}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if code := problemCode(t, resp); code != "nsk_node_mismatch" {
		t.Errorf("code = %q, want %q", code, "nsk_node_mismatch")
	}
}

func TestSessionActivity_WrongMethod_Returns405(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(sessionURL(ts.URL, "sess-1"))
	if err != nil {
		t.Fatalf("GET session activity: %v", err)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	plaintext, err := nodeapi.DecryptSecret(srv.NSK(), body)
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
