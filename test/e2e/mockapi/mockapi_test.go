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
}

// ---------------------------------------------------------------------------
// REQ-008: Concurrent counters (Task 2.8)
// ---------------------------------------------------------------------------

func TestConcurrentCounters(t *testing.T) {
	_, ts := newTestServer(t)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n * 4) // 100 goroutines × 4 endpoint types

	// 100 register calls.
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Post(ts.URL+"/v1/register", "application/json", strings.NewReader(registerBody))
			if err != nil {
				return
			}
			resp.Body.Close()
		}()
	}

	// 100 heartbeat calls.
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Post(ts.URL+"/v1/nodes/node-1/heartbeat", "application/json", strings.NewReader(heartbeatBody))
			if err != nil {
				return
			}
			resp.Body.Close()
		}()
	}

	// 100 state calls.
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/v1/nodes/node-1/state")
			if err != nil {
				return
			}
			resp.Body.Close()
		}()
	}

	// 100 metadata calls.
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/v1/nodes/node-1/metadata")
			if err != nil {
				return
			}
			resp.Body.Close()
		}()
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
