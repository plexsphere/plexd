package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestClient creates a ControlPlane client pointed at the given test server.
func newTestClient(t *testing.T, serverURL string) *ControlPlane {
	t.Helper()
	cfg := Config{
		BaseURL: serverURL,
	}
	c, err := NewControlPlane(cfg, "1.2.3", slog.Default())
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	return c
}

func TestClient_AuthHeaderInjected(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.SetAuthToken("tok123")

	if err := c.GetJSON(context.Background(), "/v1/health", nil); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok123")
	}
}

func TestClient_UserAgentSet(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	if err := c.GetJSON(context.Background(), "/v1/health", nil); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if gotUA != "plexd/1.2.3" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "plexd/1.2.3")
	}
}

// Only the three observability ingest operations document a request encoding
// other than identity. Every other handler decodes the body as it arrives, so a
// compressed one is read as JSON and refused — which is how a capability
// manifest that crossed the threshold drew a 400 naming the gzip magic byte.
func TestClient_DoesNotGzipOrdinaryRequests(t *testing.T) {
	var gotEncoding string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	// Comfortably past gzipThreshold: the old client compressed this.
	largePayload := map[string]string{"data": strings.Repeat("x", 2048)}

	var result map[string]bool
	if err := c.PostJSON(context.Background(), "/v1/test", largePayload, &result); err != nil {
		t.Fatalf("PostJSON: %v", err)
	}

	if gotEncoding != "" {
		t.Errorf("Content-Encoding = %q, want none on an ordinary operation", gotEncoding)
	}
	// The body has to arrive as plain JSON, not as bytes that merely decompress
	// to it: the receiving handler does no inflating.
	var decoded map[string]string
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("body is not plain JSON: %v", err)
	}
	if len(decoded["data"]) != 2048 {
		t.Errorf("data length = %d, want 2048", len(decoded["data"]))
	}
}

// The ingest operations are the ones whose contract accepts gzip, and a
// telemetry batch is exactly where compression is worth having.
func TestClient_GzipsIngestRequests(t *testing.T) {
	var gotEncoding string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		if gotEncoding == "gzip" {
			gr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Fatalf("gzip.NewReader: %v", err)
			}
			defer gr.Close()
			gotBody, _ = io.ReadAll(gr)
		} else {
			gotBody, _ = io.ReadAll(r.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted_at":"2026-01-01T00:00:00Z","records":1}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	samples := []MetricSample{{
		Group:     "system",
		Name:      "cpu",
		Value:     1,
		Timestamp: time.Now().UTC(),
		Labels:    map[string]string{"pad": strings.Repeat("x", 2048)},
	}}
	if _, err := c.ReportMetrics(context.Background(), "n1", samples); err != nil {
		t.Fatalf("ReportMetrics: %v", err)
	}

	if gotEncoding != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip on an ingest operation", gotEncoding)
	}
	if !bytes.Contains(gotBody, []byte(`"cpu"`)) {
		t.Errorf("inflated body does not carry the sample: %s", gotBody)
	}
}

func TestClient_SmallBodyNotCompressed(t *testing.T) {
	var gotEncoding string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	smallPayload := map[string]string{"key": "val"}

	var result map[string]bool
	if err := c.PostJSON(context.Background(), "/v1/test", smallPayload, &result); err != nil {
		t.Fatalf("PostJSON: %v", err)
	}

	if gotEncoding != "" {
		t.Errorf("Content-Encoding = %q, want empty (no compression)", gotEncoding)
	}
}

func TestClient_GzipResponseDecompression(t *testing.T) {
	type testResp struct {
		Message string `json:"message"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := json.Marshal(testResp{Message: "hello-gzip"})

		var buf strings.Builder
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write(payload)
		_ = gw.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, buf.String())
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	var result testResp
	if err := c.GetJSON(context.Background(), "/v1/test", &result); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}

	if result.Message != "hello-gzip" {
		t.Errorf("Message = %q, want %q", result.Message, "hello-gzip")
	}
}

func TestClient_ErrorPropagation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("not allowed"))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	err := c.GetJSON(context.Background(), "/v1/health", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("errors.Is(err, ErrUnauthorized) = false; err = %v", err)
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As failed")
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
	}
}

func TestClient_NewControlPlane_ValidatesConfig(t *testing.T) {
	cfg := Config{
		BaseURL: "", // missing required field
	}
	_, err := NewControlPlane(cfg, "1.0.0", slog.Default())
	if err == nil {
		t.Fatal("expected error for empty BaseURL, got nil")
	}
	if !strings.Contains(err.Error(), "BaseURL") {
		t.Errorf("error = %q, want mention of BaseURL", err.Error())
	}
}

func TestClient_NewControlPlane_AppliesDefaults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		BaseURL: srv.URL,
		// Leave timeouts at zero to verify defaults are applied.
	}
	c, err := NewControlPlane(cfg, "0.1.0", slog.Default())
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}

	// Verify the client works (defaults were applied so timeouts are non-zero).
	if err := c.GetJSON(context.Background(), "/v1/health", nil); err != nil {
		t.Fatalf("GetJSON with defaults: %v", err)
	}

	// Verify the httpClient timeout matches the default.
	if c.httpClient.Timeout != DefaultRequestTimeout {
		t.Errorf("httpClient.Timeout = %v, want %v", c.httpClient.Timeout, DefaultRequestTimeout)
	}
}

func TestClient_SetAuthToken_ThreadSafe(t *testing.T) {
	cfg := Config{
		BaseURL: "https://example.com",
	}
	c, err := NewControlPlane(cfg, "1.0.0", slog.Default())
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half the goroutines write, half read — run with -race to detect data races.
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			c.SetAuthToken("token-" + strings.Repeat("x", n%10))
		}(i)
		go func() {
			defer wg.Done()
			_ = c.getAuthToken()
		}()
	}

	wg.Wait()

	// If we get here without a race detector complaint, the test passes.
	token := c.getAuthToken()
	if token == "" {
		t.Error("expected non-empty token after concurrent writes")
	}
}

// TestClient_BodylessSuccessAccepted verifies that a success status carrying no
// body is treated as success even when the caller passed a non-nil result. RFC
// 9110 makes a response body a SHOULD, not a MUST: a 202 Accepted after a
// durable enqueue and a 204 for an idempotent no-op upsert may both arrive
// empty. Decoding into result must not turn that acknowledgement into an
// "api: decode response: EOF" error that drives a retry of an already-accepted
// request.
func TestClient_BodylessSuccessAccepted(t *testing.T) {
	t.Run("202 empty body via ingest", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted) // no body
		}))
		defer srv.Close()

		c := newTestClient(t, srv.URL)
		if _, err := c.ReportMetrics(context.Background(), "node-1", []MetricSample{{Group: "g", Name: "n"}}); err != nil {
			t.Fatalf("ReportMetrics() with bodyless 202 = %v, want nil", err)
		}
	})

	t.Run("204 no content via state report", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent) // no body
		}))
		defer srv.Close()

		c := newTestClient(t, srv.URL)
		if _, err := c.PutStateReport(context.Background(), "node-1", "health", NodeStateReportRequest{Value: "{}"}); err != nil {
			t.Fatalf("PutStateReport() with bodyless 204 = %v, want nil", err)
		}
	})
}

// TestClient_TruncatedIngestReceiptAccepted verifies that the tolerance covers
// every receipt a 202 can arrive with, not just an empty one. A body cut short by
// a connection reset yields io.ErrUnexpectedEOF rather than io.EOF; treating that
// as an error would re-send a batch the platform already accepted, and ingest
// carries no idempotency key for the control plane to deduplicate it with.
func TestClient_TruncatedIngestReceiptAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted_at":"2026-07-2`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if _, err := c.ReportMetrics(context.Background(), "node-1", []MetricSample{{Group: "g", Name: "n"}}); err != nil {
		t.Fatalf("ReportMetrics() with a truncated 202 receipt = %v, want nil", err)
	}
}

// TestClient_EmptyBodyOnStateIsError verifies that the ingest tolerance for a
// bodyless 202 does not leak into the state-bearing endpoints. A gateway that
// answers GET /v1/nodes/{id}/state with 200 and Content-Length: 0 must surface
// a decode error: returning a zero-valued snapshot instead would read as
// "no peers desired" and tear down every configured WireGuard peer.
func TestClient_EmptyBodyOnStateIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // no body
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	snap, err := c.FetchState(context.Background(), "node-1")
	if err == nil {
		t.Fatalf("FetchState() with empty 200 body = %+v, nil; want a decode error", snap)
	}
	if !strings.Contains(err.Error(), "decode response") {
		t.Errorf("FetchState() error = %v, want a decode response error", err)
	}
}
