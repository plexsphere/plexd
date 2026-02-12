package api

import (
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

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
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

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if gotUA != "plexd/1.2.3" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "plexd/1.2.3")
	}
}

func TestClient_GzipCompression(t *testing.T) {
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	// Create a body larger than gzipThreshold (1024 bytes).
	largePayload := map[string]string{
		"data": strings.Repeat("x", 2048),
	}

	var result map[string]bool
	if err := c.PostJSON(context.Background(), "/v1/test", largePayload, &result); err != nil {
		t.Fatalf("PostJSON: %v", err)
	}

	if gotEncoding != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", gotEncoding, "gzip")
	}

	// Verify the decompressed body is valid JSON with our payload.
	var decoded map[string]string
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("Unmarshal decompressed body: %v", err)
	}
	if len(decoded["data"]) != 2048 {
		t.Errorf("data length = %d, want 2048", len(decoded["data"]))
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

	err := c.Ping(context.Background())
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
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with defaults: %v", err)
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
