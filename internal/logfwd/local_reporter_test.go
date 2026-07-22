package logfwd

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testNSK() []byte {
	return make([]byte, 32) // deterministic zero key for tests
}

func encryptTestSecret(nsk []byte, plaintext string) []byte {
	block, _ := aes.NewCipher(nsk)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil)
}

// mockSecretFetcher returns pre-configured secret envelopes.
type mockSecretFetcher struct {
	mu       sync.Mutex
	calls    int
	response *api.SecretEnvelope
	err      error
	versions []int
}

func (m *mockSecretFetcher) FetchSecret(_ context.Context, _, _ string, version int) (*api.SecretEnvelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.versions = append(m.versions, version)
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func (m *mockSecretFetcher) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *mockSecretFetcher) setError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLocalReporter_PostsLogBatchWithBearerAuth(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "test-token")

	var gotReq struct {
		method      string
		contentType string
		authHeader  string
		body        []byte
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq.method = r.Method
		gotReq.contentType = r.Header.Get("Content-Type")
		gotReq.authHeader = r.Header.Get("Authorization")
		gotReq.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		response: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	cfg := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "local-logs",
		TLSInsecureSkipVerify: true,
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	reporter.httpClient = srv.Client()

	batch := api.LogBatch{
		{
			Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Source:    "journald",
			Unit:      "test.service",
			Message:   "hello world",
			Severity:  "info",
			Hostname:  "node-1",
		},
	}

	err := reporter.ReportLogs(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}

	if gotReq.method != http.MethodPost {
		t.Errorf("method = %q, want POST", gotReq.method)
	}
	if gotReq.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotReq.contentType)
	}
	if gotReq.authHeader != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", gotReq.authHeader, "Bearer test-token")
	}
	if !strings.Contains(string(gotReq.body), "hello world") {
		t.Errorf("body does not contain log message: %s", gotReq.body)
	}
	// The forwarder always resolves the current version.
	fetcher.mu.Lock()
	if len(fetcher.versions) == 0 || fetcher.versions[0] != 0 {
		t.Errorf("FetchSecret versions = %v, want first call version 0", fetcher.versions)
	}
	fetcher.mu.Unlock()
}

func TestLocalReporter_CachesAndRefreshesCredential(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "token-v1")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		response: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	cfg := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "local-logs",
		TLSInsecureSkipVerify: true,
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	reporter.httpClient = srv.Client()
	reporter.cacheTTL = 50 * time.Millisecond

	batch := api.LogBatch{{Timestamp: time.Now(), Source: "test", Message: "m1", Severity: "info", Hostname: "h"}}

	// First call fetches the secret.
	if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("first call error = %v", err)
	}
	if fetcher.callCount() != 1 {
		t.Fatalf("expected 1 fetch call, got %d", fetcher.callCount())
	}

	// Second call uses cached token.
	if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("second call error = %v", err)
	}
	if fetcher.callCount() != 1 {
		t.Fatalf("expected still 1 fetch call (cached), got %d", fetcher.callCount())
	}

	// Wait for cache to expire.
	time.Sleep(60 * time.Millisecond)

	// Update the response to a new token.
	envelope2 := encryptTestSecret(nsk, "token-v2")
	fetcher.mu.Lock()
	fetcher.response = &api.SecretEnvelope{Data: envelope2, Version: 2}
	fetcher.mu.Unlock()

	if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("third call error = %v", err)
	}
	if fetcher.callCount() != 2 {
		t.Fatalf("expected 2 fetch calls after TTL expiry, got %d", fetcher.callCount())
	}
}

func TestLocalReporter_UsesStaleCacheOnFetchError(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "stale-token")

	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		response: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	ch := &capturingHandler{}
	logger := slog.New(ch)

	cfg := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "local-logs",
		TLSInsecureSkipVerify: true,
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", logger)
	reporter.httpClient = srv.Client()
	reporter.cacheTTL = 50 * time.Millisecond

	batch := api.LogBatch{{Timestamp: time.Now(), Source: "test", Message: "m1", Severity: "info", Hostname: "h"}}

	// Populate cache.
	if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("initial call error = %v", err)
	}

	// Expire cache and make fetcher fail.
	time.Sleep(60 * time.Millisecond)
	fetcher.setError(errors.New("network error"))

	// Should succeed using stale token.
	if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("stale cache call error = %v", err)
	}
	if gotAuth != "Bearer stale-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer stale-token")
	}

	// Verify warning was logged with the fetch error.
	rec := ch.find("using cached credential")
	if rec == nil {
		t.Fatal("expected warning log about using cached credential")
	}
	if rec.Level != slog.LevelWarn {
		t.Errorf("log level = %v, want WARN", rec.Level)
	}
}

func TestLocalReporter_ReturnsErrorWhenNoCacheAndFetchFails(t *testing.T) {
	nsk := testNSK()

	postCalled := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		postCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{err: errors.New("secret store unavailable")}

	cfg := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "local-logs",
		TLSInsecureSkipVerify: true,
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	reporter.httpClient = srv.Client()

	batch := api.LogBatch{{Timestamp: time.Now(), Source: "test", Message: "m1", Severity: "info", Hostname: "h"}}

	err := reporter.ReportLogs(context.Background(), "node-1", batch)
	if err == nil {
		t.Fatal("expected error when no cache and fetch fails, got nil")
	}
	if !strings.Contains(err.Error(), "logfwd") {
		t.Errorf("error = %q, want error containing 'logfwd'", err.Error())
	}
	if postCalled {
		t.Error("expected no HTTP POST when credential resolution fails")
	}
}

func TestLocalReporter_NonSuccessStatusReturnsError(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "test-token")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		response: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	cfg := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "local-logs",
		TLSInsecureSkipVerify: true,
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	reporter.httpClient = srv.Client()

	batch := api.LogBatch{{Timestamp: time.Now(), Source: "test", Message: "m1", Severity: "info", Hostname: "h"}}

	err := reporter.ReportLogs(context.Background(), "node-1", batch)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want error containing '500'", err.Error())
	}
}

func TestLocalReporter_PreservesLogEntryFields(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "test-token")

	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		response: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	cfg := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "local-logs",
		TLSInsecureSkipVerify: true,
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	reporter.httpClient = srv.Client()

	ts := time.Date(2025, 6, 15, 12, 30, 0, 0, time.UTC)
	batch := api.LogBatch{
		{
			Timestamp: ts,
			Source:    "journald",
			Unit:      "nginx.service",
			Message:   "request received",
			Severity:  "warning",
			Hostname:  "web-node-3",
		},
	}

	if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}

	var decoded []api.LogEntry
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded len = %d, want 1", len(decoded))
	}

	got := decoded[0]
	if !got.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, ts)
	}
	if got.Source != "journald" {
		t.Errorf("Source = %q, want %q", got.Source, "journald")
	}
	if got.Unit != "nginx.service" {
		t.Errorf("Unit = %q, want %q", got.Unit, "nginx.service")
	}
	if got.Message != "request received" {
		t.Errorf("Message = %q, want %q", got.Message, "request received")
	}
	if got.Severity != "warning" {
		t.Errorf("Severity = %q, want %q", got.Severity, "warning")
	}
	if got.Hostname != "web-node-3" {
		t.Errorf("Hostname = %q, want %q", got.Hostname, "web-node-3")
	}
}

func TestLocalReporter_RateLimitedFetchError(t *testing.T) {
	rateLimitErr := &api.APIError{StatusCode: 429, Code: "per_node_rate_limited", RetryAfter: 7 * time.Second}

	t.Run("populated cache falls back with warning", func(t *testing.T) {
		nsk := testNSK()
		envelope := encryptTestSecret(nsk, "rl-cached-tok")

		var gotAuth string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		fetcher := &mockSecretFetcher{response: &api.SecretEnvelope{Data: envelope, Version: 1}}
		ch := &capturingHandler{}

		cfg := api.LocalEndpointConfig{URL: srv.URL, SecretKey: "local-logs", TLSInsecureSkipVerify: true}
		reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", slog.New(ch))
		reporter.httpClient = srv.Client()
		reporter.cacheTTL = 50 * time.Millisecond

		batch := api.LogBatch{{Timestamp: time.Now(), Source: "test", Message: "m1", Severity: "info", Hostname: "h"}}
		if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("initial call: %v", err)
		}
		time.Sleep(60 * time.Millisecond)
		fetcher.setError(rateLimitErr)
		if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("rate-limited fallback: %v", err)
		}

		if gotAuth != "Bearer rl-cached-tok" {
			t.Errorf("Authorization = %q, want cached token", gotAuth)
		}
		if ch.find("using cached credential") == nil {
			t.Error("expected warning about using cached credential")
		}
	})

	t.Run("empty cache returns wrapped error", func(t *testing.T) {
		nsk := testNSK()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		fetcher := &mockSecretFetcher{err: rateLimitErr}
		cfg := api.LocalEndpointConfig{URL: srv.URL, SecretKey: "local-logs", TLSInsecureSkipVerify: true}
		reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
		reporter.httpClient = srv.Client()

		batch := api.LogBatch{{Timestamp: time.Now(), Source: "test", Message: "m1", Severity: "info", Hostname: "h"}}
		err := reporter.ReportLogs(context.Background(), "node-1", batch)
		if err == nil {
			t.Fatal("expected error with empty cache")
		}
		if !strings.Contains(err.Error(), "logfwd: fetch secret:") {
			t.Errorf("error = %q, want logfwd: fetch secret prefix", err.Error())
		}
	})
}

func TestLocalReporter_DecryptFailureWarnCarriesKIDAndVersion(t *testing.T) {
	nsk := testNSK()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// A fetch that succeeds but returns an undecryptable envelope must fall back
	// to the cached token and log the KID and version.
	fetcher := &mockSecretFetcher{response: &api.SecretEnvelope{Data: make([]byte, 28), Version: 9, KID: "kid-9"}}

	var buf bytes.Buffer
	cfg := api.LocalEndpointConfig{URL: srv.URL, SecretKey: "local-logs", TLSInsecureSkipVerify: true}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", slog.New(slog.NewTextHandler(&buf, nil)))
	reporter.httpClient = srv.Client()

	reporter.mu.Lock()
	reporter.cachedToken = "stale-tok"
	reporter.fetchedAt = time.Now().Add(-time.Hour)
	reporter.mu.Unlock()

	batch := api.LogBatch{{Timestamp: time.Now(), Source: "test", Message: "m1", Severity: "info", Hostname: "h"}}
	if err := reporter.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logOut := buf.String()
	if !strings.Contains(logOut, "kid=kid-9") {
		t.Errorf("log missing kid attribute: %s", logOut)
	}
	if !strings.Contains(logOut, "version=9") {
		t.Errorf("log missing version attribute: %s", logOut)
	}
}
