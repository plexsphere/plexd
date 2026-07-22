package metrics

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// encryptTestSecret seals plaintext with AES-256-GCM under the given NSK,
// returning the raw envelope nonce || ciphertext+tag suitable for DecryptSecret.
func encryptTestSecret(nsk []byte, plaintext string) []byte {
	block, _ := aes.NewCipher(nsk)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil)
}

// testNSK returns a deterministic 32-byte key for testing.
func testNSK() []byte {
	nsk := make([]byte, 32)
	for i := range nsk {
		nsk[i] = byte(i)
	}
	return nsk
}

// mockSecretFetcher records calls and returns a pre-configured SecretEnvelope.
type mockSecretFetcher struct {
	mu             sync.Mutex
	calls          int
	resp           *api.SecretEnvelope
	err            error
	failAfter      int // if >0, succeed for the first failAfter calls, then fail
	failErr        error
	calledWith     []string // names passed to FetchSecret
	calledVersions []int    // versions passed to FetchSecret
}

func (m *mockSecretFetcher) FetchSecret(_ context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.calledWith = append(m.calledWith, name)
	m.calledVersions = append(m.calledVersions, version)
	if m.failAfter > 0 && m.calls > m.failAfter {
		return nil, m.failErr
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func (m *mockSecretFetcher) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// newTestReporter creates a LocalReporter backed by a TLS httptest server.
// The returned server and reporter are ready for use; the caller must defer
// srv.Close().
func newTestReporter(t *testing.T, handler http.Handler, fetcher SecretFetcher) (*httptest.Server, *LocalReporter) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	nsk := testNSK()
	cfg := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	r := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	// Use the TLS test server's client so certificates are trusted.
	r.httpClient = srv.Client()
	return srv, r
}

// newTestFetcher returns a mockSecretFetcher that returns a valid encrypted
// token.
func newTestFetcher(token string) *mockSecretFetcher {
	nsk := testNSK()
	return &mockSecretFetcher{
		resp: &api.SecretEnvelope{
			Data:    encryptTestSecret(nsk, token),
			Version: 1,
		},
	}
}

// capturingHandler captures slog records for test assertions.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *capturingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *capturingHandler) WithGroup(name string) slog.Handler {
	return h
}

func (h *capturingHandler) getRecords() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	cp := make([]slog.Record, len(h.records))
	copy(cp, h.records)
	return cp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLocalReporter_PostsJSONBatchToConfiguredURL(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotBody        []byte
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("tok-1")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{"cpu":0.5}`)},
	}

	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}

	var decoded api.MetricBatch
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if len(decoded) != 1 {
		t.Errorf("batch length = %d, want 1", len(decoded))
	}
}

func TestLocalReporter_IncludesBearerTokenInAuthHeader(t *testing.T) {
	var gotAuth string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("super-secret-token")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "Bearer super-secret-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer super-secret-token")
	}
}

func TestLocalReporter_ResolvesCredentialViaFetchAndDecrypt(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("decrypted-value")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fetcher.callCount() != 1 {
		t.Errorf("FetchSecret calls = %d, want 1", fetcher.callCount())
	}
	fetcher.mu.Lock()
	if fetcher.calledWith[0] != "metrics-token" {
		t.Errorf("FetchSecret name = %q, want %q", fetcher.calledWith[0], "metrics-token")
	}
	if fetcher.calledVersions[0] != 0 {
		t.Errorf("FetchSecret version = %d, want 0", fetcher.calledVersions[0])
	}
	fetcher.mu.Unlock()
}

func TestLocalReporter_RateLimitedFetchError(t *testing.T) {
	rateLimitErr := &api.APIError{StatusCode: 429, Code: "per_node_rate_limited", RetryAfter: 7 * time.Second}

	t.Run("populated cache falls back with warning", func(t *testing.T) {
		var gotAuth string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		})

		fetcher := newTestFetcher("rl-cached-tok")
		fetcher.failAfter = 1
		fetcher.failErr = rateLimitErr

		ch := &capturingHandler{}
		srv, reporter := newTestReporter(t, handler, fetcher)
		defer srv.Close()
		reporter.logger = slog.New(ch)
		reporter.cacheTTL = 1 * time.Millisecond

		batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
		if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("first call: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("rate-limited fallback: %v", err)
		}

		if gotAuth != "Bearer rl-cached-tok" {
			t.Errorf("Authorization = %q, want cached token", gotAuth)
		}
		found := false
		for _, r := range ch.getRecords() {
			if strings.Contains(r.Message, "using cached credential") {
				found = true
			}
		}
		if !found {
			t.Error("expected warning about using cached credential")
		}
	})

	t.Run("empty cache returns wrapped error", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		fetcher := &mockSecretFetcher{err: rateLimitErr}
		srv, reporter := newTestReporter(t, handler, fetcher)
		defer srv.Close()

		batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
		err := reporter.ReportMetrics(context.Background(), "node-1", batch)
		if err == nil {
			t.Fatal("expected error with empty cache")
		}
		if !strings.Contains(err.Error(), "metrics: fetch secret:") {
			t.Errorf("error = %q, want metrics: fetch secret prefix", err.Error())
		}
	})
}

func TestLocalReporter_DecryptFailureWarnCarriesKIDAndVersion(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// A fetch that succeeds but returns an undecryptable envelope must fall back
	// to the cached token and log the KID and version.
	fetcher := &mockSecretFetcher{
		resp: &api.SecretEnvelope{Data: make([]byte, 28), Version: 9, KID: "kid-9"},
	}

	var buf bytes.Buffer
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()
	reporter.logger = slog.New(slog.NewTextHandler(&buf, nil))

	reporter.mu.Lock()
	reporter.cachedToken = "stale-tok"
	reporter.fetchedAt = time.Now().Add(-time.Hour)
	reporter.mu.Unlock()

	batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
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

func TestLocalReporter_CachesTokenWithinTTL(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("cached-tok")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()
	reporter.cacheTTL = 1 * time.Minute

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	// First call — triggers fetch.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Second call within TTL — should use cache.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fetcher.callCount() != 1 {
		t.Errorf("FetchSecret calls = %d, want 1 (cached)", fetcher.callCount())
	}
}

func TestLocalReporter_RefreshesTokenAfterTTLExpiry(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("refreshed-tok")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()
	reporter.cacheTTL = 1 * time.Millisecond // very short TTL

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)

	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fetcher.callCount() != 2 {
		t.Errorf("FetchSecret calls = %d, want 2 (refreshed after TTL)", fetcher.callCount())
	}
}

func TestLocalReporter_UsesStaleCacheOnFetchError(t *testing.T) {
	var gotAuth string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("stale-tok")
	fetcher.failAfter = 1
	fetcher.failErr = errors.New("network error")

	ch := &capturingHandler{}
	logger := slog.New(ch)

	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()
	reporter.logger = logger
	reporter.cacheTTL = 1 * time.Millisecond

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}

	// First call — succeeds and caches.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	// Second call — fetch fails, should use stale token.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error on stale fallback: %v", err)
	}

	if gotAuth != "Bearer stale-tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer stale-tok")
	}

	// Verify warning was logged.
	records := ch.getRecords()
	found := false
	for _, r := range records {
		if strings.Contains(r.Message, "using cached credential") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning log about using cached credential")
	}
}

func TestLocalReporter_ReturnsErrorWhenNoCacheAndFetchFails(t *testing.T) {
	var called atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	fetcher := &mockSecretFetcher{err: errors.New("connection refused")}
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	err := reporter.ReportMetrics(context.Background(), "node-1", batch)
	if err == nil {
		t.Fatal("expected error when no cache and fetch fails")
	}
	if !strings.Contains(err.Error(), "metrics:") {
		t.Errorf("error = %q, want metrics-prefixed error", err.Error())
	}
	if called.Load() {
		t.Error("HTTP POST should not have been made when token resolution fails")
	}
}

func TestLocalReporter_NonSuccessStatusReturnsError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	fetcher := newTestFetcher("tok")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	err := reporter.ReportMetrics(context.Background(), "node-1", batch)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want status code 500 mentioned", err.Error())
	}
}

func TestLocalReporter_TLSInsecureSkipVerify(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	nsk := testNSK()
	fetcher := newTestFetcher("tls-tok")
	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}

	// With TLSInsecureSkipVerify=true: should succeed.
	cfgInsecure := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	rInsecure := NewLocalReporter(cfgInsecure, fetcher, nsk, "node-1", discardLogger())
	if err := rInsecure.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("InsecureSkipVerify=true failed: %v", err)
	}

	// With TLSInsecureSkipVerify=false: should fail due to self-signed cert.
	cfgSecure := api.LocalEndpointConfig{
		URL:                   srv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: false,
	}
	fetcher2 := newTestFetcher("tls-tok")
	rSecure := NewLocalReporter(cfgSecure, fetcher2, nsk, "node-1", discardLogger())
	err := rSecure.ReportMetrics(context.Background(), "node-1", batch)
	if err == nil {
		t.Fatal("expected TLS error with InsecureSkipVerify=false against self-signed cert")
	}
}

func TestLocalReporter_RequestTimeout(t *testing.T) {
	// Use a raw TCP listener that accepts but never responds, guaranteeing
	// the HTTP client times out without leaving dangling server goroutines.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Accept connections but do nothing (simulates unresponsive server).
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold connection open until test completes.
			go func() {
				defer conn.Close()
				<-time.After(10 * time.Second)
			}()
		}
	}()

	nsk := testNSK()
	fetcher := newTestFetcher("timeout-tok")
	cfg := api.LocalEndpointConfig{
		URL:                   "http://" + ln.Addr().String(),
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	reporter.httpClient.Timeout = 50 * time.Millisecond

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	reportErr := reporter.ReportMetrics(context.Background(), "node-1", batch)
	if reportErr == nil {
		t.Fatal("expected timeout error")
	}
}

func TestLocalReporter_ConcurrentAccessSafe(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("concurrent-tok")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()
	reporter.cacheTTL = 1 * time.Millisecond // force frequent refreshes

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}

	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent call failed: %v", err)
	}
}

func TestLocalReporter_TokenNotInLogs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secretToken := "super-secret-value-12345"
	fetcher := newTestFetcher(secretToken)
	fetcher.failAfter = 1
	fetcher.failErr = errors.New("transient error")

	ch := &capturingHandler{}
	logger := slog.New(ch)

	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()
	reporter.logger = logger
	reporter.cacheTTL = 1 * time.Millisecond

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}

	// First call caches token.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	// Second call — fetch fails, stale cache used, warning logged.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	records := ch.getRecords()
	for _, r := range records {
		if strings.Contains(r.Message, secretToken) {
			t.Errorf("log message contains secret token: %q", r.Message)
		}
		// Check attrs too.
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(fmt.Sprintf("%v", a.Value), secretToken) {
				t.Errorf("log attr %q contains secret token", a.Key)
			}
			return true
		})
	}
}

// ---------------------------------------------------------------------------
// Edge case tests: credential cache (Task 2.2)
// ---------------------------------------------------------------------------

func TestLocalReporter_TTLBoundary_ExactExpiry(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("boundary-tok")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}

	// First call populates cache.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetcher.callCount() != 1 {
		t.Fatalf("expected 1 fetch call, got %d", fetcher.callCount())
	}

	// Manually set fetchedAt to exactly defaultCacheTTL ago.
	reporter.mu.Lock()
	reporter.fetchedAt = time.Now().Add(-defaultCacheTTL)
	reporter.mu.Unlock()

	// Next call should trigger a refresh since TTL has elapsed.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetcher.callCount() != 2 {
		t.Errorf("expected 2 fetch calls after TTL boundary, got %d", fetcher.callCount())
	}
}

func TestLocalReporter_StaleFallbackUnderRepeatedFailures(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("stale-repeated-tok")
	fetcher.failAfter = 1
	fetcher.failErr = errors.New("persistent network error")

	ch := &capturingHandler{}
	logger := slog.New(ch)

	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()
	reporter.logger = logger
	reporter.cacheTTL = 1 * time.Millisecond

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}

	// First call succeeds and caches.
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}

	// Three subsequent calls, each after TTL, should all use stale cache.
	for i := 0; i < 3; i++ {
		time.Sleep(5 * time.Millisecond)
		if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("unexpected error on stale fallback call %d: %v", i+1, err)
		}
	}

	// Verify warnings were logged for each stale fallback.
	records := ch.getRecords()
	warnCount := 0
	for _, r := range records {
		if strings.Contains(r.Message, "using cached credential") {
			warnCount++
		}
	}
	if warnCount != 3 {
		t.Errorf("expected 3 stale cache warnings, got %d", warnCount)
	}
}

func TestLocalReporter_EmptyBatchStillPosts(t *testing.T) {
	var gotBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("empty-tok")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	// Empty batch (nil).
	var batch api.MetricBatch
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error with empty batch: %v", err)
	}

	if gotBody == nil {
		t.Fatal("expected HTTP POST to be made for empty batch")
	}

	// Should serialize as null or empty array.
	if string(gotBody) != "null" && string(gotBody) != "[]" {
		var decoded api.MetricBatch
		if err := json.Unmarshal(gotBody, &decoded); err != nil {
			t.Fatalf("body is not valid JSON: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case tests: HTTP behavior (Task 2.3)
// ---------------------------------------------------------------------------

func TestLocalReporter_LargeBatch(t *testing.T) {
	var gotBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	fetcher := newTestFetcher("large-tok")
	srv, reporter := newTestReporter(t, handler, fetcher)
	defer srv.Close()

	// Create a batch with 1000 points.
	batch := make(api.MetricBatch, 1000)
	for i := range batch {
		batch[i] = api.MetricPoint{
			Timestamp: time.Now(),
			Group:     GroupSystem,
			Data:      json.RawMessage(fmt.Sprintf(`{"cpu":%d}`, i)),
		}
	}

	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error with large batch: %v", err)
	}

	var decoded api.MetricBatch
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if len(decoded) != 1000 {
		t.Errorf("decoded batch length = %d, want 1000", len(decoded))
	}
}

func TestLocalReporter_ServerClosesConnectionMidResponse(t *testing.T) {
	// Create a listener that accepts connections and immediately closes them.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	nsk := testNSK()
	fetcher := newTestFetcher("connclose-tok")
	cfg := api.LocalEndpointConfig{
		URL:       "http://" + ln.Addr().String(),
		SecretKey: "metrics-token",
	}
	reporter := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)},
	}
	reportErr := reporter.ReportMetrics(context.Background(), "node-1", batch)
	if reportErr == nil {
		t.Fatal("expected error when server closes connection")
	}
}
