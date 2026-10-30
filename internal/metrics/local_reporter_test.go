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

// TestLocalReporter_LogsRefusedCredentialFallbackAtDebug pins that falling back
// to the cached token because the secret fetch was refused locally for the
// node credential is logged at Debug, while any other fetch failure stays a
// Warn.
func TestLocalReporter_LogsRefusedCredentialFallbackAtDebug(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		level slog.Level
	}{
		{"refused credential", fmt.Errorf("x: %w", api.ErrCredentialRefused), slog.LevelDebug},
		{"other failure", errors.New("boom"), slog.LevelWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			fetcher := newTestFetcher("stale-tok")
			fetcher.failAfter = 1
			fetcher.failErr = tc.err

			ch := &capturingHandler{}
			srv, reporter := newTestReporter(t, handler, fetcher)
			defer srv.Close()
			reporter.logger = slog.New(ch)
			// A zero TTL makes every call fetch again, so the second call
			// takes the fetch-error branch with the token the first cached.
			reporter.cacheTTL = 0

			batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
			if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("first call: %v", err)
			}
			if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("stale fallback: %v", err)
			}
			if fetcher.callCount() != 2 {
				t.Fatalf("FetchSecret calls = %d, want 2", fetcher.callCount())
			}

			if n := countLog(ch, tc.level, "using cached credential"); n != 1 {
				t.Errorf("%s records %q = %d, want 1", tc.level, "using cached credential", n)
			}
			if n := len(ch.getRecords()); n != 1 {
				t.Errorf("records = %d, want only the cached-credential fallback", n)
			}
		})
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
// Edge case tests: credential cache
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
// Edge case tests: HTTP behavior
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

// ---------------------------------------------------------------------------
// Revoked credentials
// ---------------------------------------------------------------------------

// postRecorder is a local endpoint that records the Authorization header of
// every POST it receives.
type postRecorder struct {
	mu    sync.Mutex
	auths []string
}

func (p *postRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.auths = append(p.auths, r.Header.Get("Authorization"))
	p.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (p *postRecorder) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.auths...)
}

// dropRecords returns the captured "dropping revoked credential" records.
func dropRecords(ch *capturingHandler) []slog.Record {
	var out []slog.Record
	for _, r := range ch.getRecords() {
		if r.Message == "dropping revoked credential" {
			out = append(out, r)
		}
	}
	return out
}

// TestLocalReporter_DropsCachedCredentialOnRevocation pins that a 403 or 404
// from the secret fetch drops the cached token instead of falling back to it:
// the send fails without a POST, the drop is logged once, and every later send
// fetches again.
func TestLocalReporter_DropsCachedCredentialOnRevocation(t *testing.T) {
	// The fetch answers that say the Node may no longer read the secret,
	// each with the sentinel the send's error must match.
	cases := []struct {
		name   string
		err    error
		target error
	}{
		{"403 permission_denied", &api.APIError{StatusCode: 403, Code: "permission_denied"}, api.ErrForbidden},
		{"403 without a code", &api.APIError{StatusCode: 403}, api.ErrForbidden},
		{"404 secret_not_found", &api.APIError{StatusCode: 404, Code: "secret_not_found"}, api.ErrNotFound},
		{"404 secret_version_not_found", &api.APIError{StatusCode: 404, Code: "secret_version_not_found"}, api.ErrNotFound},
		{"wrapped 403", fmt.Errorf("fetch: %w", &api.APIError{StatusCode: 403, Code: "permission_denied"}), api.ErrForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := &postRecorder{}
			fetcher := newTestFetcher("cached-tok")
			fetcher.failAfter = 1
			fetcher.failErr = tc.err

			ch := &capturingHandler{}
			srv, reporter := newTestReporter(t, endpoint, fetcher)
			defer srv.Close()
			reporter.logger = slog.New(ch)
			// A zero TTL makes every call fetch again, so the second call
			// takes the fetch-error branch with the token the first cached.
			reporter.cacheTTL = 0

			batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
			if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("first call: %v", err)
			}

			err := reporter.ReportMetrics(context.Background(), "node-1", batch)
			if !errors.Is(err, tc.target) {
				t.Fatalf("second call error = %v, want one matching %v", err, tc.target)
			}
			if !strings.Contains(err.Error(), "metrics: fetch secret:") {
				t.Errorf("error = %q, want metrics: fetch secret prefix", err.Error())
			}
			if got := endpoint.got(); len(got) != 1 {
				t.Fatalf("POSTs = %q, want only the first call's", got)
			}

			drops := dropRecords(ch)
			if len(drops) != 1 {
				t.Fatalf("%q records = %d, want 1", "dropping revoked credential", len(drops))
			}
			if drops[0].Level != slog.LevelWarn {
				t.Errorf("drop level = %v, want WARN", drops[0].Level)
			}
			attrs := map[string]string{}
			drops[0].Attrs(func(a slog.Attr) bool {
				attrs[a.Key] = fmt.Sprintf("%v", a.Value)
				return true
			})
			if attrs["component"] != "metrics" {
				t.Errorf("drop component = %q, want metrics", attrs["component"])
			}
			if _, ok := attrs["error"]; !ok {
				t.Error("drop record carries no error attribute")
			}

			for _, r := range ch.getRecords() {
				if r.Message == "using cached credential" {
					t.Errorf("unexpected %q record at %v", r.Message, r.Level)
				}
				if strings.Contains(r.Message, "cached-tok") {
					t.Errorf("log message contains the token: %q", r.Message)
				}
				r.Attrs(func(a slog.Attr) bool {
					if strings.Contains(fmt.Sprintf("%v", a.Value), "cached-tok") {
						t.Errorf("log attr %q contains the token", a.Key)
					}
					return true
				})
			}

			// The cache stays empty: the next send fetches again and fails
			// the same way, without a second drop.
			err = reporter.ReportMetrics(context.Background(), "node-1", batch)
			if !errors.Is(err, tc.target) {
				t.Fatalf("third call error = %v, want one matching %v", err, tc.target)
			}
			if fetcher.callCount() != 3 {
				t.Errorf("FetchSecret calls = %d, want 3", fetcher.callCount())
			}
			if got := endpoint.got(); len(got) != 1 {
				t.Errorf("POSTs = %q, want only the first call's", got)
			}
			if n := len(dropRecords(ch)); n != 1 {
				t.Errorf("%q records = %d, want still 1", "dropping revoked credential", n)
			}
		})
	}
}

// TestLocalReporter_ResumesAfterRevocationOnSuccessfulFetch pins that once a
// revocation dropped the token, the first fetch that succeeds again restores
// forwarding with the token it returned.
func TestLocalReporter_ResumesAfterRevocationOnSuccessfulFetch(t *testing.T) {
	endpoint := &postRecorder{}
	fetcher := newTestFetcher("cached-tok")
	fetcher.failAfter = 1
	fetcher.failErr = &api.APIError{StatusCode: 403, Code: "permission_denied"}

	srv, reporter := newTestReporter(t, endpoint, fetcher)
	defer srv.Close()
	reporter.cacheTTL = 0

	batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); !errors.Is(err, api.ErrForbidden) {
		t.Fatalf("revoked call error = %v, want one matching api.ErrForbidden", err)
	}

	// The grant is restored, and the fetch serves a new version.
	fetcher.mu.Lock()
	fetcher.failAfter = 0
	fetcher.failErr = nil
	fetcher.resp = &api.SecretEnvelope{Data: encryptTestSecret(testNSK(), "regranted-tok"), Version: 2}
	fetcher.mu.Unlock()

	if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("call after the grant was restored: %v", err)
	}
	want := []string{"Bearer cached-tok", "Bearer regranted-tok"}
	if got := endpoint.got(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Authorization headers = %q, want %q", got, want)
	}
}

// TestLocalReporter_RevocationWithoutCacheReturnsError pins that a 403 with
// nothing cached fails every send, fetching again each time, and logs no drop.
func TestLocalReporter_RevocationWithoutCacheReturnsError(t *testing.T) {
	endpoint := &postRecorder{}
	fetcher := &mockSecretFetcher{err: &api.APIError{StatusCode: 403, Code: "permission_denied"}}

	ch := &capturingHandler{}
	srv, reporter := newTestReporter(t, endpoint, fetcher)
	defer srv.Close()
	reporter.logger = slog.New(ch)
	reporter.cacheTTL = 0

	batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
	for i := 0; i < 2; i++ {
		if err := reporter.ReportMetrics(context.Background(), "node-1", batch); !errors.Is(err, api.ErrForbidden) {
			t.Fatalf("call %d error = %v, want one matching api.ErrForbidden", i+1, err)
		}
	}
	if fetcher.callCount() != 2 {
		t.Errorf("FetchSecret calls = %d, want 2", fetcher.callCount())
	}
	if got := endpoint.got(); len(got) != 0 {
		t.Errorf("POSTs = %q, want none", got)
	}
	if n := len(dropRecords(ch)); n != 0 {
		t.Errorf("%q records = %d, want 0", "dropping revoked credential", n)
	}
}

// TestLocalReporter_KeepsCachedCredentialOnNonRevocationFetchError pins that a
// fetch failure that says nothing about the grant still falls back to the
// cached token.
func TestLocalReporter_KeepsCachedCredentialOnNonRevocationFetchError(t *testing.T) {
	// Fetch failures that say nothing about the grant, each with the level
	// the fallback to the cached token is logged at.
	cases := []struct {
		name  string
		err   error
		level slog.Level
	}{
		{"401 unauthorized", &api.APIError{StatusCode: 401, Code: "unauthorized"}, slog.LevelWarn},
		{"refused credential", fmt.Errorf("x: %w", api.ErrCredentialRefused), slog.LevelDebug},
		{"429 per_node_rate_limited", &api.APIError{StatusCode: 429, Code: "per_node_rate_limited", RetryAfter: 7 * time.Second}, slog.LevelWarn},
		{"500", &api.APIError{StatusCode: 500}, slog.LevelWarn},
		{"501 secrets_not_provisioned", &api.APIError{StatusCode: 501, Code: "secrets_not_provisioned"}, slog.LevelWarn},
		{"503 openbao_unavailable", &api.APIError{StatusCode: 503, Code: "openbao_unavailable"}, slog.LevelWarn},
		{"503 authz_unavailable", &api.APIError{StatusCode: 503, Code: "authz_unavailable"}, slog.LevelWarn},
		{"deadline exceeded", context.DeadlineExceeded, slog.LevelWarn},
		{"transport error", errors.New("dial tcp: connection refused"), slog.LevelWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := &postRecorder{}
			fetcher := newTestFetcher("cached-tok")
			fetcher.failAfter = 1
			fetcher.failErr = tc.err

			ch := &capturingHandler{}
			srv, reporter := newTestReporter(t, endpoint, fetcher)
			defer srv.Close()
			reporter.logger = slog.New(ch)
			reporter.cacheTTL = 0

			batch := api.MetricBatch{{Timestamp: time.Now(), Group: GroupSystem, Data: json.RawMessage(`{}`)}}
			if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("first call: %v", err)
			}
			if err := reporter.ReportMetrics(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("fallback call: %v", err)
			}

			want := []string{"Bearer cached-tok", "Bearer cached-tok"}
			if got := endpoint.got(); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("Authorization headers = %q, want %q", got, want)
			}
			if n := countLog(ch, tc.level, "using cached credential"); n != 1 {
				t.Errorf("%s records %q = %d, want 1", tc.level, "using cached credential", n)
			}
			if n := len(dropRecords(ch)); n != 0 {
				t.Errorf("%q records = %d, want 0", "dropping revoked credential", n)
			}
		})
	}
}
