package auditfwd

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

func encryptTestSecret(nsk []byte, plaintext string) []byte {
	block, _ := aes.NewCipher(nsk)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil)
}

// mockSecretFetcher is a test double for SecretFetcher.
type mockSecretFetcher struct {
	mu       sync.Mutex
	calls    int
	resp     *api.SecretEnvelope
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
	return m.resp, nil
}

func (m *mockSecretFetcher) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// testNSK returns a deterministic 32-byte AES key for tests.
func testNSK() []byte {
	nsk := make([]byte, 32)
	for i := range nsk {
		nsk[i] = byte(i)
	}
	return nsk
}

func newTestLocalReporter(url string, fetcher SecretFetcher, httpClient *http.Client) *LocalReporter {
	nsk := testNSK()
	r := &LocalReporter{
		httpClient: httpClient,
		url:        url,
		secretKey:  "audit-secret",
		fetcher:    fetcher,
		nsk:        nsk,
		nodeID:     "node-1",
		logger:     discardLogger(),
		cacheTTL:   5 * time.Minute,
	}
	return r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLocalReporter_PostsAuditBatchPreservingRawMessage(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "test-token")

	var receivedBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		resp: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())

	subject := json.RawMessage(`{"user":"admin","role":"operator"}`)
	object := json.RawMessage(`{"resource":"/api/v1/nodes","id":"node-123"}`)

	batch := api.AuditBatch{
		{
			Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Source:    "k8s-audit",
			EventType: "SYSCALL",
			Subject:   subject,
			Object:    object,
			Action:    "create",
			Result:    "success",
			Hostname:  "host-1",
			Raw:       "raw-line",
		},
	}

	err := reporter.ReportAudit(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the POST body preserves json.RawMessage fields.
	var decoded []api.AuditEntry
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(decoded))
	}
	if string(decoded[0].Subject) != `{"user":"admin","role":"operator"}` {
		t.Errorf("Subject = %s, want %s", decoded[0].Subject, `{"user":"admin","role":"operator"}`)
	}
	if string(decoded[0].Object) != `{"resource":"/api/v1/nodes","id":"node-123"}` {
		t.Errorf("Object = %s, want %s", decoded[0].Object, `{"resource":"/api/v1/nodes","id":"node-123"}`)
	}
	if decoded[0].Source != "k8s-audit" {
		t.Errorf("Source = %q, want %q", decoded[0].Source, "k8s-audit")
	}
	if decoded[0].Raw != "raw-line" {
		t.Errorf("Raw = %q, want %q", decoded[0].Raw, "raw-line")
	}
}

func TestLocalReporter_CredentialResolutionAndCaching(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "test-token")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		resp: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())
	reporter.cacheTTL = 50 * time.Millisecond

	batch := api.AuditBatch{
		{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
	}

	// First call should fetch the secret.
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if fetcher.callCount() != 1 {
		t.Fatalf("expected 1 fetch call, got %d", fetcher.callCount())
	}
	fetcher.mu.Lock()
	if len(fetcher.versions) == 0 || fetcher.versions[0] != 0 {
		t.Errorf("FetchSecret versions = %v, want first call version 0", fetcher.versions)
	}
	fetcher.mu.Unlock()

	// Second call should use cached credential.
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if fetcher.callCount() != 1 {
		t.Fatalf("expected still 1 fetch call (cached), got %d", fetcher.callCount())
	}

	// Wait for cache to expire.
	time.Sleep(60 * time.Millisecond)

	// Third call should re-fetch.
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("third call: %v", err)
	}
	if fetcher.callCount() != 2 {
		t.Fatalf("expected 2 fetch calls after TTL, got %d", fetcher.callCount())
	}
}

func TestLocalReporter_BearerAuthHeader(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "my-bearer-token")

	var receivedAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		resp: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())

	batch := api.AuditBatch{
		{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
	}

	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAuth != "Bearer my-bearer-token" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer my-bearer-token")
	}
}

func TestLocalReporter_UsesStaleCacheOnFetchError(t *testing.T) {
	nsk := testNSK()
	envelope := encryptTestSecret(nsk, "stale-token")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		resp: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	ch := &capturingHandler{}
	logger := slog.New(ch)

	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())
	reporter.logger = logger
	reporter.cacheTTL = 50 * time.Millisecond

	batch := api.AuditBatch{
		{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
	}

	// Populate the cache.
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("initial call: %v", err)
	}

	// Let cache expire, then make fetcher fail.
	time.Sleep(60 * time.Millisecond)
	fetcher.mu.Lock()
	fetcher.err = errors.New("api unavailable")
	fetcher.mu.Unlock()

	// Should still succeed using stale token.
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("expected stale fallback to succeed, got: %v", err)
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
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := &mockSecretFetcher{
		err: errors.New("api unavailable"),
	}

	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())

	batch := api.AuditBatch{
		{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
	}

	err := reporter.ReportAudit(context.Background(), "node-1", batch)
	if err == nil {
		t.Fatal("expected error when no cache and fetch fails")
	}
	if !errors.Is(err, fetcher.err) {
		t.Errorf("error = %v, want wrapped %v", err, fetcher.err)
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
		resp: &api.SecretEnvelope{Data: envelope, Version: 1},
	}

	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())

	batch := api.AuditBatch{
		{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
	}

	err := reporter.ReportAudit(context.Background(), "node-1", batch)
	if err == nil {
		t.Fatal("expected error for non-success status")
	}
	if got := err.Error(); got != "auditfwd: post audit batch: unexpected status 500" {
		t.Errorf("error = %q, want %q", got, "auditfwd: post audit batch: unexpected status 500")
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

		fetcher := &mockSecretFetcher{resp: &api.SecretEnvelope{Data: envelope, Version: 1}}
		ch := &capturingHandler{}
		reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())
		reporter.logger = slog.New(ch)
		reporter.cacheTTL = 50 * time.Millisecond

		batch := api.AuditBatch{{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"}}
		if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("initial call: %v", err)
		}
		time.Sleep(60 * time.Millisecond)
		fetcher.mu.Lock()
		fetcher.err = rateLimitErr
		fetcher.mu.Unlock()
		if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
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
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		fetcher := &mockSecretFetcher{err: rateLimitErr}
		reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())

		batch := api.AuditBatch{{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"}}
		err := reporter.ReportAudit(context.Background(), "node-1", batch)
		if err == nil {
			t.Fatal("expected error with empty cache")
		}
		if !strings.Contains(err.Error(), "auditfwd: fetch secret:") {
			t.Errorf("error = %q, want auditfwd: fetch secret prefix", err.Error())
		}
	})
}

func TestLocalReporter_DecryptFailureWarnCarriesKIDAndVersion(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// A fetch that succeeds but returns an undecryptable envelope must fall back
	// to the cached token and log the KID and version.
	fetcher := &mockSecretFetcher{resp: &api.SecretEnvelope{Data: make([]byte, 28), Version: 9, KID: "kid-9"}}
	var buf bytes.Buffer
	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())
	reporter.logger = slog.New(slog.NewTextHandler(&buf, nil))

	reporter.mu.Lock()
	reporter.cachedToken = "stale-tok"
	reporter.fetchedAt = time.Now().Add(-time.Hour)
	reporter.mu.Unlock()

	batch := api.AuditBatch{{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"}}
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
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
