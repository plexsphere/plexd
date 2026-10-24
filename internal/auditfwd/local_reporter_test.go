package auditfwd

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
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			fetcher := &mockSecretFetcher{
				resp: &api.SecretEnvelope{Data: encryptTestSecret(testNSK(), "stale-token"), Version: 1},
			}

			ch := &capturingHandler{}
			reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())
			reporter.logger = slog.New(ch)
			// A zero TTL makes every call fetch again, so the second call
			// takes the fetch-error branch with the token the first cached.
			reporter.cacheTTL = 0

			batch := api.AuditBatch{
				{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
			}
			if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("initial call: %v", err)
			}
			fetcher.mu.Lock()
			fetcher.err = tc.err
			fetcher.mu.Unlock()
			if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("expected stale fallback to succeed, got: %v", err)
			}
			if fetcher.callCount() != 2 {
				t.Fatalf("FetchSecret calls = %d, want 2", fetcher.callCount())
			}

			rec := ch.find("using cached credential")
			if rec == nil {
				t.Fatal("expected a log about using cached credential")
			}
			if rec.Level != tc.level {
				t.Errorf("log level = %v, want %v", rec.Level, tc.level)
			}
			ch.mu.Lock()
			n := len(ch.records)
			ch.mu.Unlock()
			if n != 1 {
				t.Errorf("records = %d, want only the cached-credential fallback", n)
			}
		})
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

// newRecordingReporter returns a LocalReporter that posts to endpoint over TLS,
// logs to ch, and fetches on every call. The caller must close the server.
func newRecordingReporter(endpoint http.Handler, fetcher SecretFetcher, ch *capturingHandler) (*httptest.Server, *LocalReporter) {
	srv := httptest.NewTLSServer(endpoint)
	reporter := newTestLocalReporter(srv.URL, fetcher, srv.Client())
	reporter.logger = slog.New(ch)
	// A zero TTL makes every call fetch again, so a call after the first
	// takes the fetch-error branch with the token the first cached.
	reporter.cacheTTL = 0
	return srv, reporter
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
			fetcher := &mockSecretFetcher{
				resp: &api.SecretEnvelope{Data: encryptTestSecret(testNSK(), "cached-tok"), Version: 1},
			}
			ch := &capturingHandler{}
			srv, reporter := newRecordingReporter(endpoint, fetcher, ch)
			defer srv.Close()

			batch := api.AuditBatch{
				{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
			}
			if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("first call: %v", err)
			}
			fetcher.mu.Lock()
			fetcher.err = tc.err
			fetcher.mu.Unlock()

			err := reporter.ReportAudit(context.Background(), "node-1", batch)
			if !errors.Is(err, tc.target) {
				t.Fatalf("second call error = %v, want one matching %v", err, tc.target)
			}
			if !strings.Contains(err.Error(), "auditfwd: fetch secret:") {
				t.Errorf("error = %q, want auditfwd: fetch secret prefix", err.Error())
			}
			if got := endpoint.got(); len(got) != 1 {
				t.Fatalf("POSTs = %q, want only the first call's", got)
			}

			if n := countLog(ch, slog.LevelWarn, "dropping revoked credential"); n != 1 {
				t.Fatalf("WARN %q records = %d, want 1", "dropping revoked credential", n)
			}
			rec := ch.find("dropping revoked credential")
			if rec.Attrs["component"] != "auditfwd" {
				t.Errorf("drop component = %v, want auditfwd", rec.Attrs["component"])
			}
			if _, ok := rec.Attrs["error"]; !ok {
				t.Error("drop record carries no error attribute")
			}

			ch.mu.Lock()
			records := append([]logRecord(nil), ch.records...)
			ch.mu.Unlock()
			for _, r := range records {
				if r.Message == "using cached credential" {
					t.Errorf("unexpected %q record at %v", r.Message, r.Level)
				}
				if strings.Contains(r.Message, "cached-tok") {
					t.Errorf("log message contains the token: %q", r.Message)
				}
				for k, v := range r.Attrs {
					if strings.Contains(fmt.Sprintf("%v", v), "cached-tok") {
						t.Errorf("log attr %q contains the token", k)
					}
				}
			}

			// The cache stays empty: the next send fetches again and fails
			// the same way, without a second drop.
			err = reporter.ReportAudit(context.Background(), "node-1", batch)
			if !errors.Is(err, tc.target) {
				t.Fatalf("third call error = %v, want one matching %v", err, tc.target)
			}
			if fetcher.callCount() != 3 {
				t.Errorf("FetchSecret calls = %d, want 3", fetcher.callCount())
			}
			if got := endpoint.got(); len(got) != 1 {
				t.Errorf("POSTs = %q, want only the first call's", got)
			}
			if n := countLog(ch, slog.LevelWarn, "dropping revoked credential"); n != 1 {
				t.Errorf("WARN %q records = %d, want still 1", "dropping revoked credential", n)
			}
		})
	}
}

// TestLocalReporter_ResumesAfterRevocationOnSuccessfulFetch pins that once a
// revocation dropped the token, the first fetch that succeeds again restores
// forwarding with the token it returned.
func TestLocalReporter_ResumesAfterRevocationOnSuccessfulFetch(t *testing.T) {
	endpoint := &postRecorder{}
	fetcher := &mockSecretFetcher{
		resp: &api.SecretEnvelope{Data: encryptTestSecret(testNSK(), "cached-tok"), Version: 1},
	}
	srv, reporter := newRecordingReporter(endpoint, fetcher, &capturingHandler{})
	defer srv.Close()

	batch := api.AuditBatch{
		{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
	}
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("first call: %v", err)
	}
	fetcher.mu.Lock()
	fetcher.err = &api.APIError{StatusCode: 403, Code: "permission_denied"}
	fetcher.mu.Unlock()
	if err := reporter.ReportAudit(context.Background(), "node-1", batch); !errors.Is(err, api.ErrForbidden) {
		t.Fatalf("revoked call error = %v, want one matching api.ErrForbidden", err)
	}

	// The grant is restored, and the fetch serves a new version.
	fetcher.mu.Lock()
	fetcher.err = nil
	fetcher.resp = &api.SecretEnvelope{Data: encryptTestSecret(testNSK(), "regranted-tok"), Version: 2}
	fetcher.mu.Unlock()

	if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
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
	srv, reporter := newRecordingReporter(endpoint, fetcher, ch)
	defer srv.Close()

	batch := api.AuditBatch{
		{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
	}
	for i := 0; i < 2; i++ {
		if err := reporter.ReportAudit(context.Background(), "node-1", batch); !errors.Is(err, api.ErrForbidden) {
			t.Fatalf("call %d error = %v, want one matching api.ErrForbidden", i+1, err)
		}
	}
	if fetcher.callCount() != 2 {
		t.Errorf("FetchSecret calls = %d, want 2", fetcher.callCount())
	}
	if got := endpoint.got(); len(got) != 0 {
		t.Errorf("POSTs = %q, want none", got)
	}
	if rec := ch.find("dropping revoked credential"); rec != nil {
		t.Errorf("unexpected %q record at %v", rec.Message, rec.Level)
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
			fetcher := &mockSecretFetcher{
				resp: &api.SecretEnvelope{Data: encryptTestSecret(testNSK(), "cached-tok"), Version: 1},
			}
			ch := &capturingHandler{}
			srv, reporter := newRecordingReporter(endpoint, fetcher, ch)
			defer srv.Close()

			batch := api.AuditBatch{
				{Timestamp: time.Now(), Source: "test", EventType: "TEST", Action: "a", Result: "ok", Hostname: "h"},
			}
			if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("first call: %v", err)
			}
			fetcher.mu.Lock()
			fetcher.err = tc.err
			fetcher.mu.Unlock()
			if err := reporter.ReportAudit(context.Background(), "node-1", batch); err != nil {
				t.Fatalf("fallback call: %v", err)
			}

			want := []string{"Bearer cached-tok", "Bearer cached-tok"}
			if got := endpoint.got(); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("Authorization headers = %q, want %q", got, want)
			}
			if n := countLog(ch, tc.level, "using cached credential"); n != 1 {
				t.Errorf("%s records %q = %d, want 1", tc.level, "using cached credential", n)
			}
			if rec := ch.find("dropping revoked credential"); rec != nil {
				t.Errorf("unexpected %q record at %v", rec.Message, rec.Level)
			}
		})
	}
}
