package logfwd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Integration test helpers
// ---------------------------------------------------------------------------

type logHTTPCapture struct {
	mu       sync.Mutex
	requests []logCapturedRequest
}

type logCapturedRequest struct {
	Method      string
	ContentType string
	Auth        string
	Body        []byte
}

func (c *logHTTPCapture) handler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests = append(c.requests, logCapturedRequest{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			Auth:        r.Header.Get("Authorization"),
			Body:        body,
		})
		c.mu.Unlock()
		w.WriteHeader(status)
	})
}

func (c *logHTTPCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *logHTTPCapture) get(i int) logCapturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[i]
}

func logWaitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting: %s", msg)
		case <-tick.C:
		}
	}
}

func makeLogEntries(n int) []api.LogEntry {
	entries := make([]api.LogEntry, n)
	for i := range entries {
		entries[i] = api.LogEntry{
			Timestamp: time.Now(),
			Source:    "journald",
			Unit:      "test.service",
			Message:   "test log message",
			Severity:  "info",
			Hostname:  "test-host",
		}
	}
	return entries
}

func newLogTestFetcher(token string) *mockSecretFetcher {
	nsk := testNSK()
	return &mockSecretFetcher{
		response: &api.SecretEnvelope{Data: encryptTestSecret(nsk, token), Version: 1},
	}
}

// ---------------------------------------------------------------------------
// REQ-001, REQ-003, REQ-005, REQ-008: Dual delivery happy path
// ---------------------------------------------------------------------------

func TestIntegration_DualDelivery_BothReceiveSameLogBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &logHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockLogReporter{}

	nsk := testNSK()
	fetcher := newLogTestFetcher("integration-token")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "logs-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()

	multi := NewMultiReporter(platform, local, discardLogger())

	fwdCfg := Config{
		Enabled:         true,
		CollectInterval: 25 * time.Millisecond,
		ReportInterval:  60 * time.Millisecond,
		BatchSize:       200,
	}
	src := &mockLogSource{entries: makeLogEntries(3)}
	fwd := NewForwarder(fwdCfg, []LogSource{src}, multi, "node-1", "test-host", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fwd.Run(ctx) }()

	logWaitFor(t, 3*time.Second, func() bool {
		return platform.callCount() >= 1 && localCapture.count() >= 1
	}, "both platform and local to receive at least one log batch")

	cancel()
	<-done

	// Verify platform received the batch.
	platform.mu.Lock()
	pBatch := platform.calls[0].Batch
	platform.mu.Unlock()
	if len(pBatch) == 0 {
		t.Fatal("platform received empty log batch")
	}

	// Verify local endpoint received JSON POST.
	req := localCapture.get(0)
	if req.Method != http.MethodPost {
		t.Errorf("local method = %q, want POST", req.Method)
	}
	if req.ContentType != "application/json" {
		t.Errorf("local Content-Type = %q, want application/json", req.ContentType)
	}

	// Verify local received valid log batch.
	var localBatch api.LogBatch
	if err := json.Unmarshal(req.Body, &localBatch); err != nil {
		t.Fatalf("failed to unmarshal local body: %v", err)
	}
	if len(localBatch) == 0 {
		t.Fatal("local received empty log batch")
	}
	if len(pBatch) != len(localBatch) {
		t.Errorf("batch size mismatch: platform=%d, local=%d", len(pBatch), len(localBatch))
	}
}

func TestIntegration_DualDelivery_CredentialResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &logHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockLogReporter{}

	nsk := testNSK()
	fetcher := newLogTestFetcher("resolved-log-bearer")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "logs-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()

	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeLogEntries(2)
	err := multi.ReportLogs(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("ReportLogs error: %v", err)
	}

	if localCapture.count() < 1 {
		t.Fatal("local endpoint did not receive request")
	}
	req := localCapture.get(0)
	if req.Auth != "Bearer resolved-log-bearer" {
		t.Errorf("Authorization = %q, want %q", req.Auth, "Bearer resolved-log-bearer")
	}
	if fetcher.callCount() != 1 {
		t.Errorf("FetchSecret calls = %d, want 1", fetcher.callCount())
	}
}

// ---------------------------------------------------------------------------
// REQ-004, REQ-009: Error isolation
// ---------------------------------------------------------------------------

func TestIntegration_LocalDown_PlatformReceivesLogs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer localSrv.Close()

	platform := &mockLogReporter{}
	nsk := testNSK()
	fetcher := newLogTestFetcher("tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "logs-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()
	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeLogEntries(2)
	err := multi.ReportLogs(context.Background(), "node-1", batch)

	if err != nil {
		t.Fatalf("expected nil error (platform succeeded), got %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
}

func TestIntegration_CredentialFailure_LogFwd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	platform := &mockLogReporter{}
	fetcher := &mockSecretFetcher{err: errors.New("secret store unavailable")}

	nsk := testNSK()
	cfg := api.LocalEndpointConfig{
		URL:                   "https://unreachable.local:9999/ingest",
		SecretKey:             "logs-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeLogEntries(2)
	err := multi.ReportLogs(context.Background(), "node-1", batch)

	if err != nil {
		t.Fatalf("expected nil error (platform succeeded), got %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
}

// ---------------------------------------------------------------------------
// REQ-006, REQ-010: TLS skip-verify
// ---------------------------------------------------------------------------

func TestIntegration_TLSSkipVerify_LogFwd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &logHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	nsk := testNSK()
	fetcher := newLogTestFetcher("tls-tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "logs-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())

	batch := makeLogEntries(1)
	err := local.ReportLogs(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("expected success with skip-verify=true, got %v", err)
	}
	if localCapture.count() != 1 {
		t.Errorf("local requests = %d, want 1", localCapture.count())
	}
}

func TestIntegration_TLSStrictVerify_LogFwd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &logHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockLogReporter{}

	nsk := testNSK()
	fetcher := newLogTestFetcher("tls-tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "logs-token",
		TLSInsecureSkipVerify: false,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeLogEntries(1)
	err := multi.ReportLogs(context.Background(), "node-1", batch)

	if err != nil {
		t.Fatalf("expected nil (platform succeeded), got %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
	if localCapture.count() != 0 {
		t.Errorf("local requests = %d, want 0 (TLS failure)", localCapture.count())
	}
}
