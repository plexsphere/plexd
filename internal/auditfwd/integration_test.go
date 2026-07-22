package auditfwd

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

type auditHTTPCapture struct {
	mu       sync.Mutex
	requests []auditCapturedRequest
}

type auditCapturedRequest struct {
	Method      string
	ContentType string
	Auth        string
	Body        []byte
}

func (c *auditHTTPCapture) handler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests = append(c.requests, auditCapturedRequest{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			Auth:        r.Header.Get("Authorization"),
			Body:        body,
		})
		c.mu.Unlock()
		w.WriteHeader(status)
	})
}

func (c *auditHTTPCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *auditHTTPCapture) get(i int) auditCapturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[i]
}

func auditWaitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
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

func makeAuditEntries(n int) []api.AuditEntry {
	entries := make([]api.AuditEntry, n)
	for i := range entries {
		entries[i] = api.AuditEntry{
			Timestamp: time.Now(),
			Source:    "test-audit",
			EventType: "SYSCALL",
			Action:    "create",
			Result:    "success",
			Hostname:  "test-host",
		}
	}
	return entries
}

func newAuditTestFetcher(token string) *mockSecretFetcher {
	nsk := testNSK()
	return &mockSecretFetcher{
		resp: &api.SecretEnvelope{Data: encryptTestSecret(nsk, token), Version: 1},
	}
}

// ---------------------------------------------------------------------------
// REQ-001, REQ-003, REQ-005, REQ-008: Dual delivery happy path
// ---------------------------------------------------------------------------

func TestIntegration_DualDelivery_BothReceiveSameAuditBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &auditHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockAuditReporter{}

	nsk := testNSK()
	fetcher := newAuditTestFetcher("integration-token")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "audit-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()

	multi := NewMultiReporter(platform, local, discardLogger())

	fwdCfg := Config{
		Enabled:         true,
		CollectInterval: 25 * time.Millisecond,
		ReportInterval:  60 * time.Millisecond,
		BatchSize:       500,
	}
	src := &mockAuditSource{entries: makeAuditEntries(3)}
	fwd := NewForwarder(fwdCfg, []AuditSource{src}, multi, "node-1", "test-host", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fwd.Run(ctx) }()

	auditWaitFor(t, 3*time.Second, func() bool {
		return platform.callCount() >= 1 && localCapture.count() >= 1
	}, "both platform and local to receive at least one audit batch")

	cancel()
	<-done

	// Verify platform received the batch.
	platform.mu.Lock()
	pBatch := platform.calls[0].Batch
	platform.mu.Unlock()
	if len(pBatch) == 0 {
		t.Fatal("platform received empty audit batch")
	}

	// Verify local endpoint received JSON POST.
	req := localCapture.get(0)
	if req.Method != http.MethodPost {
		t.Errorf("local method = %q, want POST", req.Method)
	}
	if req.ContentType != "application/json" {
		t.Errorf("local Content-Type = %q, want application/json", req.ContentType)
	}

	// Verify local received valid audit batch.
	var localBatch api.AuditBatch
	if err := json.Unmarshal(req.Body, &localBatch); err != nil {
		t.Fatalf("failed to unmarshal local body: %v", err)
	}
	if len(localBatch) == 0 {
		t.Fatal("local received empty audit batch")
	}
	if len(pBatch) != len(localBatch) {
		t.Errorf("batch size mismatch: platform=%d, local=%d", len(pBatch), len(localBatch))
	}
}

func TestIntegration_DualDelivery_CredentialResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &auditHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockAuditReporter{}

	nsk := testNSK()
	fetcher := newAuditTestFetcher("resolved-audit-bearer")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "audit-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()

	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeAuditEntries(2)
	err := multi.ReportAudit(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("ReportAudit error: %v", err)
	}

	if localCapture.count() < 1 {
		t.Fatal("local endpoint did not receive request")
	}
	req := localCapture.get(0)
	if req.Auth != "Bearer resolved-audit-bearer" {
		t.Errorf("Authorization = %q, want %q", req.Auth, "Bearer resolved-audit-bearer")
	}
	if fetcher.callCount() != 1 {
		t.Errorf("FetchSecret calls = %d, want 1", fetcher.callCount())
	}
}

// ---------------------------------------------------------------------------
// REQ-004, REQ-009: Error isolation
// ---------------------------------------------------------------------------

func TestIntegration_LocalDown_PlatformReceivesAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer localSrv.Close()

	platform := &mockAuditReporter{}
	nsk := testNSK()
	fetcher := newAuditTestFetcher("tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "audit-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()
	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeAuditEntries(2)
	err := multi.ReportAudit(context.Background(), "node-1", batch)

	if err != nil {
		t.Fatalf("expected nil error (platform succeeded), got %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
}

func TestIntegration_CredentialFailure_AuditFwd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	platform := &mockAuditReporter{}
	fetcher := &mockSecretFetcher{err: errors.New("secret store unavailable")}

	nsk := testNSK()
	cfg := api.LocalEndpointConfig{
		URL:                   "https://unreachable.local:9999/ingest",
		SecretKey:             "audit-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeAuditEntries(2)
	err := multi.ReportAudit(context.Background(), "node-1", batch)

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

func TestIntegration_TLSSkipVerify_AuditFwd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &auditHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	nsk := testNSK()
	fetcher := newAuditTestFetcher("tls-tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "audit-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())

	batch := makeAuditEntries(1)
	err := local.ReportAudit(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("expected success with skip-verify=true, got %v", err)
	}
	if localCapture.count() != 1 {
		t.Errorf("local requests = %d, want 1", localCapture.count())
	}
}

func TestIntegration_TLSStrictVerify_AuditFwd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &auditHTTPCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockAuditReporter{}

	nsk := testNSK()
	fetcher := newAuditTestFetcher("tls-tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "audit-token",
		TLSInsecureSkipVerify: false,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	multi := NewMultiReporter(platform, local, discardLogger())

	batch := makeAuditEntries(1)
	err := multi.ReportAudit(context.Background(), "node-1", batch)

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
