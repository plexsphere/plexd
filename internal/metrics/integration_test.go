package metrics

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

// httpCapture records incoming HTTP requests for assertions.
type httpCapture struct {
	mu       sync.Mutex
	requests []capturedRequest
}

type capturedRequest struct {
	Method      string
	ContentType string
	Auth        string
	Body        []byte
}

func (c *httpCapture) handler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests = append(c.requests, capturedRequest{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			Auth:        r.Header.Get("Authorization"),
			Body:        body,
		})
		c.mu.Unlock()
		w.WriteHeader(status)
	})
}

func (c *httpCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *httpCapture) get(i int) capturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[i]
}

// waitFor polls until cond returns true or timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
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

// ---------------------------------------------------------------------------
// REQ-001, REQ-003, REQ-005, REQ-008: Dual delivery happy path
// ---------------------------------------------------------------------------

func TestIntegration_DualDelivery_BothReceiveSameBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Set up a local HTTPS endpoint that records requests.
	localCapture := &httpCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	// Platform mock reporter.
	platform := &mockReporter{}

	// Create LocalReporter pointing to the TLS server.
	nsk := testNSK()
	fetcher := newTestFetcher("integration-token")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()

	// Wrap in MultiReporter.
	multi := NewMultiReporter(platform, local, discardLogger())

	// Create Manager with short intervals.
	mgrCfg := Config{
		Enabled:         true,
		CollectInterval: 25 * time.Millisecond,
		ReportInterval:  60 * time.Millisecond,
		BatchSize:       100,
	}
	pts := testPoints(GroupSystem, 3)
	coll := &mockCollector{points: pts}
	mgr := NewManager(mgrCfg, []Collector{coll}, multi, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Run(ctx) }()

	// Wait for both to receive at least one batch.
	waitFor(t, 3*time.Second, func() bool {
		return platform.callCount() >= 1 && localCapture.count() >= 1
	}, "both platform and local to receive at least one batch")

	cancel()
	<-done

	// Verify platform received the batch.
	platform.mu.Lock()
	pBatch := platform.calls[0].Batch
	platform.mu.Unlock()
	if len(pBatch) == 0 {
		t.Fatal("platform received empty batch")
	}

	// Verify local endpoint received JSON POST.
	req := localCapture.get(0)
	if req.Method != http.MethodPost {
		t.Errorf("local method = %q, want POST", req.Method)
	}
	if req.ContentType != "application/json" {
		t.Errorf("local Content-Type = %q, want application/json", req.ContentType)
	}

	// Verify local received valid metric batch.
	var localBatch api.MetricBatch
	if err := json.Unmarshal(req.Body, &localBatch); err != nil {
		t.Fatalf("failed to unmarshal local body: %v", err)
	}
	if len(localBatch) == 0 {
		t.Fatal("local received empty batch")
	}

	// Both should have the same number of points in the first batch.
	if len(pBatch) != len(localBatch) {
		t.Errorf("batch size mismatch: platform=%d, local=%d", len(pBatch), len(localBatch))
	}
}

func TestIntegration_DualDelivery_CredentialResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &httpCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockReporter{}

	nsk := testNSK()
	fetcher := newTestFetcher("resolved-bearer-token")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()

	multi := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupSystem, 2)
	err := multi.ReportMetrics(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("ReportMetrics error: %v", err)
	}

	// Verify local endpoint received the bearer token.
	if localCapture.count() < 1 {
		t.Fatal("local endpoint did not receive request")
	}

	req := localCapture.get(0)
	if req.Auth != "Bearer resolved-bearer-token" {
		t.Errorf("Authorization = %q, want %q", req.Auth, "Bearer resolved-bearer-token")
	}

	// Verify fetcher was called.
	if fetcher.callCount() != 1 {
		t.Errorf("FetchSecret calls = %d, want 1", fetcher.callCount())
	}
}

// ---------------------------------------------------------------------------
// REQ-002: Platform-only when URL empty
// ---------------------------------------------------------------------------

func TestIntegration_PlatformOnly_WhenURLEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Simulate the conditional wiring pattern from up.go.
	platform := &mockReporter{}

	// When URL is empty, use platform directly (no MultiReporter).
	var reporter MetricsReporter = platform
	localURL := ""
	if localURL != "" {
		t.Fatal("this test requires empty URL")
	}

	mgrCfg := Config{
		Enabled:         true,
		CollectInterval: 25 * time.Millisecond,
		ReportInterval:  60 * time.Millisecond,
		BatchSize:       100,
	}
	coll := &mockCollector{points: testPoints(GroupSystem, 2)}
	mgr := NewManager(mgrCfg, []Collector{coll}, reporter, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Run(ctx) }()

	waitFor(t, 3*time.Second, func() bool {
		return platform.callCount() >= 1
	}, "platform to receive at least one batch")

	cancel()
	<-done

	platform.mu.Lock()
	batch := platform.calls[0].Batch
	platform.mu.Unlock()
	if len(batch) == 0 {
		t.Error("expected non-empty batch from platform-only reporter")
	}
}

func TestIntegration_ConditionalWiring_Pattern(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &httpCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockReporter{}
	nsk := testNSK()

	// Case 1: URL configured -> MultiReporter.
	cfgWithURL := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	var reporter1 MetricsReporter = platform
	if cfgWithURL.URL != "" {
		localMetrics := NewLocalReporter(cfgWithURL, newTestFetcher("tok"), nsk, "node-1", discardLogger())
		localMetrics.httpClient = localSrv.Client()
		reporter1 = NewMultiReporter(platform, localMetrics, discardLogger())
	}
	if _, ok := reporter1.(*MultiReporter); !ok {
		t.Errorf("expected *MultiReporter when URL configured, got %T", reporter1)
	}

	// Case 2: URL empty -> platform directly.
	cfgWithoutURL := api.LocalEndpointConfig{}
	var reporter2 MetricsReporter = platform
	if cfgWithoutURL.URL != "" {
		t.Fatal("should not enter this branch")
	}
	if _, ok := reporter2.(*mockReporter); !ok {
		t.Errorf("expected *mockReporter when URL empty, got %T", reporter2)
	}
}

// ---------------------------------------------------------------------------
// REQ-004, REQ-009: Error isolation
// ---------------------------------------------------------------------------

func TestIntegration_LocalDown_PlatformUnaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Local endpoint returns HTTP 500.
	localCapture := &httpCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusInternalServerError))
	defer localSrv.Close()

	platform := &mockReporter{}

	nsk := testNSK()
	fetcher := newTestFetcher("tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()

	multi := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupSystem, 2)
	err := multi.ReportMetrics(context.Background(), "node-1", batch)

	// Platform succeeded, so error should be nil.
	if err != nil {
		t.Fatalf("expected nil error (platform succeeded), got %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
	if localCapture.count() != 1 {
		t.Errorf("local requests = %d, want 1", localCapture.count())
	}
}

func TestIntegration_LocalHTTP500_PlatformUnaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer localSrv.Close()

	platform := &mockReporter{}
	nsk := testNSK()
	fetcher := newTestFetcher("tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())
	local.httpClient = localSrv.Client()
	multi := NewMultiReporter(platform, local, discardLogger())

	mgrCfg := Config{
		Enabled:         true,
		CollectInterval: 25 * time.Millisecond,
		ReportInterval:  60 * time.Millisecond,
		BatchSize:       100,
	}
	coll := &mockCollector{points: testPoints(GroupSystem, 2)}
	mgr := NewManager(mgrCfg, []Collector{coll}, multi, "node-1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Run(ctx) }()

	waitFor(t, 3*time.Second, func() bool {
		return platform.callCount() >= 1
	}, "platform to receive at least one batch despite local failure")

	cancel()
	<-done

	platform.mu.Lock()
	batch := platform.calls[0].Batch
	platform.mu.Unlock()
	if len(batch) == 0 {
		t.Error("expected non-empty batch from platform")
	}
}

func TestIntegration_CredentialFailure_PlatformStillReceives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	platform := &mockReporter{}

	fetcher := &mockSecretFetcher{err: errors.New("secret store unavailable")}

	nsk := testNSK()
	cfg := api.LocalEndpointConfig{
		URL:                   "https://unreachable.local:9999/ingest",
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())

	multi := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupSystem, 2)
	err := multi.ReportMetrics(context.Background(), "node-1", batch)

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

func TestIntegration_TLSSkipVerify_SelfSignedSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &httpCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	nsk := testNSK()
	fetcher := newTestFetcher("tls-tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: true,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())

	batch := testPoints(GroupSystem, 1)
	err := local.ReportMetrics(context.Background(), "node-1", batch)
	if err != nil {
		t.Fatalf("expected success with skip-verify=true, got %v", err)
	}
	if localCapture.count() != 1 {
		t.Errorf("local requests = %d, want 1", localCapture.count())
	}
}

func TestIntegration_TLSStrictVerify_SelfSignedFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	localCapture := &httpCapture{}
	localSrv := httptest.NewTLSServer(localCapture.handler(http.StatusOK))
	defer localSrv.Close()

	platform := &mockReporter{}

	nsk := testNSK()
	fetcher := newTestFetcher("tls-tok")
	cfg := api.LocalEndpointConfig{
		URL:                   localSrv.URL,
		SecretKey:             "metrics-token",
		TLSInsecureSkipVerify: false,
	}
	local := NewLocalReporter(cfg, fetcher, nsk, "node-1", discardLogger())

	multi := NewMultiReporter(platform, local, discardLogger())

	batch := testPoints(GroupSystem, 1)
	err := multi.ReportMetrics(context.Background(), "node-1", batch)

	// Platform should succeed.
	if err != nil {
		t.Fatalf("expected nil (platform succeeded), got %v", err)
	}
	if platform.callCount() != 1 {
		t.Errorf("platform calls = %d, want 1", platform.callCount())
	}
	// Local should NOT have received the request (TLS handshake fails).
	if localCapture.count() != 0 {
		t.Errorf("local requests = %d, want 0 (TLS failure)", localCapture.count())
	}
}
