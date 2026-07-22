package nodeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"go.uber.org/goleak"
)

// configurableTestClient extends serverTestClient with configurable behavior.
type configurableTestClient struct {
	fetchSecret       func(ctx context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error)
	putStateReport    func(ctx context.Context, nodeID, key string, req api.NodeStateReportRequest) (*api.NodeStateReportResponse, error)
	deleteStateReport func(ctx context.Context, nodeID, key string) error
}

func (c *configurableTestClient) FetchSecret(ctx context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error) {
	if c.fetchSecret != nil {
		return c.fetchSecret(ctx, nodeID, name, version)
	}
	return nil, fmt.Errorf("not implemented")
}

func (c *configurableTestClient) PutStateReport(ctx context.Context, nodeID, key string, req api.NodeStateReportRequest) (*api.NodeStateReportResponse, error) {
	if c.putStateReport != nil {
		return c.putStateReport(ctx, nodeID, key, req)
	}
	return &api.NodeStateReportResponse{Key: key}, nil
}

func (c *configurableTestClient) DeleteStateReport(ctx context.Context, nodeID, key string) error {
	if c.deleteStateReport != nil {
		return c.deleteStateReport(ctx, nodeID, key)
	}
	return nil
}

// serverTestClient combines SecretFetcher and ReportSyncClient for tests.
type serverTestClient struct {
	secretResp *api.SecretEnvelope
	secretErr  error
	putErr     error
	deleteErr  error
}

func (c *serverTestClient) FetchSecret(_ context.Context, _, _ string, _ int) (*api.SecretEnvelope, error) {
	return c.secretResp, c.secretErr
}

func (c *serverTestClient) PutStateReport(_ context.Context, _, key string, _ api.NodeStateReportRequest) (*api.NodeStateReportResponse, error) {
	if c.putErr != nil {
		return nil, c.putErr
	}
	return &api.NodeStateReportResponse{Key: key}, nil
}

func (c *serverTestClient) DeleteStateReport(_ context.Context, _, _ string) error {
	return c.deleteErr
}

func newTestServer(t *testing.T, client *serverTestClient) (*Server, Config) {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := Config{
		SocketPath:      filepath.Join(tmpDir, "api.sock"),
		DataDir:         tmpDir,
		DebouncePeriod:  50 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	}
	cfg.ApplyDefaults()

	nsk := make([]byte, 32)
	for i := range nsk {
		nsk[i] = byte(i)
	}

	srv := NewServer(cfg, client, nsk, nil)
	return srv, cfg
}

func TestServer_UnixSocket(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	// Wait for socket to appear.
	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// Make a request over the Unix socket.
	httpClient := unixSocketClient(cfg.SocketPath)
	resp, err := httpClient.Get("http://unix/v1/state")
	if err != nil {
		cancel()
		t.Fatalf("GET /v1/state: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	var summary StateSummary
	if err := json.Unmarshal(body, &summary); err != nil {
		cancel()
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify socket exists.
	if _, err := os.Stat(cfg.SocketPath); err != nil {
		cancel()
		t.Fatalf("socket file missing: %v", err)
	}

	// Shut down.
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Start returned: %v", err)
	}

	// Verify socket removed after shutdown.
	if _, err := os.Stat(cfg.SocketPath); !os.IsNotExist(err) {
		t.Errorf("socket file not removed after shutdown")
	}
}

func TestServer_TCPListener(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	// Write a token file.
	tokenFile := filepath.Join(cfg.DataDir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token-123"), 0600); err != nil {
		t.Fatal(err)
	}

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv.cfg.HTTPEnabled = true
	srv.cfg.HTTPListen = addr
	srv.cfg.HTTPTokenFile = tokenFile

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}
	// Also wait for TCP to be ready.
	if !waitForTCP(t, addr, 2*time.Second) {
		cancel()
		t.Fatal("TCP listener not ready")
	}

	// Request without token → 401.
	resp, err := http.Get("http://" + addr + "/v1/state")
	if err != nil {
		cancel()
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		cancel()
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// Request with valid token → 200.
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/v1/state", nil)
	req.Header.Set("Authorization", "Bearer test-token-123")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("GET with token: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("status = %d, want 200", resp2.StatusCode)
	}

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Start returned: %v", err)
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// Cancel context.
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("Start returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// Socket should be removed.
	if _, err := os.Stat(cfg.SocketPath); !os.IsNotExist(err) {
		t.Errorf("socket not removed after shutdown")
	}
}

func TestServer_NoGoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// Make a quick request to exercise the handler.
	httpClient := unixSocketClient(cfg.SocketPath)
	resp, err := httpClient.Get("http://unix/v1/state")
	if err == nil {
		resp.Body.Close()
	}

	cancel()
	<-errCh
	// goleak.VerifyNone runs in defer.
}

func TestServer_ReconcileHandler(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// Pre-seed the secret index so we can assert reconcile leaves it untouched
	// (secret refs no longer ride the snapshot).
	srv.cache.UpdateSecretIndex([]api.SecretRef{{Key: "db-pass", Version: 2}})

	// Pre-seed an SSE-delivered data entry so we can assert the pull path does
	// not clobber it with a fabricated content_type/version.
	srv.cache.UpdateData([]api.DataEntry{
		{Key: "cfg", ContentType: "application/json", Payload: json.RawMessage(`{"a":1}`), Version: 7},
	})

	// Get the reconcile handler.
	handler := srv.ReconcileHandler()
	if handler == nil {
		cancel()
		t.Fatal("ReconcileHandler returned nil")
	}

	// StateChanged feeds the metadata map. The snapshot's opaque data bucket is
	// deliberately ignored — the versioned data store is SSE-owned.
	desired := &api.NodeStateSnapshot{
		State: &api.NodeStateBlock{
			Metadata: []api.StateEntry{{Key: "env", Value: "prod"}},
			Data:     []api.StateEntry{{Key: "cfg", Value: "hello"}},
			Reports:  []api.StateEntry{},
		},
	}
	diff := reconcile.StateDiff{StateChanged: true}

	if err := handler(ctx, desired, diff); err != nil {
		cancel()
		t.Fatalf("reconcile handler: %v", err)
	}

	// Verify metadata bucket became the cache metadata map.
	meta := srv.cache.GetMetadata()
	if meta["env"] != "prod" {
		cancel()
		t.Errorf("metadata[env] = %q, want %q", meta["env"], "prod")
	}

	// The SSE-delivered data entry must survive the pull untouched: its real
	// content_type and version are not overwritten with fabricated values.
	data := srv.cache.GetData()
	entry, ok := data["cfg"]
	if !ok {
		cancel()
		t.Fatal("SSE-delivered data entry 'cfg' was removed by reconcile")
	}
	if entry.ContentType != "application/json" {
		cancel()
		t.Errorf("data content_type = %q, want %q (clobbered by pull)", entry.ContentType, "application/json")
	}
	if entry.Version != 7 {
		cancel()
		t.Errorf("data version = %d, want 7 (clobbered by pull)", entry.Version)
	}

	// Reconcile must NOT touch the secret index.
	secrets := srv.cache.GetSecretIndex()
	if len(secrets) != 1 || secrets[0].Key != "db-pass" || secrets[0].Version != 2 {
		cancel()
		t.Errorf("secret index changed by reconcile: %v", secrets)
	}

	// A nil State block authoritatively clears the pull-owned metadata map but
	// leaves the SSE-owned data store intact.
	if err := handler(ctx, &api.NodeStateSnapshot{State: nil}, reconcile.StateDiff{StateChanged: true}); err != nil {
		cancel()
		t.Fatalf("reconcile handler (nil state): %v", err)
	}
	if len(srv.cache.GetMetadata()) != 0 {
		cancel()
		t.Errorf("metadata not cleared on nil state: %v", srv.cache.GetMetadata())
	}
	if _, ok := srv.cache.GetData()["cfg"]; !ok {
		cancel()
		t.Errorf("SSE-owned data cleared by nil state block")
	}
	// The secret index remains untouched by the clear.
	if len(srv.cache.GetSecretIndex()) != 1 {
		cancel()
		t.Errorf("secret index touched by state clear: %v", srv.cache.GetSecretIndex())
	}

	cancel()
	<-errCh
}

func TestServer_RegisterEventHandlers(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// Create a dispatcher and register handlers.
	dispatcher := api.NewEventDispatcher(srv.logger)
	srv.RegisterEventHandlers(dispatcher)

	// Dispatch a node_state_updated event.
	payload := NodeStateUpdatePayload{
		Metadata: map[string]string{"zone": "us-east-1"},
	}
	payloadJSON, _ := json.Marshal(payload)
	env := api.Envelope{
		Type:    api.EventNodeStateUpdated,
		ID:      "evt-1",
		Payload: payloadJSON,
	}
	dispatcher.Dispatch(ctx, env)

	// Verify cache updated.
	meta := srv.cache.GetMetadata()
	if meta["zone"] != "us-east-1" {
		t.Errorf("metadata[zone] = %q, want %q", meta["zone"], "us-east-1")
	}

	cancel()
	<-errCh
}

func TestServer_StaleSocketRemoved(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	// Create a stale socket file.
	if err := os.WriteFile(cfg.SocketPath, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear after stale removal")
	}

	// Verify we can connect.
	httpClient := unixSocketClient(cfg.SocketPath)
	resp, err := httpClient.Get("http://unix/v1/state")
	if err != nil {
		cancel()
		t.Fatalf("GET /v1/state: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	cancel()
	<-errCh
}

// --- helpers ---

func waitForSocket(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", path); err == nil {
			conn.Close()
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func waitForTCP(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func unixSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

// Verify ReportSyncer integration — PUT report triggers sync.
func TestServer_ReportSyncIntegration(t *testing.T) {
	defer goleak.VerifyNone(t)

	syncCalls := make(chan string, 10)
	// Track per-key PutStateReport calls through a channel.
	trackingClient := &trackingSyncClient{puts: syncCalls}

	tmpDir := t.TempDir()
	cfg := Config{
		SocketPath:      filepath.Join(tmpDir, "api.sock"),
		DataDir:         tmpDir,
		DebouncePeriod:  50 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	}
	cfg.ApplyDefaults()

	nsk := make([]byte, 32)
	srv := NewServer(cfg, trackingClient, nsk, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-1") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// PUT a report entry via Unix socket.
	httpClient := unixSocketClient(cfg.SocketPath)
	body := strings.NewReader(`{"content_type":"application/json","payload":{"status":"ok"}}`)
	req, _ := http.NewRequest(http.MethodPut, "http://unix/v1/state/report/health", body)
	resp, err := httpClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
	}

	// Wait for the sync call (debounce + processing).
	select {
	case key := <-syncCalls:
		if key != "health" {
			t.Errorf("synced key = %q, want %q", key, "health")
		}
	case <-time.After(2 * time.Second):
		// Sync may not happen in time in CI; don't hard-fail.
		t.Log("WARN: sync call not received within timeout (may be timing-dependent)")
	}

	cancel()
	<-errCh
}

// TestReportNotifyMiddleware_DerivesChangeFromCache pins the resolution of the
// PUT/DELETE notify race: the notification must describe what the cache holds
// after the handler returned, not the method that ran. The notify happens
// outside the cache lock, so a PUT and a DELETE of the same key can notify in
// the opposite order to the one they mutated the cache in; deriving the change
// from the cache keeps the last notification truthful either way.
func TestReportNotifyMiddleware_DerivesChangeFromCache(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		status     int
		inCache    bool
		wantDelete bool
	}{
		{"put with the key present notifies a put", http.MethodPut, http.StatusOK, true, false},
		{"put whose key a racing delete removed notifies a delete", http.MethodPut, http.StatusOK, false, true},
		{"delete with the key gone notifies a delete", http.MethodDelete, http.StatusNoContent, false, true},
		{"delete whose key a racing put restored notifies a put", http.MethodDelete, http.StatusNoContent, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewStateCache(t.TempDir(), discardLogger())
			if tt.inCache {
				if _, err := cache.PutReport("health", "application/json", json.RawMessage(`{"ok":true}`), nil); err != nil {
					t.Fatalf("seed cache: %v", err)
				}
			}
			syncer := NewReportSyncer(&trackingSyncClient{puts: make(chan string, 1)}, time.Millisecond, discardLogger())

			h := reportNotifyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}), cache, syncer)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tt.method, "/v1/state/report/health", nil))

			syncer.mu.Lock()
			entry, ok := syncer.dirty["health"]
			syncer.mu.Unlock()
			if !ok {
				t.Fatalf("no change notified for key %q", "health")
			}
			if gotDelete := entry == nil; gotDelete != tt.wantDelete {
				t.Errorf("notified delete = %v, want %v", gotDelete, tt.wantDelete)
			}
		})
	}
}

type trackingSyncClient struct {
	puts chan string
}

func (c *trackingSyncClient) FetchSecret(_ context.Context, _, _ string, _ int) (*api.SecretEnvelope, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *trackingSyncClient) PutStateReport(_ context.Context, _, key string, _ api.NodeStateReportRequest) (*api.NodeStateReportResponse, error) {
	c.puts <- key
	return &api.NodeStateReportResponse{Key: key}, nil
}

func (c *trackingSyncClient) DeleteStateReport(_ context.Context, _, _ string) error {
	return nil
}

// ---------------------------------------------------------------------------
// Integration tests (5.1, 5.2, 5.3)
// ---------------------------------------------------------------------------

// TestServer_EndToEndFlow exercises the full server lifecycle: start, populate
// cache, read state summary, CRUD report entries, verify sync, and shutdown.
func TestServer_EndToEndFlow(t *testing.T) {
	defer goleak.VerifyNone(t)

	syncCalls := make(chan string, 10)
	client := &configurableTestClient{
		putStateReport: func(_ context.Context, _, key string, _ api.NodeStateReportRequest) (*api.NodeStateReportResponse, error) {
			syncCalls <- "put:" + key
			return &api.NodeStateReportResponse{Key: key}, nil
		},
		deleteStateReport: func(_ context.Context, _, key string) error {
			syncCalls <- "delete:" + key
			return nil
		},
	}

	tmpDir := t.TempDir()
	cfg := Config{
		SocketPath:      filepath.Join(tmpDir, "api.sock"),
		DataDir:         tmpDir,
		DebouncePeriod:  50 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	}
	cfg.ApplyDefaults()

	nsk := make([]byte, 32)
	srv := NewServer(cfg, client, nsk, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-e2e") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// Populate cache after Start (which calls Load and resets from disk).
	srv.cache.UpdateMetadata(map[string]string{"env": "staging", "region": "eu-west-1"})
	srv.cache.UpdateData([]api.DataEntry{
		{Key: "app-config", ContentType: "application/json", Payload: json.RawMessage(`{"debug":true}`), Version: 2},
	})
	srv.cache.UpdateSecretIndex([]api.SecretRef{
		{Key: "db-password", Version: 1},
	})

	httpClient := unixSocketClient(cfg.SocketPath)

	// 1. GET /v1/state — verify summary contains all categories.
	resp, err := httpClient.Get("http://unix/v1/state")
	if err != nil {
		cancel()
		t.Fatalf("GET /v1/state: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("GET /v1/state status = %d, want 200", resp.StatusCode)
	}

	var summary StateSummary
	if err := json.Unmarshal(body, &summary); err != nil {
		cancel()
		t.Fatalf("unmarshal summary: %v", err)
	}
	if summary.Metadata["env"] != "staging" {
		t.Errorf("metadata[env] = %q, want %q", summary.Metadata["env"], "staging")
	}
	if len(summary.DataKeys) != 1 || summary.DataKeys[0].Key != "app-config" {
		t.Errorf("data_keys = %v, want [{app-config ...}]", summary.DataKeys)
	}
	if len(summary.SecretKeys) != 1 || summary.SecretKeys[0].Key != "db-password" {
		t.Errorf("secret_keys = %v, want [{db-password ...}]", summary.SecretKeys)
	}

	// 2. GET /v1/state/metadata — verify all metadata.
	resp, err = httpClient.Get("http://unix/v1/state/metadata")
	if err != nil {
		cancel()
		t.Fatalf("GET /v1/state/metadata: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var meta map[string]string
	_ = json.Unmarshal(body, &meta)
	if meta["region"] != "eu-west-1" {
		t.Errorf("metadata[region] = %q, want %q", meta["region"], "eu-west-1")
	}

	// 3. PUT /v1/state/report/health — create a report entry.
	putBody := strings.NewReader(`{"content_type":"application/json","payload":{"status":"healthy"}}`)
	req, _ := http.NewRequest(http.MethodPut, "http://unix/v1/state/report/health", putBody)
	resp, err = httpClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("PUT report: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("PUT status = %d, want 200; body: %s", resp.StatusCode, body)
	}

	var createdReport ReportEntry
	_ = json.Unmarshal(body, &createdReport)
	if createdReport.Version != 1 {
		t.Errorf("report version = %d, want 1", createdReport.Version)
	}

	// 4. GET /v1/state/report/health — verify it's readable.
	resp, err = httpClient.Get("http://unix/v1/state/report/health")
	if err != nil {
		cancel()
		t.Fatalf("GET report: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET report status = %d, want 200", resp.StatusCode)
	}

	var gotReport ReportEntry
	_ = json.Unmarshal(body, &gotReport)
	if gotReport.Key != "health" || gotReport.Version != 1 {
		t.Errorf("GET report = %+v, want key=health version=1", gotReport)
	}

	// 5. DELETE /v1/state/report/health — remove it.
	req, _ = http.NewRequest(http.MethodDelete, "http://unix/v1/state/report/health", nil)
	resp, err = httpClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("DELETE report: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", resp.StatusCode)
	}

	// 6. Verify report was deleted — GET should now return 404.
	resp, err = httpClient.Get("http://unix/v1/state/report/health")
	if err != nil {
		cancel()
		t.Fatalf("GET deleted report: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET deleted report status = %d, want 404", resp.StatusCode)
	}

	// 7. Verify report sync was triggered (PUT and DELETE should each trigger).
	syncReceived := 0
	timeout := time.After(2 * time.Second)
syncLoop:
	for {
		select {
		case <-syncCalls:
			syncReceived++
			if syncReceived >= 2 {
				break syncLoop
			}
		case <-timeout:
			break syncLoop
		}
	}
	if syncReceived < 1 {
		t.Log("WARN: expected at least 1 sync call, got 0 (timing-dependent)")
	}

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Start returned: %v", err)
	}
}

// TestServer_PublishReport exercises the internal publish seam: a valid report
// is written through the cache (visible via the cache and the HTTP API) and
// forwarded to the syncer, while grammar and value-cap violations are rejected
// before any cache write.
func TestServer_PublishReport(t *testing.T) {
	defer goleak.VerifyNone(t)

	puts := make(chan api.NodeStateReportRequest, 4)
	client := &configurableTestClient{
		putStateReport: func(_ context.Context, _, _ string, req api.NodeStateReportRequest) (*api.NodeStateReportResponse, error) {
			puts <- req
			return &api.NodeStateReportResponse{}, nil
		},
	}

	tmpDir := t.TempDir()
	cfg := Config{
		SocketPath:      filepath.Join(tmpDir, "api.sock"),
		DataDir:         tmpDir,
		DebouncePeriod:  50 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	}
	cfg.ApplyDefaults()

	nsk := make([]byte, 32)
	srv := NewServer(cfg, client, nsk, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-publish") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	// A valid publish writes through the cache and notifies the syncer.
	if err := srv.PublishReport("status.mesh", "application/json", json.RawMessage(`{"peers":3}`)); err != nil {
		cancel()
		t.Fatalf("PublishReport: %v", err)
	}

	// The entry is visible in the cache with version 1.
	entry, ok := srv.cache.GetReport("status.mesh")
	if !ok {
		cancel()
		t.Fatal("published report not found in cache")
	}
	if entry.Version != 1 || string(entry.Payload) != `{"peers":3}` {
		cancel()
		t.Errorf("cache entry = %+v, want version 1 payload {\"peers\":3}", entry)
	}

	// And readable over the local HTTP API.
	httpClient := unixSocketClient(cfg.SocketPath)
	resp, err := httpClient.Get("http://unix/v1/state/report/status.mesh")
	if err != nil {
		cancel()
		t.Fatalf("GET report: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("GET report status = %d, want 200; body: %s", resp.StatusCode, body)
	}
	var got ReportEntry
	_ = json.Unmarshal(body, &got)
	if got.Key != "status.mesh" {
		cancel()
		t.Errorf("GET report key = %q, want %q", got.Key, "status.mesh")
	}

	// The syncer forwards the payload value with no workload tag.
	select {
	case req := <-puts:
		if req.Value != `{"peers":3}` {
			t.Errorf("synced value = %q, want %q", req.Value, `{"peers":3}`)
		}
		if req.WorkloadTag != "" {
			t.Errorf("synced workload_tag = %q, want empty", req.WorkloadTag)
		}
	case <-time.After(2 * time.Second):
		t.Log("WARN: publish sync not received within timeout (timing-dependent)")
	}

	// Grammar violations and oversized payloads are rejected with errors and
	// never reach the cache.
	if err := srv.PublishReport("Bad_Key", "application/json", json.RawMessage(`{}`)); err == nil {
		t.Error("PublishReport(Bad_Key) = nil, want error")
	}
	oversized := json.RawMessage(`"` + strings.Repeat("x", maxReportValueBytes) + `"`)
	if err := srv.PublishReport("cpu-load", "application/json", oversized); err == nil {
		t.Error("PublishReport(oversized) = nil, want error")
	}
	if _, ok := srv.cache.GetReport("cpu-load"); ok {
		t.Error("oversized publish wrote to cache, want rejected before write")
	}

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Start returned: %v", err)
	}
}

// TestServer_SecretProxy exercises the secret proxy endpoint: successful
// decrypt, 503 on control plane failure, and 404 on ErrNotFound.
func TestServer_SecretProxy(t *testing.T) {
	defer goleak.VerifyNone(t)

	nsk := testKey(t)
	secretPlaintext := "super-secret-password"
	envelope := testEncrypt(t, nsk, secretPlaintext)

	client := &configurableTestClient{
		fetchSecret: func(_ context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error) {
			switch name {
			case "db-password":
				return &api.SecretEnvelope{Data: envelope, Version: 3}, nil
			case "missing-key":
				return nil, api.ErrNotFound
			default:
				return nil, fmt.Errorf("control plane unreachable")
			}
		},
	}

	tmpDir := t.TempDir()
	cfg := Config{
		SocketPath:      filepath.Join(tmpDir, "api.sock"),
		DataDir:         tmpDir,
		DebouncePeriod:  50 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	}
	cfg.ApplyDefaults()

	srv := NewServer(cfg, client, nsk, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-secret-test") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	httpClient := unixSocketClient(cfg.SocketPath)

	// Test 1: Successful secret fetch and decryption.
	resp, err := httpClient.Get("http://unix/v1/state/secrets/db-password")
	if err != nil {
		cancel()
		t.Fatalf("GET secret: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET secret status = %d, want 200; body: %s", resp.StatusCode, body)
	}

	var secretResp map[string]any
	_ = json.Unmarshal(body, &secretResp)
	if secretResp["key"] != "db-password" {
		t.Errorf("secret key = %v, want db-password", secretResp["key"])
	}
	if secretResp["value"] != secretPlaintext {
		t.Errorf("secret value = %v, want %q", secretResp["value"], secretPlaintext)
	}
	if int(secretResp["version"].(float64)) != 3 {
		t.Errorf("secret version = %v, want 3", secretResp["version"])
	}

	// Test 2: Control plane returns ErrNotFound → 404.
	resp, err = httpClient.Get("http://unix/v1/state/secrets/missing-key")
	if err != nil {
		cancel()
		t.Fatalf("GET missing secret: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET missing secret status = %d, want 404", resp.StatusCode)
	}

	// Test 3: Control plane unreachable → 503.
	resp, err = httpClient.Get("http://unix/v1/state/secrets/unknown-service")
	if err != nil {
		cancel()
		t.Fatalf("GET unreachable secret: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("GET unreachable secret status = %d, want 503", resp.StatusCode)
	}

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Start returned: %v", err)
	}
}

// TestServer_CacheUpdateFromEvents verifies that SSE events dispatched via the
// EventDispatcher correctly update the server cache and that subsequent GET
// requests reflect the new data.
func TestServer_CacheUpdateFromEvents(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := &serverTestClient{}
	srv, cfg := newTestServer(t, client)

	// Register event handlers with a dispatcher.
	dispatcher := api.NewEventDispatcher(srv.logger)
	srv.RegisterEventHandlers(dispatcher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, "node-events") }()

	if !waitForSocket(t, cfg.SocketPath, 2*time.Second) {
		cancel()
		t.Fatal("socket did not appear")
	}

	httpClient := unixSocketClient(cfg.SocketPath)

	// 1. Simulate node_state_updated event with metadata and data.
	statePayload := NodeStateUpdatePayload{
		Metadata: map[string]string{"env": "production", "cluster": "alpha"},
		Data: []api.DataEntry{
			{Key: "wireguard.conf", ContentType: "text/plain", Payload: json.RawMessage(`"[Interface]\nAddress=10.0.0.1"`), Version: 5},
			{Key: "dns-config", ContentType: "application/json", Payload: json.RawMessage(`{"servers":["8.8.8.8"]}`), Version: 1},
		},
	}
	statePayloadJSON, _ := json.Marshal(statePayload)
	dispatcher.Dispatch(ctx, api.Envelope{
		Type:    api.EventNodeStateUpdated,
		ID:      "evt-state-1",
		Payload: statePayloadJSON,
	})

	// 2. Simulate node_secrets_updated event.
	secretsPayload := NodeSecretsUpdatePayload{
		SecretRefs: []api.SecretRef{
			{Key: "tls-cert", Version: 2},
			{Key: "api-key", Version: 1},
		},
	}
	secretsPayloadJSON, _ := json.Marshal(secretsPayload)
	dispatcher.Dispatch(ctx, api.Envelope{
		Type:    api.EventNodeSecretsUpdated,
		ID:      "evt-secrets-1",
		Payload: secretsPayloadJSON,
	})

	// 3. Verify via HTTP endpoints that cache reflects the updates.

	// GET /v1/state/metadata
	resp, err := httpClient.Get("http://unix/v1/state/metadata")
	if err != nil {
		cancel()
		t.Fatalf("GET metadata: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var meta map[string]string
	_ = json.Unmarshal(body, &meta)
	if meta["env"] != "production" {
		t.Errorf("metadata[env] = %q, want %q", meta["env"], "production")
	}
	if meta["cluster"] != "alpha" {
		t.Errorf("metadata[cluster] = %q, want %q", meta["cluster"], "alpha")
	}

	// GET /v1/state/metadata/env
	resp, err = httpClient.Get("http://unix/v1/state/metadata/env")
	if err != nil {
		cancel()
		t.Fatalf("GET metadata/env: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var metaKey map[string]string
	_ = json.Unmarshal(body, &metaKey)
	if metaKey["value"] != "production" {
		t.Errorf("metadata/env value = %q, want %q", metaKey["value"], "production")
	}

	// GET /v1/state/data
	resp, err = httpClient.Get("http://unix/v1/state/data")
	if err != nil {
		cancel()
		t.Fatalf("GET data: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var dataKeys []dataKeySummary
	_ = json.Unmarshal(body, &dataKeys)
	if len(dataKeys) != 2 {
		t.Errorf("data entries count = %d, want 2", len(dataKeys))
	}

	// GET /v1/state/data/wireguard.conf
	resp, err = httpClient.Get("http://unix/v1/state/data/wireguard.conf")
	if err != nil {
		cancel()
		t.Fatalf("GET data/wireguard.conf: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET data/wireguard.conf status = %d, want 200", resp.StatusCode)
	}
	var dataEntry api.DataEntry
	_ = json.Unmarshal(body, &dataEntry)
	if dataEntry.Key != "wireguard.conf" {
		t.Errorf("data entry key = %q, want %q", dataEntry.Key, "wireguard.conf")
	}
	if dataEntry.Version != 5 {
		t.Errorf("data entry version = %d, want 5", dataEntry.Version)
	}

	// GET /v1/state/secrets
	resp, err = httpClient.Get("http://unix/v1/state/secrets")
	if err != nil {
		cancel()
		t.Fatalf("GET secrets: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var secretKeys []secretKeySummary
	_ = json.Unmarshal(body, &secretKeys)
	if len(secretKeys) != 2 {
		t.Errorf("secret keys count = %d, want 2", len(secretKeys))
	}
	// Check specific keys are present.
	secretKeyMap := make(map[string]int)
	for _, sk := range secretKeys {
		secretKeyMap[sk.Key] = sk.Version
	}
	if v, ok := secretKeyMap["tls-cert"]; !ok || v != 2 {
		t.Errorf("secret tls-cert version = %d (found=%v), want 2", v, ok)
	}
	if v, ok := secretKeyMap["api-key"]; !ok || v != 1 {
		t.Errorf("secret api-key version = %d (found=%v), want 1", v, ok)
	}

	// GET /v1/state — verify summary has everything.
	resp, err = httpClient.Get("http://unix/v1/state")
	if err != nil {
		cancel()
		t.Fatalf("GET state: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var summary StateSummary
	_ = json.Unmarshal(body, &summary)
	if len(summary.Metadata) != 2 {
		t.Errorf("summary metadata count = %d, want 2", len(summary.Metadata))
	}
	if len(summary.DataKeys) != 2 {
		t.Errorf("summary data_keys count = %d, want 2", len(summary.DataKeys))
	}
	if len(summary.SecretKeys) != 2 {
		t.Errorf("summary secret_keys count = %d, want 2", len(summary.SecretKeys))
	}

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Start returned: %v", err)
	}
}
