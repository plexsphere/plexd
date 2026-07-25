package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/actions"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nodeapi"
)

func boolPtr(v bool) *bool { return &v }

// noopActionReporter is a no-op for testing.
type noopActionReporter struct{}

func (noopActionReporter) ExecutionCallback(_ context.Context, _, _ string, _ api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	return &api.ExecutionCallbackResponse{}, nil
}
func (noopActionReporter) UploadExecutionOutput(_ context.Context, _ string, _ []byte) error {
	return nil
}

// noopHookVerifier is a no-op integrity verifier for testing.
type noopHookVerifier struct{}

func (noopHookVerifier) VerifyHook(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

// testSecretFetcher is a no-op SecretFetcher for testing.
type testSecretFetcher struct{}

func (testSecretFetcher) FetchSecret(_ context.Context, _, _ string, _ int) (*api.SecretEnvelope, error) {
	return &api.SecretEnvelope{}, nil
}

// testReportSyncClient is a no-op ReportSyncClient for testing.
type testReportSyncClient struct{}

func (testReportSyncClient) PutStateReport(_ context.Context, _, key string, _ api.NodeStateReportRequest) (*api.NodeStateReportResponse, error) {
	return &api.NodeStateReportResponse{Key: key}, nil
}

func (testReportSyncClient) DeleteStateReport(_ context.Context, _, _ string) error {
	return nil
}

// testNodeAPIClient combines both interfaces needed by nodeapi.Server.
type testNodeAPIClient struct {
	testSecretFetcher
	testReportSyncClient
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startTestNodeAPI starts a nodeapi server on a temporary unix socket with
// the given ActionProvider and HookReloader. It returns the socket path.
// The server shuts down when the context is cancelled.
func startTestNodeAPI(t *testing.T, ctx context.Context, provider nodeapi.ActionProvider, reloader nodeapi.HookReloader) string {
	t.Helper()

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "plexd.sock")

	cfg := nodeapi.Config{
		SocketPath: socketPath,
		DataDir:    dir,
	}
	cfg.ApplyDefaults()

	client := &testNodeAPIClient{}
	nsk := []byte("test-secret-key-1234567890123456")

	srv := nodeapi.NewServer(cfg, client, nsk, discardLogger())
	srv.SetActionProvider(provider)
	srv.SetHookReloader(reloader)

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx, "test-node-1")
	}()

	// Wait for socket to become available.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			conn.Close()
			return socketPath
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("nodeapi server did not start within timeout")
	return ""
}

func TestIntegration_ActionsList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create an executor with built-in actions.
	cfg := actions.Config{Enabled: boolPtr(true)}
	cfg.ApplyDefaults()
	executor := actions.NewExecutor(cfg, noopActionReporter{}, noopHookVerifier{}, discardLogger())
	executor.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics", nil, actions.DiagnosticsCollect())
	executor.RegisterBuiltin("service.restart", "Restart plexd service", nil, actions.ServiceRestart())

	socketPath := startTestNodeAPI(t, ctx, executor, nil)

	// Call actions list via socket.
	resp, err := socketGet(socketPath, "/v1/actions")
	if err != nil {
		t.Fatalf("socketGet(/v1/actions): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var result actionsListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(result.BuiltinActions) != 2 {
		t.Errorf("len(BuiltinActions) = %d, want 2", len(result.BuiltinActions))
	}

	found := map[string]bool{}
	for _, a := range result.BuiltinActions {
		found[a.Name] = true
	}
	if !found["diagnostics.collect"] {
		t.Error("missing diagnostics.collect in builtin actions")
	}
	if !found["service.restart"] {
		t.Error("missing service.restart in builtin actions")
	}
}

func TestIntegration_ActionsRunSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := actions.Config{Enabled: boolPtr(true)}
	cfg.ApplyDefaults()
	executor := actions.NewExecutor(cfg, noopActionReporter{}, noopHookVerifier{}, discardLogger())
	executor.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics", nil, actions.DiagnosticsCollect())

	socketPath := startTestNodeAPI(t, ctx, executor, nil)

	// Run a builtin action via socket.
	reqBody := runActionRequest{
		Action:     "diagnostics.collect",
		Parameters: nil,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp, err := socketPost(socketPath, "/v1/actions/run", "application/json", jsonReader(data))
	if err != nil {
		t.Fatalf("socketPost(/v1/actions/run): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var result runActionResponseMsg
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("status = %q, want %q", result.Status, "success")
	}
	if result.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", result.ExitCode)
	}
}

func TestIntegration_ActionsRunUnknown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := actions.Config{Enabled: boolPtr(true)}
	cfg.ApplyDefaults()
	executor := actions.NewExecutor(cfg, noopActionReporter{}, noopHookVerifier{}, discardLogger())

	socketPath := startTestNodeAPI(t, ctx, executor, nil)

	reqBody := runActionRequest{
		Action: "nonexistent.action",
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp, err := socketPost(socketPath, "/v1/actions/run", "application/json", jsonReader(data))
	if err != nil {
		t.Fatalf("socketPost(/v1/actions/run): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var result runActionResponseMsg
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result.Status != "error" {
		t.Errorf("status = %q, want %q", result.Status, "error")
	}
}

func TestIntegration_HooksList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create an executor with hooks dir containing an executable script.
	hooksDir := t.TempDir()
	hookPath := filepath.Join(hooksDir, "deploy.sh")
	if err := os.WriteFile(hookPath, []byte("#!/bin/bash\necho deploy"), 0755); err != nil {
		t.Fatalf("write hook: %v", err)
	}
	// Write sidecar metadata.
	sidecarPath := filepath.Join(hooksDir, "deploy.sh.json")
	sidecar := map[string]string{"description": "Deploy script"}
	sidecarData, _ := json.Marshal(sidecar)
	if err := os.WriteFile(sidecarPath, sidecarData, 0644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	cfg := actions.Config{Enabled: boolPtr(true), HooksDir: hooksDir}
	cfg.ApplyDefaults()
	executor := actions.NewExecutor(cfg, noopActionReporter{}, noopHookVerifier{}, discardLogger())

	// Discover hooks initially.
	hooks, err := actions.DiscoverHooks(hooksDir, discardLogger())
	if err != nil {
		t.Fatalf("DiscoverHooks: %v", err)
	}
	executor.SetHooks(hooks)

	socketPath := startTestNodeAPI(t, ctx, executor, nil)

	resp, err := socketGet(socketPath, "/v1/hooks")
	if err != nil {
		t.Fatalf("socketGet(/v1/hooks): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var hooksList []api.HookInfo
	if err := json.Unmarshal(body, &hooksList); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(hooksList) != 1 {
		t.Fatalf("len(hooks) = %d, want 1", len(hooksList))
	}
	if hooksList[0].Name != "deploy.sh" {
		t.Errorf("hook name = %q, want %q", hooksList[0].Name, "deploy.sh")
	}
}

func TestIntegration_HooksReload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hooksDir := t.TempDir()

	cfg := actions.Config{Enabled: boolPtr(true), HooksDir: hooksDir}
	cfg.ApplyDefaults()
	executor := actions.NewExecutor(cfg, noopActionReporter{}, noopHookVerifier{}, discardLogger())

	// Use a HookWatcher as the HookReloader.
	watcher := actions.NewHookWatcher(hooksDir, executor.SetHooks, nil, discardLogger())

	socketPath := startTestNodeAPI(t, ctx, executor, watcher)

	// No hooks yet.
	resp, err := socketPost(socketPath, "/v1/hooks/reload", "application/json", nil)
	if err != nil {
		t.Fatalf("socketPost(/v1/hooks/reload): %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var result hooksReloadResponseMsg
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result.Status != "reloaded" {
		t.Errorf("status = %q, want %q", result.Status, "reloaded")
	}
	if len(result.Hooks) != 0 {
		t.Errorf("hooks = %d, want 0", len(result.Hooks))
	}
}

// jsonReader returns an io.Reader for JSON data.
func jsonReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}
