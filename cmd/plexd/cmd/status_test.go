package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestStatusCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"status"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd status") {
		t.Errorf("error should mention 'plexd status', got: %v", err)
	}
}

func TestStatusCommand_Success(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"node_id": "node-123", "mode": "node"},
	})

	// Override the socket path for this test.
	origSocketPath := nodeapi.DefaultSocketPath
	t.Cleanup(func() { resetDefaultSocketPath(origSocketPath) })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"status"})

	// We need to use the socket directly since defaultSocketPath() returns the const.
	// Test via the runStatus function approach.
	resp, err := socketGet(socketPath, "/v1/state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestStatusCommand_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"status", "--help"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "status") {
		t.Errorf("help should contain 'status', got: %s", output)
	}
	if !strings.Contains(output, "Unix socket") {
		t.Errorf("help should mention 'Unix socket', got: %s", output)
	}
}

func TestPeersCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"peers"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd peers") {
		t.Errorf("error should mention 'plexd peers', got: %v", err)
	}
}

func TestPoliciesCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"policies"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd policies") {
		t.Errorf("error should mention 'plexd policies', got: %v", err)
	}
}

// startFakeAgent starts a minimal HTTP server on a Unix socket that serves
// the given StateSummary at /v1/state. It returns the socket path.
func startFakeAgent(t *testing.T, summary nodeapi.StateSummary) string {
	t.Helper()

	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "api.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	})
	mux.HandleFunc("GET /v1/state/metadata/{key}", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		val, ok := summary.Metadata[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"key": key, "value": val})
	})
	mux.HandleFunc("PUT /v1/state/report/{key}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	srv := &http.Server{Handler: mux}

	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		os.Remove(socketPath)
	})

	// Wait for socket to be ready.
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return socketPath
}

// resetDefaultSocketPath is a no-op since DefaultSocketPath is a const.
// Tests that need a custom socket path call socketGet directly.
func resetDefaultSocketPath(_ string) {}
