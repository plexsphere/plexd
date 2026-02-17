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

// startTestSocketServer starts an HTTP server on a temporary Unix socket.
// It returns the socket path and cleans up on test completion.
func startTestSocketServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()

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

// startFakeAgent starts a minimal HTTP server on a Unix socket that serves
// the given StateSummary at /v1/state. It returns the socket path.
func startFakeAgent(t *testing.T, summary nodeapi.StateSummary) string {
	t.Helper()

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
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]nodeapi.PeerStatus{})
	})
	mux.HandleFunc("GET /v1/policies", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]any{})
	})
	mux.HandleFunc("GET /v1/log-status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeapi.ForwarderStatus{Enabled: true, SourceCount: 1})
	})
	mux.HandleFunc("GET /v1/audit/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeapi.ForwarderStatus{Enabled: true, SourceCount: 2})
	})

	return startTestSocketServer(t, mux)
}

// overrideSocketPath sets socketPathOverride for the duration of the test
// and restores it on cleanup.
func overrideSocketPath(t *testing.T, path string) {
	t.Helper()
	old := socketPathOverride
	socketPathOverride = path
	t.Cleanup(func() { socketPathOverride = old })
}

// executeCmd runs rootCmd with the given args and returns the combined output and error.
func executeCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()
	return buf.String(), err
}

// assertCmdError runs the given command and asserts it fails with an error
// containing wantErrSub.
func assertCmdError(t *testing.T, wantErrSub string, args ...string) {
	t.Helper()

	_, err := executeCmd(t, args...)
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", wantErrSub)
	}
	if !strings.Contains(err.Error(), wantErrSub) {
		t.Errorf("error should contain %q, got: %v", wantErrSub, err)
	}
}

// executeHelp runs a command's --help through rootCmd and returns the output.
// It properly resets cobra's help flag state to avoid polluting subsequent tests.
func executeHelp(t *testing.T, args ...string) string {
	t.Helper()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)

	_ = rootCmd.Execute()

	// Reset the help flag on the target subcommand so subsequent tests
	// that invoke the same subcommand are not affected.
	if cmd, _, err := rootCmd.Find(args[:len(args)-1]); err == nil {
		if f := cmd.Flags().Lookup("help"); f != nil {
			_ = f.Value.Set("false")
			f.Changed = false
		}
	}

	return buf.String()
}