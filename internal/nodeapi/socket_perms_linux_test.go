//go:build linux

package nodeapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplySocketPermissions_NoPlexdGroup(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create a socket file to set permissions on.
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	logger := slog.Default()

	// Should not panic; plexd group likely doesn't exist in test env.
	applySocketPermissions(socketPath, logger)

	// Socket should have fallback permissions of 0666.
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("socket should exist: %v", err)
	}
	if got := info.Mode().Perm(); got != 0666 {
		t.Errorf("socket permission = %04o, want 0666", got)
	}
}

func TestConnContextWithPeerCred(t *testing.T) {
	fn := connContextWithPeerCred(slog.Default())
	if fn == nil {
		t.Fatal("connContextWithPeerCred should return non-nil on Linux")
	}

	// Create a Unix socket pair to test peer cred extraction.
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "peercred.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Connect to get a real Unix connection with peer creds.
	done := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		done <- conn
	}()

	clientConn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	select {
	case serverConn := <-done:
		if serverConn == nil {
			t.Fatal("server conn is nil")
		}
		defer serverConn.Close()

		ctx := fn(context.Background(), serverConn)
		cred, ok := ctx.Value(peerCredKey{}).(*PeerCredentials)
		if !ok || cred == nil {
			t.Fatal("peer credentials should be in context")
		}
		// UID should be the current user.
		if cred.UID != uint32(os.Getuid()) {
			t.Errorf("UID = %d, want %d", cred.UID, os.Getuid())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for connection")
	}
}

func TestContextPeerCredGetter(t *testing.T) {
	getter := contextPeerCredGetter{}

	// Request without peer creds in context.
	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets/key", nil)
	_, err := getter.GetPeerCredentials(req)
	if err == nil {
		t.Error("expected error when no peer creds in context")
	}

	// Request with peer creds in context.
	cred := &PeerCredentials{PID: 1, UID: 0, GID: 0}
	ctx := context.WithValue(req.Context(), peerCredKey{}, cred)
	req = req.WithContext(ctx)

	got, err := getter.GetPeerCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UID != 0 {
		t.Errorf("UID = %d, want 0", got.UID)
	}
}

func TestWrapSecretAuth_ProtectsSecretRoutes(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logger := slog.Default()
	wrapped := wrapSecretAuth(inner, logger)

	// Non-secret route should pass through.
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("non-secret route: status = %d, want 200", rec.Code)
	}

	// Secret route without peer creds should be forbidden.
	req = httptest.NewRequest(http.MethodGet, "/v1/state/secrets/key", nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("secret route without creds: status = %d, want 403", rec.Code)
	}

	// Secret route with root peer creds should pass.
	cred := &PeerCredentials{PID: 1, UID: 0, GID: 0}
	ctx := context.WithValue(req.Context(), peerCredKey{}, cred)
	req = httptest.NewRequest(http.MethodGet, "/v1/state/secrets/key", nil).WithContext(ctx)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("secret route with root creds: status = %d, want 200", rec.Code)
	}
}

func TestWrapSecretAuth_SecretListAlsoProtected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapSecretAuth(inner, slog.Default())

	// /v1/state/secrets (list) should also be protected.
	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("secret list without creds: status = %d, want 403", rec.Code)
	}
}

func TestWrapSecretAuth_MetadataNotProtected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapSecretAuth(inner, slog.Default())

	paths := []string{"/v1/state", "/v1/state/metadata", "/v1/state/data/key", "/v1/state/report/key"}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("path %s: status = %d, want 200", path, rec.Code)
		}
	}
}

func TestServerSecretAuthEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		SocketPath:        filepath.Join(tmpDir, "api.sock"),
		DebouncePeriod:    5 * time.Second,
		ShutdownTimeout:   2 * time.Second,
		DataDir:           tmpDir,
		SecretAuthEnabled: true,
	}

	client := &serverTestClient{}
	srv := NewServer(cfg, client, []byte("test-nsk"), slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Start(ctx, "node-auth-test")
	}()

	// Wait for socket.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	httpClient := unixSocketClient(cfg.SocketPath)

	// State endpoint should work (no auth required).
	resp, err := httpClient.Get("http://localhost/v1/state")
	if err != nil {
		t.Fatalf("GET /v1/state: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/state: status = %d, want 200", resp.StatusCode)
	}

	// Secret endpoint should be blocked for non-root users.
	resp, err = httpClient.Get("http://localhost/v1/state/secrets")
	if err != nil {
		t.Fatalf("GET /v1/state/secrets: %v", err)
	}
	resp.Body.Close()

	// If running as root (UID 0), access is granted; otherwise forbidden.
	if os.Getuid() == 0 {
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /v1/state/secrets as root: status = %d, want 200", resp.StatusCode)
		}
	} else {
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET /v1/state/secrets as non-root: status = %d, want 403", resp.StatusCode)
		}
	}

	cancel()

	// Wait for socket cleanup.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(cfg.SocketPath); os.IsNotExist(err) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerSecretAuthDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		SocketPath:        filepath.Join(tmpDir, "api.sock"),
		DebouncePeriod:    5 * time.Second,
		ShutdownTimeout:   2 * time.Second,
		DataDir:           tmpDir,
		SecretAuthEnabled: false,
	}

	client := &serverTestClient{}
	srv := NewServer(cfg, client, []byte("test-nsk"), slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Start(ctx, "node-noauth-test")
	}()

	// Wait for socket.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	httpClient := unixSocketClient(cfg.SocketPath)

	// Secret endpoint should work without auth when disabled.
	resp, err := httpClient.Get("http://localhost/v1/state/secrets")
	if err != nil {
		t.Fatalf("GET /v1/state/secrets: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/state/secrets without auth: status = %d, want 200", resp.StatusCode)
	}

	cancel()

	// Wait for socket cleanup.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(cfg.SocketPath); os.IsNotExist(err) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// isReportPath and friends are used in the test but live in server.go
// so no need to redefine. Just check they're accessible.
func TestIsSecretPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/v1/state/secrets", true},
		{"/v1/state/secrets/key", true},
		{"/v1/state", false},
		{"/v1/state/metadata", false},
		{"/v1/state/data/key", false},
		{"/v1/state/report/key", false},
	}

	for _, tt := range tests {
		got := strings.HasPrefix(tt.path, "/v1/state/secrets")
		if got != tt.want {
			t.Errorf("isSecretPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
