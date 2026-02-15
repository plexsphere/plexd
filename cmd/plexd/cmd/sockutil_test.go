package cmd

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestSocketURL(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/v1/state", "http://localhost/v1/state"},
		{"/v1/hooks", "http://localhost/v1/hooks"},
		{"/", "http://localhost/"},
	}
	for _, tt := range tests {
		got := socketURL(tt.path)
		if got != tt.want {
			t.Errorf("socketURL(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestSocketGet_Success(t *testing.T) {
	socketPath := startTestSocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))

	resp, err := socketGet(socketPath, "/v1/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("expected body 'hello', got %q", string(body))
	}
}

func TestSocketGet_ConnectionRefused(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	_, err := socketGet(socketPath, "/v1/state")
	if err == nil {
		t.Fatal("expected error for nonexistent socket")
	}
	if !strings.Contains(err.Error(), "agent not running or socket unavailable at") {
		t.Errorf("error should contain 'agent not running or socket unavailable at', got: %v", err)
	}
	if !strings.Contains(err.Error(), socketPath) {
		t.Errorf("error should contain socket path %q, got: %v", socketPath, err)
	}
}

func TestSocketPost_Success(t *testing.T) {
	var receivedBody string
	var receivedContentType string
	socketPath := startTestSocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	resp, err := socketPost(socketPath, "/v1/test", "application/json", strings.NewReader(`{"key":"val"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected content type 'application/json', got %q", receivedContentType)
	}
	if receivedBody != `{"key":"val"}` {
		t.Errorf("expected body '{\"key\":\"val\"}', got %q", receivedBody)
	}
}

func TestSocketPost_ConnectionRefused(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	_, err := socketPost(socketPath, "/v1/test", "text/plain", strings.NewReader("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent socket")
	}
	if !strings.Contains(err.Error(), "agent not running or socket unavailable at") {
		t.Errorf("error should contain 'agent not running or socket unavailable at', got: %v", err)
	}
	if !strings.Contains(err.Error(), socketPath) {
		t.Errorf("error should contain socket path %q, got: %v", socketPath, err)
	}
}

func TestDefaultSocketPath(t *testing.T) {
	got := defaultSocketPath()
	if got != nodeapi.DefaultSocketPath {
		t.Errorf("defaultSocketPath() = %q, want %q", got, nodeapi.DefaultSocketPath)
	}
}

func TestDefaultSocketPath_Override(t *testing.T) {
	overrideSocketPath(t, "/tmp/test-override.sock")
	got := defaultSocketPath()
	if got != "/tmp/test-override.sock" {
		t.Errorf("defaultSocketPath() = %q, want %q", got, "/tmp/test-override.sock")
	}
}
