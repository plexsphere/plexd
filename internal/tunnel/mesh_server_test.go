package tunnel

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestMeshServer_NewWithSSH(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	cfg := Config{
		SSHListenAddr: "127.0.0.1:0",
	}
	m := NewMeshServer(cfg, hostKey, &mockJWTVerifier{}, slog.Default())

	if m.SSHServer() == nil {
		t.Fatal("SSHServer() = nil, want non-nil when SSHListenAddr is set")
	}
	if m.SessionManager() == nil {
		t.Fatal("SessionManager() = nil, want non-nil")
	}
}

func TestMeshServer_NewWithoutSSH(t *testing.T) {
	cfg := Config{}
	m := NewMeshServer(cfg, nil, &mockJWTVerifier{}, slog.Default())

	if m.SSHServer() != nil {
		t.Fatal("SSHServer() = non-nil, want nil when SSHListenAddr is empty")
	}
	if m.SessionManager() == nil {
		t.Fatal("SessionManager() = nil, want non-nil")
	}
}

func TestMeshServer_StartAndShutdown(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	cfg := Config{
		SSHListenAddr: "127.0.0.1:0",
	}
	m := NewMeshServer(cfg, hostKey, &mockJWTVerifier{}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	addr := m.SSHServer().Addr()
	if addr == "" {
		t.Fatal("SSHServer().Addr() returned empty after Start()")
	}

	// Verify SSH is actually listening by connecting.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial SSH addr %s: %v", addr, err)
	}
	conn.Close()

	if err := m.Shutdown(); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// After shutdown, new connections should fail.
	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		t.Fatal("dial after shutdown should fail")
	}
}

func TestMeshServer_ShutdownOrder(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	cfg := Config{
		SSHListenAddr: "127.0.0.1:0",
	}
	m := NewMeshServer(cfg, hostKey, &mockJWTVerifier{}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	addr := m.SSHServer().Addr()

	// Connect an SSH client, verify connectivity, then close it.
	clientKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() for client error: %v", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	sshConn, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	sshConn.Close()

	// Shutdown should complete promptly: SSH listener closed first, then sessions drained.
	done := make(chan error, 1)
	go func() {
		done <- m.Shutdown()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown() error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown() timed out")
	}

	// SSH server should be closed after shutdown.
	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		t.Fatal("dial after shutdown should fail")
	}
}
