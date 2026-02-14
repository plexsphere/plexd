package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type mockJWTVerifier struct {
	err error
}

func (m *mockJWTVerifier) Verify(token string) error { return m.err }

func TestSSHServerConfig_ApplyDefaults(t *testing.T) {
	cfg := SSHServerConfig{}
	cfg.ApplyDefaults()

	if cfg.MaxSessions != DefaultMaxSSHSessions {
		t.Errorf("MaxSessions = %d, want %d", cfg.MaxSessions, DefaultMaxSSHSessions)
	}
	if cfg.IdleTimeout != DefaultSSHIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", cfg.IdleTimeout, DefaultSSHIdleTimeout)
	}
}

func TestSSHServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SSHServerConfig
		wantErr string
	}{
		{
			name:    "missing listen addr",
			cfg:     SSHServerConfig{MaxSessions: 10, IdleTimeout: 5 * time.Minute},
			wantErr: "tunnel: ssh: config: ListenAddr is required",
		},
		{
			name:    "invalid max sessions",
			cfg:     SSHServerConfig{ListenAddr: "127.0.0.1:2222", MaxSessions: 0, IdleTimeout: 5 * time.Minute},
			wantErr: "tunnel: ssh: config: MaxSessions must be positive",
		},
		{
			name:    "negative max sessions",
			cfg:     SSHServerConfig{ListenAddr: "127.0.0.1:2222", MaxSessions: -1, IdleTimeout: 5 * time.Minute},
			wantErr: "tunnel: ssh: config: MaxSessions must be positive",
		},
		{
			name:    "idle timeout too short",
			cfg:     SSHServerConfig{ListenAddr: "127.0.0.1:2222", MaxSessions: 10, IdleTimeout: 30 * time.Second},
			wantErr: "tunnel: ssh: config: IdleTimeout must be at least 1m",
		},
		{
			name: "valid config",
			cfg:  SSHServerConfig{ListenAddr: "127.0.0.1:2222", MaxSessions: 10, IdleTimeout: 5 * time.Minute},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNewSSHServer(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	srv := NewSSHServer(SSHServerConfig{
		ListenAddr: "127.0.0.1:0",
	}, hostKey, &mockJWTVerifier{}, slog.Default())

	if srv == nil {
		t.Fatal("NewSSHServer() returned nil")
	}
}

func TestSSHServer_AcceptsAuthenticatedConnection(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	srv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 5 * time.Minute,
	}, hostKey, &mockJWTVerifier{err: nil}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

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

	conn, err := ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	conn.Close()
}

func TestSSHServer_RejectsInvalidToken(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	srv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 5 * time.Minute,
	}, hostKey, &mockJWTVerifier{err: errors.New("invalid token")}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

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

	_, err = ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err == nil {
		t.Fatal("ssh.Dial() should have failed with invalid token")
	}
}

func TestSSHServer_EnforcesMaxSessions(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	srv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		MaxSessions: 1,
		IdleTimeout: 5 * time.Minute,
	}, hostKey, &mockJWTVerifier{err: nil}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

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

	// First connection should succeed.
	conn1, err := ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err != nil {
		t.Fatalf("first ssh.Dial() error: %v", err)
	}
	defer conn1.Close()

	// Second connection should fail (max sessions = 1).
	_, err = ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err == nil {
		t.Fatal("second ssh.Dial() should have failed due to max sessions")
	}
}

func TestSSHServer_Shutdown(t *testing.T) {
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	srv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 5 * time.Minute,
	}, hostKey, &mockJWTVerifier{err: nil}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty string after Start()")
	}

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

	conn, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	conn.Close()

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// After shutdown, new connections should fail.
	_, err = ssh.Dial("tcp", addr, clientCfg)
	if err == nil {
		t.Fatal("ssh.Dial() should have failed after shutdown")
	}
}
