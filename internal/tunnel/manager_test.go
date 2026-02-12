package tunnel

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func newTestManager(t *testing.T, cfg Config) *SessionManager {
	t.Helper()
	mgr := NewSessionManager(cfg, "127.0.0.1", slog.Default())
	t.Cleanup(func() { mgr.Shutdown() })
	return mgr
}

func validSetup(sessionID, echoAddr string) api.SSHSessionSetup {
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	return api.SSHSessionSetup{
		SessionID:  sessionID,
		TargetHost: host,
		TargetPort: port,
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
}

func TestSessionManager_CreateSession(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	addr, err := mgr.CreateSession(context.Background(), validSetup("s1", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	if addr == "" {
		t.Fatal("expected non-empty listen address")
	}
	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}
}

func TestSessionManager_DuplicateSessionRejected(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	_, err := mgr.CreateSession(context.Background(), validSetup("dup", echoAddr))
	if err != nil {
		t.Fatalf("first CreateSession() error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), validSetup("dup", echoAddr))
	if err == nil {
		t.Fatal("expected error for duplicate session ID")
	}
}

func TestSessionManager_MaxSessionsEnforced(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{
		Enabled:        true,
		MaxSessions:    2,
		DefaultTimeout: 5 * time.Minute,
	})

	_, err := mgr.CreateSession(context.Background(), validSetup("m1", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession(m1) error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), validSetup("m2", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession(m2) error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), validSetup("m3", echoAddr))
	if err == nil {
		t.Fatal("expected error when max sessions reached")
	}
}

func TestSessionManager_CloseSession(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	_, err := mgr.CreateSession(context.Background(), validSetup("c1", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	mgr.CloseSession("c1", "test")

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after close, got %d", mgr.ActiveCount())
	}
}

func TestSessionManager_Shutdown(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := NewSessionManager(Config{}, "127.0.0.1", slog.Default())

	_, err := mgr.CreateSession(context.Background(), validSetup("sh1", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession(sh1) error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), validSetup("sh2", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession(sh2) error: %v", err)
	}

	mgr.Shutdown()

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after shutdown, got %d", mgr.ActiveCount())
	}
}

func TestSessionManager_ExpiredSessionRejected(t *testing.T) {
	mgr := newTestManager(t, Config{})

	setup := api.SSHSessionSetup{
		SessionID:  "expired",
		TargetHost: "127.0.0.1",
		TargetPort: 22,
		ExpiresAt:  time.Now().Add(-1 * time.Minute),
	}

	_, err := mgr.CreateSession(context.Background(), setup)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestSessionManager_DefaultTimeoutCapsExpiry(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: 2 * time.Second,
	})

	setup := validSetup("cap1", echoAddr)
	setup.ExpiresAt = time.Now().Add(24 * time.Hour)

	_, err := mgr.CreateSession(context.Background(), setup)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}

	// Wait for the session to expire (capped at ~2s).
	time.Sleep(3 * time.Second)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected session to auto-expire, ActiveCount()=%d", mgr.ActiveCount())
	}
}

func TestSessionManager_InvalidPortRejected(t *testing.T) {
	mgr := newTestManager(t, Config{})

	tests := []struct {
		name string
		port int
	}{
		{"zero port", 0},
		{"negative port", -1},
		{"port above 65535", 65536},
		{"high port", 100000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := api.SSHSessionSetup{
				SessionID:  "port-" + tt.name,
				TargetHost: "127.0.0.1",
				TargetPort: tt.port,
				ExpiresAt:  time.Now().Add(5 * time.Minute),
			}
			_, err := mgr.CreateSession(context.Background(), setup)
			if err == nil {
				t.Fatalf("expected error for port %d", tt.port)
			}
		})
	}
}

func TestSessionManager_CloseSessionReturnsMetadata(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	_, err := mgr.CreateSession(context.Background(), validSetup("meta1", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	info := mgr.CloseSession("meta1", "test")
	if info == nil {
		t.Fatal("expected non-nil ClosedSessionInfo")
	}
	if info.Duration <= 0 {
		t.Errorf("expected positive duration, got %v", info.Duration)
	}
}

func TestSessionManager_CloseSessionNotFound(t *testing.T) {
	mgr := newTestManager(t, Config{})

	info := mgr.CloseSession("nonexistent", "test")
	if info != nil {
		t.Errorf("expected nil for nonexistent session, got %+v", info)
	}
}

func TestSessionManager_DisabledRejectsAll(t *testing.T) {
	mgr := newTestManager(t, Config{
		Enabled:        false,
		MaxSessions:    10,
		DefaultTimeout: 5 * time.Minute,
	})

	setup := api.SSHSessionSetup{
		SessionID:  "disabled",
		TargetHost: "127.0.0.1",
		TargetPort: 22,
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	_, err := mgr.CreateSession(context.Background(), setup)
	if err == nil {
		t.Fatal("expected error when tunneling is disabled")
	}
}
