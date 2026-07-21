package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
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

// closedRecord captures one invocation of a SetOnClosed callback.
type closedRecord struct {
	sessionID string
	reason    string
	info      *ClosedSessionInfo
}

// sessionListenAddr reads a live session's listener address from the manager's
// session map (white-box). The session_started row no longer carries the listen
// address, so tests that need to dial the tunnel read it here.
func sessionListenAddr(t *testing.T, mgr *SessionManager, sessionID string) string {
	t.Helper()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	sess, ok := mgr.sessions[sessionID]
	if !ok {
		t.Fatalf("session %q not found", sessionID)
	}
	return sess.ListenAddr()
}

func TestSessionManager_OnClosedFiresForRevoke(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	mgr := newTestManager(t, Config{})

	var (
		mu      sync.Mutex
		records []closedRecord
	)
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, closedRecord{sessionID: sessionID, reason: reason, info: info})
	})

	addr, err := mgr.CreateSession(context.Background(), validSetup("oc-revoke", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	msg := "count me"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	// CloseSession drains the forwarding goroutines before reading the counters,
	// so the callback sees the full byte counts with no polling here.
	mgr.CloseSession("oc-revoke", "revoked")

	mu.Lock()
	defer mu.Unlock()
	if len(records) != 1 {
		t.Fatalf("expected 1 on-closed callback, got %d", len(records))
	}
	rec := records[0]
	if rec.sessionID != "oc-revoke" {
		t.Errorf("callback session_id = %q, want %q", rec.sessionID, "oc-revoke")
	}
	if rec.reason != "revoked" {
		t.Errorf("callback reason = %q, want %q", rec.reason, "revoked")
	}
	if rec.info == nil {
		t.Fatal("callback info is nil")
	}
	if rec.info.TargetHost != host {
		t.Errorf("info.TargetHost = %q, want %q", rec.info.TargetHost, host)
	}
	if rec.info.TargetPort != port {
		t.Errorf("info.TargetPort = %d, want %d", rec.info.TargetPort, port)
	}
	if rec.info.BytesIn != int64(len(msg)) {
		t.Errorf("info.BytesIn = %d, want %d", rec.info.BytesIn, len(msg))
	}
	if rec.info.BytesOut != int64(len(msg)) {
		t.Errorf("info.BytesOut = %d, want %d", rec.info.BytesOut, len(msg))
	}
}

func TestSessionManager_OnClosedFiresForExpiry(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	mgr := newTestManager(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: time.Minute,
	})

	var (
		mu      sync.Mutex
		records []closedRecord
	)
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, closedRecord{sessionID: sessionID, reason: reason, info: info})
	})

	setup := validSetup("oc-expire", echoAddr)
	setup.ExpiresAt = time.Now().Add(50 * time.Millisecond)
	if _, err := mgr.CreateSession(context.Background(), setup); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// The TTL timer fires CloseSession(id, "expired"), which must reach the
	// on-closed callback.
	waitForCondition(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(records) == 1
	})

	mu.Lock()
	defer mu.Unlock()
	rec := records[0]
	if rec.sessionID != "oc-expire" {
		t.Errorf("callback session_id = %q, want %q", rec.sessionID, "oc-expire")
	}
	if rec.reason != "expired" {
		t.Errorf("callback reason = %q, want %q", rec.reason, "expired")
	}
	if rec.info == nil {
		t.Fatal("callback info is nil")
	}
	if rec.info.TargetHost != host {
		t.Errorf("info.TargetHost = %q, want %q", rec.info.TargetHost, host)
	}
	if rec.info.TargetPort != port {
		t.Errorf("info.TargetPort = %d, want %d", rec.info.TargetPort, port)
	}
}

func TestSessionManager_OnClosedFiresForShutdown(t *testing.T) {
	// The session_ended row is the only carrier of a session's byte counters,
	// so a node restart must not drop it for the sessions that were still live.
	echoAddr := startEchoServer(t)
	mgr := NewSessionManager(Config{}, "127.0.0.1", slog.Default())

	var (
		mu      sync.Mutex
		records []closedRecord
	)
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, closedRecord{sessionID: sessionID, reason: reason, info: info})
	})

	if _, err := mgr.CreateSession(context.Background(), validSetup("oc-shutdown", echoAddr)); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	mgr.Shutdown()

	mu.Lock()
	defer mu.Unlock()
	if len(records) != 1 {
		t.Fatalf("expected 1 on-closed callback for Shutdown(), got %d", len(records))
	}
	if records[0].reason != "shutdown" {
		t.Errorf("callback reason = %q, want %q", records[0].reason, "shutdown")
	}
	if got := TerminatedByFromReason(records[0].reason); got != api.TerminatedByPlexdClose {
		t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByPlexdClose)
	}
}

// TestSessionManager_ShutdownReportsConcurrently verifies Shutdown closes
// sessions concurrently. The on-closed report blocks (a real report is a bounded
// HTTP POST), so serial closing would stretch teardown to sessionCount times the
// per-report bound; concurrent closing keeps it near a single report's cost.
func TestSessionManager_ShutdownReportsConcurrently(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := NewSessionManager(Config{}, "127.0.0.1", slog.Default())

	const (
		sessionCount = 8
		reportDelay  = 100 * time.Millisecond
	)

	var closed atomic.Int32
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		time.Sleep(reportDelay)
		closed.Add(1)
	})

	for i := 0; i < sessionCount; i++ {
		id := "sh-conc-" + strconv.Itoa(i)
		if _, err := mgr.CreateSession(context.Background(), validSetup(id, echoAddr)); err != nil {
			t.Fatalf("CreateSession(%s) error: %v", id, err)
		}
	}

	start := time.Now()
	mgr.Shutdown()
	elapsed := time.Since(start)

	if n := closed.Load(); int(n) != sessionCount {
		t.Fatalf("on-closed fired %d times, want %d", n, sessionCount)
	}

	// Serial closing takes sessionCount*reportDelay (800ms); concurrent closing
	// takes ~reportDelay. The midpoint (400ms) cleanly separates the two.
	if maxWant := sessionCount * reportDelay / 2; elapsed >= maxWant {
		t.Fatalf("Shutdown took %v for %d sessions; want < %v (reports must run concurrently)", elapsed, sessionCount, maxWant)
	}
}

func TestSessionManager_OnClosedFiresOnceForDoubleClose(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	var count atomic.Int32
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		count.Add(1)
	})

	if _, err := mgr.CreateSession(context.Background(), validSetup("oc-double", echoAddr)); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	mgr.CloseSession("oc-double", "revoked")
	mgr.CloseSession("oc-double", "revoked")

	if n := count.Load(); n != 1 {
		t.Errorf("on-closed callback fired %d times, want 1", n)
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
