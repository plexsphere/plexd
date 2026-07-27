package tunnel

import (
	"context"
	"errors"
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

// tcpSession builds a tcp-kind entry of the pull's sessions block, the only
// kind CreateSession provisions.
func tcpSession(sessionID, host string, port int, expiresAt time.Time) api.NodeStateSession {
	return api.NodeStateSession{
		SessionID: sessionID,
		JTI:       sessionID,
		Kind:      api.SessionKindTCP,
		Target:    api.SessionTarget{TCP: &api.SessionTargetTCP{Host: host, Port: port}},
		ExpiresAt: expiresAt,
	}
}

func TestSessionManager_CreateSession(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	addr, err := mgr.CreateSession(context.Background(), echoSession(t, "s1", echoAddr))
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

	_, err := mgr.CreateSession(context.Background(), echoSession(t, "dup", echoAddr))
	if err != nil {
		t.Fatalf("first CreateSession() error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), echoSession(t, "dup", echoAddr))
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

	_, err := mgr.CreateSession(context.Background(), echoSession(t, "m1", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession(m1) error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), echoSession(t, "m2", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession(m2) error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), echoSession(t, "m3", echoAddr))
	if err == nil {
		t.Fatal("expected error when max sessions reached")
	}
}

func TestSessionManager_CloseSession(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	_, err := mgr.CreateSession(context.Background(), echoSession(t, "c1", echoAddr))
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

	_, err := mgr.CreateSession(context.Background(), echoSession(t, "sh1", echoAddr))
	if err != nil {
		t.Fatalf("CreateSession(sh1) error: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), echoSession(t, "sh2", echoAddr))
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

	setup := tcpSession("expired", "127.0.0.1", 22, time.Now().Add(-1*time.Minute))

	_, err := mgr.CreateSession(context.Background(), setup)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestSessionManager_NonProvisionableKindRejected(t *testing.T) {
	mgr := newTestManager(t, Config{})

	sshSession := api.NodeStateSession{
		SessionID: "ssh-kind",
		Kind:      api.SessionKindSSH,
		Target:    api.SessionTarget{SSH: &api.SessionTargetSSH{User: "ops"}},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	tcpWithoutTarget := api.NodeStateSession{
		SessionID: "tcp-no-target",
		Kind:      api.SessionKindTCP,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	for _, tt := range []struct {
		name string
		sess api.NodeStateSession
	}{
		{"ssh kind", sshSession},
		{"tcp kind without tcp target", tcpWithoutTarget},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mgr.CreateSession(context.Background(), tt.sess)
			if err == nil {
				t.Fatal("expected error for a non-provisionable session")
			}
			if err.Error() != "tunnel: session kind is not provisionable" {
				t.Errorf("CreateSession() error = %q, want %q", err, "tunnel: session kind is not provisionable")
			}
			if mgr.ActiveCount() != 0 {
				t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
			}
		})
	}
}

func TestSessionManager_ActiveSessionsReportsCappedExpiry(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: time.Minute,
	})

	setup := echoSession(t, "active-1", echoAddr)
	setup.ExpiresAt = time.Now().Add(24 * time.Hour)
	created := time.Now()
	if _, err := mgr.CreateSession(context.Background(), setup); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	active := mgr.ActiveSessions()
	if len(active) != 1 {
		t.Fatalf("ActiveSessions() has %d entries, want 1", len(active))
	}
	expiresAt, ok := active["active-1"]
	if !ok {
		t.Fatalf("ActiveSessions() = %v, want an entry for %q", active, "active-1")
	}

	// The wire expiry is a day out; the manager caps it at DefaultTimeout, and
	// the teardown pass discriminates on the capped value.
	capped := created.Add(time.Minute)
	if expiresAt.After(capped.Add(time.Second)) || expiresAt.Before(capped.Add(-time.Second)) {
		t.Errorf("ActiveSessions() expiry = %v, want ~%v", expiresAt, capped)
	}

	// The returned map is a copy: mutating it must not disturb the manager.
	delete(active, "active-1")
	if mgr.ActiveCount() != 1 {
		t.Errorf("ActiveCount() = %d after mutating the returned map, want 1", mgr.ActiveCount())
	}
}

func TestSessionManager_IdleTimeoutClosesUnreachedListener(t *testing.T) {
	echoAddr := startEchoServer(t)
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

	// The listener bind is the session's first activity, so a listener nothing
	// ever connects to idles out one window after Start.
	setup := echoSession(t, "idle-unreached", echoAddr)
	setup.IdleTimeoutSeconds = 1
	if _, err := mgr.CreateSession(context.Background(), setup); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	waitForCondition(t, 4*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(records) == 1
	})

	mu.Lock()
	defer mu.Unlock()
	if records[0].reason != reasonIdle {
		t.Errorf("callback reason = %q, want %q", records[0].reason, reasonIdle)
	}
	if got := TerminatedByFromReason(records[0].reason); got != api.TerminatedByIdleTimeout {
		t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByIdleTimeout)
	}
}

func TestSessionManager_IdleWindowRearmedByByteFlow(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	var closed atomic.Int32
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		closed.Add(1)
	})

	setup := echoSession(t, "idle-rearm", echoAddr)
	setup.IdleTimeoutSeconds = 1
	addr, err := mgr.CreateSession(context.Background(), setup)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	// Echo a byte every 250ms for 2s: twice the idle window, so a window that
	// byte flow did not re-arm would already have closed the session.
	buf := make([]byte, 1)
	for i := 0; i < 8; i++ {
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatalf("Write() error: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("ReadFull() error: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}

	if n := closed.Load(); n != 0 {
		t.Fatalf("session closed %d times while bytes were flowing, want 0", n)
	}

	// Silence closes it one window later.
	waitForCondition(t, 4*time.Second, func() bool { return closed.Load() == 1 })
}

func TestSessionManager_ZeroIdleTimeoutArmsNoMonitor(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	// IdleTimeoutSeconds is absent, so the session has no idle window at all:
	// no monitor goroutine (TestMain's goleak check enforces that) and no
	// activity stamping on the forwarding path.
	if _, err := mgr.CreateSession(context.Background(), echoSession(t, "idle-off", echoAddr)); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	mgr.mu.Lock()
	idle := mgr.sessions["idle-off"].idleTimeout
	mgr.mu.Unlock()
	if idle != 0 {
		t.Errorf("session idleTimeout = %v, want 0", idle)
	}

	time.Sleep(100 * time.Millisecond)
	if mgr.ActiveCount() != 1 {
		t.Errorf("expected the session to stay open, ActiveCount()=%d", mgr.ActiveCount())
	}
}

func TestSessionManager_IdleMonitorStopsOnOtherClose(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	// An hour-long idle window: if the close did not cancel the session context,
	// the monitor goroutine would sit on its timer past the end of the test and
	// TestMain's goleak check would report it.
	setup := echoSession(t, "idle-stop", echoAddr)
	setup.IdleTimeoutSeconds = 3600
	if _, err := mgr.CreateSession(context.Background(), setup); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	mgr.CloseSession("idle-stop", reasonDrained)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after close, got %d", mgr.ActiveCount())
	}
}

func TestSessionManager_DefaultTimeoutCapsExpiry(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: 2 * time.Second,
	})

	setup := echoSession(t, "cap1", echoAddr)
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
			setup := tcpSession("port-"+tt.name, "127.0.0.1", tt.port, time.Now().Add(5*time.Minute))
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

	_, err := mgr.CreateSession(context.Background(), echoSession(t, "meta1", echoAddr))
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

	addr, err := mgr.CreateSession(context.Background(), echoSession(t, "oc-revoke", echoAddr))
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
	mgr.CloseSession("oc-revoke", reasonDrained)

	mu.Lock()
	defer mu.Unlock()
	if len(records) != 1 {
		t.Fatalf("expected 1 on-closed callback, got %d", len(records))
	}
	rec := records[0]
	if rec.sessionID != "oc-revoke" {
		t.Errorf("callback session_id = %q, want %q", rec.sessionID, "oc-revoke")
	}
	if rec.reason != reasonDrained {
		t.Errorf("callback reason = %q, want %q", rec.reason, reasonDrained)
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

	setup := echoSession(t, "oc-expire", echoAddr)
	setup.ExpiresAt = time.Now().Add(50 * time.Millisecond)
	if _, err := mgr.CreateSession(context.Background(), setup); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// The TTL timer fires CloseSession(id, reasonExpired), which must reach the
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
	if rec.reason != reasonExpired {
		t.Errorf("callback reason = %q, want %q", rec.reason, reasonExpired)
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

	if _, err := mgr.CreateSession(context.Background(), echoSession(t, "oc-shutdown", echoAddr)); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	mgr.Shutdown()

	mu.Lock()
	defer mu.Unlock()
	if len(records) != 1 {
		t.Fatalf("expected 1 on-closed callback for Shutdown(), got %d", len(records))
	}
	if records[0].reason != reasonShutdown {
		t.Errorf("callback reason = %q, want %q", records[0].reason, reasonShutdown)
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
		if _, err := mgr.CreateSession(context.Background(), echoSession(t, id, echoAddr)); err != nil {
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

	if _, err := mgr.CreateSession(context.Background(), echoSession(t, "oc-double", echoAddr)); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	mgr.CloseSession("oc-double", reasonDrained)
	mgr.CloseSession("oc-double", reasonDrained)

	if n := count.Load(); n != 1 {
		t.Errorf("on-closed callback fired %d times, want 1", n)
	}
}

// TestSessionManager_UnbindableMeshIPRejected covers the fail-closed bind guard:
// a session listener carries no authentication, so a mesh IP that is not a
// bindable unicast address would have net.Listen bind every unicast address on
// the host and publish an unauthenticated forward to an internal service on the
// node's public and LAN interfaces. The address is copied verbatim from the
// control plane's registration response, so the wildcards are as reachable a
// value as the empty one.
//
// The mapped and zoned spellings are the ones a guard written against the parsed
// address lets through: netip.Addr.IsUnspecified matches exactly 0.0.0.0 and ::,
// while net.Listen binds the same dual-stack wildcard for all of them.
func TestSessionManager_UnbindableMeshIPRejected(t *testing.T) {
	echoAddr := startEchoServer(t)

	for _, tt := range []struct {
		name   string
		meshIP string
	}{
		{"empty", ""},
		{"ipv4 wildcard", "0.0.0.0"},
		{"ipv6 wildcard", "::"},
		{"bracketed ipv6 wildcard", "[::]"},
		{"ipv4-mapped ipv6 wildcard", "::ffff:0.0.0.0"},
		{"ipv4-mapped ipv6 wildcard in hex form", "::ffff:0:0"},
		{"zoned ipv6 wildcard", "::%eth0"},
		{"zoned ipv4-mapped ipv6 wildcard", "::ffff:0.0.0.0%eth0"},
		{"multicast", "224.0.0.1"},
		{"not an address", "mesh.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewSessionManager(Config{}, tt.meshIP, slog.Default())
			t.Cleanup(func() { mgr.Shutdown() })

			_, err := mgr.CreateSession(context.Background(), echoSession(t, "mesh-ip", echoAddr))
			if err == nil {
				t.Fatalf("expected an error for mesh IP %q", tt.meshIP)
			}
			if mgr.ActiveCount() != 0 {
				t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
			}
		})
	}
}

// TestSessionManager_StaleIdleCloseSparesSuccessor covers the guard the idle
// monitor shares with the expiry timer. The monitor commits to its close once
// the window has fired, so a cancellation racing that decision must not let it
// take down a session that reused the id: that close would strand a session the
// control plane still believes is live, with no pull able to rebuild it while
// its entry stands.
func TestSessionManager_StaleIdleCloseSparesSuccessor(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	setup := echoSession(t, "sess-reissued", echoAddr)
	setup.IdleTimeoutSeconds = 3600
	if _, err := mgr.CreateSession(context.Background(), setup); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// The first session's idle closer, captured while it is still the live one.
	mgr.mu.Lock()
	staleOnIdle := mgr.sessions["sess-reissued"].onIdle
	mgr.mu.Unlock()

	mgr.CloseSession("sess-reissued", reasonDrained)
	if _, err := mgr.CreateSession(context.Background(), setup); err != nil {
		t.Fatalf("re-provisioning CreateSession() error: %v", err)
	}

	staleOnIdle()

	if mgr.ActiveCount() != 1 {
		t.Errorf("the stale idle closer took down the successor session, ActiveCount()=%d", mgr.ActiveCount())
	}
}

// TestSessionManager_InvalidIdleTimeoutRejected covers the values that would
// leave idleTimeout <= 0 — indistinguishable from "no idle window" — and so
// silently disable the enforcement that closes an abandoned forward.
func TestSessionManager_InvalidIdleTimeoutRejected(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{})

	for _, tt := range []struct {
		name    string
		seconds int
	}{
		{"negative", -1},
		{"overflows the duration multiplication", 1 << 62},
		{"above the bound", maxIdleTimeoutSeconds + 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setup := echoSession(t, "idle-"+tt.name, echoAddr)
			setup.IdleTimeoutSeconds = tt.seconds

			_, err := mgr.CreateSession(context.Background(), setup)
			if err == nil {
				t.Fatalf("expected an error for idle_timeout_seconds=%d", tt.seconds)
			}
			if mgr.ActiveCount() != 0 {
				t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
			}
		})
	}
}

// TestSessionManager_ExpiryTimerSparesNewSessionOnSameID covers the id being
// re-issued: the dispatcher re-provisions a drained id by design, so a timer
// armed for the earlier session must not close the one that took its place —
// that close would strand a session the control plane still believes is live.
func TestSessionManager_ExpiryTimerSparesNewSessionOnSameID(t *testing.T) {
	echoAddr := startEchoServer(t)
	mgr := newTestManager(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: time.Minute,
	})

	var closes atomic.Int32
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		closes.Add(1)
	})

	// The first session's expiry timer is armed for ~150ms.
	first := echoSession(t, "reissued", echoAddr)
	first.ExpiresAt = time.Now().Add(150 * time.Millisecond)
	if _, err := mgr.CreateSession(context.Background(), first); err != nil {
		t.Fatalf("CreateSession(first) error: %v", err)
	}

	// It is torn down and the id re-issued well before that timer fires.
	mgr.CloseSession("reissued", reasonDrained)
	if _, err := mgr.CreateSession(context.Background(), echoSession(t, "reissued", echoAddr)); err != nil {
		t.Fatalf("CreateSession(second) error: %v", err)
	}

	// The stale timer fires here; the second session must survive it.
	time.Sleep(400 * time.Millisecond)

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected the re-provisioned session to survive the stale timer, ActiveCount()=%d", mgr.ActiveCount())
	}
	if n := closes.Load(); n != 1 {
		t.Errorf("on-closed fired %d times, want 1 (the first session only)", n)
	}
}

func TestSessionManager_DisabledRejectsAll(t *testing.T) {
	mgr := newTestManager(t, Config{
		Enabled:        false,
		MaxSessions:    10,
		DefaultTimeout: 5 * time.Minute,
	})

	setup := tcpSession("disabled", "127.0.0.1", 22, time.Now().Add(5*time.Minute))

	_, err := mgr.CreateSession(context.Background(), setup)
	if err == nil {
		t.Fatal("expected error when tunneling is disabled")
	}
	if !errors.Is(err, ErrTunnelingDisabled) {
		t.Errorf("CreateSession() error = %v, want ErrTunnelingDisabled", err)
	}
}
