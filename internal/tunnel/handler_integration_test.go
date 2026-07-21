package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// waitForCondition polls until cond returns true or timeout expires.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out after %v waiting for condition", timeout)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// TestIntegration_FullTunnelLifecycle wires a real SessionManager with a local
// TCP echo server. Verifies the full lifecycle:
// SSE setup → listener opens → client connects → data flows → session expires → cleanup.
func TestIntegration_FullTunnelLifecycle(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	mgr := NewSessionManager(Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: 3 * time.Second,
	}, "127.0.0.1", slog.Default())
	t.Cleanup(func() { mgr.Shutdown() })

	reporter := &mockReporter{}
	handler := HandleSSHSessionSetup(mgr, reporter)

	// The session_ended row arrives via the manager's on-closed callback, just
	// as up.go wires it in production.
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		reporter.ReportSessionEnded(context.Background(), sessionID, info.TargetHost, info.TargetPort, info.BytesIn, info.BytesOut, TerminatedByFromReason(reason))
	})

	// 1. Dispatch ssh_session_setup SSE event.
	setup := api.SSHSessionSetup{
		SessionID:     "integ-lifecycle-1",
		TargetHost:    host,
		TargetPort:    port,
		AuthorizedKey: "ssh-ed25519 AAAAC3...",
		ExpiresAt:     time.Now().Add(3 * time.Second),
	}
	envelope := testEnvelope(api.EventSSHSessionSetup, setup)

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("HandleSSHSessionSetup() error: %v", err)
	}

	// 2. Verify session is active and the started row was reported.
	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}

	reporter.mu.Lock()
	if len(reporter.startedCalls) != 1 {
		reporter.mu.Unlock()
		t.Fatalf("expected 1 ReportSessionStarted call, got %d", len(reporter.startedCalls))
	}
	started := reporter.startedCalls[0]
	reporter.mu.Unlock()

	if started.TargetHost != host || started.TargetPort != port {
		t.Errorf("started row target = %s:%d, want %s:%d", started.TargetHost, started.TargetPort, host, port)
	}

	// 3. Connect and verify bidirectional data flow. The started row carries no
	// listen address (production operators reach it via the mesh), so read it
	// from the live session directly.
	listenAddr := sessionListenAddr(t, mgr, "integ-lifecycle-1")
	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	msg := "integration test data"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), msg)
	}

	// 4. Close the client connection so the forwarding goroutines can exit
	// before the session expires. CloseSession drains them before reading the
	// counters, so the ended row below carries the full byte counts.
	conn.Close()

	// 5. Wait for the session to expire (DefaultTimeout caps at 3s) and the
	// on-closed callback to emit the session_ended row. Waiting on the ended
	// row (not ActiveCount) avoids racing the callback, which fires after the
	// session is already removed from the map.
	waitForCondition(t, 5*time.Second, func() bool {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		return len(reporter.endedCalls) == 1
	})

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected session to auto-expire, ActiveCount()=%d", mgr.ActiveCount())
	}

	// 6. The session_ended row must carry the counted bytes and the ttl_expired
	// reason.
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.endedCalls) != 1 {
		t.Fatalf("expected 1 ReportSessionEnded call, got %d", len(reporter.endedCalls))
	}
	ended := reporter.endedCalls[0]
	if ended.SessionID != "integ-lifecycle-1" {
		t.Errorf("ended row session_id = %q, want %q", ended.SessionID, "integ-lifecycle-1")
	}
	if ended.BytesIn != int64(len(msg)) {
		t.Errorf("ended row bytes_in = %d, want %d", ended.BytesIn, len(msg))
	}
	if ended.BytesOut != int64(len(msg)) {
		t.Errorf("ended row bytes_out = %d, want %d", ended.BytesOut, len(msg))
	}
	if ended.TerminatedBy != api.TerminatedByTTLExpired {
		t.Errorf("ended row terminated_by = %q, want %q", ended.TerminatedBy, api.TerminatedByTTLExpired)
	}
}

// TestIntegration_SessionRevocationDuringActiveConnection verifies that a
// session_revoked SSE event terminates an active TCP connection.
func TestIntegration_SessionRevocationDuringActiveConnection(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	mgr := NewSessionManager(Config{}, "127.0.0.1", slog.Default())
	t.Cleanup(func() { mgr.Shutdown() })

	reporter := &mockReporter{}
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		reporter.ReportSessionEnded(context.Background(), sessionID, info.TargetHost, info.TargetPort, info.BytesIn, info.BytesOut, TerminatedByFromReason(reason))
	})

	// Create session via handler.
	setupHandler := HandleSSHSessionSetup(mgr, reporter)
	setup := api.SSHSessionSetup{
		SessionID:  "integ-revoke-1",
		TargetHost: host,
		TargetPort: port,
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	envelope := testEnvelope(api.EventSSHSessionSetup, setup)

	if err := setupHandler(context.Background(), envelope); err != nil {
		t.Fatalf("HandleSSHSessionSetup() error: %v", err)
	}

	listenAddr := sessionListenAddr(t, mgr, "integ-revoke-1")

	// Connect a client.
	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	// Verify connection works.
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	oneByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, oneByte); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	// Revoke via handler (no reporter arg: the ended row comes via the callback).
	revokeHandler := HandleSessionRevoked(mgr)
	revokePayload := struct {
		SessionID string `json:"session_id"`
	}{SessionID: "integ-revoke-1"}
	revokeEnvelope := testEnvelope(api.EventSessionRevoked, revokePayload)

	if err := revokeHandler(context.Background(), revokeEnvelope); err != nil {
		t.Fatalf("HandleSessionRevoked() error: %v", err)
	}

	// Session should be removed.
	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after revocation, got %d", mgr.ActiveCount())
	}

	// The client connection should be terminated — reads should fail.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected read error on revoked connection, got nil")
	}

	// The on-closed callback must have emitted a session_ended row with the
	// operator_revoke reason and the counted bytes.
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.endedCalls) != 1 {
		t.Fatalf("expected 1 ReportSessionEnded call, got %d", len(reporter.endedCalls))
	}
	ended := reporter.endedCalls[0]
	if ended.TerminatedBy != api.TerminatedByOperatorRevoke {
		t.Errorf("ended row terminated_by = %q, want %q", ended.TerminatedBy, api.TerminatedByOperatorRevoke)
	}
	if ended.BytesIn != 1 || ended.BytesOut != 1 {
		t.Errorf("ended row bytes = (%d, %d), want (1, 1)", ended.BytesIn, ended.BytesOut)
	}
}

// TestIntegration_MaxSessionsWithConcurrentSetups verifies that concurrent
// ssh_session_setup events respect MaxSessions under the race detector.
func TestIntegration_MaxSessionsWithConcurrentSetups(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	const maxSessions = 3
	const totalAttempts = 10

	mgr := NewSessionManager(Config{
		Enabled:        true,
		MaxSessions:    maxSessions,
		DefaultTimeout: 30 * time.Second,
	}, "127.0.0.1", slog.Default())
	t.Cleanup(func() { mgr.Shutdown() })

	reporter := &mockReporter{}
	handler := HandleSSHSessionSetup(mgr, reporter)

	var (
		wg       sync.WaitGroup
		accepted atomic.Int32
		rejected atomic.Int32
	)

	for i := 0; i < totalAttempts; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			setup := api.SSHSessionSetup{
				SessionID:  fmt.Sprintf("concurrent-%d", idx),
				TargetHost: host,
				TargetPort: port,
				ExpiresAt:  time.Now().Add(30 * time.Second),
			}
			data, _ := json.Marshal(setup)
			envelope := api.SignedEnvelope{
				EventType: api.EventSSHSessionSetup,
				EventID:   fmt.Sprintf("evt-concurrent-%d", idx),
				Payload:   data,
			}

			err := handler(context.Background(), envelope)
			if err != nil {
				rejected.Add(1)
			} else {
				accepted.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Exactly maxSessions should have been accepted.
	if n := accepted.Load(); n != maxSessions {
		t.Errorf("accepted sessions = %d, want %d", n, maxSessions)
	}

	if n := rejected.Load(); n != totalAttempts-maxSessions {
		t.Errorf("rejected sessions = %d, want %d", n, totalAttempts-maxSessions)
	}

	if n := mgr.ActiveCount(); n != maxSessions {
		t.Errorf("ActiveCount() = %d, want %d", n, maxSessions)
	}
}
