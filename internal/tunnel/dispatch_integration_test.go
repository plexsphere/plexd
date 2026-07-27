package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// startedRows returns the recorded session_started rows for one session id.
func startedRows(reporter *mockReporter, sessionID string) []sessionStartedCall {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	var rows []sessionStartedCall
	for _, row := range reporter.startedCalls {
		if row.SessionID == sessionID {
			rows = append(rows, row)
		}
	}
	return rows
}

// endedRows returns the recorded session_ended rows for one session id.
func endedRows(reporter *mockReporter, sessionID string) []sessionEndedCall {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	var rows []sessionEndedCall
	for _, row := range reporter.endedCalls {
		if row.SessionID == sessionID {
			rows = append(rows, row)
		}
	}
	return rows
}

// newIntegrationDispatcher wires a real SessionManager, a Dispatcher, and the
// on-closed callback that carries the session_ended row — the same wiring up.go
// builds in production.
func newIntegrationDispatcher(t *testing.T, cfg Config) (*Dispatcher, *SessionManager, *mockReporter) {
	t.Helper()
	mgr := NewSessionManager(cfg, "127.0.0.1", slog.Default())
	t.Cleanup(func() { mgr.Shutdown() })

	reporter := &mockReporter{}
	mgr.SetOnClosed(func(sessionID, reason string, info *ClosedSessionInfo) {
		reporter.ReportSessionEnded(context.Background(), sessionID, info.TargetHost, info.TargetPort, info.BytesIn, info.BytesOut, TerminatedByFromReason(reason))
	})

	return NewDispatcher(mgr, reporter, slog.Default()), mgr, reporter
}

// TestIntegration_FullTunnelLifecycle drives a real SessionManager through the
// sessions block of the pull, against a local TCP echo server: an entry appears
// and the listener opens, a client connects and data flows, the entry is
// re-observed without disturbing the session, a second session lapses locally
// while its entry lingers, and the block drains to tear the last one down.
func TestIntegration_FullTunnelLifecycle(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	d, mgr, reporter := newIntegrationDispatcher(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: time.Minute,
	})

	// 1. The block carries two entries: one for the whole test, one whose TTL
	// lapses locally while its entry keeps being served.
	live := tcpSession("integ-lifecycle-1", host, port, time.Now().Add(time.Minute))
	shortTTL := tcpSession("integ-lifecycle-ttl", host, port, time.Now().Add(300*time.Millisecond))
	block := sessionsSnapshot(live, shortTTL)

	d.Handle(context.Background(), block)

	if mgr.ActiveCount() != 2 {
		t.Fatalf("expected ActiveCount()=2, got %d", mgr.ActiveCount())
	}

	// 2. Both listeners reported a started row carrying the bound address.
	started := startedRows(reporter, "integ-lifecycle-1")
	if len(started) != 1 {
		t.Fatalf("expected 1 started row for the live session, got %d", len(started))
	}
	if started[0].TargetHost != host || started[0].TargetPort != port {
		t.Errorf("started row target = %s:%d, want %s:%d", started[0].TargetHost, started[0].TargetPort, host, port)
	}
	listenAddr := sessionListenAddr(t, mgr, "integ-lifecycle-1")
	if started[0].ListenerEndpoint != listenAddr {
		t.Errorf("started row listener_endpoint = %q, want %q", started[0].ListenerEndpoint, listenAddr)
	}

	// 3. Connect through the listener and verify the echo round trip.
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

	// 4. The short-TTL session expires locally while its entry is still served.
	waitForCondition(t, 3*time.Second, func() bool {
		return len(endedRows(reporter, "integ-lifecycle-ttl")) == 1
	})
	if got := endedRows(reporter, "integ-lifecycle-ttl")[0].TerminatedBy; got != api.TerminatedByTTLExpired {
		t.Errorf("lapsed session terminated_by = %q, want %q", got, api.TerminatedByTTLExpired)
	}

	// 5. The same block again: the live session is re-observed rather than set up
	// twice, and the lapsed one is not brought back.
	d.Handle(context.Background(), block)

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1 on the re-observing pull, got %d", mgr.ActiveCount())
	}
	if n := len(startedRows(reporter, "integ-lifecycle-1")); n != 1 {
		t.Errorf("live session reported %d started rows, want 1", n)
	}
	if n := len(startedRows(reporter, "integ-lifecycle-ttl")); n != 1 {
		t.Errorf("lapsed session reported %d started rows, want 1", n)
	}
	if got := sessionListenAddr(t, mgr, "integ-lifecycle-1"); got != listenAddr {
		t.Errorf("listener address changed from %q to %q", listenAddr, got)
	}

	// 6. Close the client connection so the forwarding goroutines can add their
	// byte counts, then drain the block: the disappearance is the teardown.
	conn.Close()
	d.Handle(context.Background(), sessionsSnapshot())

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after the drain, got %d", mgr.ActiveCount())
	}

	ended := endedRows(reporter, "integ-lifecycle-1")
	if len(ended) != 1 {
		t.Fatalf("expected 1 ended row for the live session, got %d", len(ended))
	}
	// A drained entry is reported as a local close: the node cannot tell a
	// revocation from a block the control plane failed to serve.
	if ended[0].TerminatedBy != api.TerminatedByPlexdClose {
		t.Errorf("ended row terminated_by = %q, want %q", ended[0].TerminatedBy, api.TerminatedByPlexdClose)
	}
	if ended[0].BytesIn != int64(len(msg)) || ended[0].BytesOut != int64(len(msg)) {
		t.Errorf("ended row bytes = (%d, %d), want (%d, %d)", ended[0].BytesIn, ended[0].BytesOut, len(msg), len(msg))
	}
}

// TestIntegration_SessionRevocationDuringActiveConnection verifies that an entry
// draining from the block tears down a connection with bytes in flight.
func TestIntegration_SessionRevocationDuringActiveConnection(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	d, mgr, reporter := newIntegrationDispatcher(t, Config{})

	entry := tcpSession("integ-revoke-1", host, port, time.Now().Add(5*time.Minute))
	d.Handle(context.Background(), sessionsSnapshot(entry))

	listenAddr := sessionListenAddr(t, mgr, "integ-revoke-1")
	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	// Bytes are flowing when the entry disappears.
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	d.Handle(context.Background(), sessionsSnapshot())

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after the drain, got %d", mgr.ActiveCount())
	}

	// The client connection is torn down with the session.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("expected read error on the torn-down connection, got nil")
	}

	ended := endedRows(reporter, "integ-revoke-1")
	if len(ended) != 1 {
		t.Fatalf("expected 1 ended row, got %d", len(ended))
	}
	if ended[0].TerminatedBy != api.TerminatedByPlexdClose {
		t.Errorf("ended row terminated_by = %q, want %q", ended[0].TerminatedBy, api.TerminatedByPlexdClose)
	}
	if ended[0].BytesIn != 1 || ended[0].BytesOut != 1 {
		t.Errorf("ended row bytes = (%d, %d), want (1, 1)", ended[0].BytesIn, ended[0].BytesOut)
	}
}

// TestIntegration_IdleWindowReportsIdleTimeout drives the idle window through
// the production wiring: the entry carries idle_timeout_seconds, the monitor
// closes the session on its own, and the on-closed callback is what turns that
// into the session_ended row the control plane audits on.
func TestIntegration_IdleWindowReportsIdleTimeout(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	d, mgr, reporter := newIntegrationDispatcher(t, Config{})

	entry := tcpSession("integ-idle-1", host, port, time.Now().Add(5*time.Minute))
	entry.IdleTimeoutSeconds = 1
	d.Handle(context.Background(), sessionsSnapshot(entry))

	// Nothing ever connects, so the window runs out from the listener bind.
	waitForCondition(t, 4*time.Second, func() bool {
		return len(endedRows(reporter, "integ-idle-1")) == 1
	})

	if got := endedRows(reporter, "integ-idle-1")[0].TerminatedBy; got != api.TerminatedByIdleTimeout {
		t.Errorf("ended row terminated_by = %q, want %q", got, api.TerminatedByIdleTimeout)
	}
	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after the idle close, got %d", mgr.ActiveCount())
	}
}

// TestIntegration_MaxSessionsBoundsOneBlock verifies that a block longer than
// MaxSessions provisions exactly the cap and leaves the rest unsettled, so a
// later pull picks one up as soon as a slot frees.
func TestIntegration_MaxSessionsBoundsOneBlock(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	const (
		maxSessions = 3
		entries     = 10
	)

	d, mgr, reporter := newIntegrationDispatcher(t, Config{
		Enabled:        true,
		MaxSessions:    maxSessions,
		DefaultTimeout: 30 * time.Second,
	})

	served := make([]api.NodeStateSession, 0, entries)
	for i := 0; i < entries; i++ {
		served = append(served, tcpSession(fmt.Sprintf("integ-cap-%d", i), host, port, time.Now().Add(30*time.Second)))
	}
	block := sessionsSnapshot(served...)

	d.Handle(context.Background(), block)

	if n := mgr.ActiveCount(); n != maxSessions {
		t.Fatalf("ActiveCount() = %d, want %d", n, maxSessions)
	}
	reporter.mu.Lock()
	reported := len(reporter.startedCalls)
	reporter.mu.Unlock()
	if reported != maxSessions {
		t.Fatalf("started rows = %d, want %d", reported, maxSessions)
	}

	// The seven rejected entries stayed unsettled: freeing a slot lets the next
	// pull provision the first of them.
	mgr.CloseSession("integ-cap-0", reasonDrained)
	d.Handle(context.Background(), block)

	if n := mgr.ActiveCount(); n != maxSessions {
		t.Errorf("ActiveCount() = %d after the retry, want %d", n, maxSessions)
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != maxSessions+1 {
		t.Fatalf("started rows = %d after the retry, want %d", len(reporter.startedCalls), maxSessions+1)
	}
	if got := reporter.startedCalls[maxSessions].SessionID; got != "integ-cap-3" {
		t.Errorf("retried session_id = %q, want %q", got, "integ-cap-3")
	}
}
