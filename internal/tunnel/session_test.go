package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSession_BindsToMeshIP(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	session := NewSession("test-bind", "127.0.0.1", 9999, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("expected listener addr to start with 127.0.0.1:, got %s", addr)
	}
}

func TestSession_ForwardBidirectional(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	ctx := context.Background()
	logger := slog.Default()

	session := NewSession("test-fwd", host, port, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	msg := "hello tunnel"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("expected %q, got %q", msg, string(buf))
	}
}

func TestSession_CountsBytesBothDirections(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	ctx := context.Background()
	logger := slog.Default()

	session := NewSession("test-counters", host, port, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	msg := "count these bytes"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	// The echo server writes back exactly what it received. Close drains the
	// forwarding goroutines, so the counters are complete once it returns —
	// this is exactly what CloseSession relies on before it reports the
	// session_ended row.
	if err := session.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	in, out := session.Counters()
	if in != int64(len(msg)) {
		t.Errorf("bytesIn = %d, want %d", in, len(msg))
	}
	if out != int64(len(msg)) {
		t.Errorf("bytesOut = %d, want %d", out, len(msg))
	}
}

func TestSession_CountersSettleBeforeCloseReturns(t *testing.T) {
	// After a full round-trip both forwarding goroutines are parked in io.Copy,
	// each having copied len(msg) bytes but not yet run the trailing counter
	// add. Close must not return until those adds land, otherwise a Counters()
	// read right after Close — exactly what CloseSession does before it reports
	// the session_ended row — races the netpoller waking the goroutines and
	// undercounts the session. Without the drain this loop observes a short
	// count within a few iterations; with it, every iteration is exact.
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	msg := []byte("count these bytes")
	for i := range 50 {
		session := NewSession("test-drain", host, port, "127.0.0.1", time.Now().Add(5*time.Minute), slog.Default())

		addr, err := session.Start(context.Background())
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("Dial() error: %v", err)
		}

		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("Write() error: %v", err)
		}
		buf := make([]byte, len(msg))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("ReadFull() error: %v", err)
		}

		if err := session.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
		conn.Close()

		if in, out := session.Counters(); in != int64(len(msg)) || out != int64(len(msg)) {
			t.Fatalf("iteration %d: counters after Close() = (%d, %d), want (%d, %d)",
				i, in, out, len(msg), len(msg))
		}
	}
}

func TestSession_DialFailureClosesClient(t *testing.T) {
	// Use a port that nothing listens on.
	ctx := context.Background()
	logger := slog.Default()

	session := NewSession("test-dial-fail", "127.0.0.1", 1, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	// The session should close the client connection when dial to target fails.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected read error after dial failure, got nil")
	}
}

func TestSession_SingleConnection(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	ctx := context.Background()
	logger := slog.Default()

	session := NewSession("test-single", host, port, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// First connection should succeed.
	conn1, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() first connection error: %v", err)
	}
	defer conn1.Close()

	// Verify first connection is working.
	if _, err := conn1.Write([]byte("x")); err != nil {
		t.Fatalf("Write() first connection error: %v", err)
	}
	_ = conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn1, buf); err != nil {
		t.Fatalf("ReadFull() first connection error: %v", err)
	}

	// Second connection should be closed immediately.
	conn2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() second connection error: %v", err)
	}
	defer conn2.Close()

	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn2.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected second connection to be closed, but read succeeded")
	}
}

func TestSession_ContextCancellation(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.Default()

	session := NewSession("test-cancel", host, port, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	// Cancel the context.
	cancel()

	// Give some time for the cancellation to propagate.
	time.Sleep(100 * time.Millisecond)

	// The listener should be closed; new connections should fail.
	_, err = net.DialTimeout("tcp", addr, 1*time.Second)
	if err == nil {
		t.Fatal("expected dial to fail after context cancellation")
	}
}

func TestSession_DialRespectsContextCancellation(t *testing.T) {
	// Use an unreachable address (RFC 5737 TEST-NET) to force a slow dial.
	// With DialContext, cancelling the context should abort the dial promptly.
	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.Default()

	session := NewSession("test-dial-ctx", "192.0.2.1", 9999, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Connect a client which will trigger forward() → DialContext to 192.0.2.1 (unreachable).
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() to tunnel listener error: %v", err)
	}
	defer conn.Close()

	// Give forward() a moment to start dialing.
	time.Sleep(50 * time.Millisecond)

	// Cancel the context — DialContext should abort quickly.
	cancel()

	// The client connection should be closed because DialContext failed.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected read error after context cancellation during dial")
	}
}

func TestSession_CloseIsIdempotent(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	session := NewSession("test-idempotent", "127.0.0.1", 9999, "127.0.0.1", time.Now().Add(5*time.Minute), logger)

	_, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}
}

func TestSession_StartStampsActivity(t *testing.T) {
	logger := slog.Default()

	session := NewSession("test-activity-bind", "127.0.0.1", 9999, "127.0.0.1", time.Now().Add(5*time.Minute), logger)
	t.Cleanup(func() { session.Close() })

	if got := session.lastActive.Load(); got != 0 {
		t.Errorf("activity stamp before Start() = %d, want 0", got)
	}

	before := time.Now()
	if _, err := session.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// A listener no connection ever reaches must still age against the bind
	// rather than against the start of the process.
	if got := session.IdleFor(); got < 0 || got > time.Since(before)+time.Second {
		t.Errorf("IdleFor() after Start() = %v, want no more than the time since the bind", got)
	}
}

func TestSession_IdleWindowStampsActivityBothDirections(t *testing.T) {
	// The target is driven by hand rather than by startEchoServer so that each
	// direction of the forwarded byte flow can be exercised on its own.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := mustAtoi(t, portStr)

	session := NewSession("test-activity-flow", host, port, "127.0.0.1", time.Now().Add(5*time.Minute), slog.Default())
	// Arm the idle window, the pair the manager always sets together. A minute is
	// far longer than this test runs, so what is asserted here is the stamping,
	// not the monitor acting on it.
	session.idleTimeout = time.Minute
	session.onIdle = func() { t.Error("idle monitor fired while bytes were flowing") }
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	client, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer client.Close()

	var target net.Conn
	select {
	case target = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("target never saw the forwarded connection")
	}
	defer target.Close()

	msg := []byte("byte flow")
	buf := make([]byte, len(msg))

	// client -> target
	bind := time.Duration(session.lastActive.Load())
	settleClockPast(t, bind)
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("client Write() error: %v", err)
	}
	_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(target, buf); err != nil {
		t.Fatalf("target ReadFull() error: %v", err)
	}
	inbound := waitForActivityAfter(t, session, bind)

	// target -> client
	settleClockPast(t, inbound)
	if _, err := target.Write(msg); err != nil {
		t.Fatalf("target Write() error: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client ReadFull() error: %v", err)
	}
	waitForActivityAfter(t, session, inbound)
}

func TestSession_WithoutIdleWindowActivityStaysAtBind(t *testing.T) {
	// Without an idle window the sources stay unwrapped so io.Copy keeps its
	// splice(2) fast path, which means byte flow does not stamp activity: the
	// bind timestamp is all a session without a window ever reports.
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	session := NewSession("test-activity-unarmed", host, port, "127.0.0.1", time.Now().Add(5*time.Minute), slog.Default())
	t.Cleanup(func() { session.Close() })

	addr, err := session.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	bind := time.Duration(session.lastActive.Load())

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	msg := []byte("no stamping here")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	if got := time.Duration(session.lastActive.Load()); got != bind {
		t.Errorf("activity stamp after forwarding = %v, want the bind stamp %v", got, bind)
	}
}

// settleClockPast waits until the monotonic reading a stamp is taken from has
// moved past base, so the next chunk forwarded is certain to stamp a strictly
// greater value.
//
// Windows advances that clock in timer ticks of roughly 15ms rather than
// continuously, so two chunks forwarded inside one tick carry the same reading
// and a strict comparison against the earlier one can never succeed however
// long it is polled for. The granularity is irrelevant to the idle window
// itself, which is armed in minutes.
func settleClockPast(t *testing.T, base time.Duration) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Since(processStart) <= base {
		if time.Now().After(deadline) {
			t.Fatalf("monotonic clock did not advance past %v within 2s", base)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitForActivityAfter polls the session's activity stamp until it moves past
// base, so the assertion does not race the forwarding goroutine storing it. The
// stamp is a monotonic offset from processStart, not a wall-clock time.
func waitForActivityAfter(t *testing.T, s *Session, base time.Duration) time.Duration {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := time.Duration(s.lastActive.Load()); got > base {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("activity stamp %v did not advance past %v within 2s", time.Duration(s.lastActive.Load()), base)
	return 0
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("mustAtoi(%q): %v", s, err)
	}
	return n
}
