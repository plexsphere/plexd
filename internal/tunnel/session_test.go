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
				io.Copy(conn, conn)
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
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("expected %q, got %q", msg, string(buf))
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
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
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
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
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

	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
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
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
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

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("mustAtoi(%q): %v", s, err)
	}
	return n
}
