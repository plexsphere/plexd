package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestIntegration_SSHTunnelLifecycle verifies the full SSH tunnel lifecycle:
// 1. Start SSH server with generated host key and mock JWT verifier
// 2. Connect real SSH client
// 3. Open direct-tcpip channel to local echo server
// 4. Verify bidirectional data flow through the SSH channel
// 5. Close channel and disconnect
// 6. Verify session cleanup (goleak handles goroutine leak detection via TestMain)
func TestIntegration_SSHTunnelLifecycle(t *testing.T) {
	// Start echo server as the tunnel target.
	echoAddr := startEchoServer(t)

	// Generate host key.
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	// Create SSH server with mock JWT verifier (always accepts).
	srv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		MaxSessions: 5,
		IdleTimeout: 5 * time.Minute,
	}, hostKey, &mockJWTVerifier{err: nil}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

	// Generate client key and connect.
	clientKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() for client error: %v", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            "test-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	defer client.Close()

	// Parse echo server address for direct-tcpip channel.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := mustAtoi(t, echoPortStr)

	// Open direct-tcpip channel to echo server.
	// The SSH library's Dial method opens a direct-tcpip channel.
	channel, err := client.Dial("tcp", net.JoinHostPort(echoHost, echoPortStr))
	if err != nil {
		t.Fatalf("client.Dial() for direct-tcpip error: %v", err)
	}
	defer channel.Close()

	// Verify bidirectional data flow.
	msg := "hello through SSH tunnel"
	if _, err := channel.Write([]byte(msg)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	buf := make([]byte, len(msg))
	_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(channel, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), msg)
	}

	// Send a second message to verify the channel stays open.
	msg2 := "second message"
	if _, err := channel.Write([]byte(msg2)); err != nil {
		t.Fatalf("Write() second message error: %v", err)
	}

	buf2 := make([]byte, len(msg2))
	_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(channel, buf2); err != nil {
		t.Fatalf("ReadFull() second message error: %v", err)
	}

	if string(buf2) != msg2 {
		t.Errorf("second echo mismatch: got %q, want %q", string(buf2), msg2)
	}

	// Close channel explicitly.
	channel.Close()

	// Close client connection.
	client.Close()

	// Verify server can still accept new connections after client disconnects.
	client2, err := ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err != nil {
		t.Fatalf("second ssh.Dial() error: %v", err)
	}
	client2.Close()

	// Note: use the echoPort variable to suppress unused warning if needed
	_ = echoPort
}

// TestIntegration_SSHTunnelDirectTCPIP_DialFailure verifies that a direct-tcpip
// channel request to an unreachable target is rejected properly.
func TestIntegration_SSHTunnelDirectTCPIP_DialFailure(t *testing.T) {
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
		User:            "test-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	defer client.Close()

	// Try to open direct-tcpip to a port that nothing listens on.
	// Port 1 is typically not listening.
	_, err = client.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("client.Dial() to unreachable target should have failed")
	}

	// The SSH session itself should still be alive.
	// Open another channel to the unreachable target to verify session is alive
	// (it should fail again, but the point is the session didn't die).
	_, err = client.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("second client.Dial() to unreachable target should have failed")
	}
}

// TestIntegration_SSHTunnelMultipleChannels verifies that multiple direct-tcpip
// channels can be opened concurrently on the same SSH connection.
func TestIntegration_SSHTunnelMultipleChannels(t *testing.T) {
	echoAddr := startEchoServer(t)

	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	srv := NewSSHServer(SSHServerConfig{
		ListenAddr:  "127.0.0.1:0",
		MaxSessions: 5,
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
		User:            "test-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", srv.Addr(), clientCfg)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	defer client.Close()

	// Open 3 channels concurrently.
	const numChannels = 3
	channels := make([]net.Conn, numChannels)
	for i := 0; i < numChannels; i++ {
		ch, err := client.Dial("tcp", echoAddr)
		if err != nil {
			t.Fatalf("client.Dial() channel %d error: %v", i, err)
		}
		channels[i] = ch
	}

	// Send and receive on all channels.
	for i, ch := range channels {
		msg := fmt.Sprintf("channel-%d", i)
		if _, err := ch.Write([]byte(msg)); err != nil {
			t.Fatalf("Write() channel %d error: %v", i, err)
		}

		buf := make([]byte, len(msg))
		_ = ch.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(ch, buf); err != nil {
			t.Fatalf("ReadFull() channel %d error: %v", i, err)
		}

		if string(buf) != msg {
			t.Errorf("channel %d echo mismatch: got %q, want %q", i, string(buf), msg)
		}
	}

	// Close all channels.
	for _, ch := range channels {
		ch.Close()
	}
}
