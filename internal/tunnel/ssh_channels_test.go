package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// mockNewChannel implements ssh.NewChannel for testing.
type mockNewChannel struct {
	channelType  string
	extraData    []byte
	acceptCh     *mockChannel
	acceptErr    error
	rejectCalled bool
	rejectReason ssh.RejectionReason
	rejectMsg    string
	mu           sync.Mutex
}

func (m *mockNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	if m.acceptErr != nil {
		return nil, nil, m.acceptErr
	}
	reqs := make(chan *ssh.Request)
	close(reqs)
	return m.acceptCh, reqs, nil
}

func (m *mockNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejectCalled = true
	m.rejectReason = reason
	m.rejectMsg = message
	return nil
}

func (m *mockNewChannel) ChannelType() string { return m.channelType }
func (m *mockNewChannel) ExtraData() []byte    { return m.extraData }

// mockChannel implements ssh.Channel backed by a net.Conn from net.Pipe.
type mockChannel struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (m *mockChannel) CloseWrite() error { return nil }
func (m *mockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}
func (m *mockChannel) Stderr() io.ReadWriter { return nil }

func (m *mockChannel) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	return m.Conn.Close()
}

func newMockChannelPair() (*mockChannel, net.Conn) {
	server, client := net.Pipe()
	ch := &mockChannel{Conn: server}
	return ch, client
}

func TestHandleDirectTCPIP_Success(t *testing.T) {
	// Start a local TCP echo server.
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	payload := directTCPIPPayload{
		DestHost:   host,
		DestPort:   uint32(port),
		OriginHost: "10.0.0.1",
		OriginPort: 12345,
	}
	data := ssh.Marshal(&payload)

	ch, clientConn := newMockChannelPair()
	defer clientConn.Close()

	mock := &mockNewChannel{
		channelType: "direct-tcpip",
		extraData:   data,
		acceptCh:    ch,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDirectTCPIP(context.Background(), mock, slog.Default())
	}()

	// Write data through the mock channel and verify echo.
	msg := "hello direct-tcpip"
	if _, err := clientConn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	buf := make([]byte, len(msg))
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), msg)
	}

	// Close the client side to allow handleDirectTCPIP to finish.
	clientConn.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleDirectTCPIP did not return within timeout")
	}
}

func TestHandleDirectTCPIP_DialFailure(t *testing.T) {
	// Point to a port that nothing listens on.
	payload := directTCPIPPayload{
		DestHost:   "127.0.0.1",
		DestPort:   1,
		OriginHost: "10.0.0.1",
		OriginPort: 12345,
	}
	data := ssh.Marshal(&payload)

	ch, clientConn := newMockChannelPair()
	defer clientConn.Close()
	defer ch.Close()

	mock := &mockNewChannel{
		channelType: "direct-tcpip",
		extraData:   data,
		acceptCh:    ch,
	}

	handleDirectTCPIP(context.Background(), mock, slog.Default())

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if !mock.rejectCalled {
		t.Fatal("expected Reject to be called on dial failure")
	}
	if mock.rejectReason != ssh.ConnectionFailed {
		t.Errorf("reject reason = %v, want %v", mock.rejectReason, ssh.ConnectionFailed)
	}
}

func TestHandleDirectTCPIP_InvalidPayload(t *testing.T) {
	mock := &mockNewChannel{
		channelType: "direct-tcpip",
		extraData:   []byte("garbage data that is not valid ssh wire format"),
	}

	handleDirectTCPIP(context.Background(), mock, slog.Default())

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if !mock.rejectCalled {
		t.Fatal("expected Reject to be called on invalid payload")
	}
	if mock.rejectReason != ssh.ConnectionFailed {
		t.Errorf("reject reason = %v, want %v", mock.rejectReason, ssh.ConnectionFailed)
	}
}

func TestDirectTCPIPPayload_Marshal(t *testing.T) {
	original := directTCPIPPayload{
		DestHost:   "127.0.0.1",
		DestPort:   8080,
		OriginHost: "10.0.0.1",
		OriginPort: 12345,
	}

	data := ssh.Marshal(&original)

	var decoded directTCPIPPayload
	if err := ssh.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if decoded.DestHost != original.DestHost {
		t.Errorf("DestHost = %q, want %q", decoded.DestHost, original.DestHost)
	}
	if decoded.DestPort != original.DestPort {
		t.Errorf("DestPort = %d, want %d", decoded.DestPort, original.DestPort)
	}
	if decoded.OriginHost != original.OriginHost {
		t.Errorf("OriginHost = %q, want %q", decoded.OriginHost, original.OriginHost)
	}
	if decoded.OriginPort != original.OriginPort {
		t.Errorf("OriginPort = %d, want %d", decoded.OriginPort, original.OriginPort)
	}
}
