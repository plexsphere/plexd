package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Session represents an active tunnel session with a local TCP listener
// that forwards connections to a target host through the mesh.
type Session struct {
	SessionID  string
	TargetHost string
	TargetPort int
	MeshIP     string

	listener  net.Listener
	cancel    context.CancelFunc
	startTime time.Time
	expiresAt time.Time

	mu     sync.Mutex
	conn   net.Conn // active connection (at most one)
	closed bool
	// copyDone is closed once the forwarding goroutines for the active
	// connection have returned and added their byte counts. It is nil while no
	// connection is being forwarded.
	copyDone chan struct{}

	bytesIn  atomic.Int64 // bytes forwarded client -> target (operator -> target)
	bytesOut atomic.Int64 // bytes forwarded target -> client (target -> operator)

	logger *slog.Logger
}

// drainTimeout bounds how long Close waits for the forwarding goroutines to
// finish after the connections are torn down. They return as soon as the closed
// sockets surface an error, so this only guards against a wedged conn.
const drainTimeout = 2 * time.Second

// NewSession creates a Session with the given parameters.
func NewSession(sessionID, targetHost string, targetPort int, meshIP string, expiresAt time.Time, logger *slog.Logger) *Session {
	return &Session{
		SessionID:  sessionID,
		TargetHost: targetHost,
		TargetPort: targetPort,
		MeshIP:     meshIP,
		expiresAt:  expiresAt,
		startTime:  time.Now(),
		logger:     logger.With("session_id", sessionID),
	}
}

// Start opens a TCP listener bound to the mesh IP and begins accepting connections.
func (s *Session) Start(ctx context.Context) (string, error) {
	ctx, s.cancel = context.WithCancel(ctx)

	addr := net.JoinHostPort(s.MeshIP, "0")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("tunnel: listen on %s: %w", addr, err)
	}
	s.listener = ln

	s.logger.Info("session started",
		"listen_addr", ln.Addr().String(),
		"target", net.JoinHostPort(s.TargetHost, strconv.Itoa(s.TargetPort)),
	)

	go s.acceptLoop(ctx)

	return ln.Addr().String(), nil
}

func (s *Session) acceptLoop(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // Listener was closed.
		}

		if !s.tryAccept(conn) {
			continue
		}

		s.forward(ctx, conn)
	}
}

// tryAccept checks whether a new connection can be accepted (only one active
// connection at a time). Returns true if accepted, false if rejected (conn is
// closed on rejection).
func (s *Session) tryAccept(conn net.Conn) bool {
	s.mu.Lock()
	busy := s.conn != nil
	s.mu.Unlock()

	if busy {
		conn.Close()
		s.logger.Debug("rejected connection: session already has active connection")
		return false
	}
	return true
}

func (s *Session) forward(ctx context.Context, clientConn net.Conn) {
	targetAddr := net.JoinHostPort(s.TargetHost, strconv.Itoa(s.TargetPort))
	var d net.Dialer
	targetConn, err := d.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		clientConn.Close()
		s.logger.Error("failed to dial target", "target", targetAddr, "error", err)
		return
	}

	// copyDone lets Close wait for the final counter updates before a caller
	// reads Counters().
	done := make(chan struct{})
	s.mu.Lock()
	s.conn = clientConn
	s.copyDone = done
	s.mu.Unlock()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			clientConn.Close()
			targetConn.Close()
			s.mu.Lock()
			s.conn = nil
			s.mu.Unlock()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// io.Copy already returns the forwarded byte count, so the counters are
	// settled from its result rather than from a wrapper around the destination.
	// A wrapper would hide the *net.TCPConn destination from TCPConn.WriteTo and
	// cost the connection its splice(2) fast path, adding a userspace copy and a
	// syscall pair per 32 KiB chunk in both directions.
	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, clientConn)
		s.bytesIn.Add(n)
		cleanup()
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, targetConn)
		s.bytesOut.Add(n)
		cleanup()
	}()

	wg.Wait()

	s.mu.Lock()
	s.copyDone = nil
	s.mu.Unlock()
	close(done)
}

// Close shuts down the session idempotently.
func (s *Session) Close() error {
	conn, done, alreadyClosed := s.markClosed()
	if alreadyClosed {
		return nil
	}

	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if conn != nil {
		conn.Close()
	}

	// Wait for the forwarding goroutines to add their final byte counts, so a
	// Counters() read after Close reflects everything that was forwarded.
	if done != nil {
		select {
		case <-done:
		case <-time.After(drainTimeout):
			s.logger.Warn("timed out waiting for forwarding to drain; byte counters may be short")
		}
	}

	s.logger.Info("session closed", "duration", time.Since(s.startTime).String())
	return nil
}

// markClosed atomically marks the session as closed and returns the active
// connection and its forwarding-done channel (both nil when nothing is being
// forwarded) along with whether the session was already closed.
func (s *Session) markClosed() (activeConn net.Conn, copyDone chan struct{}, alreadyClosed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, true
	}
	s.closed = true
	return s.conn, s.copyDone, false
}

// Counters returns the bytes forwarded in each direction: in is client -> target
// (operator to target), out is target -> client (target to operator).
func (s *Session) Counters() (in, out int64) {
	return s.bytesIn.Load(), s.bytesOut.Load()
}

// ListenAddr returns the listener address or empty string if not started.
func (s *Session) ListenAddr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}
