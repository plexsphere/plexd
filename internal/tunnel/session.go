package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
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

	logger *slog.Logger
}

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

	s.mu.Lock()
	s.conn = clientConn
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

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientConn)
		cleanup()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		cleanup()
	}()

	wg.Wait()
}

// Close shuts down the session idempotently.
func (s *Session) Close() error {
	conn, alreadyClosed := s.markClosed()
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

	s.logger.Info("session closed", "duration", time.Since(s.startTime).String())
	return nil
}

// markClosed atomically marks the session as closed and returns the active
// connection (if any) along with whether the session was already closed.
func (s *Session) markClosed() (activeConn net.Conn, alreadyClosed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, true
	}
	s.closed = true
	return s.conn, false
}

// ListenAddr returns the listener address or empty string if not started.
func (s *Session) ListenAddr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}
