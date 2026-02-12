package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// RelaySession represents a relay session forwarding UDP packets between two peers.
type RelaySession struct {
	SessionID string
	PeerAAddr *net.UDPAddr
	PeerBAddr *net.UDPAddr

	conn   *net.UDPConn // shared relay socket
	logger *slog.Logger

	mu     sync.Mutex
	closed bool
}

// Forward sends data to the peer that is NOT the source.
// If srcAddr matches PeerA, forward to PeerB and vice versa.
// Packets from unknown sources are dropped.
func (s *RelaySession) Forward(srcAddr *net.UDPAddr, data []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	var dst *net.UDPAddr
	switch srcAddr.String() {
	case s.PeerAAddr.String():
		dst = s.PeerBAddr
	case s.PeerBAddr.String():
		dst = s.PeerAAddr
	default:
		s.logger.Debug("relay: dropping packet from unknown source",
			"component", "bridge",
			"session_id", s.SessionID,
			"source", srcAddr.String(),
		)
		return
	}

	if _, err := s.conn.WriteToUDP(data, dst); err != nil {
		s.logger.Error("relay: forward failed",
			"component", "bridge",
			"session_id", s.SessionID,
			"dst", dst.String(),
			"error", err,
		)
	}
}

// Close marks the session as closed. Idempotent.
func (s *RelaySession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.logger.Info("relay session closed",
		"component", "bridge",
		"session_id", s.SessionID,
	)
	return nil
}

// Relay manages a UDP listener and relay sessions.
type Relay struct {
	listenPort  int
	maxSessions int
	sessionTTL  time.Duration
	logger      *slog.Logger

	mu        sync.RWMutex
	conn      *net.UDPConn
	sessions  map[string]*RelaySession
	addrIndex map[string]*RelaySession // srcAddr.String() -> session for O(1) lookup
	timers    map[string]*time.Timer   // TTL timers per session
	active    bool
}

// NewRelay creates a new Relay.
func NewRelay(listenPort, maxSessions int, sessionTTL time.Duration, logger *slog.Logger) *Relay {
	return &Relay{
		listenPort:  listenPort,
		maxSessions: maxSessions,
		sessionTTL:  sessionTTL,
		logger:      logger.With("component", "bridge"),
		sessions:    make(map[string]*RelaySession),
		addrIndex:   make(map[string]*RelaySession),
		timers:      make(map[string]*time.Timer),
	}
}

// Start opens a UDP socket and begins the dispatch loop.
func (r *Relay) Start(ctx context.Context) error {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: r.listenPort}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("bridge: relay: listen on :%d: %w", r.listenPort, err)
	}

	r.mu.Lock()
	r.conn = conn
	r.active = true
	r.mu.Unlock()

	r.logger.Info("relay started",
		"listen_port", r.listenPort,
	)

	go r.dispatchLoop(ctx, conn)
	return nil
}

const relayBufSize = 65535

func (r *Relay) dispatchLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, relayBufSize)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // conn closed
		}

		r.mu.RLock()
		session, ok := r.addrIndex[srcAddr.String()]
		r.mu.RUnlock()

		if !ok {
			r.logger.Debug("relay: packet from unregistered address",
				"source", srcAddr.String(),
			)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		session.Forward(srcAddr, data)
	}
}

// AddSession creates and registers a new relay session.
func (r *Relay) AddSession(assignment api.RelaySessionAssignment) error {
	if assignment.SessionID == "" {
		return fmt.Errorf("bridge: relay: empty session ID")
	}

	peerA, err := net.ResolveUDPAddr("udp", assignment.PeerAEndpoint)
	if err != nil {
		return fmt.Errorf("bridge: relay: resolve peer A endpoint %q: %w", assignment.PeerAEndpoint, err)
	}
	peerB, err := net.ResolveUDPAddr("udp", assignment.PeerBEndpoint)
	if err != nil {
		return fmt.Errorf("bridge: relay: resolve peer B endpoint %q: %w", assignment.PeerBEndpoint, err)
	}
	if peerA.String() == peerB.String() {
		return fmt.Errorf("bridge: relay: peer A and peer B endpoints must differ: %s", peerA.String())
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sessions[assignment.SessionID]; exists {
		return fmt.Errorf("bridge: relay: duplicate session ID: %s", assignment.SessionID)
	}
	if len(r.sessions) >= r.maxSessions {
		return fmt.Errorf("bridge: relay: max sessions reached (%d)", r.maxSessions)
	}

	session := &RelaySession{
		SessionID: assignment.SessionID,
		PeerAAddr: peerA,
		PeerBAddr: peerB,
		conn:      r.conn,
		logger:    r.logger,
	}

	r.sessions[assignment.SessionID] = session
	r.addrIndex[peerA.String()] = session
	r.addrIndex[peerB.String()] = session

	// Start TTL timer.
	ttl := r.sessionTTL
	if !assignment.ExpiresAt.IsZero() {
		remaining := time.Until(assignment.ExpiresAt)
		if remaining > 0 && remaining < ttl {
			ttl = remaining
		}
	}
	timer := time.AfterFunc(ttl, func() {
		r.RemoveSession(assignment.SessionID)
	})
	r.timers[assignment.SessionID] = timer

	r.logger.Info("relay session added",
		"session_id", assignment.SessionID,
		"peer_a", peerA.String(),
		"peer_b", peerB.String(),
		"ttl", ttl.String(),
	)

	return nil
}

// RemoveSession closes and removes a session by ID. No-op if not found.
func (r *Relay) RemoveSession(sessionID string) {
	r.mu.Lock()
	session, ok := r.sessions[sessionID]
	if !ok {
		r.mu.Unlock()
		return
	}

	// Stop TTL timer.
	if timer, ok := r.timers[sessionID]; ok {
		timer.Stop()
		delete(r.timers, sessionID)
	}

	// Remove from addr index.
	delete(r.addrIndex, session.PeerAAddr.String())
	delete(r.addrIndex, session.PeerBAddr.String())
	delete(r.sessions, sessionID)
	r.mu.Unlock()

	session.Close()
}

// Stop closes all sessions and the UDP listener. Idempotent.
func (r *Relay) Stop() error {
	r.mu.Lock()
	if !r.active {
		r.mu.Unlock()
		return nil
	}
	r.active = false

	// Stop all timers.
	for _, timer := range r.timers {
		timer.Stop()
	}
	r.timers = make(map[string]*time.Timer)

	// Collect sessions to close.
	sessions := make([]*RelaySession, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.sessions = make(map[string]*RelaySession)
	r.addrIndex = make(map[string]*RelaySession)

	conn := r.conn
	r.conn = nil
	r.mu.Unlock()

	// Close all sessions.
	for _, s := range sessions {
		s.Close()
	}

	// Close UDP listener.
	if conn != nil {
		conn.Close()
	}

	r.logger.Info("relay stopped")
	return nil
}

// ActiveCount returns the number of active relay sessions.
func (r *Relay) ActiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// SessionIDs returns the IDs of all active sessions.
func (r *Relay) SessionIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	return ids
}

// ListenAddr returns the local address of the relay UDP listener.
// Returns nil if not started.
func (r *Relay) ListenAddr() net.Addr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.conn == nil {
		return nil
	}
	return r.conn.LocalAddr()
}
