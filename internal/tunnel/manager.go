package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// SessionManager manages the lifecycle of tunnel sessions.
type SessionManager struct {
	cfg    Config
	meshIP string
	logger *slog.Logger

	mu       sync.Mutex
	sessions map[string]*Session
	onClosed func(sessionID, reason string, info *ClosedSessionInfo)
}

// NewSessionManager creates a new SessionManager with default config applied.
func NewSessionManager(cfg Config, meshIP string, logger *slog.Logger) *SessionManager {
	cfg.ApplyDefaults()
	return &SessionManager{
		cfg:      cfg,
		meshIP:   meshIP,
		logger:   logger.With("component", "tunnel"),
		sessions: make(map[string]*Session),
	}
}

// CreateSession creates and starts a new tunnel session.
func (m *SessionManager) CreateSession(ctx context.Context, setup api.SSHSessionSetup) (string, error) {
	if !m.cfg.Enabled {
		return "", fmt.Errorf("tunnel: tunneling is disabled")
	}

	if setup.SessionID == "" || setup.TargetHost == "" || setup.TargetPort <= 0 || setup.TargetPort > 65535 {
		return "", fmt.Errorf("tunnel: invalid session setup: session_id, target_host, and valid target_port (1-65535) are required")
	}

	now := time.Now()
	if setup.ExpiresAt.Before(now) {
		return "", fmt.Errorf("tunnel: session already expired")
	}

	// Cap ExpiresAt at DefaultTimeout from now.
	maxExpiry := now.Add(m.cfg.DefaultTimeout)
	expiresAt := setup.ExpiresAt
	if expiresAt.After(maxExpiry) {
		expiresAt = maxExpiry
	}

	m.mu.Lock()
	if _, exists := m.sessions[setup.SessionID]; exists {
		m.mu.Unlock()
		return "", fmt.Errorf("tunnel: duplicate session ID: %s", setup.SessionID)
	}
	if len(m.sessions) >= m.cfg.MaxSessions {
		m.mu.Unlock()
		return "", fmt.Errorf("tunnel: max sessions reached (%d)", m.cfg.MaxSessions)
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := NewSession(setup.SessionID, setup.TargetHost, setup.TargetPort, m.meshIP, expiresAt, m.logger)
	session.cancel = cancel

	addr, err := session.Start(sessionCtx)
	if err != nil {
		cancel()
		m.mu.Unlock()
		return "", err
	}

	m.sessions[setup.SessionID] = session
	m.mu.Unlock()

	// Start expiry timer.
	ttl := time.Until(expiresAt)
	if ttl > 0 {
		time.AfterFunc(ttl, func() {
			m.CloseSession(setup.SessionID, "expired")
		})
	}

	m.logger.Info("session created",
		"session_id", setup.SessionID,
		"listen_addr", addr,
		"expires_at", expiresAt.String(),
	)

	return addr, nil
}

// ClosedSessionInfo contains metadata about a session that was closed.
type ClosedSessionInfo struct {
	Duration   time.Duration
	TargetHost string
	TargetPort int
	BytesIn    int64
	BytesOut   int64
}

// SetOnClosed registers a callback invoked after a session is successfully
// closed and removed, for every close reason including "shutdown". The callback
// carries the close reason and the session's final metadata, and is the single
// path by which a session_ended activity row — TTL expiry, operator revoke, and
// node shutdown alike — reaches the control plane. Because it is the only
// carrier of the session's byte counters, skipping it on shutdown would leave
// the control plane's audit record for every live session without bytes_in,
// bytes_out, or terminated_by.
func (m *SessionManager) SetOnClosed(fn func(sessionID, reason string, info *ClosedSessionInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onClosed = fn
}

// CloseSession closes and removes a session by ID.
// Returns session metadata if the session existed, or nil if not found.
func (m *SessionManager) CloseSession(sessionID, reason string) *ClosedSessionInfo {
	session := m.removeSession(sessionID)
	if session == nil {
		m.logger.Debug("session not found for close", "session_id", sessionID)
		return nil
	}

	session.Close()
	duration := time.Since(session.startTime)
	bytesIn, bytesOut := session.Counters()
	info := &ClosedSessionInfo{
		Duration:   duration,
		TargetHost: session.TargetHost,
		TargetPort: session.TargetPort,
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
	}
	m.logger.Info("session closed",
		"session_id", sessionID,
		"reason", reason,
		"duration", duration.String(),
	)

	// Report every successful close. Read the callback under the lock but invoke
	// it outside so we never hold the lock across the callback. Double-close
	// fires nothing here because removeSession returns nil on the second call.
	m.mu.Lock()
	onClosed := m.onClosed
	m.mu.Unlock()
	if onClosed != nil {
		onClosed(sessionID, reason, info)
	}

	return info
}

// Shutdown closes all active sessions, reporting each one through the on-closed
// callback with reason "shutdown" so its byte counters and a plexd_close
// terminated_by reach the control plane before the node goes offline.
//
// The on-closed callback performs a blocking, bounded report, so the sessions
// are closed concurrently: total shutdown latency is then the single slowest
// report rather than their sum. Closing serially instead would let a slow or
// unreachable control plane stretch teardown to MaxSessions times the per-report
// bound, overrunning a typical orchestrator termination grace period.
func (m *SessionManager) Shutdown() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			m.CloseSession(id, "shutdown")
		}(id)
	}
	wg.Wait()

	m.logger.Info("all tunnel sessions closed")
}

// removeSession removes and returns the session for the given ID, or nil if not found.
func (m *SessionManager) removeSession(sessionID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[sessionID]
	if !ok {
		return nil
	}
	delete(m.sessions, sessionID)
	return session
}

// ActiveCount returns the number of active sessions.
func (m *SessionManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
