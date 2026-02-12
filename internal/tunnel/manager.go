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
	Duration time.Duration
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
	m.logger.Info("session closed",
		"session_id", sessionID,
		"reason", reason,
		"duration", duration.String(),
	)
	return &ClosedSessionInfo{Duration: duration}
}

// Shutdown closes all active sessions. This is a local cleanup operation
// during node shutdown and does not report individual close events to the
// control plane — the control plane infers session loss from the node going
// offline (heartbeat timeout).
func (m *SessionManager) Shutdown() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	for _, id := range ids {
		m.CloseSession(id, "shutdown")
	}

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
