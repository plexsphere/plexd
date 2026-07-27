package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ErrTunnelingDisabled is returned by CreateSession when tunneling is switched
// off in the node's configuration. It is a sentinel because that refusal is
// permanent for the life of the process, and a caller matching it with
// errors.Is can settle the session instead of retrying it on every pull.
var ErrTunnelingDisabled = errors.New("tunnel: tunneling is disabled")

// maxIdleTimeoutSeconds bounds the idle window a session entry may carry. It is
// far above any usable window and only exists to keep the seconds-to-Duration
// multiplication from overflowing into a negative value.
const maxIdleTimeoutSeconds = 24 * 60 * 60

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

// CreateSession creates and starts a tunnel session for one entry of the pull's
// sessions block and returns the bound listener address. Only tcp-kind entries
// are provisionable: the session dispatcher filters the block before calling in,
// and the kind guard here keeps the manager safe to call on its own.
func (m *SessionManager) CreateSession(ctx context.Context, sess api.NodeStateSession) (string, error) {
	if !m.cfg.Enabled {
		return "", ErrTunnelingDisabled
	}

	if sess.Kind != api.SessionKindTCP || sess.Target.TCP == nil {
		return "", fmt.Errorf("tunnel: session kind is not provisionable")
	}

	if sess.SessionID == "" || sess.Target.TCP.Host == "" || sess.Target.TCP.Port <= 0 || sess.Target.TCP.Port > 65535 {
		return "", fmt.Errorf("tunnel: invalid session setup: session_id, target_host, and valid target_port (1-65535) are required")
	}

	// A negative idle window, or one large enough to overflow the multiplication
	// into a negative Duration, would leave idleTimeout <= 0 — indistinguishable
	// from "no idle window" and silently disabling the enforcement that closes an
	// abandoned forward.
	if sess.IdleTimeoutSeconds < 0 || sess.IdleTimeoutSeconds > maxIdleTimeoutSeconds {
		return "", fmt.Errorf("tunnel: invalid idle_timeout_seconds: %d", sess.IdleTimeoutSeconds)
	}

	// A session listener carries no authentication of its own, so the mesh
	// address it binds is the whole of its reachability boundary. The address is
	// copied verbatim from the control plane's registration response into
	// identity.json, so it is parsed here rather than trusted: an empty value,
	// something that is not an address at all, or an unspecified one (0.0.0.0,
	// ::) would each have net.Listen bind every unicast address on the host and
	// publish an unauthenticated forward to an internal service on the node's
	// public and LAN interfaces. A multicast one binds a group address instead
	// of the node's own, which is not a reachability boundary either.
	//
	// The guard runs on the address net.Listen would actually bind, not on the
	// parsed one: netip.Addr.IsUnspecified matches exactly 0.0.0.0 and ::, while
	// the net package normalises 4-byte and 16-byte forms and splits the zone
	// off, so it binds the same dual-stack wildcard for "::ffff:0.0.0.0" and
	// "::%eth0". Validating the parsed form would classify those two differently
	// from the bind they produce. WithZone must precede Unmap — a zoned address
	// is never Is4In6, so Unmap alone is a no-op on "::ffff:0.0.0.0%eth0".
	meshAddr, err := netip.ParseAddr(m.meshIP)
	bindAddr := meshAddr.WithZone("").Unmap()
	if err != nil || bindAddr.IsUnspecified() || bindAddr.IsMulticast() {
		return "", fmt.Errorf("tunnel: mesh IP %q is not a bindable unicast address; refusing to bind a session listener", m.meshIP)
	}

	now := time.Now()
	if sess.ExpiresAt.Before(now) {
		return "", fmt.Errorf("tunnel: session already expired")
	}

	// Cap ExpiresAt at DefaultTimeout from now. The cap is local policy and the
	// control plane does not learn it from the pull, so a truncation is logged:
	// the session then ends — with a ttl_expired session_ended row — while its
	// entry still stands in the block, and it is not provisioned a second time.
	maxExpiry := now.Add(m.cfg.DefaultTimeout)
	expiresAt := sess.ExpiresAt
	if expiresAt.After(maxExpiry) {
		m.logger.Warn("session expiry capped below the granted expires_at; the session will end early",
			"session_id", sess.SessionID,
			"granted_expires_at", sess.ExpiresAt,
			"capped_expires_at", maxExpiry,
			"default_timeout", m.cfg.DefaultTimeout.String(),
		)
		expiresAt = maxExpiry
	}

	m.mu.Lock()
	if _, exists := m.sessions[sess.SessionID]; exists {
		m.mu.Unlock()
		return "", fmt.Errorf("tunnel: duplicate session ID: %s", sess.SessionID)
	}
	if len(m.sessions) >= m.cfg.MaxSessions {
		m.mu.Unlock()
		return "", fmt.Errorf("tunnel: max sessions reached (%d)", m.cfg.MaxSessions)
	}

	session := NewSession(sess.SessionID, sess.Target.TCP.Host, sess.Target.TCP.Port, m.meshIP, expiresAt, m.logger)

	// Both are set before Start because it arms the idle monitor, and because
	// forward decides per connection whether to stamp activity — the first
	// connection can arrive as soon as the listener is up.
	session.idleTimeout = time.Duration(sess.IdleTimeoutSeconds) * time.Second
	// Closed for this session, not just for its id, for the same reason as the
	// expiry timer below: the monitor commits to the close once its window has
	// fired, so a cancellation racing that decision must not let it take down the
	// successor of the session it was watching.
	session.onIdle = func() { m.closeSession(sess.SessionID, reasonIdle, session) }

	addr, err := session.Start(ctx)
	if err != nil {
		m.mu.Unlock()
		return "", err
	}

	m.sessions[sess.SessionID] = session
	m.mu.Unlock()

	// Start expiry timer. It is armed for this session, not just for its id: the
	// dispatcher re-provisions a re-issued id by design, so a timer left over
	// from an earlier session must not close the one that took its place — that
	// close would strand a session the control plane still believes is live,
	// with no pull able to rebuild it while its entry stands.
	ttl := time.Until(expiresAt)
	if ttl > 0 {
		time.AfterFunc(ttl, func() {
			m.closeSession(sess.SessionID, reasonExpired, session)
		})
	}

	m.logger.Info("session created",
		"session_id", sess.SessionID,
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
	return m.closeSession(sessionID, reason, nil)
}

// closeSession closes and removes a session by ID. A non-nil want closes the id
// only while it still holds exactly that session, so a caller holding a stale
// reference cannot close the successor of the session it meant to close.
func (m *SessionManager) closeSession(sessionID, reason string, want *Session) *ClosedSessionInfo {
	session := m.removeSession(sessionID, want)
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
			m.CloseSession(id, reasonShutdown)
		}(id)
	}
	wg.Wait()

	m.logger.Info("all tunnel sessions closed")
}

// removeSession removes and returns the session for the given ID, or nil if not
// found. A non-nil want also requires the live session to be exactly that one.
func (m *SessionManager) removeSession(sessionID string, want *Session) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[sessionID]
	if !ok || (want != nil && session != want) {
		return nil
	}
	delete(m.sessions, sessionID)
	return session
}

// ActiveSessions returns the live sessions as session id to capped local
// expiry, in a fresh map taken under the lock. The session dispatcher's teardown
// pass consumes it: an id the pull's sessions block no longer carries is closed,
// and the expiry is what tells a revocation apart from a hard expiry — both
// reach the node as the same absence.
func (m *SessionManager) ActiveSessions() map[string]time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := make(map[string]time.Time, len(m.sessions))
	for id, session := range m.sessions {
		active[id] = session.expiresAt
	}
	return active
}

// ActiveCount returns the number of active sessions.
func (m *SessionManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
