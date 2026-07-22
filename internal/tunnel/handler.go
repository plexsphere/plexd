package tunnel

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/plexsphere/plexd/internal/api"
)

// SessionActivityReporter reports the tcp-phase session_started row to the
// control plane once the listener is up. The matching session_ended row is
// emitted from the SessionManager's on-closed callback, not through here.
type SessionActivityReporter interface {
	ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int)
}

// HandleSSHSessionSetup returns an api.EventHandler for ssh_session_setup events.
// It parses the SSE payload, creates a tunnel session via the SessionManager,
// and reports the session_started row via the SessionActivityReporter.
func HandleSSHSessionSetup(mgr *SessionManager, reporter SessionActivityReporter) api.EventHandler {
	return func(ctx context.Context, envelope api.Envelope) error {
		var setup api.SSHSessionSetup
		if err := json.Unmarshal(envelope.Payload, &setup); err != nil {
			mgr.logger.Error("ssh_session_setup: parse payload failed",
				"event_id", envelope.ID,
				"error", err,
			)
			return fmt.Errorf("tunnel: ssh_session_setup: parse payload: %w", err)
		}

		if _, err := mgr.CreateSession(ctx, setup); err != nil {
			return fmt.Errorf("tunnel: ssh_session_setup: %w", err)
		}

		reporter.ReportSessionStarted(ctx, setup.SessionID, setup.TargetHost, setup.TargetPort)
		return nil
	}
}

// HandleSessionRevoked returns an api.EventHandler for session_revoked events.
// It looks up the session by ID and closes it with reason "revoked"; the
// session_ended row is emitted by the manager's on-closed callback, keeping a
// single reporting path for every close reason. Revoking a non-existent session
// is a no-op.
func HandleSessionRevoked(mgr *SessionManager) api.EventHandler {
	return func(ctx context.Context, envelope api.Envelope) error {
		var payload struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			mgr.logger.Error("session_revoked: parse payload failed",
				"event_id", envelope.ID,
				"error", err,
			)
			return fmt.Errorf("tunnel: session_revoked: parse payload: %w", err)
		}

		mgr.CloseSession(payload.SessionID, "revoked")
		return nil
	}
}

// TerminatedByFromReason maps an internal session close reason to the wire
// terminated_by enum reported on a session_ended row: "expired" becomes
// ttl_expired, "revoked" becomes operator_revoke, and any other reason
// (including a local plexd-initiated close) becomes plexd_close.
// api.TerminatedByIdleTimeout is reserved and never produced here — the tunnel
// subsystem has no idle timer.
func TerminatedByFromReason(reason string) string {
	switch reason {
	case "expired":
		return api.TerminatedByTTLExpired
	case "revoked":
		return api.TerminatedByOperatorRevoke
	default:
		return api.TerminatedByPlexdClose
	}
}
