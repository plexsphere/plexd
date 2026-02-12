package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// TunnelReporter reports tunnel session lifecycle events to the control plane.
type TunnelReporter interface {
	ReportReady(ctx context.Context, sessionID, listenAddr string)
	ReportClosed(ctx context.Context, sessionID, reason string, duration time.Duration)
}

// HandleSSHSessionSetup returns an api.EventHandler for ssh_session_setup events.
// It parses the SSE payload, creates a tunnel session via the SessionManager,
// and reports readiness via the TunnelReporter.
func HandleSSHSessionSetup(mgr *SessionManager, reporter TunnelReporter) api.EventHandler {
	return func(ctx context.Context, envelope api.SignedEnvelope) error {
		var setup api.SSHSessionSetup
		if err := json.Unmarshal(envelope.Payload, &setup); err != nil {
			mgr.logger.Error("ssh_session_setup: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("tunnel: ssh_session_setup: parse payload: %w", err)
		}

		addr, err := mgr.CreateSession(ctx, setup)
		if err != nil {
			return fmt.Errorf("tunnel: ssh_session_setup: %w", err)
		}

		reporter.ReportReady(ctx, setup.SessionID, addr)
		return nil
	}
}

// HandleSessionRevoked returns an api.EventHandler for session_revoked events.
// It looks up the session by ID and closes it with reason "revoked".
// Revoking a non-existent session is a no-op.
func HandleSessionRevoked(mgr *SessionManager, reporter TunnelReporter) api.EventHandler {
	return func(ctx context.Context, envelope api.SignedEnvelope) error {
		var payload struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			mgr.logger.Error("session_revoked: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("tunnel: session_revoked: parse payload: %w", err)
		}

		info := mgr.CloseSession(payload.SessionID, "revoked")
		if info == nil {
			mgr.logger.Debug("session_revoked: session not found",
				"session_id", payload.SessionID,
			)
			return nil
		}

		reporter.ReportClosed(ctx, payload.SessionID, "revoked", info.Duration)
		return nil
	}
}
