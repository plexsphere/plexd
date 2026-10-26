package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/plexsphere/plexd/internal/api"
)

// errRevocationUnnamed is returned for a session_revoked payload that names no
// single session.
var errRevocationUnnamed = errors.New("tunnel: session_revoked payload names no session: session_id is empty or jti differs from it")

// SessionRevokedHandler returns the handler for the session_revoked event. The
// SSE stream has verified the envelope's signature and freshness before any
// handler runs, and the payload names the session the control plane revoked,
// so the handler closes that session when it is live here. Its session_ended
// row reports the payload's revoke_reason, mapped by closeReasonForRevocation:
// operator_revoke for the operator-driven reasons, ttl_expired and
// idle_timeout for the sweeper's.
//
// The close runs on its own goroutine, because it blocks on the session's drain
// and on the bounded session_ended post, and the SSE stream dispatches its
// handlers one after another. trigger fires after the close returns, so the
// pull it starts cannot drain the session first and report it as plexd_close.
// The pull still runs: it is the teardown for every revocation whose event
// never arrives.
//
// A payload that does not decode, or whose session_id is empty or differs from
// its jti, closes nothing. The handler still triggers the reconcile and returns
// the error, which the event dispatcher logs. A missing or unrecognised
// revoke_reason still closes the session and reports operator_revoke, because
// the agent contract defines that value as a close caused by this event.
func (d *Dispatcher) SessionRevokedHandler(trigger api.ReconcileTrigger) api.EventHandler {
	return func(_ context.Context, env api.Envelope) error {
		var rev api.SessionRevocation
		if err := json.Unmarshal(env.Payload, &rev); err != nil {
			trigger.TriggerReconcile()
			return fmt.Errorf("tunnel: session_revoked payload: %w", err)
		}
		// The contract makes jti equal to the session id. Two names that disagree
		// do not name one session, and closing either would be a guess.
		if rev.SessionID == "" || rev.JTI != rev.SessionID {
			trigger.TriggerReconcile()
			return errRevocationUnnamed
		}

		reason, recognised := closeReasonForRevocation(rev.RevokeReason)
		if !recognised {
			d.logger.Warn("session_revoked carries an unrecognised revoke_reason; reporting operator_revoke",
				"session_id", rev.SessionID,
				"revoke_reason", rev.RevokeReason,
			)
		}

		// Recorded before the close, so a pull rendered before the revocation
		// committed cannot provision the session again while the close runs, and
		// a listener such a pull is binding right now is closed by Handle once it
		// is up, with this reason.
		d.markRevoked(rev.SessionID, reason)

		go func() {
			if info := d.manager.CloseSession(rev.SessionID, reason); info != nil {
				d.logger.Info("session_revoked closed the session",
					"session_id", rev.SessionID,
					"revoke_reason", rev.RevokeReason,
					"terminated_by", TerminatedByFromReason(reason),
				)
			} else {
				// The drain or a local timer closed it first and reported its own
				// reason, or it was never provisioned on this node.
				d.logger.Info("session_revoked names no live session; nothing to close",
					"session_id", rev.SessionID,
					"revoke_reason", rev.RevokeReason,
				)
			}
			trigger.TriggerReconcile()
		}()
		return nil
	}
}
