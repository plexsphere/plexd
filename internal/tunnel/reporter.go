package tunnel

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
)

// SessionActivityReporter reports the tcp-phase session_started row to the
// control plane. The session dispatcher posts it once the listener is up, so the
// row carries the bound listener address alongside the target. That address is
// the operator's only route to the listener, so the error is returned rather
// than swallowed: a dropped row leaves a listener nobody can reach. The matching
// session_ended row is emitted from the SessionManager's on-closed callback, not
// through here.
type SessionActivityReporter interface {
	ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int, listenerEndpoint string) error
}

// The close reasons handed to CloseSession. They are the sole input to
// TerminatedByFromReason, which turns them into the wire terminated_by value the
// control plane audits on, so producer and consumer share this vocabulary
// instead of matching bare string literals across files.
const (
	// reasonExpired is the session's capped local expiry lapsing.
	reasonExpired = "expired"
	// reasonDrained is the session's entry leaving the pull's sessions block
	// before its local expiry lapsed.
	reasonDrained = "drained"
	// reasonIdle is the idle window elapsing without byte flow.
	reasonIdle = "idle"
	// reasonShutdown is the node going down.
	reasonShutdown = "shutdown"
)

// TerminatedByFromReason maps an internal session close reason to the wire
// terminated_by enum reported on a session_ended row: reasonExpired becomes
// ttl_expired, reasonIdle becomes idle_timeout, and every other reason becomes
// plexd_close.
//
// api.TerminatedByOperatorRevoke is never produced here. It is a factual claim
// about a human action, and the node cannot make it: a revocation reaches the
// node as the absence of the entry, which is indistinguishable from a control
// plane that failed to serve the block. Asserting it would write a confidently
// wrong answer into the audit trail on every degraded pull.
func TerminatedByFromReason(reason string) string {
	switch reason {
	case reasonExpired:
		return api.TerminatedByTTLExpired
	case reasonIdle:
		return api.TerminatedByIdleTimeout
	default:
		return api.TerminatedByPlexdClose
	}
}
