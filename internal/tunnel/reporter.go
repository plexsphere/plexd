package tunnel

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
)

// SessionActivityReporter reports a session's session_started row to the
// control plane: the tcp row, which carries the target, for a tcp entry, and the
// ssh lifecycle row for an ssh entry. The session dispatcher posts it once the
// listener is up, so the row carries the bound listener address. That address is
// the operator's only route to the listener, so the error is returned rather
// than swallowed: a dropped row leaves a listener nobody can reach. The matching
// session_ended row is emitted from the SessionManager's on-closed callback, not
// through here.
type SessionActivityReporter interface {
	ReportSessionStarted(ctx context.Context, entry api.NodeStateSession, listenerEndpoint string) error
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
	// reasonRevoked is the control plane revoking the session and saying so in
	// a verified session_revoked event.
	reasonRevoked = "revoked"
)

// TerminatedByFromReason maps an internal session close reason to the wire
// terminated_by enum reported on a session_ended row: reasonExpired becomes
// ttl_expired, reasonIdle becomes idle_timeout, reasonRevoked becomes
// operator_revoke, and every other reason becomes plexd_close.
//
// api.TerminatedByOperatorRevoke is produced only for reasonRevoked, which only
// the session_revoked handler passes: the agent contract defines
// operator_revoke as a close caused by that event, and the event is signed and
// names the session. A drain never produces it. A revocation the node learns
// only from the pull reaches it as the absence of the entry, which is
// indistinguishable from a control plane that failed to serve the block, and
// asserting a revocation on that evidence would write a confidently wrong
// answer into the audit trail on every degraded pull.
func TerminatedByFromReason(reason string) string {
	switch reason {
	case reasonExpired:
		return api.TerminatedByTTLExpired
	case reasonIdle:
		return api.TerminatedByIdleTimeout
	case reasonRevoked:
		return api.TerminatedByOperatorRevoke
	default:
		return api.TerminatedByPlexdClose
	}
}

// closeReasonForRevocation maps a session_revoked event's revoke_reason to the
// close reason handed to CloseSession. The sweeper's two reasons keep their own
// terminated_by values: a session the control plane ended at its hard expiry or
// its idle timeout is reported as ttl_expired or idle_timeout, as the node's
// own timers would report it. The four operator-driven reasons become
// reasonRevoked. recognised is false for a value outside the six the contract
// names, the empty string included; such a value still maps to reasonRevoked,
// because the close is still caused by the event.
func closeReasonForRevocation(revokeReason string) (reason string, recognised bool) {
	switch revokeReason {
	case api.RevokeReasonTTLExpired:
		return reasonExpired, true
	case api.RevokeReasonIdleTimeout:
		return reasonIdle, true
	case api.RevokeReasonOperatorRequest, api.RevokeReasonPolicyViolation,
		api.RevokeReasonIdentityCompromise, api.RevokeReasonResourceDecommissioned:
		return reasonRevoked, true
	default:
		return reasonRevoked, false
	}
}
