package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/plexsphere/plexd/internal/api"
)

// SessionConnector opens the connection a session_connect event asked for, to
// the control plane, and returns it carrying the session's SSH bytes.
// api.ControlPlane.OpenSessionConnection, bound to the node's id, is the
// production implementation.
type SessionConnector interface {
	OpenSessionConnection(ctx context.Context, sessionID, connectionID string) (net.Conn, error)
}

// errSessionConnectUnnamed is returned for a session_connect payload that names
// no connection to open.
var errSessionConnectUnnamed = errors.New("tunnel: session_connect payload names no connection: session_id or connection_id is empty")

// SessionConnectHandler returns the handler for the session_connect event. The
// SSE stream has verified the envelope's signature and freshness before any
// handler runs, and the payload names the ssh session a client attached to and
// the connection the control plane waits for, so the handler opens that
// connection with connector and serves the session's SSH login on it
// (SessionManager.ConnectSSHSession).
//
// The open runs on its own goroutine, because it blocks on the control plane
// and the SSE stream dispatches its handlers one after another. It logs one
// line per event with its outcome. Nothing is opened for a session that is not
// live here, for one this node does not serve, or past the session's
// connection limit.
//
// DECISION: the handler does not judge the payload's expires_at against the
// node's clock. The verifier admits envelopes up to DefaultStalenessWindow off,
// while the control plane waits seconds for the connection, so a node clock a
// few seconds ahead would drop every request. The control plane refuses a late
// connection with 404 session_connection_not_found, which the failure line
// carries. A failed open is not retried either: the next attach asks for a new
// connection.
//
// A payload that does not decode, or that names no session or no connection,
// opens nothing; the handler returns the error, which the event dispatcher
// logs. The event carries no desired state, so it never triggers a reconcile.
func (d *Dispatcher) SessionConnectHandler(connector SessionConnector) api.EventHandler {
	return func(_ context.Context, env api.Envelope) error {
		var req api.SessionConnectRequest
		if err := json.Unmarshal(env.Payload, &req); err != nil {
			return fmt.Errorf("tunnel: session_connect payload: %w", err)
		}
		if req.SessionID == "" || req.ConnectionID == "" {
			return errSessionConnectUnnamed
		}

		go func() {
			err := d.manager.ConnectSSHSession(req.SessionID, req.ConnectionID, func(ctx context.Context) (net.Conn, error) {
				return connector.OpenSessionConnection(ctx, req.SessionID, req.ConnectionID)
			})
			attrs := []any{"session_id", req.SessionID, "connection_id", req.ConnectionID}
			switch {
			case err == nil:
				d.logger.Info("session connection opened", attrs...)
			case errors.Is(err, ErrSessionNotLive):
				// A session that closed, or drained, while its client attached.
				d.logger.Info("session_connect names no live ssh session; not connecting", attrs...)
			case errors.Is(err, ErrTunnelingDisabled),
				errors.Is(err, ErrSSHSessionsDisabled),
				errors.Is(err, ErrSSHSessionsUnsupported),
				errors.Is(err, ErrNotSSHSession),
				errors.Is(err, ErrSSHConnectionLimit):
				d.logger.Warn("session_connect cannot be served on this node; not connecting", append(attrs, "error", err)...)
			case errors.Is(err, errSessionClosedWhileConnecting):
				d.logger.Info("session closed while its connection opened; closed the connection", attrs...)
			default:
				d.logger.Warn("session connection to the control plane failed", append(attrs, "error", err)...)
			}
		}()
		return nil
	}
}
