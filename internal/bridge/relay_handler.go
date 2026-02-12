package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// HandleRelaySessionAssigned returns an api.EventHandler that adds a relay
// session when a relay_session_assigned SSE event is received.
func HandleRelaySessionAssigned(relay *Relay, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var assignment api.RelaySessionAssignment
		if err := json.Unmarshal(envelope.Payload, &assignment); err != nil {
			logger.Error("relay_session_assigned: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: relay_session_assigned: parse payload: %w", err)
		}

		if err := relay.AddSession(assignment); err != nil {
			return fmt.Errorf("bridge: relay_session_assigned: %w", err)
		}
		return nil
	}
}

// HandleRelaySessionRevoked returns an api.EventHandler that removes a relay
// session when a relay_session_revoked SSE event is received.
func HandleRelaySessionRevoked(relay *Relay, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, envelope api.SignedEnvelope) error {
		var payload struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			logger.Error("relay_session_revoked: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("bridge: relay_session_revoked: parse payload: %w", err)
		}

		relay.RemoveSession(payload.SessionID)
		return nil
	}
}

// RelayReconcileHandler returns a reconcile.ReconcileHandler that reconciles
// relay sessions to match the desired RelayConfig. Sessions not in the desired
// state are removed; missing sessions are added.
func RelayReconcileHandler(relay *Relay, logger *slog.Logger) reconcile.ReconcileHandler {
	return func(_ context.Context, desired *api.StateResponse, _ reconcile.StateDiff) error {
		if desired == nil || desired.RelayConfig == nil {
			return nil
		}

		// Build desired set keyed by SessionID.
		desiredSet := make(map[string]api.RelaySessionAssignment, len(desired.RelayConfig.Sessions))
		for _, s := range desired.RelayConfig.Sessions {
			desiredSet[s.SessionID] = s
		}

		// Remove stale sessions.
		currentIDs := relay.SessionIDs()
		for _, id := range currentIDs {
			if _, ok := desiredSet[id]; !ok {
				relay.RemoveSession(id)
			}
		}

		// Add missing sessions.
		currentSet := make(map[string]bool, len(currentIDs))
		for _, id := range currentIDs {
			currentSet[id] = true
		}

		var errs []error
		for id, assignment := range desiredSet {
			if currentSet[id] {
				continue
			}
			if err := relay.AddSession(assignment); err != nil {
				logger.Error("relay reconcile: add session failed",
					"session_id", id,
					"error", err,
				)
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
}
