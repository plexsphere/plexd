package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// HandleActionRequest returns an api.EventHandler for action_request events.
// It parses the SSE payload into an ActionRequest and delegates to the Executor.
// When the executor's config is disabled, all requests are rejected with reason=actions_disabled.
func HandleActionRequest(executor *Executor, nodeID string, logger *slog.Logger) api.EventHandler {
	log := logger.With("component", "actions")
	return func(ctx context.Context, envelope api.Envelope) error {
		var req api.ActionRequest
		if err := json.Unmarshal(envelope.Payload, &req); err != nil {
			log.Error("action_request: parse payload failed",
				"event_id", envelope.ID,
				"error", err,
			)
			return fmt.Errorf("actions: action_request: parse payload: %w", err)
		}

		if req.ExecutionID == "" {
			log.Error("action_request: missing execution_id",
				"event_id", envelope.ID,
			)
			return fmt.Errorf("actions: action_request: missing execution_id")
		}

		// When disabled, reject immediately with the same ack + failed
		// sequence as every other rejection.
		if !executor.cfg.IsEnabled() {
			log.Warn("action_request: actions disabled",
				"execution_id", req.ExecutionID,
				"action", req.Action,
			)
			executor.reject(ctx, nodeID, req, "actions_disabled")
			return nil
		}

		log.Info("action_request: received",
			"execution_id", req.ExecutionID,
			"action", req.Action,
		)

		executor.Execute(ctx, nodeID, req)
		return nil
	}
}
