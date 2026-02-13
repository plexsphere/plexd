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
	return func(ctx context.Context, envelope api.SignedEnvelope) error {
		var req api.ActionRequest
		if err := json.Unmarshal(envelope.Payload, &req); err != nil {
			log.Error("action_request: parse payload failed",
				"event_id", envelope.EventID,
				"error", err,
			)
			return fmt.Errorf("actions: action_request: parse payload: %w", err)
		}

		if req.ExecutionID == "" {
			log.Error("action_request: missing execution_id",
				"event_id", envelope.EventID,
			)
			return fmt.Errorf("actions: action_request: missing execution_id")
		}

		// When disabled, reject immediately.
		if !executor.cfg.Enabled {
			log.Warn("action_request: actions disabled",
				"execution_id", req.ExecutionID,
				"action", req.Action,
			)
			ack := api.ExecutionAck{
				ExecutionID: req.ExecutionID,
				Status:      "rejected",
				Reason:      "actions_disabled",
			}
			if err := executor.reporter.AckExecution(ctx, nodeID, req.ExecutionID, ack); err != nil {
				log.Warn("action_request: ack failed", "execution_id", req.ExecutionID, "error", err)
			}
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
