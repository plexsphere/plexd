package nodeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// NodeStateUpdatePayload is the payload for node_state_updated events.
type NodeStateUpdatePayload struct {
	Metadata map[string]string `json:"metadata"`
	Data     []api.DataEntry   `json:"data"`
}

// NodeSecretsUpdatePayload is the payload for node_secrets_updated events.
type NodeSecretsUpdatePayload struct {
	SecretRefs []api.SecretRef `json:"secret_refs"`
}

// RegisterEventHandlers registers SSE event handlers for node_state_updated
// and node_secrets_updated with the given dispatcher.
func RegisterEventHandlers(dispatcher *api.EventDispatcher, cache *StateCache, logger *slog.Logger) {
	dispatcher.Register(api.EventNodeStateUpdated, func(ctx context.Context, env api.SignedEnvelope) error {
		return HandleNodeStateUpdated(cache, logger, env)
	})
	dispatcher.Register(api.EventNodeSecretsUpdated, func(ctx context.Context, env api.SignedEnvelope) error {
		return HandleNodeSecretsUpdated(cache, logger, env)
	})
}

// HandleNodeStateUpdated parses the event payload and updates metadata and
// data entries in the cache.
func HandleNodeStateUpdated(cache *StateCache, logger *slog.Logger, env api.SignedEnvelope) error {
	var payload NodeStateUpdatePayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		logger.Error("failed to parse node_state_updated payload",
			"component", "nodeapi",
			"event_id", env.EventID,
			"error", err,
		)
		return fmt.Errorf("nodeapi: parse node_state_updated: %w", err)
	}

	cache.UpdateMetadata(payload.Metadata)
	cache.UpdateData(payload.Data)

	logger.Info("cache updated from node_state_updated",
		"component", "nodeapi",
		"event_id", env.EventID,
		"metadata_keys", len(payload.Metadata),
		"data_entries", len(payload.Data),
	)
	return nil
}

// HandleNodeSecretsUpdated parses the event payload and updates the secret
// index in the cache.
func HandleNodeSecretsUpdated(cache *StateCache, logger *slog.Logger, env api.SignedEnvelope) error {
	var payload NodeSecretsUpdatePayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		logger.Error("failed to parse node_secrets_updated payload",
			"component", "nodeapi",
			"event_id", env.EventID,
			"error", err,
		)
		return fmt.Errorf("nodeapi: parse node_secrets_updated: %w", err)
	}

	cache.UpdateSecretIndex(payload.SecretRefs)

	logger.Info("secret index updated from node_secrets_updated",
		"component", "nodeapi",
		"event_id", env.EventID,
		"secret_refs", len(payload.SecretRefs),
	)
	return nil
}
