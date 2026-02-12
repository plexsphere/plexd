package nodeapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func makeEnvelope(t *testing.T, eventType string, payload any) api.SignedEnvelope {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return api.SignedEnvelope{
		EventType: eventType,
		EventID:   "test-event-1",
		IssuedAt:  time.Now(),
		Payload:   data,
	}
}

func TestEventHandler_NodeStateUpdated(t *testing.T) {
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	logger := slog.Default()

	payload := NodeStateUpdatePayload{
		Metadata: map[string]string{"role": "worker", "region": "us-east"},
		Data: []api.DataEntry{
			{Key: "config-a", ContentType: "application/json", Payload: json.RawMessage(`{"x":1}`), Version: 1, UpdatedAt: time.Now()},
		},
	}
	env := makeEnvelope(t, api.EventNodeStateUpdated, payload)

	if err := HandleNodeStateUpdated(cache, logger, env); err != nil {
		t.Fatalf("HandleNodeStateUpdated: %v", err)
	}

	// Verify metadata updated.
	meta := cache.GetMetadata()
	if meta["role"] != "worker" {
		t.Errorf("metadata role = %q, want %q", meta["role"], "worker")
	}
	if meta["region"] != "us-east" {
		t.Errorf("metadata region = %q, want %q", meta["region"], "us-east")
	}

	// Verify data entries updated.
	data := cache.GetData()
	if len(data) != 1 {
		t.Fatalf("data len = %d, want 1", len(data))
	}
	if data["config-a"].Version != 1 {
		t.Errorf("data config-a version = %d, want 1", data["config-a"].Version)
	}
}

func TestEventHandler_NodeSecretsUpdated(t *testing.T) {
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	logger := slog.Default()

	payload := NodeSecretsUpdatePayload{
		SecretRefs: []api.SecretRef{
			{Key: "db-password", Version: 1},
			{Key: "api-token", Version: 3},
		},
	}
	env := makeEnvelope(t, api.EventNodeSecretsUpdated, payload)

	if err := HandleNodeSecretsUpdated(cache, logger, env); err != nil {
		t.Fatalf("HandleNodeSecretsUpdated: %v", err)
	}

	// Verify secret index updated.
	refs := cache.GetSecretIndex()
	if len(refs) != 2 {
		t.Fatalf("secret index len = %d, want 2", len(refs))
	}
	if refs[0].Key != "db-password" || refs[0].Version != 1 {
		t.Errorf("refs[0] = %+v, want {db-password 1}", refs[0])
	}
	if refs[1].Key != "api-token" || refs[1].Version != 3 {
		t.Errorf("refs[1] = %+v, want {api-token 3}", refs[1])
	}
}

func TestEventHandler_MalformedPayload(t *testing.T) {
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	logger := slog.Default()

	env := api.SignedEnvelope{
		EventType: api.EventNodeStateUpdated,
		EventID:   "test-bad-1",
		IssuedAt:  time.Now(),
		Payload:   json.RawMessage(`{not valid json`),
	}

	err := HandleNodeStateUpdated(cache, logger, env)
	if err == nil {
		t.Fatal("HandleNodeStateUpdated with malformed payload: expected error, got nil")
	}

	// Verify cache was NOT modified.
	meta := cache.GetMetadata()
	if len(meta) != 0 {
		t.Errorf("metadata should be empty after malformed payload, got %v", meta)
	}
}

func TestEventHandler_NodeSecretsUpdated_MalformedPayload(t *testing.T) {
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	logger := slog.Default()

	env := api.SignedEnvelope{
		EventType: api.EventNodeSecretsUpdated,
		EventID:   "test-bad-2",
		IssuedAt:  time.Now(),
		Payload:   json.RawMessage(`<<<broken`),
	}

	err := HandleNodeSecretsUpdated(cache, logger, env)
	if err == nil {
		t.Fatal("HandleNodeSecretsUpdated with malformed payload: expected error, got nil")
	}

	// Verify cache was NOT modified.
	refs := cache.GetSecretIndex()
	if len(refs) != 0 {
		t.Errorf("secret index should be empty after malformed payload, got %v", refs)
	}
}

func TestRegisterEventHandlers(t *testing.T) {
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	logger := slog.Default()
	dispatcher := api.NewEventDispatcher(logger)

	RegisterEventHandlers(dispatcher, cache, logger)

	// Dispatch a node_state_updated event.
	payload := NodeStateUpdatePayload{
		Metadata: map[string]string{"env": "prod"},
		Data: []api.DataEntry{
			{Key: "cfg", ContentType: "text/plain", Payload: json.RawMessage(`"hello"`), Version: 1, UpdatedAt: time.Now()},
		},
	}
	env := makeEnvelope(t, api.EventNodeStateUpdated, payload)
	dispatcher.Dispatch(context.Background(), env)

	// Verify cache was updated via the registered handler.
	meta := cache.GetMetadata()
	if meta["env"] != "prod" {
		t.Errorf("metadata env = %q, want %q", meta["env"], "prod")
	}
	data := cache.GetData()
	if len(data) != 1 {
		t.Fatalf("data len = %d, want 1", len(data))
	}
	if data["cfg"].ContentType != "text/plain" {
		t.Errorf("data cfg content_type = %q, want %q", data["cfg"].ContentType, "text/plain")
	}
}

func TestRegisterEventHandlers_SecretsEvent(t *testing.T) {
	dir := t.TempDir()
	cache := NewStateCache(dir, discardLogger())
	if err := cache.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	logger := slog.Default()
	dispatcher := api.NewEventDispatcher(logger)

	RegisterEventHandlers(dispatcher, cache, logger)

	// Dispatch a node_secrets_updated event.
	payload := NodeSecretsUpdatePayload{
		SecretRefs: []api.SecretRef{
			{Key: "tls-cert", Version: 5},
		},
	}
	env := makeEnvelope(t, api.EventNodeSecretsUpdated, payload)
	dispatcher.Dispatch(context.Background(), env)

	// Verify secret index was updated via the registered handler.
	refs := cache.GetSecretIndex()
	if len(refs) != 1 {
		t.Fatalf("secret index len = %d, want 1", len(refs))
	}
	if refs[0].Key != "tls-cert" || refs[0].Version != 5 {
		t.Errorf("refs[0] = %+v, want {tls-cert 5}", refs[0])
	}
}
