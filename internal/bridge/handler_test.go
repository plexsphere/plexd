package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReconcileTrigger records TriggerReconcile calls.
type mockReconcileTrigger struct {
	triggered int
}

func (m *mockReconcileTrigger) TriggerReconcile() {
	m.triggered++
}

// ---------------------------------------------------------------------------
// SSE Handler tests
// ---------------------------------------------------------------------------

func TestHandleBridgeConfigUpdated(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleBridgeConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventBridgeConfigUpdated,
		EventID:   "evt-1",
		Payload:   json.RawMessage(`{"access_subnets":["10.0.0.0/24"]}`),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}

func TestHandleBridgeConfigUpdated_MalformedPayload(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleBridgeConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventBridgeConfigUpdated,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	// TriggerReconcile should still be called despite malformed payload.
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}
