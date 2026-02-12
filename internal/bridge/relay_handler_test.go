package bridge

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// relayAssignmentEnvelope builds a SignedEnvelope for a relay session assignment.
func relayAssignmentEnvelope(t *testing.T, assignment api.RelaySessionAssignment) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(assignment)
	if err != nil {
		t.Fatalf("marshal assignment: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventRelaySessionAssigned,
		EventID:   "evt-" + assignment.SessionID,
		Payload:   payload,
	}
}

// relayRevocationEnvelope builds a SignedEnvelope for a relay session revocation.
func relayRevocationEnvelope(t *testing.T, sessionID string) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(struct {
		SessionID string `json:"session_id"`
	}{SessionID: sessionID})
	if err != nil {
		t.Fatalf("marshal revocation: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventRelaySessionRevoked,
		EventID:   "evt-revoke-" + sessionID,
		Payload:   payload,
	}
}

// ---------------------------------------------------------------------------
// HandleRelaySessionAssigned tests
// ---------------------------------------------------------------------------

func TestHandleRelaySessionAssigned_Success(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	handler := HandleRelaySessionAssigned(relay, discardLogger())

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-1",
		PeerAID:       "peer-a",
		PeerAEndpoint: "127.0.0.1:5000",
		PeerBID:       "peer-b",
		PeerBEndpoint: "127.0.0.1:5001",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	envelope := relayAssignmentEnvelope(t, assignment)

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if relay.ActiveCount() != 1 {
		t.Errorf("ActiveCount = %d, want 1", relay.ActiveCount())
	}
}

func TestHandleRelaySessionAssigned_MalformedPayload(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	handler := HandleRelaySessionAssigned(relay, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventRelaySessionAssigned,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

func TestHandleRelaySessionAssigned_DuplicateSession(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	handler := HandleRelaySessionAssigned(relay, discardLogger())

	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-dup",
		PeerAID:       "peer-a",
		PeerAEndpoint: "127.0.0.1:5000",
		PeerBID:       "peer-b",
		PeerBEndpoint: "127.0.0.1:5001",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	envelope := relayAssignmentEnvelope(t, assignment)

	// First add should succeed.
	if err := handler(context.Background(), envelope); err != nil {
		t.Fatalf("first handler call: %v", err)
	}

	// Second add with same session ID should fail.
	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for duplicate session")
	}
}

// ---------------------------------------------------------------------------
// HandleRelaySessionRevoked tests
// ---------------------------------------------------------------------------

func TestHandleRelaySessionRevoked_Success(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	assignHandler := HandleRelaySessionAssigned(relay, discardLogger())
	revokeHandler := HandleRelaySessionRevoked(relay, discardLogger())

	// Add a session first.
	assignment := api.RelaySessionAssignment{
		SessionID:     "sess-revoke",
		PeerAID:       "peer-a",
		PeerAEndpoint: "127.0.0.1:5000",
		PeerBID:       "peer-b",
		PeerBEndpoint: "127.0.0.1:5001",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := assignHandler(context.Background(), relayAssignmentEnvelope(t, assignment)); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if relay.ActiveCount() != 1 {
		t.Fatalf("ActiveCount after assign = %d, want 1", relay.ActiveCount())
	}

	// Revoke the session.
	envelope := relayRevocationEnvelope(t, "sess-revoke")
	err := revokeHandler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if relay.ActiveCount() != 0 {
		t.Errorf("ActiveCount after revoke = %d, want 0", relay.ActiveCount())
	}
}

func TestHandleRelaySessionRevoked_MalformedPayload(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	handler := HandleRelaySessionRevoked(relay, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventRelaySessionRevoked,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

func TestHandleRelaySessionRevoked_NonExistent(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	handler := HandleRelaySessionRevoked(relay, discardLogger())

	// Revoking a non-existent session should be a no-op.
	envelope := relayRevocationEnvelope(t, "nonexistent")
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// RelayReconcileHandler tests
// ---------------------------------------------------------------------------

func TestRelayReconcileHandler_NilRelayConfig(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	handler := RelayReconcileHandler(relay, discardLogger())

	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk", MeshIP: "10.42.0.2"}},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if relay.ActiveCount() != 0 {
		t.Errorf("ActiveCount = %d, want 0", relay.ActiveCount())
	}
}

func TestRelayReconcileHandler_AddMissing(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	handler := RelayReconcileHandler(relay, discardLogger())

	desired := &api.StateResponse{
		RelayConfig: &api.RelayConfig{
			Sessions: []api.RelaySessionAssignment{
				{
					SessionID:     "sess-1",
					PeerAID:       "peer-a",
					PeerAEndpoint: "127.0.0.1:5000",
					PeerBID:       "peer-b",
					PeerBEndpoint: "127.0.0.1:5001",
					ExpiresAt:     time.Now().Add(5 * time.Minute),
				},
				{
					SessionID:     "sess-2",
					PeerAID:       "peer-c",
					PeerAEndpoint: "127.0.0.1:5002",
					PeerBID:       "peer-d",
					PeerBEndpoint: "127.0.0.1:5003",
					ExpiresAt:     time.Now().Add(5 * time.Minute),
				},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if relay.ActiveCount() != 2 {
		t.Errorf("ActiveCount = %d, want 2", relay.ActiveCount())
	}
}

func TestRelayReconcileHandler_RemoveStale(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	// Pre-populate the relay with a session.
	assignment := api.RelaySessionAssignment{
		SessionID:     "stale-sess",
		PeerAID:       "peer-a",
		PeerAEndpoint: "127.0.0.1:5000",
		PeerBID:       "peer-b",
		PeerBEndpoint: "127.0.0.1:5001",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(assignment); err != nil {
		t.Fatalf("AddSession: %v", err)
	}
	if relay.ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d, want 1", relay.ActiveCount())
	}

	handler := RelayReconcileHandler(relay, discardLogger())

	// Desired state has no sessions — stale session should be removed.
	desired := &api.StateResponse{
		RelayConfig: &api.RelayConfig{
			Sessions: []api.RelaySessionAssignment{},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if relay.ActiveCount() != 0 {
		t.Errorf("ActiveCount = %d, want 0", relay.ActiveCount())
	}
}

func TestRelayReconcileHandler_Mixed(t *testing.T) {
	relay := NewRelay(0, 100, 5*time.Minute, discardLogger())

	// Pre-populate with two sessions.
	keep := api.RelaySessionAssignment{
		SessionID:     "keep-sess",
		PeerAID:       "peer-a",
		PeerAEndpoint: "127.0.0.1:5000",
		PeerBID:       "peer-b",
		PeerBEndpoint: "127.0.0.1:5001",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	stale := api.RelaySessionAssignment{
		SessionID:     "stale-sess",
		PeerAID:       "peer-c",
		PeerAEndpoint: "127.0.0.1:5002",
		PeerBID:       "peer-d",
		PeerBEndpoint: "127.0.0.1:5003",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := relay.AddSession(keep); err != nil {
		t.Fatalf("AddSession keep: %v", err)
	}
	if err := relay.AddSession(stale); err != nil {
		t.Fatalf("AddSession stale: %v", err)
	}
	if relay.ActiveCount() != 2 {
		t.Fatalf("ActiveCount = %d, want 2", relay.ActiveCount())
	}

	handler := RelayReconcileHandler(relay, discardLogger())

	// Desired: keep "keep-sess", add "new-sess", remove "stale-sess".
	desired := &api.StateResponse{
		RelayConfig: &api.RelayConfig{
			Sessions: []api.RelaySessionAssignment{
				keep,
				{
					SessionID:     "new-sess",
					PeerAID:       "peer-e",
					PeerAEndpoint: "127.0.0.1:5004",
					PeerBID:       "peer-f",
					PeerBEndpoint: "127.0.0.1:5005",
					ExpiresAt:     time.Now().Add(5 * time.Minute),
				},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if relay.ActiveCount() != 2 {
		t.Errorf("ActiveCount = %d, want 2", relay.ActiveCount())
	}

	// Verify the correct sessions exist.
	ids := relay.SessionIDs()
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	if !idSet["keep-sess"] {
		t.Error("expected keep-sess to be present")
	}
	if !idSet["new-sess"] {
		t.Error("expected new-sess to be present")
	}
	if idSet["stale-sess"] {
		t.Error("expected stale-sess to be removed")
	}
}
