package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

func handlerTestPeer(id string) api.Peer {
	return api.Peer{
		ID:         id,
		PublicKey:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		MeshIP:     "10.0.0.2",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.0.0.2/32"},
	}
}

func testEnvelope(eventType string, payload interface{}) api.SignedEnvelope {
	data, _ := json.Marshal(payload)
	return api.SignedEnvelope{
		EventType: eventType,
		EventID:   "evt-1",
		Payload:   data,
	}
}

func newTestManager(ctrl WGController) *Manager {
	return NewManager(ctrl, Config{}, discardLogger())
}

// ---------------------------------------------------------------------------
// ReconcileHandler tests
// ---------------------------------------------------------------------------

func TestReconcileHandler_FullDiff(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	// Pre-populate index so RemovePeerByID can resolve the key.
	delPeer := handlerTestPeer("peer-del")
	mgr.PeerIndex().Add("peer-del", delPeer.PublicKey)

	updPeer := handlerTestPeer("peer-upd")
	addPeer := handlerTestPeer("peer-add")

	diff := reconcile.StateDiff{
		PeersToRemove: []string{"peer-del"},
		PeersToUpdate: []api.Peer{updPeer},
		PeersToAdd:    []api.Peer{addPeer},
	}

	handler := ReconcileHandler(mgr)
	err := handler(context.Background(), nil, diff)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// RemovePeer should be called once (for the removed peer).
	if n := len(ctrl.callsFor("RemovePeer")); n != 1 {
		t.Errorf("expected 1 RemovePeer call, got %d", n)
	}

	// AddPeer should be called twice: once for update (upsert) and once for add.
	if n := len(ctrl.callsFor("AddPeer")); n != 2 {
		t.Errorf("expected 2 AddPeer calls, got %d", n)
	}
}

func TestReconcileHandler_EmptyDiff(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	diff := reconcile.StateDiff{}

	handler := ReconcileHandler(mgr)
	err := handler(context.Background(), nil, diff)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// No controller calls expected.
	if n := len(ctrl.callsFor("AddPeer")); n != 0 {
		t.Errorf("expected 0 AddPeer calls, got %d", n)
	}
	if n := len(ctrl.callsFor("RemovePeer")); n != 0 {
		t.Errorf("expected 0 RemovePeer calls, got %d", n)
	}
}

func TestReconcileHandler_PartialFailure(t *testing.T) {
	ctrl := &mockController{
		addPeerErr: errors.New("controller: add failed"),
	}
	mgr := newTestManager(ctrl)

	peer := handlerTestPeer("peer-1")
	diff := reconcile.StateDiff{
		PeersToAdd: []api.Peer{peer},
	}

	handler := ReconcileHandler(mgr)
	err := handler(context.Background(), nil, diff)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

// ---------------------------------------------------------------------------
// SSE Event Handler tests
// ---------------------------------------------------------------------------

func TestSSEHandler_PeerAdded(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	peer := handlerTestPeer("peer-1")
	envelope := testEnvelope(api.EventPeerAdded, peer)

	handler := HandlePeerAdded(mgr)
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if n := len(ctrl.callsFor("AddPeer")); n != 1 {
		t.Errorf("expected 1 AddPeer call, got %d", n)
	}
}

func TestSSEHandler_PeerRemoved(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	// Pre-populate index so RemovePeerByID can resolve the key.
	peer := handlerTestPeer("peer-1")
	mgr.PeerIndex().Add("peer-1", peer.PublicKey)

	payload := struct {
		PeerID string `json:"peer_id"`
	}{PeerID: "peer-1"}
	envelope := testEnvelope(api.EventPeerRemoved, payload)

	handler := HandlePeerRemoved(mgr)
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if n := len(ctrl.callsFor("RemovePeer")); n != 1 {
		t.Errorf("expected 1 RemovePeer call, got %d", n)
	}
}

func TestSSEHandler_PeerKeyRotated(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	// Pre-populate index with old key.
	oldKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	mgr.PeerIndex().Add("peer-1", oldKey)

	// New peer with a different key.
	newKey := make([]byte, 32)
	newKey[0] = 0xFF
	peer := api.Peer{
		ID:         "peer-1",
		PublicKey:  base64.StdEncoding.EncodeToString(newKey),
		MeshIP:     "10.0.0.2",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.0.0.2/32"},
	}
	envelope := testEnvelope(api.EventPeerKeyRotated, peer)

	handler := HandlePeerKeyRotated(mgr)
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// RemovePeer called with old key, AddPeer called with new key.
	if n := len(ctrl.callsFor("RemovePeer")); n != 1 {
		t.Errorf("expected 1 RemovePeer call, got %d", n)
	}
	if n := len(ctrl.callsFor("AddPeer")); n != 1 {
		t.Errorf("expected 1 AddPeer call, got %d", n)
	}
}

func TestSSEHandler_PeerEndpointChanged(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	// Pre-populate index.
	peer := handlerTestPeer("peer-1")
	mgr.PeerIndex().Add("peer-1", peer.PublicKey)

	// Update endpoint.
	peer.Endpoint = "5.6.7.8:51820"
	envelope := testEnvelope(api.EventPeerEndpointChanged, peer)

	handler := HandlePeerEndpointChanged(mgr)
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// UpdatePeer calls AddPeer on controller (upsert).
	if n := len(ctrl.callsFor("AddPeer")); n != 1 {
		t.Errorf("expected 1 AddPeer call, got %d", n)
	}
}

func TestSSEHandler_MalformedPayload(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	envelope := api.SignedEnvelope{
		EventType: api.EventPeerAdded,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not json"),
	}

	handler := HandlePeerAdded(mgr)
	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("expected non-nil error for malformed payload")
	}
}
