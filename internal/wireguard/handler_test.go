package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

func newTestManager(ctrl WGController) *Manager {
	return NewManager(ctrl, Config{}, discardLogger())
}

// ---------------------------------------------------------------------------
// ReconcileHandler tests
// ---------------------------------------------------------------------------

// snapshotPeer builds an api.SnapshotPeer with a valid 32-byte base64 key.
func snapshotPeer(nodeID, meshIP, fallback string) api.SnapshotPeer {
	return api.SnapshotPeer{
		NodeID:           nodeID,
		MeshIP:           meshIP,
		PublicKey:        base64.StdEncoding.EncodeToString(make([]byte, 32)),
		FallbackEndpoint: fallback,
	}
}

func TestReconcileHandler_ConvertsSnapshotPeer(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	peer := snapshotPeer("peer-add", "10.0.0.7", "203.0.113.9:51820")
	diff := reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}

	handler := ReconcileHandler(mgr)
	if err := handler(context.Background(), nil, diff); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	calls := ctrl.callsFor("AddPeer")
	if len(calls) != 1 {
		t.Fatalf("expected 1 AddPeer call, got %d", len(calls))
	}
	cfg, ok := calls[0].Args[1].(PeerConfig)
	if !ok {
		t.Fatalf("expected PeerConfig arg, got %T", calls[0].Args[1])
	}
	// AllowedIPs are derived locally as mesh_ip/32.
	if len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0] != "10.0.0.7/32" {
		t.Errorf("AllowedIPs = %v, want [10.0.0.7/32]", cfg.AllowedIPs)
	}
	// The fallback endpoint is programmed as the peer endpoint.
	if cfg.Endpoint != "203.0.113.9:51820" {
		t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, "203.0.113.9:51820")
	}
	// No PSK is fabricated; PeerConfigFromAPI leaves PSK nil for an empty PSK.
	if cfg.PSK != nil {
		t.Errorf("PSK = %v, want nil (no preshared key fabricated)", cfg.PSK)
	}
}

// A non-IPv4 mesh_ip must be rejected, not string-concatenated into AllowedIPs:
// net.ParseCIDR("fd00::1/32") would mask a 128-bit address to the fd00::/32
// network, authorizing 2^96 addresses for the peer key. The rule is an error and
// the peer is never programmed.
func TestReconcileHandler_RejectsNonIPv4MeshIP(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	peer := snapshotPeer("peer-v6", "fd00::1", "203.0.113.9:51820")
	diff := reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}

	handler := ReconcileHandler(mgr)
	if err := handler(context.Background(), nil, diff); err == nil {
		t.Fatal("expected error for non-IPv4 mesh_ip, got nil")
	}
	if n := len(ctrl.callsFor("AddPeer")); n != 0 {
		t.Errorf("expected 0 AddPeer calls for invalid mesh_ip, got %d", n)
	}
}

func TestReconcileHandler_FullDiff(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	// Pre-populate index so RemovePeerByID can resolve the key by node ID.
	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	mgr.PeerIndex().Add("peer-del", pubKey)

	diff := reconcile.StateDiff{
		PeersToRemove: []string{"peer-del"},
		PeersToUpdate: []api.SnapshotPeer{snapshotPeer("peer-upd", "10.0.0.2", "1.2.3.4:51820")},
		PeersToAdd:    []api.SnapshotPeer{snapshotPeer("peer-add", "10.0.0.3", "")},
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

func TestReconcileHandler_RemoveUnknownPeer(t *testing.T) {
	ctrl := &mockController{}
	mgr := newTestManager(ctrl)

	// peer-unknown is absent from the index, so RemovePeerByID errors and the
	// controller is never touched.
	diff := reconcile.StateDiff{PeersToRemove: []string{"peer-unknown"}}

	handler := ReconcileHandler(mgr)
	err := handler(context.Background(), nil, diff)
	if err == nil {
		t.Fatal("expected non-nil error for unknown peer removal")
	}
	if n := len(ctrl.callsFor("RemovePeer")); n != 0 {
		t.Errorf("expected 0 RemovePeer calls for unknown peer, got %d", n)
	}
}

func TestReconcileHandler_PartialFailure(t *testing.T) {
	ctrl := &mockController{
		addPeerErr: errors.New("controller: add failed"),
	}
	mgr := newTestManager(ctrl)

	diff := reconcile.StateDiff{
		PeersToAdd: []api.SnapshotPeer{snapshotPeer("peer-1", "10.0.0.2", "1.2.3.4:51820")},
	}

	handler := ReconcileHandler(mgr)
	err := handler(context.Background(), nil, diff)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}
