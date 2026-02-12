package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/registration"
)

func testIdentity() *registration.NodeIdentity {
	return &registration.NodeIdentity{
		NodeID:     "node-1",
		MeshIP:     "10.0.0.1",
		PrivateKey: make([]byte, 32),
	}
}

func testPeer(id string) api.Peer {
	return api.Peer{
		ID:         id,
		PublicKey:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		MeshIP:     "10.0.0.2",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.0.0.2/32"},
	}
}

func TestManager_Setup(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.Setup(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Setup() returned error: %v", err)
	}

	// Verify CreateInterface was called.
	ci := ctrl.callsFor("CreateInterface")
	if len(ci) != 1 {
		t.Fatalf("expected 1 CreateInterface call, got %d", len(ci))
	}
	if ci[0].Args[0] != "wg0" {
		t.Errorf("CreateInterface iface = %v, want wg0", ci[0].Args[0])
	}

	// Verify ConfigureAddress was called with /32 suffix.
	ca := ctrl.callsFor("ConfigureAddress")
	if len(ca) != 1 {
		t.Fatalf("expected 1 ConfigureAddress call, got %d", len(ca))
	}
	if ca[0].Args[1] != "10.0.0.1/32" {
		t.Errorf("ConfigureAddress address = %v, want 10.0.0.1/32", ca[0].Args[1])
	}

	// Verify SetInterfaceUp was called.
	su := ctrl.callsFor("SetInterfaceUp")
	if len(su) != 1 {
		t.Fatalf("expected 1 SetInterfaceUp call, got %d", len(su))
	}

	// Verify SetMTU was NOT called (MTU=0).
	mtu := ctrl.callsFor("SetMTU")
	if len(mtu) != 0 {
		t.Errorf("expected 0 SetMTU calls, got %d", len(mtu))
	}
}

func TestManager_Setup_WithMTU(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{MTU: 1420}, discardLogger())

	err := mgr.Setup(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Setup() returned error: %v", err)
	}

	mtu := ctrl.callsFor("SetMTU")
	if len(mtu) != 1 {
		t.Fatalf("expected 1 SetMTU call, got %d", len(mtu))
	}
	if mtu[0].Args[1] != 1420 {
		t.Errorf("SetMTU mtu = %v, want 1420", mtu[0].Args[1])
	}
}

func TestManager_Setup_InterfaceAlreadyExists(t *testing.T) {
	ctrl := &mockController{
		createInterfaceErr: errors.New("interface already exists"),
	}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.Setup(context.Background(), testIdentity())
	if err == nil {
		t.Fatal("Setup() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "setup") {
		t.Errorf("error %q does not contain 'setup'", err.Error())
	}
	if !strings.Contains(err.Error(), "interface already exists") {
		t.Errorf("error %q does not wrap original error", err.Error())
	}

	// Verify no further calls were made after CreateInterface failed.
	ca := ctrl.callsFor("ConfigureAddress")
	if len(ca) != 0 {
		t.Errorf("expected 0 ConfigureAddress calls after CreateInterface error, got %d", len(ca))
	}
	su := ctrl.callsFor("SetInterfaceUp")
	if len(su) != 0 {
		t.Errorf("expected 0 SetInterfaceUp calls after CreateInterface error, got %d", len(su))
	}
}

func TestManager_Setup_CreateInterfaceError(t *testing.T) {
	ctrl := &mockController{
		createInterfaceErr: errors.New("device busy"),
	}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.Setup(context.Background(), testIdentity())
	if err == nil {
		t.Fatal("Setup() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "setup") {
		t.Errorf("error %q does not contain 'setup'", err.Error())
	}
}

func TestManager_Teardown(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.Teardown()
	if err != nil {
		t.Fatalf("Teardown() returned error: %v", err)
	}

	di := ctrl.callsFor("DeleteInterface")
	if len(di) != 1 {
		t.Fatalf("expected 1 DeleteInterface call, got %d", len(di))
	}
	if di[0].Args[0] != "wg0" {
		t.Errorf("DeleteInterface iface = %v, want wg0", di[0].Args[0])
	}
}

func TestManager_Teardown_NoInterface(t *testing.T) {
	// Simulate idempotent controller: DeleteInterface returns nil even for non-existent interface.
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	// Call Teardown twice; both calls must succeed (idempotent).
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("first Teardown() returned error: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown() returned error: %v", err)
	}

	di := ctrl.callsFor("DeleteInterface")
	if len(di) != 2 {
		t.Fatalf("expected 2 DeleteInterface calls, got %d", len(di))
	}
}

func TestManager_Teardown_DeleteError(t *testing.T) {
	ctrl := &mockController{
		deleteInterfaceErr: errors.New("permission denied"),
	}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.Teardown()
	if err == nil {
		t.Fatal("Teardown() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "teardown") {
		t.Errorf("error %q does not contain 'teardown'", err.Error())
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error %q does not wrap original error", err.Error())
	}
}

func TestManager_AddPeer(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	peer := testPeer("peer-1")
	err := mgr.AddPeer(peer)
	if err != nil {
		t.Fatalf("AddPeer() returned error: %v", err)
	}

	// Verify ctrl.AddPeer was called.
	ap := ctrl.callsFor("AddPeer")
	if len(ap) != 1 {
		t.Fatalf("expected 1 AddPeer call, got %d", len(ap))
	}

	// Verify peer index was updated.
	pubKey, ok := mgr.PeerIndex().Lookup("peer-1")
	if !ok {
		t.Fatal("peer-1 not found in peer index")
	}
	if pubKey != peer.PublicKey {
		t.Errorf("peer index public key = %v, want %v", pubKey, peer.PublicKey)
	}
}

func TestManager_RemovePeer(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	pubKey := make([]byte, 32)
	pubKey[0] = 0x01 // Distinct key to verify passthrough.

	err := mgr.RemovePeer(pubKey)
	if err != nil {
		t.Fatalf("RemovePeer() returned error: %v", err)
	}

	// Verify ctrl.RemovePeer was called with the correct interface and key.
	rp := ctrl.callsFor("RemovePeer")
	if len(rp) != 1 {
		t.Fatalf("expected 1 RemovePeer call, got %d", len(rp))
	}
	if rp[0].Args[0] != "wg0" {
		t.Errorf("RemovePeer iface = %v, want wg0", rp[0].Args[0])
	}
	gotKey, ok := rp[0].Args[1].([]byte)
	if !ok {
		t.Fatalf("RemovePeer publicKey arg is not []byte")
	}
	if gotKey[0] != 0x01 {
		t.Errorf("RemovePeer publicKey[0] = %d, want 1", gotKey[0])
	}
}

func TestManager_RemovePeer_Error(t *testing.T) {
	ctrl := &mockController{
		removePeerErr: errors.New("peer not found"),
	}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.RemovePeer(make([]byte, 32))
	if err == nil {
		t.Fatal("RemovePeer() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "remove peer") {
		t.Errorf("error %q does not contain 'remove peer'", err.Error())
	}
}

func TestManager_RemovePeerByID(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	// Add a peer first to populate the index.
	peer := testPeer("peer-1")
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer() returned error: %v", err)
	}

	// Remove by ID.
	err := mgr.RemovePeerByID("peer-1")
	if err != nil {
		t.Fatalf("RemovePeerByID() returned error: %v", err)
	}

	// Verify ctrl.RemovePeer was called.
	rp := ctrl.callsFor("RemovePeer")
	if len(rp) != 1 {
		t.Fatalf("expected 1 RemovePeer call, got %d", len(rp))
	}

	// Verify peer index entry was removed.
	_, ok := mgr.PeerIndex().Lookup("peer-1")
	if ok {
		t.Error("peer-1 should have been removed from peer index")
	}
}

func TestManager_RemovePeerByID_UnknownID(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.RemovePeerByID("nonexistent")
	if err == nil {
		t.Fatal("RemovePeerByID() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown peer ID") {
		t.Errorf("error %q does not contain 'unknown peer ID'", err.Error())
	}
}

func TestManager_UpdatePeer(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	peer := testPeer("peer-1")
	err := mgr.UpdatePeer(peer)
	if err != nil {
		t.Fatalf("UpdatePeer() returned error: %v", err)
	}

	// Verify ctrl.AddPeer was called (idempotent upsert).
	ap := ctrl.callsFor("AddPeer")
	if len(ap) != 1 {
		t.Fatalf("expected 1 AddPeer call, got %d", len(ap))
	}

	// Verify peer index was updated.
	pubKey, ok := mgr.PeerIndex().Lookup("peer-1")
	if !ok {
		t.Fatal("peer-1 not found in peer index")
	}
	if pubKey != peer.PublicKey {
		t.Errorf("peer index public key = %v, want %v", pubKey, peer.PublicKey)
	}
}

func TestManager_ConfigurePeers(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	peers := []api.Peer{
		testPeer("peer-1"),
		testPeer("peer-2"),
		testPeer("peer-3"),
	}

	err := mgr.ConfigurePeers(context.Background(), peers)
	if err != nil {
		t.Fatalf("ConfigurePeers() returned error: %v", err)
	}

	// Verify 3 AddPeer calls.
	ap := ctrl.callsFor("AddPeer")
	if len(ap) != 3 {
		t.Fatalf("expected 3 AddPeer calls, got %d", len(ap))
	}

	// Verify index is populated.
	for _, p := range peers {
		_, ok := mgr.PeerIndex().Lookup(p.ID)
		if !ok {
			t.Errorf("peer %s not found in peer index", p.ID)
		}
	}
}

func TestManager_ConfigurePeers_ContextCancellation(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	peers := []api.Peer{
		testPeer("peer-1"),
		testPeer("peer-2"),
		testPeer("peer-3"),
	}

	err := mgr.ConfigurePeers(ctx, peers)
	if err == nil {
		t.Fatal("ConfigurePeers() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("error %q does not contain 'context canceled'", err.Error())
	}
}
