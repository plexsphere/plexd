package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

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
	if ci[0].Args[0] != "plexd0" {
		t.Errorf("CreateInterface iface = %v, want plexd0", ci[0].Args[0])
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

func TestManager_Setup_InterfaceAddressPrefix(t *testing.T) {
	tests := []struct {
		name           string
		domainMeshCIDR string
		wantAddress    string
	}{
		{
			name:           "cidr containing the mesh ip sets the interface prefix",
			domainMeshCIDR: "10.0.0.0/16",
			wantAddress:    "10.0.0.1/16",
		},
		{
			name:           "empty cidr falls back to /32",
			domainMeshCIDR: "",
			wantAddress:    "10.0.0.1/32",
		},
		{
			name:           "invalid cidr falls back to /32",
			domainMeshCIDR: "not-a-cidr",
			wantAddress:    "10.0.0.1/32",
		},
		{
			name:           "cidr not containing the mesh ip falls back to /32",
			domainMeshCIDR: "192.168.0.0/16",
			wantAddress:    "10.0.0.1/32",
		},
		{
			name:           "overly broad cidr falls back to /32",
			domainMeshCIDR: "0.0.0.0/0",
			wantAddress:    "10.0.0.1/32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &mockController{}
			mgr := NewManager(ctrl, Config{}, discardLogger())

			identity := testIdentity()
			identity.DomainMeshCIDR = tt.domainMeshCIDR

			if err := mgr.Setup(context.Background(), identity); err != nil {
				t.Fatalf("Setup() returned error: %v", err)
			}

			ca := ctrl.callsFor("ConfigureAddress")
			if len(ca) != 1 {
				t.Fatalf("expected 1 ConfigureAddress call, got %d", len(ca))
			}
			if ca[0].Args[1] != tt.wantAddress {
				t.Errorf("ConfigureAddress address = %v, want %v", ca[0].Args[1], tt.wantAddress)
			}
		})
	}
}

func TestManager_MeshPrefix(t *testing.T) {
	tests := []struct {
		name           string
		domainMeshCIDR string
		want           netip.Prefix
	}{
		{"domain mesh cidr", "10.99.0.0/24", netip.MustParsePrefix("10.99.0.0/24")},
		{"no domain mesh cidr gives the host /32", "", netip.MustParsePrefix("10.99.0.5/32")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(&mockController{}, Config{}, discardLogger())
			if got := mgr.MeshPrefix(); got.IsValid() {
				t.Fatalf("MeshPrefix() before Setup = %v, want the zero prefix", got)
			}

			identity := testIdentity()
			identity.MeshIP = "10.99.0.5"
			identity.DomainMeshCIDR = tt.domainMeshCIDR
			if err := mgr.Setup(context.Background(), identity); err != nil {
				t.Fatalf("Setup() returned error: %v", err)
			}
			if got := mgr.MeshPrefix(); got != tt.want {
				t.Errorf("MeshPrefix() = %v, want %v", got, tt.want)
			}
		})
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
	if di[0].Args[0] != "plexd0" {
		t.Errorf("DeleteInterface iface = %v, want plexd0", di[0].Args[0])
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

func TestManager_UpdatePrivateKey(t *testing.T) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	key := make([]byte, 32)
	key[0] = 0x07 // Distinct byte to verify passthrough.

	err := mgr.UpdatePrivateKey(key)
	if err != nil {
		t.Fatalf("UpdatePrivateKey() returned error: %v", err)
	}

	// Verify ctrl.SetPrivateKey was called once with the configured interface.
	sp := ctrl.callsFor("SetPrivateKey")
	if len(sp) != 1 {
		t.Fatalf("expected 1 SetPrivateKey call, got %d", len(sp))
	}
	if sp[0].Args[0] != "plexd0" {
		t.Errorf("SetPrivateKey iface = %v, want plexd0", sp[0].Args[0])
	}
	gotKey, ok := sp[0].Args[1].([]byte)
	if !ok {
		t.Fatalf("SetPrivateKey privateKey arg is not []byte")
	}
	if !bytes.Equal(gotKey, key) {
		t.Errorf("SetPrivateKey privateKey = %v, want %v", gotKey, key)
	}
}

func TestManager_UpdatePrivateKey_Error(t *testing.T) {
	cause := errors.New("device busy")
	ctrl := &mockController{
		setPrivateKeyErr: cause,
	}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	err := mgr.UpdatePrivateKey(make([]byte, 32))
	if err == nil {
		t.Fatal("UpdatePrivateKey() expected error, got nil")
	}
	if !errors.Is(err, cause) {
		t.Errorf("error %q does not wrap cause", err.Error())
	}
	if !strings.HasPrefix(err.Error(), "wireguard: update private key:") {
		t.Errorf("error %q does not start with 'wireguard: update private key:'", err.Error())
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
	if rp[0].Args[0] != "plexd0" {
		t.Errorf("RemovePeer iface = %v, want plexd0", rp[0].Args[0])
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

// Every mesh peer write carries the configured keepalive: 25 s by default, and
// 0 under persistent_keepalive: 0s, which both controllers write as well so it
// clears a keepalive an earlier run left on the device.
func TestManager_PeerWritesCarryKeepalive(t *testing.T) {
	zero := time.Duration(0)
	configs := []struct {
		name string
		cfg  Config
		want int
	}{
		{"default", Config{}, 25},
		{"0s", Config{PersistentKeepalive: &zero}, 0},
	}
	writes := []struct {
		name  string
		write func(*Manager) error
	}{
		{"AddPeer", func(m *Manager) error { return m.AddPeer(testPeer("peer-1")) }},
		{"UpdatePeer", func(m *Manager) error { return m.UpdatePeer(testPeer("peer-1")) }},
		{"ConfigurePeers", func(m *Manager) error {
			return m.ConfigurePeers(context.Background(), []api.Peer{testPeer("peer-1")})
		}},
	}
	for _, c := range configs {
		for _, w := range writes {
			t.Run(c.name+"/"+w.name, func(t *testing.T) {
				ctrl := &mockController{}
				mgr := NewManager(ctrl, c.cfg, discardLogger())
				if err := w.write(mgr); err != nil {
					t.Fatalf("%s: %v", w.name, err)
				}
				cfgs := addPeerConfigs(t, ctrl)
				if len(cfgs) != 1 {
					t.Fatalf("AddPeer calls = %d, want 1", len(cfgs))
				}
				if cfgs[0].PersistentKeepalive != c.want {
					t.Errorf("PersistentKeepalive = %d, want %d", cfgs[0].PersistentKeepalive, c.want)
				}
			})
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

// namingController is a mockController that also reports a kernel interface
// name, the shape DarwinController has on macOS.
type namingController struct {
	mockController
	osName string
	found  bool
}

func (c *namingController) OSInterfaceName(string) (string, bool) {
	return c.osName, c.found
}

func TestManager_OSInterfaceName_Default(t *testing.T) {
	mgr := NewManager(&mockController{}, Config{}, discardLogger())

	// mockController does not implement OSInterfaceNamer, so the configured
	// name stands. This is the Linux case.
	if got := mgr.OSInterfaceName(); got != "plexd0" {
		t.Errorf("OSInterfaceName() = %q, want %q", got, "plexd0")
	}
}

func TestManager_OSInterfaceName_Mapped(t *testing.T) {
	ctrl := &namingController{osName: "utun3", found: true}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	if got := mgr.OSInterfaceName(); got != "utun3" {
		t.Errorf("OSInterfaceName() = %q, want %q", got, "utun3")
	}
}

func TestManager_OSInterfaceName_Unmapped(t *testing.T) {
	// The controller implements the interface but has no mapping yet: the
	// interface was never created, or was already deleted.
	ctrl := &namingController{found: false}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	if got := mgr.OSInterfaceName(); got != "plexd0" {
		t.Errorf("OSInterfaceName() = %q, want %q", got, "plexd0")
	}
}

func TestManager_OSInterfaceName_NilController(t *testing.T) {
	// plexd up builds a Manager even where newWGController returns nil, so the
	// type assertion has to survive a nil controller rather than panic.
	mgr := NewManager(nil, Config{}, discardLogger())

	if got := mgr.OSInterfaceName(); got != "plexd0" {
		t.Errorf("OSInterfaceName() = %q, want %q", got, "plexd0")
	}
}

// statsController is a mockController that can also read peer runtime state,
// the shape every production controller has. It returns stats and err as
// configured and records the interface name it was asked for.
type statsController struct {
	mockController
	stats []PeerStat
	err   error
}

func (c *statsController) PeerStats(name string) ([]PeerStat, error) {
	c.mu.Lock()
	c.calls = append(c.calls, mockCall{Method: "PeerStats", Args: []interface{}{name}})
	c.mu.Unlock()
	return c.stats, c.err
}

// keyedPeer returns testPeer(id) carrying key as its public key. testPeer
// gives every peer the same all-zero key, which the reverse index leaves out
// as shared.
func keyedPeer(id, b64Key string) api.Peer {
	p := testPeer(id)
	p.PublicKey = b64Key
	return p
}

func TestManager_MeshPeerStats_MapsIndexedPeers(t *testing.T) {
	keyA, b64A := testKey(0x0a)
	keyB, b64B := testKey(0x0b)
	rotatedOut, b64RotatedOut := testKey(0x0c)

	ctrl := &statsController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	if err := mgr.AddPeer(keyedPeer("node-a", b64A)); err != nil {
		t.Fatalf("AddPeer(node-a): %v", err)
	}
	// node-b rotated its key: the index holds the new one, while the device
	// still carries the old key next to it.
	if err := mgr.AddPeer(keyedPeer("node-b", b64RotatedOut)); err != nil {
		t.Fatalf("AddPeer(node-b): %v", err)
	}
	if err := mgr.UpdatePeer(keyedPeer("node-b", b64B)); err != nil {
		t.Fatalf("UpdatePeer(node-b): %v", err)
	}

	handshake := time.Unix(1700000000, 0)
	ctrl.stats = []PeerStat{
		{PublicKey: keyB, Endpoint: netip.MustParseAddrPort("[2001:db8::7]:51820"), RxBytes: 10, TxBytes: 20},
		{PublicKey: rotatedOut, Endpoint: netip.MustParseAddrPort("203.0.113.9:51820"), LastHandshake: handshake, RxBytes: 1, TxBytes: 2},
		{PublicKey: keyA, Endpoint: netip.MustParseAddrPort("198.51.100.7:51820"), LastHandshake: handshake, RxBytes: 2048, TxBytes: 1024},
	}

	got, err := mgr.MeshPeerStats()
	if err != nil {
		t.Fatalf("MeshPeerStats: %v", err)
	}

	// Sorted by NodeID, the rotated-out key dropped, and node-b kept although
	// it never completed a handshake.
	want := []MeshPeerStat{
		{NodeID: "node-a", Endpoint: netip.MustParseAddrPort("198.51.100.7:51820"), LastHandshake: handshake, RxBytes: 2048, TxBytes: 1024},
		{NodeID: "node-b", Endpoint: netip.MustParseAddrPort("[2001:db8::7]:51820"), RxBytes: 10, TxBytes: 20},
	}
	assertMeshPeerStats(t, got, want)

	calls := ctrl.callsFor("PeerStats")
	if len(calls) != 1 || calls[0].Args[0] != "plexd0" {
		t.Errorf("PeerStats calls = %v, want one for plexd0", calls)
	}
}

func TestManager_MeshPeerStats_NothingMaps(t *testing.T) {
	unindexed, _ := testKey(0x0d)

	for _, tc := range []struct {
		name  string
		stats []PeerStat
	}{
		{name: "device without peers", stats: nil},
		{name: "only unindexed peers", stats: []PeerStat{{PublicKey: unindexed}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := &statsController{stats: tc.stats}
			mgr := NewManager(ctrl, Config{}, discardLogger())

			got, err := mgr.MeshPeerStats()
			if err != nil {
				t.Fatalf("MeshPeerStats: %v", err)
			}
			if got == nil || len(got) != 0 {
				t.Errorf("MeshPeerStats() = %#v, want an empty non-nil slice", got)
			}
		})
	}
}

func TestManager_MeshPeerStats_Unsupported(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctrl WGController
	}{
		// mockController does not implement PeerStatsReader.
		{name: "controller without PeerStats", ctrl: &mockController{}},
		// plexd up builds a Manager even where newWGController returns nil.
		{name: "nil controller", ctrl: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewManager(tc.ctrl, Config{}, discardLogger())

			got, err := mgr.MeshPeerStats()
			if !errors.Is(err, ErrPeerStatsUnsupported) {
				t.Fatalf("MeshPeerStats() error = %v, want ErrPeerStatsUnsupported", err)
			}
			if got != nil {
				t.Errorf("MeshPeerStats() = %v, want nil with the error", got)
			}
		})
	}
}

func TestManager_MeshPeerStats_ReadError(t *testing.T) {
	readErr := errors.New("netlink: boom")
	ctrl := &statsController{err: readErr}
	mgr := NewManager(ctrl, Config{}, discardLogger())

	_, err := mgr.MeshPeerStats()
	if !errors.Is(err, readErr) {
		t.Fatalf("MeshPeerStats() error = %v, want it to wrap %v", err, readErr)
	}
	if want := "wireguard: mesh peer stats: netlink: boom"; err.Error() != want {
		t.Errorf("MeshPeerStats() error = %q, want %q", err, want)
	}
}

// assertMeshPeerStats compares mesh peer stats field by field, the handshake
// time with time.Time.Equal.
func assertMeshPeerStats(t *testing.T, got, want []MeshPeerStat) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d mesh peer stats, want %d:\ngot  %+v\nwant %+v", len(got), len(want), got, want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.NodeID != w.NodeID || g.Endpoint != w.Endpoint ||
			!g.LastHandshake.Equal(w.LastHandshake) || g.RxBytes != w.RxBytes || g.TxBytes != w.TxBytes {
			t.Errorf("mesh peer stat %d:\ngot  %+v\nwant %+v", i, g, w)
		}
	}
}

// ---------------------------------------------------------------------------
// SetPeerPSK
// ---------------------------------------------------------------------------

func TestManager_SetPeerPSK(t *testing.T) {
	_, b64A := testKey(0x0a)
	psk := bytes.Repeat([]byte{0x42}, 32)

	t.Run("programmed peer", func(t *testing.T) {
		ctrl := &mockController{}
		mgr := NewManager(ctrl, Config{}, discardLogger())
		if err := mgr.AddPeer(keyedPeer("node-a", b64A)); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		if err := mgr.SetPeerPSK("node-a", b64A, psk); err != nil {
			t.Fatalf("SetPeerPSK: %v", err)
		}
		calls := ctrl.callsFor("AddPeer")
		if len(calls) != 2 {
			t.Fatalf("AddPeer calls = %d, want 2", len(calls))
		}
		cfg := calls[1].Args[1].(PeerConfig)
		if !bytes.Equal(cfg.PSK, psk) {
			t.Error("the write does not carry the PSK")
		}
		if len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0] != "10.0.0.2/32" {
			t.Errorf("AllowedIPs = %v, want the recorded [10.0.0.2/32]", cfg.AllowedIPs)
		}
		if cfg.Endpoint != "" {
			t.Errorf("Endpoint = %q, want empty so the device keeps its endpoint", cfg.Endpoint)
		}
		// Both controllers write the keepalive on every call, so a PSK write
		// without it would clear the peer's keepalive.
		if cfg.PersistentKeepalive != 25 {
			t.Errorf("PersistentKeepalive = %d, want the default 25", cfg.PersistentKeepalive)
		}
	})

	t.Run("unknown node and another public key", func(t *testing.T) {
		ctrl := &mockController{}
		mgr := NewManager(ctrl, Config{}, discardLogger())
		if err := mgr.AddPeer(keyedPeer("node-a", b64A)); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		_, b64Other := testKey(0x0b)
		if err := mgr.SetPeerPSK("node-unknown", b64A, psk); err != nil {
			t.Errorf("SetPeerPSK(unknown node) = %v, want nil", err)
		}
		if err := mgr.SetPeerPSK("node-a", b64Other, psk); err != nil {
			t.Errorf("SetPeerPSK(another public key) = %v, want nil", err)
		}
		if n := len(ctrl.callsFor("AddPeer")); n != 1 {
			t.Errorf("AddPeer calls = %d, want no write beyond the AddPeer", n)
		}
	})

	t.Run("controller error", func(t *testing.T) {
		ctrl := &mockController{}
		mgr := NewManager(ctrl, Config{}, discardLogger())
		if err := mgr.AddPeer(keyedPeer("node-a", b64A)); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		ctrl.addPeerErr = errors.New("netlink: busy")
		err := mgr.SetPeerPSK("node-a", b64A, psk)
		if err == nil || !strings.HasPrefix(err.Error(), "wireguard: set peer psk:") {
			t.Errorf("err = %v, want it wrapped as wireguard: set peer psk:", err)
		}
	})

	t.Run("removed peer", func(t *testing.T) {
		ctrl := &mockController{}
		mgr := NewManager(ctrl, Config{}, discardLogger())
		if err := mgr.AddPeer(keyedPeer("node-a", b64A)); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		if err := mgr.RemovePeerByID("node-a"); err != nil {
			t.Fatalf("RemovePeerByID: %v", err)
		}
		if err := mgr.SetPeerPSK("node-a", b64A, psk); err != nil {
			t.Errorf("SetPeerPSK after removal = %v, want nil", err)
		}
		if n := len(ctrl.callsFor("AddPeer")); n != 1 {
			t.Errorf("AddPeer calls = %d, want no write for a removed peer", n)
		}
	})
}

func TestManager_SetPeerPSK_ConcurrentWithUpdatePeer(t *testing.T) {
	_, b64A := testKey(0x0a)
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, discardLogger())
	peer := keyedPeer("node-a", b64A)
	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			_ = mgr.SetPeerPSK("node-a", b64A, bytes.Repeat([]byte{0x42}, 32))
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			_ = mgr.UpdatePeer(peer)
		}
	}()
	wg.Wait()
}
