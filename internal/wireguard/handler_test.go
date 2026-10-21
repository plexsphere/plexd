package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
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

	handler := ReconcileHandler(mgr, nil)
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

	handler := ReconcileHandler(mgr, nil)
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

	handler := ReconcileHandler(mgr, nil)
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

	handler := ReconcileHandler(mgr, nil)
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

	handler := ReconcileHandler(mgr, nil)
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

	handler := ReconcileHandler(mgr, nil)
	err := handler(context.Background(), nil, diff)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

// ---------------------------------------------------------------------------
// Endpoint selection
// ---------------------------------------------------------------------------

// testMesh is the Domain mesh prefix the endpoint selection tests run under.
var testMesh = netip.MustParsePrefix("10.99.0.0/24")

func TestProgrammedEndpoint_UsableDirectEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{"ipv4", "198.51.100.7:51820", "198.51.100.7:51820"},
		{"ipv6", "[2001:db8::7]:51820", "[2001:db8::7]:51820"},
		{"ipv4-mapped ipv6 is unmapped", "[::ffff:10.0.0.5]:51820", "10.0.0.5:51820"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := api.SnapshotPeer{Endpoint: tt.endpoint, FallbackEndpoint: "203.0.113.1:51820"}
			got, rejected := ProgrammedEndpoint(p, testMesh)
			if got != tt.want || rejected {
				t.Errorf("ProgrammedEndpoint(%q) = (%q, %v), want (%q, false)", tt.endpoint, got, rejected, tt.want)
			}
		})
	}
}

func TestProgrammedEndpoint_EmptyEndpointUsesFallback(t *testing.T) {
	p := api.SnapshotPeer{FallbackEndpoint: "203.0.113.1:51820"}
	got, rejected := ProgrammedEndpoint(p, testMesh)
	if got != "203.0.113.1:51820" || rejected {
		t.Errorf("ProgrammedEndpoint() = (%q, %v), want (%q, false): an absent endpoint is not a rejection", got, rejected, "203.0.113.1:51820")
	}
}

func TestProgrammedEndpoint_RejectsUnusableEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"not-an-endpoint",
		"198.51.100.7:0",
		"0.0.0.0:51820",
		"127.0.0.1:51820",
		"224.0.0.1:51820",
		"169.254.1.1:51820",
		"[fe80::1%eth0]:51820",
		"10.99.0.4:51820", // inside the mesh prefix
	} {
		t.Run(endpoint, func(t *testing.T) {
			p := api.SnapshotPeer{Endpoint: endpoint, FallbackEndpoint: "203.0.113.1:51820"}
			got, rejected := ProgrammedEndpoint(p, testMesh)
			if got != "203.0.113.1:51820" || !rejected {
				t.Errorf("ProgrammedEndpoint(%q) = (%q, %v), want the fallback with directRejected true", endpoint, got, rejected)
			}

			p.FallbackEndpoint = ""
			got, rejected = ProgrammedEndpoint(p, testMesh)
			if got != "" || !rejected {
				t.Errorf("ProgrammedEndpoint(%q) without a fallback = (%q, %v), want (\"\", true)", endpoint, got, rejected)
			}
		})
	}
}

func TestProgrammedEndpoint_ZeroMeshSkipsMeshCheck(t *testing.T) {
	p := api.SnapshotPeer{Endpoint: "10.99.0.4:51820", FallbackEndpoint: "203.0.113.1:51820"}
	got, rejected := ProgrammedEndpoint(p, netip.Prefix{})
	if got != "10.99.0.4:51820" || rejected {
		t.Errorf("ProgrammedEndpoint() with a zero mesh = (%q, %v), want (%q, false)", got, rejected, "10.99.0.4:51820")
	}
}

// setupMeshManager returns a manager set up for an identity in testMesh, so
// MeshPrefix holds the prefix the handler validates endpoints against.
func setupMeshManager(t *testing.T, ctrl WGController, logger *slog.Logger) *Manager {
	t.Helper()
	mgr := NewManager(ctrl, Config{}, logger)
	identity := testIdentity()
	identity.MeshIP = "10.99.0.5"
	identity.DomainMeshCIDR = testMesh.String()
	if err := mgr.Setup(context.Background(), identity); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return mgr
}

// addPeerConfigs returns the PeerConfig of every AddPeer call ctrl recorded.
func addPeerConfigs(t *testing.T, ctrl *mockController) []PeerConfig {
	t.Helper()
	var cfgs []PeerConfig
	for _, call := range ctrl.callsFor("AddPeer") {
		cfg, ok := call.Args[1].(PeerConfig)
		if !ok {
			t.Fatalf("AddPeer arg = %T, want PeerConfig", call.Args[1])
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs
}

func TestReconcileHandler_ProgramsDirectEndpoint(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	handler := ReconcileHandler(mgr, nil)

	peer := snapshotPeer("peer-1", "10.99.0.2", "203.0.113.1:51820")
	peer.Endpoint = "198.51.100.7:51820"
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	peer.Endpoint = "198.51.100.8:51820"
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("update: %v", err)
	}

	cfgs := addPeerConfigs(t, ctrl)
	if len(cfgs) != 2 {
		t.Fatalf("AddPeer calls = %d, want 2", len(cfgs))
	}
	if cfgs[0].Endpoint != "198.51.100.7:51820" {
		t.Errorf("added Endpoint = %q, want the direct endpoint", cfgs[0].Endpoint)
	}
	if cfgs[1].Endpoint != "198.51.100.8:51820" {
		t.Errorf("updated Endpoint = %q, want the new direct endpoint", cfgs[1].Endpoint)
	}
}

func TestReconcileHandler_WarnsOnRejectedEndpoint(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, slogTextLogger(&logs))
	handler := ReconcileHandler(mgr, nil)

	peer := snapshotPeer("peer-1", "10.99.0.2", "203.0.113.1:51820")
	peer.Endpoint = "10.99.0.4:51820"
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	cfgs := addPeerConfigs(t, ctrl)
	if len(cfgs) != 1 || cfgs[0].Endpoint != "203.0.113.1:51820" {
		t.Fatalf("AddPeer configs = %+v, want one programming the fallback", cfgs)
	}
	out := logs.String()
	for _, want := range []string{
		"peer direct endpoint unusable, leaving it out of the dial order",
		"level=WARN",
		"endpoint=10.99.0.4:51820",
		"fallback=203.0.113.1:51820",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
}

// stubPSKs is an EdgePSKLookup holding one PSK for one (node ID, public key).
type stubPSKs struct {
	nodeID, publicKey string
	psk               []byte
}

func (s stubPSKs) Lookup(peerNodeID, publicKey string) ([]byte, bool) {
	if peerNodeID == s.nodeID && publicKey == s.publicKey {
		return s.psk, true
	}
	return nil, false
}

func TestReconcileHandler_ProgramsLookedUpPSK(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	peer := snapshotPeer("peer-1", "10.99.0.2", "203.0.113.1:51820")

	tests := []struct {
		name    string
		psks    EdgePSKLookup
		wantPSK []byte
	}{
		{"psk for the peer's current key", stubPSKs{nodeID: "peer-1", publicKey: peer.PublicKey, psk: psk}, psk},
		{"psk for another key", stubPSKs{nodeID: "peer-1", publicKey: "another-key", psk: psk}, nil},
		{"nil lookup", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &mockController{}
			mgr := setupMeshManager(t, ctrl, discardLogger())
			handler := ReconcileHandler(mgr, tt.psks)
			if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
				t.Fatalf("add: %v", err)
			}
			cfgs := addPeerConfigs(t, ctrl)
			if len(cfgs) != 1 {
				t.Fatalf("AddPeer calls = %d, want 1", len(cfgs))
			}
			if !bytes.Equal(cfgs[0].PSK, tt.wantPSK) {
				t.Errorf("PSK = %x, want %x", cfgs[0].PSK, tt.wantPSK)
			}
		})
	}
}
