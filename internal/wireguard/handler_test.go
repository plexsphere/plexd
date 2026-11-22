package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

func newTestManager(ctrl WGController) *Manager {
	return NewManager(ctrl, Config{}, discardLogger())
}

// ---------------------------------------------------------------------------
// ReconcileHandler tests
// ---------------------------------------------------------------------------

// snapshotPeer builds an api.SnapshotPeer with a valid 32-byte base64 key,
// fallback as its fallback_endpoint and relays as its fallback_endpoints.
func snapshotPeer(nodeID, meshIP, fallback string, relays ...string) api.SnapshotPeer {
	return api.SnapshotPeer{
		NodeID:            nodeID,
		MeshIP:            meshIP,
		PublicKey:         base64.StdEncoding.EncodeToString(make([]byte, 32)),
		FallbackEndpoint:  fallback,
		FallbackEndpoints: relays,
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

	// peer-unknown is absent from the index, so it is already gone: the
	// removal succeeds and the controller is never touched. A failed run
	// hands the same removal over again, after the peer left the index (see
	// TestReconcileHandler_RemovalAppliedAgainAfterARouteFailure).
	diff := reconcile.StateDiff{PeersToRemove: []string{"peer-unknown"}}

	handler := ReconcileHandler(mgr, nil)
	if err := handler(context.Background(), nil, diff); err != nil {
		t.Fatalf("removal of a peer the index does not hold = %v, want nil", err)
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

// ---------------------------------------------------------------------------
// Routed subnets
// ---------------------------------------------------------------------------

func TestUsableRoutedSubnets(t *testing.T) {
	local := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}

	tests := []struct {
		name         string
		subnets      []string
		mesh         netip.Prefix
		wantAccepted []string
		wantSkipped  []skippedSubnet
	}{
		{
			name:         "a network behind the peer",
			subnets:      []string{"10.20.0.0/16"},
			mesh:         testMesh,
			wantAccepted: []string{"10.20.0.0/16"},
		},
		{
			name:        "host bits set",
			subnets:     []string{"10.20.0.1/16"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"10.20.0.1/16", "invalid"}},
		},
		{
			name:        "ipv6",
			subnets:     []string{"fd00::/64"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"fd00::/64", "invalid"}},
		},
		{
			name:        "ipv4-mapped ipv6",
			subnets:     []string{"::ffff:10.20.0.0/112"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"::ffff:10.20.0.0/112", "invalid"}},
		},
		{
			name:        "not a prefix",
			subnets:     []string{"not-a-prefix"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"not-a-prefix", "invalid"}},
		},
		{
			name:        "inside the mesh",
			subnets:     []string{"10.99.0.0/25"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"10.99.0.0/25", "overlaps_mesh"}},
		},
		{
			name:        "around the mesh",
			subnets:     []string{"0.0.0.0/0"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"0.0.0.0/0", "overlaps_mesh"}},
		},
		{
			name:         "a zero mesh skips the mesh check",
			subnets:      []string{"10.99.0.0/25"},
			wantAccepted: []string{"10.99.0.0/25"},
		},
		{
			name:        "a local network",
			subnets:     []string{"192.168.1.0/24"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"192.168.1.0/24", "inside_local_network"}},
		},
		{
			name:        "inside a local network",
			subnets:     []string{"192.168.1.128/25"},
			mesh:        testMesh,
			wantSkipped: []skippedSubnet{{"192.168.1.128/25", "inside_local_network"}},
		},
		{
			name:         "around a local network",
			subnets:      []string{"192.168.0.0/16"},
			mesh:         testMesh,
			wantAccepted: []string{"192.168.0.0/16"},
		},
		{
			name:         "repeated",
			subnets:      []string{"10.20.0.0/16", "10.30.0.0/16", "10.20.0.0/16"},
			mesh:         testMesh,
			wantAccepted: []string{"10.20.0.0/16", "10.30.0.0/16"},
			wantSkipped:  []skippedSubnet{{"10.20.0.0/16", "duplicate"}},
		},
		{
			name:         "the list's order is kept",
			subnets:      []string{"10.30.0.0/16", "10.99.0.0/25", "10.20.0.0/16", "not-a-prefix", "10.21.0.0/16"},
			mesh:         testMesh,
			wantAccepted: []string{"10.30.0.0/16", "10.20.0.0/16", "10.21.0.0/16"},
			wantSkipped:  []skippedSubnet{{"10.99.0.0/25", "overlaps_mesh"}, {"not-a-prefix", "invalid"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accepted, skipped := usableRoutedSubnets(tt.subnets, tt.mesh, local)
			if !slices.Equal(accepted, tt.wantAccepted) {
				t.Errorf("accepted = %v, want %v", accepted, tt.wantAccepted)
			}
			if !slices.Equal(skipped, tt.wantSkipped) {
				t.Errorf("skipped = %v, want %v", skipped, tt.wantSkipped)
			}
		})
	}

	for name, subnets := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			accepted, skipped := usableRoutedSubnets(subnets, testMesh, local)
			if len(accepted) != 0 || len(skipped) != 0 {
				t.Errorf("usableRoutedSubnets(%#v) = (%v, %v), want two empty lists", subnets, accepted, skipped)
			}
		})
	}
}

// routedPeer returns a snapshot peer without endpoints whose public key is
// testKey(key) and whose routed_subnets are subnets.
func routedPeer(nodeID, meshIP string, key byte, subnets ...string) api.SnapshotPeer {
	p := snapshotPeer(nodeID, meshIP, "")
	_, p.PublicKey = testKey(key)
	p.RoutedSubnets = subnets
	return p
}

// routeCalls returns the route calls ctrl recorded through a mockRouter, as
// "AddRoute <subnet> <iface>" and "RemoveRoute <subnet> <iface>".
func routeCalls(ctrl *mockController) []string {
	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	var calls []string
	for _, c := range ctrl.calls {
		if c.Method == "AddRoute" || c.Method == "RemoveRoute" {
			calls = append(calls, fmt.Sprintf("%s %s %s", c.Method, c.Args[0], c.Args[1]))
		}
	}
	return calls
}

// callCount returns how many calls ctrl recorded, its device calls and the
// route calls of a mockRouter over it together.
func callCount(ctrl *mockController) int {
	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	return len(ctrl.calls)
}

// lastAllowedIPs returns the allowed IPs of the last AddPeer call ctrl
// recorded.
func lastAllowedIPs(t *testing.T, ctrl *mockController) []string {
	t.Helper()
	cfgs := addPeerConfigs(t, ctrl)
	if len(cfgs) == 0 {
		t.Fatal("no AddPeer call recorded")
	}
	return cfgs[len(cfgs)-1].AllowedIPs
}

func TestReconcileHandler_RoutesRoutedSubnets(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, slogTextLogger(&logs))
	mgr.SetPeerRouter(&mockRouter{ctrl: ctrl})
	handler := ReconcileHandler(mgr, nil)
	ctx := context.Background()

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got, want := lastAllowedIPs(t, ctrl), []string{"10.99.0.2/32", "10.20.0.0/16"}; !slices.Equal(got, want) {
		t.Errorf("AllowedIPs = %v, want %v", got, want)
	}
	if got, want := routeCalls(ctrl), []string{"AddRoute 10.20.0.0/16 plexd0"}; !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
	if out := logs.String(); !strings.Contains(out, `level=INFO msg="wireguard: peer routes changed" component=wireguard added=[10.20.0.0/16] removed=[]`) {
		t.Errorf("log does not name the added route:\n%s", out)
	}

	// The same snapshot again: the reconciler's diff is empty, and the
	// handler touches neither the device nor a route.
	before := callCount(ctrl)
	logs.Reset()
	if err := handler(ctx, nil, reconcile.StateDiff{}); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	if after := callCount(ctrl); after != before {
		t.Errorf("calls after an unchanged run = %d, want the %d before it", after, before)
	}
	if strings.Contains(logs.String(), "peer routes changed") {
		t.Errorf("an unchanged run logged a route change:\n%s", logs.String())
	}

	// The member is gone: the route goes, and the peer is written with its
	// mesh address alone.
	peer.RoutedSubnets = nil
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got, want := lastAllowedIPs(t, ctrl), []string{"10.99.0.2/32"}; !slices.Equal(got, want) {
		t.Errorf("AllowedIPs after the member is gone = %v, want %v", got, want)
	}
	if got, want := routeCalls(ctrl), []string{"AddRoute 10.20.0.0/16 plexd0", "RemoveRoute 10.20.0.0/16 plexd0"}; !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
	if out := logs.String(); !strings.Contains(out, "added=[] removed=[10.20.0.0/16]") {
		t.Errorf("log does not name the removed route:\n%s", out)
	}
}

func TestReconcileHandler_PeerRoutesOnOSInterfaceName(t *testing.T) {
	ctrl := &namingController{osName: "utun7", found: true}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	mgr.SetPeerRouter(&mockRouter{ctrl: &ctrl.mockController})
	handler := ReconcileHandler(mgr, nil)

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got, want := routeCalls(&ctrl.mockController), []string{"AddRoute 10.20.0.0/16 utun7"}; !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v: route(8) takes the kernel's name", got, want)
	}
}

func TestReconcileHandler_SkipsUnusableRoutedSubnets(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, slogTextLogger(&logs))
	mgr.SetLocalPrefixes(func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
	})
	mgr.SetPeerRouter(&mockRouter{ctrl: ctrl})
	handler := ReconcileHandler(mgr, nil)

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.99.0.0/25", "192.168.1.0/24", "10.20.0.0/16", "10.20.0.0/16")
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got, want := lastAllowedIPs(t, ctrl), []string{"10.99.0.2/32", "10.20.0.0/16"}; !slices.Equal(got, want) {
		t.Errorf("AllowedIPs = %v, want %v", got, want)
	}
	if got, want := routeCalls(ctrl), []string{"AddRoute 10.20.0.0/16 plexd0"}; !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
	out := logs.String()
	for _, want := range []string{
		`level=WARN msg="wireguard: routed subnet not programmed" component=wireguard peer_id=peer-1 subnet=10.99.0.0/25 reason=overlaps_mesh`,
		`level=WARN msg="wireguard: routed subnet not programmed" component=wireguard peer_id=peer-1 subnet=192.168.1.0/24 reason=inside_local_network`,
		`level=WARN msg="wireguard: routed subnet not programmed" component=wireguard peer_id=peer-1 subnet=10.20.0.0/16 reason=duplicate`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
}

func TestReconcileHandler_SharedRoutedSubnet(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	mgr.SetPeerRouter(&mockRouter{ctrl: ctrl})
	handler := ReconcileHandler(mgr, nil)
	ctx := context.Background()

	a := routedPeer("peer-a", "10.99.0.2", 0x0a, "10.20.0.0/16")
	b := routedPeer("peer-b", "10.99.0.3", 0x0b, "10.20.0.0/16", "10.30.0.0/16")
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{a, b}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	want := []string{"AddRoute 10.20.0.0/16 plexd0", "AddRoute 10.30.0.0/16 plexd0"}
	if got := routeCalls(ctrl); !slices.Equal(got, want) {
		t.Fatalf("route calls = %v, want %v: a subnet two peers list is routed once", got, want)
	}

	// peer-a drops the shared subnet: peer-b still lists it.
	a.RoutedSubnets = nil
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{a}}); err != nil {
		t.Fatalf("update peer-a: %v", err)
	}
	if got := routeCalls(ctrl); !slices.Equal(got, want) {
		t.Fatalf("route calls = %v, want %v: the route stays while peer-b lists the subnet", got, want)
	}

	// peer-b drops it too: the route goes.
	b.RoutedSubnets = []string{"10.30.0.0/16"}
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{b}}); err != nil {
		t.Fatalf("update peer-b: %v", err)
	}
	want = append(want, "RemoveRoute 10.20.0.0/16 plexd0")
	if got := routeCalls(ctrl); !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
}

func TestReconcileHandler_SetPeerPSKKeepsRoutedSubnets(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	mgr.SetPeerRouter(&mockRouter{ctrl: ctrl})
	handler := ReconcileHandler(mgr, nil)

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Every device write replaces the allowed IPs, so a PSK write that left
	// the routed subnets out would cut the networks behind the peer off.
	if err := mgr.SetPeerPSK("peer-1", peer.PublicKey, bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatalf("SetPeerPSK: %v", err)
	}
	if n := len(addPeerConfigs(t, ctrl)); n != 2 {
		t.Fatalf("AddPeer calls = %d, want the add and the PSK write", n)
	}
	if got, want := lastAllowedIPs(t, ctrl), []string{"10.99.0.2/32", "10.20.0.0/16"}; !slices.Equal(got, want) {
		t.Errorf("AllowedIPs of the PSK write = %v, want %v", got, want)
	}
}

func TestReconcileHandler_RemovedPeerRemovesRoutes(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	mgr.SetPeerRouter(&mockRouter{ctrl: ctrl})
	handler := ReconcileHandler(mgr, nil)
	ctx := context.Background()

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16", "10.30.0.0/16")
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToRemove: []string{"peer-1"}}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	want := []string{
		"AddRoute 10.20.0.0/16 plexd0",
		"AddRoute 10.30.0.0/16 plexd0",
		"RemoveRoute 10.20.0.0/16 plexd0",
		"RemoveRoute 10.30.0.0/16 plexd0",
	}
	if got := routeCalls(ctrl); !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
}

// TestReconcileHandler_RemovalAppliedAgainAfterARouteFailure removes a peer
// in a run whose route removal fails, so the handler fails and the
// reconciler hands the same removal over again. The second run must remove
// the route and succeed, not fail on the peer the first run removed: that
// would fail every run after it.
func TestReconcileHandler_RemovalAppliedAgainAfterARouteFailure(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	router := &mockRouter{ctrl: ctrl}
	mgr.SetPeerRouter(router)
	handler := ReconcileHandler(mgr, nil)
	ctx := context.Background()

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	routeErr := errors.New("route: writing to routing socket: transient")
	router.removeRouteErr = routeErr
	removal := reconcile.StateDiff{PeersToRemove: []string{"peer-1"}}
	if err := handler(ctx, nil, removal); !errors.Is(err, routeErr) {
		t.Fatalf("first removal = %v, want it to wrap %v", err, routeErr)
	}

	router.removeRouteErr = nil
	if err := handler(ctx, nil, removal); err != nil {
		t.Fatalf("the removal applied again = %v, want nil", err)
	}
	want := []string{
		"AddRoute 10.20.0.0/16 plexd0",
		"RemoveRoute 10.20.0.0/16 plexd0",
		"RemoveRoute 10.20.0.0/16 plexd0",
	}
	if got := routeCalls(ctrl); !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
	if n := len(ctrl.callsFor("RemovePeer")); n != 1 {
		t.Errorf("RemovePeer calls = %d, want 1: the second run finds the peer gone", n)
	}
}

// TestReconcileHandler_KeyRotationRemovesTheOldDevicePeer rotates a peer's
// key in the pull that also drops its routed subnet. WireGuard moves to the
// new key only the allowed IPs its write names, so the device peer of the old
// key would keep the subnet and could still send from it: the old device
// peer is removed before the new one is written. A failed removal changes
// nothing, and the next run tries the rotation again.
func TestReconcileHandler_KeyRotationRemovesTheOldDevicePeer(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	mgr.SetPeerRouter(&mockRouter{ctrl: ctrl})
	handler := ReconcileHandler(mgr, nil)
	ctx := context.Background()

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	oldKey, _ := testKey(0x0a)

	rotated := routedPeer("peer-1", "10.99.0.2", 0x0b)
	removeErr := errors.New("remove device peer: transient")
	ctrl.mu.Lock()
	ctrl.removePeerErr = removeErr
	ctrl.calls = nil
	ctrl.mu.Unlock()
	update := reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{rotated}}
	if err := handler(ctx, nil, update); !errors.Is(err, removeErr) {
		t.Fatalf("rotation with a failing removal = %v, want it to wrap %v", err, removeErr)
	}
	if n := len(ctrl.callsFor("AddPeer")); n != 0 {
		t.Fatalf("AddPeer calls after a failed removal = %d, want 0: the new key must not be written", n)
	}

	ctrl.mu.Lock()
	ctrl.removePeerErr = nil
	ctrl.calls = nil
	ctrl.mu.Unlock()
	if err := handler(ctx, nil, update); err != nil {
		t.Fatalf("rotation applied again: %v", err)
	}
	var order []string
	for _, c := range ctrl.callsFor("RemovePeer") {
		if !bytes.Equal(c.Args[1].([]byte), oldKey[:]) {
			t.Errorf("RemovePeer key = %x, want the old key %x", c.Args[1], oldKey[:])
		}
	}
	ctrl.mu.Lock()
	for _, c := range ctrl.calls {
		if c.Method == "RemovePeer" || c.Method == "AddPeer" {
			order = append(order, c.Method)
		}
	}
	ctrl.mu.Unlock()
	if want := []string{"RemovePeer", "AddPeer"}; !slices.Equal(order, want) {
		t.Errorf("device writes = %v, want %v", order, want)
	}
	if got, want := lastAllowedIPs(t, ctrl), []string{"10.99.0.2/32"}; !slices.Equal(got, want) {
		t.Errorf("AllowedIPs of the new key = %v, want %v", got, want)
	}
	if got, want := routeCalls(ctrl), []string{"RemoveRoute 10.20.0.0/16 plexd0"}; !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
}

func TestReconcileHandler_PeerRouteFailure(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, slogTextLogger(&logs))
	routeErr := errors.New("route: writing to routing socket: Network is unreachable")
	router := &mockRouter{ctrl: ctrl, addRouteErr: routeErr}
	mgr.SetPeerRouter(router)
	handler := ReconcileHandler(mgr, nil)
	ctx := context.Background()

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
	err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}})
	if !errors.Is(err, routeErr) {
		t.Fatalf("handler error = %v, want it to wrap %v", err, routeErr)
	}
	// The peer is on the device all the same: the route failed, not the write.
	if got, want := lastAllowedIPs(t, ctrl), []string{"10.99.0.2/32", "10.20.0.0/16"}; !slices.Equal(got, want) {
		t.Errorf("AllowedIPs = %v, want %v", got, want)
	}
	out := logs.String()
	for _, want := range []string{
		`level=ERROR msg="wireguard: peer route failed" component=wireguard subnet=10.20.0.0/16 op=add`,
		"Network is unreachable",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "peer routes changed") {
		t.Errorf("a run that changed no route logged a change:\n%s", out)
	}

	// The failed subnet stays unprogrammed, so the next run adds it again.
	router.addRouteErr = nil
	if err := handler(ctx, nil, reconcile.StateDiff{}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	want := []string{"AddRoute 10.20.0.0/16 plexd0", "AddRoute 10.20.0.0/16 plexd0"}
	if got := routeCalls(ctrl); !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}

	// A failed remove keeps the route programmed, and the next run removes
	// it again.
	router.removeRouteErr = routeErr
	peer.RoutedSubnets = nil
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{peer}}); !errors.Is(err, routeErr) {
		t.Fatalf("handler error = %v, want it to wrap %v", err, routeErr)
	}
	router.removeRouteErr = nil
	if err := handler(ctx, nil, reconcile.StateDiff{}); err != nil {
		t.Fatalf("retry remove: %v", err)
	}
	want = append(want, "RemoveRoute 10.20.0.0/16 plexd0", "RemoveRoute 10.20.0.0/16 plexd0")
	if got := routeCalls(ctrl); !slices.Equal(got, want) {
		t.Errorf("route calls = %v, want %v", got, want)
	}
}

func TestReconcileHandler_NoPeerRouter(t *testing.T) {
	ctrl := &mockController{}
	mgr := setupMeshManager(t, ctrl, discardLogger())
	handler := ReconcileHandler(mgr, nil)

	peer := routedPeer("peer-1", "10.99.0.2", 0x0a, "10.20.0.0/16")
	if err := handler(context.Background(), nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("add without a router = %v, want nil", err)
	}
	if got, want := lastAllowedIPs(t, ctrl), []string{"10.99.0.2/32", "10.20.0.0/16"}; !slices.Equal(got, want) {
		t.Errorf("AllowedIPs = %v, want %v", got, want)
	}
	if got := routeCalls(ctrl); len(got) != 0 {
		t.Errorf("route calls = %v, want none", got)
	}
}

// TestReconcileHandler_NewCandidateStartsADirectRetry runs the direct retry
// through the handler. A pull that adds an endpoint candidate to a peer
// connected over its relay writes the candidate on a fresh device peer, and a
// pull that withdraws it again during the retry dials the relay at once,
// whether its endpoint_candidates is nil or empty.
func TestReconcileHandler_NewCandidateStartsADirectRetry(t *testing.T) {
	const relay, candidate = "203.0.113.1:51820", "192.0.2.44:51820"
	key, b64 := testKey(0x0a)
	ctx := context.Background()
	update := func(t *testing.T, handler reconcile.ReconcileHandler, peer api.SnapshotPeer) {
		t.Helper()
		if err := handler(ctx, nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{peer}}); err != nil {
			t.Fatalf("update: %v", err)
		}
	}
	start := func(t *testing.T) (*Manager, *statsController, reconcile.ReconcileHandler, api.SnapshotPeer) {
		t.Helper()
		var logs bytes.Buffer
		mgr, ctrl, clock := newSelectionManager(Config{}, &logs)
		handler := ReconcileHandler(mgr, nil)
		peer := snapshotPeer("peer-1", "10.99.0.2", relay)
		peer.PublicKey = b64
		if err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
			t.Fatalf("add: %v", err)
		}
		ctrl.stats = []PeerStat{{
			PublicKey:     key,
			Endpoint:      netip.MustParseAddrPort(relay),
			LastHandshake: selectionStart.Add(5 * time.Second),
		}}
		passAt(t, mgr, clock, 5*time.Second)
		if st := mgr.dial["peer-1"]; !st.connected || !st.relayed {
			t.Fatalf("after the handshake over the relay connected = %v, relayed = %v, want both", st.connected, st.relayed)
		}

		peer.EndpointCandidates = []string{candidate}
		before := len(deviceWrites(ctrl))
		clock.Set(selectionStart.Add(10 * time.Second))
		update(t, handler, peer)
		if got, want := deviceWrites(ctrl)[before:], []string{"remove", "add " + candidate}; !slices.Equal(got, want) {
			t.Fatalf("device writes for the new candidate = %v, want %v", got, want)
		}
		return mgr, ctrl, handler, peer
	}

	for _, tc := range []struct {
		name       string
		candidates []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr, ctrl, handler, peer := start(t)
			peer.EndpointCandidates = tc.candidates
			before := len(deviceWrites(ctrl))
			update(t, handler, peer)
			if got, want := deviceWrites(ctrl)[before:], []string{"remove", "add " + relay}; !slices.Equal(got, want) {
				t.Errorf("device writes after the candidate was withdrawn = %v, want %v", got, want)
			}
			if st := mgr.dial["peer-1"]; !st.relayed {
				t.Error("relayed = false after the candidate was withdrawn, want true")
			}
		})
	}
}

func TestFailureDetectionDispatchHandler(t *testing.T) {
	const (
		setMsg       = "wireguard: failure detection time set"
		rangeMsg     = "wireguard: failure detection time out of range"
		malformedMsg = "wireguard: failure detection block malformed"
	)
	// newHandler returns a handler on a fresh manager that logs into logs.
	newHandler := func(logs *bytes.Buffer) (*Manager, reconcile.DispatchHandler) {
		mgr, _, _ := newSelectionManager(Config{}, logs)
		return mgr, FailureDetectionDispatchHandler(mgr)
	}
	pull := func(h reconcile.DispatchHandler, block string) {
		snap := &api.NodeStateSnapshot{}
		if block != "" {
			snap.FailureDetection = json.RawMessage(block)
		}
		h(context.Background(), snap)
	}
	requireHeld := func(t *testing.T, mgr *Manager, want time.Duration) {
		t.Helper()
		if d, held := mgr.FailureDetection(); d != want || held != (want > 0) {
			t.Errorf("FailureDetection() = %v, %v, want %v, %v", d, held, want, want > 0)
		}
	}
	// holding15 returns a handler whose manager holds 15 s from a first pull,
	// with the log of that pull dropped.
	holding15 := func(t *testing.T, logs *bytes.Buffer) (*Manager, reconcile.DispatchHandler) {
		t.Helper()
		mgr, h := newHandler(logs)
		pull(h, `{"detect_after_seconds":15}`)
		requireHeld(t, mgr, 15*time.Second)
		logs.Reset()
		return mgr, h
	}

	t.Run("a value in range", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, h := newHandler(&logs)
		pull(h, `{"detect_after_seconds":15}`)
		requireHeld(t, mgr, 15*time.Second)
		requireLogLine(t, logs.String(), setMsg, "level=INFO", "component=wireguard", "detect_after=15s", "previous=0s", "pass=1s")
		pull(h, `{"detect_after_seconds":15}`)
		if n := len(logLines(logs.String(), setMsg)); n != 1 {
			t.Errorf("%d set lines after a pull that repeats the value, want 1:\n%s", n, logs.String())
		}
		if lines := strings.Count(logs.String(), "\n"); lines != 1 {
			t.Errorf("%d lines for two pulls of one value, want 1:\n%s", lines, logs.String())
		}
	})

	t.Run("absent and null", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, h := holding15(t, &logs)
		pull(h, "")
		pull(h, "null")
		h(context.Background(), nil)
		requireHeld(t, mgr, 15*time.Second)
		if logs.Len() != 0 {
			t.Errorf("an absent block, a null and no snapshot logged:\n%s", logs.String())
		}
	})

	for _, tt := range []struct{ block, raw string }{
		{`{}`, "0"},
		{`{"detect_after_seconds":0}`, "0"},
		{`{"detect_after_seconds":-5}`, "-5"},
	} {
		t.Run("zero or less "+tt.block, func(t *testing.T) {
			var logs bytes.Buffer
			mgr, h := holding15(t, &logs)
			pull(h, tt.block)
			requireHeld(t, mgr, 15*time.Second)
			requireLogLine(t, logs.String(), rangeMsg, "level=WARN", "component=wireguard", "detect_after_seconds="+tt.raw)
			if strings.Contains(logs.String(), "applied=") || len(logLines(logs.String(), setMsg)) != 0 {
				t.Errorf("a value of %s applied something:\n%s", tt.raw, logs.String())
			}
		})
	}

	t.Run("clamped", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, h := newHandler(&logs)
		for _, tt := range []struct {
			raw     string
			applied time.Duration
		}{
			{"4", 5 * time.Second},
			{"181", 180 * time.Second},
			{"9000000000000", 180 * time.Second},
		} {
			pull(h, `{"detect_after_seconds":`+tt.raw+`}`)
			requireHeld(t, mgr, tt.applied)
			lines := 0
			for _, line := range logLines(logs.String(), rangeMsg) {
				if slices.Contains(strings.Fields(line), "detect_after_seconds="+tt.raw) {
					lines++
				}
			}
			if lines != 1 {
				t.Errorf("%d out of range lines for %s, want 1:\n%s", lines, tt.raw, logs.String())
			}
			requireLogLine(t, logs.String(), rangeMsg, "level=WARN", "detect_after_seconds="+tt.raw, "applied="+tt.applied.String())
		}
	})

	t.Run("malformed", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, h := holding15(t, &logs)
		for _, block := range []string{`"soon"`, `{"detect_after_seconds":15.5}`, `{"detect_after_seconds":"15"}`} {
			pull(h, block)
		}
		requireHeld(t, mgr, 15*time.Second)
		if n := len(logLines(logs.String(), malformedMsg)); n != 1 {
			t.Fatalf("%d malformed lines across three malformed pulls, want 1:\n%s", n, logs.String())
		}
		requireLogLine(t, logs.String(), malformedMsg, "level=WARN", "component=wireguard")
		if !strings.Contains(logs.String(), "error=") {
			t.Errorf("the malformed line does not name its error:\n%s", logs.String())
		}

		pull(h, `{"detect_after_seconds":15}`)
		pull(h, `"soon"`)
		if n := len(logLines(logs.String(), malformedMsg)); n != 2 {
			t.Errorf("%d malformed lines after a valid block and another malformed one, want 2:\n%s", n, logs.String())
		}
	})

	t.Run("a run of the same raw value", func(t *testing.T) {
		count := func(logs *bytes.Buffer) int { return len(logLines(logs.String(), rangeMsg)) }

		var same bytes.Buffer
		_, h := newHandler(&same)
		for range 3 {
			pull(h, `{"detect_after_seconds":2}`)
		}
		if n := count(&same); n != 1 {
			t.Errorf("%d out of range lines for 2, 2, 2, want 1:\n%s", n, same.String())
		}

		var broken bytes.Buffer
		mgr, h := newHandler(&broken)
		for _, raw := range []string{"2", "15", "2"} {
			pull(h, `{"detect_after_seconds":`+raw+`}`)
		}
		if n := count(&broken); n != 2 {
			t.Errorf("%d out of range lines for 2, 15, 2, want 2:\n%s", n, broken.String())
		}
		requireHeld(t, mgr, 5*time.Second)
	})

	t.Run("no value and no block", func(t *testing.T) {
		var logs bytes.Buffer
		mgr, h := newHandler(&logs)
		pull(h, "")
		requireHeld(t, mgr, 0)
		if logs.Len() != 0 {
			t.Errorf("a pull without the block logged:\n%s", logs.String())
		}
	})
}
