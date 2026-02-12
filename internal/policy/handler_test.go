package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockWGController implements wireguard.WGController for handler tests.
type mockWGController struct {
	calls          []mockWGCall
	addPeerErr     error
	removePeerErr  error
	removePeerErrs map[string]error // per-peerID errors for RemovePeer
}

type mockWGCall struct {
	Method string
	Args   []interface{}
}

func (m *mockWGController) CreateInterface(string, []byte, int) error { return nil }
func (m *mockWGController) DeleteInterface(string) error             { return nil }
func (m *mockWGController) ConfigureAddress(string, string) error    { return nil }
func (m *mockWGController) SetInterfaceUp(string) error              { return nil }
func (m *mockWGController) SetMTU(string, int) error                 { return nil }

func (m *mockWGController) AddPeer(iface string, cfg wireguard.PeerConfig) error {
	m.calls = append(m.calls, mockWGCall{Method: "AddPeer", Args: []interface{}{iface, cfg}})
	return m.addPeerErr
}

func (m *mockWGController) RemovePeer(iface string, publicKey []byte) error {
	m.calls = append(m.calls, mockWGCall{Method: "RemovePeer", Args: []interface{}{iface, publicKey}})
	if m.removePeerErrs != nil {
		// Match by public key base64 for per-peer errors
		b64 := base64.StdEncoding.EncodeToString(publicKey)
		if err, ok := m.removePeerErrs[b64]; ok {
			return err
		}
	}
	return m.removePeerErr
}

func (m *mockWGController) callsFor(method string) []mockWGCall {
	var result []mockWGCall
	for _, c := range m.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

func testPeer(id, meshIP string) api.Peer {
	return api.Peer{
		ID:         id,
		PublicKey:  base64.StdEncoding.EncodeToString([]byte(id + "-key-padding-to-32b")),
		MeshIP:     meshIP,
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{meshIP + "/32"},
	}
}

func newTestWGManager(ctrl wireguard.WGController) *wireguard.Manager {
	return wireguard.NewManager(ctrl, wireguard.Config{}, testLogger())
}

func newTestEnforcer(fw FirewallController) *Enforcer {
	return NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{}, testLogger())
}

// mockReconcileTrigger records TriggerReconcile calls.
type mockReconcileTrigger struct {
	triggered int
}

func (m *mockReconcileTrigger) TriggerReconcile() {
	m.triggered++
}

// ---------------------------------------------------------------------------
// ReconcileHandler tests
// ---------------------------------------------------------------------------

func TestReconcileHandler_PolicyChange(t *testing.T) {
	wgCtrl := &mockWGController{}
	wgMgr := newTestWGManager(wgCtrl)
	fwCtrl := &mockFirewallController{}
	enforcer := newTestEnforcer(fwCtrl)

	handler := ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0")

	desired := &api.StateResponse{
		Peers: []api.Peer{
			testPeer("peer-b", "10.0.0.2"),
			testPeer("peer-c", "10.0.0.3"),
		},
		Policies: []api.Policy{
			{
				ID: "pol-1",
				Rules: []api.PolicyRule{
					{Src: "node-a", Dst: "peer-b", Action: "allow"},
				},
			},
		},
	}
	diff := reconcile.StateDiff{
		PoliciesToAdd: []api.Policy{desired.Policies[0]},
	}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Firewall rules should have been applied.
	if len(fwCtrl.ensureChainCalls) != 1 {
		t.Errorf("EnsureChain calls = %d, want 1", len(fwCtrl.ensureChainCalls))
	}
	if len(fwCtrl.applyRulesCalls) != 1 {
		t.Errorf("ApplyRules calls = %d, want 1", len(fwCtrl.applyRulesCalls))
	}

	// Only peer-b should be added (peer-c is not allowed by policy).
	addCalls := wgCtrl.callsFor("AddPeer")
	if len(addCalls) != 1 {
		t.Fatalf("AddPeer calls = %d, want 1", len(addCalls))
	}
}

func TestReconcileHandler_PeerChangeWithPolicies(t *testing.T) {
	wgCtrl := &mockWGController{}
	wgMgr := newTestWGManager(wgCtrl)
	fwCtrl := &mockFirewallController{}
	enforcer := newTestEnforcer(fwCtrl)

	handler := ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0")

	// First call: establish initial state with policy allowing peer-b.
	desired1 := &api.StateResponse{
		Peers: []api.Peer{testPeer("peer-b", "10.0.0.2")},
		Policies: []api.Policy{
			{
				ID:    "pol-1",
				Rules: []api.PolicyRule{{Src: "node-a", Dst: "peer-b", Action: "allow"}},
			},
		},
	}
	diff1 := reconcile.StateDiff{
		PoliciesToAdd: desired1.Policies,
		PeersToAdd:    desired1.Peers,
	}
	_ = handler(context.Background(), desired1, diff1)
	wgCtrl.calls = nil // reset

	// Second call: new peer-c added, but not allowed by policy.
	desired2 := &api.StateResponse{
		Peers: []api.Peer{
			testPeer("peer-b", "10.0.0.2"),
			testPeer("peer-c", "10.0.0.3"),
		},
		Policies: desired1.Policies, // same policy — only peer-b allowed
	}
	diff2 := reconcile.StateDiff{
		PeersToAdd: []api.Peer{testPeer("peer-c", "10.0.0.3")},
	}

	err := handler(context.Background(), desired2, diff2)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// peer-c should NOT be added (not allowed by policy).
	addCalls := wgCtrl.callsFor("AddPeer")
	if len(addCalls) != 0 {
		t.Errorf("AddPeer calls = %d, want 0 (peer-c not allowed)", len(addCalls))
	}
}

func TestReconcileHandler_NoDriftSkips(t *testing.T) {
	wgCtrl := &mockWGController{}
	wgMgr := newTestWGManager(wgCtrl)
	fwCtrl := &mockFirewallController{}
	enforcer := newTestEnforcer(fwCtrl)

	handler := ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0")

	desired := &api.StateResponse{
		Peers:    []api.Peer{testPeer("peer-b", "10.0.0.2")},
		Policies: []api.Policy{{ID: "pol-1", Rules: []api.PolicyRule{{Src: "*", Dst: "*", Action: "allow"}}}},
	}
	// Empty diff — no policy or peer changes.
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// No firewall calls.
	if len(fwCtrl.ensureChainCalls) != 0 {
		t.Errorf("EnsureChain calls = %d, want 0", len(fwCtrl.ensureChainCalls))
	}
	// No WG calls.
	if len(wgCtrl.calls) != 0 {
		t.Errorf("WG controller calls = %d, want 0", len(wgCtrl.calls))
	}
}

func TestReconcileHandler_RemovedPolicyRevokesPeer(t *testing.T) {
	wgCtrl := &mockWGController{}
	wgMgr := newTestWGManager(wgCtrl)
	fwCtrl := &mockFirewallController{}
	enforcer := newTestEnforcer(fwCtrl)

	handler := ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0")

	// First call: peer-b allowed by policy.
	peerB := testPeer("peer-b", "10.0.0.2")
	desired1 := &api.StateResponse{
		Peers: []api.Peer{peerB},
		Policies: []api.Policy{
			{ID: "pol-1", Rules: []api.PolicyRule{{Src: "node-a", Dst: "peer-b", Action: "allow"}}},
		},
	}
	diff1 := reconcile.StateDiff{
		PoliciesToAdd: desired1.Policies,
		PeersToAdd:    desired1.Peers,
	}
	_ = handler(context.Background(), desired1, diff1)
	wgCtrl.calls = nil // reset

	// Second call: policy removed — peer-b should be revoked (deny-by-default).
	desired2 := &api.StateResponse{
		Peers:    []api.Peer{peerB},
		Policies: nil,
	}
	diff2 := reconcile.StateDiff{
		PoliciesToRemove: []string{"pol-1"},
	}

	err := handler(context.Background(), desired2, diff2)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// peer-b should be removed from WG.
	removeCalls := wgCtrl.callsFor("RemovePeer")
	if len(removeCalls) != 1 {
		t.Fatalf("RemovePeer calls = %d, want 1", len(removeCalls))
	}
}

func TestReconcileHandler_PartialFailureAggregated(t *testing.T) {
	wgCtrl := &mockWGController{}
	wgMgr := newTestWGManager(wgCtrl)
	fwCtrl := &mockFirewallController{
		ensureChainErr: errors.New("firewall error"),
	}
	enforcer := newTestEnforcer(fwCtrl)

	handler := ReconcileHandler(enforcer, wgMgr, "node-a", "10.0.0.1", "wg0")

	desired := &api.StateResponse{
		Peers: []api.Peer{
			testPeer("peer-b", "10.0.0.2"),
			testPeer("peer-c", "10.0.0.3"),
		},
		Policies: []api.Policy{
			{ID: "pol-1", Rules: []api.PolicyRule{{Src: "*", Dst: "*", Action: "allow"}}},
		},
	}
	diff := reconcile.StateDiff{
		PoliciesToAdd: desired.Policies,
		PeersToAdd:    desired.Peers,
	}

	err := handler(context.Background(), desired, diff)
	if err == nil {
		t.Fatal("handler error = nil, want error (firewall failed)")
	}

	// Despite firewall error, peers should still be processed.
	addCalls := wgCtrl.callsFor("AddPeer")
	if len(addCalls) != 2 {
		t.Errorf("AddPeer calls = %d, want 2 (should still process peers despite firewall error)", len(addCalls))
	}
}

// ---------------------------------------------------------------------------
// SSE Handler tests
// ---------------------------------------------------------------------------

func TestSSEHandler_PolicyUpdated(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandlePolicyUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventPolicyUpdated,
		EventID:   "evt-1",
		Payload:   json.RawMessage(`{"policy_id": "pol-1"}`),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}

func TestSSEHandler_PolicyUpdated_MalformedPayload(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandlePolicyUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventPolicyUpdated,
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
