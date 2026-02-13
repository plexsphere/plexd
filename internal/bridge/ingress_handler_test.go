package bridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// ruleAssignmentEnvelope builds a SignedEnvelope for an ingress rule assignment.
func ruleAssignmentEnvelope(t *testing.T, rule api.IngressRule) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventIngressRuleAssigned,
		EventID:   "evt-assign-" + rule.RuleID,
		Payload:   payload,
	}
}

// ruleRevocationEnvelope builds a SignedEnvelope for an ingress rule revocation.
func ruleRevocationEnvelope(t *testing.T, ruleID string) api.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(struct {
		RuleID string `json:"rule_id"`
	}{RuleID: ruleID})
	if err != nil {
		t.Fatalf("marshal revocation: %v", err)
	}
	return api.SignedEnvelope{
		EventType: api.EventIngressRuleRevoked,
		EventID:   "evt-revoke-" + ruleID,
		Payload:   payload,
	}
}

// newTestIngressManager creates an IngressManager for handler tests with mocks.
func newTestIngressManager(t *testing.T, ctrl *mockIngressController) *IngressManager {
	t.Helper()
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		IngressEnabled:  true,
	}
	cfg.ApplyDefaults()

	ctrl.listenFn = func(addr string, tlsCfg *tls.Config) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}

	mgr := NewIngressManager(ctrl, cfg, discardLogger())
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ctrl.resetIngress()
	return mgr
}

// ---------------------------------------------------------------------------
// HandleIngressConfigUpdated tests
// ---------------------------------------------------------------------------

func TestHandleIngressConfigUpdated(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleIngressConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventIngressConfigUpdated,
		EventID:   "evt-1",
		Payload:   json.RawMessage(`{"enabled":true}`),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}

func TestHandleIngressConfigUpdated_MalformedPayload(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandleIngressConfigUpdated(mock)

	envelope := api.SignedEnvelope{
		EventType: api.EventIngressConfigUpdated,
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

// ---------------------------------------------------------------------------
// HandleIngressRuleAssigned tests
// ---------------------------------------------------------------------------

func TestHandleIngressRuleAssigned(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	handler := HandleIngressRuleAssigned(mgr, discardLogger())

	rule := api.IngressRule{
		RuleID:     "rule-1",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}
	envelope := ruleAssignmentEnvelope(t, rule)

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Verify Listen was called.
	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 1 {
		t.Fatalf("expected 1 Listen call, got %d", len(listenCalls))
	}

	// Verify rule is tracked.
	ids := mgr.RuleIDs()
	if len(ids) != 1 || ids[0] != "rule-1" {
		t.Errorf("RuleIDs = %v, want [rule-1]", ids)
	}

	status := mgr.IngressStatus()
	if status == nil || status.RuleCount != 1 {
		t.Errorf("RuleCount = %v, want 1", status)
	}
}

func TestHandleIngressRuleAssigned_MalformedPayload(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	handler := HandleIngressRuleAssigned(mgr, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventIngressRuleAssigned,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

// ---------------------------------------------------------------------------
// HandleIngressRuleRevoked tests
// ---------------------------------------------------------------------------

func TestHandleIngressRuleRevoked(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	// Add a rule first.
	rule := api.IngressRule{
		RuleID:     "rule-revoke",
		ListenPort: 0,
		TargetAddr: "10.0.0.5:8080",
		Mode:       "tcp",
	}
	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if len(mgr.RuleIDs()) != 1 {
		t.Fatalf("RuleIDs count after add = %d, want 1", len(mgr.RuleIDs()))
	}

	handler := HandleIngressRuleRevoked(mgr, discardLogger())

	envelope := ruleRevocationEnvelope(t, "rule-revoke")
	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if len(mgr.RuleIDs()) != 0 {
		t.Errorf("RuleIDs count after revoke = %d, want 0", len(mgr.RuleIDs()))
	}
}

func TestHandleIngressRuleRevoked_MalformedPayload(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	handler := HandleIngressRuleRevoked(mgr, discardLogger())

	envelope := api.SignedEnvelope{
		EventType: api.EventIngressRuleRevoked,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("handler should return error for malformed payload")
	}
}

// ---------------------------------------------------------------------------
// IngressReconcileHandler tests
// ---------------------------------------------------------------------------

func TestIngressReconcileHandler_NilConfig(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	handler := IngressReconcileHandler(mgr, discardLogger())

	// Desired state has nil IngressConfig — no changes.
	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", PublicKey: "pk", MeshIP: "10.42.0.2"}},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	if len(ctrl.ingressCallsFor("Listen")) != 0 {
		t.Error("Listen should not be called when IngressConfig is nil")
	}
}

func TestIngressReconcileHandler_AddsNewRules(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	handler := IngressReconcileHandler(mgr, discardLogger())

	desired := &api.StateResponse{
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules: []api.IngressRule{
				{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"},
				{RuleID: "rule-2", ListenPort: 0, TargetAddr: "10.0.0.6:8080", Mode: "tcp"},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 2 {
		t.Fatalf("expected 2 Listen calls, got %d", len(listenCalls))
	}

	ids := mgr.RuleIDs()
	if len(ids) != 2 {
		t.Errorf("RuleIDs count = %d, want 2", len(ids))
	}
}

func TestIngressReconcileHandler_RemovesStaleRules(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with two rules.
	if err := mgr.AddRule(api.IngressRule{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := mgr.AddRule(api.IngressRule{RuleID: "rule-2", ListenPort: 0, TargetAddr: "10.0.0.6:8080", Mode: "tcp"}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	ctrl.resetIngress()

	handler := IngressReconcileHandler(mgr, discardLogger())

	// Desired state: only rule-1 remains.
	desired := &api.StateResponse{
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules: []api.IngressRule{
				{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Verify Close was called for rule-2.
	closeCalls := ctrl.ingressCallsFor("Close")
	if len(closeCalls) != 1 {
		t.Fatalf("expected 1 Close call, got %d", len(closeCalls))
	}

	ids := mgr.RuleIDs()
	if len(ids) != 1 {
		t.Fatalf("RuleIDs count = %d, want 1", len(ids))
	}
	if ids[0] != "rule-1" {
		t.Errorf("remaining rule = %v, want rule-1", ids[0])
	}
}

func TestIngressReconcileHandler_DetectsChangedRules(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with a rule targeting port 8080.
	original := api.IngressRule{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"}
	if err := mgr.AddRule(original); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	ctrl.resetIngress()

	handler := IngressReconcileHandler(mgr, discardLogger())

	// Desired state: same rule ID but different TargetAddr.
	changed := api.IngressRule{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:9090", Mode: "tcp"}
	desired := &api.StateResponse{
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules:   []api.IngressRule{changed},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Should have removed the old rule (Close) and re-added (Listen).
	closeCalls := ctrl.ingressCallsFor("Close")
	if len(closeCalls) != 1 {
		t.Fatalf("expected 1 Close call for changed rule, got %d", len(closeCalls))
	}
	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 1 {
		t.Fatalf("expected 1 Listen call for changed rule, got %d", len(listenCalls))
	}

	// Verify the active rule has the new config.
	got, ok := mgr.GetRule("rule-1")
	if !ok {
		t.Fatal("rule-1 should still be active after change")
	}
	if got.TargetAddr != "10.0.0.5:9090" {
		t.Errorf("TargetAddr = %q, want %q", got.TargetAddr, "10.0.0.5:9090")
	}
}

func TestIngressReconcileHandler_UnchangedRulesUntouched(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with a rule.
	rule := api.IngressRule{RuleID: "rule-1", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"}
	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	ctrl.resetIngress()

	handler := IngressReconcileHandler(mgr, discardLogger())

	// Desired state: same rule, unchanged.
	desired := &api.StateResponse{
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules:   []api.IngressRule{rule},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// No Close or Listen calls — rule is unchanged.
	if len(ctrl.ingressCallsFor("Close")) != 0 {
		t.Error("Close should not be called for unchanged rule")
	}
	if len(ctrl.ingressCallsFor("Listen")) != 0 {
		t.Error("Listen should not be called for unchanged rule")
	}
}

func TestIngressReconcileHandler_Mixed(t *testing.T) {
	ctrl := &mockIngressController{}
	mgr := newTestIngressManager(t, ctrl)
	defer func() { _ = mgr.Teardown() }()

	// Pre-populate with two rules.
	if err := mgr.AddRule(api.IngressRule{RuleID: "rule-keep", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := mgr.AddRule(api.IngressRule{RuleID: "rule-stale", ListenPort: 0, TargetAddr: "10.0.0.6:8080", Mode: "tcp"}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	ctrl.resetIngress()

	handler := IngressReconcileHandler(mgr, discardLogger())

	// Desired: keep rule-keep, add rule-new, remove rule-stale.
	desired := &api.StateResponse{
		IngressConfig: &api.IngressConfig{
			Enabled: true,
			Rules: []api.IngressRule{
				{RuleID: "rule-keep", ListenPort: 0, TargetAddr: "10.0.0.5:8080", Mode: "tcp"},
				{RuleID: "rule-new", ListenPort: 0, TargetAddr: "10.0.0.7:8080", Mode: "tcp"},
			},
		},
	}
	diff := reconcile.StateDiff{}

	err := handler(context.Background(), desired, diff)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}

	// Verify rule-stale was removed.
	closeCalls := ctrl.ingressCallsFor("Close")
	if len(closeCalls) != 1 {
		t.Fatalf("expected 1 Close call, got %d", len(closeCalls))
	}

	// Verify rule-new was added.
	listenCalls := ctrl.ingressCallsFor("Listen")
	if len(listenCalls) != 1 {
		t.Fatalf("expected 1 Listen call, got %d", len(listenCalls))
	}

	ids := mgr.RuleIDs()
	if len(ids) != 2 {
		t.Fatalf("RuleIDs count = %d, want 2", len(ids))
	}

	// Verify we have the expected rules.
	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[id] = struct{}{}
	}
	if _, ok := idSet["rule-keep"]; !ok {
		t.Error("rule-keep should still be active")
	}
	if _, ok := idSet["rule-new"]; !ok {
		t.Error("rule-new should be active")
	}
	if _, ok := idSet["rule-stale"]; ok {
		t.Error("rule-stale should have been removed")
	}
}
