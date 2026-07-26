package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newEnabledEnforcer(fw FirewallController) *Enforcer {
	return NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{Enabled: boolPtr(true), ChainName: "TEST"}, testLogger())
}

func policySnapshot(fingerprint string, rules ...api.PolicyRule) *api.PolicySnapshot {
	return &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: fingerprint, Rules: rules}
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

func TestReconcileHandler_PolicyUnchangedSkips(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := ReconcileHandler(enforcer, "wg0")

	desired := &api.NodeStateSnapshot{Policy: policySnapshot("fp")}
	diff := reconcile.StateDiff{} // PolicyChanged is false.

	if err := handler(context.Background(), desired, diff); err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if len(fwCtrl.ensureChainCalls) != 0 || len(fwCtrl.applyRulesCalls) != 0 {
		t.Errorf("enforcer touched despite PolicyChanged=false: ensure=%d apply=%d",
			len(fwCtrl.ensureChainCalls), len(fwCtrl.applyRulesCalls))
	}
}

func TestReconcileHandler_PolicyChangedApplies(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := ReconcileHandler(enforcer, "wg0")

	desired := &api.NodeStateSnapshot{
		Policy: policySnapshot("fp",
			api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
		),
	}
	diff := reconcile.StateDiff{PolicyChanged: true}

	if err := handler(context.Background(), desired, diff); err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if len(fwCtrl.ensureChainCalls) != 1 {
		t.Errorf("EnsureChain calls = %d, want 1", len(fwCtrl.ensureChainCalls))
	}
	if len(fwCtrl.applyRulesCalls) != 1 {
		t.Fatalf("ApplyRules calls = %d, want 1", len(fwCtrl.applyRulesCalls))
	}
	// 1 policy rule + trailing default-deny.
	if got := len(fwCtrl.applyRulesCalls[0].Rules); got != 2 {
		t.Errorf("applied rules = %d, want 2", got)
	}
}

func TestReconcileHandler_NilPolicyAppliesDefaultDeny(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := ReconcileHandler(enforcer, "wg0")

	// Policy transitioned populated→nil: PolicyChanged is true, desired.Policy nil.
	desired := &api.NodeStateSnapshot{Policy: nil}
	diff := reconcile.StateDiff{PolicyChanged: true}

	if err := handler(context.Background(), desired, diff); err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if len(fwCtrl.applyRulesCalls) != 1 {
		t.Fatalf("ApplyRules calls = %d, want 1", len(fwCtrl.applyRulesCalls))
	}
	rules := fwCtrl.applyRulesCalls[0].Rules
	if len(rules) != 1 || rules[0].Action != "deny" {
		t.Errorf("nil policy should apply default-deny only, got %+v", rules)
	}
}

func TestReconcileHandler_EnforcerErrorPropagates(t *testing.T) {
	fwCtrl := &mockFirewallController{ensureChainErr: errors.New("firewall error")}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := ReconcileHandler(enforcer, "wg0")

	desired := &api.NodeStateSnapshot{Policy: policySnapshot("fp")}
	diff := reconcile.StateDiff{PolicyChanged: true}

	if err := handler(context.Background(), desired, diff); err == nil {
		t.Fatal("handler error = nil, want error (firewall failed)")
	}
}

func TestReconcileHandler_InvalidRulesetDoesNotWedgeSnapshot(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := ReconcileHandler(enforcer, "wg0")

	// One rule the engine cannot translate. Returning the error would hold the
	// reconciler snapshot back, so the identical revision would be re-diffed and
	// every handler re-run at the reconcile interval forever.
	desired := &api.NodeStateSnapshot{
		Policy: policySnapshot("fp-bad",
			api.PolicyRule{Action: "quarantine", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0"},
		),
	}
	diff := reconcile.StateDiff{PolicyChanged: true}

	if err := handler(context.Background(), desired, diff); err != nil {
		t.Fatalf("handler error = %v, want nil (rejected revision must not wedge the snapshot)", err)
	}
	// Fail-closed: the previously applied ruleset stays in place.
	if len(fwCtrl.applyRulesCalls) != 0 {
		t.Errorf("ApplyRules calls = %d, want 0", len(fwCtrl.applyRulesCalls))
	}
}

func TestReconcileHandler_DisabledEnforcementDoesNotClaimApplied(t *testing.T) {
	var logs bytes.Buffer
	enforcer := NewEnforcer(
		NewPolicyEngine(testLogger()),
		&mockFirewallController{},
		Config{Enabled: boolPtr(false), ChainName: "TEST"},
		slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
	handler := ReconcileHandler(enforcer, "wg0")

	desired := &api.NodeStateSnapshot{Policy: policySnapshot("fp")}
	diff := reconcile.StateDiff{PolicyChanged: true}

	if err := handler(context.Background(), desired, diff); err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	if strings.Contains(logs.String(), "policy ruleset applied") {
		t.Errorf("handler logged %q with enforcement disabled; nothing was applied:\n%s",
			"policy ruleset applied", logs.String())
	}
}

// ---------------------------------------------------------------------------
// SSE Handler tests
// ---------------------------------------------------------------------------

func TestSSEHandler_PolicyUpdated(t *testing.T) {
	mock := &mockReconcileTrigger{}

	handler := HandlePolicyUpdated(mock)

	envelope := api.Envelope{
		Type:    api.EventPolicyUpdated,
		ID:      "evt-1",
		Payload: json.RawMessage(`{"policy_id": "pol-1"}`),
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

	envelope := api.Envelope{
		Type:    api.EventPolicyUpdated,
		ID:      "evt-bad",
		Payload: json.RawMessage("not valid json"),
	}

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("handler error = %v, want nil", err)
	}
	// TriggerReconcile should still be called despite a malformed payload.
	if mock.triggered != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", mock.triggered)
	}
}
