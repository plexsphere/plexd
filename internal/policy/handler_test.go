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
// DispatchHandler tests
// ---------------------------------------------------------------------------

// pull wraps a policy block in the snapshot a dispatch handler receives.
func pull(policy *api.PolicySnapshot) *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{Policy: policy}
}

func TestDispatchHandler_SameFingerprintSkips(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	handler := DispatchHandler(newEnabledEnforcer(fwCtrl), "wg0")

	handler(context.Background(), pull(policySnapshot("fp")))
	handler(context.Background(), pull(policySnapshot("fp")))

	if len(fwCtrl.applyRulesCalls) != 1 {
		t.Errorf("ApplyRules calls = %d after two pulls of one fingerprint, want 1", len(fwCtrl.applyRulesCalls))
	}
}

func TestDispatchHandler_NewBlockApplies(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := DispatchHandler(enforcer, "wg0")

	handler(context.Background(), pull(policySnapshot("fp",
		api.PolicyRule{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
	)))

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
	if st := enforcer.Status(); !st.HasApplied || st.Applied == nil || st.Applied.Fingerprint != "fp" {
		t.Errorf("Status() = %+v, want the block applied", st)
	}
}

// A pull with policy: null after a pull with a block takes the block away,
// which leaves the default deny alone.
func TestDispatchHandler_NullPolicyAfterABlockAppliesDefaultDeny(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := DispatchHandler(enforcer, "wg0")

	handler(context.Background(), pull(policySnapshot("fp",
		api.PolicyRule{Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"},
	)))
	handler(context.Background(), pull(nil))

	if len(fwCtrl.applyRulesCalls) != 2 {
		t.Fatalf("ApplyRules calls = %d, want 2", len(fwCtrl.applyRulesCalls))
	}
	rules := fwCtrl.applyRulesCalls[1].Rules
	if len(rules) != 1 || rules[0].Action != "deny" {
		t.Errorf("policy: null should apply default-deny only, got %+v", rules)
	}
	if st := enforcer.Status(); !st.HasApplied || st.Applied != nil {
		t.Errorf("Status() = %+v, want the null pull applied (HasApplied, nil Applied)", st)
	}
}

// A backend failure is the Enforcer's to record and retry; a dispatch handler
// has no error to return, so it can never hold the snapshot back.
func TestDispatchHandler_BackendErrorIsRecorded(t *testing.T) {
	fwCtrl := &mockFirewallController{ensureChainErr: errors.New("firewall error")}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := DispatchHandler(enforcer, "wg0")

	handler(context.Background(), pull(policySnapshot("fp")))

	st := enforcer.Status()
	if st.Rejected == nil || st.Rejected.Fingerprint != "fp" || !strings.Contains(st.Reason, "firewall error") {
		t.Errorf("Status() = %+v, want fp rejected with the backend's error", st)
	}
}

func TestDispatchHandler_InvalidRulesetKeepsPrevious(t *testing.T) {
	fwCtrl := &mockFirewallController{}
	enforcer := newEnabledEnforcer(fwCtrl)
	handler := DispatchHandler(enforcer, "wg0")

	handler(context.Background(), pull(policySnapshot("fp-good",
		api.PolicyRule{Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"},
	)))
	// One rule the engine cannot translate.
	handler(context.Background(), pull(policySnapshot("fp-bad",
		api.PolicyRule{LegacyAction: legacyAction("quarantine"), Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0"},
	)))

	// Fail-closed: the previously applied ruleset stays in place.
	if len(fwCtrl.applyRulesCalls) != 1 {
		t.Errorf("ApplyRules calls = %d, want 1", len(fwCtrl.applyRulesCalls))
	}
	st := enforcer.Status()
	if st.Applied == nil || st.Applied.Fingerprint != "fp-good" {
		t.Errorf("Applied = %+v, want fp-good kept", st.Applied)
	}
	if st.Rejected == nil || st.Rejected.Fingerprint != "fp-bad" {
		t.Errorf("Rejected = %+v, want fp-bad", st.Rejected)
	}
}

func TestDispatchHandler_DisabledEnforcementDoesNotClaimApplied(t *testing.T) {
	var logs bytes.Buffer
	enforcer := NewEnforcer(
		NewPolicyEngine(testLogger()),
		&mockFirewallController{},
		Config{Enabled: boolPtr(false), ChainName: "TEST"},
		slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
	handler := DispatchHandler(enforcer, "wg0")

	handler(context.Background(), pull(policySnapshot("fp")))

	if strings.Contains(logs.String(), "policy ruleset applied") {
		t.Errorf("handler logged %q with enforcement disabled; nothing was applied:\n%s",
			"policy ruleset applied", logs.String())
	}
	if st := enforcer.Status(); st.Enforcement != api.PolicyEnforcementDisabled || st.HasApplied {
		t.Errorf("Status() = %+v, want disabled and nothing applied", st)
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
