package policy

import (
	"errors"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// mockFirewallController records method calls and returns configurable errors.
type mockFirewallController struct {
	ensureChainCalls []string
	applyRulesCalls  []struct {
		Chain string
		Rules []FirewallRule
	}
	flushChainCalls  []string
	deleteChainCalls []string

	ensureChainErr error
	applyRulesErr  error
	flushChainErr  error
	deleteChainErr error
}

func (m *mockFirewallController) EnsureChain(chain string) error {
	m.ensureChainCalls = append(m.ensureChainCalls, chain)
	return m.ensureChainErr
}

func (m *mockFirewallController) ApplyRules(chain string, rules []FirewallRule) error {
	m.applyRulesCalls = append(m.applyRulesCalls, struct {
		Chain string
		Rules []FirewallRule
	}{chain, rules})
	return m.applyRulesErr
}

func (m *mockFirewallController) FlushChain(chain string) error {
	m.flushChainCalls = append(m.flushChainCalls, chain)
	return m.flushChainErr
}

func (m *mockFirewallController) DeleteChain(chain string) error {
	m.deleteChainCalls = append(m.deleteChainCalls, chain)
	return m.deleteChainErr
}

func TestEnforcer_FilterPeersDisabled(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	cfg := Config{Enabled: false, ChainName: "TEST"}
	enf := NewEnforcer(eng, nil, cfg, testLogger())

	peers := []api.Peer{
		{ID: "peer-a", MeshIP: "10.0.0.2"},
		{ID: "peer-b", MeshIP: "10.0.0.3"},
	}
	policies := []api.Policy{
		{
			ID: "pol-1",
			Rules: []api.PolicyRule{
				{Src: "node-a", Dst: "peer-a", Action: "allow"},
			},
		},
	}

	got := enf.FilterPeers(peers, policies, "node-a")
	if len(got) != len(peers) {
		t.Fatalf("FilterPeers() returned %d peers, want %d (disabled should return all)", len(got), len(peers))
	}
}

func TestEnforcer_FilterPeersEnabled(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	cfg := Config{Enabled: true, ChainName: "TEST"}
	enf := NewEnforcer(eng, nil, cfg, testLogger())

	peers := []api.Peer{
		{ID: "peer-a", MeshIP: "10.0.0.2"},
		{ID: "peer-b", MeshIP: "10.0.0.3"},
	}
	policies := []api.Policy{
		{
			ID: "pol-1",
			Rules: []api.PolicyRule{
				{Src: "node-a", Dst: "peer-a", Action: "allow"},
			},
		},
	}

	got := enf.FilterPeers(peers, policies, "node-a")
	if len(got) != 1 {
		t.Fatalf("FilterPeers() returned %d peers, want 1", len(got))
	}
	if got[0].ID != "peer-a" {
		t.Errorf("FilterPeers()[0].ID = %q, want %q", got[0].ID, "peer-a")
	}
}

func TestEnforcer_ApplyFirewallRulesDisabled(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: false, ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	err := enf.ApplyFirewallRules(nil, "node-a", "wg0", nil)
	if err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v, want nil", err)
	}
	if len(mock.ensureChainCalls) != 0 {
		t.Errorf("EnsureChain called %d times, want 0", len(mock.ensureChainCalls))
	}
}

func TestEnforcer_ApplyFirewallRulesNilFirewall(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	cfg := Config{Enabled: true, ChainName: "TEST"}
	enf := NewEnforcer(eng, nil, cfg, testLogger())

	err := enf.ApplyFirewallRules(nil, "node-a", "wg0", nil)
	if err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v, want nil", err)
	}
}

func TestEnforcer_ApplyFirewallRulesSuccess(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: true, ChainName: "TEST-CHAIN"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	policies := []api.Policy{
		{
			ID: "pol-1",
			Rules: []api.PolicyRule{
				{Src: "node-a", Dst: "peer-b", Port: 443, Protocol: "tcp", Action: "allow"},
			},
		},
	}
	peersByID := map[string]string{
		"node-a": "10.0.0.1",
		"peer-b": "10.0.0.2",
	}

	err := enf.ApplyFirewallRules(policies, "node-a", "wg0", peersByID)
	if err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v, want nil", err)
	}

	if len(mock.ensureChainCalls) != 1 {
		t.Fatalf("EnsureChain called %d times, want 1", len(mock.ensureChainCalls))
	}
	if mock.ensureChainCalls[0] != "TEST-CHAIN" {
		t.Errorf("EnsureChain chain = %q, want %q", mock.ensureChainCalls[0], "TEST-CHAIN")
	}

	if len(mock.applyRulesCalls) != 1 {
		t.Fatalf("ApplyRules called %d times, want 1", len(mock.applyRulesCalls))
	}
	if mock.applyRulesCalls[0].Chain != "TEST-CHAIN" {
		t.Errorf("ApplyRules chain = %q, want %q", mock.applyRulesCalls[0].Chain, "TEST-CHAIN")
	}
	// 1 policy rule + 1 default-deny = 2
	if len(mock.applyRulesCalls[0].Rules) != 2 {
		t.Errorf("ApplyRules rules count = %d, want 2", len(mock.applyRulesCalls[0].Rules))
	}
}

func TestEnforcer_ApplyFirewallRulesEnsureChainError(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{
		ensureChainErr: errors.New("chain creation failed"),
	}
	cfg := Config{Enabled: true, ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	err := enf.ApplyFirewallRules(nil, "node-a", "wg0", nil)
	if err == nil {
		t.Fatal("ApplyFirewallRules() error = nil, want error")
	}
	if !errors.Is(err, mock.ensureChainErr) {
		t.Errorf("error does not wrap original: %v", err)
	}
	want := "policy: enforce: chain creation failed"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestEnforcer_ApplyFirewallRulesApplyRulesError(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{
		applyRulesErr: errors.New("apply failed"),
	}
	cfg := Config{Enabled: true, ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	err := enf.ApplyFirewallRules(nil, "node-a", "wg0", nil)
	if err == nil {
		t.Fatal("ApplyFirewallRules() error = nil, want error")
	}
	if !errors.Is(err, mock.applyRulesErr) {
		t.Errorf("error does not wrap original: %v", err)
	}
	want := "policy: enforce: apply failed"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestEnforcer_TeardownNilFirewall(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	cfg := Config{Enabled: true, ChainName: "TEST"}
	enf := NewEnforcer(eng, nil, cfg, testLogger())

	err := enf.Teardown()
	if err != nil {
		t.Fatalf("Teardown() error = %v, want nil", err)
	}
}

func TestEnforcer_TeardownSuccess(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: true, ChainName: "TEST-CHAIN"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	err := enf.Teardown()
	if err != nil {
		t.Fatalf("Teardown() error = %v, want nil", err)
	}

	if len(mock.flushChainCalls) != 1 {
		t.Fatalf("FlushChain called %d times, want 1", len(mock.flushChainCalls))
	}
	if mock.flushChainCalls[0] != "TEST-CHAIN" {
		t.Errorf("FlushChain chain = %q, want %q", mock.flushChainCalls[0], "TEST-CHAIN")
	}

	if len(mock.deleteChainCalls) != 1 {
		t.Fatalf("DeleteChain called %d times, want 1", len(mock.deleteChainCalls))
	}
	if mock.deleteChainCalls[0] != "TEST-CHAIN" {
		t.Errorf("DeleteChain chain = %q, want %q", mock.deleteChainCalls[0], "TEST-CHAIN")
	}
}

func TestEnforcer_TeardownFlushError(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{
		flushChainErr: errors.New("flush failed"),
	}
	cfg := Config{Enabled: true, ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	err := enf.Teardown()
	if err == nil {
		t.Fatal("Teardown() error = nil, want error")
	}
	if !errors.Is(err, mock.flushChainErr) {
		t.Errorf("error does not wrap original: %v", err)
	}
	want := "policy: teardown: flush failed"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	// DeleteChain should NOT be called if FlushChain fails.
	if len(mock.deleteChainCalls) != 0 {
		t.Errorf("DeleteChain called %d times, want 0 (should not be called after flush error)", len(mock.deleteChainCalls))
	}
}
