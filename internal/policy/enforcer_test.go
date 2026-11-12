package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// mockFirewallController records method calls and returns configurable errors.
type mockFirewallController struct {
	probeCalls       int
	ensureChainCalls []string
	applyRulesCalls  []struct {
		Chain string
		Rules []FirewallRule
	}
	flushChainCalls  []string
	deleteChainCalls []string

	probeErr       error
	ensureChainErr error
	applyRulesErr  error
	flushChainErr  error
	deleteChainErr error
}

func (m *mockFirewallController) Probe() error {
	m.probeCalls++
	return m.probeErr
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

func TestEnforcer_ApplyFirewallRulesDisabled(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: boolPtr(false), ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	applied, err := enf.ApplyFirewallRules(nil, "wg0")
	if err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v, want nil", err)
	}
	if applied {
		t.Error("ApplyFirewallRules() applied = true, want false (enforcement disabled)")
	}
	if len(mock.ensureChainCalls) != 0 {
		t.Errorf("EnsureChain called %d times, want 0 (disabled)", len(mock.ensureChainCalls))
	}
}

func TestEnforcer_ApplyFirewallRulesNilFirewall(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
	enf := NewEnforcer(eng, nil, cfg, testLogger())

	applied, err := enf.ApplyFirewallRules(nil, "wg0")
	if err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v, want nil", err)
	}
	if applied {
		t.Error("ApplyFirewallRules() applied = true, want false (no firewall backend)")
	}
}

func TestEnforcer_ApplyFirewallRulesNilPolicyDefaultDeny(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST-CHAIN"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	// A nil policy yields the default-deny-only ruleset.
	applied, err := enf.ApplyFirewallRules(nil, "wg0")
	if err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v, want nil", err)
	}
	if !applied {
		t.Error("ApplyFirewallRules() applied = false, want true")
	}
	if len(mock.applyRulesCalls) != 1 {
		t.Fatalf("ApplyRules called %d times, want 1", len(mock.applyRulesCalls))
	}
	rules := mock.applyRulesCalls[0].Rules
	if len(rules) != 1 || rules[0].Action != "deny" {
		t.Errorf("nil policy should apply default-deny only, got %+v", rules)
	}
}

func TestEnforcer_ApplyFirewallRulesSuccess(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST-CHAIN"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	policy := &api.PolicySnapshot{
		RevisionID:  "rev-1",
		Fingerprint: "fp-1",
		Rules: []api.PolicyRule{
			{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
		},
	}

	applied, err := enf.ApplyFirewallRules(policy, "wg0")
	if err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v, want nil", err)
	}
	if !applied {
		t.Error("ApplyFirewallRules() applied = false, want true")
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
	// 1 policy rule + 1 default-deny = 2.
	if len(mock.applyRulesCalls[0].Rules) != 2 {
		t.Errorf("ApplyRules rules count = %d, want 2", len(mock.applyRulesCalls[0].Rules))
	}
}

func TestEnforcer_ApplyFirewallRulesEnsureChainError(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{
		ensureChainErr: errors.New("chain creation failed"),
	}
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	_, err := enf.ApplyFirewallRules(nil, "wg0")
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
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	_, err := enf.ApplyFirewallRules(nil, "wg0")
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

// A revision the engine rejects never reaches the backend: neither EnsureChain,
// which on Linux rewrites the table, nor ApplyRules runs. Every action but
// allow, from the format before plexsphere/plexsphere#1058, is such a revision.
func TestEnforcer_ApplyFirewallRulesInvalidRuleset(t *testing.T) {
	for _, action := range []string{"deny", "log", "", "ALLOW", "quarantine"} {
		t.Run(action, func(t *testing.T) {
			eng := NewPolicyEngine(testLogger())
			mock := &mockFirewallController{}
			cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
			enf := NewEnforcer(eng, mock, cfg, testLogger())

			policy := &api.PolicySnapshot{
				RevisionID:  "rev-bad",
				Fingerprint: "fp-bad",
				Rules: []api.PolicyRule{
					{LegacyAction: legacyAction(action), Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0"},
				},
			}

			applied, err := enf.ApplyFirewallRules(policy, "wg0")
			if err == nil {
				t.Fatal("ApplyFirewallRules() error = nil, want error")
			}
			if applied {
				t.Error("ApplyFirewallRules() applied = true, want false")
			}
			if !errors.Is(err, ErrInvalidRuleset) {
				t.Errorf("error does not wrap ErrInvalidRuleset: %v", err)
			}
			if !strings.Contains(err.Error(), "unsupported action") {
				t.Errorf("error = %v, want one naming the unsupported action", err)
			}
			// The previously installed chain must be left untouched — a revision
			// that does not translate never reaches the backend.
			if len(mock.ensureChainCalls) != 0 {
				t.Errorf("EnsureChain called %d times, want 0", len(mock.ensureChainCalls))
			}
			if len(mock.applyRulesCalls) != 0 {
				t.Errorf("ApplyRules called %d times, want 0", len(mock.applyRulesCalls))
			}
		})
	}
}

func TestEnforcer_TeardownNilFirewall(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
	enf := NewEnforcer(eng, nil, cfg, testLogger())

	err := enf.Teardown()
	if err != nil {
		t.Fatalf("Teardown() error = %v, want nil", err)
	}
}

func TestEnforcer_TeardownSuccess(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST-CHAIN"}
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
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
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

func TestEnforcer_PreflightDisabled(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{probeErr: errors.New("operation not permitted")}
	cfg := Config{Enabled: boolPtr(false), ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	if err := enf.Preflight(); err != nil {
		t.Fatalf("Preflight() error = %v, want nil (enforcement disabled)", err)
	}
	// A node that was told not to enforce must start on a host that could not
	// enforce anyway, so the backend is never asked.
	if mock.probeCalls != 0 {
		t.Errorf("Probe called %d times, want 0 (disabled)", mock.probeCalls)
	}
}

func TestEnforcer_PreflightNilFirewall(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
	enf := NewEnforcer(eng, nil, cfg, testLogger())

	if err := enf.Preflight(); err != nil {
		t.Fatalf("Preflight() error = %v, want nil (no firewall backend)", err)
	}
}

func TestEnforcer_PreflightProbeSucceeds(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{}
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	if err := enf.Preflight(); err != nil {
		t.Fatalf("Preflight() error = %v, want nil", err)
	}
	if mock.probeCalls != 1 {
		t.Errorf("Probe called %d times, want 1", mock.probeCalls)
	}
	// The probe must not change kernel state: no chain, no rules.
	if len(mock.ensureChainCalls) != 0 || len(mock.applyRulesCalls) != 0 {
		t.Errorf("Preflight mutated the firewall: %d EnsureChain, %d ApplyRules calls",
			len(mock.ensureChainCalls), len(mock.applyRulesCalls))
	}
}

func TestEnforcer_PreflightProbeError(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	mock := &mockFirewallController{
		probeErr: errors.New("policy: nftables: probe: operation not permitted"),
	}
	cfg := Config{Enabled: boolPtr(true), ChainName: "TEST"}
	enf := NewEnforcer(eng, mock, cfg, testLogger())

	err := enf.Preflight()
	if err == nil {
		t.Fatal("Preflight() error = nil, want error")
	}
	if !errors.Is(err, mock.probeErr) {
		t.Errorf("error does not wrap the backend error: %v", err)
	}
	want := "policy: preflight: policy: nftables: probe: operation not permitted"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// reportingFirewall is a mockFirewallController that can report connections.
// It records the sink it is given and, at each ApplyRules, the tags the sink
// already knows.
type reportingFirewall struct {
	mockFirewallController
	sinks          []ConnSink
	tagsAtApply    [][]string
	revisionAtTags []string
}

func (f *reportingFirewall) SetConnSink(sink ConnSink) {
	f.sinks = append(f.sinks, sink)
}

func (f *reportingFirewall) ApplyRules(chain string, rules []FirewallRule) error {
	var tags []string
	revision := ""
	if len(f.sinks) > 0 {
		if cl, ok := f.sinks[len(f.sinks)-1].(*ConnLogger); ok {
			cl.mu.Lock()
			for tag, entry := range cl.current {
				tags = append(tags, tag)
				revision = entry.revisionID
			}
			cl.mu.Unlock()
		}
	}
	slices.Sort(tags)
	f.tagsAtApply = append(f.tagsAtApply, tags)
	f.revisionAtTags = append(f.revisionAtTags, revision)
	return f.mockFirewallController.ApplyRules(chain, rules)
}

// fourRules is a policy whose rules 1 and 3 carry log: true.
func fourRules(revision string) *api.PolicySnapshot {
	return &api.PolicySnapshot{
		RevisionID: revision,
		Rules: []api.PolicyRule{
			{Protocol: "tcp", SourceCIDR: "10.99.0.0/24", DestinationCIDR: "10.99.0.1/32", Ports: &api.PortRange{From: 22, To: 22}},
			{Protocol: "tcp", SourceCIDR: "10.99.0.0/24", DestinationCIDR: "10.99.0.1/32", Ports: &api.PortRange{From: 443, To: 443}, Log: true},
			{Protocol: "udp", SourceCIDR: "10.99.0.0/24", DestinationCIDR: "10.99.0.1/32", Ports: &api.PortRange{From: 53, To: 53}},
			{Protocol: "any", SourceCIDR: "10.99.0.3/32", DestinationCIDR: "10.99.0.1/32", Log: true},
		},
	}
}

func TestEnforcer_TagsLoggedRulesAndAppliesThemFirst(t *testing.T) {
	fw := &reportingFirewall{}
	e := NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{}, testLogger())

	for gen := 1; gen <= 2; gen++ {
		if _, err := e.ApplyFirewallRules(fourRules("R"), "plexd0"); err != nil {
			t.Fatalf("apply %d: ApplyFirewallRules() error = %v", gen, err)
		}
		got := fw.applyRulesCalls[gen-1].Rules
		if len(got) != 5 {
			t.Fatalf("apply %d handed the firewall %d rules, want 5: %+v", gen, len(got), got)
		}
		want := []struct {
			port int
			tag  string
		}{
			{443, fmt.Sprintf("%d/1", gen)},
			{0, fmt.Sprintf("%d/3", gen)},
			{22, ""},
			{53, ""},
		}
		for i, w := range want {
			if got[i].Port != w.port || got[i].LogTag != w.tag || got[i].Action != "allow" {
				t.Errorf("apply %d rule %d = %+v, want port %d and tag %q", gen, i, got[i], w.port, w.tag)
			}
		}
		if got[4].Action != "deny" || got[4].LogTag != "" || got[4].SrcIP != "" {
			t.Errorf("apply %d rule 4 = %+v, want the untagged default deny", gen, got[4])
		}
	}
}

func TestEnforcer_HandsItsConnLoggerTheTagsBeforeTheApply(t *testing.T) {
	fw := &reportingFirewall{}
	e := NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{}, testLogger())

	if len(fw.sinks) != 1 || fw.sinks[0] != ConnSink(e.ConnLogger()) {
		t.Fatalf("NewEnforcer() set the sinks %v, want once the Enforcer's ConnLogger", fw.sinks)
	}
	if _, err := e.ApplyFirewallRules(fourRules("R"), "plexd0"); err != nil {
		t.Fatalf("ApplyFirewallRules() error = %v", err)
	}
	if got := fw.tagsAtApply[0]; !slices.Equal(got, []string{"1/1", "1/3"}) || fw.revisionAtTags[0] != "R" {
		t.Errorf("at ApplyRules the logger knew the tags %v of revision %q, want [1/1 1/3] of R", got, fw.revisionAtTags[0])
	}
	if len(fw.sinks) != 1 {
		t.Errorf("SetConnSink was called %d times, want once", len(fw.sinks))
	}

	// A firewall that cannot report is left alone.
	plain := &mockFirewallController{}
	if NewEnforcer(NewPolicyEngine(testLogger()), plain, Config{}, testLogger()).ConnLogger() == nil {
		t.Error("ConnLogger() = nil for a firewall that cannot report")
	}
}

func TestEnforcer_NoLoggedRulesAppliesUntagged(t *testing.T) {
	for name, policy := range map[string]*api.PolicySnapshot{
		"a nil policy": nil,
		"empty rules":  {RevisionID: "R", Rules: []api.PolicyRule{}},
	} {
		t.Run(name, func(t *testing.T) {
			fw := &reportingFirewall{}
			e := NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{}, testLogger())
			if _, err := e.ApplyFirewallRules(policy, "plexd0"); err != nil {
				t.Fatalf("ApplyFirewallRules() error = %v", err)
			}
			got := fw.applyRulesCalls[0].Rules
			if len(got) != 1 || got[0].Action != "deny" || got[0].LogTag != "" {
				t.Errorf("ApplyRules got %+v, want only the untagged default deny", got)
			}
			if len(fw.tagsAtApply[0]) != 0 {
				t.Errorf("the logger knew the tags %v, want none", fw.tagsAtApply[0])
			}
		})
	}
}

func TestEnforcer_NoGenerationWithoutEnforcement(t *testing.T) {
	disabled := false
	off := NewEnforcer(NewPolicyEngine(testLogger()), &reportingFirewall{}, Config{Enabled: &disabled}, testLogger())
	none := NewEnforcer(NewPolicyEngine(testLogger()), nil, Config{}, testLogger())
	for name, e := range map[string]*Enforcer{"disabled": off, "no firewall": none} {
		if _, err := e.ApplyFirewallRules(fourRules("R"), "plexd0"); err != nil {
			t.Fatalf("%s: ApplyFirewallRules() error = %v", name, err)
		}
		if e.generation != 0 {
			t.Errorf("%s: generation = %d, want 0", name, e.generation)
		}
	}
}

func TestEnforcer_RevertsTheConnLoggerWhenTheApplyFails(t *testing.T) {
	for name, fail := range map[string]func(fw *reportingFirewall){
		"EnsureChain": func(fw *reportingFirewall) { fw.ensureChainErr = errors.New("netlink: busy") },
		"ApplyRules":  func(fw *reportingFirewall) { fw.applyRulesErr = errors.New("netlink: busy") },
	} {
		t.Run(name, func(t *testing.T) {
			fw := &reportingFirewall{}
			e := NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{}, testLogger())
			if _, err := e.ApplyFirewallRules(fourRules("R1"), "plexd0"); err != nil {
				t.Fatalf("first ApplyFirewallRules() error = %v", err)
			}

			fail(fw)
			for i := 0; i < 2; i++ {
				if _, err := e.ApplyFirewallRules(fourRules("R2"), "plexd0"); err == nil {
					t.Fatal("ApplyFirewallRules() error = nil, want the injected failure")
				}
			}

			cl := e.ConnLogger()
			cl.mu.Lock()
			_, installed := cl.current["1/1"]
			_, failed := cl.current["3/1"]
			cl.mu.Unlock()
			if !installed || failed {
				t.Errorf("after two failed applies the logger holds tag 1/1: %v and tag 3/1: %v, want true and false", installed, failed)
			}
		})
	}

	// A successful apply keeps its tags.
	fw := &reportingFirewall{}
	e := NewEnforcer(NewPolicyEngine(testLogger()), fw, Config{}, testLogger())
	for range 2 {
		if _, err := e.ApplyFirewallRules(fourRules("R"), "plexd0"); err != nil {
			t.Fatalf("ApplyFirewallRules() error = %v", err)
		}
	}
	cl := e.ConnLogger()
	cl.mu.Lock()
	_, current := cl.current["2/1"]
	_, previous := cl.previous["1/1"]
	cl.mu.Unlock()
	if !current || !previous {
		t.Errorf("after two successful applies the logger holds 2/1: %v and previously 1/1: %v, want both", current, previous)
	}
}
