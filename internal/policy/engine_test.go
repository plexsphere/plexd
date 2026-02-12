package policy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestFilterPeers_NoPoliciesDeniesAll(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	peers := []api.Peer{
		{ID: "peer-a", MeshIP: "10.0.0.2"},
		{ID: "peer-b", MeshIP: "10.0.0.3"},
	}

	got := eng.FilterPeers(peers, nil, "node-a")
	if len(got) != 0 {
		t.Fatalf("FilterPeers() returned %d peers, want 0 (deny-by-default)", len(got))
	}
}

func TestFilterPeers_EmptyPoliciesDeniesAll(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	peers := []api.Peer{
		{ID: "peer-a", MeshIP: "10.0.0.2"},
		{ID: "peer-b", MeshIP: "10.0.0.3"},
	}

	got := eng.FilterPeers(peers, []api.Policy{}, "node-a")
	if len(got) != 0 {
		t.Fatalf("FilterPeers() returned %d peers, want 0 (deny-by-default)", len(got))
	}
}

func TestFilterPeers_AllowSpecificPeer(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	peers := []api.Peer{
		{ID: "peer-b", MeshIP: "10.0.0.2"},
		{ID: "peer-c", MeshIP: "10.0.0.3"},
	}
	policies := []api.Policy{
		{
			ID: "pol-1",
			Rules: []api.PolicyRule{
				{Src: "node-a", Dst: "peer-b", Port: 0, Protocol: "", Action: "allow"},
			},
		},
	}

	got := eng.FilterPeers(peers, policies, "node-a")
	if len(got) != 1 {
		t.Fatalf("FilterPeers() returned %d peers, want 1", len(got))
	}
	if got[0].ID != "peer-b" {
		t.Errorf("FilterPeers()[0].ID = %q, want %q", got[0].ID, "peer-b")
	}
}

func TestFilterPeers_WildcardAllowsAll(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	peers := []api.Peer{
		{ID: "peer-a", MeshIP: "10.0.0.2"},
		{ID: "peer-b", MeshIP: "10.0.0.3"},
		{ID: "peer-c", MeshIP: "10.0.0.4"},
	}
	policies := []api.Policy{
		{
			ID: "pol-open",
			Rules: []api.PolicyRule{
				{Src: "*", Dst: "*", Port: 0, Protocol: "", Action: "allow"},
			},
		},
	}

	got := eng.FilterPeers(peers, policies, "node-a")
	if len(got) != len(peers) {
		t.Fatalf("FilterPeers() returned %d peers, want %d", len(got), len(peers))
	}
}

func TestFilterPeers_DenyDoesNotGrantVisibility(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	peers := []api.Peer{
		{ID: "peer-b", MeshIP: "10.0.0.2"},
	}
	policies := []api.Policy{
		{
			ID: "pol-deny",
			Rules: []api.PolicyRule{
				{Src: "node-a", Dst: "peer-b", Port: 0, Protocol: "", Action: "deny"},
			},
		},
	}

	got := eng.FilterPeers(peers, policies, "node-a")
	if len(got) != 0 {
		t.Fatalf("FilterPeers() returned %d peers, want 0", len(got))
	}
}

func TestFilterPeers_BidirectionalAllow(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	peers := []api.Peer{
		{ID: "peer-b", MeshIP: "10.0.0.2"},
	}
	// Rule is Src=peer-b, Dst=node-a — reverse direction but should still allow visibility.
	policies := []api.Policy{
		{
			ID: "pol-reverse",
			Rules: []api.PolicyRule{
				{Src: "peer-b", Dst: "node-a", Port: 443, Protocol: "tcp", Action: "allow"},
			},
		},
	}

	got := eng.FilterPeers(peers, policies, "node-a")
	if len(got) != 1 {
		t.Fatalf("FilterPeers() returned %d peers, want 1", len(got))
	}
	if got[0].ID != "peer-b" {
		t.Errorf("FilterPeers()[0].ID = %q, want %q", got[0].ID, "peer-b")
	}
}

func TestBuildFirewallRules_BasicRule(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
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

	got := eng.BuildFirewallRules(policies, "node-a", "wg0", peersByID)
	// 1 policy rule + 1 default-deny = 2
	if len(got) != 2 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 2", len(got))
	}
	r := got[0]
	if r.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q, want %q", r.SrcIP, "10.0.0.1")
	}
	if r.DstIP != "10.0.0.2" {
		t.Errorf("DstIP = %q, want %q", r.DstIP, "10.0.0.2")
	}
	if r.Port != 443 {
		t.Errorf("Port = %d, want 443", r.Port)
	}
	if r.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want %q", r.Protocol, "tcp")
	}
	if r.Action != "allow" {
		t.Errorf("Action = %q, want %q", r.Action, "allow")
	}
	if r.Interface != "wg0" {
		t.Errorf("Interface = %q, want %q", r.Interface, "wg0")
	}
}

func TestBuildFirewallRules_WildcardSrc(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	policies := []api.Policy{
		{
			ID: "pol-wildcard",
			Rules: []api.PolicyRule{
				{Src: "*", Dst: "node-a", Port: 80, Protocol: "tcp", Action: "allow"},
			},
		},
	}
	peersByID := map[string]string{
		"node-a": "10.0.0.1",
	}

	got := eng.BuildFirewallRules(policies, "node-a", "wg0", peersByID)
	// 1 policy rule + 1 default-deny = 2
	if len(got) != 2 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 2", len(got))
	}
	if got[0].SrcIP != "0.0.0.0/0" {
		t.Errorf("SrcIP = %q, want %q", got[0].SrcIP, "0.0.0.0/0")
	}
	if got[0].DstIP != "10.0.0.1" {
		t.Errorf("DstIP = %q, want %q", got[0].DstIP, "10.0.0.1")
	}
}

func TestBuildFirewallRules_SkipsIrrelevantRules(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	policies := []api.Policy{
		{
			ID: "pol-other",
			Rules: []api.PolicyRule{
				{Src: "peer-x", Dst: "peer-y", Port: 22, Protocol: "tcp", Action: "allow"},
			},
		},
	}
	peersByID := map[string]string{
		"node-a": "10.0.0.1",
		"peer-x": "10.0.0.5",
		"peer-y": "10.0.0.6",
	}

	got := eng.BuildFirewallRules(policies, "node-a", "wg0", peersByID)
	// Only the default-deny rule should be present (no relevant policy rules).
	if len(got) != 1 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 1 (default-deny only)", len(got))
	}
	if got[0].Action != "deny" {
		t.Errorf("rule[0].Action = %q, want %q (default-deny)", got[0].Action, "deny")
	}
}

func TestBuildFirewallRules_DefaultDenyAppended(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
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

	got := eng.BuildFirewallRules(policies, "node-a", "wg0", peersByID)
	if len(got) < 2 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want at least 2", len(got))
	}

	last := got[len(got)-1]
	if last.Action != "deny" {
		t.Errorf("last rule Action = %q, want %q", last.Action, "deny")
	}
	if last.SrcIP != "0.0.0.0/0" {
		t.Errorf("last rule SrcIP = %q, want %q", last.SrcIP, "0.0.0.0/0")
	}
	if last.DstIP != "0.0.0.0/0" {
		t.Errorf("last rule DstIP = %q, want %q", last.DstIP, "0.0.0.0/0")
	}
	if last.Interface != "wg0" {
		t.Errorf("last rule Interface = %q, want %q", last.Interface, "wg0")
	}
}

func TestBuildFirewallRules_InvalidProtocolSkipped(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	policies := []api.Policy{
		{
			ID: "pol-1",
			Rules: []api.PolicyRule{
				{Src: "node-a", Dst: "peer-b", Port: 443, Protocol: "sctp", Action: "allow"},
				{Src: "node-a", Dst: "peer-b", Port: 80, Protocol: "tcp", Action: "allow"},
			},
		},
	}
	peersByID := map[string]string{
		"node-a": "10.0.0.1",
		"peer-b": "10.0.0.2",
	}

	got := eng.BuildFirewallRules(policies, "node-a", "wg0", peersByID)
	// 1 valid rule + 1 default-deny = 2 (invalid "sctp" rule skipped)
	if len(got) != 2 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 2 (invalid protocol skipped)", len(got))
	}
	if got[0].Protocol != "tcp" {
		t.Errorf("rule[0].Protocol = %q, want %q", got[0].Protocol, "tcp")
	}
	if got[0].Port != 80 {
		t.Errorf("rule[0].Port = %d, want 80", got[0].Port)
	}
}

func TestBuildFirewallRules_BothWildcards(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	policies := []api.Policy{
		{
			ID: "pol-open",
			Rules: []api.PolicyRule{
				{Src: "*", Dst: "*", Port: 0, Protocol: "", Action: "allow"},
			},
		},
	}
	peersByID := map[string]string{
		"node-a": "10.0.0.1",
	}

	got := eng.BuildFirewallRules(policies, "node-a", "wg0", peersByID)
	// 1 wildcard rule + 1 default-deny = 2
	if len(got) != 2 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 2", len(got))
	}
	if got[0].SrcIP != "0.0.0.0/0" {
		t.Errorf("rule[0].SrcIP = %q, want %q", got[0].SrcIP, "0.0.0.0/0")
	}
	if got[0].DstIP != "0.0.0.0/0" {
		t.Errorf("rule[0].DstIP = %q, want %q", got[0].DstIP, "0.0.0.0/0")
	}
}
