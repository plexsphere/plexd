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

func TestBuildFirewallRules_FiveTupleMapping(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	rules := []api.PolicyRule{
		{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
	}

	got, err := eng.BuildFirewallRules(rules, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	// 1 rule + default-deny.
	if len(got) != 2 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 2", len(got))
	}
	r := got[0]
	if r.SrcIP != "10.0.0.0/24" {
		t.Errorf("SrcIP = %q, want %q", r.SrcIP, "10.0.0.0/24")
	}
	if r.DstIP != "0.0.0.0/0" {
		t.Errorf("DstIP = %q, want %q", r.DstIP, "0.0.0.0/0")
	}
	if r.Port != 443 {
		t.Errorf("Port = %d, want 443", r.Port)
	}
	if r.PortTo != 0 {
		t.Errorf("PortTo = %d, want 0 (single-port range)", r.PortTo)
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

func TestBuildFirewallRules_PortRangeMapping(t *testing.T) {
	eng := NewPolicyEngine(testLogger())

	t.Run("single-port range collapses to Port with PortTo 0", func(t *testing.T) {
		got, err := eng.BuildFirewallRules([]api.PolicyRule{
			{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
		}, "wg0")
		if err != nil {
			t.Fatalf("BuildFirewallRules() error = %v", err)
		}
		if got[0].Port != 443 || got[0].PortTo != 0 {
			t.Errorf("Port/PortTo = %d/%d, want 443/0", got[0].Port, got[0].PortTo)
		}
	})

	t.Run("multi-port range keeps PortTo", func(t *testing.T) {
		got, err := eng.BuildFirewallRules([]api.PolicyRule{
			{Action: "allow", Protocol: "udp", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 1000, To: 2000}},
		}, "wg0")
		if err != nil {
			t.Fatalf("BuildFirewallRules() error = %v", err)
		}
		if got[0].Port != 1000 || got[0].PortTo != 2000 {
			t.Errorf("Port/PortTo = %d/%d, want 1000/2000", got[0].Port, got[0].PortTo)
		}
	})
}

func TestBuildFirewallRules_PortlessRule(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	got, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "10.0.0.0/8"},
	}, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	if got[0].Port != 0 || got[0].PortTo != 0 {
		t.Errorf("Port/PortTo = %d/%d, want 0/0 for a portless rule", got[0].Port, got[0].PortTo)
	}
}

func TestBuildFirewallRules_AnyProtocolMapsToEmpty(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	got, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Action: "allow", Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"},
	}, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	if got[0].Protocol != "" {
		t.Errorf("Protocol = %q, want \"\" (any maps to empty)", got[0].Protocol)
	}
}

func TestBuildFirewallRules_ICMPPassesThrough(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	got, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Action: "allow", Protocol: "icmp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"},
	}, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	if got[0].Protocol != "icmp" {
		t.Errorf("Protocol = %q, want %q", got[0].Protocol, "icmp")
	}
	if got[0].Port != 0 {
		t.Errorf("icmp rule Port = %d, want 0", got[0].Port)
	}
}

func TestBuildFirewallRules_LogActionSkipped(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	got, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Action: "log", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 80, To: 80}},
	}, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	// The log rule is observational and non-terminating; only the trailing
	// default-deny remains.
	if len(got) != 1 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 1 (log rule skipped)", len(got))
	}
	if got[0].Action != "deny" {
		t.Errorf("remaining rule Action = %q, want %q (default-deny)", got[0].Action, "deny")
	}
}

// An unknown action must abort the whole ruleset: nftables verdicts are terminal
// and order-sensitive, so silently dropping one rule out of an ordered ACL can
// flip the verdict for the traffic it covered (a deny carving an exception out
// of a following broad allow would fail open).
func TestBuildFirewallRules_UnknownActionErrors(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	_, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Action: "deny", Protocol: "tcp", SourceCIDR: "10.0.0.99/32", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 22, To: 22}},
		{Action: "reject", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0"},
	}, "wg0")
	if err == nil {
		t.Fatal("BuildFirewallRules() error = nil, want error for unknown action")
	}
}

func TestBuildFirewallRules_UnknownProtocolErrors(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	_, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Action: "deny", Protocol: "sctp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.99.0.5/32"},
		{Action: "allow", Protocol: "any", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "0.0.0.0/0"},
	}, "wg0")
	if err == nil {
		t.Fatal("BuildFirewallRules() error = nil, want error for unknown protocol")
	}
}

func TestBuildFirewallRules_PortsOnICMPErrors(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	_, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Action: "allow", Protocol: "icmp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24", Ports: &api.PortRange{From: 80, To: 80}},
	}, "wg0")
	if err == nil {
		t.Fatal("BuildFirewallRules() error = nil, want error for ports on a portless protocol")
	}
}

// Port and CIDR bounds: every out-of-contract value widens or mis-targets a rule
// once it reaches nftables (a zero/out-of-range port drops the port match, an
// out-of-range port wraps through uint16, an empty CIDR matches every address),
// so each must abort the build rather than be silently coerced.
func TestBuildFirewallRules_PortAndCIDRBounds(t *testing.T) {
	eng := NewPolicyEngine(testLogger())

	tests := []struct {
		name string
		rule api.PolicyRule
	}{
		{
			name: "zero from port",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 0, To: 0}},
		},
		{
			name: "negative from port",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: -1, To: -1}},
		},
		{
			name: "from port above 65535 truncates through uint16",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 70000, To: 70000}},
		},
		{
			name: "to port above 65535",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 65558, To: 65558}},
		},
		{
			name: "inverted range collapses to single port",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 1000, To: 80}},
		},
		{
			name: "empty source cidr matches every address",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "", DestinationCIDR: "10.99.0.5/32", Ports: &api.PortRange{From: 22, To: 22}},
		},
		{
			name: "empty destination cidr matches every address",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "10.99.0.5/32", DestinationCIDR: "", Ports: &api.PortRange{From: 22, To: 22}},
		},
		{
			name: "non-ipv4 source cidr",
			rule: api.PolicyRule{Action: "allow", Protocol: "tcp", SourceCIDR: "fd00::/32", DestinationCIDR: "10.99.0.5/32", Ports: &api.PortRange{From: 22, To: 22}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := eng.BuildFirewallRules([]api.PolicyRule{tt.rule}, "wg0"); err == nil {
				t.Fatalf("BuildFirewallRules() error = nil, want error for %s", tt.name)
			}
		})
	}
}

func TestBuildFirewallRules_DefaultDenyAlwaysAppended(t *testing.T) {
	eng := NewPolicyEngine(testLogger())

	for _, rules := range [][]api.PolicyRule{
		nil,
		{},
		{{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}}},
	} {
		got, err := eng.BuildFirewallRules(rules, "wg0")
		if err != nil {
			t.Fatalf("BuildFirewallRules() error = %v", err)
		}
		if len(got) == 0 {
			t.Fatal("BuildFirewallRules() returned no rules, want at least the default-deny")
		}
		last := got[len(got)-1]
		if last.Action != "deny" || last.SrcIP != "0.0.0.0/0" || last.DstIP != "0.0.0.0/0" {
			t.Errorf("trailing rule = %+v, want default-deny 0.0.0.0/0", last)
		}
		if last.Interface != "wg0" {
			t.Errorf("trailing rule Interface = %q, want %q", last.Interface, "wg0")
		}
	}
}
