package policy

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureLogger returns a logger whose Info and higher lines land in buf.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// legacyAction returns a pointer to action, the shape the action key of the
// format before plexsphere/plexsphere#1058 decodes into.
func legacyAction(action string) *string {
	return &action
}

func TestBuildFirewallRules_FiveTupleMapping(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	rules := []api.PolicyRule{
		{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
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
			{Protocol: "tcp", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
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
			{Protocol: "udp", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 1000, To: 2000}},
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
		{Protocol: "tcp", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "10.0.0.0/8"},
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
		{Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"},
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
		{Protocol: "icmp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24"},
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

// A logged rule is enforced like any other. This release logs none of its
// traffic and says so once per set, not once per rule.
func TestBuildFirewallRules_LogRuleEnforcedAsAllow(t *testing.T) {
	const line = `msg="policy rules ask for logging, which this release does not do"`

	var buf bytes.Buffer
	eng := NewPolicyEngine(captureLogger(&buf))
	got, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 80, To: 80}, Log: true},
		{Protocol: "udp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.5/32", Ports: &api.PortRange{From: 53, To: 53}, Log: true},
		{Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.6/32"},
	}, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("BuildFirewallRules() returned %d rules, want 4 (three allows and the default deny)", len(got))
	}
	for _, r := range got[:3] {
		if r.Action != "allow" {
			t.Errorf("rule %+v Action = %q, want allow", r, r.Action)
		}
	}
	if n := strings.Count(buf.String(), line); n != 1 {
		t.Fatalf("log has %d logging lines, want 1:\n%s", n, buf.String())
	}
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, line) && !strings.HasSuffix(l, " count=2") {
			t.Errorf("logging line does not carry count=2: %s", l)
		}
	}

	// No logged rule: no line.
	buf.Reset()
	if _, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.6/32"},
	}, "wg0"); err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	if strings.Contains(buf.String(), line) {
		t.Errorf("logging line written for a set without logged rules:\n%s", buf.String())
	}

	// A set rejected after a logged rule: no line, since nothing is enforced.
	buf.Reset()
	if _, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Protocol: "any", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.6/32", Log: true},
		{Protocol: "sctp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.6/32"},
	}, "wg0"); err == nil {
		t.Fatal("BuildFirewallRules() error = nil, want error for the sctp rule")
	}
	if strings.Contains(buf.String(), line) {
		t.Errorf("logging line written for a rejected set:\n%s", buf.String())
	}
}

// The action key of the format before plexsphere/plexsphere#1058 reads as an
// allow when it says allow, as today's control plane sends it.
func TestBuildFirewallRules_LegacyActionAllowAccepted(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	got, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.5/32", Ports: &api.PortRange{From: 22, To: 22}},
		{LegacyAction: legacyAction("allow"), Protocol: "udp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.5/32", Ports: &api.PortRange{From: 53, To: 53}},
	}, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	want := []FirewallRule{
		{Interface: "wg0", SrcIP: "10.0.0.0/24", DstIP: "10.0.0.5/32", Port: 22, Protocol: "tcp", Action: "allow"},
		{Interface: "wg0", SrcIP: "10.0.0.0/24", DstIP: "10.0.0.5/32", Port: 53, Protocol: "udp", Action: "allow"},
		{Interface: "wg0", Action: "deny"},
	}
	if len(got) != len(want) {
		t.Fatalf("BuildFirewallRules() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Any other action rejects the whole set: a deny from a control plane that
// predates the allow-only model must not be enforced as an allow.
func TestBuildFirewallRules_LegacyActionOtherRejected(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	for _, action := range []string{"deny", "log", "", "ALLOW"} {
		_, err := eng.BuildFirewallRules([]api.PolicyRule{
			{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.5/32", Ports: &api.PortRange{From: 22, To: 22}},
			{LegacyAction: legacyAction(action), Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0"},
		}, "wg0")
		want := `policy: rule 1: unsupported action "` + action + `"`
		if err == nil || err.Error() != want {
			t.Errorf("BuildFirewallRules(action %q) error = %v, want %q", action, err, want)
		}
	}
}

// An IPv6 rule maps like an IPv4 one.
func TestBuildFirewallRules_IPv6Rule(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	got, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Protocol: "tcp", SourceCIDR: "fd00:99::/64", DestinationCIDR: "fd00:99::1/128", Ports: &api.PortRange{From: 443, To: 443}},
	}, "wg0")
	if err != nil {
		t.Fatalf("BuildFirewallRules() error = %v", err)
	}
	want := FirewallRule{Interface: "wg0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::1/128", Port: 443, Protocol: "tcp", Action: "allow"}
	if len(got) != 2 || got[0] != want {
		t.Errorf("BuildFirewallRules() = %+v, want [%+v, default deny]", got, want)
	}
}

// Each address the format forbids rejects the set with a text naming why.
func TestBuildFirewallRules_AddressErrors(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	for _, tt := range []struct {
		src, dst string
		want     string
	}{
		{src: "fd00::/32", dst: "10.99.0.5/32", want: `policy: rule 0: source_cidr "fd00::/32" and destination_cidr "10.99.0.5/32" differ in address family`},
		{src: "::ffff:10.0.0.1/128", dst: "::/0", want: `policy: rule 0: source_cidr: policy: firewall rule: IPv4-mapped IPv6 address "::ffff:10.0.0.1/128"`},
		{src: "", dst: "10.99.0.5/32", want: "policy: rule 0: source_cidr: policy: firewall rule: address is empty"},
		{src: "10.0.0.1", dst: "10.99.0.5/32", want: `policy: rule 0: source_cidr: policy: firewall rule: invalid address "10.0.0.1"`},
	} {
		_, err := eng.BuildFirewallRules([]api.PolicyRule{{Protocol: "any", SourceCIDR: tt.src, DestinationCIDR: tt.dst}}, "wg0")
		if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
			t.Errorf("BuildFirewallRules(%q -> %q) error = %v, want one starting %q", tt.src, tt.dst, err, tt.want)
		}
	}
}

func TestBuildFirewallRules_UnknownProtocolErrors(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	_, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Protocol: "sctp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.99.0.5/32"},
		{Protocol: "any", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "0.0.0.0/0"},
	}, "wg0")
	if err == nil {
		t.Fatal("BuildFirewallRules() error = nil, want error for unknown protocol")
	}
}

func TestBuildFirewallRules_PortsOnICMPErrors(t *testing.T) {
	eng := NewPolicyEngine(testLogger())
	_, err := eng.BuildFirewallRules([]api.PolicyRule{
		{Protocol: "icmp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "10.0.0.0/24", Ports: &api.PortRange{From: 80, To: 80}},
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
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 0, To: 0}},
		},
		{
			name: "negative from port",
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: -1, To: -1}},
		},
		{
			name: "from port above 65535 truncates through uint16",
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 70000, To: 70000}},
		},
		{
			name: "to port above 65535",
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 65558, To: 65558}},
		},
		{
			name: "inverted range collapses to single port",
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "0.0.0.0/0", DestinationCIDR: "10.0.0.7/32", Ports: &api.PortRange{From: 1000, To: 80}},
		},
		{
			name: "empty source cidr matches every address",
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "", DestinationCIDR: "10.99.0.5/32", Ports: &api.PortRange{From: 22, To: 22}},
		},
		{
			name: "empty destination cidr matches every address",
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "10.99.0.5/32", DestinationCIDR: "", Ports: &api.PortRange{From: 22, To: 22}},
		},
		{
			name: "source and destination of different families",
			rule: api.PolicyRule{Protocol: "tcp", SourceCIDR: "fd00::/32", DestinationCIDR: "10.99.0.5/32", Ports: &api.PortRange{From: 22, To: 22}},
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
		{{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}}},
	} {
		got, err := eng.BuildFirewallRules(rules, "wg0")
		if err != nil {
			t.Fatalf("BuildFirewallRules() error = %v", err)
		}
		if len(got) == 0 {
			t.Fatal("BuildFirewallRules() returned no rules, want at least the default-deny")
		}
		// No addresses: the default deny covers IPv4 and IPv6 alike.
		if last := got[len(got)-1]; last != (FirewallRule{Interface: "wg0", Action: "deny"}) {
			t.Errorf("trailing rule = %+v, want the address-less default deny on wg0", last)
		}
		if len(rules) == 0 {
			if len(got) != 1 {
				t.Errorf("BuildFirewallRules(%v) returned %d rules, want only the default deny", rules, len(got))
			}
		}
	}
}
