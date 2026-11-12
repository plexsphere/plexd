package policy

import (
	"net/netip"
	"testing"
)

func TestFirewallRule_ValidateAcceptsValid(t *testing.T) {
	valid := []FirewallRule{
		{Action: "allow"},
		{Action: "deny"},
		{Action: "allow", Port: 443, Protocol: "tcp"},
		{Action: "deny", Port: 53, Protocol: "udp"},
		{Action: "allow", Protocol: "tcp"},
		{Action: "allow", Protocol: "icmp", DstIP: "10.0.0.1"},
		{Action: "allow", Port: 1000, PortTo: 2000, Protocol: "tcp"},
		{Action: "allow", Port: 443, PortTo: 443, Protocol: "tcp"},
		{Action: "allow", SrcIP: "10.0.0.0/8", DstIP: "192.168.1.1", Interface: "eth0"},
	}
	for _, r := range valid {
		if err := r.Validate(); err != nil {
			t.Errorf("Validate() returned error for valid rule %+v: %v", r, err)
		}
	}
}

func TestFirewallRule_ValidateRejectsInvalidAction(t *testing.T) {
	for _, action := range []string{"", "accept", "drop", "ALLOW"} {
		r := FirewallRule{Action: action}
		if err := r.Validate(); err == nil {
			t.Errorf("Validate() accepted invalid action %q", action)
		}
	}
}

func TestFirewallRule_ValidateRejectsInvalidPort(t *testing.T) {
	for _, port := range []int{-1, 65536, -100} {
		r := FirewallRule{Action: "allow", Port: port}
		if err := r.Validate(); err == nil {
			t.Errorf("Validate() accepted invalid port %d", port)
		}
	}
}

func TestFirewallRule_ValidateRejectsInvalidProtocol(t *testing.T) {
	for _, proto := range []string{"TCP", "UDP", "ICMP", "sctp"} {
		r := FirewallRule{Action: "allow", Protocol: proto}
		if err := r.Validate(); err == nil {
			t.Errorf("Validate() accepted invalid protocol %q", proto)
		}
	}
}

func TestFirewallRule_ValidateRejectsPortWithoutProtocol(t *testing.T) {
	r := FirewallRule{Action: "allow", Port: 80}
	if err := r.Validate(); err == nil {
		t.Error("Validate() accepted port > 0 with empty protocol")
	}
}

func TestFirewallRule_ValidateRejectsPortWithICMP(t *testing.T) {
	// icmp is a valid protocol, but ports are not valid for it.
	r := FirewallRule{Action: "allow", Port: 80, Protocol: "icmp"}
	if err := r.Validate(); err == nil {
		t.Error("Validate() accepted a port with icmp protocol")
	}
}

func TestFirewallRule_ValidateAcceptsICMPWithoutPort(t *testing.T) {
	r := FirewallRule{Action: "allow", Protocol: "icmp", DstIP: "10.0.0.1"}
	if err := r.Validate(); err != nil {
		t.Errorf("Validate() rejected a portless icmp rule: %v", err)
	}
}

func TestFirewallRule_ValidateRejectsPortToWithoutPort(t *testing.T) {
	r := FirewallRule{Action: "allow", PortTo: 2000, Protocol: "tcp"}
	if err := r.Validate(); err == nil {
		t.Error("Validate() accepted PortTo without a start Port")
	}
}

func TestFirewallRule_ValidateRejectsPortToBounds(t *testing.T) {
	// PortTo below Port and PortTo above 65535 are both invalid.
	for _, r := range []FirewallRule{
		{Action: "allow", Port: 2000, PortTo: 1000, Protocol: "tcp"},
		{Action: "allow", Port: 1000, PortTo: 70000, Protocol: "tcp"},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("Validate() accepted out-of-bounds port range %+v", r)
		}
	}
}

func TestFirewallRule_ValidateFamilies(t *testing.T) {
	for _, r := range []FirewallRule{
		{Action: "allow", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5"},
		{Action: "allow", SrcIP: "fd00::/64", DstIP: "fd00::1", Protocol: "icmp"},
		{Action: "allow", SrcIP: "::/0", DstIP: "fd00::1/128", Port: 443, Protocol: "tcp"},
		{Action: "deny"},
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", r, err)
		}
	}

	for _, tt := range []struct {
		rule FirewallRule
		want string
	}{
		{
			rule: FirewallRule{Action: "allow", SrcIP: "fd00::/32", DstIP: "10.99.0.5/32"},
			want: `policy: firewall rule: source "fd00::/32" and destination "10.99.0.5/32" differ in address family`,
		},
		{
			rule: FirewallRule{Action: "allow", DstIP: "::ffff:10.0.0.1"},
			want: `policy: firewall rule: IPv4-mapped IPv6 address "::ffff:10.0.0.1"`,
		},
		{
			rule: FirewallRule{Action: "allow", SrcIP: "::ffff:10.0.0.1/128"},
			want: `policy: firewall rule: IPv4-mapped IPv6 address "::ffff:10.0.0.1/128"`,
		},
		{
			rule: FirewallRule{Action: "allow", SrcIP: "not-an-ip"},
			want: `policy: firewall rule: invalid IP address "not-an-ip"`,
		},
		{
			rule: FirewallRule{Action: "allow", DstIP: "fe80::1%eth0"},
			want: `policy: firewall rule: invalid IP address "fe80::1%eth0"`,
		},
		{
			rule: FirewallRule{Action: "allow", Protocol: "icmp"},
			want: "policy: firewall rule: protocol icmp needs an address to choose between ICMP and ICMPv6",
		},
	} {
		err := tt.rule.Validate()
		if err == nil || err.Error() != tt.want {
			t.Errorf("Validate(%+v) = %v, want %q", tt.rule, err, tt.want)
		}
	}
}

func TestParseRuleAddr(t *testing.T) {
	for _, tt := range []struct {
		in     string
		want   netip.Prefix
		wantOK bool
	}{
		{in: "", want: netip.Prefix{}, wantOK: false},
		{in: "10.0.0.1", want: netip.MustParsePrefix("10.0.0.1/32"), wantOK: true},
		{in: "fd00::1", want: netip.MustParsePrefix("fd00::1/128"), wantOK: true},
		{in: "10.0.0.5/24", want: netip.MustParsePrefix("10.0.0.0/24"), wantOK: true},
		{in: "fd00::5/64", want: netip.MustParsePrefix("fd00::/64"), wantOK: true},
		{in: "0.0.0.0/0", want: netip.MustParsePrefix("0.0.0.0/0"), wantOK: true},
		{in: "::/0", want: netip.MustParsePrefix("::/0"), wantOK: true},
	} {
		got, ok, err := parseRuleAddr(tt.in)
		if err != nil || ok != tt.wantOK || got != tt.want {
			t.Errorf("parseRuleAddr(%q) = %v, %v, %v; want %v, %v, nil", tt.in, got, ok, err, tt.want, tt.wantOK)
		}
	}
}

func TestFirewallRule_Family(t *testing.T) {
	for _, tt := range []struct {
		rule FirewallRule
		want addrFamily
	}{
		{rule: FirewallRule{}, want: familyAny},
		{rule: FirewallRule{SrcIP: "10.0.0.0/8"}, want: familyIPv4},
		{rule: FirewallRule{DstIP: "0.0.0.0/0"}, want: familyIPv4},
		{rule: FirewallRule{SrcIP: "::/0", DstIP: "fd00::1"}, want: familyIPv6},
	} {
		got, err := tt.rule.family()
		if err != nil || got != tt.want {
			t.Errorf("family(%+v) = %v, %v; want %v, nil", tt.rule, got, err, tt.want)
		}
	}
}
