package policy

import (
	"net/netip"
	"strings"
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

func TestFirewallRule_ValidateLogTag(t *testing.T) {
	allow := FirewallRule{Action: "allow", Protocol: "tcp", Port: 443, LogTag: "1/0"}
	if err := allow.Validate(); err != nil {
		t.Errorf("Validate() of an allow tagged %q = %v, want nil", allow.LogTag, err)
	}

	deny := FirewallRule{Action: "deny", LogTag: "1/0"}
	if err := deny.Validate(); err == nil || err.Error() != `policy: firewall rule: log tag on a "deny" rule` {
		t.Errorf("Validate() of a tagged deny = %v, want %q", err, `policy: firewall rule: log tag on a "deny" rule`)
	}

	long := FirewallRule{Action: "allow", LogTag: strings.Repeat("7", 65)}
	if err := long.Validate(); err == nil || !strings.Contains(err.Error(), "longer than 64 bytes") {
		t.Errorf("Validate() of a 65-byte tag = %v, want an error containing %q", err, "longer than 64 bytes")
	}

	edge := FirewallRule{Action: "allow", LogTag: strings.Repeat("7", 64)}
	if err := edge.Validate(); err != nil {
		t.Errorf("Validate() of a 64-byte tag = %v, want nil", err)
	}
}

func TestFirewallRule_Admits(t *testing.T) {
	v4 := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	rule := FirewallRule{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5/32", Port: 443, Protocol: "tcp", Action: "allow"}
	match := ConnEvent{Dir: ConnIn, Src: v4("10.0.0.7"), Dst: v4("10.1.0.5"), Protocol: ipProtoTCP, SrcPort: 40000, DstPort: 443}

	if !rule.admits(match) {
		t.Errorf("admits(%+v) = false, want true", match)
	}
	// Neither the interface nor the direction decides.
	out := match
	out.Dir = ConnOut
	if !rule.admits(out) {
		t.Errorf("admits(%+v) = false for direction out, want true", out)
	}

	for name, ev := range map[string]ConnEvent{
		"port 444":        {Src: v4("10.0.0.7"), Dst: v4("10.1.0.5"), Protocol: ipProtoTCP, DstPort: 444},
		"udp":             {Src: v4("10.0.0.7"), Dst: v4("10.1.0.5"), Protocol: ipProtoUDP, DstPort: 443},
		"source 10.0.1.7": {Src: v4("10.0.1.7"), Dst: v4("10.1.0.5"), Protocol: ipProtoTCP, DstPort: 443},
		"destination .6":  {Src: v4("10.0.0.7"), Dst: v4("10.1.0.6"), Protocol: ipProtoTCP, DstPort: 443},
		"zero event":      {},
		"an IPv6 event":   {Src: netip.MustParseAddr("fd00::7"), Dst: netip.MustParseAddr("fd00::5"), Protocol: ipProtoTCP, DstPort: 443},
	} {
		if rule.admits(ev) {
			t.Errorf("admits(%s) = true, want false", name)
		}
	}

	ranged := FirewallRule{SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 53, PortTo: 60, Protocol: "udp", Action: "allow"}
	for port, want := range map[uint16]bool{52: false, 53: true, 57: true, 60: true, 61: false} {
		ev := ConnEvent{Src: v4("10.0.0.1"), Dst: v4("10.1.0.5"), Protocol: ipProtoUDP, DstPort: port}
		if got := ranged.admits(ev); got != want {
			t.Errorf("admits() of a 53-60 rule for port %d = %v, want %v", port, got, want)
		}
	}

	icmp6 := FirewallRule{SrcIP: "fd00::/64", DstIP: "fd00::1/128", Protocol: "icmp", Action: "allow"}
	ev6 := ConnEvent{Src: netip.MustParseAddr("fd00::2"), Dst: netip.MustParseAddr("fd00::1"), Protocol: ipProtoICMPv6}
	if !icmp6.admits(ev6) {
		t.Error("an icmp IPv6 rule does not admit protocol 58")
	}
	ev6.Protocol = ipProtoICMP
	if icmp6.admits(ev6) {
		t.Error("an icmp IPv6 rule admits protocol 1")
	}

	icmp4 := FirewallRule{SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Protocol: "icmp", Action: "allow"}
	if !icmp4.admits(ConnEvent{Src: v4("10.0.0.1"), Dst: v4("10.1.0.5"), Protocol: ipProtoICMP}) {
		t.Error("an icmp IPv4 rule does not admit protocol 1")
	}

	anything := FirewallRule{Interface: "plexd0", Action: "allow"}
	udp6 := ConnEvent{Src: netip.MustParseAddr("fd00::2"), Dst: netip.MustParseAddr("fd00::1"), Protocol: ipProtoUDP, DstPort: 53}
	if !anything.admits(udp6) {
		t.Errorf("a rule without addresses or protocol does not admit %+v", udp6)
	}

	wildcard4 := FirewallRule{SrcIP: "10.0.0.0/24", DstIP: "0.0.0.0/0", Action: "allow"}
	if !wildcard4.admits(ConnEvent{Src: v4("10.0.0.1"), Dst: v4("192.0.2.9"), Protocol: ipProtoTCP}) {
		t.Error("0.0.0.0/0 does not admit an IPv4 destination")
	}
	wildcard6 := FirewallRule{DstIP: "::/0", Action: "allow"}
	if wildcard6.admits(ConnEvent{Src: v4("10.0.0.1"), Dst: v4("192.0.2.9")}) {
		t.Error("::/0 admits an IPv4 destination")
	}
}

func TestLogTagHelpers(t *testing.T) {
	if hasLogTags(nil) {
		t.Error("hasLogTags(nil) = true")
	}
	rules := []FirewallRule{
		{Interface: "plexd0", Action: "allow", LogTag: "1/0"},
		{Interface: "plexd0", Action: "deny"},
	}
	if !hasLogTags(rules) {
		t.Error("hasLogTags() = false for a ruleset with a tagged rule")
	}
	if hasLogTags(rules[1:]) {
		t.Error("hasLogTags() = true for a ruleset without a tag")
	}

	stripped := withoutLogTags(rules)
	if hasLogTags(stripped) {
		t.Errorf("withoutLogTags() = %+v, still tagged", stripped)
	}
	if rules[0].LogTag != "1/0" {
		t.Errorf("withoutLogTags() changed its input: %+v", rules[0])
	}
	if len(stripped) != 2 || stripped[0].Interface != "plexd0" || stripped[1].Action != "deny" {
		t.Errorf("withoutLogTags() = %+v, want the same rules untagged", stripped)
	}
	if withoutLogTags(nil) != nil {
		t.Error("withoutLogTags(nil) != nil")
	}
	if got := withoutLogTags([]FirewallRule{}); got == nil || len(got) != 0 {
		t.Errorf("withoutLogTags(empty) = %#v, want an empty slice", got)
	}
}

func TestConnDirString(t *testing.T) {
	for d, want := range map[ConnDir]string{ConnIn: "in", ConnOut: "out", ConnForward: "forward", ConnDir(7): "ConnDir(7)"} {
		if got := d.String(); got != want {
			t.Errorf("ConnDir(%d).String() = %q, want %q", int(d), got, want)
		}
	}
}

// The documentation and the Docker e2e suite look for this line by its text.
func TestConnLogUnavailableText(t *testing.T) {
	const want = "policy connection logging unavailable, logged rules are enforced without it"
	if connLogUnavailable != want {
		t.Errorf("connLogUnavailable = %q, want %q", connLogUnavailable, want)
	}
}
