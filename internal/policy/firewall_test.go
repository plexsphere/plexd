package policy

import "testing"

func TestFirewallRule_ValidateAcceptsValid(t *testing.T) {
	valid := []FirewallRule{
		{Action: "allow"},
		{Action: "deny"},
		{Action: "allow", Port: 443, Protocol: "tcp"},
		{Action: "deny", Port: 53, Protocol: "udp"},
		{Action: "allow", Protocol: "tcp"},
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
	for _, proto := range []string{"icmp", "TCP", "UDP", "sctp"} {
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
