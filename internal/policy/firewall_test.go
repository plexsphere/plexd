package policy

import "testing"

func TestFirewallRule_ValidateAcceptsValid(t *testing.T) {
	valid := []FirewallRule{
		{Action: "allow"},
		{Action: "deny"},
		{Action: "allow", Port: 443, Protocol: "tcp"},
		{Action: "deny", Port: 53, Protocol: "udp"},
		{Action: "allow", Protocol: "tcp"},
		{Action: "allow", Protocol: "icmp"},
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
	r := FirewallRule{Action: "allow", Protocol: "icmp"}
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
