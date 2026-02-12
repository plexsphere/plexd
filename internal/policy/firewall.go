package policy

import "fmt"

// FirewallRule describes a single iptables-style packet filter rule.
type FirewallRule struct {
	Interface string // network interface name
	SrcIP     string // source IP (CIDR or single IP)
	DstIP     string // destination IP (CIDR or single IP)
	Port      int    // destination port (0 = any)
	Protocol  string // "tcp", "udp", or "" (any)
	Action    string // "allow" or "deny"
}

// Validate checks the rule for semantic correctness and returns an error
// if any field contains an invalid value.
func (r *FirewallRule) Validate() error {
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("policy: firewall rule: invalid action %q", r.Action)
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("policy: firewall rule: invalid port %d", r.Port)
	}
	if r.Protocol != "" && r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("policy: firewall rule: invalid protocol %q", r.Protocol)
	}
	if r.Port > 0 && r.Protocol == "" {
		return fmt.Errorf("policy: firewall rule: port %d requires a protocol", r.Port)
	}
	return nil
}

// FirewallController abstracts OS-level iptables operations for testability.
type FirewallController interface {
	// EnsureChain creates the named iptables chain if it does not already exist.
	EnsureChain(chain string) error
	// ApplyRules replaces all rules in the named chain atomically.
	ApplyRules(chain string, rules []FirewallRule) error
	// FlushChain removes all rules from the named chain.
	FlushChain(chain string) error
	// DeleteChain deletes the named chain.
	// Implementations must be idempotent: deleting a non-existent chain must return nil.
	DeleteChain(chain string) error
}
