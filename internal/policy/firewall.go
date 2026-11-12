package policy

import (
	"errors"
	"fmt"
	"net/netip"
)

// The formats every backend rejects an address field with, so a rejected rule
// reads the same on Linux, macOS and Windows. The three renderers sit in
// build-tagged files that no single test compiles together, which is why the
// text is shared here rather than repeated in each of them.
const (
	errNonIPv4Address = "non-IPv4 address %q"
	errInvalidAddress = "invalid IP address %q"
	errMappedAddress  = "IPv4-mapped IPv6 address %q"
	errMixedFamily    = "source %q and destination %q differ in address family"
)

// addrFamily is the address family a rule's addresses select.
type addrFamily int

const (
	// familyAny is a rule without addresses. It governs both families, which
	// is what the default deny needs.
	familyAny addrFamily = iota
	familyIPv4
	familyIPv6
)

// parseRuleAddr parses one address field of a FirewallRule. The second result
// is false for an empty field, which matches every address of either family.
// A prefix comes back masked, and a bare address as its host prefix. A
// zero-length prefix, 0.0.0.0/0 or ::/0, is every address of its family: a
// backend renders it as a family match without an address match.
//
// An IPv4-mapped IPv6 address is refused rather than unmapped: it would match
// IPv6 packets that never carry it, or IPv4 packets under a family the rule
// did not name. A zone is refused as well, because a rule names no link.
func parseRuleAddr(addr string) (netip.Prefix, bool, error) {
	if addr == "" {
		return netip.Prefix{}, false, nil
	}

	if prefix, err := netip.ParsePrefix(addr); err == nil {
		if prefix.Addr().Is4In6() {
			return netip.Prefix{}, false, fmt.Errorf(errMappedAddress, addr)
		}
		return prefix.Masked(), true, nil
	}

	parsed, err := netip.ParseAddr(addr)
	if err != nil || parsed.Zone() != "" {
		return netip.Prefix{}, false, fmt.Errorf(errInvalidAddress, addr)
	}
	if parsed.Is4In6() {
		return netip.Prefix{}, false, fmt.Errorf(errMappedAddress, addr)
	}
	return netip.PrefixFrom(parsed, parsed.BitLen()), true, nil
}

// familyOf returns the family of a parsed prefix.
func familyOf(prefix netip.Prefix) addrFamily {
	if prefix.Addr().Is4() {
		return familyIPv4
	}
	return familyIPv6
}

// FirewallRule describes a single packet filter rule. An address field holds
// a prefix or a single address of either family; both fields together name one
// family, and a rule with both empty matches both.
type FirewallRule struct {
	Interface string // network interface name
	SrcIP     string // source IP (CIDR or single IP); "" matches every address
	DstIP     string // destination IP (CIDR or single IP); "" matches every address
	Port      int    // destination port (0 = any)
	PortTo    int    // inclusive end of a destination port range, 0 means single-Port match
	Protocol  string // "tcp", "udp", "icmp", or "" (any)
	Action    string // "allow" or "deny"
}

// family returns the address family the rule's addresses select: familyAny
// when both are empty, otherwise the family of the ones present. Two addresses
// of different families are an error, since no packet carries both.
func (r *FirewallRule) family() (addrFamily, error) {
	src, srcOK, err := parseRuleAddr(r.SrcIP)
	if err != nil {
		return familyAny, err
	}
	dst, dstOK, err := parseRuleAddr(r.DstIP)
	if err != nil {
		return familyAny, err
	}

	switch {
	case srcOK && dstOK:
		if src.Addr().Is4() != dst.Addr().Is4() {
			return familyAny, fmt.Errorf(errMixedFamily, r.SrcIP, r.DstIP)
		}
		return familyOf(src), nil
	case srcOK:
		return familyOf(src), nil
	case dstOK:
		return familyOf(dst), nil
	}
	return familyAny, nil
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
	if r.Protocol != "" && r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" {
		return fmt.Errorf("policy: firewall rule: invalid protocol %q", r.Protocol)
	}
	if r.Port > 0 && r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("policy: firewall rule: port %d requires protocol tcp or udp", r.Port)
	}
	if r.PortTo != 0 {
		if r.Port <= 0 {
			return fmt.Errorf("policy: firewall rule: port range end %d requires a start port", r.PortTo)
		}
		if r.PortTo < r.Port || r.PortTo > 65535 {
			return fmt.Errorf("policy: firewall rule: invalid port range end %d", r.PortTo)
		}
	}
	fam, err := r.family()
	if err != nil {
		return fmt.Errorf("policy: firewall rule: %w", err)
	}
	// ICMP and ICMPv6 are different protocols with different numbers, and a
	// rule without an address names neither family.
	if r.Protocol == "icmp" && fam == familyAny {
		return errors.New("policy: firewall rule: protocol icmp needs an address to choose between ICMP and ICMPv6")
	}
	return nil
}

// FirewallController abstracts OS-level iptables operations for testability.
type FirewallController interface {
	// Probe reports whether the backend is usable, without changing any kernel
	// state. It must exercise the same privileged path the mutating calls take,
	// so a missing capability or an unavailable subsystem surfaces here rather
	// than on the first EnsureChain.
	Probe() error
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
