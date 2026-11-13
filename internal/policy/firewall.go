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
	errInvalidAddress = "invalid IP address %q"
	errMappedAddress  = "IPv4-mapped IPv6 address %q"
	errMixedFamily    = "source %q and destination %q differ in address family"
)

// connLogUnavailable is the Warn line every backend logs, once per apply that
// carries a logged rule, when the reader that reports the connections a logged
// rule admits cannot start. It is shared for the same reason as the texts
// above. The ruleset is installed without its log tags then: logging never
// blocks enforcement.
const connLogUnavailable = "policy connection logging unavailable, logged rules are enforced without it"

// maxLogTagLen bounds FirewallRule.LogTag, which keeps a tag inside the
// 127-byte prefix an nftables log expression carries.
const maxLogTagLen = 64

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

// RelayProbePort is the UDP port of plexd's relay liveness probe
// (relayProbePort in internal/wireguard/dial.go).
//
// DECISION: every backend lets the node send UDP to this port over the mesh
// interface without a rule, ahead of the policy rules (author, 2026-11-12,
// #178). Any local process can do so, to any address the mesh routes,
// and the receiving node's inbound rules still apply. Without the exemption a
// narrow policy fails every probe send, and plexd notices a dead relay only
// once the handshake goes stale.
const RelayProbePort = 9

// FirewallRule describes a single packet filter rule. An address field holds
// a prefix or a single address of either family; both fields together name one
// family, and a rule with both empty matches both.
//
// A backend applies each rule to what arrives on Interface, delivered to the
// node or forwarded through it, and to what the node's own sockets send over
// Interface. A rule matches by its addresses. The control plane compiles every
// authored rule for both ends (plexsphere/plexsphere#1056): the destination
// node gets a copy naming the source as sender, the source node one naming
// itself, so each copy matches one direction.
//
// DECISION: a rule carries no direction. The rejected alternative, the engine
// tagging each rule inbound or outbound, needs the node's own mesh address,
// which the engine does not receive.
type FirewallRule struct {
	Interface string // network interface name
	SrcIP     string // source IP (CIDR or single IP); "" matches every address
	DstIP     string // destination IP (CIDR or single IP); "" matches every address
	Port      int    // destination port (0 = any)
	PortTo    int    // inclusive end of a destination port range, 0 means single-Port match
	Protocol  string // "tcp", "udp", "icmp", or "" (any)
	Action    string // "allow" or "deny"
	// LogTag, when set, asks the backend to report the connections this rule
	// admits, carrying the tag. Only an allow carries one.
	LogTag string
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
	if r.LogTag != "" {
		if r.Action != "allow" {
			return fmt.Errorf("policy: firewall rule: log tag on a %q rule", r.Action)
		}
		if len(r.LogTag) > maxLogTagLen {
			return fmt.Errorf("policy: firewall rule: log tag %q longer than %d bytes", r.LogTag, maxLogTagLen)
		}
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

// admits reports whether the rule's addresses, protocol and port match the
// event. It ignores Interface and Dir: a rule matches by its addresses in
// either direction, and the backend that reported the event read it off the
// interface already. An empty address matches every address and a zero-length
// prefix every address of its family. Protocol "" matches every protocol, icmp
// matches ICMP for an IPv4 event and ICMPv6 for an IPv6 one, and a port or port
// range matches the event's destination port. The connection logger uses it to
// drop an event a backend attributed to the wrong rule.
func (r *FirewallRule) admits(ev ConnEvent) bool {
	if !addrAdmits(r.SrcIP, ev.Src) || !addrAdmits(r.DstIP, ev.Dst) {
		return false
	}
	switch r.Protocol {
	case "":
	case "tcp":
		if ev.Protocol != ipProtoTCP {
			return false
		}
	case "udp":
		if ev.Protocol != ipProtoUDP {
			return false
		}
	case "icmp":
		want := uint8(ipProtoICMP)
		if ev.Dst.Is6() {
			want = ipProtoICMPv6
		}
		if ev.Protocol != want {
			return false
		}
	default:
		return false
	}
	if r.Port > 0 {
		last := r.Port
		if r.PortTo > r.Port {
			last = r.PortTo
		}
		if int(ev.DstPort) < r.Port || int(ev.DstPort) > last {
			return false
		}
	}
	return true
}

// addrAdmits reports whether addr lies in the prefix an address field of a
// FirewallRule names. An empty field matches every address.
func addrAdmits(field string, addr netip.Addr) bool {
	prefix, ok, err := parseRuleAddr(field)
	if err != nil {
		return false
	}
	if !ok {
		return true
	}
	return prefix.Contains(addr)
}

// hasLogTags reports whether any rule carries a LogTag.
func hasLogTags(rules []FirewallRule) bool {
	for _, r := range rules {
		if r.LogTag != "" {
			return true
		}
	}
	return false
}

// withoutLogTags returns a copy of rules with every LogTag cleared, the ruleset
// a backend installs when it cannot report what its logged rules admit.
func withoutLogTags(rules []FirewallRule) []FirewallRule {
	if rules == nil {
		return nil
	}
	out := make([]FirewallRule, len(rules))
	for i, r := range rules {
		r.LogTag = ""
		out[i] = r
	}
	return out
}

// ConnDir is the direction of a connection a logged rule admitted, as the node
// sees it.
type ConnDir int

const (
	// ConnIn is a connection addressed to the node.
	ConnIn ConnDir = iota
	// ConnOut is a connection the node's own sockets opened.
	ConnOut
	// ConnForward is a connection the node routes.
	ConnForward
)

// String returns the direction as the connection line names it.
func (d ConnDir) String() string {
	switch d {
	case ConnIn:
		return "in"
	case ConnOut:
		return "out"
	case ConnForward:
		return "forward"
	}
	return fmt.Sprintf("ConnDir(%d)", int(d))
}

// ConnEvent is one connection a logged rule admitted, as a backend's kernel
// reported it. SrcPort and DstPort are 0 unless Protocol is TCP or UDP.
type ConnEvent struct {
	Tag              string
	Dir              ConnDir
	Src, Dst         netip.Addr
	Protocol         uint8
	SrcPort, DstPort uint16
}

// ConnSink receives what a backend's reader produces. Lost counts records the
// reader knows it missed.
type ConnSink interface {
	Event(ev ConnEvent)
	Lost(n int)
}

// ConnReporter is implemented by a FirewallController that can report the
// connections its logged rules admit.
type ConnReporter interface {
	SetConnSink(sink ConnSink)
}

// DropCounter is implemented by a FirewallController that counts what the
// deny rules of a chain dropped since the chain was last loaded. The engine's
// only deny is the default deny, so the count is what the default deny
// dropped. The Enforcer reports it to the control plane; a backend without it
// reports no drops.
type DropCounter interface {
	DropCounts(chain string) (packets, bytes uint64, err error)
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
	// ApplyRules replaces all rules of the named chain atomically, for
	// traffic in both directions: what arrives on a rule's interface and what
	// the node itself sends over it.
	ApplyRules(chain string, rules []FirewallRule) error
	// FlushChain removes all rules from the named chain.
	FlushChain(chain string) error
	// DeleteChain deletes the named chain.
	// Implementations must be idempotent: deleting a non-existent chain must return nil.
	DeleteChain(chain string) error
}
