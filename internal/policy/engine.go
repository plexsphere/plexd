package policy

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/plexsphere/plexd/internal/api"
)

// PolicyEngine translates the control plane's merged policy rules into concrete
// firewall rules for the local node.
type PolicyEngine struct {
	logger *slog.Logger
}

// NewPolicyEngine creates a PolicyEngine with the given logger.
func NewPolicyEngine(logger *slog.Logger) *PolicyEngine {
	return &PolicyEngine{
		logger: logger.With("component", "policy"),
	}
}

// BuildFirewallRules converts the merged policy's rules into concrete
// FirewallRule entries for the local node.
//
// Every rule is an allow and rule order carries no meaning: a packet passes
// when any rule allows it, and the default deny appended last drops the rest.
// A rule that still carries the action key of the format before
// plexsphere/plexsphere#1058 passes only when that action is allow. Any other
// value, a deny from a control plane that predates the allow-only model
// included, rejects the set, since enforcing it as an allow would open what
// the operator denied.
//
// DECISION: one untranslatable rule rejects the whole set, and the caller
// keeps the previously installed ruleset. Under allow-only, skipping the rule
// would only narrow the ruleset, but the node would then enforce a ruleset
// that matches no revision, and a revision is reported as either applied or
// rejected (plexd#177).
//
// Protocols tcp/udp/icmp are kept and any maps to "" (match all). Both CIDRs
// must be parseable prefixes of one family, IPv4 or IPv6. An empty string
// reaches the backends as "match any address" and would silently widen the
// rule, and an IPv4-mapped IPv6 prefix would match no packet the operator
// meant. Ports are valid only for tcp/udp and must be a bounded, non-inverted
// range; a zero or out-of-range port would drop the port match entirely
// (widening the rule to every port) or wrap through uint16 onto an unrelated
// port.
//
// A rule's Log flag is read and the rule enforced like any other, but this
// release logs nothing for it: one Info line per set says how many rules asked.
//
// The trailing default-deny rule is always appended — including when rules is
// empty or nil — for a deny-by-default posture. It carries no addresses, so
// every backend applies it to both families.
func (e *PolicyEngine) BuildFirewallRules(rules []api.PolicyRule, iface string) ([]FirewallRule, error) {
	var fwRules []FirewallRule
	logged := 0

	for i, r := range rules {
		if r.LegacyAction != nil && *r.LegacyAction != "allow" {
			return nil, fmt.Errorf("policy: rule %d: unsupported action %q", i, *r.LegacyAction)
		}
		if r.Log {
			logged++
		}

		var proto string
		switch r.Protocol {
		case "tcp", "udp", "icmp":
			proto = r.Protocol
		case "any":
			proto = ""
		default:
			return nil, fmt.Errorf("policy: rule %d: unsupported protocol %q", i, r.Protocol)
		}

		src, err := validateCIDR(r.SourceCIDR)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %d: source_cidr: %w", i, err)
		}
		dst, err := validateCIDR(r.DestinationCIDR)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %d: destination_cidr: %w", i, err)
		}
		if src.Addr().Is4() != dst.Addr().Is4() {
			return nil, fmt.Errorf("policy: rule %d: source_cidr %q and destination_cidr %q differ in address family",
				i, r.SourceCIDR, r.DestinationCIDR)
		}

		// Ports are only valid for tcp/udp; a portless protocol with ports set
		// violates the contract.
		if r.Ports != nil && proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("policy: rule %d: ports set on portless protocol %q", i, r.Protocol)
		}

		var port, portTo int
		if r.Ports != nil {
			if r.Ports.From < 1 || r.Ports.From > 65535 || r.Ports.To < r.Ports.From || r.Ports.To > 65535 {
				return nil, fmt.Errorf("policy: rule %d: port range %d-%d out of bounds",
					i, r.Ports.From, r.Ports.To)
			}
			port = r.Ports.From
			if r.Ports.To > r.Ports.From {
				portTo = r.Ports.To
			}
		}

		fw := FirewallRule{
			Interface: iface,
			SrcIP:     r.SourceCIDR,
			DstIP:     r.DestinationCIDR,
			Port:      port,
			PortTo:    portTo,
			Protocol:  proto,
			Action:    "allow",
		}
		if err := fw.Validate(); err != nil {
			return nil, fmt.Errorf("policy: rule %d: %w", i, err)
		}
		fwRules = append(fwRules, fw)
	}

	if logged > 0 {
		e.logger.Info("policy rules ask for logging, which this release does not do",
			"count", logged,
		)
	}

	// Append the default-deny rule as the last rule to drop all unmatched
	// traffic (deny-by-default posture). Without addresses it covers IPv4 and
	// IPv6 alike.
	fwRules = append(fwRules, FirewallRule{
		Interface: iface,
		Action:    "deny",
	})

	e.logger.Debug("built firewall rules",
		"count", len(fwRules),
		"interface", iface,
	)
	return fwRules, nil
}

// validateCIDR parses a policy rule address, which must be an IPv4 or IPv6
// prefix. The zero value is rejected explicitly: the backends read an empty
// address as "match any", so an omitted field would widen the rule instead of
// narrowing it. An IPv4-mapped IPv6 prefix is rejected too: it names an IPv4
// host in the IPv6 family, where no mesh packet carries it.
func validateCIDR(cidr string) (netip.Prefix, error) {
	if cidr == "" {
		return netip.Prefix{}, fmt.Errorf("policy: firewall rule: address is empty")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("policy: firewall rule: invalid address %q: %w", cidr, err)
	}
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("policy: firewall rule: IPv4-mapped IPv6 address %q", cidr)
	}
	return prefix, nil
}
