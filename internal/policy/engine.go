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

// BuildFirewallRules converts the merged policy's five-tuple rules into concrete
// FirewallRule entries for the local node.
//
// The ruleset is ordered and nftables verdicts are terminal: the first matching
// rule decides accept or drop. Dropping one rule out of the middle therefore
// changes the verdict for the traffic it covered rather than merely omitting an
// entry — a deny that carves an exception out of a following broad allow would
// fail open. Every unparseable rule is therefore an error for the whole set, so
// the caller keeps the previously installed ruleset and retries.
//
// Actions allow and deny are kept and a log action is the sole skip: it is
// observational only (the nftables layer has no log verdict) and non-terminating
// in the control plane's policy language, so omitting it cannot change the
// accept/drop outcome. Protocols tcp/udp/icmp are kept and any maps to ""
// (match all). Both CIDRs must be parseable IPv4 prefixes — an empty string
// reaches nftables as "match any address" and would silently widen the rule.
// Ports are valid only for tcp/udp and must be a bounded, non-inverted range;
// a zero or out-of-range port would drop the port match entirely (widening the
// rule to every port) or wrap through uint16 onto an unrelated port.
//
// The trailing default-deny rule is always appended — including when rules is
// empty or nil — for a deny-by-default posture.
func (e *PolicyEngine) BuildFirewallRules(rules []api.PolicyRule, iface string) ([]FirewallRule, error) {
	var fwRules []FirewallRule

	for i, r := range rules {
		var action string
		switch r.Action {
		case "allow", "deny":
			action = r.Action
		case "log":
			e.logger.Warn("skipping log rule (observational only)",
				"action", r.Action,
			)
			continue
		default:
			return nil, fmt.Errorf("policy: rule %d: unsupported action %q", i, r.Action)
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

		if err := validateCIDR(r.SourceCIDR); err != nil {
			return nil, fmt.Errorf("policy: rule %d: source_cidr: %w", i, err)
		}
		if err := validateCIDR(r.DestinationCIDR); err != nil {
			return nil, fmt.Errorf("policy: rule %d: destination_cidr: %w", i, err)
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
			Action:    action,
		}
		if err := fw.Validate(); err != nil {
			return nil, fmt.Errorf("policy: rule %d: %w", i, err)
		}
		fwRules = append(fwRules, fw)
	}

	// Append the default-deny rule as the last rule to drop all unmatched
	// traffic (deny-by-default posture).
	fwRules = append(fwRules, FirewallRule{
		Interface: iface,
		SrcIP:     "0.0.0.0/0",
		DstIP:     "0.0.0.0/0",
		Port:      0,
		Protocol:  "",
		Action:    "deny",
	})

	e.logger.Debug("built firewall rules",
		"count", len(fwRules),
		"interface", iface,
	)
	return fwRules, nil
}

// validateCIDR checks that a policy rule address is a parseable IPv4 prefix.
// The zero value is rejected explicitly: the nftables backend reads an empty
// address as "match any", so an omitted field would widen the rule instead of
// narrowing it.
func validateCIDR(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("policy: firewall rule: address is empty")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("policy: firewall rule: invalid address %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return fmt.Errorf("policy: firewall rule: non-IPv4 address %q", cidr)
	}
	return nil
}
