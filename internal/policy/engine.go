package policy

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// PolicyEngine evaluates network policies to determine peer visibility
// and to generate firewall rules for the local node.
type PolicyEngine struct {
	logger *slog.Logger
}

// NewPolicyEngine creates a PolicyEngine with the given logger.
func NewPolicyEngine(logger *slog.Logger) *PolicyEngine {
	return &PolicyEngine{
		logger: logger.With("component", "policy"),
	}
}

// FilterPeers returns the subset of peers that the local node is allowed to
// communicate with according to the provided policies. If no policies are
// supplied, no peers are returned (deny-by-default).
func (e *PolicyEngine) FilterPeers(peers []api.Peer, policies []api.Policy, localNodeID string) []api.Peer {
	if len(policies) == 0 {
		e.logger.Debug("no policies defined, denying all peers (deny-by-default)")
		return nil
	}

	var allowed []api.Peer
	for _, p := range peers {
		if p.ID == localNodeID {
			continue
		}
		if e.peerAllowed(p.ID, localNodeID, policies) {
			allowed = append(allowed, p)
		}
	}

	e.logger.Debug("filtered peers by policy",
		"total", len(peers),
		"allowed", len(allowed),
		"local_node", localNodeID,
	)
	return allowed
}

// peerAllowed returns true if any allow rule in any policy references both
// the local node and the peer (in either direction). The wildcard "*" matches
// any node ID.
func (e *PolicyEngine) peerAllowed(peerID, localNodeID string, policies []api.Policy) bool {
	for _, pol := range policies {
		for _, r := range pol.Rules {
			if r.Action != "allow" {
				continue
			}
			srcMatchesLocal := r.Src == localNodeID || r.Src == "*"
			dstMatchesPeer := r.Dst == peerID || r.Dst == "*"
			if srcMatchesLocal && dstMatchesPeer {
				return true
			}

			srcMatchesPeer := r.Src == peerID || r.Src == "*"
			dstMatchesLocal := r.Dst == localNodeID || r.Dst == "*"
			if srcMatchesPeer && dstMatchesLocal {
				return true
			}
		}
	}
	return false
}

// BuildFirewallRules converts policy rules into concrete FirewallRule entries
// for the local node. peersByID maps peer IDs to their mesh IPs. Only rules
// that reference localNodeID (or the wildcard "*") are included.
func (e *PolicyEngine) BuildFirewallRules(policies []api.Policy, localNodeID string, iface string, peersByID map[string]string) []FirewallRule {
	localIP := peersByID[localNodeID]
	var rules []FirewallRule

	for _, pol := range policies {
		for _, r := range pol.Rules {
			if !isValidProtocol(r.Protocol) {
				e.logger.Warn("skipping rule with invalid protocol",
					"policy_id", pol.ID,
					"protocol", r.Protocol,
				)
				continue
			}

			srcMatchesLocal := r.Src == localNodeID || r.Src == "*"
			dstMatchesLocal := r.Dst == localNodeID || r.Dst == "*"

			if !srcMatchesLocal && !dstMatchesLocal {
				continue
			}

			var srcIP, dstIP string

			if srcMatchesLocal && !dstMatchesLocal {
				// Outbound: local → peer
				srcIP = localIP
				dstIP = e.resolveIP(r.Dst, peersByID)
			} else if dstMatchesLocal && !srcMatchesLocal {
				// Inbound: peer → local
				srcIP = e.resolveIP(r.Src, peersByID)
				dstIP = localIP
			} else {
				// Both match local (e.g. wildcard on both sides)
				srcIP = e.resolveWildcard(r.Src, localIP)
				dstIP = e.resolveWildcard(r.Dst, localIP)
			}

			rules = append(rules, FirewallRule{
				Interface: iface,
				SrcIP:     srcIP,
				DstIP:     dstIP,
				Port:      r.Port,
				Protocol:  r.Protocol,
				Action:    r.Action,
			})
		}
	}

	// Append default-deny rule as the last rule to drop all unmatched traffic.
	rules = append(rules, FirewallRule{
		Interface: iface,
		SrcIP:     "0.0.0.0/0",
		DstIP:     "0.0.0.0/0",
		Port:      0,
		Protocol:  "",
		Action:    "deny",
	})

	e.logger.Debug("built firewall rules",
		"count", len(rules),
		"local_node", localNodeID,
		"interface", iface,
	)
	return rules
}

// isValidProtocol returns true if the protocol is one of the supported values.
func isValidProtocol(proto string) bool {
	return proto == "" || proto == "tcp" || proto == "udp"
}

// resolveIP returns the mesh IP for a peer ID, or "0.0.0.0/0" for the wildcard "*".
func (e *PolicyEngine) resolveIP(id string, peersByID map[string]string) string {
	if id == "*" {
		return "0.0.0.0/0"
	}
	return peersByID[id]
}

// resolveWildcard returns "0.0.0.0/0" for "*", otherwise the given fallback IP.
func (e *PolicyEngine) resolveWildcard(id, fallback string) string {
	if id == "*" {
		return "0.0.0.0/0"
	}
	return fallback
}
