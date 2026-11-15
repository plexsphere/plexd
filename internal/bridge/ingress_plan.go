package bridge

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/plexsphere/plexd/internal/api"
)

// The reasons a rule of the bridge.ingress block is not served.
const (
	// IngressReasonInvalid: a field of the rule is missing or malformed; the
	// state's Detail names the field.
	IngressReasonInvalid = "invalid_rule"
	// IngressReasonDuplicateID: an earlier rule of the block has the same id.
	IngressReasonDuplicateID = "duplicate_id"
	// IngressReasonListenerConflict: a held rule has the same listen port and
	// host, or one of the two has no host; Detail is the holder's slug.
	IngressReasonListenerConflict = "listener_conflict"
	// IngressReasonMaxRules: bridge.max_ingress_rules rules are held already.
	IngressReasonMaxRules = "max_rules"
	// IngressReasonModeNotServed: the rule is held, but its mode, terminate
	// or acme, needs a certificate the block does not name yet.
	IngressReasonModeNotServed = "mode_not_served"
	// IngressReasonListenFailed: the listener for the rule's port could not
	// be opened; every later Apply tries again.
	IngressReasonListenFailed = "listen_failed"
)

// maxHostLen is the longest DNS name, in bytes, without a trailing dot.
const maxHostLen = 253

// IngressRuleState is the outcome of one rule of the last Apply.
type IngressRuleState struct {
	Rule   api.IngressRule
	Served bool
	Reason string // empty when served
	Detail string // the field of an invalid rule, or the slug of the rule that holds the listener
}

// ingressPlan is what planIngress makes of a block.
type ingressPlan struct {
	tables map[int]*ingressTable // by listen port; only ports with a held passthrough rule
	states []IngressRuleState    // one per input rule, in input order
}

// ingressTable routes the connections of one listen port.
type ingressTable struct {
	plain    *ingressRoute            // the rule without sni_host; nil on an SNI port
	exact    map[string]*ingressRoute // by lowercase host
	wildcard map[string]*ingressRoute // by the suffix after "*."
}

// ingressRoute is one held rule in a table.
type ingressRoute struct {
	rule   api.IngressRule
	target string // net.JoinHostPort(rule.TargetAddress, strconv.Itoa(rule.TargetPort))
	served bool   // false for a held terminate or acme rule
	ctx    context.Context
	cancel context.CancelFunc
}

// match returns the route for a ClientHello's server name, or nil. It compares
// case-insensitively, prefers an exact host, and otherwise looks the name up
// with its first label cut off, so *.example.com matches a.example.com and
// neither example.com nor a.b.example.com.
func (t *ingressTable) match(serverName string) *ingressRoute {
	name := strings.ToLower(serverName)
	if name == "" {
		return nil
	}
	if r, ok := t.exact[name]; ok {
		return r
	}
	label, rest, ok := strings.Cut(name, ".")
	if !ok || label == "" || rest == "" {
		return nil
	}
	return t.wildcard[rest]
}

// routes returns every route of the table.
func (t *ingressTable) routes() []*ingressRoute {
	var out []*ingressRoute
	if t.plain != nil {
		out = append(out, t.plain)
	}
	for _, r := range t.exact {
		out = append(out, r)
	}
	for _, r := range t.wildcard {
		out = append(out, r)
	}
	return out
}

// planIngress decides which rules of a block are held and builds the routing
// table of each listen port. It walks the rules in the order the pull lists
// them and gives each the first reason that applies; a rule that passes every
// check up to the bound is held. A held passthrough rule is served once its
// port is bound, and a held terminate or acme rule keeps its slot but is not
// served. Only a port with a held passthrough rule gets a table.
func planIngress(rules []api.IngressRule, maxRules int) ingressPlan {
	plan := ingressPlan{tables: make(map[int]*ingressTable)}
	if len(rules) > 0 {
		plan.states = make([]IngressRuleState, 0, len(rules))
	}

	// portHolders is what the held rules of one port occupy.
	type portHolders struct {
		first string            // slug of the first rule held on the port
		plain string            // slug of the held rule without a host
		hosts map[string]string // slug by lowercase host
		table *ingressTable
		pass  bool // a held passthrough rule is among them
	}
	ports := make(map[int]*portHolders)
	ids := make(map[string]struct{})
	held := 0

	for _, r := range rules {
		st := IngressRuleState{Rule: r}
		host := strings.ToLower(r.SNIHost)
		_, dup := ids[r.ID]
		if r.ID != "" {
			ids[r.ID] = struct{}{}
		}

		switch {
		case r.ID == "":
			st.Reason, st.Detail = IngressReasonInvalid, "id"
		case dup:
			st.Reason = IngressReasonDuplicateID
		case r.Mode != api.IngressModePassthrough && r.Mode != api.IngressModeTerminate && r.Mode != api.IngressModeACME:
			st.Reason, st.Detail = IngressReasonInvalid, "mode"
		case r.ListenPort < 1 || r.ListenPort > 65535:
			st.Reason, st.Detail = IngressReasonInvalid, "listen_port"
		case !validSNIHost(host) || (host == "" && r.Mode != api.IngressModePassthrough):
			st.Reason, st.Detail = IngressReasonInvalid, "sni_host"
		case !validTargetAddress(r.TargetAddress):
			st.Reason, st.Detail = IngressReasonInvalid, "target_address"
		case r.TargetPort < 1 || r.TargetPort > 65535:
			st.Reason, st.Detail = IngressReasonInvalid, "target_port"
		}
		if st.Reason == "" {
			if h := ports[r.ListenPort]; h != nil {
				switch {
				case h.plain != "":
					st.Reason, st.Detail = IngressReasonListenerConflict, h.plain
				case host == "":
					st.Reason, st.Detail = IngressReasonListenerConflict, h.first
				case h.hosts[host] != "":
					st.Reason, st.Detail = IngressReasonListenerConflict, h.hosts[host]
				}
			}
		}
		if st.Reason == "" && held >= maxRules {
			st.Reason = IngressReasonMaxRules
		}
		if st.Reason != "" {
			plan.states = append(plan.states, st)
			continue
		}

		// The rule is held.
		held++
		h := ports[r.ListenPort]
		if h == nil {
			h = &portHolders{
				first: r.Slug,
				hosts: make(map[string]string),
				table: &ingressTable{
					exact:    make(map[string]*ingressRoute),
					wildcard: make(map[string]*ingressRoute),
				},
			}
			ports[r.ListenPort] = h
		}
		route := &ingressRoute{
			rule:   r,
			target: net.JoinHostPort(r.TargetAddress, strconv.Itoa(r.TargetPort)),
			served: r.Mode == api.IngressModePassthrough,
		}
		switch {
		case host == "":
			h.plain = r.Slug
			h.table.plain = route
		case strings.HasPrefix(host, "*."):
			h.hosts[host] = r.Slug
			h.table.wildcard[host[2:]] = route
		default:
			h.hosts[host] = r.Slug
			h.table.exact[host] = route
		}
		if route.served {
			h.pass = true
			st.Served = true
		} else {
			st.Reason = IngressReasonModeNotServed
		}
		plan.states = append(plan.states, st)
	}

	for port, h := range ports {
		if h.pass {
			plan.tables[port] = h.table
		}
	}
	return plan
}

// validSNIHost reports whether a lowercase sni_host is empty or a name the
// bridge can match: at most 253 bytes, no empty label, and a "*" only as the
// whole first label of a name with at least two labels.
func validSNIHost(host string) bool {
	if host == "" {
		return true
	}
	if len(host) > maxHostLen {
		return false
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if label == "" {
			return false
		}
		if strings.Contains(label, "*") && (i != 0 || label != "*" || len(labels) < 2) {
			return false
		}
	}
	return true
}

// validTargetAddress reports whether target_address is an IPv4 or IPv6
// address without brackets, a port or a zone.
func validTargetAddress(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	return err == nil && ip.Zone() == ""
}
