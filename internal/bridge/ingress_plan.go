package bridge

import (
	"context"
	"net/netip"
	"net/url"
	"slices"
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
	// IngressReasonListenerConflict: a held rule of the same protocol has the
	// same listen port and host, or one of the two has no host; Detail is the
	// holder's slug. A udp rule has no host, so it conflicts with every held
	// udp rule on its port, and a tcp and a udp rule never conflict.
	IngressReasonListenerConflict = "listener_conflict"
	// IngressReasonMaxRules: bridge.max_ingress_rules rules are held already.
	IngressReasonMaxRules = "max_rules"
	// IngressReasonListenFailed: the listener for the rule's port could not
	// be opened; every later Apply tries again.
	IngressReasonListenFailed = "listen_failed"
	// IngressReasonACMEDirectoryInvalid: the block's acme member is missing,
	// or its directory_url is not an absolute https URL; Detail is the URL.
	IngressReasonACMEDirectoryInvalid = "acme_directory_invalid"
	// IngressReasonACMEDirectoryNotAllowed: bridge.acme_directory_urls does
	// not list the block's directory_url; Detail is the URL.
	IngressReasonACMEDirectoryNotAllowed = "acme_directory_not_allowed"
	// IngressReasonACMEChallengePortTaken: a rule of another mode on port 443
	// would take the CA's challenge connection for the acme rule's host;
	// Detail is that rule's slug.
	IngressReasonACMEChallengePortTaken = "acme_challenge_port_taken"
	// IngressReasonACMENotIssued: a served acme rule whose host's last
	// certificate request did not succeed, or was not made yet. Only the
	// ingress status report carries it; the rule is served, and the next
	// client handshake asks autocert again.
	IngressReasonACMENotIssued = "acme_not_issued"
	// IngressReasonCertificateSecretNotListed: the secret inventory does not
	// list the Secret a terminate rule names; Detail is the Secret name.
	IngressReasonCertificateSecretNotListed = "certificate_secret_not_listed"
	// IngressReasonCertificateFetchFailed: the listed version of a terminate
	// rule's Secret could not be fetched yet; Detail is the Secret name.
	IngressReasonCertificateFetchFailed = "certificate_fetch_failed"
	// IngressReasonCertificateInvalid: the listed version of a terminate
	// rule's Secret holds no certificate chain with a matching key; Detail is
	// the Secret name.
	IngressReasonCertificateInvalid = "certificate_invalid"
)

// acmeChallengePort is the port the CA connects to for the TLS-ALPN-01
// challenge of an acme rule's host (RFC 8737).
const acmeChallengePort = 443

// maxHostLen is the longest DNS name, in bytes, without a trailing dot.
const maxHostLen = 253

// IngressRuleState is the outcome of one rule of the last Apply.
type IngressRuleState struct {
	Rule   api.IngressRule
	Served bool
	Reason string // empty when served
	Detail string // the field of an invalid rule, the slug of the rule that holds the listener, a directory URL or a Secret name

	// held is set for a rule that keeps its listener slot, served or not.
	held bool
}

// acmeAvailability says whether the bridge can obtain certificates for the
// block's acme rules. An empty Reason means it can; otherwise every held acme
// rule carries Reason and Detail.
type acmeAvailability struct {
	Reason, Detail string
}

// ValidACMEDirectoryURL reports whether s is an absolute https URL with a host
// and without user information, a directory the bridge can register at.
func ValidACMEDirectoryURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// checkACMEDirectory decides whether the acme member of a block names a
// directory the bridge accepts: an absolute https URL that allowed lists,
// when allowed is not empty. Entries and URL are compared after trimming
// surrounding space.
func checkACMEDirectory(settings *api.IngressACME, allowed []string) acmeAvailability {
	if settings == nil {
		return acmeAvailability{Reason: IngressReasonACMEDirectoryInvalid}
	}
	dir := settings.DirectoryURL
	if !ValidACMEDirectoryURL(dir) {
		return acmeAvailability{Reason: IngressReasonACMEDirectoryInvalid, Detail: dir}
	}
	if len(allowed) > 0 && !slices.ContainsFunc(allowed, func(a string) bool {
		return strings.TrimSpace(a) == strings.TrimSpace(dir)
	}) {
		return acmeAvailability{Reason: IngressReasonACMEDirectoryNotAllowed, Detail: dir}
	}
	return acmeAvailability{}
}

// ingressPlan is what planIngress makes of a block: a routing table for each
// TCP listen port and a route for each UDP listen port.
type ingressPlan struct {
	tables map[int]*ingressTable // by listen port; every port with a held tcp rule, and the challenge port
	udp    map[int]*ingressRoute // by listen port; the held udp rule of each port, served
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
	served bool   // false for a held acme rule with a reason
	ctx    context.Context
	cancel context.CancelFunc
}

// newIngressTable returns a table without routes.
func newIngressTable() *ingressTable {
	return &ingressTable{
		exact:    make(map[string]*ingressRoute),
		wildcard: make(map[string]*ingressRoute),
	}
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

// planIngress decides which rules of a block are held, builds the routing
// table of each TCP listen port and picks the route of each UDP listen port.
// It sets an empty protocol to tcp on its copy of each rule before any check,
// so every state and route carries tcp or udp. It walks the rules in the order
// the pull lists them and gives each the first reason that applies; a rule
// that passes every check up to the bound is held, and the rules of both
// protocols count toward the bound. Listener conflicts are per protocol: a
// tcp rule conflicts only with held tcp rules, and a udp rule with the held
// udp rule of its port. Every port with a held tcp rule gets a table, and
// every port with a held udp rule gets that rule's route in plan.udp, served.
// A held passthrough or terminate rule is served once its port is bound (a
// terminate rule also needs its certificate, which the manager overlays). A
// held acme rule is served when acme carries no reason and no rule of another
// mode on TCP port 443 would take the CA's challenge connection for its host;
// when one is served and TCP port 443 holds no rule, the plan adds an empty
// table for 443, so the port opens for challenges. A udp rule on 443 neither
// takes the challenge connection nor holds the port for it.
func planIngress(rules []api.IngressRule, maxRules int, acme acmeAvailability) ingressPlan {
	plan := ingressPlan{
		tables: make(map[int]*ingressTable),
		udp:    make(map[int]*ingressRoute),
	}
	if len(rules) > 0 {
		plan.states = make([]IngressRuleState, 0, len(rules))
	}

	// portHolders is what the held rules of one port occupy.
	type portHolders struct {
		first string            // slug of the first rule held on the port
		plain string            // slug of the held rule without a host
		hosts map[string]string // slug by lowercase host
		table *ingressTable
	}
	// heldACME is a held acme rule: its state's index and its route.
	type heldACME struct {
		state int
		route *ingressRoute
	}
	ports := make(map[int]*portHolders)
	ids := make(map[string]struct{})
	var acmeRules []heldACME
	held := 0

	for _, r := range rules {
		// A rule without a protocol, as a control plane before
		// plexsphere/plexsphere#1110 sends it, is a tcp rule. Apply keeps a
		// route whose rule compares equal to the last one, so the rule must
		// not change when the control plane starts to send the member.
		if r.Protocol == "" {
			r.Protocol = api.IngressProtocolTCP
		}
		udp := r.Protocol == api.IngressProtocolUDP
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
		case r.Protocol != api.IngressProtocolTCP && !udp:
			st.Reason, st.Detail = IngressReasonInvalid, "protocol"
		case (r.Mode != api.IngressModePassthrough && r.Mode != api.IngressModeTerminate && r.Mode != api.IngressModeACME) ||
			(udp && r.Mode != api.IngressModePassthrough):
			// The bridge forwards a udp rule's datagrams unchanged, so a udp
			// rule is a passthrough rule.
			st.Reason, st.Detail = IngressReasonInvalid, "mode"
		case r.ListenPort < 1 || r.ListenPort > 65535:
			st.Reason, st.Detail = IngressReasonInvalid, "listen_port"
		case (udp && host != "") || !validSNIHost(host) || (host == "" && r.Mode != api.IngressModePassthrough) ||
			(r.Mode == api.IngressModeACME && (strings.HasPrefix(host, "*.") || !strings.Contains(host, "."))):
			// A udp rule has no server name to match. An acme rule never
			// names a wildcard, and autocert refuses a name of one label.
			st.Reason, st.Detail = IngressReasonInvalid, "sni_host"
		case !validTargetAddress(r.TargetAddress):
			st.Reason, st.Detail = IngressReasonInvalid, "target_address"
		case r.TargetPort < 1 || r.TargetPort > 65535:
			st.Reason, st.Detail = IngressReasonInvalid, "target_port"
		case r.Mode == api.IngressModeTerminate && !api.ValidSecretName(r.CertificateSecretName):
			st.Reason, st.Detail = IngressReasonInvalid, "certificate_secret_name"
		}
		if st.Reason == "" {
			if udp {
				if holder := plan.udp[r.ListenPort]; holder != nil {
					st.Reason, st.Detail = IngressReasonListenerConflict, holder.rule.Slug
				}
			} else if h := ports[r.ListenPort]; h != nil {
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
		if udp {
			plan.udp[r.ListenPort] = &ingressRoute{rule: r, target: ingressTarget(r), served: true}
			st.held, st.Served = true, true
			plan.states = append(plan.states, st)
			continue
		}
		h := ports[r.ListenPort]
		if h == nil {
			h = &portHolders{
				first: r.Slug,
				hosts: make(map[string]string),
				table: newIngressTable(),
			}
			ports[r.ListenPort] = h
		}
		route := &ingressRoute{
			rule:   r,
			target: ingressTarget(r),
			served: r.Mode != api.IngressModeACME || acme.Reason == "",
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
		st.held = true
		st.Served = route.served
		if !route.served {
			st.Reason, st.Detail = acme.Reason, acme.Detail
		}
		if r.Mode == api.IngressModeACME {
			acmeRules = append(acmeRules, heldACME{state: len(plan.states), route: route})
		}
		plan.states = append(plan.states, st)
	}

	for port, h := range ports {
		plan.tables[port] = h.table
	}

	// The CA proves an acme host on port 443, so a rule of another mode that
	// port 443 routes the host to would take the challenge connection.
	challenge := plan.tables[acmeChallengePort]
	challenged := false
	for _, a := range acmeRules {
		st := &plan.states[a.state]
		if st.Reason != "" {
			continue
		}
		if challenge != nil {
			holder := challenge.plain
			if holder == nil {
				holder = challenge.match(st.Rule.SNIHost)
			}
			if holder != nil && holder.rule.Mode != api.IngressModeACME {
				a.route.served = false
				st.Served = false
				st.Reason, st.Detail = IngressReasonACMEChallengePortTaken, holder.rule.Slug
				continue
			}
		}
		challenged = true
	}
	if challenged && challenge == nil {
		plan.tables[acmeChallengePort] = newIngressTable()
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
