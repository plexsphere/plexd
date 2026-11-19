package bridge

import (
	"cmp"
	"context"
	"net/http"
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
	// holder's slug. Rules with request conditions share a port and host when
	// they all name the same mode and certificate_secret_name and no two have
	// the same conditions; a rule that breaks this conflicts with the host's
	// first held rule, or with the held rule whose conditions equal its own.
	// A udp rule has no host, so it conflicts with every held udp rule on its
	// port, and a tcp and a udp rule never conflict.
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

// The bounds of a rule's request conditions, as the control plane validates
// them.
const (
	maxPathPrefixLen      = 1024
	maxHeaderConditions   = 8
	maxHeaderNameLen      = 64
	maxHeaderValueLen     = 256
	pathPrefixPunctuation = "-._~!$&'()*+,;=:@"
	headerNamePunctuation = "!#$%&'*+-.^_`|~"
)

// IngressRuleState is the outcome of one rule of the last Apply.
type IngressRuleState struct {
	Rule   api.IngressRule
	Served bool
	Reason string // empty when served
	Detail string // the field of an invalid rule, the slug of the held rule it conflicts with, a directory URL or a Secret name

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
	plain    *ingressRoute           // the rule without sni_host; nil on an SNI port
	exact    map[string]*ingressHost // by lowercase host
	wildcard map[string]*ingressHost // by the suffix after "*."
}

// ingressHost is what one sni_host of a port routes to.
type ingressHost struct {
	// routes holds one route for a rule without conditions; otherwise the
	// rules that share the host, in precedence order.
	routes []*ingressRoute
	// http is set when the rules have conditions: the bridge reads each
	// request.
	http bool
}

// lead returns the host's first route, whose rule names the host's mode and
// Secret and whose served state is the host's.
func (h *ingressHost) lead() *ingressRoute {
	return h.routes[0]
}

// route returns the first route, in precedence order, whose conditions the
// request matches, or nil.
func (h *ingressHost) route(path string, hdr http.Header) *ingressRoute {
	for _, r := range h.routes {
		if r.matches(path, hdr) {
			return r
		}
	}
	return nil
}

// ingressRoute is one held rule in a table.
type ingressRoute struct {
	rule   api.IngressRule
	target string // net.JoinHostPort(rule.TargetAddress, strconv.Itoa(rule.TargetPort))
	served bool   // false for a held acme rule with a reason
	ctx    context.Context
	cancel context.CancelFunc
}

// matches reports whether a request matches the route's conditions: its path
// prefix is empty or "/", equals the path, or is followed by "/" in the path,
// and every header condition's value is the value of one field line of its
// name. The comparison is case-sensitive, and the path is compared as the
// client sent it, without the query.
func (r *ingressRoute) matches(path string, hdr http.Header) bool {
	if p := r.rule.Conditions.PathPrefix; p != "" && p != "/" && path != p &&
		(!strings.HasPrefix(path, p) || path[len(p)] != '/') {
		return false
	}
	for _, c := range r.rule.Conditions.Headers {
		if !slices.Contains(hdr.Values(c.Name), c.Value) {
			return false
		}
	}
	return true
}

// newIngressTable returns a table without routes.
func newIngressTable() *ingressTable {
	return &ingressTable{
		exact:    make(map[string]*ingressHost),
		wildcard: make(map[string]*ingressHost),
	}
}

// match returns the host for a ClientHello's server name, or nil. It compares
// case-insensitively, prefers an exact host, and otherwise looks the name up
// with its first label cut off, so *.example.com matches a.example.com and
// neither example.com nor a.b.example.com.
func (t *ingressTable) match(serverName string) *ingressHost {
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
	for _, h := range t.exact {
		out = append(out, h.routes...)
	}
	for _, h := range t.wildcard {
		out = append(out, h.routes...)
	}
	return out
}

// planIngress decides which rules of a block are held, builds the routing
// table of each TCP listen port and picks the route of each UDP listen port.
// It sets an empty protocol to tcp and an empty list of header conditions to
// nil on its copy of each rule before any check, so every state and route
// carries tcp or udp. It walks the rules in the order the pull lists them and
// gives each the first reason that applies; a rule that passes every check up
// to the bound is held, and the rules of both protocols count toward the
// bound. Listener conflicts are per protocol: a tcp rule conflicts only with
// held tcp rules, and a udp rule with the held udp rule of its port. Rules
// with request conditions share a host of a port under the terms the control
// plane guarantees (see IngressReasonListenerConflict); after the walk the
// routes of each host are sorted by precedence: the longer path prefix first,
// an empty one counting as "/", then more header conditions, then the lower
// slug in byte order, then the lower id. Every port with a held tcp rule gets
// a table, and
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
		first string                  // slug of the first rule held on the port
		plain string                  // slug of the held rule without a host
		hosts map[string]*ingressHost // by lowercase host
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
		// An empty list of header conditions is no condition, as an absent
		// one is.
		if len(r.Conditions.Headers) == 0 {
			r.Conditions.Headers = nil
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
		case !r.Conditions.IsZero() && r.Mode == api.IngressModePassthrough:
			// The bridge reads no request of a passthrough rule, which
			// every udp rule is.
			st.Reason, st.Detail = IngressReasonInvalid, "conditions"
		case !validPathPrefix(r.Conditions.PathPrefix):
			st.Reason, st.Detail = IngressReasonInvalid, "conditions.path_prefix"
		case !validHeaderConditions(r.Conditions.Headers):
			st.Reason, st.Detail = IngressReasonInvalid, "conditions.headers"
		case r.StripPathPrefix && (r.Conditions.PathPrefix == "" || r.Conditions.PathPrefix == "/"):
			st.Reason, st.Detail = IngressReasonInvalid, "strip_path_prefix"
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
				case h.hosts[host] != nil:
					if holder := hostConflict(h.hosts[host], r); holder != "" {
						st.Reason, st.Detail = IngressReasonListenerConflict, holder
					}
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
				hosts: make(map[string]*ingressHost),
				table: newIngressTable(),
			}
			ports[r.ListenPort] = h
		}
		route := &ingressRoute{
			rule:   r,
			target: ingressTarget(r),
			served: r.Mode != api.IngressModeACME || acme.Reason == "",
		}
		if host == "" {
			h.plain = r.Slug
			h.table.plain = route
		} else {
			ih := h.hosts[host]
			if ih == nil {
				ih = &ingressHost{http: !r.Conditions.IsZero()}
				h.hosts[host] = ih
				if strings.HasPrefix(host, "*.") {
					h.table.wildcard[host[2:]] = ih
				} else {
					h.table.exact[host] = ih
				}
			}
			ih.routes = append(ih.routes, route)
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
		for _, ih := range h.hosts {
			slices.SortFunc(ih.routes, comparePrecedence)
		}
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
				if h := challenge.match(st.Rule.SNIHost); h != nil {
					holder = h.lead()
				}
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

// hostConflict returns the slug of the held rule a rule for the held host
// conflicts with, or "" when the rule may join the host: the host's first
// held rule when the rule or the host's rules have no conditions, or the
// rule's mode or, on terminate, its certificate_secret_name differs; the held
// rule whose conditions equal the rule's otherwise. The caller walks the rules
// in block order, so routes[0] is the host's first held rule.
func hostConflict(h *ingressHost, r api.IngressRule) string {
	first := h.routes[0].rule
	switch {
	case r.Conditions.IsZero() || !h.http,
		r.Mode != first.Mode,
		r.Mode == api.IngressModeTerminate && r.CertificateSecretName != first.CertificateSecretName:
		return first.Slug
	}
	key := conditionsKey(r.Conditions)
	for _, route := range h.routes {
		if conditionsKey(route.rule.Conditions) == key {
			return route.rule.Slug
		}
	}
	return ""
}

// conditionsKey returns what tells two rules' conditions apart: the path
// prefix, "/" when it is empty, then name:value per header condition in name
// order, each ended by a line feed. A valid name holds no colon and a valid
// value no line feed.
func conditionsKey(c api.IngressConditions) string {
	prefix := c.PathPrefix
	if prefix == "" {
		prefix = "/"
	}
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteByte('\n')
	headers := slices.Clone(c.Headers)
	slices.SortFunc(headers, func(x, y api.IngressHeaderCondition) int { return strings.Compare(x.Name, y.Name) })
	for _, h := range headers {
		b.WriteString(h.Name)
		b.WriteByte(':')
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	return b.String()
}

// comparePrecedence orders the routes of a host: the longer path prefix
// first, an empty one counting as "/", then more header conditions, then the
// lower slug in byte order, then the lower id.
func comparePrecedence(a, b *ingressRoute) int {
	prefixLen := func(r *ingressRoute) int { return max(len(r.rule.Conditions.PathPrefix), 1) }
	if c := cmp.Compare(prefixLen(b), prefixLen(a)); c != 0 {
		return c
	}
	if c := cmp.Compare(len(b.rule.Conditions.Headers), len(a.rule.Conditions.Headers)); c != 0 {
		return c
	}
	if c := strings.Compare(a.rule.Slug, b.rule.Slug); c != 0 {
		return c
	}
	return strings.Compare(a.rule.ID, b.rule.ID)
}

// validPathPrefix reports whether a path prefix is empty or one the bridge
// can match: "/", or at most 1024 bytes that start with "/", do not end in
// "/", and hold segments that are not empty, "." or "..", made of letters,
// digits and - . _ ~ ! $ & ' ( ) * + , ; = : @.
func validPathPrefix(p string) bool {
	if p == "" || p == "/" {
		return true
	}
	if p[0] != '/' || len(p) > maxPathPrefixLen || strings.HasSuffix(p, "/") {
		return false
	}
	for seg := range strings.SplitSeq(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := range len(seg) {
			if !isAlnum(seg[i]) && !strings.ContainsRune(pathPrefixPunctuation, rune(seg[i])) {
				return false
			}
		}
	}
	return true
}

// validHeaderConditions reports whether header conditions are at most 8, each
// with a name of 1 to 64 lowercase RFC 9110 token characters that is not host
// and that no earlier condition carries, and a value of 1 to 256 bytes of
// 0x20 to 0x7E without a leading or trailing space.
func validHeaderConditions(headers []api.IngressHeaderCondition) bool {
	if len(headers) > maxHeaderConditions {
		return false
	}
	seen := make(map[string]struct{}, len(headers))
	for _, h := range headers {
		if !validHeaderName(h.Name) || h.Name == "host" {
			return false
		}
		if _, dup := seen[h.Name]; dup {
			return false
		}
		seen[h.Name] = struct{}{}
		if !validHeaderValue(h.Value) {
			return false
		}
	}
	return true
}

// validHeaderName reports whether name is 1 to 64 characters of lowercase
// letters, digits and ! # $ % & ' * + - . ^ _ ` | ~.
func validHeaderName(name string) bool {
	if name == "" || len(name) > maxHeaderNameLen {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && !strings.ContainsRune(headerNamePunctuation, rune(c)) {
			return false
		}
	}
	return true
}

// validHeaderValue reports whether value is 1 to 256 bytes of 0x20 to 0x7E
// that neither start nor end with a space.
func validHeaderValue(value string) bool {
	if value == "" || len(value) > maxHeaderValueLen || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7E {
			return false
		}
	}
	return true
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
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
