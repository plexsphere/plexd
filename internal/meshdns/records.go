package meshdns

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/plexsphere/plexd/internal/api"
)

// Result is the kind of answer Lookup gives. The server turns it into a
// response code and decides which sections it fills.
type Result int

const (
	// ResultRefused means the name lies outside every accepted zone and
	// reverse zone, or no block arrived yet. The server answers REFUSED, so
	// the system resolver treats the name as not plexd's to answer. It is the
	// zero value, so an Answer nobody filled in denies nothing it should not.
	ResultRefused Result = iota
	// ResultNXDomain means the name lies under Zone and does not exist.
	ResultNXDomain
	// ResultNoData means the name exists under Zone but has no record of the
	// asked type, so the server answers NOERROR with an empty answer section.
	ResultNoData
	// ResultFound means the name has a record of the asked type: an address
	// in Addr, a PTR target in Target, or, at a zone itself, the SOA the
	// server synthesizes for Zone.
	ResultFound
)

// String returns the name of the result, for log lines and test failures.
func (r Result) String() string {
	switch r {
	case ResultRefused:
		return "refused"
	case ResultNXDomain:
		return "nxdomain"
	case ResultNoData:
		return "nodata"
	case ResultFound:
		return "found"
	default:
		return fmt.Sprintf("Result(%d)", int(r))
	}
}

// Answer is what Lookup found for a name and a type.
type Answer struct {
	// Result is the kind of answer.
	Result Result
	// Zone is the accepted zone or reverse zone with the longest label-wise
	// suffix match, set for every result but ResultRefused. It owns the SOA
	// the server synthesizes for a negative answer and for an SOA query at a
	// zone itself.
	Zone string
	// Addr is the mesh IP of an A or AAAA answer.
	Addr netip.Addr
	// Target is the fully qualified name of a PTR answer, without a
	// trailing dot.
	Target string
}

// reservedZones are the names the contract rules out as zones, with every
// name under them. arpa holds the reverse zones, which have their own list,
// and local and localhost belong to mDNS and the host itself, so a zone among
// them would swallow resolution the host depends on.
var reservedZones = []string{"arpa", "local", "localhost"}

// Records is the validated set of mesh names of one dns block. Nothing changes
// it after BuildRecords returns, so the server reads it from any number of
// goroutines and a pull replaces it whole. A nil *Records answers
// ResultRefused for every name, which is what the server holds before the
// first block.
type Records struct {
	// searchDomain is the zone of the node's own Project, or empty.
	searchDomain string
	// zones are the accepted zones, ascending.
	zones []string
	// reverseZones are the accepted reverse zones, ascending.
	reverseZones []string
	// apexes holds every accepted zone and reverse zone, the candidates for
	// the longest suffix match.
	apexes map[string]struct{}
	// hosts maps each accepted FQDN to its mesh IP.
	hosts map[string]netip.Addr
	// ptrs maps the reverse name of a mesh IP to the FQDN of the first host
	// that holds it.
	ptrs map[string]string
	// names holds every name that exists: the hosts, the reverse names, the
	// zones and reverse zones themselves, and every name above one of them,
	// which makes the empty non-terminals answer NODATA rather than NXDOMAIN.
	names map[string]struct{}
}

// BuildRecords validates block and builds the records the server answers
// from. The control plane is trusted, but a bug there must not hand the node a
// zone that swallows the host's own resolution, so every entry is checked
// where it enters. The second result names each entry that was skipped, one
// sentence per entry, for the manager to log. A zone or reverse zone listed
// twice is kept once without a sentence.
func BuildRecords(block api.NodeStateDNS) (*Records, []string) {
	var skipped []string
	r := &Records{
		apexes: make(map[string]struct{}),
		hosts:  make(map[string]netip.Addr),
		ptrs:   make(map[string]string),
		names:  make(map[string]struct{}),
	}

	zones := make(map[string]struct{})
	for _, z := range block.Zones {
		name := foldName(z)
		if reason := invalidName(name); reason != "" {
			skipped = append(skipped, fmt.Sprintf("zone %q is not a valid name because it %s", z, reason))
			continue
		}
		if reserved, ok := reservedParent(name); ok {
			if name == reserved {
				skipped = append(skipped, fmt.Sprintf("zone %q is %s itself, which the contract rules out", z, reserved))
			} else {
				skipped = append(skipped, fmt.Sprintf("zone %q is under %s, which the contract rules out", z, reserved))
			}
			continue
		}
		zones[name] = struct{}{}
	}

	reverseZones := make(map[string]struct{})
	for _, z := range block.ReverseZones {
		name := foldName(z)
		if reason := invalidName(name); reason != "" {
			skipped = append(skipped, fmt.Sprintf("reverse zone %q is not a valid name because it %s", z, reason))
			continue
		}
		if !strings.HasSuffix(name, ".in-addr.arpa") && !strings.HasSuffix(name, ".ip6.arpa") {
			skipped = append(skipped, fmt.Sprintf("reverse zone %q does not end in .in-addr.arpa or .ip6.arpa", z))
			continue
		}
		reverseZones[name] = struct{}{}
	}

	// owners maps each accepted FQDN to the node that holds it, so a repeated
	// FQDN names the node it collides with.
	owners := make(map[string]string)
	for _, h := range block.Hosts {
		name := foldName(h.FQDN)
		if reason := invalidName(name); reason != "" {
			skipped = append(skipped, fmt.Sprintf("host %q of node %q is not a valid name because it %s", h.FQDN, h.NodeID, reason))
			continue
		}
		zone, ok := longestMatch(name, zones)
		if !ok {
			skipped = append(skipped, fmt.Sprintf("host %q of node %q lies under no accepted zone", h.FQDN, h.NodeID))
			continue
		}
		if zone == name {
			skipped = append(skipped, fmt.Sprintf("host %q of node %q is the zone itself, and a host must lie at least one label below its zone", h.FQDN, h.NodeID))
			continue
		}
		addr, err := netip.ParseAddr(h.MeshIP)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("host %q of node %q has mesh_ip %q, which is not an IP address", h.FQDN, h.NodeID, h.MeshIP))
			continue
		}
		if first, dup := owners[name]; dup {
			skipped = append(skipped, fmt.Sprintf("host %q of node %q repeats the fqdn of node %q", h.FQDN, h.NodeID, first))
			continue
		}
		// An IPv4-mapped address answers A, as the IPv4 address it carries.
		// A zone means nothing in a DNS record, so it is dropped as well.
		addr = addr.Unmap().WithZone("")
		owners[name] = h.NodeID
		r.hosts[name] = addr

		rev := reverseName(addr)
		if _, under := longestMatch(rev, reverseZones); !under {
			continue
		}
		if _, taken := r.ptrs[rev]; !taken {
			r.ptrs[rev] = name
		}
	}

	if block.SearchDomain != "" {
		name := foldName(block.SearchDomain)
		if _, ok := zones[name]; ok {
			r.searchDomain = name
		} else {
			skipped = append(skipped, fmt.Sprintf("search_domain %q is no accepted zone, so the node has no search domain", block.SearchDomain))
		}
	}

	r.zones = slices.Sorted(maps.Keys(zones))
	r.reverseZones = slices.Sorted(maps.Keys(reverseZones))
	for _, z := range r.zones {
		r.apexes[z] = struct{}{}
		addWithAncestors(r.names, z)
	}
	for _, z := range r.reverseZones {
		r.apexes[z] = struct{}{}
		addWithAncestors(r.names, z)
	}
	for name := range r.hosts {
		addWithAncestors(r.names, name)
	}
	for name := range r.ptrs {
		addWithAncestors(r.names, name)
	}
	return r, skipped
}

// Lookup answers name for the type qtype. The name may carry one trailing
// dot, as a parsed question does, and is compared in ASCII lower case, so the
// answer does not depend on the spelling of the query.
func (r *Records) Lookup(name string, qtype dnsmessage.Type) Answer {
	if r == nil {
		return Answer{Result: ResultRefused}
	}
	name = foldName(strings.TrimSuffix(name, "."))
	zone, ok := longestMatch(name, r.apexes)
	if !ok {
		return Answer{Result: ResultRefused}
	}

	switch qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if addr, ok := r.hosts[name]; ok && addr.Is4() == (qtype == dnsmessage.TypeA) {
			return Answer{Result: ResultFound, Zone: zone, Addr: addr}
		}
	case dnsmessage.TypePTR:
		if target, ok := r.ptrs[name]; ok {
			return Answer{Result: ResultFound, Zone: zone, Target: target}
		}
	case dnsmessage.TypeSOA:
		if name == zone {
			return Answer{Result: ResultFound, Zone: zone}
		}
	}
	if _, ok := r.names[name]; ok {
		return Answer{Result: ResultNoData, Zone: zone}
	}
	return Answer{Result: ResultNXDomain, Zone: zone}
}

// Registration returns what the system resolver should send to server
// through the interface iface. Routing a domain routes every name under it, so
// a zone below another accepted zone is left out, which keeps the list short
// when every Project has a zone under the Domain's default domain. The search
// domain is a routing domain too, so it is left out as well. Reverse zones
// are never merged: a wider zone would make plexd deny the addresses outside
// the mesh. Each group is in ascending byte order, so equal records give equal
// registrations.
func (r *Records) Registration(iface string, server netip.AddrPort) Registration {
	reg := Registration{Interface: iface, Server: server}
	if r == nil {
		return reg
	}
	reg.SearchDomain = r.searchDomain
	for _, z := range r.zones {
		// apexes holds the reverse zones too, but no zone lies under arpa, so
		// only an accepted zone can be found above z.
		if z == r.searchDomain || hasProperAncestor(z, r.apexes) {
			continue
		}
		reg.RoutingDomains = append(reg.RoutingDomains, z)
	}
	reg.RoutingDomains = append(reg.RoutingDomains, r.reverseZones...)
	return reg
}

// Equal reports whether r and o answer every query alike, so the manager logs
// a change only when a pull changed a name. Node IDs are not answered and are
// not compared. A nil *Records equals only another nil one, so the first
// block counts as a change even when it is empty.
func (r *Records) Equal(o *Records) bool {
	if r == nil || o == nil {
		return r == o
	}
	return r.searchDomain == o.searchDomain &&
		slices.Equal(r.zones, o.zones) &&
		slices.Equal(r.reverseZones, o.reverseZones) &&
		maps.Equal(r.hosts, o.hosts) &&
		maps.Equal(r.ptrs, o.ptrs)
}

// SearchDomain returns the accepted search domain, or empty when the node has
// none.
func (r *Records) SearchDomain() string {
	if r == nil {
		return ""
	}
	return r.searchDomain
}

// HostCount returns the number of accepted hosts.
func (r *Records) HostCount() int {
	if r == nil {
		return 0
	}
	return len(r.hosts)
}

// ZoneCount returns the number of accepted zones.
func (r *Records) ZoneCount() int {
	if r == nil {
		return 0
	}
	return len(r.zones)
}

// ReverseZoneCount returns the number of accepted reverse zones.
func (r *Records) ReverseZoneCount() int {
	if r == nil {
		return 0
	}
	return len(r.reverseZones)
}

// foldName folds the ASCII letters of s to lower case and leaves every other
// byte alone. DNS compares names in ASCII case only, so strings.ToLower,
// which folds Unicode as well, would make names equal that are not.
func foldName(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// invalidName returns why name, already folded, is not a valid name, or
// empty when it is valid. A valid name has 1 to 253 characters, no trailing
// dot, and labels of 1 to 63 characters from a-z, 0-9 and - that neither
// start nor end with -. The root zone is never valid, because the empty
// name is not.
func invalidName(name string) string {
	switch {
	case name == "":
		return "is empty"
	case len(name) > 253:
		return "has more than 253 characters"
	case strings.HasSuffix(name, "."):
		return "ends in a dot"
	}
	for label := range strings.SplitSeq(name, ".") {
		switch {
		case label == "":
			return "has an empty label"
		case len(label) > 63:
			return "has a label of more than 63 characters"
		case label[0] == '-' || label[len(label)-1] == '-':
			return "has a label that starts or ends with -"
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "has a character outside a-z, 0-9 and -"
			}
		}
	}
	return ""
}

// reservedParent returns the reserved zone name equals or lies under.
func reservedParent(name string) (string, bool) {
	for _, reserved := range reservedZones {
		if name == reserved || strings.HasSuffix(name, "."+reserved) {
			return reserved, true
		}
	}
	return "", false
}

// longestMatch returns the member of set that is name itself or the nearest
// name above it, label by label, so "example.lab.internal" matches
// "lab.internal" and "xlab.internal" does not.
func longestMatch(name string, set map[string]struct{}) (string, bool) {
	for s := name; ; {
		if _, ok := set[s]; ok {
			return s, true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return "", false
		}
		s = s[i+1:]
	}
}

// hasProperAncestor reports whether a member of set lies strictly above name.
func hasProperAncestor(name string, set map[string]struct{}) bool {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return false
	}
	_, ok := longestMatch(name[i+1:], set)
	return ok
}

// addWithAncestors adds name and every name above it to names. A name already
// present had its ancestors added with it, so the walk stops there and the
// whole build stays linear in the length of the names.
func addWithAncestors(names map[string]struct{}, name string) {
	for s := name; ; {
		if _, ok := names[s]; ok {
			return
		}
		names[s] = struct{}{}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return
		}
		s = s[i+1:]
	}
}

// reverseName returns the name a PTR query for addr asks for:
// <octets reversed>.in-addr.arpa for IPv4 and <32 nibbles reversed>.ip6.arpa
// for IPv6, in lower case hex.
func reverseName(addr netip.Addr) string {
	if addr.Is4() {
		a := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", a[3], a[2], a[1], a[0])
	}
	const hex = "0123456789abcdef"
	a := addr.As16()
	var b strings.Builder
	b.Grow(len("ip6.arpa") + 4*len(a))
	for i := len(a) - 1; i >= 0; i-- {
		b.WriteByte(hex[a[i]&0x0f])
		b.WriteByte('.')
		b.WriteByte(hex[a[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String()
}
