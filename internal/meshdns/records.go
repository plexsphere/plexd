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
	// reverse zone, or no block arrived yet. The server forwards a query for
	// such a name when its forwarding table routes the name, and otherwise
	// answers REFUSED, so the system resolver treats the name as not plexd's
	// to answer. It is the zero value, so an Answer nobody filled in denies
	// nothing it should not.
	ResultRefused Result = iota
	// ResultNXDomain means the name lies under Zone and does not exist.
	ResultNXDomain
	// ResultNoData means the name exists under Zone but has no record of the
	// asked type, so the server answers NOERROR with an empty answer section.
	ResultNoData
	// ResultFound means the name has a record of the asked type, or is a
	// CNAME the system resolver follows on: the records are in RRs.
	ResultFound
)

// maxCNAMEChain is how many CNAME records one answer holds at most. A chain
// that reaches the limit ends with its last CNAME, as one that leaves the
// zones plexd answers does, so the client follows on from there, and a chain
// longer than any real one fails at the client's own limit.
const maxCNAMEChain = 8

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
	// suffix match of the name the lookup ended at, set for every result but
	// ResultRefused. It owns the SOA the server synthesizes for a negative
	// answer. After a CNAME into another zone it is the target's zone.
	Zone string
	// RRs are the records of the answer section in order: the CNAME records
	// a lookup followed, then the records of the asked type. A negative
	// answer carries the CNAME records that led to it, and none otherwise.
	// The records share their Text with the Records they came from, which
	// nothing changes.
	RRs []RR
}

// RR is one resource record of an answer. Name and Target are folded to
// lower case and carry no trailing dot. Only the members of Type are set: Addr
// for A and AAAA, Target for PTR and CNAME, Priority and Target for MX, whose
// preference Priority holds, Priority, Weight, Port and Target for SRV, and
// Text for TXT. An SOA record carries Name alone, because the server
// synthesizes its data.
type RR struct {
	Name     string
	Type     dnsmessage.Type
	Addr     netip.Addr
	Target   string
	Priority uint16
	Weight   uint16
	Port     uint16
	Text     []string
}

// equal reports whether rr and o are the same record, Text compared in order.
func (rr RR) equal(o RR) bool {
	return rr.Name == o.Name && rr.Type == o.Type && rr.Addr == o.Addr &&
		rr.Target == o.Target && rr.Priority == o.Priority && rr.Weight == o.Weight &&
		rr.Port == o.Port && slices.Equal(rr.Text, o.Text)
}

// recordTypes maps the record types the contract defines to their DNS types.
// A record of any other type is skipped.
var recordTypes = map[string]dnsmessage.Type{
	"A":     dnsmessage.TypeA,
	"AAAA":  dnsmessage.TypeAAAA,
	"CNAME": dnsmessage.TypeCNAME,
	"TXT":   dnsmessage.TypeTXT,
	"SRV":   dnsmessage.TypeSRV,
	"MX":    dnsmessage.TypeMX,
}

// maxTextLen is the longest TXT string a DNS message carries, RFC 1035's
// limit on one character-string.
const maxTextLen = 255

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
	// records maps each accepted record name to its records, in the order
	// of the block. A CNAME is the only record at its name.
	records map[string][]RR
	// recordCount is the number of accepted records.
	recordCount int
	// names holds every name that exists: the hosts, the reverse names, the
	// record names, the zones and reverse zones themselves, and every name
	// above one of them, which makes the empty non-terminals answer NODATA
	// rather than NXDOMAIN.
	names map[string]struct{}
}

// BuildRecords validates block and builds the records the server answers
// from. The control plane is trusted, but a bug there must not hand the node a
// zone that swallows the host's own resolution, so every entry is checked
// where it enters. The second result names each entry that was skipped, one
// sentence per entry, for the manager to log. A zone or reverse zone listed
// twice is kept once without a sentence. Records are checked against what a
// DNS message needs, not against the limits the control plane sets on them,
// so a change of those limits needs no new plexd.
func BuildRecords(block api.NodeStateDNS) (*Records, []string) {
	var skipped []string
	r := &Records{
		apexes:  make(map[string]struct{}),
		hosts:   make(map[string]netip.Addr),
		ptrs:    make(map[string]string),
		records: make(map[string][]RR),
		names:   make(map[string]struct{}),
	}

	zones := make(map[string]struct{})
	for _, z := range block.Zones {
		name := foldName(z)
		if reason := invalidName(name, false); reason != "" {
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
		if reason := invalidName(name, false); reason != "" {
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
		if reason := invalidName(name, false); reason != "" {
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

	for _, rec := range block.Records {
		if reason := r.addRecord(rec, zones, owners); reason != "" {
			skipped = append(skipped, fmt.Sprintf("record %q of type %q %s", rec.FQDN, rec.Type, reason))
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
	for name := range r.records {
		addWithAncestors(r.names, name)
	}
	return r, skipped
}

// addRecord validates rec and adds it to r, or returns why it is skipped,
// naming the first check it failed. zones are the accepted zones and owners
// the accepted hosts by FQDN, with the node that holds each. The checks run in
// this order: the type, the name, the zone the name lies under, a host at the
// name, the data, a CNAME beside another record, and a repeat. The first
// record at a name decides the CNAME check, so of a CNAME and an address
// record at one name, the one the block lists first stays.
func (r *Records) addRecord(rec api.NodeStateDNSRecord, zones map[string]struct{}, owners map[string]string) string {
	t, ok := recordTypes[rec.Type]
	if !ok {
		return "has a type plexd does not answer"
	}
	name := foldName(rec.FQDN)
	if reason := invalidName(name, true); reason != "" {
		return "is not a valid name because it " + reason
	}
	if _, ok := longestMatch(name, zones); !ok {
		return "lies under no accepted zone"
	}
	if node, ok := owners[name]; ok {
		return fmt.Sprintf("is the name of node %q, which is answered from hosts only", node)
	}
	rr, reason := recordData(name, t, rec)
	if reason != "" {
		return reason
	}
	set := r.records[name]
	if len(set) > 0 && (set[0].Type == dnsmessage.TypeCNAME || t == dnsmessage.TypeCNAME) {
		return "shares its name with a CNAME, which is the only record at its name"
	}
	for _, o := range set {
		if o.equal(rr) {
			return "repeats an earlier record"
		}
	}
	r.records[name] = append(set, rr)
	r.recordCount++
	return ""
}

// recordData returns the record of type t at name with the data of rec, or
// why the data breaks the rule of t. A member t does not take is ignored, so
// a member a later contract adds costs no record.
func recordData(name string, t dnsmessage.Type, rec api.NodeStateDNSRecord) (RR, string) {
	rr := RR{Name: name, Type: t}
	var reason string
	switch t {
	case dnsmessage.TypeA:
		addr, err := netip.ParseAddr(rec.Address)
		if err != nil || addr.Zone() != "" || !addr.Is4() {
			return RR{}, fmt.Sprintf("has address %q, which is not an IPv4 address", rec.Address)
		}
		rr.Addr = addr
	case dnsmessage.TypeAAAA:
		// An IPv4-mapped address is an IPv4 address in an AAAA record's
		// clothes, which no client asking for AAAA wants.
		addr, err := netip.ParseAddr(rec.Address)
		if err != nil || addr.Zone() != "" || !addr.Is6() || addr.Is4In6() {
			return RR{}, fmt.Sprintf("has address %q, which is not an IPv6 address", rec.Address)
		}
		rr.Addr = addr
	case dnsmessage.TypeCNAME:
		if rr.Target, reason = recordTarget(rec.Target); reason != "" {
			return RR{}, reason
		}
	case dnsmessage.TypeTXT:
		if len(rec.Text) == 0 {
			return RR{}, "has no text"
		}
		for _, s := range rec.Text {
			if len(s) > maxTextLen {
				return RR{}, fmt.Sprintf("has a text string of more than %d bytes", maxTextLen)
			}
		}
		// A copy, so nothing the block's owner does later reaches the
		// records the server answers from.
		rr.Text = slices.Clone(rec.Text)
	case dnsmessage.TypeSRV:
		if rr.Priority, reason = recordNumber("priority", rec.Priority); reason != "" {
			return RR{}, reason
		}
		if rr.Weight, reason = recordNumber("weight", rec.Weight); reason != "" {
			return RR{}, reason
		}
		if rr.Port, reason = recordNumber("port", rec.Port); reason != "" {
			return RR{}, reason
		}
		if rr.Target, reason = recordTarget(rec.Target); reason != "" {
			return RR{}, reason
		}
	case dnsmessage.TypeMX:
		if rr.Priority, reason = recordNumber("priority", rec.Priority); reason != "" {
			return RR{}, reason
		}
		if rr.Target, reason = recordTarget(rec.Target); reason != "" {
			return RR{}, reason
		}
	}
	return rr, ""
}

// recordTarget folds the target of a CNAME, SRV or MX record, or returns why
// it is not a valid name. A target may lie anywhere, inside or outside the
// zones plexd answers, and may carry _ in a label.
func recordTarget(target string) (string, string) {
	name := foldName(target)
	if reason := invalidName(name, true); reason != "" {
		return "", fmt.Sprintf("has target %q, which is not a valid name because it %s", target, reason)
	}
	return name, ""
}

// recordNumber returns the 16-bit value of the member named member, or why it
// is missing or out of range.
func recordNumber(member string, v *int) (uint16, string) {
	switch {
	case v == nil:
		return 0, "has no " + member
	case *v < 0 || *v > 0xffff:
		return 0, fmt.Sprintf("has a %s outside 0 to 65535", member)
	}
	return uint16(*v), ""
}

// Lookup answers name for the type qtype. The name may carry one trailing
// dot, as a parsed question does, and is compared in ASCII lower case, so the
// answer does not depend on the spelling of the query.
//
// At each name it tries, in this order: a host of the asked address family; a
// PTR for a reverse name that maps to a host; a CNAME, which answers every
// type and is followed, unless the query asks for CNAME or for any type, while
// its target lies under a zone or reverse zone plexd answers; the records of
// the asked type; the SOA of a zone itself. A name that exists without any of them answers ResultNoData, and any
// other name ResultNXDomain, both with the CNAME records that led there. The
// response code is that of the last name, as RFC 6604 has it.
func (r *Records) Lookup(name string, qtype dnsmessage.Type) Answer {
	if r == nil {
		return Answer{Result: ResultRefused}
	}
	name = foldName(strings.TrimSuffix(name, "."))
	zone, ok := longestMatch(name, r.apexes)
	if !ok {
		return Answer{Result: ResultRefused}
	}
	var rrs []RR
	// visited holds the names a CNAME chain passed, so a chain that comes
	// back to one of them ends there rather than going round.
	var visited []string
	for {
		if addr, ok := r.hosts[name]; ok &&
			(qtype == dnsmessage.TypeA && addr.Is4() || qtype == dnsmessage.TypeAAAA && addr.Is6()) {
			return Answer{Result: ResultFound, Zone: zone, RRs: append(rrs, RR{Name: name, Type: qtype, Addr: addr})}
		}
		if qtype == dnsmessage.TypePTR {
			if target, ok := r.ptrs[name]; ok {
				return Answer{Result: ResultFound, Zone: zone, RRs: append(rrs, RR{Name: name, Type: qtype, Target: target})}
			}
		}
		set := r.records[name]
		if len(set) == 1 && set[0].Type == dnsmessage.TypeCNAME {
			cname := set[0]
			// A query for the CNAME itself, or for any type, which the CNAME
			// matches (RFC 1034 4.3.2), gets the CNAME and is not followed.
			if qtype == dnsmessage.TypeCNAME || qtype == dnsmessage.TypeALL {
				return Answer{Result: ResultFound, Zone: zone, RRs: append(rrs, cname)}
			}
			rrs = append(rrs, cname)
			visited = append(visited, name)
			// rrs holds CNAME records only while the chain goes on, so its
			// length is the length of the chain.
			next, under := longestMatch(cname.Target, r.apexes)
			if !under || slices.Contains(visited, cname.Target) || len(rrs) == maxCNAMEChain {
				return Answer{Result: ResultFound, Zone: zone, RRs: rrs}
			}
			name, zone = cname.Target, next
			continue
		}
		n := len(rrs)
		for _, rr := range set {
			if rr.Type == qtype {
				rrs = append(rrs, rr)
			}
		}
		if len(rrs) > n {
			return Answer{Result: ResultFound, Zone: zone, RRs: rrs}
		}
		if qtype == dnsmessage.TypeSOA && name == zone {
			return Answer{Result: ResultFound, Zone: zone, RRs: append(rrs, RR{Name: zone, Type: dnsmessage.TypeSOA})}
		}
		if _, ok := r.names[name]; ok {
			return Answer{Result: ResultNoData, Zone: zone, RRs: rrs}
		}
		return Answer{Result: ResultNXDomain, Zone: zone, RRs: rrs}
	}
}

// Registration returns what the system resolver should send to server
// through the interface iface. Routing a domain routes every name under it, so
// a zone below another accepted zone is left out, which keeps the list short
// when every Project has a zone under the Domain's default domain. The search
// domain is a routing domain too, so it is left out as well. Reverse zones
// are never merged: a wider zone would make plexd deny the addresses outside
// the mesh. The accepted forward zones of fwd follow, every one of them, so
// the link lists each zone the node forwards. Each group is in ascending byte
// order, so equal records and tables give equal registrations. DefaultRoute is
// set when fwd has a catch-all resolver. A nil r adds no zone and no search
// domain, and a nil fwd no forward zone and no default route.
func (r *Records) Registration(iface string, server netip.AddrPort, fwd *Forwarding) Registration {
	reg := Registration{Interface: iface, Server: server}
	if r != nil {
		reg.SearchDomain = r.searchDomain
		for _, z := range r.zones {
			// apexes holds the reverse zones too, but no zone lies under
			// arpa, so only an accepted zone can be found above z.
			if z == r.searchDomain || hasProperAncestor(z, r.apexes) {
				continue
			}
			reg.RoutingDomains = append(reg.RoutingDomains, z)
		}
		reg.RoutingDomains = append(reg.RoutingDomains, r.reverseZones...)
	}
	if fwd != nil {
		reg.RoutingDomains = append(reg.RoutingDomains, fwd.zones...)
	}
	reg.DefaultRoute = fwd.CatchAllCount() > 0
	return reg
}

// Equal reports whether r and o answer every query alike, so the manager logs
// a change only when a pull changed a name or a record. Node IDs are not
// answered and are not compared. The records of a name are compared in
// order, because they are answered in that order. A nil *Records equals only
// another nil one, so the first block counts as a change even when it is
// empty.
func (r *Records) Equal(o *Records) bool {
	if r == nil || o == nil {
		return r == o
	}
	return r.searchDomain == o.searchDomain &&
		slices.Equal(r.zones, o.zones) &&
		slices.Equal(r.reverseZones, o.reverseZones) &&
		maps.Equal(r.hosts, o.hosts) &&
		maps.Equal(r.ptrs, o.ptrs) &&
		r.recordCount == o.recordCount &&
		maps.EqualFunc(r.records, o.records, func(a, b []RR) bool { return slices.EqualFunc(a, b, RR.equal) })
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

// RecordCount returns the number of accepted records.
func (r *Records) RecordCount() int {
	if r == nil {
		return 0
	}
	return r.recordCount
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
// start nor end with -. With underscore set a label may also carry _ at any
// position, as the names and targets of records do (_ldap._tcp). The root
// zone is never valid, because the empty name is not.
func invalidName(name string, underscore bool) string {
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
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && (!underscore || c != '_') {
				if underscore {
					return "has a character outside a-z, 0-9, - and _"
				}
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
