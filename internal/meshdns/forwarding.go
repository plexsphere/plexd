package meshdns

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/plexsphere/plexd/internal/api"
)

// forwardReserved are the names the contract rules out as forward zones:
// local and localhost belong to mDNS and the host itself, and arpa,
// in-addr.arpa and ip6.arpa would take every reverse name of the host. A name
// under local, such as an Active Directory zone, and a reverse zone under
// in-addr.arpa or ip6.arpa are forward zones like any other.
var forwardReserved = []string{"local", "localhost", "arpa", "in-addr.arpa", "ip6.arpa"}

// broadcast4 is the IPv4 limited broadcast address, which reaches every host
// of the link and no single resolver.
var broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Forwarding is the validated forwarding member of one dns block: the forward
// zones plexd accepted, each with the resolvers that answer the names under
// it, and the catch-all resolvers that answer every name outside the mesh
// zones, the reverse zones and the forward zones. Nothing changes it after
// BuildForwarding returns, so the server reads it from any number of
// goroutines and a pull replaces it whole. A nil *Forwarding forwards
// nothing, which is what the server holds while the manager keeps no
// forwarding member.
type Forwarding struct {
	// zones are the accepted forward zones, ascending.
	zones []string
	// apexes holds every accepted forward zone, the candidates for the
	// longest suffix match.
	apexes map[string]struct{}
	// resolvers maps each accepted forward zone to its accepted resolvers,
	// in the order the member gave them.
	resolvers map[string][]netip.Addr
	// catchAll are the accepted catch-all resolvers, in the order the member
	// gave them.
	catchAll []netip.Addr
}

// BuildForwarding validates setting and builds the table the server forwards
// with. records supplies the accepted mesh zones and reverse zones, which
// answer every name under them, so a forward zone that equals one of them or
// lies under one is skipped; a nil records has none. self is the address the
// resolver listens on, which no query is forwarded to. The second result names
// each entry that was skipped, one sentence per entry, for the manager to log.
//
// A forward zone is folded to lower case and checked in this order, and the
// first check it fails skips it: the name, the reserved names, a mesh zone
// above it, an accepted forward zone of the same name, and at least one
// accepted resolver. A resolver is checked in this order, and a skipped one
// costs only itself: it parses as an IP address, it is an address a query can
// be sent to, it is not self, and the same owner did not list it before. The
// checks guard the host, not the limits the control plane sets on the number
// of zones and resolvers, so a change of those limits needs no new plexd.
func BuildForwarding(setting api.NodeStateDNSForwarding, records *Records, self netip.Addr) (*Forwarding, []string) {
	var skipped []string
	f := &Forwarding{
		apexes:    make(map[string]struct{}),
		resolvers: make(map[string][]netip.Addr),
	}
	var mesh map[string]struct{}
	if records != nil {
		mesh = records.apexes
	}
	// An IPv4-mapped listen address listens as the IPv4 address it carries,
	// which is how a resolver is compared, since a mapped one is skipped.
	self = self.Unmap()

	for _, fz := range setting.ForwardZones {
		name := foldName(fz.Zone)
		if reason := invalidName(name, true); reason != "" {
			skipped = append(skipped, fmt.Sprintf("forward zone %q is not a valid name because it %s", fz.Zone, reason))
			continue
		}
		if reason := reservedForward(name); reason != "" {
			skipped = append(skipped, fmt.Sprintf("forward zone %q %s, which the contract rules out", fz.Zone, reason))
			continue
		}
		if zone, ok := longestMatch(name, mesh); ok {
			skipped = append(skipped, fmt.Sprintf("forward zone %q is shadowed by the mesh zone %q, which answers its names", fz.Zone, zone))
			continue
		}
		if _, ok := f.apexes[name]; ok {
			skipped = append(skipped, fmt.Sprintf("forward zone %q repeats an earlier forward zone", fz.Zone))
			continue
		}
		resolvers, reasons := acceptResolvers(fz.Resolvers, fmt.Sprintf("forward zone %q", fz.Zone), self)
		skipped = append(skipped, reasons...)
		if len(resolvers) == 0 {
			skipped = append(skipped, fmt.Sprintf("forward zone %q has no usable resolver", fz.Zone))
			continue
		}
		f.apexes[name] = struct{}{}
		f.resolvers[name] = resolvers
	}

	catchAll, reasons := acceptResolvers(setting.CatchAll, "the catch-all", self)
	skipped = append(skipped, reasons...)
	f.catchAll = catchAll
	f.zones = slices.Sorted(maps.Keys(f.apexes))
	return f, skipped
}

// reservedForward returns why the folded name is ruled out as a forward
// zone, as the part of the sentence after the zone, or empty when it is not.
func reservedForward(name string) string {
	switch {
	case slices.Contains(forwardReserved, name):
		return fmt.Sprintf("is %s itself", name)
	case strings.HasSuffix(name, ".localhost"):
		return "is under localhost"
	case strings.HasSuffix(name, ".arpa") &&
		!strings.HasSuffix(name, ".in-addr.arpa") && !strings.HasSuffix(name, ".ip6.arpa"):
		return "is under arpa"
	}
	return ""
}

// acceptResolvers returns the resolvers among values that a query may go to,
// in their order, and one sentence for each value it skips. owner names the
// forward zone or the catch-all the values belong to, as the sentences name
// it, and self is the resolver's own listen address.
func acceptResolvers(values []string, owner string, self netip.Addr) ([]netip.Addr, []string) {
	var accepted []netip.Addr
	var skipped []string
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		switch {
		case err != nil:
			skipped = append(skipped, fmt.Sprintf("resolver %q of %s is not an IP address", v, owner))
		case !forwardable(addr):
			skipped = append(skipped, fmt.Sprintf("resolver %q of %s is not an address plexd forwards to", v, owner))
		case addr == self:
			skipped = append(skipped, fmt.Sprintf("resolver %q of %s is the resolver's own listen address", v, owner))
		case slices.Contains(accepted, addr):
			skipped = append(skipped, fmt.Sprintf("resolver %q of %s repeats an earlier resolver", v, owner))
		default:
			accepted = append(accepted, addr)
		}
	}
	return accepted, skipped
}

// forwardable reports whether a query may be sent to addr. An address with a
// zone names a link rather than a host, and an IPv4-mapped one is an IPv4
// address in an IPv6 address's clothes. The unspecified, multicast,
// link-local and broadcast addresses reach no single resolver of the mesh or
// a bridge, and a loopback one comes back to the host: 127.0.0.53 is
// systemd-resolved's stub, which would send the query straight back to plexd.
func forwardable(addr netip.Addr) bool {
	return addr.Zone() == "" && !addr.Is4In6() && !addr.IsUnspecified() && !addr.IsLoopback() &&
		!addr.IsMulticast() && !addr.IsLinkLocalUnicast() && addr != broadcast4
}

// Route returns where a query for name goes: the resolvers of the longest
// accepted forward zone that is name itself or lies above it, label by label,
// with that zone; otherwise the catch-all resolvers with the zone ".", when
// there are any; otherwise ok is false. The name may carry one trailing dot,
// as a parsed question does, and is compared in ASCII lower case. The
// resolvers are shared with the table, which nothing changes.
func (f *Forwarding) Route(name string) (resolvers []netip.Addr, zone string, ok bool) {
	if f == nil {
		return nil, "", false
	}
	name = foldName(strings.TrimSuffix(name, "."))
	if zone, ok := longestMatch(name, f.apexes); ok {
		return f.resolvers[zone], zone, true
	}
	if len(f.catchAll) > 0 {
		return f.catchAll, ".", true
	}
	return nil, "", false
}

// Equal reports whether f and o forward every query alike: the same zones
// with the same resolvers in the same order, and the same catch-all in the
// same order. A nil *Forwarding equals one without zones and without a
// catch-all, so a node that never forwards logs no change.
func (f *Forwarding) Equal(o *Forwarding) bool {
	var none Forwarding
	if f == nil {
		f = &none
	}
	if o == nil {
		o = &none
	}
	return slices.Equal(f.zones, o.zones) &&
		maps.EqualFunc(f.resolvers, o.resolvers, slices.Equal[[]netip.Addr]) &&
		slices.Equal(f.catchAll, o.catchAll)
}

// ZoneCount returns the number of accepted forward zones.
func (f *Forwarding) ZoneCount() int {
	if f == nil {
		return 0
	}
	return len(f.zones)
}

// CatchAllCount returns the number of accepted catch-all resolvers.
func (f *Forwarding) CatchAllCount() int {
	if f == nil {
		return 0
	}
	return len(f.catchAll)
}
