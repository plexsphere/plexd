package nat

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/plexsphere/plexd/internal/api"
)

// Interface is one network interface as candidate gathering sees it: the
// fields of net.Interface the eligibility rules read, and its addresses as
// prefixes. It exists so the rules can be tested over fabricated interfaces
// instead of the host's.
type Interface struct {
	Name     string
	Index    int
	Flags    net.Flags
	Prefixes []netip.Prefix
}

// CandidateFilter narrows the interfaces and addresses published as endpoint
// candidates.
type CandidateFilter struct {
	// Interfaces is an allowlist of interface names. Empty means every
	// eligible interface. A listed name bypasses virtualInterfacePrefixes.
	Interfaces []string
	// ExcludeInterfaces names interfaces that are always skipped: the mesh
	// interface, whose addresses a peer reaches through the tunnel itself.
	ExcludeInterfaces []string
	// ExcludePrefix skips every address inside it: the Domain mesh prefix.
	// The zero prefix skips nothing.
	ExcludePrefix netip.Prefix
}

// virtualInterfacePrefixes are name prefixes of container, bridge, overlay and
// VPN interfaces. Their addresses are skipped unless CandidateFilter.Interfaces
// names the interface: they exist on many hosts at once (Docker's 172.17.0.1
// is on every Docker host), so a peer that dialed one would reach its own host
// rather than this node.
var virtualInterfacePrefixes = []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "cilium", "lxcbr", "lxdbr", "vxlan", "kube-", "podman", "tailscale", "zt"}

// SystemInterfaces reads the host's interfaces and their addresses. An
// interface whose addresses cannot be read is skipped rather than failing the
// whole read, and an address that is not an *net.IPNet is ignored.
func SystemInterfaces() ([]Interface, error) {
	nifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("nat: list interfaces: %w", err)
	}
	ifaces := make([]Interface, 0, len(nifs))
	for _, nif := range nifs {
		addrs, err := nif.Addrs()
		if err != nil {
			continue
		}
		iface := Interface{Name: nif.Name, Index: nif.Index, Flags: nif.Flags}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if p, ok := prefixFromIPNet(ipnet); ok {
				iface.Prefixes = append(iface.Prefixes, p)
			}
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

// EligiblePrefixes returns the prefixes of every eligible address, under the
// same interface and address rules SelectCandidates applies. An
// IPv4-mapped IPv6 prefix comes back as the IPv4 prefix it carries. The
// WireGuard manager reads them to tell which of a peer's candidates share a
// subnet with this node, so they are neither deduplicated against the
// candidates nor capped at api.MaxEndpointCandidates.
func EligiblePrefixes(ifaces []Interface, f CandidateFilter) []netip.Prefix {
	eligible := eligibleAddrs(ifaces, f)
	prefixes := make([]netip.Prefix, 0, len(eligible))
	for _, e := range eligible {
		prefixes = append(prefixes, e.prefix)
	}
	return prefixes
}

// SelectCandidates renders each eligible address joined with port as a
// host:port candidate. The order is IPv4 before IPv6, then the lower interface
// index, then the lower address, so a report is stable across cycles and the
// cap keeps the same addresses. An address on two interfaces is published
// once, at its first position. Past api.MaxEndpointCandidates the rest are
// dropped and counted in truncated. Nothing eligible yields an empty non-nil
// slice, the report that withdraws every earlier candidate.
func SelectCandidates(ifaces []Interface, port int, f CandidateFilter) (candidates []string, truncated int) {
	eligible := eligibleAddrs(ifaces, f)
	slices.SortFunc(eligible, func(a, b eligibleAddr) int {
		if c := cmp.Compare(familyRank(a.prefix.Addr()), familyRank(b.prefix.Addr())); c != 0 {
			return c
		}
		if c := cmp.Compare(a.index, b.index); c != 0 {
			return c
		}
		return a.prefix.Addr().Compare(b.prefix.Addr())
	})

	candidates = []string{}
	seen := make(map[string]struct{}, len(eligible))
	for _, e := range eligible {
		c := netip.AddrPortFrom(e.prefix.Addr().WithZone(""), uint16(port)).String()
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		if len(candidates) == api.MaxEndpointCandidates {
			truncated++
			continue
		}
		candidates = append(candidates, c)
	}
	return candidates, truncated
}

// GatherCandidates reads the host's interfaces and selects the candidates
// joined with port. A failed read is returned unchanged.
func GatherCandidates(port int, f CandidateFilter) (candidates []string, truncated int, err error) {
	ifaces, err := SystemInterfaces()
	if err != nil {
		return nil, 0, err
	}
	candidates, truncated = SelectCandidates(ifaces, port, f)
	return candidates, truncated, nil
}

// eligibleAddr is one eligible address with the index of the interface that
// carries it.
type eligibleAddr struct {
	index  int
	prefix netip.Prefix
}

// eligibleAddrs applies the interface rules and then the address rules,
// returning every surviving prefix in interface order.
func eligibleAddrs(ifaces []Interface, f CandidateFilter) []eligibleAddr {
	exclude, excludeValid := unmapPrefix(f.ExcludePrefix)
	var out []eligibleAddr
	for _, iface := range ifaces {
		if !interfaceEligible(iface, f) {
			continue
		}
		for _, p := range iface.Prefixes {
			p, ok := unmapPrefix(p)
			if !ok || !addrEligible(p.Addr()) {
				continue
			}
			if excludeValid && exclude.Contains(p.Addr()) {
				continue
			}
			out = append(out, eligibleAddr{index: iface.Index, prefix: p})
		}
	}
	return out
}

// interfaceEligible reports whether iface may carry candidates. A down
// interface accepts nothing, a loopback address is useless to a peer, and a
// point-to-point interface (kernel WireGuard, tun, utun) is a tunnel whose
// addresses are reached through the tunnel rather than the LAN.
func interfaceEligible(iface Interface, f CandidateFilter) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagPointToPoint != 0 {
		return false
	}
	if slices.Contains(f.ExcludeInterfaces, iface.Name) {
		return false
	}
	if len(f.Interfaces) > 0 {
		return slices.Contains(f.Interfaces, iface.Name)
	}
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(iface.Name, prefix) {
			return false
		}
	}
	return true
}

// addrEligible reports whether a peer could dial addr from another host:
// unspecified, loopback, link-local and multicast addresses cannot be.
func addrEligible(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.IsUnspecified() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsInterfaceLocalMulticast() &&
		!addr.IsMulticast()
}

// prefixFromIPNet converts an interface address to a prefix through
// netip.AddrFromSlice, Unmap and the mask's size. The net package hands an
// IPv4 address over in its 16-byte form with a 4-byte mask, so a 32-bit mask
// unmaps the address before the length is applied. A genuine IPv4-mapped
// IPv6 address carries a 128-bit mask and is left to unmapPrefix. ok is false
// for an unreadable address or a non-canonical mask.
func prefixFromIPNet(ipnet *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	if bits == 8*net.IPv4len {
		addr = addr.Unmap()
	}
	return unmapPrefix(netip.PrefixFrom(addr, ones))
}

// unmapPrefix returns p with an IPv4-mapped IPv6 address rewritten as the IPv4
// address it carries, and the 96 bits of the mapping prefix taken off its
// length, so ::ffff:10.0.0.5/120 becomes 10.0.0.5/24. A mapped prefix shorter
// than /96 spans more than the mapped range, so only the address itself is
// kept, as a /32. ok is false for an invalid prefix.
func unmapPrefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	addr := p.Addr()
	if !addr.Is4In6() {
		return p, true
	}
	bits := p.Bits() - 96
	if bits < 0 {
		bits = 32
	}
	return netip.PrefixFrom(addr.Unmap(), bits), true
}

// familyRank orders IPv4 addresses before IPv6 ones.
func familyRank(addr netip.Addr) int {
	if addr.Is4() {
		return 0
	}
	return 1
}
