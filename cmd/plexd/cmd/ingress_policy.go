package cmd

import (
	"net"
	"net/netip"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/policy"
)

// dialAdmitter is the part of *policy.Enforcer the dial policy reads.
type dialAdmitter interface {
	AdmitsTCPDial(src netip.Addr, dst netip.AddrPort) (admitted, enforced bool)
	AdmitsUDPDial(src netip.Addr, dst netip.AddrPort) (admitted, enforced bool)
}

var _ dialAdmitter = (*policy.Enforcer)(nil)

// ingressDialPolicy tells the ingress manager whether the node's compiled
// policy blocks a TCP or UDP dial to a target. Every firewall backend applies
// the policy to what the node's own sockets send over the mesh interface from
// the mesh address, so a dial counts only when the kernel would send it from
// meshIP; a dial to meshIP itself takes the loopback.
type ingressDialPolicy struct {
	enforcer dialAdmitter
	meshIP   netip.Addr
	// sourceFor returns the source address the kernel picks for target;
	// udpSourceFor outside tests.
	sourceFor func(target netip.AddrPort) (netip.Addr, error)
}

var _ bridge.IngressDialPolicy = ingressDialPolicy{}

// newIngressDialPolicy returns the dial policy of a node whose mesh address
// is meshIP, reading enforcer's installed ruleset. It fails for a meshIP that
// is no address.
func newIngressDialPolicy(enforcer dialAdmitter, meshIP string) (ingressDialPolicy, error) {
	addr, err := netip.ParseAddr(meshIP)
	if err != nil {
		return ingressDialPolicy{}, err
	}
	return ingressDialPolicy{enforcer: enforcer, meshIP: addr.Unmap(), sourceFor: udpSourceFor}, nil
}

// DialDenied reports whether the ruleset the Enforcer holds blocks a dial of
// protocol from the mesh address to target: a UDP dial for
// api.IngressProtocolUDP and a TCP dial for every other protocol. It answers
// false, without asking the Enforcer, for a target that is the mesh address,
// and for a target the kernel would not reach from the mesh address or no
// route reaches; and false while nothing is enforced.
func (p ingressDialPolicy) DialDenied(protocol string, target netip.AddrPort) bool {
	dst := netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if dst.Addr() == p.meshIP {
		return false
	}
	src, err := p.sourceFor(dst)
	if err != nil || src.Unmap() != p.meshIP {
		return false
	}
	admits := p.enforcer.AdmitsTCPDial
	if protocol == api.IngressProtocolUDP {
		admits = p.enforcer.AdmitsUDPDial
	}
	admitted, enforced := admits(p.meshIP, dst)
	return enforced && !admitted
}

// udpSourceFor returns the source address the kernel picks for target: a UDP
// connect chooses the route and its source address and sends no packet.
func udpSourceFor(target netip.AddrPort) (netip.Addr, error) {
	conn, err := net.Dial("udp", target.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}
