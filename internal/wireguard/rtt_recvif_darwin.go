//go:build darwin

package wireguard

import (
	"fmt"
	"log/slog"
	"net"

	// The package declares its own ipv4, the header view of the mesh source
	// rewrite.
	xipv4 "golang.org/x/net/ipv4"
)

// rttMeshOnly returns conn wrapped so that ReadFrom hands over only the
// datagrams that arrived on iface, and conn itself where the kernel
// already confines the socket.
//
// On macOS it looks up the index of iface and switches FlagInterface of
// golang.org/x/net/ipv4 on, so the kernel reports with each datagram the
// interface it arrived on. conn must be a *net.UDPConn. Either failure
// closes conn and returns the error wrapped as "wireguard: rtt probe:
// receive interface of <iface>: <error>". rttOpen then logs wireguard: rtt
// probe listen failed, and the next round listens again.
func rttMeshOnly(conn net.PacketConn, iface string, logger *slog.Logger) (net.PacketConn, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("wireguard: rtt probe: receive interface of %s: %w", iface, err)
	}
	pc := xipv4.NewPacketConn(conn)
	if err := pc.SetControlMessage(xipv4.FlagInterface, true); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("wireguard: rtt probe: receive interface of %s: %w", iface, err)
	}
	return &rttMeshOnlyConn{PacketConn: conn, pc: pc, index: ifi.Index, logger: logger}, nil
}

// rttMeshOnlyConn is a probe socket whose ReadFrom hands over only the
// datagrams that arrived on the interface with index index. Every other
// method, WriteTo and Close included, is the embedded socket's.
//
// The probe socket is bound to the mesh utun with IP_BOUND_IF
// (ifbind.Control), and that does not filter what it receives: on a Mac
// that forwards, a bound socket still receives a datagram for its address
// that arrived on another utun, and sends its answer through the bound
// utun. The kernel names the interface a datagram arrived on, on a bound
// socket too, once FlagInterface is on. golang.org/x/net switches it on with
// IP_RECVPKTINFO on macOS and reads the index from the IP_PKTINFO control
// message. Both were measured on macos-latest for #245.
type rttMeshOnlyConn struct {
	net.PacketConn
	pc     *xipv4.PacketConn
	index  int
	logger *slog.Logger
}

// ReadFrom reads the next datagram that arrived on c's interface into b. It
// drops every datagram for which rttArrivedOn reports false, logs
// wireguard: rtt probe dropped a datagram from another interface at Debug
// for each, and reads again. A read error is returned as it is, so a read on
// a closed socket fails with net.ErrClosed.
func (c *rttMeshOnlyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, cm, src, err := c.pc.ReadFrom(b)
		if err != nil {
			return n, src, err
		}
		if rttArrivedOn(cm, c.index) {
			return n, src, nil
		}
		source, index := "", 0
		if src != nil {
			source = src.String()
		}
		if cm != nil {
			index = cm.IfIndex
		}
		c.logger.Debug("wireguard: rtt probe dropped a datagram from another interface",
			"component", "wireguard",
			"source", source,
			"interface_index", index,
		)
	}
}

// rttArrivedOn reports whether cm names index as the interface its datagram
// arrived on. A datagram without a control message counts as from another
// interface, so a kernel that stops sending it leaves the probe silent,
// never open.
func rttArrivedOn(cm *xipv4.ControlMessage, index int) bool {
	return cm != nil && cm.IfIndex == index
}
