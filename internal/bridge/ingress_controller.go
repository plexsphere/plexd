package bridge

import (
	"crypto/tls"
	"net"
)

// IngressController abstracts the sockets of public ingress for testability:
// a TCP listener for each listen port of the tcp rules and a UDP socket for
// each listen port of the udp rules. All methods must be idempotent where
// applicable.
type IngressController interface {
	// Listen creates a TCP listener on the given address.
	// If tlsCfg is non-nil, the listener will accept TLS connections.
	// Returns the listener and any error.
	Listen(addr string, tlsCfg *tls.Config) (net.Listener, error)

	// Close closes the given listener.
	// Idempotent: closing an already-closed listener returns nil.
	Close(listener net.Listener) error

	// ListenUDP opens a UDP socket on the given address. The manager closes
	// the socket itself.
	ListenUDP(addr string) (*net.UDPConn, error)
}
