package bridge

import (
	"crypto/tls"
	"net"
)

// IngressController abstracts TCP listener operations for ingress testability.
// All methods must be idempotent where applicable.
type IngressController interface {
	// Listen creates a TCP listener on the given address.
	// If tlsCfg is non-nil, the listener will accept TLS connections.
	// Returns the listener and any error.
	Listen(addr string, tlsCfg *tls.Config) (net.Listener, error)

	// Close closes the given listener.
	// Idempotent: closing an already-closed listener returns nil.
	Close(listener net.Listener) error
}
