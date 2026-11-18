package bridge

import (
	"crypto/tls"
	"log/slog"
	"net"
)

// StdIngressController implements IngressController using the standard library
// net and crypto/tls packages. It is cross-platform.
type StdIngressController struct {
	logger *slog.Logger
}

// NewStdIngressController returns a new StdIngressController.
func NewStdIngressController(logger *slog.Logger) *StdIngressController {
	return &StdIngressController{logger: logger}
}

// Listen opens a TCP listener on the given address. If tlsCfg is non-nil,
// the listener is wrapped with TLS.
func (c *StdIngressController) Listen(addr string, tlsCfg *tls.Config) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	c.logger.Debug("ingress listener started",
		"component", "bridge",
		"addr", addr,
		"tls", tlsCfg != nil,
	)

	return ln, nil
}

// Close closes the given listener.
func (c *StdIngressController) Close(listener net.Listener) error {
	return listener.Close()
}

// ListenUDP resolves addr and opens a UDP socket on it. An address without a
// host, such as ":53", binds the dual-stack wildcard address, as the relay's
// socket does.
func (c *StdIngressController) ListenUDP(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", udpAddr)
}
