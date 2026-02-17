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
