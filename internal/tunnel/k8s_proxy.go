package tunnel

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// K8sProxy is a reverse proxy that forwards HTTP requests to a Kubernetes API server.
type K8sProxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
	logger *slog.Logger
}

// NewK8sProxy creates a K8sProxy targeting the given API server URL.
// If tlsConfig is non-nil, it is used for TLS connections to the API server.
func NewK8sProxy(targetURL string, tlsConfig *tls.Config, logger *slog.Logger) (*K8sProxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("tunnel: k8s proxy: parse target: %w", err)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("tunnel: k8s proxy: parse target: empty host")
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			clientIP := req.RemoteAddr
			if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				clientIP = host
			}
			req.Header.Set("X-Forwarded-For", clientIP)
		},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("reverse proxy error",
			"component", "tunnel",
			"error", err,
			"path", r.URL.Path,
		)
		w.WriteHeader(http.StatusBadGateway)
	}

	if tlsConfig != nil {
		proxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	return &K8sProxy{
		target: target,
		proxy:  proxy,
		logger: logger,
	}, nil
}

// ServeHTTP implements http.Handler, forwarding requests to the K8s API server.
func (p *K8sProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// Handler returns the proxy as an http.Handler.
func (p *K8sProxy) Handler() http.Handler {
	return p
}
