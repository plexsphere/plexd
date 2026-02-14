//go:build linux

package nodeapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// applySocketPermissions sets socket ownership and permissions on Linux.
func applySocketPermissions(socketPath string, logger *slog.Logger) {
	if err := SetSocketPermissions(socketPath, logger); err != nil {
		logger.Warn("failed to set socket permissions", "error", err)
	}
}

// peerCredKey is the context key for storing PeerCredentials.
type peerCredKey struct{}

// connContextWithPeerCred returns a ConnContext function for http.Server
// that extracts Unix socket peer credentials and stores them in the context.
func connContextWithPeerCred(logger *slog.Logger) func(ctx context.Context, c net.Conn) context.Context {
	return func(ctx context.Context, c net.Conn) context.Context {
		cred, err := GetPeerCredentials(c)
		if err != nil {
			logger.Debug("failed to get peer credentials", "error", err)
			return ctx
		}
		return context.WithValue(ctx, peerCredKey{}, cred)
	}
}

// contextPeerCredGetter extracts peer credentials from the request context.
type contextPeerCredGetter struct{}

func (contextPeerCredGetter) GetPeerCredentials(r *http.Request) (*PeerCredentials, error) {
	cred, ok := r.Context().Value(peerCredKey{}).(*PeerCredentials)
	if !ok || cred == nil {
		return nil, fmt.Errorf("nodeapi: peer credentials not available")
	}
	return cred, nil
}

// wrapSecretAuth wraps a handler with SecretAuthMiddleware for secret routes
// on the Unix socket. On Linux, SO_PEERCRED is used for authorization.
func wrapSecretAuth(next http.Handler, logger *slog.Logger) http.Handler {
	checker := OSGroupChecker{}
	getter := contextPeerCredGetter{}
	secretAuth := SecretAuthMiddleware(checker, getter, logger)
	protected := secretAuth(next)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/state/secrets") {
			protected.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
