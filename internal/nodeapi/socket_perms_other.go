//go:build !linux

package nodeapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
)

// applySocketPermissions is a no-op on non-Linux platforms.
func applySocketPermissions(_ string, _ *slog.Logger) {}

// connContextWithPeerCred returns nil on non-Linux platforms (no SO_PEERCRED).
func connContextWithPeerCred(_ *slog.Logger) func(ctx context.Context, c net.Conn) context.Context {
	return nil
}

// wrapSecretAuth is a no-op on non-Linux platforms (no peer credential extraction).
func wrapSecretAuth(next http.Handler, _ *slog.Logger) http.Handler {
	return next
}
