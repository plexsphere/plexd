package nodeapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// PeerCredGetter extracts peer credentials from an HTTP request's
// underlying connection.
type PeerCredGetter interface {
	GetPeerCredentials(r *http.Request) (*PeerCredentials, error)
}

// peerCredKey is the context key for storing PeerCredentials.
type peerCredKey struct{}

// connContextWithPeerCred returns a ConnContext function for http.Server
// that extracts the peer credentials of the accepted local connection and
// stores them in the context.
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
