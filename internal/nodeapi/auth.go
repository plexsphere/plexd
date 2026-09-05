package nodeapi

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// BearerAuthMiddleware returns middleware that validates Bearer token
// authentication. Requests without a valid token receive 401 Unauthorized.
// Unix socket requests bypass this middleware (it is only applied to the TCP
// listener).
func BearerAuthMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				writeAuthError(w)
				return
			}

			// Expect "Bearer <token>"
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				writeAuthError(w)
				return
			}

			// Constant-time comparison to prevent timing attacks.
			if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) != 1 {
				writeAuthError(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeAuthError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
}

// SecretPolicy decides whether an identified local peer may read secret values.
type SecretPolicy interface {
	AllowSecrets(cred *PeerCredentials) bool
}

// SecretAuthMiddleware returns HTTP middleware that restricts the secret
// endpoints to the peers the platform's SecretPolicy admits. A peer whose
// credentials cannot be read is denied.
//
// The middleware takes the peer credentials of the request's underlying
// connection from a PeerCredGetter: contextPeerCredGetter in production, a
// mock in tests.
func SecretAuthMiddleware(policy SecretPolicy, getter PeerCredGetter, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cred, err := getter.GetPeerCredentials(r)
			if err != nil {
				logger.Error("failed to get peer credentials", "error", err)
				writeSecretAuthError(w)
				return
			}
			if policy.AllowSecrets(cred) {
				next.ServeHTTP(w, r)
				return
			}
			logger.Warn("secret access denied", append(cred.logAttrs(), "path", r.URL.Path)...)
			writeSecretAuthError(w)
		})
	}
}

// wrapSecretAuth sends the secret routes of next through SecretAuthMiddleware
// and leaves every other route untouched.
func wrapSecretAuth(next http.Handler, policy SecretPolicy, logger *slog.Logger) http.Handler {
	protected := SecretAuthMiddleware(policy, contextPeerCredGetter{}, logger)(next)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/state/secrets") {
			protected.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeSecretAuthError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: insufficient privileges for secret access"})
}
