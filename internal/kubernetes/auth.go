package kubernetes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultCACertPath is the default path to the Kubernetes cluster CA certificate.
const DefaultCACertPath = ServiceAccountBasePath + "/ca.crt"

// TokenReviewClient abstracts Kubernetes TokenReview API access for testability.
type TokenReviewClient interface {
	// Review validates a bearer token via the Kubernetes TokenReview API.
	// Returns the authenticated identity if valid, or an error if invalid or unreachable.
	Review(ctx context.Context, token string) (*TokenReviewResult, error)
}

// TokenReviewResult contains the result of a TokenReview API call.
type TokenReviewResult struct {
	Authenticated bool
	Username      string
	UID           string
	Groups        []string
	Audiences     []string
}

// TokenReviewAuthenticator validates bearer tokens using the Kubernetes TokenReview API.
type TokenReviewAuthenticator struct {
	client    TokenReviewClient
	logger    *slog.Logger
	audiences []string
}

// NewTokenReviewAuthenticator creates a new authenticator that validates tokens
// via the provided TokenReviewClient. If audiences is non-empty, the result must
// contain at least one matching audience for authentication to succeed.
func NewTokenReviewAuthenticator(client TokenReviewClient, logger *slog.Logger, audiences []string) *TokenReviewAuthenticator {
	return &TokenReviewAuthenticator{
		client:    client,
		logger:    logger.With("component", "kubernetes"),
		audiences: audiences,
	}
}

// Authenticate validates the given bearer token. Returns the review result
// if the token is valid, or an error if authentication fails.
// If audiences are configured, the result must contain at least one matching audience.
func (a *TokenReviewAuthenticator) Authenticate(ctx context.Context, token string) (*TokenReviewResult, error) {
	if token == "" {
		return nil, fmt.Errorf("kubernetes: authenticate: empty token")
	}

	result, err := a.client.Review(ctx, token)
	if err != nil {
		a.logger.WarnContext(ctx, "token review failed", "error", err)
		return nil, fmt.Errorf("kubernetes: authenticate: review failed: %w", err)
	}

	if !result.Authenticated {
		a.logger.InfoContext(ctx, "token review: not authenticated")
		return nil, fmt.Errorf("kubernetes: authenticate: token not authenticated")
	}

	if len(a.audiences) > 0 {
		if !audienceMatch(a.audiences, result.Audiences) {
			a.logger.WarnContext(ctx, "token review: audience mismatch",
				"expected", a.audiences,
				"actual", result.Audiences,
			)
			return nil, fmt.Errorf("kubernetes: authenticate: audience mismatch")
		}
	}

	a.logger.InfoContext(ctx, "token review: authenticated",
		"username", result.Username,
		"uid", result.UID,
	)
	return result, nil
}

// audienceMatch returns true if at least one expected audience appears in the
// actual audiences list.
func audienceMatch(expected, actual []string) bool {
	set := make(map[string]struct{}, len(actual))
	for _, a := range actual {
		set[a] = struct{}{}
	}
	for _, e := range expected {
		if _, ok := set[e]; ok {
			return true
		}
	}
	return false
}

// tokenReviewRequest is the JSON body sent to the TokenReview API.
type tokenReviewRequest struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       tokenReviewSpec `json:"spec"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type tokenReviewResponse struct {
	Status tokenReviewStatus `json:"status"`
}

type tokenReviewStatus struct {
	Authenticated bool             `json:"authenticated"`
	User          *tokenReviewUser `json:"user,omitempty"`
	Audiences     []string         `json:"audiences,omitempty"`
	Error         string           `json:"error,omitempty"`
}

type tokenReviewUser struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups,omitempty"`
}

// authIdentityKey is the context key for storing the authenticated identity.
type authIdentityKey struct{}

// TokenReviewMiddleware returns an HTTP middleware that authenticates requests
// using the TokenReviewAuthenticator. It extracts the Bearer token from the
// Authorization header, validates it, and attaches the identity to the request
// context. Returns 401 Unauthorized on failure.
func TokenReviewMiddleware(auth *TokenReviewAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(header, "Bearer ")

			result, err := auth.Authenticate(r.Context(), token)
			if err != nil {
				http.Error(w, "authentication failed", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), authIdentityKey{}, result)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// IdentityFromContext retrieves the TokenReviewResult from the request context.
// Returns nil if no identity is present.
func IdentityFromContext(ctx context.Context) *TokenReviewResult {
	v, _ := ctx.Value(authIdentityKey{}).(*TokenReviewResult)
	return v
}

// HTTPTokenReviewClient implements TokenReviewClient using the Kubernetes API server.
type HTTPTokenReviewClient struct {
	apiServer  string
	saToken    string
	httpClient *http.Client
}

// NewHTTPTokenReviewClient creates a new client that calls the TokenReview API
// on the given apiServer. The saTokenPath is the filesystem path to the service
// account token used to authenticate with the API server.
func NewHTTPTokenReviewClient(apiServer, saTokenPath string) *HTTPTokenReviewClient {
	apiServer = strings.TrimRight(apiServer, "/")

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	caCert, err := os.ReadFile(DefaultCACertPath)
	if err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = pool
	}

	return &HTTPTokenReviewClient{
		apiServer: apiServer,
		saToken:   saTokenPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// Review validates a bearer token by calling the Kubernetes TokenReview API.
func (c *HTTPTokenReviewClient) Review(ctx context.Context, token string) (*TokenReviewResult, error) {
	saToken, err := os.ReadFile(c.saToken)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: token review: read service account token: %w", err)
	}

	reqBody := tokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: tokenReviewSpec{
			Token: token,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: token review: marshal request: %w", err)
	}

	url := c.apiServer + "/apis/authentication.k8s.io/v1/tokenreviews"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("kubernetes: token review: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(saToken)))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: token review: http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: token review: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		truncated := string(respBody)
		if len(truncated) > 256 {
			truncated = truncated[:256] + "...(truncated)"
		}
		return nil, fmt.Errorf("kubernetes: token review: unexpected status %d: %s", resp.StatusCode, truncated)
	}

	var trResp tokenReviewResponse
	if err := json.Unmarshal(respBody, &trResp); err != nil {
		return nil, fmt.Errorf("kubernetes: token review: unmarshal response: %w", err)
	}

	if trResp.Status.Error != "" {
		return nil, fmt.Errorf("kubernetes: token review: api error: %s", trResp.Status.Error)
	}

	result := &TokenReviewResult{
		Authenticated: trResp.Status.Authenticated,
		Audiences:     trResp.Status.Audiences,
	}
	if trResp.Status.User != nil {
		result.Username = trResp.Status.User.Username
		result.UID = trResp.Status.User.UID
		result.Groups = trResp.Status.User.Groups
	}

	return result, nil
}
