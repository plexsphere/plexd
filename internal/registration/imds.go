// Package registration implements node self-registration.
package registration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// imdsSessionTTL is the TTL (in seconds) requested for IMDSv2 session tokens.
const imdsSessionTTL = "21600"

// imdsSessionTokenPath is the IMDSv2 endpoint for acquiring a session token.
const imdsSessionTokenPath = "/latest/api/token"

// IMDSProvider reads a bootstrap token from a cloud instance metadata service.
// It supports both IMDSv2 (session-based) and IMDSv1 (open GET) with
// automatic fallback: a PUT is attempted first to acquire a session token;
// if that fails the subsequent GET proceeds without the session header.
type IMDSProvider struct {
	baseURL   string
	tokenPath string
	client    *http.Client
}

// NewIMDSProvider creates an IMDSProvider that reads the bootstrap token from
// baseURL + cfg.MetadataTokenPath.
// The HTTP client timeout is set to cfg.MetadataTimeout.
func NewIMDSProvider(cfg *Config, baseURL string) *IMDSProvider {
	return &IMDSProvider{
		baseURL:   strings.TrimRight(baseURL, "/"),
		tokenPath: cfg.MetadataTokenPath,
		client: &http.Client{
			Timeout: cfg.MetadataTimeout,
		},
	}
}

// acquireSessionToken attempts to obtain an IMDSv2 session token via PUT.
// Returns the token string on success or empty string if IMDSv2 is
// unavailable (allowing graceful fallback to IMDSv1).
func (p *IMDSProvider) acquireSessionToken(ctx context.Context) string {
	url := p.baseURL + imdsSessionTokenPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", imdsSessionTTL)

	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenLength+1))
	if err != nil {
		return ""
	}

	token := strings.TrimSpace(string(body))
	if len(token) > maxTokenLength {
		return ""
	}
	return token
}

// ReadToken fetches the bootstrap token from the metadata service.
// It first attempts IMDSv2 session token acquisition; if that fails it
// falls back to an unauthenticated IMDSv1 GET.
func (p *IMDSProvider) ReadToken(ctx context.Context) (string, error) {
	sessionToken := p.acquireSessionToken(ctx)

	url := p.baseURL + p.tokenPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("registration: imds: create request: %w", err)
	}

	if sessionToken != "" {
		req.Header.Set("X-aws-ec2-metadata-token", sessionToken)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registration: imds: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registration: imds: unexpected status %d", resp.StatusCode)
	}

	// Read one byte beyond maxTokenLength to detect oversized responses
	// without silently truncating them.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenLength+1))
	if err != nil {
		return "", fmt.Errorf("registration: imds: read body: %w", err)
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("registration: imds: empty token")
	}

	if err := validateToken(token); err != nil {
		return "", err
	}

	return token, nil
}
