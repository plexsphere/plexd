// Package registration implements node self-registration.
package registration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// imdsSessionTTL is the TTL (in seconds) requested for IMDSv2 session tokens.
const imdsSessionTTL = "21600"

// imdsSessionTTLDuration is imdsSessionTTL expressed as a Duration.
const imdsSessionTTLDuration = 21600 * time.Second

// imdsSessionTokenPath is the IMDSv2 endpoint for acquiring a session token.
const imdsSessionTokenPath = "/latest/api/token"

// ErrMetadataNotFound reports that the metadata service serves no value at the
// requested path. Callers treat it as "not provisioned" rather than a failure,
// which keeps optional registration inputs optional.
var ErrMetadataNotFound = errors.New("registration: imds: no value at path")

// IMDSProvider reads values (bootstrap token, project id, resource handle)
// from a cloud instance metadata service.
// It supports both IMDSv2 (session-based) and IMDSv1 (open GET) with
// automatic fallback: a PUT is attempted first to acquire a session token;
// if that fails the subsequent GET proceeds without the session header.
type IMDSProvider struct {
	baseURL string
	client  *http.Client

	// mu guards token and tokenExpiry. The IMDSv2 session token is reused
	// across reads: registration resolves up to four values and a token is
	// valid for imdsSessionTTLDuration, so one PUT covers them all.
	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// NewIMDSProvider creates an IMDSProvider that reads values from baseURL,
// using timeout as the HTTP client timeout.
func NewIMDSProvider(timeout time.Duration, baseURL string) *IMDSProvider {
	return &IMDSProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// cachedSessionToken returns an IMDSv2 session token, reusing the cached one
// until it approaches expiry. Only successes are cached, so a failed
// acquisition still retries on the next read and preserves the IMDSv1
// fallback. The HTTP PUT runs outside the lock.
func (p *IMDSProvider) cachedSessionToken(ctx context.Context) string {
	p.mu.Lock()
	if p.token != "" && time.Now().Before(p.tokenExpiry) {
		token := p.token
		p.mu.Unlock()
		return token
	}
	p.mu.Unlock()

	token := p.acquireSessionToken(ctx)
	if token == "" {
		return ""
	}

	p.mu.Lock()
	p.token = token
	// Renew well before the requested TTL lapses.
	p.tokenExpiry = time.Now().Add(imdsSessionTTLDuration / 2)
	p.mu.Unlock()
	return token
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

// ReadValue fetches the value at path from the metadata service.
// It first attempts IMDSv2 session token acquisition; if that fails it
// falls back to an unauthenticated IMDSv1 GET.
func (p *IMDSProvider) ReadValue(ctx context.Context, path string) (string, error) {
	// Paths are configurable (registration.metadata_*_path), and the URL is
	// built by concatenation. A path opening with "@" or "//" would parse the
	// base address as userinfo or drop it entirely, retargeting the request —
	// and the session token in the header — at an attacker-chosen host.
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "", fmt.Errorf("registration: imds: path must be absolute, got %q", path)
	}

	sessionToken := p.cachedSessionToken(ctx)

	url := p.baseURL + path
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

	if resp.StatusCode == http.StatusNotFound {
		return "", ErrMetadataNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registration: imds: unexpected status %d", resp.StatusCode)
	}

	// Read one byte beyond maxValueLength to detect oversized responses
	// without silently truncating them.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxValueLength+1))
	if err != nil {
		return "", fmt.Errorf("registration: imds: read body: %w", err)
	}
	if len(body) > maxValueLength {
		return "", fmt.Errorf("registration: imds: value exceeds maximum length of %d bytes", maxValueLength)
	}

	value := strings.TrimSpace(string(body))
	if value == "" {
		return "", fmt.Errorf("registration: imds: empty value")
	}

	return value, nil
}
