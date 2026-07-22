package auditfwd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nodeapi"
)

const (
	// defaultCacheTTL is the duration a resolved credential token is cached
	// before a fresh fetch is attempted.
	defaultCacheTTL = 5 * time.Minute

	// defaultHTTPTimeout is the HTTP client timeout for local endpoint requests.
	defaultHTTPTimeout = 10 * time.Second
)

// SecretFetcher abstracts retrieval of encrypted secrets from the control plane.
type SecretFetcher interface {
	FetchSecret(ctx context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error)
}

// LocalReporter sends audit batches to a local data-plane endpoint.
type LocalReporter struct {
	httpClient *http.Client
	url        string
	secretKey  string
	fetcher    SecretFetcher
	nsk        []byte
	nodeID     string
	logger     *slog.Logger

	mu          sync.RWMutex
	cachedToken string
	fetchedAt   time.Time
	cacheTTL    time.Duration
}

// NewLocalReporter creates a LocalReporter that posts audit data to cfg.URL.
func NewLocalReporter(cfg api.LocalEndpointConfig, fetcher SecretFetcher, nsk []byte, nodeID string, logger *slog.Logger) *LocalReporter {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSInsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-configured
	}
	return &LocalReporter{
		httpClient: &http.Client{Timeout: defaultHTTPTimeout, Transport: transport},
		url:        cfg.URL,
		secretKey:  cfg.SecretKey,
		fetcher:    fetcher,
		nsk:        nsk,
		nodeID:     nodeID,
		logger:     logger,
		cacheTTL:   defaultCacheTTL,
	}
}

// ReportAudit sends the audit batch to the local endpoint as a JSON POST.
func (r *LocalReporter) ReportAudit(ctx context.Context, nodeID string, batch api.AuditBatch) error {
	token, err := r.resolveToken(ctx)
	if err != nil {
		return fmt.Errorf("auditfwd: resolve credential: %w", err)
	}

	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("auditfwd: marshal audit batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("auditfwd: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auditfwd: post audit batch: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck // drain body

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("auditfwd: post audit batch: unexpected status %d", resp.StatusCode)
	}

	return nil
}

// resolveToken returns a bearer token, using a cached value when still valid.
func (r *LocalReporter) resolveToken(ctx context.Context) (string, error) {
	r.mu.RLock()
	if r.cachedToken != "" && time.Since(r.fetchedAt) < r.cacheTTL {
		token := r.cachedToken
		r.mu.RUnlock()
		return token, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if r.cachedToken != "" && time.Since(r.fetchedAt) < r.cacheTTL {
		return r.cachedToken, nil
	}

	secret, err := r.fetcher.FetchSecret(ctx, r.nodeID, r.secretKey, 0)
	if err != nil {
		if r.cachedToken != "" {
			r.logger.Warn("using cached credential", "component", "auditfwd", "error", err)
			return r.cachedToken, nil
		}
		return "", fmt.Errorf("auditfwd: fetch secret: %w", err)
	}

	plaintext, err := nodeapi.DecryptSecret(r.nsk, secret.Data)
	if err != nil {
		if r.cachedToken != "" {
			r.logger.Warn("using cached credential", "component", "auditfwd", "kid", secret.KID, "version", secret.Version, "error", err)
			return r.cachedToken, nil
		}
		return "", fmt.Errorf("auditfwd: decrypt secret: %w", err)
	}

	r.cachedToken = plaintext
	r.fetchedAt = time.Now()
	return r.cachedToken, nil
}
