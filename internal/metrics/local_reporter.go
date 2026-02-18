package metrics

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

// SecretFetcher abstracts the control plane client for secret retrieval.
type SecretFetcher interface {
	FetchSecret(ctx context.Context, nodeID, key string) (*api.SecretResponse, error)
}

// LocalReporter implements MetricsReporter by posting metric batches to a
// locally-configured HTTPS endpoint with bearer-token authentication.
type LocalReporter struct {
	httpClient *http.Client
	url        string
	secretKey  string
	fetcher    SecretFetcher
	nsk        []byte
	nodeID     string
	logger     *slog.Logger

	// cacheTTL controls how long a resolved token is reused. Defaults to
	// defaultCacheTTL; tests may override this value.
	cacheTTL time.Duration

	mu          sync.RWMutex
	cachedToken string
	fetchedAt   time.Time
}

// NewLocalReporter creates a LocalReporter from the given configuration.
func NewLocalReporter(cfg api.LocalEndpointConfig, fetcher SecretFetcher, nsk []byte, nodeID string, logger *slog.Logger) *LocalReporter {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSInsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // user-configured opt-in
		}
	}

	return &LocalReporter{
		httpClient: &http.Client{
			Timeout:   defaultHTTPTimeout,
			Transport: transport,
		},
		url:       cfg.URL,
		secretKey: cfg.SecretKey,
		fetcher:   fetcher,
		nsk:       nsk,
		nodeID:    nodeID,
		logger:    logger,
		cacheTTL:  defaultCacheTTL,
	}
}

// ReportMetrics posts the metric batch as JSON to the configured local
// endpoint, authenticating with a bearer token resolved from the secret store.
func (r *LocalReporter) ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error {
	token, err := r.resolveToken(ctx)
	if err != nil {
		return fmt.Errorf("metrics: resolve credential: %w", err)
	}

	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("metrics: marshal batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("metrics: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("metrics: post batch: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck // drain body for connection reuse

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("metrics: post batch: unexpected status %d", resp.StatusCode)
	}

	return nil
}

// resolveToken returns a bearer token, using a cached value when still valid.
// On fetch or decrypt failure it falls back to a stale cached token (with a
// warning log) rather than failing outright.
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

	// Double-check: another goroutine may have refreshed while we waited.
	if r.cachedToken != "" && time.Since(r.fetchedAt) < r.cacheTTL {
		return r.cachedToken, nil
	}

	resp, err := r.fetcher.FetchSecret(ctx, r.nodeID, r.secretKey)
	if err != nil {
		if r.cachedToken != "" {
			r.logger.Warn("using cached credential", "component", "metrics", "error", err)
			return r.cachedToken, nil
		}
		return "", fmt.Errorf("metrics: fetch secret: %w", err)
	}

	token, err := nodeapi.DecryptSecret(r.nsk, resp.Ciphertext, resp.Nonce)
	if err != nil {
		if r.cachedToken != "" {
			r.logger.Warn("using cached credential", "component", "metrics", "error", err)
			return r.cachedToken, nil
		}
		return "", fmt.Errorf("metrics: decrypt secret: %w", err)
	}

	r.cachedToken = token
	r.fetchedAt = time.Now()
	return token, nil
}
