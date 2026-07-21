package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// gzipThreshold is the minimum body size for gzip compression.
	gzipThreshold = 1024 // 1 KiB

	// maxResponseSize is the maximum decompressed response body size (10 MiB).
	// Protects against gzip bombs in compressed responses.
	maxResponseSize = 10 * 1024 * 1024

	// userAgentPrefix is the User-Agent header prefix.
	userAgentPrefix = "plexd/"
)

// ControlPlane is the client for the Plexsphere control plane API.
type ControlPlane struct {
	httpClient *http.Client
	baseURL    string
	version    string
	logger     *slog.Logger

	mu        sync.RWMutex
	authToken string
}

// NewControlPlane creates a new ControlPlane client with the given configuration.
func NewControlPlane(cfg Config, version string, logger *slog.Logger) (*ControlPlane, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
		},
		DialContext: (&net.Dialer{
			Timeout: cfg.ConnectTimeout,
		}).DialContext,
		DisableCompression: true,
	}

	httpClient := &http.Client{
		Timeout:   cfg.RequestTimeout,
		Transport: transport,
	}

	if cfg.TLSInsecureSkipVerify {
		logger.Warn("TLS certificate verification disabled")
	}

	return &ControlPlane{
		httpClient: httpClient,
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		version:    version,
		logger:     logger,
		authToken:  "",
	}, nil
}

// SetAuthToken sets the bearer token used for API authentication.
func (c *ControlPlane) SetAuthToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authToken = token
}

// noAuthKey marks a request context that must not carry the Authorization
// header, regardless of the shared token.
type noAuthKey struct{}

// withoutAuth returns a context that suppresses the Authorization header for
// the request built from it. It scopes token suppression to a single call so
// unauthenticated endpoints (POST /v1/register is security: []) never leak the
// shared bearer token — and never have to blank it on the live client, which
// would strand every concurrent request that depends on that token.
func withoutAuth(ctx context.Context) context.Context {
	return context.WithValue(ctx, noAuthKey{}, struct{}{})
}

// authSuppressed reports whether ctx was marked by withoutAuth.
func authSuppressed(ctx context.Context) bool {
	return ctx.Value(noAuthKey{}) != nil
}

// getAuthToken returns the current bearer token.
func (c *ControlPlane) getAuthToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authToken
}

// doRequest is the core HTTP helper that handles JSON marshaling, gzip
// compression, request execution, and response decoding.
func (c *ControlPlane) doRequest(ctx context.Context, method, path string, body any, result any) error {
	resp, err := c.sendRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	return handleResponse(resp, result)
}

// doIngest posts a caller-supplied raw body with the given content type to an
// observability ingest endpoint and decodes the response exactly as doRequest
// does. It lets the ingest endpoints send a pre-serialized JSON array or NDJSON
// payload without going through json.Marshal, while keeping identical gzip and
// error semantics. X-Plexsphere-Sent-At carries the node's wall clock at send
// time; ingest gate 4 refuses a missing or unparseable value with 400
// ingest_sent_at_invalid, so it is always stamped in RFC 3339 (nanosecond).
func (c *ControlPlane) doIngest(ctx context.Context, path, contentType string, raw []byte, result any) error {
	req, err := c.newRequest(ctx, http.MethodPost, path, contentType, raw)
	if err != nil {
		return err
	}
	req.Header.Set("X-Plexsphere-Sent-At", time.Now().UTC().Format(time.RFC3339Nano))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	return handleResponseAllowEmpty(resp, result, true)
}

// handleResponse is the shared post-send tail: it maps a non-2xx status to an
// *APIError, transparently gunzips a compressed response, and decodes the body
// into result. It closes the response body. An empty body is a decode error:
// every endpoint routed through here answers with the state the caller then
// acts on, so a gateway that returns 200 with no body must fail loudly instead
// of handing the caller a zero value it would read as "the control plane knows
// of no peers".
func handleResponse(resp *http.Response, result any) error {
	return handleResponseAllowEmpty(resp, result, false)
}

// handleResponseAllowEmpty is handleResponse with an opt-in tolerance for an
// undecodable body, which only the ingest endpoints may set. Their 202 Accepted
// acknowledges a durable enqueue and carries no state, and RFC 9110 makes a
// body a SHOULD rather than a MUST there, so a body that does not decode must
// not be misread as a failure that drives a retry of an already-accepted batch.
// The tolerance covers every decode outcome, not just a bare io.EOF: a body cut
// short by a connection reset yields io.ErrUnexpectedEOF and one an intermediate
// proxy rewrote into HTML yields a *json.SyntaxError, and re-sending on either
// would duplicate records the platform already accepted — ingest carries no
// idempotency key, so it cannot deduplicate them. The receipt is left at its
// zero value, which the callers already report as a record-count mismatch.
func handleResponseAllowEmpty(resp *http.Response, result any, allowEmpty bool) error {
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errorFromResponse(resp)
	}

	// A 204 carries no body by definition, so skip decoding it entirely.
	if result != nil && resp.StatusCode != http.StatusNoContent {
		var reader io.Reader = resp.Body
		if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			gr, err := gzip.NewReader(resp.Body)
			if err != nil {
				return fmt.Errorf("api: gzip decompress response: %w", err)
			}
			defer gr.Close()
			reader = io.LimitReader(gr, maxResponseSize)
		}
		if err := json.NewDecoder(reader).Decode(result); err != nil {
			if allowEmpty {
				return nil
			}
			return fmt.Errorf("api: decode response: %w", err)
		}
	}

	return nil
}

// doRequestRaw sends an HTTP request and returns the raw response without
// reading or closing the body. Used for SSE streams and artifact downloads.
// The caller is responsible for closing the response body.
func (c *ControlPlane) doRequestRaw(ctx context.Context, method, path string, body any) (*http.Response, error) {
	resp, err := c.sendRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return nil, errorFromResponse(resp)
	}

	return resp, nil
}

// sendRequest builds and executes an HTTP request with standard headers,
// optional JSON body marshaling, and gzip compression for large payloads.
func (c *ControlPlane) sendRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var raw []byte
	contentType := ""
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("api: marshal request body: %w", err)
		}
		raw = data
		contentType = "application/json"
	}
	req, err := c.newRequest(ctx, method, path, contentType, raw)
	if err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}

// newRequest builds an HTTP request from a pre-serialized body. It gzips the
// body when it exceeds gzipThreshold, sets Content-Type from the parameter when
// there is a body, and applies the standard Accept, Accept-Encoding,
// Authorization, and User-Agent headers.
func (c *ControlPlane) newRequest(ctx context.Context, method, path, contentType string, raw []byte) (*http.Request, error) {
	var bodyReader io.Reader
	var compressed bool

	if len(raw) > 0 {
		if len(raw) > gzipThreshold {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			if _, err := gw.Write(raw); err != nil {
				return nil, fmt.Errorf("api: gzip compress request: %w", err)
			}
			if err := gw.Close(); err != nil {
				return nil, fmt.Errorf("api: gzip close: %w", err)
			}
			bodyReader = &buf
			compressed = true
		} else {
			bodyReader = bytes.NewReader(raw)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("api: create request: %w", err)
	}

	if len(raw) > 0 && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	if token := c.getAuthToken(); token != "" && !authSuppressed(ctx) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", userAgentPrefix+c.version)

	return req, nil
}

// Ping sends a GET request to /v1/ping for health checking.
func (c *ControlPlane) Ping(ctx context.Context) error {
	return c.doRequest(ctx, http.MethodGet, "/v1/ping", nil, nil)
}

// PostJSON sends a POST request with a JSON body and decodes the JSON response.
func (c *ControlPlane) PostJSON(ctx context.Context, path string, body any, result any) error {
	return c.doRequest(ctx, http.MethodPost, path, body, result)
}

// GetJSON sends a GET request and decodes the JSON response.
func (c *ControlPlane) GetJSON(ctx context.Context, path string, result any) error {
	return c.doRequest(ctx, http.MethodGet, path, nil, result)
}
