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
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errorFromResponse(resp)
	}

	if result != nil {
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
	var bodyReader io.Reader
	var compressed bool

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("api: marshal request body: %w", err)
		}

		if len(data) > gzipThreshold {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			if _, err := gw.Write(data); err != nil {
				return nil, fmt.Errorf("api: gzip compress request: %w", err)
			}
			if err := gw.Close(); err != nil {
				return nil, fmt.Errorf("api: gzip close: %w", err)
			}
			bodyReader = &buf
			compressed = true
		} else {
			bodyReader = bytes.NewReader(data)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("api: create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	if token := c.getAuthToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", userAgentPrefix+c.version)

	return c.httpClient.Do(req)
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
