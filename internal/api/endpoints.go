package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// Register sends a registration request to the control plane.
// POST /v1/register is security: [] — the bootstrap token travels in the body,
// so the request never carries the shared bearer token even if one is set.
func (c *ControlPlane) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.doRequest(withoutAuth(ctx), http.MethodPost, "/v1/register", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ConnectSSE opens an SSE connection to the node event stream.
// The caller is responsible for closing the response body.
// GET /v1/nodes/{node_id}/events
func (c *ControlPlane) ConnectSSE(ctx context.Context, nodeID, lastEventID string) (*http.Response, error) {
	path := fmt.Sprintf("/v1/nodes/%s/events", url.PathEscape(nodeID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("api: create SSE request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if token := c.getAuthToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", userAgentPrefix+c.version)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api: SSE connect: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return nil, errorFromResponse(resp)
	}

	return resp, nil
}

// Heartbeat sends a heartbeat to the control plane.
// POST /v1/nodes/{node_id}/heartbeat
func (c *ControlPlane) Heartbeat(ctx context.Context, nodeID string, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	path := fmt.Sprintf("/v1/nodes/%s/heartbeat", url.PathEscape(nodeID))
	if err := c.doRequest(ctx, http.MethodPost, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Deregister removes a node from the control plane.
// POST /v1/nodes/{node_id}/deregister
func (c *ControlPlane) Deregister(ctx context.Context, nodeID string) error {
	path := fmt.Sprintf("/v1/nodes/%s/deregister", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPost, path, nil, nil)
}

// RotateKeys completes a pending mesh-key rotation; the server identifies the node from the NSK bearer credential.
// POST /v1/keys/rotate
func (c *ControlPlane) RotateKeys(ctx context.Context, req KeyRotateRequest) (*KeyRotateResponse, error) {
	var resp KeyRotateResponse
	if err := c.doRequest(ctx, http.MethodPost, "/v1/keys/rotate", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateCapabilities publishes the node's capabilities.
// PUT /v1/nodes/{node_id}/capabilities
func (c *ControlPlane) UpdateCapabilities(ctx context.Context, nodeID string, caps CapabilitiesPayload) error {
	path := fmt.Sprintf("/v1/nodes/%s/capabilities", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPut, path, caps, nil)
}

// ReportEndpoint reports the node's NAT endpoint information.
// PUT /v1/nodes/{node_id}/endpoint
func (c *ControlPlane) ReportEndpoint(ctx context.Context, nodeID string, req EndpointRequest) (*EndpointResponse, error) {
	var resp EndpointResponse
	path := fmt.Sprintf("/v1/nodes/%s/endpoint", url.PathEscape(nodeID))
	if err := c.doRequest(ctx, http.MethodPut, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FetchState retrieves the desired-state snapshot for a node.
// GET /v1/nodes/{node_id}/state
func (c *ControlPlane) FetchState(ctx context.Context, nodeID string) (*NodeStateSnapshot, error) {
	var resp NodeStateSnapshot
	path := fmt.Sprintf("/v1/nodes/%s/state", url.PathEscape(nodeID))
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// secretNamePattern is the control plane's secret-name grammar and the single
// source of truth for it: secretNameRe compiles it and ErrSecretNameInvalid
// quotes it, so the matcher and the error text can never describe different
// grammars.
const secretNamePattern = `^[a-z][a-z0-9_-]{0,62}$`

var secretNameRe = regexp.MustCompile(secretNamePattern)

// maxSecretEnvelopeSize is the contract's 1 MiB ciphertext cap plus the
// 12-byte nonce and 16-byte GCM tag.
const maxSecretEnvelopeSize = 1<<20 + 28

// FetchSecret retrieves a specific secret for the node as the raw AES-256-GCM
// envelope served by the control plane: the octet-stream body carries
// <12-byte nonce> || <ciphertext + 16-byte GCM tag>, and the version and KID
// ride in the X-Plexsphere-Secret-Version and X-Plexsphere-Secret-KID headers.
// A version > 0 selects an older version via ?version=N; version == 0 is the
// current version.
// GET /v1/nodes/{node_id}/secrets/{name}
func (c *ControlPlane) FetchSecret(ctx context.Context, nodeID, name string, version int) (*SecretEnvelope, error) {
	if !secretNameRe.MatchString(name) {
		return nil, fmt.Errorf("api: fetch secret %q: %w", name, ErrSecretNameInvalid)
	}
	if version < 0 {
		return nil, fmt.Errorf("api: fetch secret %q: version must be >= 0, got %d", name, version)
	}

	// The name is deliberately not escaped: the grammar forbids every character
	// url.PathEscape would touch.
	path := fmt.Sprintf("/v1/nodes/%s/secrets/%s", url.PathEscape(nodeID), name)
	if version > 0 {
		path += fmt.Sprintf("?version=%d", version)
	}

	resp, err := c.doRequestRaw(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reader, err := decodedBody(resp, maxSecretEnvelopeSize+1)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxSecretEnvelopeSize+1))
	if err != nil {
		return nil, fmt.Errorf("api: read secret envelope: %w", err)
	}
	if len(data) > maxSecretEnvelopeSize {
		return nil, fmt.Errorf("api: secret envelope exceeds the 1 MiB cap")
	}

	v, err := strconv.Atoi(resp.Header.Get("X-Plexsphere-Secret-Version"))
	if err != nil || v <= 0 {
		return nil, fmt.Errorf("api: secret response missing or invalid X-Plexsphere-Secret-Version header")
	}

	return &SecretEnvelope{
		Data:    data,
		Version: v,
		KID:     resp.Header.Get("X-Plexsphere-Secret-KID"),
	}, nil
}

// ExecutionCallback posts a single execution lifecycle callback and returns the
// server's new invocation status, plus a presigned output upload URL when the
// callback declares an over-ceiling output.
// POST /v1/nodes/{node_id}/executions/{execution_id}
func (c *ControlPlane) ExecutionCallback(ctx context.Context, nodeID, executionID string, req ExecutionCallbackRequest) (*ExecutionCallbackResponse, error) {
	var resp ExecutionCallbackResponse
	path := fmt.Sprintf("/v1/nodes/%s/executions/%s", url.PathEscape(nodeID), url.PathEscape(executionID))
	if err := c.doRequest(ctx, http.MethodPost, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UploadExecutionOutput PUTs an over-ceiling execution output to a presigned
// URL. Presigned URLs carry their own authentication, so this request sends
// neither the bearer token nor gzip encoding; it uploads the raw bytes with a
// Content-Type of application/octet-stream.
//
// The upload URL comes from the control plane, and captured action output
// routinely contains configuration and credentials, so the transport is pinned
// twice over: the URL may not be less secure than the configured control-plane
// base URL (an https control plane can never downgrade an upload to http), and
// redirects are not followed — a 3xx is surfaced as an error rather than
// re-sending the body to whatever host the redirect names.
func (c *ControlPlane) UploadExecutionOutput(ctx context.Context, uploadURL string, output []byte) error {
	if err := c.checkUploadScheme(uploadURL); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(output))
	if err != nil {
		return fmt.Errorf("api: create output upload request: %w", RedactURLError(err))
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	noRedirect := *c.httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := noRedirect.Do(req)
	if err != nil {
		return fmt.Errorf("api: upload execution output: %w", RedactURLError(err))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return errorFromResponse(resp)
	}
	resp.Body.Close()
	return nil
}

// checkUploadScheme rejects an output upload URL whose scheme is weaker than the
// control plane's own. The error never echoes the URL: it is a bearer credential.
func (c *ControlPlane) checkUploadScheme(uploadURL string) error {
	parsed, err := url.Parse(uploadURL)
	if err != nil {
		return fmt.Errorf("api: parse output upload url: %w", RedactURLError(err))
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if base, err := url.Parse(c.baseURL); err == nil && base.Scheme == parsed.Scheme {
		return nil
	}
	return fmt.Errorf("api: output upload url scheme %q is weaker than the control plane's", parsed.Scheme)
}

// ReportMetrics posts a batch of metric samples to the platform ingest
// endpoint as a JSON array and returns the 202 ingest receipt.
// POST /v1/nodes/{node_id}/metrics
func (c *ControlPlane) ReportMetrics(ctx context.Context, nodeID string, samples []MetricSample) (*IngestReceipt, error) {
	raw, err := json.Marshal(samples)
	if err != nil {
		return nil, fmt.Errorf("api: marshal metric samples: %w", err)
	}
	path := fmt.Sprintf("/v1/nodes/%s/metrics", url.PathEscape(nodeID))
	var resp IngestReceipt
	if err := c.doIngest(ctx, path, "application/json", raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReportLogs posts a batch of log lines to the platform ingest endpoint as
// NDJSON (one JSON object per line) and returns the 202 ingest receipt.
// POST /v1/nodes/{node_id}/logs
func (c *ControlPlane) ReportLogs(ctx context.Context, nodeID string, lines []LogLine) (*IngestReceipt, error) {
	raw, err := marshalNDJSON(lines)
	if err != nil {
		return nil, fmt.Errorf("api: marshal log lines: %w", err)
	}
	path := fmt.Sprintf("/v1/nodes/%s/logs", url.PathEscape(nodeID))
	var resp IngestReceipt
	if err := c.doIngest(ctx, path, "application/x-ndjson", raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReportAudit posts a batch of audit events to the platform ingest endpoint as
// NDJSON (one JSON object per line) and returns the 202 ingest receipt.
// POST /v1/nodes/{node_id}/audit
func (c *ControlPlane) ReportAudit(ctx context.Context, nodeID string, events []AuditEvent) (*IngestReceipt, error) {
	raw, err := marshalNDJSON(events)
	if err != nil {
		return nil, fmt.Errorf("api: marshal audit events: %w", err)
	}
	path := fmt.Sprintf("/v1/nodes/%s/audit", url.PathEscape(nodeID))
	var resp IngestReceipt
	if err := c.doIngest(ctx, path, "application/x-ndjson", raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// marshalNDJSON serializes items as newline-delimited JSON: each element is
// json.Marshal'ed and the encodings are joined with "\n" (no trailing newline).
func marshalNDJSON[T any](items []T) ([]byte, error) {
	var buf bytes.Buffer
	for i, item := range items {
		if i > 0 {
			buf.WriteByte('\n')
		}
		line, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
	}
	return buf.Bytes(), nil
}

// PutStateReport publishes a single per-key node state report and returns the
// server's acknowledgement.
// PUT /v1/nodes/{node_id}/state/reports/{key}
func (c *ControlPlane) PutStateReport(ctx context.Context, nodeID, key string, req NodeStateReportRequest) (*NodeStateReportResponse, error) {
	var resp NodeStateReportResponse
	path := fmt.Sprintf("/v1/nodes/%s/state/reports/%s", url.PathEscape(nodeID), url.PathEscape(key))
	if err := c.doRequest(ctx, http.MethodPut, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteStateReport removes a single per-key node state report. A 204 No
// Content returns nil; a 404 report_not_found (and any other non-2xx status)
// surfaces as an *APIError through errorFromResponse.
// DELETE /v1/nodes/{node_id}/state/reports/{key}
func (c *ControlPlane) DeleteStateReport(ctx context.Context, nodeID, key string) error {
	path := fmt.Sprintf("/v1/nodes/%s/state/reports/%s", url.PathEscape(nodeID), url.PathEscape(key))
	return c.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// ReportSessionActivity posts a one-of session activity record (ssh, k8s, or
// tcp). Success is 204 No Content.
// POST /v1/nodes/{node_id}/sessions/{session_id}
func (c *ControlPlane) ReportSessionActivity(ctx context.Context, nodeID, sessionID string, req SessionActivityRequest) error {
	path := fmt.Sprintf("/v1/nodes/%s/sessions/%s", url.PathEscape(nodeID), url.PathEscape(sessionID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
}

// ReportIntegrityViolation reports a file integrity violation to the control plane.
// POST /v1/nodes/{node_id}/integrity/violations
func (c *ControlPlane) ReportIntegrityViolation(ctx context.Context, nodeID string, req IntegrityViolationReport) error {
	path := fmt.Sprintf("/v1/nodes/%s/integrity/violations", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
}
