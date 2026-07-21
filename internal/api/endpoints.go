package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// FetchSecret retrieves a specific secret for the node.
// GET /v1/nodes/{node_id}/secrets/{key}
func (c *ControlPlane) FetchSecret(ctx context.Context, nodeID, key string) (*SecretResponse, error) {
	var resp SecretResponse
	path := fmt.Sprintf("/v1/nodes/%s/secrets/%s", url.PathEscape(nodeID), url.PathEscape(key))
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SyncReports sends report data to the control plane.
// POST /v1/nodes/{node_id}/report
func (c *ControlPlane) SyncReports(ctx context.Context, nodeID string, req ReportSyncRequest) error {
	path := fmt.Sprintf("/v1/nodes/%s/report", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
}

// AckExecution acknowledges receipt of an execution command.
// POST /v1/nodes/{node_id}/executions/{execution_id}/ack
func (c *ControlPlane) AckExecution(ctx context.Context, nodeID, executionID string, req ExecutionAck) error {
	path := fmt.Sprintf("/v1/nodes/%s/executions/%s/ack", url.PathEscape(nodeID), url.PathEscape(executionID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
}

// ReportResult reports the result of an execution.
// POST /v1/nodes/{node_id}/executions/{execution_id}/result
func (c *ControlPlane) ReportResult(ctx context.Context, nodeID, executionID string, req ExecutionResult) error {
	path := fmt.Sprintf("/v1/nodes/%s/executions/%s/result", url.PathEscape(nodeID), url.PathEscape(executionID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
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

// ReportMetrics sends a batch of metrics to the control plane.
// POST /v1/nodes/{node_id}/metrics
func (c *ControlPlane) ReportMetrics(ctx context.Context, nodeID string, batch MetricBatch) error {
	path := fmt.Sprintf("/v1/nodes/%s/metrics", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPost, path, batch, nil)
}

// ReportLogs sends a batch of logs to the control plane.
// POST /v1/nodes/{node_id}/logs
func (c *ControlPlane) ReportLogs(ctx context.Context, nodeID string, batch LogBatch) error {
	path := fmt.Sprintf("/v1/nodes/%s/logs", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPost, path, batch, nil)
}

// ReportAudit sends a batch of audit events to the control plane.
// POST /v1/nodes/{node_id}/audit
func (c *ControlPlane) ReportAudit(ctx context.Context, nodeID string, batch AuditBatch) error {
	path := fmt.Sprintf("/v1/nodes/%s/audit", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPost, path, batch, nil)
}

// FetchArtifact downloads a plexd binary artifact.
// The caller is responsible for closing the returned ReadCloser.
// GET /v1/artifacts/plexd/{version}/{os}/{arch}
func (c *ControlPlane) FetchArtifact(ctx context.Context, version, goos, arch string) (io.ReadCloser, error) {
	path := fmt.Sprintf("/v1/artifacts/plexd/%s/%s/%s", url.PathEscape(version), url.PathEscape(goos), url.PathEscape(arch))
	resp, err := c.doRequestRaw(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// TunnelReady reports that a tunnel listener is ready for connections.
// POST /v1/nodes/{node_id}/tunnels/{session_id}/ready
func (c *ControlPlane) TunnelReady(ctx context.Context, nodeID, sessionID string, req TunnelReadyRequest) error {
	path := fmt.Sprintf("/v1/nodes/%s/tunnels/%s/ready", url.PathEscape(nodeID), url.PathEscape(sessionID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
}

// TunnelClosed reports that a tunnel session has closed.
// POST /v1/nodes/{node_id}/tunnels/{session_id}/closed
func (c *ControlPlane) TunnelClosed(ctx context.Context, nodeID, sessionID string, req TunnelClosedRequest) error {
	path := fmt.Sprintf("/v1/nodes/%s/tunnels/%s/closed", url.PathEscape(nodeID), url.PathEscape(sessionID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
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
