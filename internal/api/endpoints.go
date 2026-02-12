package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Register sends a registration request to the control plane.
// POST /v1/register
func (c *ControlPlane) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.doRequest(ctx, http.MethodPost, "/v1/register", req, &resp); err != nil {
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

// RotateKeys requests key rotation for a node.
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
func (c *ControlPlane) ReportEndpoint(ctx context.Context, nodeID string, req EndpointReport) (*EndpointResponse, error) {
	var resp EndpointResponse
	path := fmt.Sprintf("/v1/nodes/%s/endpoint", url.PathEscape(nodeID))
	if err := c.doRequest(ctx, http.MethodPut, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FetchState retrieves the full desired state for a node.
// GET /v1/nodes/{node_id}/state
func (c *ControlPlane) FetchState(ctx context.Context, nodeID string) (*StateResponse, error) {
	var resp StateResponse
	path := fmt.Sprintf("/v1/nodes/%s/state", url.PathEscape(nodeID))
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReportDrift reports drift corrections performed by the node.
// POST /v1/nodes/{node_id}/drift
func (c *ControlPlane) ReportDrift(ctx context.Context, nodeID string, req DriftReport) error {
	path := fmt.Sprintf("/v1/nodes/%s/drift", url.PathEscape(nodeID))
	return c.doRequest(ctx, http.MethodPost, path, req, nil)
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
