package api

import (
	"encoding/json"
	"time"
)

// ---------------------------------------------------------------------------
// Registration  POST /v1/register
// ---------------------------------------------------------------------------

type RegisterRequest struct {
	Token        string              `json:"token"`
	PublicKey    string              `json:"public_key"`
	Hostname     string              `json:"hostname"`
	Metadata     map[string]string   `json:"metadata,omitempty"`
	Capabilities *CapabilitiesPayload `json:"capabilities,omitempty"`
}

type RegisterResponse struct {
	NodeID        string `json:"node_id"`
	MeshIP        string `json:"mesh_ip"`
	SigningPublicKey string `json:"signing_public_key"`
	NodeSecretKey string `json:"node_secret_key"`
	Peers         []Peer `json:"peers"`
}

// Peer is used in registration responses and state responses.
type Peer struct {
	ID         string   `json:"id"`
	PublicKey  string   `json:"public_key"`
	MeshIP     string   `json:"mesh_ip"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	PSK        string   `json:"psk"`
}

// ---------------------------------------------------------------------------
// Heartbeat  POST /v1/nodes/{node_id}/heartbeat
// ---------------------------------------------------------------------------

type HeartbeatRequest struct {
	NodeID         string    `json:"node_id"`
	Timestamp      time.Time `json:"timestamp"`
	Status         string    `json:"status"`
	Uptime         string    `json:"uptime"`
	BinaryChecksum string    `json:"binary_checksum"`
	Mesh           *MeshInfo `json:"mesh,omitempty"`
	NAT            *NATInfo  `json:"nat,omitempty"`
}

type MeshInfo struct {
	Interface  string `json:"interface"`
	PeerCount  int    `json:"peer_count"`
	ListenPort int    `json:"listen_port"`
}

type NATInfo struct {
	PublicEndpoint string `json:"public_endpoint"`
	Type           string `json:"type"`
}

type HeartbeatResponse struct {
	Reconcile  bool `json:"reconcile"`
	RotateKeys bool `json:"rotate_keys"`
}

// ---------------------------------------------------------------------------
// State  GET /v1/nodes/{node_id}/state
// ---------------------------------------------------------------------------

type StateResponse struct {
	Peers       []Peer            `json:"peers"`
	Policies    []Policy          `json:"policies"`
	SigningKeys *SigningKeys       `json:"signing_keys,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Data        []DataEntry       `json:"data"`
	SecretRefs  []SecretRef       `json:"secret_refs"`
}

type Policy struct {
	ID    string       `json:"id"`
	Rules []PolicyRule `json:"rules"`
}

type PolicyRule struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
}

type SigningKeys struct {
	Current           string     `json:"current"`
	Previous          string     `json:"previous,omitempty"`
	TransitionExpires *time.Time `json:"transition_expires,omitempty"`
}

type DataEntry struct {
	Key         string          `json:"key"`
	ContentType string          `json:"content_type"`
	Payload     json.RawMessage `json:"payload"`
	Version     int             `json:"version"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type SecretRef struct {
	Key     string `json:"key"`
	Version int    `json:"version"`
}

// ---------------------------------------------------------------------------
// Drift  POST /v1/nodes/{node_id}/drift
// ---------------------------------------------------------------------------

type DriftReport struct {
	Timestamp   time.Time         `json:"timestamp"`
	Corrections []DriftCorrection `json:"corrections"`
}

type DriftCorrection struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// ---------------------------------------------------------------------------
// Secrets  GET /v1/nodes/{node_id}/secrets/{key}
// ---------------------------------------------------------------------------

type SecretResponse struct {
	Key        string `json:"key"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Version    int    `json:"version"`
}

// ---------------------------------------------------------------------------
// Reports  POST /v1/nodes/{node_id}/report
// ---------------------------------------------------------------------------

type ReportSyncRequest struct {
	Entries []ReportEntry `json:"entries"`
	Deleted []string      `json:"deleted"`
}

type ReportEntry struct {
	Key         string          `json:"key"`
	ContentType string          `json:"content_type"`
	Payload     json.RawMessage `json:"payload"`
	Version     int             `json:"version"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Execution  POST /v1/nodes/{node_id}/executions/{execution_id}/ack
//            POST /v1/nodes/{node_id}/executions/{execution_id}/result
// ---------------------------------------------------------------------------

type ExecutionAck struct {
	ExecutionID string `json:"execution_id"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
}

type ExecutionResult struct {
	ExecutionID string       `json:"execution_id"`
	Status      string       `json:"status"`
	ExitCode    int          `json:"exit_code"`
	Stdout      string       `json:"stdout"`
	Stderr      string       `json:"stderr"`
	Duration    string       `json:"duration"`
	FinishedAt  time.Time    `json:"finished_at"`
	TriggeredBy *TriggeredBy `json:"triggered_by,omitempty"`
}

type TriggeredBy struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
}

// ---------------------------------------------------------------------------
// Observability
//   POST /v1/nodes/{node_id}/metrics
//   POST /v1/nodes/{node_id}/logs
//   POST /v1/nodes/{node_id}/audit
// ---------------------------------------------------------------------------

// MetricBatch is the top-level payload for POST /v1/nodes/{node_id}/metrics.
type MetricBatch = []MetricPoint

type MetricPoint struct {
	Timestamp time.Time       `json:"timestamp"`
	Group     string          `json:"group"`
	PeerID    string          `json:"peer_id,omitempty"`
	Data      json.RawMessage `json:"data"`
}

// LogBatch is the top-level payload for POST /v1/nodes/{node_id}/logs.
type LogBatch = []LogEntry

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Unit      string    `json:"unit"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Hostname  string    `json:"hostname"`
}

// AuditBatch is the top-level payload for POST /v1/nodes/{node_id}/audit.
type AuditBatch = []AuditEntry

type AuditEntry struct {
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	Subject   json.RawMessage `json:"subject"`
	Object    json.RawMessage `json:"object"`
	Action    string          `json:"action"`
	Result    string          `json:"result"`
	Hostname  string          `json:"hostname"`
	Raw       string          `json:"raw"`
}

// ---------------------------------------------------------------------------
// Capabilities  PUT /v1/nodes/{node_id}/capabilities
// ---------------------------------------------------------------------------

type CapabilitiesPayload struct {
	Binary         *BinaryInfo  `json:"binary,omitempty"`
	BuiltinActions []ActionInfo `json:"builtin_actions"`
	Hooks          []HookInfo   `json:"hooks"`
}

type BinaryInfo struct {
	Version  string `json:"version"`
	Checksum string `json:"checksum"`
}

type ActionInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Parameters  []ActionParam `json:"parameters"`
}

type ActionParam struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type HookInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Source      string        `json:"source"`
	Checksum    string        `json:"checksum"`
	Parameters  []ActionParam `json:"parameters"`
	Timeout     string        `json:"timeout"`
	Sandbox     string        `json:"sandbox"`
}

// ---------------------------------------------------------------------------
// NAT Endpoint  PUT /v1/nodes/{node_id}/endpoint
// ---------------------------------------------------------------------------

type EndpointReport struct {
	PublicEndpoint string `json:"public_endpoint"`
	NATType        string `json:"nat_type"`
}

type EndpointResponse struct {
	PeerEndpoints []PeerEndpoint `json:"peer_endpoints"`
}

type PeerEndpoint struct {
	PeerID   string `json:"peer_id"`
	Endpoint string `json:"endpoint"`
}

// ---------------------------------------------------------------------------
// Key Rotation  POST /v1/keys/rotate
// ---------------------------------------------------------------------------

type KeyRotateRequest struct {
	NodeID       string `json:"node_id"`
	NewPublicKey string `json:"new_public_key"`
}

type KeyRotateResponse struct {
	UpdatedPeers []Peer `json:"updated_peers"`
}
