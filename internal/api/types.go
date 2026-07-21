package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// ---------------------------------------------------------------------------
// Registration  POST /v1/register
// ---------------------------------------------------------------------------

type RegisterRequest struct {
	ProjectID           string `json:"project_id"`
	ResourceHandle      string `json:"resource_handle"`
	BootstrapToken      string `json:"bootstrap_token"`
	Nonce               string `json:"nonce"`
	PublicKey           string `json:"public_key"`
	RequestedResourceID string `json:"requested_resource_id,omitempty"`
}

type RegisterResponse struct {
	NodeID           string         `json:"node_id"`
	MeshIP           string         `json:"mesh_ip"`
	SigningPublicKey string         `json:"signing_public_key"`
	SigningKeyID     string         `json:"signing_key_id"`
	NSK              string         `json:"nsk"`
	PeerSnapshot     []RegisterPeer `json:"peer_snapshot"`
	DomainMeshCIDR   string         `json:"domain_mesh_cidr"`
}

// RegisterPeer is the initial peer snapshot entry returned by POST /v1/register.
// It is deliberately narrow: it carries NO psk, allowed_ips, or endpoint. The
// reconciliation peer shape is SnapshotPeer.
type RegisterPeer struct {
	NodeID           string `json:"node_id"`
	MeshIP           string `json:"mesh_ip"`
	PublicKey        string `json:"public_key"`
	FallbackEndpoint string `json:"fallback_endpoint,omitempty"`
}

// Peer is the WireGuard peer shape used only for SSE peer_* payloads
// until issue #25 migrates that contract.
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
	ClientNow      time.Time      `json:"client_now"`
	BinaryChecksum string         `json:"binary_checksum"`
	BinaryVersion  string         `json:"binary_version"`
	NATSummary     map[string]any `json:"nat_summary"`
}

type HeartbeatResponse struct {
	AcceptedAt time.Time `json:"accepted_at"`
	Reconcile  bool      `json:"reconcile"`
	RotateKeys bool      `json:"rotate_keys"`
}

// ---------------------------------------------------------------------------
// State  GET /v1/nodes/{node_id}/state
// ---------------------------------------------------------------------------

// NodeStateSnapshot is the desired-state envelope returned by
// GET /v1/nodes/{node_id}/state. Every block key is always present on the wire:
// a null value means "block not populated", never "field absent". The differ
// therefore distinguishes a nil pointer from a populated block, so none of the
// six fields carry omitempty.
type NodeStateSnapshot struct {
	Peers        []SnapshotPeer  `json:"peers"`
	Reachability json.RawMessage `json:"reachability"`
	Policy       *PolicySnapshot `json:"policy"`
	Bridge       *BridgeSnapshot `json:"bridge"`
	State        *NodeStateBlock `json:"state"`
	Reports      *NodeStateBlock `json:"reports"`
}

// SnapshotPeer is a reconciliation peer entry in NodeStateSnapshot. It is a
// separate type from RegisterPeer (one Go type per contract schema) and carries
// NO psk, allowed_ips, or endpoint: AllowedIPs are derived locally as
// mesh_ip/32, fallback_endpoint is the relay target programmed as the WireGuard
// endpoint, and no preshared key is fabricated.
type SnapshotPeer struct {
	NodeID           string `json:"node_id"`
	MeshIP           string `json:"mesh_ip"`
	PublicKey        string `json:"public_key"`
	FallbackEndpoint string `json:"fallback_endpoint,omitempty"`
}

// PolicySnapshot is the single merged policy block. Fingerprint is a 44-char
// base64 SHA-256 over the server's canonical rule byte stream; plexd treats it
// as an opaque comparison key and never re-derives it from Rules.
type PolicySnapshot struct {
	RevisionID  string       `json:"revision_id"`
	Fingerprint string       `json:"fingerprint"`
	Rules       []PolicyRule `json:"rules"`
}

// PolicyRule is a five-tuple firewall rule. Ports is present iff Protocol is
// tcp or udp and is absent for icmp/any.
type PolicyRule struct {
	Action          string     `json:"action"`
	Protocol        string     `json:"protocol"`
	SourceCIDR      string     `json:"source_cidr"`
	DestinationCIDR string     `json:"destination_cidr"`
	Ports           *PortRange `json:"ports,omitempty"`
}

// PortRange is a single inclusive destination port range (from <= to).
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// BridgeSnapshot carries the four bridge subtrees. Each child is
// present-but-nullable; there are no base fields on the wire.
type BridgeSnapshot struct {
	Relay      *RelayConfig      `json:"relay"`
	UserAccess *UserAccessConfig `json:"user_access"`
	Ingress    *IngressConfig    `json:"ingress"`
	SiteToSite *SiteToSiteConfig `json:"site_to_site"`
}

// NodeStateBlock is a three-bucket state block. Each bucket is a required array
// (never null when the block is populated), with entries ordered by key
// ascending.
type NodeStateBlock struct {
	Metadata []StateEntry `json:"metadata"`
	Data     []StateEntry `json:"data"`
	Reports  []StateEntry `json:"reports"`
}

// StateEntry is a single state entry. Value is an opaque string; WorkloadTag is
// absent/empty when the entry is unattributed.
type StateEntry struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	WorkloadTag string `json:"workload_tag,omitempty"`
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

// NodeStateReportRequest is the control-plane wire format for the body of
// PUT /v1/nodes/{id}/state/reports/{key}. Value is the opaque report payload;
// WorkloadTag attributes the report to a workload and is absent when the report
// is unattributed.
type NodeStateReportRequest struct {
	Value       string `json:"value"`
	WorkloadTag string `json:"workload_tag,omitempty"`
}

// NodeStateReportResponse is the control-plane wire format for the 200 body of
// PUT /v1/nodes/{id}/state/reports/{key} (and DELETE /v1/nodes/{id}/state/
// reports/{key}). Key echoes the report key the operation addressed.
type NodeStateReportResponse struct {
	AcceptedAt time.Time `json:"accepted_at"`
	Key        string    `json:"key"`
}

// ---------------------------------------------------------------------------
// Execution  POST /v1/nodes/{node_id}/executions/{execution_id}
// ---------------------------------------------------------------------------

// ActionRequest is the SSE payload for action_request events.
type ActionRequest struct {
	ExecutionID string            `json:"execution_id"`
	Action      string            `json:"action"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Timeout     string            `json:"timeout"`
	Checksum    string            `json:"checksum,omitempty"`
	TriggeredBy *TriggeredBy      `json:"triggered_by,omitempty"`
}

type TriggeredBy struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
}

// Execution callback statuses a node reports on the v1 execution callback
// (POST /v1/nodes/{node_id}/executions/{execution_id}).
const (
	// ExecutionStatusAck acknowledges receipt of the action request.
	ExecutionStatusAck = "ack"
	// ExecutionStatusStarted reports that the action has begun running.
	ExecutionStatusStarted = "started"
	// ExecutionStatusSucceeded is the terminal callback for a successful run.
	ExecutionStatusSucceeded = "succeeded"
	// ExecutionStatusFailed is the terminal callback for a failed run.
	ExecutionStatusFailed = "failed"
	// ExecutionStatusCancelled is the terminal callback for a cancelled run.
	ExecutionStatusCancelled = "cancelled"
)

// RFC 9457 problem codes with which the control plane refuses an execution
// callback. A refusal carrying one of these is deliberate and permanent: the
// node must stop driving the execution instead of retrying or double-reporting.
const (
	// CodeNSKNodeMismatch (403) means the callback's node id does not match the
	// node identified by the NSK bearer credential.
	CodeNSKNodeMismatch = "nsk_node_mismatch"
	// CodeInvalidStateTransition (409) means the callback would advance the
	// invocation along an illegal edge of the execution state machine.
	CodeInvalidStateTransition = "invalid_state_transition"
	// CodeExecutionAlreadyTerminal (409) means the invocation has already
	// settled and accepts no further callbacks.
	CodeExecutionAlreadyTerminal = "execution_already_terminal"
)

// ExecutionCallbackRequest is the single callback a node posts to
// POST /v1/nodes/{node_id}/executions/{execution_id} to advance an execution
// through its lifecycle. Status is one of the ExecutionStatus* values. ExitCode
// is a pointer so a terminal callback can report an explicit zero. Error is set
// on failed terminals. DeclaredOutputBytes is the byte length of the captured
// output; a declaration over the 16 KiB inline ceiling drives the presign mint.
type ExecutionCallbackRequest struct {
	Status              string           `json:"status"`
	ExitCode            *int             `json:"exit_code,omitempty"`
	Error               string           `json:"error,omitempty"`
	DeclaredOutputBytes int64            `json:"declared_output_bytes,omitempty"`
	Output              *ExecutionOutput `json:"output,omitempty"`
}

// ExecutionOutput carries an execution's captured output on a terminal
// callback. Inline is the base64-encoded output body and is used only when it
// is at most 16 KiB. ObjectKey and SHA256 describe an already-uploaded
// over-ceiling output: ObjectKey is the object-store key and SHA256 is the
// lowercase-hex SHA-256 of the uploaded bytes.
type ExecutionOutput struct {
	Inline    string `json:"inline,omitempty"`
	ObjectKey string `json:"object_key,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// ExecutionCallbackResponse is the 200 response to an execution callback. Status
// is the new invocation status. OutputUploadURL is a presigned PUT URL present
// only on the first callback that declares an over-ceiling output; the node
// derives the object key from the URL path and uploads the bytes there.
type ExecutionCallbackResponse struct {
	Status          string `json:"status"`
	OutputUploadURL string `json:"output_upload_url,omitempty"`
}

// ---------------------------------------------------------------------------
// Observability
//   POST /v1/nodes/{node_id}/metrics
//   POST /v1/nodes/{node_id}/logs
//   POST /v1/nodes/{node_id}/audit
// ---------------------------------------------------------------------------

// MetricSample is the control-plane wire format for a single metric in the
// body of POST /v1/nodes/{node_id}/metrics. Group is one of the MetricGroup*
// values; Labels is absent when the sample carries no dimensions.
type MetricSample struct {
	Group     string            `json:"group"`
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// Wire metric groups (closed set; out-of-set → 400 ingest_batch_malformed).
const (
	MetricGroupNodeResources = "node_resources"
	MetricGroupTunnelHealth  = "tunnel_health"
	MetricGroupPeerLatency   = "peer_latency"
	MetricGroupAgentStats    = "agent_stats"
)

// LogLine is the control-plane wire format for a single log record in the body
// of POST /v1/nodes/{node_id}/logs. Unit and Hostname are absent when unknown.
type LogLine struct {
	Severity  string    `json:"severity"`
	Unit      string    `json:"unit,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// AuditEvent is the control-plane wire format for a single audit record in the
// body of POST /v1/nodes/{node_id}/audit.
type AuditEvent struct {
	Source    string    `json:"source"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	Timestamp time.Time `json:"timestamp"`
}

// IngestReceipt is the 202 body of the three ingest operations
// (POST /v1/nodes/{node_id}/metrics|logs|audit). Records is the number of
// records the control plane accepted from the batch.
type IngestReceipt struct {
	AcceptedAt time.Time `json:"accepted_at"`
	Records    int       `json:"records"`
}

// MetricBatch is the internal pipeline and local-endpoint payload for a batch
// of metric points. The control-plane leg of POST /v1/nodes/{node_id}/metrics
// sends MetricSample instead.
type MetricBatch = []MetricPoint

// MetricPoint is the internal pipeline and local-endpoint format for a single
// metric. The control-plane leg sends MetricSample instead.
type MetricPoint struct {
	Timestamp time.Time       `json:"timestamp"`
	Group     string          `json:"group"`
	PeerID    string          `json:"peer_id,omitempty"`
	Data      json.RawMessage `json:"data"`
}

// LogBatch is the internal pipeline and local-endpoint payload for a batch of
// log entries. The control-plane leg of POST /v1/nodes/{node_id}/logs sends
// LogLine instead.
type LogBatch = []LogEntry

// LogEntry is the internal pipeline and local-endpoint format for a single log
// record. The control-plane leg sends LogLine instead.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Unit      string    `json:"unit"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Hostname  string    `json:"hostname"`
}

// AuditBatch is the internal pipeline and local-endpoint payload for a batch of
// audit entries. The control-plane leg of POST /v1/nodes/{node_id}/audit sends
// AuditEvent instead.
type AuditBatch = []AuditEntry

// AuditEntry is the internal pipeline and local-endpoint format for a single
// audit record. The control-plane leg sends AuditEvent instead.
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
	Default     string `json:"default,omitempty"`
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

type EndpointRequest struct {
	Endpoint   string    `json:"endpoint"`
	NATType    string    `json:"nat_type"`
	ReportedAt time.Time `json:"reported_at"`
}

type EndpointResponse struct {
	AcceptedAt time.Time `json:"accepted_at"`
	StaleAfter time.Time `json:"stale_after"`
}

// ---------------------------------------------------------------------------
// Key Rotation  POST /v1/keys/rotate
// ---------------------------------------------------------------------------

type KeyRotateRequest struct {
	NewPublicKey string `json:"new_public_key"`
}

type KeyRotateResponse struct {
	RotationID     string `json:"rotation_id"`
	KID            string `json:"kid"`
	WrapKeyVersion int    `json:"wrap_key_version"`
}

// ---------------------------------------------------------------------------
// Session  POST /v1/nodes/{node_id}/sessions/{session_id}
// ---------------------------------------------------------------------------

// SSHSessionSetup is the payload of an ssh_session_setup SSE event.
type SSHSessionSetup struct {
	SessionID     string    `json:"session_id"`
	TargetHost    string    `json:"target_host"`
	TargetPort    int       `json:"target_port"`
	AuthorizedKey string    `json:"authorized_key"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// SessionActivityRequest is the one-of activity record a node posts to
// POST /v1/nodes/{node_id}/sessions/{session_id}. Exactly one member is set,
// selecting the session kind: SSH, K8s, or TCP.
type SessionActivityRequest struct {
	SSH *SSHActivity `json:"ssh,omitempty"`
	K8s *K8sActivity `json:"k8s,omitempty"`
	TCP *TCPActivity `json:"tcp,omitempty"`
}

// SSHActivity records a completed SSH session command. Command is the executed
// command line and is capped at 1 KiB. StartedAt and CompletedAt are RFC 3339
// timestamps.
type SSHActivity struct {
	Command     string     `json:"command"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// K8sActivity records a single Kubernetes API action proxied through the
// session. Verb is the API verb; the remaining fields describe the target
// object and the outcome.
type K8sActivity struct {
	Verb         string `json:"verb"`
	ResourceKind string `json:"resource_kind,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Name         string `json:"name,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
	DurationMS   int64  `json:"duration_ms,omitempty"`
}

// TCPActivity records a TCP session lifecycle event. Phase is one of the
// TCPPhase* values. BytesIn (operator to target) and BytesOut (target to
// operator) are pointers so a session_ended row carries explicit zeros while a
// session_started row omits the byte counters. TerminatedBy, when set, is one
// of the TerminatedBy* values.
type TCPActivity struct {
	Phase        string `json:"phase"`
	TargetHost   string `json:"target_host,omitempty"`
	TargetPort   int    `json:"target_port,omitempty"`
	BytesIn      *int64 `json:"bytes_in,omitempty"`
	BytesOut     *int64 `json:"bytes_out,omitempty"`
	TerminatedBy string `json:"terminated_by,omitempty"`
}

// TCP session lifecycle phases reported on a TCPActivity.
const (
	// TCPPhaseSessionStarted marks the opening of a TCP session.
	TCPPhaseSessionStarted = "session_started"
	// TCPPhaseSessionEnded marks the close of a TCP session.
	TCPPhaseSessionEnded = "session_ended"
)

// Reasons a TCP session was terminated, reported on a session_ended TCPActivity.
const (
	// TerminatedByTTLExpired means the session reached its time-to-live.
	TerminatedByTTLExpired = "ttl_expired"
	// TerminatedByIdleTimeout means the session was idle past its timeout.
	TerminatedByIdleTimeout = "idle_timeout"
	// TerminatedByPlexdClose means plexd closed the session locally.
	TerminatedByPlexdClose = "plexd_close"
	// TerminatedByOperatorRevoke means the operator's access was revoked.
	TerminatedByOperatorRevoke = "operator_revoke"
)

// ---------------------------------------------------------------------------
// Integrity  POST /v1/nodes/{node_id}/integrity/violations
// ---------------------------------------------------------------------------

// IntegrityViolationReport is sent when a file integrity check fails.
type IntegrityViolationReport struct {
	Type             string    `json:"type"`
	Path             string    `json:"path"`
	ExpectedChecksum string    `json:"expected_checksum"`
	ActualChecksum   string    `json:"actual_checksum"`
	Detail           string    `json:"detail"`
	Timestamp        time.Time `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Bridge Mode
// ---------------------------------------------------------------------------

// BridgeInfo is the bridge status reported by the node in heartbeats.
type BridgeInfo struct {
	Enabled                 bool   `json:"enabled"`
	AccessInterface         string `json:"access_interface"`
	ActiveRoutes            int    `json:"active_routes"`
	RelayEnabled            bool   `json:"relay_enabled"`
	ActiveRelaySessions     int    `json:"active_relay_sessions"`
	IngressEnabled          bool   `json:"ingress_enabled"`
	ActiveIngressRules      int    `json:"active_ingress_rules"`
	SiteToSiteEnabled       bool   `json:"site_to_site_enabled"`
	ActiveSiteToSiteTunnels int    `json:"active_site_to_site_tunnels"`
}

// RelayConfig is the relay configuration pushed from the control plane.
// It contains the list of relay session assignments for this bridge node.
type RelayConfig struct {
	Sessions []RelaySessionAssignment `json:"sessions"`
}

// RelaySessionAssignment represents a relay session assigned by the control plane.
type RelaySessionAssignment struct {
	SessionID     string    `json:"session_id"`
	PeerAID       string    `json:"peer_a_id"`
	PeerAEndpoint string    `json:"peer_a_endpoint"`
	PeerBID       string    `json:"peer_b_id"`
	PeerBEndpoint string    `json:"peer_b_endpoint"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// ---------------------------------------------------------------------------
// User Access
// ---------------------------------------------------------------------------

// UserAccessConfig is the user access configuration pushed from the control plane.
type UserAccessConfig struct {
	Enabled       bool             `json:"enabled"`
	InterfaceName string           `json:"interface_name"`
	ListenPort    int              `json:"listen_port"`
	Peers         []UserAccessPeer `json:"peers"`
}

// UserAccessPeer represents a user access peer (external VPN client).
type UserAccessPeer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	PSK        string   `json:"psk,omitempty"`
	Label      string   `json:"label"`
}

// UserAccessInfo is the user access status reported by the node in heartbeats.
type UserAccessInfo struct {
	Enabled        bool   `json:"enabled"`
	InterfaceName  string `json:"interface_name"`
	PeerCount      int    `json:"peer_count"`
	ListenPort     int    `json:"listen_port"`
	ProviderName   string `json:"provider_name,omitempty"`
	ProviderStatus string `json:"provider_status,omitempty"`
}

// ---------------------------------------------------------------------------
// Public Ingress
// ---------------------------------------------------------------------------

// IngressConfig is the ingress configuration pushed from the control plane.
type IngressConfig struct {
	Enabled bool          `json:"enabled"`
	Rules   []IngressRule `json:"rules"`
}

// IngressRule represents a single public ingress rule.
type IngressRule struct {
	RuleID     string `json:"rule_id"`
	ListenPort int    `json:"listen_port"`
	TargetAddr string `json:"target_addr"`
	// Mode is the TLS handling mode: "tcp" (passthrough), "terminate" (static cert),
	// or "acme" (automatic certificate via ACME).
	Mode     string `json:"mode"`
	CertPEM  string `json:"cert_pem,omitempty"`
	KeyPEM   string `json:"key_pem,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// IngressInfo is the ingress status reported by the node in heartbeats.
type IngressInfo struct {
	Enabled         bool `json:"enabled"`
	RuleCount       int  `json:"rule_count"`
	ConnectionCount int  `json:"connection_count"`
	ACMEEnabled     bool `json:"acme_enabled"`
}

// ---------------------------------------------------------------------------
// Site-to-Site VPN
// ---------------------------------------------------------------------------

// SiteToSiteConfig is the site-to-site VPN configuration pushed from the control plane.
type SiteToSiteConfig struct {
	Enabled bool               `json:"enabled"`
	Tunnels []SiteToSiteTunnel `json:"tunnels"`
}

// SiteToSiteTunnel represents a single site-to-site VPN tunnel definition.
type SiteToSiteTunnel struct {
	TunnelID        string   `json:"tunnel_id"`
	RemoteEndpoint  string   `json:"remote_endpoint"`
	RemotePublicKey string   `json:"remote_public_key"`
	LocalSubnets    []string `json:"local_subnets"`
	RemoteSubnets   []string `json:"remote_subnets"`
	PSK             string   `json:"psk,omitempty"`
	InterfaceName   string   `json:"interface_name"`
	ListenPort      int      `json:"listen_port"`
	// ProviderType specifies which tunnel provider to use for this tunnel.
	// Empty or "wireguard" means the default WireGuard-based approach.
	// Other values (e.g. "ipsec", "openvpn") delegate to the corresponding TunnelProvider.
	ProviderType string `json:"provider_type,omitempty"`
}

// SiteToSiteInfo is the site-to-site VPN status reported by the node in heartbeats.
type SiteToSiteInfo struct {
	Enabled             bool     `json:"enabled"`
	TunnelCount         int      `json:"tunnel_count"`
	TunnelProviderNames []string `json:"tunnel_provider_names,omitempty"`
}

// ---------------------------------------------------------------------------
// Local Endpoint Configuration (shared by metrics, logfwd, auditfwd)
// ---------------------------------------------------------------------------

// LocalEndpointConfig holds the configuration for a local data-plane endpoint
// that a pipeline can send data to in addition to the platform.
// A zero-valued LocalEndpointConfig means "not configured" and passes validation.
type LocalEndpointConfig struct {
	// URL is the HTTPS endpoint URL. Must use the https:// scheme when set.
	URL string `yaml:"url"`

	// SecretKey is the authentication credential for the local endpoint.
	// Required when URL is non-empty.
	SecretKey string `yaml:"secret_key"`

	// TLSInsecureSkipVerify disables TLS certificate verification.
	TLSInsecureSkipVerify bool `yaml:"tls_insecure_skip_verify"`
}

// Validate checks that the local endpoint configuration is well-formed.
// The prefix is prepended to error messages for context (e.g. "metrics").
func (c *LocalEndpointConfig) Validate(prefix string) error {
	if c.URL == "" {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s: config: local_endpoint: invalid URL %q", prefix, c.URL)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s: config: local_endpoint: URL must be HTTPS, got %q", prefix, u.Scheme)
	}
	if c.SecretKey == "" {
		return fmt.Errorf("%s: config: local_endpoint: SecretKey is required when URL is set", prefix)
	}
	return nil
}
