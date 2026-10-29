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

// Peer is the internal WireGuard programming shape built by peerFromSnapshot.
type Peer struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	MeshIP    string `json:"mesh_ip"`
	// Endpoint is the first entry of Endpoints, or empty when the peer has no
	// endpoint to dial.
	Endpoint string `json:"endpoint"`
	// Endpoints is the peer's dial order: the endpoints the WireGuard manager
	// tries one after another until a handshake completes.
	Endpoints []string `json:"endpoints,omitempty"`
	// Fallback is the peer's fallback_endpoint when that is the last entry of
	// Endpoints, and empty otherwise. Endpoint selection holds that entry as
	// long as the entries before it took together.
	Fallback   string   `json:"fallback,omitempty"`
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
// ten fields carry omitempty.
type NodeStateSnapshot struct {
	Peers        []SnapshotPeer       `json:"peers"`
	Reachability json.RawMessage      `json:"reachability"`
	Policy       *PolicySnapshot      `json:"policy"`
	Bridge       *BridgeSnapshot      `json:"bridge"`
	State        *NodeStateBlock      `json:"state"`
	Reports      *NodeStateBlock      `json:"reports"`
	Executions   []NodeStateExecution `json:"executions"`
	// Sessions is a pointer for the same reason the block fields above are: the
	// sessions block is desired state whose emptiness is destructive — an empty
	// block tears every live session down — so "the control plane says you have
	// no sessions" ([]) has to stay distinguishable from "the control plane did
	// not populate the block" (null, or a key a build predating the block never
	// wrote). A nil pointer is the second case and is not a teardown signal.
	Sessions *[]NodeStateSession `json:"sessions"`
	// Secrets is the node's secret inventory, ordered by name. It is a pointer
	// for the reason Sessions is: [] says the node may read nothing and empties
	// the node API's secret index, while a nil value, the wire's null or a key a
	// control plane predating the block never wrote, means the control plane did
	// not say this time, and the index is kept.
	Secrets *[]NodeStateSecret `json:"secrets"`
	// SigningKey is the key the node's Domain signs envelopes and session
	// tokens with. A nil value, the wire's null or a key a control plane
	// predating the block never wrote, means the control plane could not say
	// this time: the node keeps the key it holds, and never drops it.
	SigningKey *NodeStateSigningKey `json:"signing_key"`
}

// NodeStateSigningKey is the signing_key block of the state pull, the Domain
// signing key as the "Domain signing key" section of plexsphere's agent
// contract (docs/reference/api/plexd-agent-contract.md) describes it: the id
// the key signs under and its 32-byte Ed25519 public key in standard base64,
// the same encodings POST /v1/register uses.
type NodeStateSigningKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// NodeStateSecret is one entry of the secrets block of the state pull, a Secret
// the node may read as the "Secret inventory" section of plexsphere's agent
// contract (docs/reference/api/plexd-agent-contract.md) describes it: its name
// and current version, never its value, which the node fetches through
// GET /v1/nodes/{node_id}/secrets/{name}. The node API maps Name onto the key
// of its secret index (SecretRef.Key).
type NodeStateSecret struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// SnapshotPeer is a reconciliation peer entry in NodeStateSnapshot. It is a
// separate type from RegisterPeer (one Go type per contract schema) and carries
// the peer's direct endpoint but NO psk or allowed_ips: AllowedIPs are derived
// locally as mesh_ip/32, and the pairwise edge PSK is fetched per edge from
// GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk, never projected.
type SnapshotPeer struct {
	NodeID    string `json:"node_id"`
	MeshIP    string `json:"mesh_ip"`
	PublicKey string `json:"public_key"`
	// Endpoint is the peer's direct WireGuard endpoint as host:port (an IPv6
	// host in brackets), the address it last reported through PUT
	// /v1/nodes/{node_id}/endpoint. It is absent while the peer has no fresh
	// observation. FallbackEndpoint is the relay target, the last entry of the
	// dial order the WireGuard manager tries.
	Endpoint         string `json:"endpoint,omitempty"`
	FallbackEndpoint string `json:"fallback_endpoint,omitempty"`
	// EndpointCandidates are the peer's endpoint candidates as host:port
	// strings, at most MaxEndpointCandidates. The control plane lists first
	// the peer's peer-observed endpoints: each address and port at which at
	// least two live nodes of the Domain reported, through
	// POST /v1/nodes/{node_id}/handshakes, a direct handshake with the peer
	// within the Domain's endpoint TTL. The peer's last accepted, unexpired
	// local candidates (PUT /v1/nodes/{node_id}/endpoint-candidates) follow,
	// in the order the peer sent them. The wire does not mark which entry is
	// which, and plexd orders them alike. The field is absent when the peer
	// has none, and on every control plane that does not deliver them.
	EndpointCandidates []string `json:"endpoint_candidates,omitempty"`
}

// ReachabilitySnapshot is the interior of the snapshot's reachability block: the
// control plane's own verdict about this node, derived from the heartbeats it has
// admitted. It is a diagnostic projection, never desired state.
//
// State is a plain string and is never validated against the constants below.
// The verdict vocabulary belongs to the control plane and grows there —
// never_reported was added after plexd shipped — so a value this build does not
// know must keep flowing to the log rather than be rejected. LastHeartbeatAt is
// absent until the first heartbeat is accepted; ChangedAt is always present.
type ReachabilitySnapshot struct {
	State           string     `json:"state"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at,omitempty"`
	ChangedAt       time.Time  `json:"changed_at"`
}

// Reachability verdicts the platform contract documents today. The set is open:
// these are the values plexd expects to see, not the values it accepts.
const (
	// ReachabilityHealthy marks a node whose heartbeats arrive on schedule.
	ReachabilityHealthy = "healthy"
	// ReachabilityStale marks a node whose last admitted heartbeat is older than
	// the control plane's freshness window.
	ReachabilityStale = "stale"
	// ReachabilityUnreachable marks a node the control plane has given up on.
	ReachabilityUnreachable = "unreachable"
	// ReachabilityNeverReported marks a node whose first heartbeat was never
	// admitted. It is the verdict a freshly enrolled node is born with.
	ReachabilityNeverReported = "never_reported"
)

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

// SigningKeyRotation is the payload of the signing_key_rotated event: the new
// current signing key and, optionally, the previous key id kept valid until a
// transition deadline. Its shape is an author-approved assumption until the
// platform taxonomy documents it.
type SigningKeyRotation struct {
	KeyID             string    `json:"key_id"`
	PublicKey         string    `json:"public_key"`
	PreviousKeyID     string    `json:"previous_key_id"`
	TransitionExpires time.Time `json:"transition_expires"`
}

// SessionRevocation is the payload of the session_revoked event: the revoked
// session, the revoked token's jti (equal to the session id), and when and why
// the control plane revoked it. Its shape is the control plane's
// SSEEventSessionRevoked schema.
type SessionRevocation struct {
	SessionID    string    `json:"session_id"`
	JTI          string    `json:"jti"`
	RevokedAt    time.Time `json:"revoked_at"`
	RevokeReason string    `json:"revoke_reason"`
}

// SessionConnectRequest is the payload of the session_connect event: the ssh
// session a client attached to, the one-time id of the connection the node is
// asked to open for it, and the instant after which the control plane no
// longer accepts that connection. Its shape is the control plane's
// access.SessionConnectRequested event, whose event_id and occurred_at header
// members plexd does not read.
type SessionConnectRequest struct {
	SessionID    string    `json:"session_id"`
	ConnectionID string    `json:"connection_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Reasons the control plane revokes a session, carried on
// SessionRevocation.RevokeReason. The first four are operator-driven, supplied
// on the explicit revoke call; the last two are set by the control plane's
// sweeper when the session reaches its hard expiry or its idle timeout.
const (
	RevokeReasonOperatorRequest        = "operator_request"
	RevokeReasonPolicyViolation        = "policy_violation"
	RevokeReasonIdentityCompromise     = "identity_compromise"
	RevokeReasonResourceDecommissioned = "resource_decommissioned"
	RevokeReasonTTLExpired             = "ttl_expired"
	RevokeReasonIdleTimeout            = "idle_timeout"
)

type DataEntry struct {
	Key         string          `json:"key"`
	ContentType string          `json:"content_type"`
	Payload     json.RawMessage `json:"payload"`
	Version     int             `json:"version"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// SecretRef is one entry of the local node API's secret index, the list
// GET /v1/state/secrets serves. It is fed from the NodeStateSecret entries of
// the state pull, whose name becomes Key.
type SecretRef struct {
	Key     string `json:"key"`
	Version int    `json:"version"`
}

// ---------------------------------------------------------------------------
// Secrets  GET /v1/nodes/{node_id}/secrets/{key}
// ---------------------------------------------------------------------------

// SecretEnvelope is the raw AES-256-GCM envelope served by
// GET /v1/nodes/{id}/secrets/{name}: Data is <12-byte nonce> ||
// <ciphertext + 16-byte GCM tag>, Version and KID come from the
// X-Plexsphere-Secret-Version and X-Plexsphere-Secret-KID headers.
// It is parsed from headers and body, never from JSON.
type SecretEnvelope struct {
	Data    []byte
	Version int
	KID     string
}

// ---------------------------------------------------------------------------
// Edge PSK  GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk
// ---------------------------------------------------------------------------

// EdgePSKEnvelopeSize is the exact length of an edge-PSK envelope: the 12-byte
// AES-256-GCM nonce, the 32-byte PSK and the 16-byte GCM tag.
const EdgePSKEnvelopeSize = 60

// EdgePSKEnvelope is the pairwise WireGuard PSK for one edge as GET
// /v1/nodes/{id}/peers/{peer_node_id}/psk serves it, sealed under the calling
// node's NSK: Data is <12-byte nonce> || <32-byte PSK + 16-byte GCM tag>, KID
// and Epoch come from the X-Plexsphere-PSK-KID and X-Plexsphere-PSK-Epoch
// headers. Epoch is part of the envelope's additional authenticated data and
// is used verbatim to open it. Data is key material and is never logged.
type EdgePSKEnvelope struct {
	Data  []byte
	KID   string
	Epoch string
}

// ---------------------------------------------------------------------------
// Reports  PUT/DELETE /v1/nodes/{node_id}/state/reports/{key}
// ---------------------------------------------------------------------------

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

// NodeStateExecution is one pending action dispatch in the executions block of
// GET /v1/nodes/{node_id}/state. That block is the delivery channel for action
// dispatches: it is always present ([] when empty, never null) and ordered by
// RequestedAt, then ExecutionID. An entry keeps reappearing on every pull until
// its execution reaches a terminal status through the execution callback, so a
// consumer must tolerate re-observing the same ExecutionID.
//
// Type is one of the ActionKind* values; Status is ExecutionStatusPending,
// ExecutionStatusAck, or ExecutionStatusStarted. ExpiresAt is an absolute UTC
// deadline, not a relative timeout. Parameters is nullable: a JSON null decodes
// to a nil map. The entry carries no callback URL and no hook checksum.
//
// A parameter value is held as raw JSON, not decoded into any: the state
// response is decoded with a plain decoder, so a JSON number would land in an
// any as a float64 and every integer beyond 2^53 would reach the action
// rewritten. The raw form hands the value to the action exactly as the control
// plane sent it.
type NodeStateExecution struct {
	ExecutionID string                     `json:"execution_id"`
	Action      string                     `json:"action"`
	Type        string                     `json:"type"`
	Parameters  map[string]json.RawMessage `json:"parameters"`
	Status      string                     `json:"status"`
	RequestedAt time.Time                  `json:"requested_at"`
	ExpiresAt   time.Time                  `json:"expires_at"`
}

// The two legal values of a NodeStateExecution.Type.
const (
	// ActionKindBuiltin dispatches an action built into plexd.
	ActionKindBuiltin = "builtin"
	// ActionKindHook dispatches a hook registered by the node.
	ActionKindHook = "hook"
)

// Execution status observed only on the pull block.
const (
	// ExecutionStatusPending marks an execution the control plane has dispatched
	// and the node has not yet acknowledged. It appears in the executions block
	// of the node state snapshot and is never reported by a node on the
	// execution callback.
	ExecutionStatusPending = "pending"
)

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
// Sessions  GET /v1/nodes/{node_id}/state
// ---------------------------------------------------------------------------

// NodeStateSession is one live mediated-access session in the sessions block of
// GET /v1/nodes/{node_id}/state. That block is desired state, not a queue: it
// is always present on the wire ([] when empty, never null). An entry appears
// when the control plane issues the session and disappears on revocation or
// hard expiry — the disappearance is the teardown signal, there is no separate
// teardown event. A response that violates the contract by omitting or nulling
// the block decodes to a nil NodeStateSnapshot.Sessions and is not read as an
// empty block.
//
// Kind is one of the SessionKind* values and selects which member of Target is
// set. JTI equals the session id: it is carried as an opaque value and never
// evaluated. ExpiresAt is an absolute UTC timestamp, not a relative timeout.
// IdleTimeoutSeconds 0 or absent means the session has no idle window.
type NodeStateSession struct {
	SessionID          string        `json:"session_id"`
	JTI                string        `json:"jti"`
	Kind               string        `json:"kind"`
	Target             SessionTarget `json:"target"`
	ExpiresAt          time.Time     `json:"expires_at"`
	IdleTimeoutSeconds int           `json:"idle_timeout_seconds,omitempty"`
}

// SessionTarget is the target of a NodeStateSession. Exactly one member is set,
// selecting the session kind: SSH, K8s, or TCP.
type SessionTarget struct {
	SSH *SessionTargetSSH `json:"ssh,omitempty"`
	K8s *SessionTargetK8s `json:"k8s,omitempty"`
	TCP *SessionTargetTCP `json:"tcp,omitempty"`
}

// SessionTargetSSH is the target of an ssh session. User is the local account
// the session logs in as; AllowedCommands, when set, is the closed set of
// command lines the session may run.
type SessionTargetSSH struct {
	User            string   `json:"user"`
	AllowedCommands []string `json:"allowed_commands,omitempty"`
}

// SessionTargetK8s is the target of a k8s session. User is the impersonated
// Kubernetes user; ImpersonateGroups are the groups impersonated alongside it.
type SessionTargetK8s struct {
	User              string   `json:"user"`
	ImpersonateGroups []string `json:"impersonate_groups,omitempty"`
}

// SessionTargetTCP is the target of a tcp session: the host and port the node
// forwards the session's connections to.
type SessionTargetTCP struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// The three legal values of a NodeStateSession.Kind.
const (
	// SessionKindSSH mediates an SSH session; Target.SSH is set.
	SessionKindSSH = "ssh"
	// SessionKindK8s mediates a Kubernetes API session; Target.K8s is set.
	SessionKindK8s = "k8s"
	// SessionKindTCP mediates a plain TCP forward; Target.TCP is set.
	SessionKindTCP = "tcp"
)

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

// CapabilityManifestRequest is the body of PUT /v1/nodes/{node_id}/capabilities:
// the agent's binary version and digest, the hooks it advertises, and two
// inventories of what it can run: the builtin actions it implements and the
// PlexdHook resources it discovered in its cluster.
//
// The handler decodes it with DisallowUnknownFields, so this struct carries the
// contract's fields and nothing else. A manifest is refused whole, so one
// inventory entry that breaks an invariant (422) costs the binary version and
// checksum with it. The agent therefore sends only entries the contract
// accepts: at most 128 per inventory, unique names, at most 64 parameters per
// action, and a canonical image digest on every PlexdHook.
type CapabilityManifestRequest struct {
	// BinaryVersion is the agent version string, non-empty after trimming.
	BinaryVersion string `json:"binary_version"`
	// BinaryChecksum is the running binary's SHA-256 as 32 raw bytes in
	// standard-padded base64 (see integrity.WireChecksum). Anything that does
	// not decode to exactly 32 bytes is refused with 400
	// binary_checksum_invalid.
	BinaryChecksum string `json:"binary_checksum"`
	// SSHHostKeyFingerprint is the optional OpenSSH host-key fingerprint in the
	// canonical `SHA256:<base64>` form. Omitted when the agent has none.
	SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint,omitempty"`
	// DeclaredHooks are the hooks the agent advertises, at most 128, with
	// unique names. Omitted when empty rather than sent as null.
	DeclaredHooks []DeclaredHook `json:"declared_hooks,omitempty"`
	// PlexdHooks are the PlexdHook resources the agent discovered in its
	// ServiceAccount's namespace at boot, at most 128, with unique names.
	// Omitted when the agent runs outside a cluster or found nothing it can
	// report, rather than sent as null.
	PlexdHooks []DiscoveredPlexdHook `json:"plexd_hooks,omitempty"`
	// BuiltinActions is the inventory of builtin actions the agent implements,
	// sorted by name, each with its parameters in registration order. Omitted
	// when empty rather than sent as null.
	BuiltinActions []ActionInfo `json:"builtin_actions,omitempty"`
}

// DeclaredHook pairs a hook name with the digest of its payload, so the
// integrity correlator can see a hook change without re-fetching it.
type DeclaredHook struct {
	Name string `json:"name"`
	// Checksum is the hook payload's SHA-256 as 32 raw bytes in
	// standard-padded base64, same encoding as BinaryChecksum.
	Checksum string `json:"checksum"`
}

// DiscoveredPlexdHook is one PlexdHook resource as the manifest reports it (the
// contract's PlexdHook schema). It identifies the hook by its image digest
// rather than a payload checksum, so only a digest-pinned image can be
// reported.
type DiscoveredPlexdHook struct {
	// Name is the resource name, unique within the namespace it was listed in.
	Name string `json:"name"`
	// ImageDigest is the hook image's digest in canonical
	// `sha256:<64 lowercase hex>` form.
	ImageDigest string `json:"image_digest"`
	// Parameters is the spec's name/value list folded into a map.
	Parameters map[string]string `json:"parameters,omitempty"`
	// TimeoutSeconds is the execution timeout. The CRD has no timeout field,
	// so the agent never sets it and the key stays off the wire.
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`
	// Sandbox reports that the hook runs sandboxed: a read-only root
	// filesystem with every capability dropped, which is how the controller
	// runs any hook that is not privileged.
	Sandbox bool `json:"sandbox,omitempty"`
}

// BinaryInfo describes the running agent binary. It is reported through the
// node API's local surface; the control plane receives the same two values as
// the flat binary_version / binary_checksum fields of a capability manifest.
type BinaryInfo struct {
	Version  string `json:"version"`
	Checksum string `json:"checksum"`
}

type ActionInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Parameters  []ActionParam `json:"parameters,omitempty"`
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
	Endpoint string `json:"endpoint"`
	NATType  string `json:"nat_type"`
	// PortMapping is "preserved" or "translated": whether the NAT kept the
	// STUN probe's source port, and so whether Endpoint was observed or
	// assumed. Omitted when empty. A control plane that predates the member
	// refuses it with 400 malformed_endpoint_request.
	PortMapping string    `json:"port_mapping,omitempty"`
	ReportedAt  time.Time `json:"reported_at"`
}

type EndpointResponse struct {
	AcceptedAt time.Time `json:"accepted_at"`
	StaleAfter time.Time `json:"stale_after"`
}

// ---------------------------------------------------------------------------
// Endpoint Candidates  PUT /v1/nodes/{node_id}/endpoint-candidates
// ---------------------------------------------------------------------------

// MaxEndpointCandidates is the contract's ceiling on one candidate report.
const MaxEndpointCandidates = 8

// EndpointCandidatesRequest is the body of
// PUT /v1/nodes/{node_id}/endpoint-candidates: the node's local interface
// addresses joined with its WireGuard listen port. Each report replaces the
// previous set, so an empty Candidates withdraws every earlier candidate.
type EndpointCandidatesRequest struct {
	// Candidates holds 0 to MaxEndpointCandidates distinct host:port strings,
	// an IPv6 host in brackets and without a zone. A null array is refused,
	// so ReportEndpointCandidates sends nil as [].
	Candidates []string `json:"candidates"` // never null on the wire
	// ReportedAt must lie within 60 seconds of server time, or the report is
	// refused with 400 endpoint_clock_skew.
	ReportedAt time.Time `json:"reported_at"`
}

// EndpointCandidatesResponse is the 200 body of
// PUT /v1/nodes/{node_id}/endpoint-candidates.
type EndpointCandidatesResponse struct {
	AcceptedAt time.Time `json:"accepted_at"`
	// StaleAfter is the deadline after which the control plane drops the set.
	StaleAfter time.Time `json:"stale_after"`
}

// ---------------------------------------------------------------------------
// Handshakes  POST /v1/nodes/{node_id}/handshakes
// ---------------------------------------------------------------------------

// MaxHandshakeReportPeers is the contract's ceiling on the peers array of one
// handshake report. A longer array is refused whole with 400
// malformed_handshake_report, taking every edge in it down, so ReportHandshakes
// refuses one before sending it.
const MaxHandshakeReportPeers = 4096

// HandshakeReportRequest is the body of POST /v1/nodes/{node_id}/handshakes:
// for each mesh peer the node has completed a WireGuard handshake with, the age
// of the latest handshake and the endpoint WireGuard used for it.
//
// The control plane anchors every age on its own receive time, so a body is
// only true for the attempt it was assembled for. The agent builds a fresh one,
// with a fresh ObservedAt and fresh ages, for every attempt and never replays
// one: a replayed age would make the handshake look newer than it was. The
// handler decodes with DisallowUnknownFields, so the struct carries the
// contract's fields and nothing else.
type HandshakeReportRequest struct {
	// ObservedAt is the agent's wall clock when it assembled the report. It
	// gates the request only: a value more than 60 seconds from server time is
	// refused with 400 handshake_clock_skew.
	ObservedAt time.Time `json:"observed_at"`
	// Peers carries at most MaxHandshakeReportPeers entries and omits a peer
	// with no handshake yet. An empty array is a valid report that records
	// nothing; a null one is refused, so ReportHandshakes sends nil as [].
	Peers []HandshakeReportPeer `json:"peers"` // never null on the wire
}

// HandshakeReportPeer is one entry of a HandshakeReportRequest.
//
// No field is omitempty: all three are required, and an age of 0 (a handshake
// within the last second) is as legitimate as any other, so it must reach the
// wire rather than be dropped as a zero value and refused as missing.
type HandshakeReportPeer struct {
	// PeerNodeID is the peer's node_id, a non-zero UUID that no other entry of
	// the report repeats. An id the control plane does not know as a live peer
	// of the node's Domain is counted as ignored rather than refused.
	PeerNodeID string `json:"peer_node_id"`
	// LastHandshakeAgeSeconds is the whole seconds between the latest completed
	// handshake and ObservedAt, in 0..2147483647 (the contract's int32).
	LastHandshakeAgeSeconds int32 `json:"last_handshake_age_seconds"`
	// Endpoint is the address WireGuard uses for the peer as host:port, with an
	// IPv6 host in brackets ([2001:db8::7]:51820). A port of 0, an unspecified
	// address or an IPv6 zone is refused with 400
	// handshake_endpoint_unparseable, for the whole report.
	Endpoint string `json:"endpoint"`
}

// HandshakeReportResponse is the 200 body of
// POST /v1/nodes/{node_id}/handshakes.
type HandshakeReportResponse struct {
	// AcceptedAt is the server receive time every age was anchored on.
	AcceptedAt time.Time `json:"accepted_at"`
	// Recorded counts the entries stored as the latest observation of their
	// directed edge.
	Recorded int `json:"recorded"`
	// Ignored counts the entries naming the node itself, an unknown node, a
	// node of another Domain or a deregistered peer.
	Ignored int `json:"ignored"`
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

// SessionActivityRequest is the one-of activity record a node posts to
// POST /v1/nodes/{node_id}/sessions/{session_id}. Exactly one member is set,
// selecting the session kind: SSH, K8s, or TCP.
type SessionActivityRequest struct {
	SSH *SSHActivity `json:"ssh,omitempty"`
	K8s *K8sActivity `json:"k8s,omitempty"`
	TCP *TCPActivity `json:"tcp,omitempty"`
}

// SSHActivity records one row of an SSH session. It takes one of two shapes.
//
// A command row carries Command, the command line of an exec request, capped
// at 1 KiB, optionally with ExitCode, StartedAt and CompletedAt (RFC 3339
// timestamps). plexd posts it twice per command: once with StartedAt before
// the command runs, and once with ExitCode and CompletedAt after it exited.
//
// A lifecycle row carries Phase, one of the SSHPhase* values, plus
// TerminatedBy (one of the TerminatedBy* values) on session_ended, and no
// command fields. An ssh session binds no listener, so plexd sends no
// ListenerEndpoint; the field stays for the session_started rows older agents
// post with one, which the control plane still admits.
//
// plexd never posts an empty Command; the control plane refuses a row that
// mixes the two shapes.
type SSHActivity struct {
	Command          string     `json:"command,omitempty"`
	ExitCode         *int       `json:"exit_code,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	Phase            string     `json:"phase,omitempty"`
	ListenerEndpoint string     `json:"listener_endpoint,omitempty"`
	TerminatedBy     string     `json:"terminated_by,omitempty"`
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
// TCPPhase* values. ListenerEndpoint is the node's bound listener address and
// is set only on session_started rows. BytesIn (operator to target) and
// BytesOut (target to operator) are pointers so a session_ended row carries
// explicit zeros while a session_started row omits the byte counters.
// TerminatedBy, when set, is one of the TerminatedBy* values. A session_active
// row carries Phase alone.
type TCPActivity struct {
	Phase            string `json:"phase"`
	TargetHost       string `json:"target_host,omitempty"`
	TargetPort       int    `json:"target_port,omitempty"`
	ListenerEndpoint string `json:"listener_endpoint,omitempty"`
	BytesIn          *int64 `json:"bytes_in,omitempty"`
	BytesOut         *int64 `json:"bytes_out,omitempty"`
	TerminatedBy     string `json:"terminated_by,omitempty"`
}

// TCP session lifecycle phases reported on a TCPActivity.
const (
	// TCPPhaseSessionStarted marks the opening of a TCP session.
	TCPPhaseSessionStarted = "session_started"
	// TCPPhaseSessionActive reports that a TCP session forwarded bytes since its
	// previous session_active row. The row carries Phase alone.
	TCPPhaseSessionActive = "session_active"
	// TCPPhaseSessionEnded marks the close of a TCP session.
	TCPPhaseSessionEnded = "session_ended"
)

// SSH session lifecycle phases reported on an SSHActivity.
const (
	// SSHPhaseSessionStarted marks an SSH session ready to serve the
	// connections the control plane asks for.
	SSHPhaseSessionStarted = "session_started"
	// SSHPhaseSessionEnded marks the close of an SSH session.
	SSHPhaseSessionEnded = "session_ended"
)

// Reasons a TCP or SSH session was terminated, reported on a session_ended
// TCPActivity or SSHActivity.
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
// Integrity  POST /v1/nodes/{node_id}/integrity-violations
// ---------------------------------------------------------------------------

// IntegrityViolationKind is the artifact class a violation applies to. The
// control plane canonicalises every entry through a value-object constructor
// that refuses anything outside this set with 400
// integrity_violation_kind_invalid, so the type exists to keep an unchecked
// string from reaching the wire in the first place.
type IntegrityViolationKind string

const (
	// IntegrityKindBinaryChecksum reports the agent's own binary.
	IntegrityKindBinaryChecksum IntegrityViolationKind = "binary_checksum"
	// IntegrityKindHookChecksum reports a hook script.
	IntegrityKindHookChecksum IntegrityViolationKind = "hook_checksum"
	// IntegrityKindSSHHostKey reports the mesh SSH host key.
	IntegrityKindSSHHostKey IntegrityViolationKind = "ssh_host_key"
)

// IntegrityDetector is the on-node detector that surfaced a violation. Like
// IntegrityViolationKind the set is closed; a value outside it is refused with
// 400 integrity_violation_detected_by_invalid.
type IntegrityDetector string

const (
	// IntegrityDetectorStartupScan is the agent's own sweep of the artifacts it
	// holds baselines for. The contract has no value for a periodic re-scan, so
	// the interval-driven sweep reports this one too.
	IntegrityDetectorStartupScan IntegrityDetector = "startup_scan"
	// IntegrityDetectorInotify is the hooks-directory watcher reacting to a
	// filesystem event.
	IntegrityDetectorInotify IntegrityDetector = "inotify"
	// IntegrityDetectorPreDispatch is the check that runs immediately before a
	// hook executes.
	IntegrityDetectorPreDispatch IntegrityDetector = "pre_dispatch"
)

// MaxIntegrityViolationsPerBatch is the contract's per-request ceiling on the
// violations array. A larger batch is refused whole with 400
// integrity_violations_too_many, and an empty one with
// integrity_violations_empty.
const MaxIntegrityViolationsPerBatch = 128

// IntegrityViolationsRequest is the body of
// POST /v1/nodes/{node_id}/integrity-violations: a batch of the tamper-evidence
// divergences the agent detected locally. The endpoint takes a batch even when
// the agent has a single violation to report, so a lone finding travels as a
// one-entry array rather than as a bare object.
type IntegrityViolationsRequest struct {
	// Violations carries between 1 and MaxIntegrityViolationsPerBatch entries.
	Violations []IntegrityViolationReport `json:"violations"`
}

// IntegrityViolationReport is one entry of an IntegrityViolationsRequest.
//
// The handler decodes the envelope with DisallowUnknownFields, so this struct
// carries the contract's fields and nothing else — in particular there is no
// timestamp (the control plane stamps its own) and no free-text detail field.
//
// Kind decides which digest pair is legal. A binary_checksum or hook_checksum
// entry carries the checksums and no fingerprint; an ssh_host_key entry carries
// the fingerprints and no checksum. Crossing them is refused with 400
// integrity_violation_kind_mismatch, which is why the four digest fields are
// omitempty: an unset one must be absent from the JSON, not present and empty.
type IntegrityViolationReport struct {
	Kind       IntegrityViolationKind `json:"kind"`
	DetectedBy IntegrityDetector      `json:"detected_by"`
	// ArtifactID identifies the affected artifact — a hook path, the binary
	// path, or the host-key file. Non-empty after trimming, at most 4096 bytes.
	ArtifactID string `json:"artifact_id"`
	// ObservedChecksum is the SHA-256 the agent computed, as 32 raw bytes in
	// standard-padded base64 (see integrity.WireChecksum). Required for the
	// checksum kinds; anything that does not decode to exactly 32 bytes is
	// refused with 400 integrity_violation_checksum_invalid.
	ObservedChecksum string `json:"observed_checksum,omitempty"`
	// ExpectedChecksum is the baseline digest, same encoding as
	// ObservedChecksum.
	ExpectedChecksum string `json:"expected_checksum,omitempty"`
	// ObservedFingerprint is the OpenSSH host-key fingerprint the agent
	// observed, in the canonical `SHA256:<base64>` form. Required for the
	// ssh_host_key kind.
	ObservedFingerprint string `json:"observed_fingerprint,omitempty"`
	// ExpectedFingerprint is the baseline fingerprint, same form as
	// ObservedFingerprint.
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
}

// IntegrityViolationsResponse is the 200 body of
// POST /v1/nodes/{node_id}/integrity-violations. The work is synchronous — every
// row and the integrity_alert outbox event are committed before the response is
// written — so the status is 200 rather than 202.
type IntegrityViolationsResponse struct {
	// AcceptedAt is the server-side commit timestamp.
	AcceptedAt time.Time `json:"accepted_at"`
	// ViolationCount echoes the number of rows persisted, matching the length
	// of the violations array on input.
	ViolationCount int `json:"violation_count"`
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

// RelayConfig is the bridge.relay block of the state pull, the control
// plane's NodeStateBridgeRelay. When Enabled is true and local consent
// (bridge.relay_enabled) allows it, the bridge relays WireGuard on UDP
// ListenPort among the peers the same pull lists. Assignments is carried as
// the control plane sends it, and the relay does not read it.
type RelayConfig struct {
	Enabled     bool              `json:"enabled"`
	ListenPort  int               `json:"listen_port"`
	Assignments []RelayAssignment `json:"assignments"`
}

// RelayAssignment is one entry of RelayConfig.Assignments: a peer whose
// fallback names this bridge, and the fallback that peer dials.
type RelayAssignment struct {
	PeerNodeID           string `json:"peer_node_id"`
	FallbackEndpoint     string `json:"fallback_endpoint"`
	FallbackEndpointPort int    `json:"fallback_endpoint_port"`
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
