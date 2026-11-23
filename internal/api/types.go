package api

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"slices"
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
	// Fallbacks is the peer's relay set as it ends Endpoints, in dial order:
	// the relay of its assigned bridge first, then its standby relays, and nil
	// when the peer has no relay. Endpoint selection holds each relay as long
	// as the entries before the first one took together, and only a peer that
	// connected over a relay dials the standbys.
	Fallbacks []string `json:"fallbacks,omitempty"`
	// AllowedIPs is the peer's mesh address as a /32 followed by
	// RoutedSubnets.
	AllowedIPs []string `json:"allowed_ips"`
	PSK        string   `json:"psk"`
	// RoutedSubnets are the subnets of the peer's routed_subnets this node
	// accepted that are no shared subnet, in the list's order, followed by
	// the shared subnets the peer holds, sorted by address and then by
	// prefix length, and nil when there are none. The WireGuard manager
	// routes each of them through the mesh interface.
	RoutedSubnets []string `json:"routed_subnets,omitempty"`
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
// fourteen fields carry omitempty.
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
	// Hooks is the node's desired set of published hook versions, ordered by
	// name. It is a pointer for the reason Secrets is: [] says the node should
	// run no rolled-out hook and removes every one it installed, while a nil
	// value, the wire's null or a key a control plane predating the block
	// never wrote, means the control plane could not compute the set this
	// time, and every rolled-out hook is kept.
	Hooks *[]NodeStateHook `json:"hooks"`
	// DNS is the mesh DNS names of the node's Domain. A block is the full set,
	// never a delta: it replaces the names the node answers. A nil value, the
	// wire's null or a key a control plane predating the block never wrote,
	// means the control plane did not say this time, and the node keeps the
	// names it holds.
	DNS *NodeStateDNS `json:"dns"`
	// FailureDetection is the Domain's failure-detection time, a
	// NodeStateFailureDetection. It is carried raw, as Reachability is, so
	// its consumer decodes it leniently and a malformed tuning value never
	// fails the pull that carries the peers and the policy. A nil value, the
	// wire's null or a key a control plane predating the block never wrote,
	// means the control plane did not say this time, and the node keeps the
	// value it holds.
	FailureDetection json.RawMessage `json:"failure_detection"`
	// SharedSubnets is the order of the bridges each shared site subnet of
	// the node's Project may be routed through, one entry per subnet. A nil
	// value, the wire's null or a key a control plane predating the block
	// never wrote, and [] all mean no shared subnet: only such a control
	// plane leaves the key out, and it has none. The member is typed, as
	// Peers is, so a value of another JSON type fails the pull's decode; the
	// WireGuard manager validates the entries.
	SharedSubnets []NodeStateSharedSubnet `json:"shared_subnets"`
}

// MaxSharedSubnetBridges is the contract's ceiling on the bridges of one
// shared_subnets entry: a carrier and up to seven standbys.
const MaxSharedSubnetBridges = 8

// NodeStateSharedSubnet is one entry of the shared_subnets block of the state
// pull, as the "Shared site subnets" section of plexsphere's agent contract
// (docs/reference/api/plexd-agent-contract.md) describes it. Subnet is a CIDR.
// Bridges are node IDs, each the node_id of a peer of the same pull: the
// carrier first, then the standbys in the order the node fails over through.
// The carrier's peer entry lists the subnet in its routed_subnets as well.
type NodeStateSharedSubnet struct {
	Subnet  string   `json:"subnet"`
	Bridges []string `json:"bridges"`
}

// NodeStateFailureDetection is the failure_detection block of the state pull,
// as the "Failure detection" section of plexsphere's agent contract
// (docs/reference/api/plexd-agent-contract.md) describes it.
// DetectAfterSeconds is how long a path the node watches on its own, today a
// relay, may stay silent before the node moves: a whole number of seconds
// from 5 to 180, and 15 for a Domain that never set it. It is int64 rather
// than int so a value out of range decodes on 32-bit builds too, and is
// clamped rather than refused as malformed.
type NodeStateFailureDetection struct {
	DetectAfterSeconds int64 `json:"detect_after_seconds"`
}

// NodeStateDNS is the dns block of the state pull, as the "Mesh DNS names"
// section of plexsphere's agent contract (docs/reference/api/plexd-agent-contract.md)
// describes it. SearchDomain is the zone of the node's own Project. Zones are
// the Domain's default domain and every Project zone, ascending. Hosts are
// every node of the Domain, the pulling node included, ordered by FQDN.
// Records are the DNS records of the Domain and of every Project, ordered by
// FQDN, then by type. A nil Records, the wire's null or a key a control plane
// predating records never wrote, means the Domain has no records: the block
// is the full set, so it is no signal to keep the records held.
// ReverseZones are the in-addr.arpa or ip6.arpa zones that cover the Domain's
// mesh CIDR and nothing wider. Forwarding is the DNS forwarding setting that
// applies to the pulling node. The control plane sends every name in lower
// case without a trailing dot, and an empty list as [].
type NodeStateDNS struct {
	SearchDomain string               `json:"search_domain"`
	Zones        []string             `json:"zones"`
	Hosts        []NodeStateDNSHost   `json:"hosts"`
	Records      []NodeStateDNSRecord `json:"records"`
	ReverseZones []string             `json:"reverse_zones"`
	// Forwarding is a pointer because the member is the full setting and its
	// absence says something else: a nil value, the wire's null or a key a
	// control plane predating forwarding never wrote, means the control plane
	// did not say this time, and the node keeps the forwarding it holds. Two
	// empty lists say the node forwards nothing. omitempty lets the mock
	// control plane, which marshals this type, serve a block without it.
	Forwarding *NodeStateDNSForwarding `json:"forwarding,omitempty"`
}

// NodeStateDNSForwarding is the forwarding member of the dns block, as the
// "Mesh DNS names" section of plexsphere's agent contract describes it: the
// Project's setting when the node's Project holds one, otherwise its Domain's,
// otherwise two empty lists. ForwardZones are ascending by zone, each with 1
// to 3 resolvers. CatchAll holds 0 to 3 resolvers, which answer every name
// outside the mesh zones, the reverse zones and the forward zones. A resolver
// is an IPv4 or IPv6 address in text form, asked in list order on port 53
// over plain DNS. A nil list, the wire's null or a missing key, is an empty
// one.
type NodeStateDNSForwarding struct {
	ForwardZones []NodeStateDNSForwardZone `json:"forward_zones"`
	CatchAll     []string                  `json:"catch_all"`
}

// NodeStateDNSForwardZone is one entry of the forwarding member's
// forward_zones, as the "Mesh DNS names" section of plexsphere's agent
// contract describes it: a zone outside the mesh and the resolvers that answer
// the names under it, in the order they are asked.
type NodeStateDNSForwardZone struct {
	Zone      string   `json:"zone"`
	Resolvers []string `json:"resolvers"`
}

// NodeStateDNSHost is one entry of the dns block's hosts, as the "Mesh DNS
// names" section of plexsphere's agent contract describes it: a node of the
// Domain, its fully qualified name, and its mesh IP, IPv4 or IPv6 by the family
// of the Domain's mesh CIDR.
type NodeStateDNSHost struct {
	NodeID string `json:"node_id"`
	FQDN   string `json:"fqdn"`
	MeshIP string `json:"mesh_ip"`
}

// NodeStateDNSRecord is one entry of the dns block's records, as the "Mesh DNS
// names" section of plexsphere's agent contract describes it: a record's fully
// qualified name, its type (A, AAAA, CNAME, TXT, SRV or MX) and the data
// members of that type, and no other member. Address belongs to A and AAAA,
// Target to CNAME, SRV and MX, Priority to SRV and MX (the preference of an
// MX), Weight and Port to SRV, and Text to TXT.
//
// The numbers are pointers because the contract sends a priority or a weight
// of 0 as 0 and leaves out every member a type does not take, which the mock
// control plane marshals this type for. They are int rather than uint16, so a
// number out of range costs the one record it belongs to, which the resolver
// skips, rather than the decode of the whole snapshot.
type NodeStateDNSRecord struct {
	FQDN     string   `json:"fqdn"`
	Type     string   `json:"type"`
	Address  string   `json:"address,omitempty"`
	Target   string   `json:"target,omitempty"`
	Priority *int     `json:"priority,omitempty"`
	Weight   *int     `json:"weight,omitempty"`
	Port     *int     `json:"port,omitempty"`
	Text     []string `json:"text,omitempty"`
}

// NodeStateHook is one entry of the hooks block of the state pull, a published
// hook version a rollout assigns the node, as the "Published hooks" section of
// plexsphere's agent contract (docs/reference/api/plexd-agent-contract.md)
// describes it. It never carries the script, which the node fetches through
// GET /v1/nodes/{node_id}/hooks/{name}/versions/{version}. Checksum is the
// SHA-256 of that script as 32 raw bytes in standard-padded base64, the
// encoding of a DeclaredHook's Checksum, so the fetched version is checked
// against the digest the pull named.
type NodeStateHook struct {
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Checksum string `json:"checksum"`
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
// locally as mesh_ip/32 followed by the entries of RoutedSubnets the node
// accepts, and the pairwise edge PSK is fetched per edge from
// GET /v1/nodes/{node_id}/peers/{peer_node_id}/psk, never projected.
type SnapshotPeer struct {
	NodeID    string `json:"node_id"`
	MeshIP    string `json:"mesh_ip"`
	PublicKey string `json:"public_key"`
	// Endpoint is the peer's direct WireGuard endpoint as host:port (an IPv6
	// host in brackets), the address it last reported through PUT
	// /v1/nodes/{node_id}/endpoint. It is absent while the peer has no fresh
	// observation.
	//
	// FallbackEndpoints is the peer's relays as host:port in dial order, at
	// most 4 by the contract: the relay of the peer's assigned bridge first,
	// then its standby relays. They end the dial order the WireGuard manager
	// tries. FallbackEndpoint is the first entry, and the only relay a
	// control plane that predates the set sends. Both are absent while the
	// peer has no relay, and the list never names this node.
	Endpoint          string   `json:"endpoint,omitempty"`
	FallbackEndpoint  string   `json:"fallback_endpoint,omitempty"`
	FallbackEndpoints []string `json:"fallback_endpoints,omitempty"`
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
	// RoutedSubnets are the IPv4 networks the control plane routes through
	// the peer as CIDRs: the networks behind the site-to-site tunnels of a
	// peer that is a bridge. A node adds the ones it accepts to the peer's
	// allowed IPs and routes them through the mesh interface, except a
	// subnet the pull's shared_subnets names, which the node takes from
	// that block and routes through one of its bridges. The field is
	// absent for a peer that routes no network, and the registration
	// response never carries it.
	RoutedSubnets []string `json:"routed_subnets,omitempty"`
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

// PolicySnapshot is the single merged policy block. Every rule is an allow and
// rule order carries no meaning: traffic no rule allows is dropped. Fingerprint
// is a 44-char base64 SHA-256 over the server's canonical rule byte stream;
// plexd treats it as an opaque comparison key and never re-derives it from
// Rules.
type PolicySnapshot struct {
	RevisionID  string       `json:"revision_id"`
	Fingerprint string       `json:"fingerprint"`
	Rules       []PolicyRule `json:"rules"`
	// Revisions names the (Policy, revision) pair of every compiled row the
	// block merges, in ascending policy_id, the order Fingerprint covers. A
	// control plane before plexsphere/plexsphere#1059 sends none. plexd echoes
	// the pairs in its policy status report and never parses them.
	Revisions []PolicyRevisionRef `json:"revisions,omitempty"`
}

// PolicyRevisionRef names one revision of one Policy. Both ids are UUIDs that
// plexd passes through as strings.
type PolicyRevisionRef struct {
	PolicyID   string `json:"policy_id"`
	RevisionID string `json:"revision_id"`
}

// Clone returns a deep copy of p: its Rules, each rule's Ports and
// LegacyAction, and its Revisions share no memory with p. A nil p yields nil.
func (p *PolicySnapshot) Clone() *PolicySnapshot {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Rules = slices.Clone(p.Rules)
	for i := range cp.Rules {
		if p.Rules[i].Ports != nil {
			ports := *p.Rules[i].Ports
			cp.Rules[i].Ports = &ports
		}
		if p.Rules[i].LegacyAction != nil {
			action := *p.Rules[i].LegacyAction
			cp.Rules[i].LegacyAction = &action
		}
	}
	cp.Revisions = slices.Clone(p.Revisions)
	return &cp
}

// PolicyRule allows the traffic from SourceCIDR to DestinationCIDR that its
// protocol and port range match. Both prefixes are IPv4 or both IPv6. Ports is
// present iff Protocol is tcp or udp and is absent for icmp/any. Log asks for
// the rule's traffic to be logged.
type PolicyRule struct {
	Protocol        string     `json:"protocol"`
	SourceCIDR      string     `json:"source_cidr"`
	DestinationCIDR string     `json:"destination_cidr"`
	Ports           *PortRange `json:"ports,omitempty"`
	Log             bool       `json:"log,omitempty"`
	// LegacyAction is the action key of the format before
	// plexsphere/plexsphere#1058; nil when the key is absent. The engine reads
	// a rule carrying "allow" as an allow and rejects any other value, so a
	// control plane that still sends deny rules cannot have them enforced as
	// allows.
	LegacyAction *string `json:"action,omitempty"`
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
// Hook versions  GET /v1/nodes/{node_id}/hooks/{name}/versions/{version}
// ---------------------------------------------------------------------------

// HookVersionEnvelopeType is the type of the envelope a published hook version
// is signed in. The envelope is not an event and never rides the event stream,
// so the type sits here rather than among the SSE event types.
const HookVersionEnvelopeType = "hook_version"

// NodeHookVersion is the 200 body of the hook version fetch: the signed
// envelope that describes one published hook version, and the script itself in
// standard base64. The script sits outside the
// envelope, so the signature covers its checksum in the payload rather than
// its bytes. Nothing here is verified on decode: the envelope's payload
// decodes into HookVersionPayload, and the installer checks the signature,
// the pair it fetched, and the script's digest before it writes anything.
type NodeHookVersion struct {
	Envelope     Envelope `json:"envelope"`
	ScriptBase64 string   `json:"script_base64"`
}

// HookVersionPayload is the payload of a hook_version envelope, the contract's
// HookVersionPayload. Name and Version repeat the pair the node fetched, and
// Checksum is the script's SHA-256 in the encoding of NodeStateHook.Checksum.
// Description, Parameters, TimeoutSeconds and SandboxLevel are the hook's
// sidecar fields, signed together with its checksum, and the control plane
// sends the first three only when the version declares them.
type HookVersionPayload struct {
	ProjectID      string        `json:"project_id"`
	Name           string        `json:"name"`
	Version        int           `json:"version"`
	Checksum       string        `json:"checksum"`
	Description    string        `json:"description,omitempty"`
	Parameters     []ActionParam `json:"parameters,omitempty"`
	TimeoutSeconds int64         `json:"timeout_seconds,omitempty"`
	SandboxLevel   string        `json:"sandbox_level"`
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
//
// CancelRequestedAt is present only on a started entry, once an operator
// cancelled the Execution: the control plane ends a pending or ack target at
// once, and such an entry leaves the block. Its presence is the signal to stop
// the run; plexd never compares its value with its own clock. A JSON null and an
// absent key both decode to nil. A value that is not an RFC 3339 string fails
// the decode of the whole state response, as a malformed expires_at does.
type NodeStateExecution struct {
	ExecutionID       string                     `json:"execution_id"`
	Action            string                     `json:"action"`
	Type              string                     `json:"type"`
	Parameters        map[string]json.RawMessage `json:"parameters"`
	Status            string                     `json:"status"`
	RequestedAt       time.Time                  `json:"requested_at"`
	ExpiresAt         time.Time                  `json:"expires_at"`
	CancelRequestedAt *time.Time                 `json:"cancel_requested_at,omitempty"`
}

// The three legal values of a NodeStateExecution.Type.
const (
	// ActionKindBuiltin dispatches an action built into plexd.
	ActionKindBuiltin = "builtin"
	// ActionKindHook dispatches a hook registered by the node.
	ActionKindHook = "hook"
	// ActionKindPlexdHook dispatches a PlexdHook resource of the node's
	// cluster. The entry's Action is the resource's metadata.name.
	ActionKindPlexdHook = "plexd_hook"
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
//
// A declared hook's metadata has limits of its own: a description and each
// parameter text field at most 4096 characters, at most 64 parameters per hook,
// timeout_seconds 0 to 86400, sandbox_level at most 64 characters, and no NUL
// in any of them. Characters are Unicode code points. Those violations answer
// 400, not 422: declared_hooks_too_many past 64 parameters and
// declared_hook_invalid otherwise. A control plane that predates the fields
// refuses them with 400 malformed_capabilities_request.
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
	// PlexdHooks are the PlexdHook resources the agent found in its
	// ServiceAccount's namespace, at most 128, with unique names. The agent
	// reports the list again when those resources change. Omitted when the
	// agent runs outside a cluster or found nothing it can report, rather than
	// sent as null, and a missing key means none: every PUT replaces the stored
	// list whole.
	PlexdHooks []DiscoveredPlexdHook `json:"plexd_hooks,omitempty"`
	// BuiltinActions is the inventory of builtin actions the agent implements,
	// sorted by name, each with its parameters in registration order. Omitted
	// when empty rather than sent as null.
	BuiltinActions []ActionInfo `json:"builtin_actions,omitempty"`
	// HookRolloutErrors are the published hook versions the node's last pull
	// listed and the node could not install, at most MaxHookRolloutErrors.
	// Omitted when nil rather than sent as null. The control plane stores an
	// absent list as [], because every PUT replaces the whole snapshot, so the
	// node clears an error by leaving it out. More than MaxHookRolloutErrors
	// entries answer 400 hook_rollout_errors_too_many, and an entry that breaks
	// a limit 400 hook_rollout_error_invalid.
	HookRolloutErrors []HookRolloutError `json:"hook_rollout_errors,omitempty"`
}

// Values of DeclaredHook.Source and HookInfo.Source: where a hook the agent
// runs came from. The wire treats an absent source as local, which is why a
// hand-placed hook is sent with no source key at all.
const (
	// HookSourceLocal marks a hook placed on the node by other means than a
	// rollout, such as a script in hooks_dir. Its pin is the digest first seen.
	HookSourceLocal = "local"
	// HookSourceRollout marks a script installed from a published hook
	// version. Its pin is the checksum the pull delivered.
	HookSourceRollout = "rollout"
)

// Codes of a HookRolloutError the contract documents. The control plane
// accepts any code that matches ^[a-z0-9_]{1,64}$ and shows it as sent, so a
// newer agent's code never refuses the manifest.
const (
	// HookRolloutCodeCollision means hooks_dir holds a hook of the rollout's
	// name. The node leaves that hook in place, keeps reporting it as local,
	// and reports the collision rather than resolving it.
	HookRolloutCodeCollision = "collision"
	// HookRolloutCodeVerificationFailed means the node fetched the version,
	// and its signature or its checksum did not verify.
	HookRolloutCodeVerificationFailed = "verification_failed"
	// HookRolloutCodeFetchFailed means the node could not fetch the version.
	HookRolloutCodeFetchFailed = "fetch_failed"
	// HookRolloutCodeInstallFailed means the node could not install the
	// version, or will not on this platform or under this configuration.
	HookRolloutCodeInstallFailed = "install_failed"
)

// Limits the control plane puts on hook_rollout_errors. plexd keeps a copy so
// a manifest it builds stays inside them; IsHookMetadataRefused covers the
// case where the copies drift apart.
const (
	// MaxHookRolloutErrors is the most entries one manifest may carry.
	MaxHookRolloutErrors = 64
	// MaxHookRolloutDetailChars is the longest detail, in Unicode code points.
	MaxHookRolloutDetailChars = 1024
)

// HookRolloutError is one published hook version the node could not install,
// as the "Published hooks" section of plexsphere's agent contract
// (docs/reference/api/plexd-agent-contract.md) describes it. Name and Version
// are the pair the pull listed, so the operator's per-node rollout status can
// put the error beside the rollout that caused it.
type HookRolloutError struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	// Code is one of the HookRolloutCode constants.
	Code string `json:"code"`
	// Detail explains the failure, at most MaxHookRolloutDetailChars code
	// points with no NUL. Omitted when empty.
	Detail string `json:"detail,omitempty"`
}

// DeclaredHook is one hook the agent advertises. Its name and the digest of its
// payload let the integrity correlator see a hook change without re-fetching
// it. The four fields after them come from the hook's sidecar and describe the
// hook for an operator. They gate nothing at the control plane and sit outside
// its digest, so a sidecar edit changes them and leaves Checksum alone. plexd
// applies the sidecar's timeout and sandbox when it runs the hook. Source and
// Version, last, mark a hook a rollout installed and name its version. The
// control plane then takes that version's published checksum as the hook's
// baseline, so a rolled-out hook is never trusted on first use.
type DeclaredHook struct {
	Name string `json:"name"`
	// Checksum is the hook payload's SHA-256 as 32 raw bytes in
	// standard-padded base64, same encoding as BinaryChecksum.
	Checksum string `json:"checksum"`
	// Description says what the hook does, at most 4096 characters. Omitted
	// when the sidecar declares none.
	Description string `json:"description,omitempty"`
	// Parameters are the parameters the hook expects, in sidecar order, at most
	// 64. Each name is non-empty after trimming and unique within the hook.
	// Omitted when empty rather than sent as null.
	Parameters []ActionParam `json:"parameters,omitempty"`
	// TimeoutSeconds is the timeout the sidecar declares, in whole seconds from
	// 0 to 86400. 0 means none declared, and the key stays off the wire.
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`
	// SandboxLevel is the sandbox level the sidecar declares, at most 64
	// characters. The contract keeps it free-form. Omitted when the sidecar
	// declares none.
	SandboxLevel string `json:"sandbox_level,omitempty"`
	// Source is HookSourceRollout for a script installed from a published
	// version. It is empty, and the key stays off the wire, for a hook placed
	// on the node by other means: the contract reads an absent source as
	// local, so a node with no rolled-out hook sends the manifest it sent
	// before rollouts existed. The contract also accepts HookSourceLocal, and
	// answers any value other than those two with 400 declared_hook_invalid.
	Source string `json:"source,omitempty"`
	// Version is the published version installed, 1 to 2147483647. It is
	// required with Source HookSourceRollout and refused on any other entry,
	// both with 400 declared_hook_invalid, so it is zero, and off the wire,
	// for every other entry.
	Version int `json:"version,omitempty"`
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
	// Version is the published version a rolled-out hook was installed from.
	// It is zero, and omitted, for a hook whose Source is HookSourceLocal,
	// which has no version.
	Version int `json:"version,omitempty"`
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

// MaxHandshakeSharedSubnets is the contract's ceiling on the shared_subnets
// of one handshake report entry. A longer list is refused whole with 400
// malformed_handshake_report.
const MaxHandshakeSharedSubnets = 256

// HandshakeReportRequest is the body of POST /v1/nodes/{node_id}/handshakes:
// for each mesh peer the node has completed a WireGuard handshake with, the age
// of the latest handshake, the endpoint WireGuard used for it, when the node
// holds one, the round-trip time through the tunnel, and the shared subnets the
// node routes through the peer.
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
// The three required fields are not omitempty: an age of 0 (a handshake within
// the last second) is as legitimate as any other, so it must reach the wire
// rather than be dropped as a zero value and refused as missing. The optional
// RTTMicroseconds is omitempty and a pointer, so it leaves the wire only when
// the node holds no measurement, never for a value. The optional SharedSubnets
// is omitempty too: an entry that carries none sends no member, which the
// control plane reads as none.
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
	// RTTMicroseconds is the round-trip time to the peer through the tunnel in
	// whole microseconds, in 1..2147483647, and nil when the node holds no
	// measurement, which leaves the member off the wire. A control plane older
	// than plexsphere/plexsphere#1145 decodes without unknown fields and refuses
	// a report that carries it with 400 malformed_handshake_report.
	RTTMicroseconds *int32 `json:"rtt_microseconds,omitempty"`
	// SharedSubnets are the subnets of the pull's shared_subnets the node
	// routes through the peer when it assembles the report, as CIDRs without
	// host bits, none repeated, at most MaxHandshakeSharedSubnets. An absent
	// member, null and [] all mean none, and the control plane then clears
	// what it stored for the edge. A control plane that predates the member
	// refuses a report that carries it with 400 malformed_handshake_report;
	// the node sends it only for a subnet a pull named, which such a control
	// plane never does.
	SharedSubnets []string `json:"shared_subnets,omitempty"`
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
// Relay Status  PUT /v1/nodes/{node_id}/relay-status
// ---------------------------------------------------------------------------

// Relay states of a RelayStatusRequest.
const (
	// RelayStateRunning marks a relay whose socket is bound on ListenPort.
	RelayStateRunning = "running"
	// RelayStateStopped marks a relay that does not run: the pull does not
	// enable it, names a listen_port outside 1..65535, or plexd stops it
	// because it shuts down.
	RelayStateStopped = "stopped"
	// RelayStateBindFailed marks a relay whose socket could not be bound on
	// ListenPort.
	RelayStateBindFailed = "bind_failed"
	// RelayStateNotConsented marks a relay the pull enables while
	// bridge.relay_enabled does not consent to it.
	RelayStateNotConsented = "not_consented"
)

// MaxRelayStatusBoundSeconds is the contract's ceiling on bound_seconds.
const MaxRelayStatusBoundSeconds = 315360000

// RelayStatusRequest is the body of PUT /v1/nodes/{node_id}/relay-status: the
// state of the bridge's relay as the node reports it. ListenPort accompanies
// running and bind_failed, BoundSeconds only running. A member the state
// requires or forbids is refused with 400 invalid_relay_status, and an
// out-of-range value or a null member with 400 malformed_relay_status. The
// handler decodes with DisallowUnknownFields, so the struct carries the
// contract's fields and nothing else.
//
// The control plane anchors BoundSeconds on its own receive time, so a body is
// only true for the attempt it was assembled for, and the agent builds a fresh
// one for every attempt.
type RelayStatusRequest struct {
	// State is one of the RelayState* constants.
	State string `json:"state"`
	// ListenPort is the relay's UDP port, in 1..65535. It stays a plain int:
	// 0 is never a valid port, and the two states that forbid the member leave
	// it 0, so omitempty drops it exactly where it must be absent.
	ListenPort int `json:"listen_port,omitempty"`
	// BoundSeconds is the whole seconds since the relay socket was bound, in
	// 0..MaxRelayStatusBoundSeconds. It is a pointer because 0 is a valid
	// value, for a socket bound less than a second ago: a plain int64 with
	// omitempty would drop it, and the control plane would refuse the running
	// report with 400 invalid_relay_status. nil omits the member, as every
	// state but running requires.
	BoundSeconds *int64 `json:"bound_seconds,omitempty"`
}

// RelayStatusResponse is the 200 body of PUT /v1/nodes/{node_id}/relay-status.
type RelayStatusResponse struct {
	// AcceptedAt is the server receive time BoundSeconds was anchored on.
	AcceptedAt time.Time `json:"accepted_at"`
}

// ---------------------------------------------------------------------------
// Ingress Status  PUT /v1/nodes/{node_id}/ingress-status
// ---------------------------------------------------------------------------

// Ingress states of an IngressStatusRequest.
const (
	// IngressStateEnabled marks a bridge whose local configuration serves the
	// public ingress rules the state pull enables.
	IngressStateEnabled = "enabled"
	// IngressStateOptedOut marks a bridge whose local configuration,
	// bridge.ingress_enabled: false, rules public ingress out: it opens no
	// public listener whatever the pull says.
	IngressStateOptedOut = "opted_out"
)

// The facets of an IngressStatusRule.
const (
	// IngressListenerListening marks a rule whose listen port is bound.
	IngressListenerListening = "listening"
	// IngressListenerNotListening marks a rule the bridge does not listen
	// for; ListenerReason says why.
	IngressListenerNotListening = "not_listening"

	// IngressCertificateNotRequired marks a passthrough rule, which needs no
	// certificate at the bridge.
	IngressCertificateNotRequired = "not_required"
	// IngressCertificateReady marks a terminate or acme rule whose
	// certificate is in place.
	IngressCertificateReady = "ready"
	// IngressCertificateNotReady marks a terminate or acme rule without its
	// certificate; CertificateReason says why.
	IngressCertificateNotReady = "not_ready"

	// IngressDialNone marks a rule for which the bridge has dialled no target
	// yet, or a target it has not dialled yet. For a udp rule a dial is a
	// send of a client's datagram.
	IngressDialNone = "none"
	// IngressDialSucceeded marks a rule whose last unit a target took, or a
	// target whose last dial succeeded.
	IngressDialSucceeded = "succeeded"
	// IngressDialFailed marks a rule whose last unit no target took, or a
	// target whose last dial failed; DialReason says why.
	IngressDialFailed = "failed"
)

// MaxIngressStatusRules is the contract's ceiling on the entries of one
// ingress status report.
const MaxIngressStatusRules = 1024

// MaxIngressStatusDialAgeSeconds is the contract's ceiling on
// dial_age_seconds, the largest signed 32-bit integer.
const MaxIngressStatusDialAgeSeconds = 2147483647

// MaxIngressStatusTargets is the contract's ceiling on the target entries of
// one rule entry, the most targets a rule holds.
const MaxIngressStatusTargets = 8

// MaxIngressStatusClientRefusals is the contract's ceiling on the refusal
// entries of one rule entry.
const MaxIngressStatusClientRefusals = 8

// MaxIngressStatusRefusalAgeSeconds is the contract's ceiling on a refusal's
// age_seconds, the largest signed 32-bit integer.
const MaxIngressStatusRefusalAgeSeconds = 2147483647

// IngressStatusRequest is the body of PUT /v1/nodes/{node_id}/ingress-status:
// whether the bridge's local configuration serves public ingress, and how
// each ingress rule of its pull fares. The control plane keeps the latest
// state per node and never ages it, and refuses ingress rule creates and
// updates on the bridge while it reads opted_out. Each report replaces the
// rule entries of the one before it.
//
// A missing, null or unknown state, an unknown member, data after the report,
// more than MaxIngressStatusRules entries, and an entry with a malformed id or
// a value outside its member's rule answer 400 malformed_ingress_status. An
// opted-out report with entries, an id that repeats an earlier entry, an
// entry that breaks the presence rules of IngressStatusRule, and a refusal
// whose reason an earlier refusal of its entry carries answer 400
// invalid_ingress_status.
type IngressStatusRequest struct {
	// State is one of the IngressState* constants.
	State string `json:"state"`
	// Rules holds one entry per reported rule, in the order of the pull; nil
	// omits the member, which the contract reads as no entries.
	Rules []IngressStatusRule `json:"rules,omitempty"`
}

// IngressStatusRule is one entry of rules, the control plane's
// IngressStatusReportRule. Each member after Listener is sent exactly when the
// facet before it calls for it: ListenerReason when Listener is not_listening;
// Certificate and Dial when it is listening; CertificateReason when
// Certificate is not_ready; DialReason when Dial is failed; DialAgeSeconds
// when Dial is succeeded or failed. ClientAuthEnforced is true only beside a
// Listener of listening, and ClientRefusals carries entries only beside a
// ClientAuthEnforced of true. omitempty drops an empty member, so a caller
// leaves every member it must not send empty.
type IngressStatusRule struct {
	// ID is the rule's id from the pull, a UUID other than the zero UUID.
	ID string `json:"id"`
	// Listener is one of the IngressListener* constants.
	Listener       string `json:"listener"`
	ListenerReason string `json:"listener_reason,omitempty"`
	// Certificate is one of the IngressCertificate* constants.
	Certificate       string `json:"certificate,omitempty"`
	CertificateReason string `json:"certificate_reason,omitempty"`
	// Dial is one of the IngressDial* constants.
	Dial       string `json:"dial,omitempty"`
	DialReason string `json:"dial_reason,omitempty"`
	// DialAgeSeconds is the whole seconds between the dial and the report, in
	// 0..MaxIngressStatusDialAgeSeconds. It is a pointer because 0 is a valid
	// age, for a dial less than a second ago.
	DialAgeSeconds *int64 `json:"dial_age_seconds,omitempty"`
	// Targets holds at most MaxIngressStatusTargets entries, one per target
	// of the rule, only beside a Listener of listening; nil omits the member,
	// which the contract reads as no entries.
	Targets []IngressStatusTarget `json:"targets,omitempty"`
	// ClientAuthEnforced says that the bridge verifies every client of the
	// rule against its client authorities, or serves no client of the rule.
	// It is sent only for a listening rule whose pull entry carries
	// client_auth; false omits the member, which the contract reads as false.
	ClientAuthEnforced bool `json:"client_auth_enforced,omitempty"`
	// ClientRefusals holds at most MaxIngressStatusClientRefusals entries,
	// one per reason, only beside a ClientAuthEnforced of true; nil omits the
	// member, which the contract reads as no entries.
	ClientRefusals []IngressStatusClientRefusal `json:"client_refusals,omitempty"`
}

// IngressStatusClientRefusal is one entry of a rule entry's client_refusals,
// the control plane's IngressStatusReportRuleClientRefusal: the last client
// the bridge refused for Reason. No two entries of one rule name the same
// Reason.
type IngressStatusClientRefusal struct {
	// Reason is a reason token: no_certificate, unknown_authority,
	// certificate_expired or certificate_invalid.
	Reason string `json:"reason"`
	// AgeSeconds is the whole seconds between the refusal and the report, in
	// 0..MaxIngressStatusRefusalAgeSeconds. The contract requires the member,
	// and 0 is a valid age, so it has no omitempty.
	AgeSeconds int64 `json:"age_seconds"`
}

// IngressStatusTarget is one entry of a rule entry's targets, the control
// plane's IngressStatusReportRuleTarget: the target as the pull names it and
// the last dial the bridge made to it. DialReason is sent exactly when Dial
// is failed, and DialAgeSeconds exactly when Dial is succeeded or failed. No
// two entries of one rule name the same NodeID and Port.
type IngressStatusTarget struct {
	// NodeID is the target's node_id from the pull, a UUID other than the
	// zero UUID.
	NodeID string `json:"node_id"`
	// Port is the target's port from the pull, in 1..65535.
	Port int `json:"port"`
	// Dial is one of the IngressDial* constants.
	Dial       string `json:"dial"`
	DialReason string `json:"dial_reason,omitempty"`
	// DialAgeSeconds is the whole seconds between the last dial to the target
	// and the report, in 0..MaxIngressStatusDialAgeSeconds.
	DialAgeSeconds *int64 `json:"dial_age_seconds,omitempty"`
}

// ValidIngressRuleID reports whether s is a UUID in canonical form, groups of
// 8, 4, 4, 4 and 12 hex digits in either case joined by hyphens, other than
// the zero UUID: an id the control plane accepts in an ingress status report.
func ValidIngressRuleID(s string) bool {
	if len(s) != 36 {
		return false
	}
	zero := true
	for i := range len(s) {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c == '0':
		case '1' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
			zero = false
		default:
			return false
		}
	}
	return !zero
}

// ValidIngressTargetNodeID reports whether s is a node_id the control plane
// accepts in a target entry of an ingress status report: a UUID in
// canonical form other than the zero UUID, as ValidIngressRuleID.
func ValidIngressTargetNodeID(s string) bool { return ValidIngressRuleID(s) }

// ValidIngressReason reports whether s is a reason token of an ingress status
// report: a lowercase letter, then up to 62 lowercase letters, digits and
// underscores (^[a-z][a-z0-9_]{0,62}$).
func ValidIngressReason(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// IngressStatusResponse is the 200 body of
// PUT /v1/nodes/{node_id}/ingress-status.
type IngressStatusResponse struct {
	// AcceptedAt is the server receive time of the report.
	AcceptedAt time.Time `json:"accepted_at"`
}

// ---------------------------------------------------------------------------
// User Access Status  PUT /v1/nodes/{node_id}/user-access-status
// ---------------------------------------------------------------------------

// User access states of a UserAccessStatusRequest.
const (
	// UserAccessStateEnabled marks a bridge whose local configuration serves
	// the user access providers the state pull enables.
	UserAccessStateEnabled = "enabled"
	// UserAccessStateOptedOut marks a bridge whose local configuration,
	// bridge.user_access_enabled: false, rules user access out: it serves no
	// provider whatever the pull says.
	UserAccessStateOptedOut = "opted_out"
)

// The health values of a UserAccessStatusProvider.
const (
	// UserAccessHealthUp marks a provider the bridge serves.
	UserAccessHealthUp = "up"
	// UserAccessHealthDown marks a provider the bridge does not serve; Reason
	// says why.
	UserAccessHealthDown = "down"
)

// MaxUserAccessStatusProviders is the contract's ceiling on the entries of
// one user access status report. A bridge with more providers reports the
// first ones in the order of the pull.
const MaxUserAccessStatusProviders = 256

// UserAccessStatusRequest is the body of
// PUT /v1/nodes/{node_id}/user-access-status: whether the bridge's local
// configuration serves user access, and whether each user access provider of
// its pull is up. The control plane keeps the latest state per node and never
// ages it, and refuses provider creates and updates and device admissions on
// the bridge while it reads opted_out. The provider entries age after three
// heartbeat intervals. Each report replaces the provider entries of the one
// before it.
//
// A missing, null or unknown state, an unknown member, data after the report,
// more than MaxUserAccessStatusProviders entries, and an entry with a
// malformed id or a value outside its member's rule answer
// 400 malformed_user_access_status, and so does an entry that breaks the
// presence rules of UserAccessStatusProvider. An opted-out report with
// entries and an id that repeats an earlier entry answer
// 400 invalid_user_access_status. A body over 64 KiB answers
// 413 user_access_status_body_too_large.
type UserAccessStatusRequest struct {
	// State is one of the UserAccessState* constants.
	State string `json:"state"`
	// Providers holds one entry per reported provider, in the order of the
	// pull; nil omits the member, which the contract reads as no entries.
	Providers []UserAccessStatusProvider `json:"providers,omitempty"`
}

// UserAccessStatusProvider is one entry of providers, the control plane's
// UserAccessStatusReportProvider. Reason is sent exactly when Health is down;
// PublicKey and ConnectedDevices only when it is up, and the bridge sends
// both for a wireguard provider that is up and neither for a vendor one.
// omitempty drops an empty member, so a caller leaves every member it must
// not send empty.
type UserAccessStatusProvider struct {
	// ID is the provider's id from the pull, a UUID other than the zero UUID.
	ID string `json:"id"`
	// Health is one of the UserAccessHealth* constants.
	Health string `json:"health"`
	// Reason is a token of the grammar ^[a-z][a-z0-9_]{0,62}$.
	Reason string `json:"reason,omitempty"`
	// PublicKey is the public half of the key of a wireguard provider's
	// interface: 44 characters of standard base64 that decode to 32 bytes.
	PublicKey string `json:"public_key,omitempty"`
	// ConnectedDevices is the number of the provider's devices whose latest
	// WireGuard handshake is at most 180 seconds old, in 0..1024. It is a
	// pointer because 0 is a valid count, for a provider no device reaches.
	ConnectedDevices *int `json:"connected_devices,omitempty"`
}

// UserAccessStatusResponse is the 200 body of
// PUT /v1/nodes/{node_id}/user-access-status.
type UserAccessStatusResponse struct {
	// AcceptedAt is the server receive time of the report.
	AcceptedAt time.Time `json:"accepted_at"`
}

// ---------------------------------------------------------------------------
// Site-to-Site Status  PUT /v1/nodes/{node_id}/site-to-site-status
// ---------------------------------------------------------------------------

// Site-to-site states of a SiteToSiteStatusRequest.
const (
	// SiteToSiteStateEnabled marks a bridge whose local configuration serves
	// the site-to-site tunnels the state pull enables.
	SiteToSiteStateEnabled = "enabled"
	// SiteToSiteStateOptedOut marks a bridge whose local configuration,
	// bridge.site_to_site_enabled: false, rules site-to-site tunnels out: it
	// serves no tunnel whatever the pull says.
	SiteToSiteStateOptedOut = "opted_out"
)

// The health values of a SiteToSiteStatusTunnel.
const (
	// SiteToSiteHealthUp marks a tunnel the bridge serves.
	SiteToSiteHealthUp = "up"
	// SiteToSiteHealthDown marks a tunnel the bridge does not serve; Reason
	// says why.
	SiteToSiteHealthDown = "down"
)

// MaxSiteToSiteStatusTunnels is the contract's ceiling on the entries of one
// site-to-site status report. A bridge with more tunnels reports the first
// ones in the order of the pull.
const MaxSiteToSiteStatusTunnels = 256

// SiteToSiteStatusRequest is the body of
// PUT /v1/nodes/{node_id}/site-to-site-status: whether the bridge's local
// configuration serves site-to-site tunnels, and whether each tunnel of its
// pull is up and answered by its remote site. The control plane keeps the
// latest state per node and never ages it, and refuses tunnel creates and
// updates on the bridge while it reads opted_out. The tunnel entries age
// after three heartbeat intervals. Each report replaces the tunnel entries
// of the one before it.
//
// A missing, null or unknown state, an unknown member, data after the report,
// more than MaxSiteToSiteStatusTunnels entries, and an entry with a malformed
// id or a value outside its member's rule answer
// 400 malformed_site_to_site_status, and so does an entry that breaks the
// presence rules of SiteToSiteStatusTunnel. An opted-out report with entries
// and an id that repeats an earlier entry answer
// 400 invalid_site_to_site_status. A body over 64 KiB answers
// 413 site_to_site_status_body_too_large.
type SiteToSiteStatusRequest struct {
	// State is one of the SiteToSiteState* constants.
	State string `json:"state"`
	// Tunnels holds one entry per reported tunnel, in the order of the pull;
	// nil omits the member, which the contract reads as no entries.
	Tunnels []SiteToSiteStatusTunnel `json:"tunnels,omitempty"`
}

// SiteToSiteStatusTunnel is one entry of tunnels, the control plane's
// SiteToSiteStatusReportTunnel. Reason is sent exactly when Health is down,
// Established exactly when it is up, and PublicKey only when it is up: the
// bridge sends it for a wireguard tunnel that is up and never for an ipsec
// or openvpn one. omitempty drops an empty member, so a caller leaves every
// member it must not send empty, and Established nil.
type SiteToSiteStatusTunnel struct {
	// ID is the tunnel's id from the pull, a UUID other than the zero UUID.
	ID string `json:"id"`
	// Health is one of the SiteToSiteHealth* constants.
	Health string `json:"health"`
	// Reason is a token of the grammar ^[a-z][a-z0-9_]{0,62}$.
	Reason string `json:"reason,omitempty"`
	// Established says whether the remote site answers: for a wireguard
	// tunnel the latest handshake with the remote peer is at most 180
	// seconds old, for an ipsec tunnel the IKE and child security
	// associations stand, and for an openvpn tunnel the peer is connected.
	// It is a pointer because false is a value the contract requires on a
	// tunnel that is up, and an entry that is down must not carry it.
	Established *bool `json:"established,omitempty"`
	// PublicKey is the public half of the key of a wireguard tunnel's
	// interface: 44 characters of standard base64 that decode to 32 bytes.
	PublicKey string `json:"public_key,omitempty"`
}

// SiteToSiteStatusResponse is the 200 body of
// PUT /v1/nodes/{node_id}/site-to-site-status.
type SiteToSiteStatusResponse struct {
	// AcceptedAt is the server receive time of the report.
	AcceptedAt time.Time `json:"accepted_at"`
}

// ---------------------------------------------------------------------------
// Policy Status  PUT /v1/nodes/{node_id}/policy-status
// ---------------------------------------------------------------------------

// Enforcement values of a PolicyStatusRequest.
const (
	// PolicyEnforcementEnforcing marks a node that programs the rulesets it
	// applies, with its default deny after them.
	PolicyEnforcementEnforcing = "enforcing"
	// PolicyEnforcementDisabled marks a node whose local configuration turned
	// enforcement off (policy.enabled: false).
	PolicyEnforcementDisabled = "disabled"
	// PolicyEnforcementUnavailable marks a node that enforces but has no
	// firewall backend that can program rules.
	PolicyEnforcementUnavailable = "unavailable"
)

// PolicyStatusRequest is the body of PUT /v1/nodes/{node_id}/policy-status:
// what the node did with the policy block of its pulls. The control plane
// decodes it with unknown members refused, refuses a missing or null required
// member with 400 invalid_policy_status, and a member of the wrong JSON type
// with 400 malformed_policy_status.
type PolicyStatusRequest struct {
	// Enforcement is one of the PolicyEnforcement* constants.
	Enforcement string `json:"enforcement"`
	// Applied is the ruleset the node applied last; nil when it applied none
	// since its agent started.
	Applied *PolicyStatusApplied `json:"applied,omitempty"`
	// Rejected is the ruleset the node's latest apply failed on; nil when the
	// latest apply did not fail.
	Rejected *PolicyStatusRejected `json:"rejected,omitempty"`
	// Drops are the default deny's counters; nil when the firewall backend
	// does not count drops.
	Drops *PolicyStatusDrops `json:"drops,omitempty"`
}

// PolicyStatusApplied echoes the policy block a node applied. Fingerprint is
// empty, and so absent on the wire, when the pull carried policy: null.
// Revisions is required; ReportPolicyStatus sends a nil one as [].
type PolicyStatusApplied struct {
	Fingerprint string              `json:"fingerprint,omitempty"`
	Revisions   []PolicyRevisionRef `json:"revisions"`
}

// PolicyStatusRejected echoes the policy block a node's latest apply failed
// on, and why. Every member is required; ReportPolicyStatus sends a nil
// Revisions as []. Reason holds 1 to 1024 bytes of UTF-8 without control
// characters.
type PolicyStatusRejected struct {
	Fingerprint string              `json:"fingerprint"`
	Revisions   []PolicyRevisionRef `json:"revisions"`
	Reason      string              `json:"reason"`
}

// PolicyStatusDrops counts what the node's default deny dropped since its
// agent last installed the ruleset. A counter below its previous report tells
// the control plane that the count restarted.
type PolicyStatusDrops struct {
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

// PolicyStatusResponse is the 200 body of PUT /v1/nodes/{node_id}/policy-status.
type PolicyStatusResponse struct {
	// AcceptedAt is the server receive time the report is stored with.
	AcceptedAt time.Time `json:"accepted_at"`
	// Status is the policy status the report derives against the ruleset the
	// pull serves: applied, pending, rejected or not_enforced.
	Status string `json:"status"`
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

// UserAccessConfig is the bridge.user_access block of the state pull, the
// control plane's NodeStateBridgeUserAccess: every user access provider of the
// bridge Resource, ordered by slug. A bridge serves Providers only when Enabled
// is true and its local configuration does not opt out; a block with Enabled
// false, and an absent or null block, serve no provider. The block is whole: a
// provider a later pull no longer lists is torn down. A block in the shape
// before plexsphere/plexsphere#1108 (interface_name, listen_port, peers)
// decodes to no providers.
type UserAccessConfig struct {
	Enabled   bool                 `json:"enabled"`
	Providers []UserAccessProvider `json:"providers"`
}

// UserAccessProvider is one provider of the block, the control plane's
// NodeStateBridgeUserAccessProvider. It carries the members of its Kind and no
// others: ListenPort, AddressPool, MaxDevices and Devices for wireguard,
// AuthSecretName for tailscale and netbird.
type UserAccessProvider struct {
	// ID is a UUID; ValidUserAccessProviderID checks it.
	ID   string `json:"id"`
	Slug string `json:"slug"`
	// Kind is one of the UserAccessKind* constants.
	Kind string `json:"kind"`
	// ListenPort is the UDP port of a wireguard provider's interface.
	ListenPort int `json:"listen_port,omitempty"`
	// AddressPool is the IPv4 network, in CIDR notation, a wireguard
	// provider's interface and devices take their addresses from. The
	// interface takes the first host address with the pool's prefix length.
	AddressPool string `json:"address_pool,omitempty"`
	// MaxDevices is the most devices a wireguard provider admits. The control
	// plane holds the ceiling; the bridge does not enforce it.
	MaxDevices int `json:"max_devices,omitempty"`
	// Devices are the devices a wireguard provider admits.
	Devices []UserAccessDevice `json:"devices,omitempty"`
	// AuthSecretName names the Secret that holds the key a tailscale or
	// netbird provider joins with, a Tailscale auth key or a NetBird setup
	// key as plain text.
	AuthSecretName string `json:"auth_secret_name,omitempty"`
}

// UserAccessDevice is one device of a wireguard provider, the control plane's
// NodeStateBridgeUserAccessDevice: a WireGuard peer of the provider's
// interface with PublicKey, and Address as its one allowed IP, a /32.
type UserAccessDevice struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

// The kinds of a user access provider.
const (
	// UserAccessKindWireGuard is a WireGuard interface on the bridge that
	// admits the devices the operator registers by their public keys.
	UserAccessKindWireGuard = "wireguard"
	// UserAccessKindTailscale joins the bridge to a tailnet.
	UserAccessKindTailscale = "tailscale"
	// UserAccessKindNetbird joins the bridge to a NetBird network.
	UserAccessKindNetbird = "netbird"
)

// ValidUserAccessProviderID reports whether s is a UUID in canonical form, in
// either case, other than the zero UUID: the check of ValidIngressRuleID, and
// the id the control plane accepts in a user access status report.
func ValidUserAccessProviderID(s string) bool {
	return ValidIngressRuleID(s)
}

// UserAccessInfo is the user access status a node publishes under the node API
// report key status.user-access: whether the last applied block enabled user
// access, and one entry per provider the bridge holds, in block order.
type UserAccessInfo struct {
	Enabled   bool                     `json:"enabled"`
	Providers []UserAccessProviderInfo `json:"providers,omitempty"`
}

// UserAccessProviderInfo is one provider of a UserAccessInfo.
type UserAccessProviderInfo struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Kind string `json:"kind"`
	// Interface is the provider's network interface; empty while it has none.
	Interface string `json:"interface,omitempty"`
	// Health is one of the UserAccessHealth* constants.
	Health string `json:"health"`
	// Reason says why a provider is down; empty while it is up.
	Reason string `json:"reason,omitempty"`
	// ListenPort is a wireguard provider's UDP port.
	ListenPort int `json:"listen_port,omitempty"`
	// Devices counts the devices configured on a wireguard provider's
	// interface.
	Devices int `json:"devices"`
	// ConnectedDevices counts those of them with a recent handshake.
	ConnectedDevices int `json:"connected_devices"`
}

// ---------------------------------------------------------------------------
// Public Ingress
// ---------------------------------------------------------------------------

// IngressConfig is the bridge.ingress block of the state pull, the control
// plane's NodeStateBridgeIngress.
type IngressConfig struct {
	// Enabled is the control plane's switch: a bridge serves Rules only when
	// it is true and its local configuration does not opt out. A block
	// without the member decodes to false and opens no public listener. The
	// control plane sends true on every block it delivers.
	Enabled bool          `json:"enabled"`
	Rules   []IngressRule `json:"rules"`
	// ACME is the account the block's acme rules share, the control plane's
	// NodeStateBridgeIngressACME. It is present exactly when a rule has mode
	// acme.
	ACME *IngressACME `json:"acme,omitempty"`
}

// IngressACME is the ACME account of a bridge's acme rules: the directory
// the bridge registers at, and the contact it registers with, empty for none.
type IngressACME struct {
	DirectoryURL string `json:"directory_url"`
	ContactEmail string `json:"contact_email,omitempty"`
}

// IngressRule is one rule of the block, the control plane's
// NodeStateBridgeIngressRule. It is not comparable with ==; Equal compares
// two rules.
type IngressRule struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	// Protocol is IngressProtocolTCP or IngressProtocolUDP. A rule of a
	// control plane before plexsphere/plexsphere#1110 carries none and
	// decodes to an empty Protocol, which a bridge serves as tcp.
	Protocol string `json:"protocol,omitempty"`
	// ListenPort is the public port the bridge listens on, TCP or UDP by
	// Protocol.
	ListenPort int `json:"listen_port"`
	// Mode is IngressModePassthrough, IngressModeTerminate or IngressModeACME.
	Mode string `json:"mode"`
	// SNIHost is the server name the rule matches on a shared port, exact or
	// a wildcard of one left-most label. A rule without it is the only rule on
	// its port.
	SNIHost string `json:"sni_host,omitempty"`
	// Targets are the rule's targets, one to eight, in round-robin order, as
	// a control plane since plexsphere/plexsphere#1120 sends them. A rule of
	// an earlier control plane carries none and marshals without the key; an
	// absent, null or empty member decodes to an empty Targets.
	Targets []IngressTarget `json:"targets,omitempty"`
	// TargetNodeID, TargetAddress and TargetPort name the rule's first
	// target. They are deprecated: a bridge reads them only when Targets is
	// empty, as a control plane before plexsphere/plexsphere#1120 sends a
	// rule.
	TargetNodeID string `json:"target_node_id"`
	// TargetAddress is the target node's mesh address, IPv4 or IPv6, without
	// brackets. Deprecated: see TargetNodeID.
	TargetAddress string `json:"target_address"`
	// TargetPort is the port on the target. Deprecated: see TargetNodeID.
	TargetPort int `json:"target_port"`
	// CertificateSecretName names the Secret of the bridge's Project that
	// holds a terminate rule's certificate chain and key, one PEM document.
	// It is empty on every other mode.
	CertificateSecretName string `json:"certificate_secret_name,omitempty"`
	// Conditions are the request conditions of a terminate or acme rule:
	// rules with conditions share one listen port and SNI host, and the
	// bridge hands each request to the rule they pick. A rule without
	// conditions marshals without the key, and an absent, null or empty
	// member decodes to a rule without conditions.
	Conditions IngressConditions `json:"conditions,omitzero"`
	// StripPathPrefix removes the matched path prefix from the front of the
	// path the target receives. Only a rule whose path prefix is present
	// and not "/" carries it.
	StripPathPrefix bool `json:"strip_path_prefix,omitempty"`
	// ClientAuth requires a client certificate that chains to one of the
	// rule's client authorities; only a terminate or acme rule carries it.
	// It is a pointer because presence is the requirement: an absent member
	// and null decode to nil, which marshals without the key, and {} and
	// {"ca_bundle": ""} decode to a value with an empty bundle, which the
	// bridge cannot build its authorities from.
	ClientAuth *IngressClientAuth `json:"client_auth,omitempty"`
}

// IngressClientAuth is the client certificate requirement of an ingress rule,
// the control plane's BridgeIngressRuleClientAuthBundle: CABundle holds the
// rule's client authorities, 1 to 8 CA certificates as PEM CERTIFICATE
// blocks.
type IngressClientAuth struct {
	CABundle string `json:"ca_bundle"`
}

// IngressConditions are the request conditions of an ingress rule, the
// control plane's NodeStateBridgeIngressConditions: a path prefix and up to 8
// header conditions, all of which a request must match. The headers arrive in
// name order.
type IngressConditions struct {
	PathPrefix string                   `json:"path_prefix,omitempty"`
	Headers    []IngressHeaderCondition `json:"headers,omitempty"`
}

// IngressHeaderCondition is one header condition: a field of Name, a
// lowercase token, that carries exactly Value.
type IngressHeaderCondition struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// IngressTarget is one target of an ingress rule, the control plane's
// NodeStateBridgeIngressRuleTarget: a target node, its mesh address, IPv4 or
// IPv6 without brackets, and a port on it.
type IngressTarget struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// IsZero reports whether c names no path prefix and no header, which is a
// rule without conditions. encoding/json's omitzero calls it.
func (c IngressConditions) IsZero() bool {
	return c.PathPrefix == "" && len(c.Headers) == 0
}

// Equal reports whether two rules carry the same members. A nil and an empty
// Conditions.Headers are equal, and so are a nil and an empty Targets; the
// order of the headers and of the targets counts. reflect.DeepEqual follows
// the ClientAuth pointer: a nil and a non-nil ClientAuth differ, and two
// bundles compare by their text, so a bundle that differs in one byte or in
// the order of its blocks makes another rule.
func (r IngressRule) Equal(o IngressRule) bool {
	if len(r.Conditions.Headers) == 0 {
		r.Conditions.Headers = nil
	}
	if len(o.Conditions.Headers) == 0 {
		o.Conditions.Headers = nil
	}
	if len(r.Targets) == 0 {
		r.Targets = nil
	}
	if len(o.Targets) == 0 {
		o.Targets = nil
	}
	return reflect.DeepEqual(r, o)
}

// The modes of an ingress rule.
const (
	IngressModePassthrough = "passthrough"
	IngressModeTerminate   = "terminate"
	IngressModeACME        = "acme"
)

// The protocols of an ingress rule. A tcp rule forwards the connections that
// reach its listen port, and a udp rule the datagrams.
const (
	IngressProtocolTCP = "tcp"
	IngressProtocolUDP = "udp"
)

// IngressInfo is the ingress status reported by the node in heartbeats.
type IngressInfo struct {
	Enabled   bool `json:"enabled"`
	RuleCount int  `json:"rule_count"`
	// ConnectionCount counts the open client connections of the tcp rules
	// and the open flows of the udp rules. A flow carries the datagrams of
	// one client address and port and the target's answers to them.
	ConnectionCount int  `json:"connection_count"`
	ACMEEnabled     bool `json:"acme_enabled"`
}

// ---------------------------------------------------------------------------
// Site-to-Site VPN
// ---------------------------------------------------------------------------

// SiteToSiteConfig is the bridge.site_to_site block of the state pull, the
// control plane's NodeStateBridgeSiteToSite: every site-to-site tunnel of the
// bridge Resource, ordered by slug. A bridge serves Tunnels only when Enabled
// is true and its local configuration does not opt out; a block with Enabled
// false, and an absent or null block, serve no tunnel. The block is whole: a
// tunnel a later pull no longer lists is torn down. A block in the shape
// before plexsphere/plexsphere#1107 (tunnel_id, remote_endpoint,
// local_subnets, remote_subnets, psk, interface_name, provider_type) decodes
// to tunnels without an id, which a bridge neither serves nor reports.
type SiteToSiteConfig struct {
	Enabled bool               `json:"enabled"`
	Tunnels []SiteToSiteTunnel `json:"tunnels"`
}

// SiteToSiteTunnel is one tunnel of the block, the control plane's
// NodeStateBridgeSiteToSiteTunnel. Every tunnel carries ID, Slug, Kind,
// RemoteHost, RemotePort and AllowedSubnets; the other members follow from
// its Kind: ListenPort, RemotePublicKey and an optional AuthSecretName for
// wireguard, AuthSecretName alone for ipsec and openvpn. No member is a
// private key or the value of a Secret.
type SiteToSiteTunnel struct {
	// ID is a UUID; ValidSiteToSiteTunnelID checks it.
	ID   string `json:"id"`
	Slug string `json:"slug"`
	// Kind is one of the SiteToSiteKind* constants.
	Kind string `json:"kind"`
	// RemoteHost is the remote site's host name of at most 253 characters
	// or its IP address.
	RemoteHost string `json:"remote_host"`
	// RemotePort is the remote site's port, 1 to 65535.
	RemotePort int `json:"remote_port"`
	// AllowedSubnets are the 1 to 64 networks behind the remote site, in
	// CIDR notation and in the order the operator wrote them.
	AllowedSubnets []string `json:"allowed_subnets"`
	// ListenPort is the UDP port of a wireguard tunnel's interface.
	ListenPort int `json:"listen_port,omitempty"`
	// RemotePublicKey is the remote site's WireGuard public key of a
	// wireguard tunnel: 44 characters of standard base64 that decode to 32
	// bytes.
	RemotePublicKey string `json:"remote_public_key,omitempty"`
	// AuthSecretName names the Secret that holds the tunnel's key as plain
	// text: the preshared key of a wireguard tunnel, absent when it uses
	// none, the IKE pre-shared key of an ipsec tunnel, or the static key of
	// an openvpn tunnel.
	AuthSecretName string `json:"auth_secret_name,omitempty"`
}

// The kinds of a site-to-site tunnel.
const (
	// SiteToSiteKindWireGuard is a WireGuard interface on the bridge with
	// one peer, the remote site.
	SiteToSiteKindWireGuard = "wireguard"
	// SiteToSiteKindIPsec is an IKE connection to the remote site,
	// authenticated with a pre-shared key.
	SiteToSiteKindIPsec = "ipsec"
	// SiteToSiteKindOpenVPN is a point-to-point OpenVPN connection to the
	// remote site with a static key.
	SiteToSiteKindOpenVPN = "openvpn"
)

// ValidSiteToSiteTunnelID reports whether s is a UUID in canonical form, in
// either case, other than the zero UUID: the check of
// ValidUserAccessProviderID, and the id the control plane accepts in a
// site-to-site status report.
func ValidSiteToSiteTunnelID(s string) bool {
	return ValidUserAccessProviderID(s)
}

// SiteToSiteInfo is the site-to-site status a node publishes under the node
// API report key status.site-to-site: whether the last applied block enabled
// site-to-site tunnels, and one entry per tunnel the bridge holds, in block
// order.
type SiteToSiteInfo struct {
	Enabled bool                   `json:"enabled"`
	Tunnels []SiteToSiteTunnelInfo `json:"tunnels,omitempty"`
}

// SiteToSiteTunnelInfo is one tunnel of a SiteToSiteInfo.
type SiteToSiteTunnelInfo struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Kind string `json:"kind"`
	// Interface is the tunnel's link; empty while it has none.
	Interface string `json:"interface,omitempty"`
	// Health is one of the SiteToSiteHealth* constants.
	Health string `json:"health"`
	// Reason says why a tunnel is down; empty while it is up.
	Reason string `json:"reason,omitempty"`
	// Established says whether the remote site of a tunnel that is up
	// answers; it is false for a tunnel that is down.
	Established bool `json:"established"`
	// ListenPort is a wireguard tunnel's UDP port.
	ListenPort     int      `json:"listen_port,omitempty"`
	RemoteHost     string   `json:"remote_host"`
	RemotePort     int      `json:"remote_port"`
	AllowedSubnets []string `json:"allowed_subnets"`
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

	// TLSCAFile names a PEM file whose certificates are trusted for the
	// endpoint in addition to the host's system roots, so an endpoint behind
	// a private CA needs neither that CA in the host's trust store nor
	// TLSInsecureSkipVerify. TLSClientConfig reads it on each call.
	TLSCAFile string `yaml:"tls_ca_file"`
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
	// Skipping verification trusts any certificate, so the named CA would be
	// silently ignored.
	if c.TLSCAFile != "" && c.TLSInsecureSkipVerify {
		return fmt.Errorf("%s: config: local_endpoint: tls_ca_file and tls_insecure_skip_verify are mutually exclusive", prefix)
	}
	return nil
}

// TLSClientConfig returns the TLS settings for a client of the endpoint, or
// nil when the endpoint sets neither TLS option and the transport's defaults
// apply.
func (c *LocalEndpointConfig) TLSClientConfig(logger *slog.Logger) (*tls.Config, error) {
	switch {
	case c.TLSCAFile != "" && c.TLSInsecureSkipVerify:
		// Validate refuses this too, but a caller that skipped it must not get
		// an unverified client from a configuration that names a CA.
		return nil, errors.New("tls_ca_file and tls_insecure_skip_verify are mutually exclusive")
	case c.TLSCAFile != "":
		pool, err := LoadRootCAs(c.TLSCAFile, logger)
		if err != nil {
			return nil, fmt.Errorf("tls_ca_file: %w", err)
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, nil
	case c.TLSInsecureSkipVerify:
		return &tls.Config{InsecureSkipVerify: true}, nil
	default:
		return nil, nil
	}
}
