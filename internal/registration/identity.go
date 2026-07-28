package registration

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/plexsphere/plexd/internal/fsutil"
)

// RotationReceipt is the control plane's receipt for a completed mesh-key
// rotation. It is persisted into identity.json so the node can prove which
// rotation the currently committed private_key belongs to.
type RotationReceipt struct {
	RotationID     string `json:"rotation_id"`
	KID            string `json:"kid"`
	WrapKeyVersion int    `json:"wrap_key_version"`
}

// NodeIdentity holds the registration identity of a node.
type NodeIdentity struct {
	NodeID           string           `json:"node_id"`
	MeshIP           string           `json:"mesh_ip"`
	SigningPublicKey string           `json:"signing_public_key"`
	SigningKeyID     string           `json:"signing_key_id"`
	DomainMeshCIDR   string           `json:"domain_mesh_cidr"`
	LastRotation     *RotationReceipt `json:"last_rotation,omitempty"`
	PrivateKey       []byte           `json:"-"` // never serialized to JSON
	NodeSecretKey    string           `json:"-"` // never serialized to JSON
}

// ErrNotRegistered indicates that no valid identity files exist in data_dir.
var ErrNotRegistered = errors.New("registration: node is not registered")

// nskSize is the length in bytes of a decoded node secret key. It doubles as
// the AES-256-GCM key for secret envelopes, so the size is fixed.
const nskSize = 32

// SecretKey decodes NodeSecretKey into the raw AES-256-GCM key used to open
// secret envelopes. Per the register contract nsk travels — and is stored — as
// standard-padded base64; the bearer credential sent in the Authorization
// header stays the encoded string.
func (id *NodeIdentity) SecretKey() ([]byte, error) {
	return decodeNSK(id.NodeSecretKey)
}

// decodeNSK decodes a base64 nsk and enforces its fixed length. Identities
// written before nsk became base64 hold the raw 32-byte secret, which earlier
// versions used verbatim as the AES-256-GCM key — accept that form so an
// upgraded node keeps its identity. Rejecting it would be terminal, not a
// fallback: the fresh registration it forces cannot succeed because the
// bootstrap token file was deleted during the original registration.
func decodeNSK(nsk string) ([]byte, error) {
	if len(nsk) == nskSize {
		return []byte(nsk), nil // legacy pre-base64 identity
	}
	raw, err := base64.StdEncoding.DecodeString(nsk)
	if err != nil {
		return nil, fmt.Errorf("registration: decode nsk: %w", err)
	}
	if len(raw) != nskSize {
		return nil, fmt.Errorf("registration: nsk must decode to %d bytes, got %d", nskSize, len(raw))
	}
	return raw, nil
}

// bearerEnvSegment is the informational `<env>` segment stamped into the
// bearer envelope. The control plane tolerates any non-empty segment without
// an underscore — the cryptographic gate is the payload, not the tag — so the
// value attributes the credential to the producing software: agent-assembled
// envelopes read `nsk_plexd_…`, which separates them from hand-assembled
// operator recipes in traffic captures. No configuration knob: nothing
// consumes the segment today, and the server-side tolerance means one can be
// added later without breaking a deployed fleet.
const bearerEnvSegment = "plexd"

// BearerToken assembles the Authorization bearer credential the control plane
// admits on every post-registration call:
//
//	nsk_<env>_<base64url(node_id_bytes(16) || nsk_plaintext_bytes(32))>
//
// The payload is exactly 48 bytes — the node's UUID followed by the decoded
// NSK — encoded with unpadded base64url. Presenting the raw base64 nsk string
// instead is refused by the control plane with 401. The embedded node id is a
// lookup hint for the control plane's resolver, not an authorizer: the server
// independently matches it against the URL path and verifies the key bytes
// against its own records.
func (id *NodeIdentity) BearerToken() (string, error) {
	nodeID, err := parseNodeUUID(id.NodeID)
	if err != nil {
		return "", err
	}
	key, err := decodeNSK(id.NodeSecretKey)
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, len(nodeID)+len(key))
	payload = append(payload, nodeID...)
	payload = append(payload, key...)
	return "nsk_" + bearerEnvSegment + "_" + base64.RawURLEncoding.EncodeToString(payload), nil
}

// parseNodeUUID decodes the canonical textual UUID the control plane issues
// as node_id (8-4-4-4-12 hex groups) into its 16 raw bytes. Anything else —
// including the free-form ids a mock-era control plane handed out — cannot
// form a bearer envelope and is rejected here rather than sent as a
// credential the server is guaranteed to refuse.
func parseNodeUUID(s string) ([]byte, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, fmt.Errorf("registration: node_id %q is not a canonical UUID", s)
	}
	compact := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	raw, err := hex.DecodeString(compact)
	if err != nil {
		return nil, fmt.Errorf("registration: node_id %q is not a canonical UUID: %w", s, err)
	}
	return raw, nil
}

// identityMu serialises every mutation of the identity file group in the data
// dir. Re-registration (SaveIdentity, driven by the heartbeat goroutine) and
// key rotation (CommitRotatedKey, driven by the rotator goroutine) both
// read-modify-write that group. Without this lock a commit can read
// identity.json inside SaveIdentity's remove-and-rewrite window — failing
// outright — or rewrite it from a snapshot taken before the re-registration,
// binding the rotated private key to the node the control plane just deleted.
// Every writer of the group must hold it; LoadIdentity does not, so functions
// holding it may read freely.
var identityMu sync.Mutex

// SaveIdentity persists the node identity atomically to dataDir.
func SaveIdentity(dataDir string, id *NodeIdentity) error {
	identityMu.Lock()
	defer identityMu.Unlock()

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	// Marshal identity.json (only exported JSON fields).
	jsonData, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	// Each write is atomic on its own, but the group is not. identity.json is
	// what LoadIdentity keys "registered" off. On re-registration it may still
	// be on disk from a previous run, so clear it first: writing it last only
	// prevents a torn identity when it did not already exist. Removing it up
	// front means a partially written key group can never combine with a stale
	// marker (old node_id/mesh_ip, new private_key/node_secret_key), and a
	// failed write leaves no identity.json — the next start reports
	// ErrNotRegistered and registers cleanly instead of loading a torn identity.
	if err := os.Remove(filepath.Join(dataDir, "identity.json")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	// private_key: base64-encoded.
	privKeyData := []byte(base64.StdEncoding.EncodeToString(id.PrivateKey))
	if err := fsutil.WriteFileAtomic(dataDir, "private_key", privKeyData, 0600); err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	// node_secret_key: raw string.
	if err := fsutil.WriteFileAtomic(dataDir, "node_secret_key", []byte(id.NodeSecretKey), 0600); err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	// signing_public_key: raw string.
	if err := fsutil.WriteFileAtomic(dataDir, "signing_public_key", []byte(id.SigningPublicKey), 0600); err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	if err := fsutil.WriteFileAtomic(dataDir, "identity.json", jsonData, 0600); err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	return nil
}

// LoadIdentity reads a previously saved node identity from dataDir.
func LoadIdentity(dataDir string) (*NodeIdentity, error) {
	// Read identity.json.
	jsonData, err := os.ReadFile(filepath.Join(dataDir, "identity.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotRegistered
		}
		return nil, fmt.Errorf("registration: load identity: %w", err)
	}

	var id NodeIdentity
	if err := json.Unmarshal(jsonData, &id); err != nil {
		return nil, fmt.Errorf("registration: load identity: %w", err)
	}

	// Read private_key (base64-encoded).
	privKeyData, err := os.ReadFile(filepath.Join(dataDir, "private_key"))
	if err != nil {
		return nil, fmt.Errorf("registration: load identity: %w", err)
	}
	privKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privKeyData)))
	if err != nil {
		return nil, fmt.Errorf("registration: load identity: %w", err)
	}
	id.PrivateKey = privKey

	// Read node_secret_key.
	nsk, err := os.ReadFile(filepath.Join(dataDir, "node_secret_key"))
	if err != nil {
		return nil, fmt.Errorf("registration: load identity: %w", err)
	}
	id.NodeSecretKey = strings.TrimSpace(string(nsk))

	// Read signing_public_key and cross-check with JSON field.
	spk, err := os.ReadFile(filepath.Join(dataDir, "signing_public_key"))
	if err != nil {
		return nil, fmt.Errorf("registration: load identity: %w", err)
	}
	fileSPK := strings.TrimSpace(string(spk))
	if fileSPK != id.SigningPublicKey {
		slog.Warn("signing_public_key file differs from identity.json, using file value",
			"file_value", fileSPK, "json_value", id.SigningPublicKey)
		id.SigningPublicKey = fileSPK
	}

	// Validate required fields.
	if id.NodeID == "" {
		return nil, fmt.Errorf("registration: load identity: node_id is empty")
	}
	if id.MeshIP == "" {
		return nil, fmt.Errorf("registration: load identity: mesh_ip is empty")
	}
	// nsk is required by everything that follows: it is the bearer credential
	// and, decoded, the AES-256-GCM key for secret envelopes. Reject an
	// undecodable one here so the caller takes the fresh-registration path,
	// rather than surfacing a decode error deep inside startup. Identities
	// written before nsk became base64 hold a raw 32-byte secret and land here.
	if _, err := decodeNSK(id.NodeSecretKey); err != nil {
		return nil, fmt.Errorf("registration: load identity: %w", err)
	}

	return &id, nil
}
