package registration

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/plexsphere/plexd/internal/fsutil"
)

// NodeIdentity holds the registration identity of a node.
type NodeIdentity struct {
	NodeID          string `json:"node_id"`
	MeshIP          string `json:"mesh_ip"`
	SigningPublicKey string `json:"signing_public_key"`
	PrivateKey      []byte `json:"-"` // never serialized to JSON
	NodeSecretKey   string `json:"-"` // never serialized to JSON
}

// ErrNotRegistered indicates that no valid identity files exist in data_dir.
var ErrNotRegistered = errors.New("registration: node is not registered")

// SaveIdentity persists the node identity atomically to dataDir.
func SaveIdentity(dataDir string, id *NodeIdentity) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	// Marshal identity.json (only exported JSON fields).
	jsonData, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("registration: save identity: %w", err)
	}

	if err := fsutil.WriteFileAtomic(dataDir, "identity.json", jsonData, 0600); err != nil {
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

	return &id, nil
}

