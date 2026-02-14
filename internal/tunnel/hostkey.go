package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/plexsphere/plexd/internal/fsutil"
)

const hostKeyFileName = "ssh_host_ed25519_key"

// GenerateHostKey generates a new Ed25519 keypair and returns it as an ssh.Signer.
func GenerateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tunnel: hostkey: generate: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("tunnel: hostkey: generate: %w", err)
	}
	return signer, nil
}

// LoadOrGenerateHostKey loads an existing Ed25519 host key from dataDir,
// or generates and persists a new one if none exists.
func LoadOrGenerateHostKey(dataDir string, logger *slog.Logger) (ssh.Signer, error) {
	keyPath := filepath.Join(dataDir, hostKeyFileName)

	data, err := os.ReadFile(keyPath)
	if err == nil {
		// Key file exists — check permissions.
		info, statErr := os.Stat(keyPath)
		if statErr == nil && info.Mode().Perm() != 0600 {
			logger.Warn("host key file has unexpected permissions",
				"path", keyPath,
				"mode", fmt.Sprintf("%04o", info.Mode().Perm()),
				"component", "tunnel",
			)
		}

		signer, parseErr := ssh.ParsePrivateKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf("tunnel: hostkey: parse existing key: %w", parseErr)
		}
		logger.Info("loaded existing host key", "path", keyPath, "component", "tunnel")
		return signer, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("tunnel: hostkey: read key file: %w", err)
	}

	// Key does not exist — generate a new one.
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("tunnel: hostkey: create data dir: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tunnel: hostkey: generate: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("tunnel: hostkey: marshal private key: %w", err)
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if err := fsutil.WriteFileAtomic(dataDir, hostKeyFileName, pemData, 0600); err != nil {
		return nil, fmt.Errorf("tunnel: hostkey: write key file: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("tunnel: hostkey: create signer: %w", err)
	}

	logger.Info("generated new host key", "path", keyPath, "component", "tunnel")
	return signer, nil
}
