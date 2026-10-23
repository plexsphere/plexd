//go:build linux

package cmd

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/fsutil"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/tunnel"
)

// selectHelperMode reports whether the helper runs socket-activated (systemd
// Accept=yes hands it one connection as fd 3) rather than as plexd's child,
// and refuses a combination that is neither or both.
func selectHelperMode(listenPID, listenFDs string, pid int, child bool, trustedKeys []string) (bool, error) {
	activated := listenPID == strconv.Itoa(pid) && listenFDs == "1"
	switch {
	case activated == child:
		return false, errors.New("plexd session-helper: start it through plexd-session-helper.socket or let plexd start it (--child)")
	case activated && len(trustedKeys) > 0:
		return false, errors.New("--trusted-key is only valid with --child")
	case child && len(trustedKeys) == 0:
		return false, errors.New("--child needs at least one --trusted-key")
	}
	return activated, nil
}

// sessionHelperKeys returns the keys the helper verifies session tokens
// against: the socket-activated helper's trust anchor, or the keys plexd passed
// a child helper.
func sessionHelperKeys(logger *slog.Logger) ([]ed25519.PublicKey, error) {
	socket, err := selectHelperMode(os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getpid(), sessionHelperChild, sessionHelperTrustedKeys)
	if err != nil {
		return nil, err
	}
	if !socket {
		return parseTrustedKeys(sessionHelperTrustedKeys)
	}

	// The process the helper starts must not believe it was socket-activated.
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(name)
	}
	cfg, _, err := agent.ParseConfig(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("session helper: %w", err)
	}
	key, err := resolveHelperSigningKey(cfg, filepath.Join(filepath.Dir(cfgFile), "session-signing-key"), logger)
	if err != nil {
		return nil, err
	}
	return []ed25519.PublicKey{key}, nil
}

// resolveHelperSigningKey returns the key the socket-activated helper verifies
// session tokens against. A configured tunnel.session_signing_public_key wins
// and leaves the pin alone. Otherwise the key pinned at pinPath is used; on the
// first run, with no pin yet, the identity's signing key is pinned there. plexd
// cannot write pinPath: both units make /etc read-only for it.
func resolveHelperSigningKey(cfg *agent.AgentConfig, pinPath string, logger *slog.Logger) (ed25519.PublicKey, error) {
	if s := cfg.Tunnel.SessionSigningPublicKey; s != "" {
		key, err := tunnel.ParseSessionSigningPublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("session helper: tunnel.session_signing_public_key: %w", err)
		}
		return key, nil
	}

	data, err := os.ReadFile(pinPath)
	switch {
	case err == nil:
		key, err := tunnel.ParseSessionSigningPublicKey(string(data))
		if err != nil {
			return nil, fmt.Errorf("session helper: pinned key %s is malformed: %w", pinPath, err)
		}
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("session helper: read pinned key %s: %w", pinPath, err)
	}

	id, err := registration.LoadIdentity(cfg.DataDir)
	if errors.Is(err, registration.ErrNotRegistered) {
		return nil, fmt.Errorf("session helper: node is not registered; no signing key to pin: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("session helper: %w", err)
	}
	key, err := tunnel.ParseSessionSigningPublicKey(id.SigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("session helper: identity signing key: %w", err)
	}
	pin := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	if err := fsutil.WriteFileAtomic(filepath.Dir(pinPath), filepath.Base(pinPath), pin, 0o644); err != nil {
		return nil, fmt.Errorf("session helper: pin the signing key at %s: %w", pinPath, err)
	}
	sum := sha256.Sum256(key)
	logger.Info("pinned the session signing key", "path", pinPath, "sha256", hex.EncodeToString(sum[:]))
	return key, nil
}
