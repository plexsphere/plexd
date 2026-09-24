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
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/fsutil"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/tunnel"
)

var (
	sessionHelperChild       bool
	sessionHelperTrustedKeys []string
)

var sessionHelperCmd = &cobra.Command{
	Use:   "session-helper",
	Short: "Start one process of a mediated ssh session",
	Long: "Serve one request of plexd's session helper protocol on fd 3: verify the\n" +
		"session token, then start a login shell or one command as the session's user.\n\n" +
		"It is not run by hand. plexd-session-helper.socket starts one instance per\n" +
		"connection, and reads the signing key from tunnel.session_signing_public_key or,\n" +
		"without it, from the key it pinned from identity.json on its first run. Where the\n" +
		"socket does not exist, plexd starts the helper as its own child with --child and\n" +
		"the keys it trusts.",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runSessionHelper,
}

func init() {
	sessionHelperCmd.Flags().BoolVar(&sessionHelperChild, "child", false, "serve the socketpair plexd passed as fd 3")
	sessionHelperCmd.Flags().StringArrayVar(&sessionHelperTrustedKeys, "trusted-key", nil, "standard-base64 Ed25519 key session tokens may be signed with (only with --child)")
	rootCmd.AddCommand(sessionHelperCmd)
}

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

func runSessionHelper(_ *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	socket, err := selectHelperMode(os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getpid(), sessionHelperChild, sessionHelperTrustedKeys)
	if err != nil {
		return err
	}

	var keys []ed25519.PublicKey
	if socket {
		// The process the helper starts must not believe it was socket-activated.
		for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
			_ = os.Unsetenv(name)
		}
		cfg, _, err := agent.ParseConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("session helper: %w", err)
		}
		key, err := resolveHelperSigningKey(cfg, filepath.Join(filepath.Dir(cfgFile), "session-signing-key"), logger)
		if err != nil {
			return err
		}
		keys = []ed25519.PublicKey{key}
	} else {
		// DECISION: child mode pins nothing and reads no config. It runs with
		// plexd's own privileges, so it guards nothing plexd could not do
		// itself, and it trusts the keys plexd passes, which follow plexd's
		// signing-key rotations.
		for _, s := range sessionHelperTrustedKeys {
			key, err := tunnel.ParseSessionSigningPublicKey(s)
			if err != nil {
				return fmt.Errorf("session helper: --trusted-key: %w", err)
			}
			keys = append(keys, key)
		}
	}

	f := os.NewFile(3, "plexd-session-helper")
	fc, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("session helper: fd 3: %w", err)
	}
	conn, ok := fc.(*net.UnixConn)
	if !ok {
		fc.Close()
		return errors.New("session helper: fd 3 is not a Unix socket")
	}
	defer conn.Close()
	return tunnel.RunSessionHelper(conn, keys, logger)
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
