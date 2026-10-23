//go:build linux || darwin

package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/spf13/cobra"

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
		"the keys it trusts. On macOS there is no helper socket: plexd always starts it\n" +
		"with --child.",
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

func runSessionHelper(_ *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	keys, err := sessionHelperKeys(logger)
	if err != nil {
		return err
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

// parseTrustedKeys decodes the keys a child helper is started with.
//
// DECISION: child mode pins nothing and reads no config. It runs with plexd's
// own privileges, so it guards nothing plexd could not do itself, and it
// trusts the keys plexd passes, which follow plexd's signing-key rotations.
func parseTrustedKeys(ss []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(ss))
	for _, s := range ss {
		key, err := tunnel.ParseSessionSigningPublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("session helper: --trusted-key: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// sessionHelperChildArgs is the command line of the child helper, trusting
// keys.
func sessionHelperChildArgs(keys []ed25519.PublicKey) []string {
	args := []string{"session-helper", "--child"}
	for _, key := range keys {
		args = append(args, "--trusted-key", base64.StdEncoding.EncodeToString(key))
	}
	return args
}

// sessionHelperStderr is where a child session helper writes its log lines:
// the daemon log writer when plexd installed one, so the lines follow a
// rotation of the daemon log the way plexd's own do, and plexd's stderr
// otherwise. Only macOS installs that writer.
func sessionHelperStderr() io.Writer {
	if daemonLog != nil {
		return droppingWriter{daemonLog}
	}
	return os.Stderr
}

// droppingWriter drops a line its writer refused instead of reporting the
// failure. os/exec copies a child's stderr into a writer that is no file
// through a pipe, and closes the pipe once a write fails: the child helper's
// next log line would kill it with SIGPIPE before it answers, and the
// command's exit status would be lost. plexd's own logger drops such a line
// the same way.
type droppingWriter struct{ w io.Writer }

func (d droppingWriter) Write(p []byte) (int, error) {
	_, _ = d.w.Write(p)
	return len(p), nil
}
