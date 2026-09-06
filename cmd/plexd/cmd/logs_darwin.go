//go:build darwin

package cmd

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/plexsphere/plexd/internal/packaging"
)

// daemonLogPath is the file launchd writes the daemon's output to, the plist's
// StandardOutPath and StandardErrorPath. It is the same pairing the macOS log
// source is built from in up_darwin.go, so the command reads exactly what the
// daemon forwards. A variable, so a test can point it at a file it owns.
var daemonLogPath = filepath.Join(packaging.DefaultLogDir, packaging.DaemonLogFile)

// logsTailLines is how many lines of that file plexd logs prints. newsyslog
// lets it reach 10 MiB before rotating, so printing the whole file would bury
// the recent lines the command was asked for; an operator who wants all of it
// reads the path itself.
const logsTailLines = 100

// logsCommand returns the tail invocation that reads the launchd log file.
//
// The file is checked before the reader because its absence is the ordinary
// case on a Mac where nobody ran plexd install: a console plexd up writes to
// its terminal, and tail would only answer with its own "No such file" on
// stderr, which names neither what plexd expected nor why it is not there.
func logsCommand(follow bool) (string, []string, error) {
	if _, err := os.Stat(daemonLogPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil, logsUnavailableError{
				"no daemon log at " + daemonLogPath + "; a console plexd up writes to its terminal",
			}
		}
		// Anything else is a real failure the operator has to see: a directory
		// that denies the lookup, an I/O error. os.Stat's own *fs.PathError
		// already names the path and the reason, so it is returned unwrapped
		// and runLogs puts the command prefix in front of it.
		return "", nil, err
	}

	tail, err := exec.LookPath("tail")
	if err != nil {
		return "", nil, logsUnavailableError{"tail not found; read " + daemonLogPath + " directly"}
	}

	args := []string{"-n", strconv.Itoa(logsTailLines)}
	if follow {
		args = append(args, "-f")
	}
	return tail, append(args, daemonLogPath), nil
}
