//go:build unix && !darwin

package cmd

import (
	"os/exec"

	"github.com/plexsphere/plexd/internal/packaging"
)

// logsCommand returns the journalctl invocation that reads the daemon's unit.
// The constraint is "unix && !darwin" rather than "linux" because journald is
// what every Unix but macOS runs plexd under here, matching the split
// internal/paths uses for the same reason.
//
// journalctl keeps the whole journal for the unit, so no line limit is passed:
// the reader is the pager the operator already expects on this platform.
func logsCommand(follow bool) (string, []string, error) {
	journalctl, err := exec.LookPath("journalctl")
	if err != nil {
		return "", nil, logsUnavailableError{
			"journalctl not found; logs may be available on stdout of the plexd process",
		}
	}

	args := []string{"-u", packaging.DefaultServiceName, "--no-pager"}
	if follow {
		args = append(args, "-f")
	}
	return journalctl, args, nil
}
