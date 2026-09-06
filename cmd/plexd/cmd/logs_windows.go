//go:build windows

package cmd

import (
	"errors"
	"os/exec"
	"strconv"

	"github.com/plexsphere/plexd/internal/packaging"
)

// logsMaxEvents caps what one plexd logs renders. The Application channel is
// shared with every other publisher on the host and holds far more than the
// daemon's own records, and Get-WinEvent returns newest first, so the cap
// selects the most recent events rather than truncating the oldest.
const logsMaxEvents = 100

// errLogsFollowUnsupported is what --follow gets on Windows. Get-WinEvent
// reads a channel and returns; the Event Log's own live feed is a subscription
// with no command-line form, so the flag fails the command rather than
// silently printing a snapshot the operator asked to keep watching.
var errLogsFollowUnsupported = errors.New(
	"--follow is not supported on windows; use Event Viewer or Get-WinEvent")

// logsCommand returns the PowerShell invocation that renders the service's own
// Application-log records. Reading that channel needs no privilege beyond the
// one every authenticated user already has.
//
// powershell.exe is resolved through PATH, as internal/packaging does for the
// Restart-Service it runs. The absolute-path rule the daemon follows is about
// a LocalSystem service inheriting somebody else's PATH; this command runs as
// the operator who typed it.
func logsCommand(follow bool) (string, []string, error) {
	if follow {
		return "", nil, errLogsFollowUnsupported
	}

	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", nil, logsUnavailableError{
			"powershell.exe not found; read the Application Event Log with Event Viewer",
		}
	}

	// -ErrorAction SilentlyContinue is what makes a channel holding no plexd
	// record print nothing and exit 0. Without it Get-WinEvent reports "No
	// events were found that match the specified selection criteria" as a
	// terminating error, and a node that has simply not logged yet would look
	// like a failed command.
	script := "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='" +
		packaging.DefaultServiceName + "'} -MaxEvents " + strconv.Itoa(logsMaxEvents) +
		" -ErrorAction SilentlyContinue | Sort-Object TimeCreated | " +
		"Format-Table -AutoSize -Wrap TimeCreated, LevelDisplayName, Message"

	return powershell, []string{"-NoProfile", "-NonInteractive", "-Command", script}, nil
}
