//go:build unix

package cmd

import "context"

// runAsService reports that this process was not started as a managed service.
// A systemd unit and a launchd daemon are ordinary foreground processes that
// their manager supervises, so there is no status protocol to speak and runUp
// runs the agent directly. Only the Windows Service Control Manager needs one.
func runAsService(_ func(context.Context) error) (bool, error) {
	return false, nil
}
