//go:build darwin

package packaging

import (
	"context"
	"os/exec"
)

// execLaunchctl is the launchctlRunner that drives the real launchctl binary.
// It lives in a darwin-tagged file because it is the only part of the launchd
// manager that touches the host: the plist rendering and the manager itself
// stay untagged so they compile and are tested on every runner.
func execLaunchctl(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "launchctl", args...).CombinedOutput()
}
