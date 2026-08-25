//go:build unix

package packaging

import "os"

// privilegeName is what the install and uninstall refusals call the privilege
// level they require.
const privilegeName = "root"

// realRootChecker implements RootChecker using os.Getuid.
type realRootChecker struct{}

// NewRootChecker returns a RootChecker that checks the real process UID.
func NewRootChecker() RootChecker {
	return &realRootChecker{}
}

func (c *realRootChecker) IsRoot() bool {
	return os.Getuid() == 0
}
