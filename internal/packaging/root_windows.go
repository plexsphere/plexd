//go:build windows

package packaging

import "golang.org/x/sys/windows"

// privilegeName is what the install and uninstall refusals call the privilege
// level they require.
const privilegeName = "Administrator"

// realRootChecker implements RootChecker using the process token's elevation
// state. os.Getuid returns -1 on Windows, so the Unix check would refuse an
// Administrator along with everybody else.
type realRootChecker struct{}

// NewRootChecker returns a RootChecker that checks whether the current process
// token is elevated.
func NewRootChecker() RootChecker {
	return &realRootChecker{}
}

func (c *realRootChecker) IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
