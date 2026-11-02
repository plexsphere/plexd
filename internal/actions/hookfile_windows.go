package actions

import (
	"io/fs"
	"os/exec"
)

// fileOwnerUID reports no owner. Windows never reaches it, because discovery
// finds no hook there.
func fileOwnerUID(fs.FileInfo) (uint32, bool) {
	return 0, false
}

// setHookProcessGroup does nothing, because Windows runs no hook scripts.
func setHookProcessGroup(*exec.Cmd) {}
