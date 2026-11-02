//go:build unix

package actions

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"syscall"
)

// fileOwnerUID returns the uid that owns the file info describes.
func fileOwnerUID(info fs.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// setHookProcessGroup starts the hook in a process group of its own and makes
// the end of its context kill that whole group. Killing the script alone left
// its children running as root after the run was reported over.
func setHookProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
