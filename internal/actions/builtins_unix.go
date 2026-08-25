//go:build unix

package actions

import (
	"os"

	"golang.org/x/sys/unix"
)

// diskRootPath returns the filesystem path whose capacity diagnostics.collect
// reports as disk_total.
func diskRootPath() string {
	return "/"
}

// diskTotalBytes returns the total capacity of the filesystem holding path, or
// 0 when it cannot be determined.
func diskTotalBytes(path string) uint64 {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0
	}
	// Bsize is int64 on linux/amd64, int32 on linux/mipsle and uint32 on darwin.
	return st.Blocks * uint64(st.Bsize)
}

// kernelRelease returns the running kernel release, or "" when uname fails.
func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// sendReloadSignal asks the process to reload its configuration.
func sendReloadSignal(pid int) error {
	return unix.Kill(pid, unix.SIGHUP)
}

// replaceExecutable installs the verified binary at binaryPath. Unix allows
// renaming over a running executable, so this is a single atomic rename.
func replaceExecutable(tmpPath, binaryPath string) error {
	return os.Rename(tmpPath, binaryPath)
}
