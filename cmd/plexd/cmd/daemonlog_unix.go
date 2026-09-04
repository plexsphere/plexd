//go:build unix

package cmd

import (
	"os"
	"syscall"
)

// daemonLogOpenFlags opens the daemon log file for appending, creating it when
// a rotation has not yet put a new one at the path. O_NOFOLLOW refuses a
// symlink: the reopen runs as root on every rotation for the life of the
// daemon, and the directory the path sits in (/Library/Logs on macOS) is
// writable by the admin group, so a symlink at the path would let an
// unprivileged member of it choose the file root appends log lines to.
const daemonLogOpenFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE | syscall.O_NOFOLLOW
