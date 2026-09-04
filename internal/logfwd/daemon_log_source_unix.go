//go:build unix

package logfwd

import "syscall"

// daemonLogReadFlags are the extra open flags the daemon log source reads its
// file with. O_NOFOLLOW refuses a symlink at the path: the daemon runs as root
// and the directory the file sits in (/Library/Logs on macOS) is writable by
// the admin group, so an unprivileged member of it could otherwise point this
// source at a file root can read and have its contents forwarded as this
// node's daemon log. The flag has to sit on the open itself, because a check
// on the path and the open that follows it can see different files.
const daemonLogReadFlags = syscall.O_NOFOLLOW
