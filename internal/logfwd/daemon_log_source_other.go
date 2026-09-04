//go:build !unix

package logfwd

// daemonLogReadFlags exists because DaemonLogSource is compiled everywhere.
// O_NOFOLLOW has no counterpart outside unix, and no service manager plexd
// supports there writes the daemon's output to a file this source reads, so
// the read adds no flags of its own.
const daemonLogReadFlags = 0
