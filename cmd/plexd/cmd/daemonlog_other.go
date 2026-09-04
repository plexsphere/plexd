//go:build !unix

package cmd

import "os"

// daemonLogOpenFlags exists because reopeningLogFile is compiled everywhere.
// O_NOFOLLOW has no counterpart outside unix, and no service manager plexd
// supports there points the daemon's output at a file plexd follows, so the
// flags stay the plain append-or-create set.
const daemonLogOpenFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE
