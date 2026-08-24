//go:build windows

package fsutil

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// replaceBudget bounds how long replaceFile waits for another handle on the
// target to go away before giving up and returning the rename error.
const replaceBudget = 2 * time.Second

// replaceFile renames oldpath onto newpath, retrying while another open handle
// on the target makes Windows refuse the replace.
//
// Go opens files with FILE_SHARE_READ|FILE_SHARE_WRITE and no
// FILE_SHARE_DELETE, so any reader of the target makes MoveFileEx fail with
// ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION. plexd reads these files while
// it rewrites them — the CLI reads the node-API state cache the daemon is
// updating — so the condition is real and it is transient: the reader closes
// its handle microseconds later. Unix has no equivalent, which is why the retry
// is Windows-only.
func replaceFile(oldpath, newpath string) error {
	deadline := time.Now().Add(replaceBudget)
	delay := 500 * time.Microsecond
	for {
		err := os.Rename(oldpath, newpath)
		if err == nil || !heldByAnotherHandle(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 20*time.Millisecond {
			delay *= 2
		}
	}
}

// heldByAnotherHandle reports whether err is Windows refusing the operation
// because someone else has the file open.
func heldByAnotherHandle(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
