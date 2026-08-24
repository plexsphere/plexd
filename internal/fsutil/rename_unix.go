//go:build unix

package fsutil

import "os"

// replaceFile renames oldpath onto newpath, replacing whatever is there.
// rename(2) is atomic and a reader holding the target open cannot block it, so
// there is nothing to retry.
func replaceFile(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
