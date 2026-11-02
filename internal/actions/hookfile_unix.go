//go:build unix

package actions

import (
	"io/fs"
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
