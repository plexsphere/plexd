package actions

import "io/fs"

// fileOwnerUID reports no owner. Windows never reaches it, because discovery
// finds no hook there.
func fileOwnerUID(fs.FileInfo) (uint32, bool) {
	return 0, false
}
