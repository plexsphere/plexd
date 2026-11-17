//go:build !windows

package integrity

import "os"

// openForHash opens path for reading. Unix renames a file whatever handles are
// open on it, so os.Open is enough; open_windows.go says why Windows is not.
func openForHash(path string) (*os.File, error) {
	return os.Open(path)
}
