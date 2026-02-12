package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to dir/name atomically using a temp file and rename.
// This ensures readers never observe a partially-written file.
func WriteFileAtomic(dir, name string, data []byte, perm os.FileMode) error {
	targetPath := filepath.Join(dir, name)
	tmpPath := filepath.Join(dir, ".tmp-"+name)

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath) // clean up on error

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, targetPath)
}
