package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to dir/name atomically using a temp file and rename.
// This ensures readers never observe a partially-written file. Both the file
// contents and the rename are fsynced, so the write survives a host power loss
// and not merely a process crash.
func WriteFileAtomic(dir, name string, data []byte, perm os.FileMode) error {
	targetPath := filepath.Join(dir, name)

	// The temp name is unique per call, not derived from name alone: two
	// concurrent writers of the same target would otherwise share one temp
	// inode, so the second writer's buffer lands in the file the first already
	// renamed into place and readers observe a torn document.
	f, err := os.CreateTemp(dir, ".tmp-"+name+"-")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath) // clean up on error

	// CreateTemp always makes the file 0600, so the requested mode is applied
	// before anything is written into it.
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}

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
	if err := replaceFile(tmpPath, targetPath); err != nil {
		return err
	}

	return syncDir(dir)
}
