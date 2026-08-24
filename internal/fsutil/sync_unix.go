//go:build unix

package fsutil

import "os"

// syncDir fsyncs a directory so an entry renamed into it survives a host power
// loss. Syncing the file only makes its contents durable; on ext4/XFS the new
// directory entry can still be lost after a power cut until the parent
// directory itself is synced.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}
