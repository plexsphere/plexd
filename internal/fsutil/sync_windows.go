//go:build windows

package fsutil

// syncDir does nothing on Windows. Go opens a directory with GENERIC_READ
// alone, and FlushFileBuffers requires GENERIC_WRITE, so the fsync the Unix
// build performs would fail with ERROR_ACCESS_DENIED on every call and take
// WriteFileAtomic down with it.
//
// NTFS journals directory metadata itself, so the renamed entry is recoverable
// without an explicit flush, and the file's own Sync in WriteFileAtomic is
// unchanged: the contents are as durable as they are on Unix.
func syncDir(string) error { return nil }
