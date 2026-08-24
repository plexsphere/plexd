//go:build windows

package fsutil

import (
	"path/filepath"
	"testing"
)

// TestSyncDir_NoOp pins the Windows contract: syncDir reports no error for any
// path, so WriteFileAtomic's last step cannot be what fails there.
func TestSyncDir_NoOp(t *testing.T) {
	for _, dir := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing"), ""} {
		if err := syncDir(dir); err != nil {
			t.Errorf("syncDir(%q) = %v, want nil", dir, err)
		}
	}
}
