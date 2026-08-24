//go:build unix

package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncDir_Existing(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Errorf("syncDir(existing dir) = %v, want nil", err)
	}
}

func TestSyncDir_Missing(t *testing.T) {
	err := syncDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("syncDir(missing dir) = nil, want the os.Open error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("syncDir(missing dir) = %v, want fs.ErrNotExist", err)
	}
}

func TestSyncDir_EmptyPath(t *testing.T) {
	err := syncDir("")
	if err == nil {
		t.Fatal(`syncDir("") = nil, want the os.Open error`)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf(`syncDir("") = %v, want a *os.PathError`, err)
	}
}
