//go:build windows

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// seedReplacePair writes a target and a source file and returns their paths.
func seedReplacePair(t *testing.T) (source, target string) {
	t.Helper()
	dir := t.TempDir()
	target = filepath.Join(dir, "target.txt")
	source = filepath.Join(dir, "source.txt")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	return source, target
}

// TestReplaceFile_RetriesWhileTargetIsOpen pins the reason replaceFile exists:
// Go opens without FILE_SHARE_DELETE, so a reader holding the target makes
// MoveFileEx fail, and the replace has to wait for that handle rather than
// report a failure the caller cannot act on.
func TestReplaceFile_RetriesWhileTargetIsOpen(t *testing.T) {
	source, target := seedReplacePair(t)

	held, err := os.Open(target)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	// Released well inside replaceBudget, so the replace can only succeed by
	// retrying after the first refusal.
	closed := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		held.Close()
		close(closed)
	}()

	if err := replaceFile(source, target); err != nil {
		t.Fatalf("replaceFile with the target briefly held open: %v", err)
	}
	<-closed

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("target = %q, want %q", got, "new")
	}
}

// TestReplaceFile_SurfacesTheErrorPastTheBudget checks the retry is bounded: a
// handle nobody releases must end in the rename error, not in a hang.
func TestReplaceFile_SurfacesTheErrorPastTheBudget(t *testing.T) {
	source, target := seedReplacePair(t)

	held, err := os.Open(target)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer held.Close()

	start := time.Now()
	err = replaceFile(source, target)
	if err == nil {
		t.Fatal("replaceFile with the target held open throughout = nil, want the rename error")
	}
	if !heldByAnotherHandle(err) {
		t.Errorf("replaceFile error = %v, want a sharing or access-denied error", err)
	}
	if elapsed := time.Since(start); elapsed < replaceBudget {
		t.Errorf("replaceFile gave up after %v, want it to retry for at least %v", elapsed, replaceBudget)
	}
}

// replaceRefused reports whether err is WriteFileAtomic giving up on its
// final replace because another handle held the target past replaceBudget.
// Only the rename counts: Windows refusing to create, write or sync the temp
// file is an *os.PathError and stays a failure.
func replaceRefused(err error) bool {
	var linkErr *os.LinkError
	return errors.As(err, &linkErr) && linkErr.Op == "rename" && heldByAnotherHandle(err)
}

func TestReplaceRefused(t *testing.T) {
	refusal := &os.LinkError{Op: "rename", Old: "a", New: "b", Err: windows.ERROR_ACCESS_DENIED}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"access denied on rename", refusal, true},
		{"sharing violation on rename", &os.LinkError{Op: "rename", Old: "a", New: "b", Err: windows.ERROR_SHARING_VIOLATION}, true},
		{"wrapped refusal", fmt.Errorf("save: %w", refusal), true},
		{"other rename error", &os.LinkError{Op: "rename", Old: "a", New: "b", Err: windows.ERROR_FILE_NOT_FOUND}, false},
		{"access denied on open", &os.PathError{Op: "open", Path: "a", Err: windows.ERROR_ACCESS_DENIED}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replaceRefused(tt.err); got != tt.want {
				t.Errorf("replaceRefused(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestWriteFileAtomic_ConcurrentSameFileOutlastsARefusedReplace holds the
// target open while the concurrent same-file writers start, so their replaces
// run out of budget the way three did on a slow CI runner. The run must
// accept exactly that and still pass every other check it makes.
func TestWriteFileAtomic_ConcurrentSameFileOutlastsARefusedReplace(t *testing.T) {
	hold := 2 * replaceBudget
	refused := writeSameFileConcurrently(t, func(target string) {
		held, err := os.Open(target)
		if err != nil {
			t.Fatalf("open target: %v", err)
		}
		// The writers' first replaces start right after the hold begins, so
		// they run out of budget long before the handle goes away. The reader's
		// opens share read and write with this handle, so it keeps reading.
		released := make(chan struct{})
		go func() {
			time.Sleep(hold)
			held.Close()
			close(released)
		}()
		// Registered after the helper's t.TempDir, so it runs first and the
		// directory is never removed under an open handle.
		t.Cleanup(func() { <-released })
	})
	if refused == 0 {
		t.Errorf("no write was refused while the target was held for %v", hold)
	}
}
