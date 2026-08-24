//go:build windows

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
