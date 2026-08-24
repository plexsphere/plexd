package fsutil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWriteFileAtomic_Success(t *testing.T) {
	dir := t.TempDir()
	data := []byte("hello, world")
	perm := os.FileMode(0o644)

	if err := WriteFileAtomic(dir, "test.txt", data, perm); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "test.txt"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(filepath.Join(dir, "test.txt"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != perm {
		t.Errorf("perm = %o, want %o", got, perm)
	}

	// Temp file should be cleaned up.
	assertNoTempFiles(t, dir)
}

// assertNoTempFiles fails when dir still holds a temp file from an interrupted
// or completed write. The temp name carries a random suffix, so it is matched
// by prefix.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestWriteFileAtomic_Overwrite(t *testing.T) {
	dir := t.TempDir()
	name := "overwrite.txt"

	data1 := []byte("first content")
	if err := WriteFileAtomic(dir, name, data1, 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}

	data2 := []byte("second content, longer")
	perm2 := os.FileMode(0o600)
	if err := WriteFileAtomic(dir, name, data2, perm2); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data2) {
		t.Errorf("content = %q, want %q", got, data2)
	}

	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != perm2 {
		t.Errorf("perm = %o, want %o", got, perm2)
	}
}

func TestWriteFileAtomic_EmptyData(t *testing.T) {
	dir := t.TempDir()
	name := "empty.txt"
	perm := os.FileMode(0o644)

	if err := WriteFileAtomic(dir, name, []byte{}, perm); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("size = %d, want 0", info.Size())
	}
	if got := info.Mode().Perm(); got != perm {
		t.Errorf("perm = %o, want %o", got, perm)
	}
}

func TestWriteFileAtomic_NilData(t *testing.T) {
	dir := t.TempDir()
	name := "nil.txt"
	perm := os.FileMode(0o644)

	if err := WriteFileAtomic(dir, name, nil, perm); err != nil {
		t.Fatalf("WriteFileAtomic with nil data: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("size = %d, want 0", info.Size())
	}
	if got := info.Mode().Perm(); got != perm {
		t.Errorf("perm = %o, want %o", got, perm)
	}
}

func TestWriteFileAtomic_LargePayload(t *testing.T) {
	dir := t.TempDir()
	name := "large.bin"

	data := make([]byte, 1<<20) // 1 MB
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	if err := WriteFileAtomic(dir, name, data, 0o644); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch: got %d bytes, want %d bytes", len(got), len(data))
	}
}

func TestWriteFileAtomic_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Cleanup(func() {
		os.Chmod(roDir, 0o700) //nolint:errcheck // best-effort cleanup
	})

	err := WriteFileAtomic(roDir, "file.txt", []byte("data"), 0o644)
	if err == nil {
		t.Fatal("expected error for read-only directory")
	}

	// Verify neither target nor temp file were left behind.
	if _, statErr := os.Stat(filepath.Join(roDir, "file.txt")); !os.IsNotExist(statErr) {
		t.Error("target file should not exist after permission denied")
	}
	assertNoTempFiles(t, roDir)
}

func TestWriteFileAtomic_NonExistentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does", "not", "exist")

	err := WriteFileAtomic(dir, "file.txt", []byte("data"), 0o644)
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
}

func TestWriteFileAtomic_PreservesOriginalOnFailure(t *testing.T) {
	dir := t.TempDir()
	name := "original.txt"
	originalData := []byte("original content")

	if err := WriteFileAtomic(dir, name, originalData, 0o644); err != nil {
		t.Fatalf("initial write: %v", err)
	}

	// Make directory read-only so the second write fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() {
		os.Chmod(dir, 0o700) //nolint:errcheck // best-effort cleanup
	})

	err := WriteFileAtomic(dir, name, []byte("new content"), 0o644)
	if err == nil {
		t.Fatal("expected error when writing to read-only directory")
	}

	// Restore permissions to read the original file.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore Chmod: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, originalData) {
		t.Errorf("original content = %q, want %q", got, originalData)
	}
}

func TestWriteFileAtomic_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines*iterations)

	// Each goroutine writes to its own file.
	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-%d.txt", id)
			for i := range iterations {
				data := []byte(fmt.Sprintf("goroutine-%d-iter-%d", id, i))
				if err := WriteFileAtomic(dir, name, data, 0o644); err != nil {
					errs <- fmt.Errorf("goroutine %d iter %d: %w", id, i, err)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write error: %v", err)
	}

	// Each file should exist with valid content from its last write.
	for g := range goroutines {
		name := fmt.Sprintf("concurrent-%d.txt", g)
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("ReadFile %s: %v", name, err)
			continue
		}
		expected := fmt.Sprintf("goroutine-%d-iter-%d", g, iterations-1)
		if string(got) != expected {
			t.Errorf("%s content = %q, want %q", name, got, expected)
		}
	}

	// Verify no leftover .tmp- files remain after all writes complete.
	assertNoTempFiles(t, dir)
}

// readSettled reads path, retrying briefly on any error. On Windows a replace
// in flight makes the open fail with a sharing violation until MoveFileEx
// finishes, which is the platform's file-sharing behaviour rather than a torn
// write — and a torn write is what the caller asserts against. On Unix the
// retry never triggers, and a genuinely unreadable file still surfaces its
// error once the budget is spent.
func readSettled(path string) ([]byte, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, err := os.ReadFile(path)
		if err == nil || !time.Now().Before(deadline) {
			return got, err
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWriteFileAtomic_ConcurrentSameFile(t *testing.T) {
	// Writers of the same target must not share a temp file: a shared temp
	// inode lets one writer's buffer land in the file another already renamed
	// into place, so a reader sees a mix of both payloads. The payloads differ
	// in length here because that is what makes the mix observable.
	dir := t.TempDir()
	const name = "shared.json"
	const goroutines = 8
	const iterations = 40

	payloads := make([][]byte, goroutines)
	for g := range goroutines {
		payloads[g] = bytes.Repeat([]byte{byte('a' + g)}, 16*(g+1))
	}

	// Seed the target so every read below has a file to open.
	if err := WriteFileAtomic(dir, name, payloads[0], 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	var writers sync.WaitGroup
	writers.Add(goroutines)
	errs := make(chan error, goroutines*iterations+1)

	for g := range goroutines {
		go func(id int) {
			defer writers.Done()
			for range iterations {
				if err := WriteFileAtomic(dir, name, payloads[id], 0o600); err != nil {
					errs <- fmt.Errorf("goroutine %d: %w", id, err)
				}
			}
		}(g)
	}

	// A concurrent reader: every observed content must be exactly one payload.
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := readSettled(filepath.Join(dir, name))
			if err != nil {
				errs <- fmt.Errorf("read: %w", err)
				return
			}
			whole := false
			for _, p := range payloads {
				if bytes.Equal(got, p) {
					whole = true
					break
				}
			}
			if !whole {
				errs <- fmt.Errorf("torn content observed: %q", got)
				return
			}
		}
	}()

	writers.Wait()
	close(stop)
	<-readerDone
	close(errs)

	for err := range errs {
		t.Errorf("%v", err)
	}
	assertNoTempFiles(t, dir)
}

func TestWriteFileAtomic_Permissions(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		perm os.FileMode
	}{
		{"0600", 0o600},
		{"0644", 0o644},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fname := "perm-" + tt.name + ".txt"
			if err := WriteFileAtomic(dir, fname, []byte("test"), tt.perm); err != nil {
				t.Fatalf("WriteFileAtomic: %v", err)
			}

			info, err := os.Stat(filepath.Join(dir, fname))
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if got := info.Mode().Perm(); got != tt.perm {
				t.Errorf("perm = %o, want %o", got, tt.perm)
			}
		})
	}
}
