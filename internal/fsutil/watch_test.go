package fsutil

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// vanishedFileError is the error fsnotify's kqueue backend (macOS and the BSDs)
// returns from Add when a file it listed in the directory is gone before it
// opens it.
func vanishedFileError(dir string) error {
	path := filepath.Join(dir, "vanished")
	return fmt.Errorf("%q: %w", path, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrNotExist})
}

func TestWatchDir_WatchesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "present"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	retries := 0
	fsw, err := WatchDir(context.Background(), dir, func(error) { retries++ })
	if err != nil {
		t.Fatalf("WatchDir() error = %v", err)
	}
	defer fsw.Close()

	if err := os.WriteFile(filepath.Join(dir, "created"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-fsw.Events:
			if filepath.Base(ev.Name) == "created" && ev.Has(fsnotify.Create) {
				if retries != 0 {
					t.Errorf("onRetry calls = %d, want 0", retries)
				}
				return
			}
		case err := <-fsw.Errors:
			t.Fatalf("watcher error: %v", err)
		case <-deadline:
			t.Fatal("no Create event for a file created after WatchDir returned")
		}
	}
}

func TestWatchDir_RetriesWhenAFileVanishes(t *testing.T) {
	dir := t.TempDir()

	var first *fsnotify.Watcher
	adds := 0
	add := func(fsw *fsnotify.Watcher, name string) error {
		adds++
		if adds == 1 {
			first = fsw
			return vanishedFileError(dir)
		}
		return fsw.Add(name)
	}
	var retryErrs []error
	start := time.Now()
	fsw, err := watchDir(context.Background(), dir, add, func(err error) { retryErrs = append(retryErrs, err) })
	if err != nil {
		t.Fatalf("watchDir() error = %v", err)
	}
	defer fsw.Close()

	if adds != 2 {
		t.Errorf("add calls = %d, want 2", adds)
	}
	if len(retryErrs) != 1 || !errors.Is(retryErrs[0], fs.ErrNotExist) {
		t.Errorf("onRetry errors = %v, want one fs.ErrNotExist", retryErrs)
	}
	if fsw == first {
		t.Error("watchDir returned the watcher whose add failed")
	}
	if err := first.Add(dir); !errors.Is(err, fsnotify.ErrClosed) {
		t.Errorf("first watcher Add() error = %v, want fsnotify.ErrClosed", err)
	}
	if elapsed := time.Since(start); elapsed < watchRetryInterval {
		t.Errorf("retried after %v, want at least %v", elapsed, watchRetryInterval)
	}
}

func TestWatchDir_NilOnRetry(t *testing.T) {
	dir := t.TempDir()

	adds := 0
	add := func(fsw *fsnotify.Watcher, name string) error {
		adds++
		if adds == 1 {
			return vanishedFileError(dir)
		}
		return fsw.Add(name)
	}
	fsw, err := watchDir(context.Background(), dir, add, nil)
	if err != nil {
		t.Fatalf("watchDir() error = %v", err)
	}
	defer fsw.Close()

	if adds != 2 {
		t.Errorf("add calls = %d, want 2", adds)
	}
}

func TestWatchDir_ReturnsOtherErrors(t *testing.T) {
	dir := t.TempDir()
	// The timeout turns a watchDir that retries this error into a failure
	// instead of a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var first *fsnotify.Watcher
	adds := 0
	add := func(fsw *fsnotify.Watcher, _ string) error {
		adds++
		first = fsw
		return fmt.Errorf("%q: %w", dir, &fs.PathError{Op: "open", Path: dir, Err: fs.ErrPermission})
	}
	retries := 0
	fsw, err := watchDir(ctx, dir, add, func(error) { retries++ })
	if fsw != nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("watchDir() = %v, %v; want nil and fs.ErrPermission", fsw, err)
	}
	if adds != 1 || retries != 0 {
		t.Errorf("add calls = %d, onRetry calls = %d; want 1 and 0", adds, retries)
	}
	if err := first.Add(dir); !errors.Is(err, fsnotify.ErrClosed) {
		t.Errorf("failed watcher Add() error = %v, want fsnotify.ErrClosed", err)
	}
}

func TestWatchDir_StopsWhenTheDirectoryIsGone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hooks")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var first *fsnotify.Watcher
	adds := 0
	add := func(fsw *fsnotify.Watcher, name string) error {
		adds++
		first = fsw
		if err := os.Remove(name); err != nil {
			t.Errorf("remove %s: %v", name, err)
		}
		return fsw.Add(name)
	}
	retries := 0
	fsw, err := watchDir(ctx, dir, add, func(error) { retries++ })
	if fsw != nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("watchDir() = %v, %v; want nil and fs.ErrNotExist", fsw, err)
	}
	if adds != 1 || retries != 0 {
		t.Errorf("add calls = %d, onRetry calls = %d; want 1 and 0", adds, retries)
	}
	if err := first.Add(t.TempDir()); !errors.Is(err, fsnotify.ErrClosed) {
		t.Errorf("failed watcher Add() error = %v, want fsnotify.ErrClosed", err)
	}
}

func TestWatchDir_GivesUpAfterTheLastAttempt(t *testing.T) {
	dir := t.TempDir()
	// The timeout turns a watchDir that never gives up into a failure instead
	// of a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Each attempt fails on a file of its own name, so the returned error
	// shows which attempt it came from.
	var tried []*fsnotify.Watcher
	add := func(fsw *fsnotify.Watcher, _ string) error {
		tried = append(tried, fsw)
		path := filepath.Join(dir, fmt.Sprintf("vanished-%d", len(tried)))
		return fmt.Errorf("%q: %w", path, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrNotExist})
	}
	retries := 0
	start := time.Now()
	fsw, err := watchDir(ctx, dir, add, func(error) { retries++ })
	if fsw != nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("watchDir() = %v, %v; want nil and fs.ErrNotExist", fsw, err)
	}
	if last := fmt.Sprintf("vanished-%d", watchAttempts); !strings.Contains(err.Error(), last) {
		t.Errorf("watchDir() error = %v, want the error of the last attempt (%s)", err, last)
	}
	if len(tried) != watchAttempts || retries != watchAttempts-1 {
		t.Errorf("add calls = %d, onRetry calls = %d; want %d and %d", len(tried), retries, watchAttempts, watchAttempts-1)
	}
	for i, w := range tried {
		if err := w.Add(dir); !errors.Is(err, fsnotify.ErrClosed) {
			t.Errorf("watcher of attempt %d Add() error = %v, want fsnotify.ErrClosed", i+1, err)
		}
	}
	if elapsed, want := time.Since(start), (watchAttempts-1)*watchRetryInterval; elapsed < want {
		t.Errorf("gave up after %v, want at least %v", elapsed, want)
	}
}

func TestWatchDir_ReturnsCtxErrWhenCancelledBetweenAttempts(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var first *fsnotify.Watcher
	adds := 0
	add := func(fsw *fsnotify.Watcher, _ string) error {
		adds++
		if adds > 1 {
			// Not retryable, so a watchDir that ignores ctx returns this at
			// once instead of looping.
			return errors.New("add called again after cancellation")
		}
		first = fsw
		return vanishedFileError(dir)
	}
	retries := 0
	fsw, err := watchDir(ctx, dir, add, func(error) { retries++; cancel() })
	if fsw != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("watchDir() = %v, %v; want nil and context.Canceled", fsw, err)
	}
	if adds != 1 || retries != 1 {
		t.Errorf("add calls = %d, onRetry calls = %d; want 1 and 1", adds, retries)
	}
	if err := first.Add(dir); !errors.Is(err, fsnotify.ErrClosed) {
		t.Errorf("failed watcher Add() error = %v, want fsnotify.ErrClosed", err)
	}
}
