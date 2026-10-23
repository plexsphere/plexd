package fsutil

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
)

// watchRetryInterval is how long WatchDir waits before it sets the watch up
// again after a file in the directory vanished while the watch was set up.
const watchRetryInterval = 100 * time.Millisecond

// watchAttempts caps how often WatchDir sets the watch up, so a file that
// keeps failing the add as missing ends set-up with an error instead of a
// loop.
const watchAttempts = 10

// WatchDir returns an fsnotify watcher on dir. On macOS and the BSDs, fsnotify
// lists dir and then inspects every file in it while it adds the watch, so a
// file removed in between fails the add with fs.ErrNotExist. WatchDir then
// closes that watcher, calls onRetry with the error when onRetry is not nil,
// and sets the watch up again on a new watcher every watchRetryInterval. It
// returns the error of the last attempt after watchAttempts, and ctx.Err()
// when ctx is done first. Any other error, and fs.ErrNotExist when dir itself
// is gone, is returned as it is.
func WatchDir(ctx context.Context, dir string, onRetry func(err error)) (*fsnotify.Watcher, error) {
	return watchDir(ctx, dir, (*fsnotify.Watcher).Add, onRetry)
}

// watchDir is WatchDir with the add step as a seam, replaced in tests.
func watchDir(ctx context.Context, dir string, add func(*fsnotify.Watcher, string) error, onRetry func(error)) (*fsnotify.Watcher, error) {
	for attempt := 1; ; attempt++ {
		fsw, err := fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
		err = add(fsw, dir)
		if err == nil {
			return fsw, nil
		}
		// A watcher whose add failed on kqueue keeps the directory registered
		// but skips its files on a second add, so every attempt starts afresh.
		// fsnotify v1.9.0's kqueue Close leaves the descriptors of the
		// directory and of the files it opened before the failure open;
		// watchAttempts bounds how many a set-up can leave behind.
		_ = fsw.Close()
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if _, statErr := os.Stat(dir); statErr != nil {
			return nil, err
		}
		if attempt == watchAttempts {
			return nil, err
		}
		if onRetry != nil {
			onRetry(err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(watchRetryInterval):
		}
	}
}
