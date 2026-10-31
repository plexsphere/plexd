package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
	"github.com/plexsphere/plexd/internal/integrity"
)

// HookEvent describes what happened to a hook.
type HookEvent struct {
	Type string // "add", "update", "remove"
	Hook api.HookInfo
}

// HookChangeCallback is called when hooks change. Receives the full current hooks list.
type HookChangeCallback func(hooks []api.HookInfo)

// IntegrityAlertCallback is called when a hook file's checksum changes unexpectedly.
type IntegrityAlertCallback func(hookName, oldChecksum, newChecksum string)

// HookWatcher monitors a hooks directory for changes using fsnotify.
type HookWatcher struct {
	hooksDir       string
	logger         *slog.Logger
	onChange       HookChangeCallback
	onIntegrity    IntegrityAlertCallback
	debouncePeriod time.Duration

	// changeMu serializes every change to hooks with the onChange call that
	// reports it, so the last onChange always carries the newest list. It is
	// held across onChange, which therefore must not block. It is taken before
	// mu, never after it.
	changeMu sync.Mutex

	mu    sync.Mutex
	hooks map[string]api.HookInfo // name -> hook info

	// watchDir is a seam over fsutil.WatchDir, replaced in tests.
	watchDir func(ctx context.Context, dir string, onRetry func(error)) (*fsnotify.Watcher, error)
	// hashFile is a seam over integrity.HashFile, replaced in tests.
	hashFile func(path string) (string, error)
}

// NewHookWatcher creates a new HookWatcher.
func NewHookWatcher(hooksDir string, onChange HookChangeCallback, onIntegrity IntegrityAlertCallback, logger *slog.Logger) *HookWatcher {
	return &HookWatcher{
		hooksDir:       hooksDir,
		logger:         logger.With("component", "actions"),
		onChange:       onChange,
		onIntegrity:    onIntegrity,
		debouncePeriod: 200 * time.Millisecond,
		hooks:          make(map[string]api.HookInfo),
		watchDir:       fsutil.WatchDir,
		hashFile:       integrity.HashFile,
	}
}

// Watch monitors the hooks directory for changes. It blocks until ctx is cancelled.
// Returns nil on clean shutdown via context cancellation.
func (w *HookWatcher) Watch(ctx context.Context) error {
	if err := os.MkdirAll(w.hooksDir, 0o755); err != nil {
		return err
	}

	fsw, err := w.watchDir(ctx, w.hooksDir, func(err error) {
		w.logger.Warn("actions: watcher: a hook vanished while the watch was set up; retrying", "error", err)
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		// Report the hooks on disk once anyway, so a failed watch costs live
		// updates, not the hooks the agent starts with.
		w.initialScan()
		return err
	}
	defer fsw.Close()

	// Scan only once the watch is in place: a hook added, changed or removed
	// from here on is in the scan, arrives as an event, or both.
	w.initialScan()

	// Per-file debounce timers.
	timersMu := sync.Mutex{}
	timers := make(map[string]*time.Timer)

	stopTimers := func() {
		timersMu.Lock()
		defer timersMu.Unlock()
		for _, t := range timers {
			t.Stop()
		}
	}

	for {
		select {
		case <-ctx.Done():
			stopTimers()
			return nil

		case event, ok := <-fsw.Events:
			if !ok {
				stopTimers()
				return nil
			}

			name := filepath.Base(event.Name)

			// Determine what to do based on the event.
			isRemove := event.Op&(fsnotify.Remove|fsnotify.Rename) != 0
			isCreateOrWrite := event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Chmod) != 0

			if !isRemove && !isCreateOrWrite {
				continue
			}

			// For .json sidecar changes, trigger re-read of the parent hook.
			if strings.HasSuffix(name, ".json") {
				hookName := strings.TrimSuffix(name, ".json")
				if !isRemove {
					w.debounce(&timersMu, timers, hookName, func() {
						w.processFile(hookName)
					})
				}
				continue
			}

			if isRemove {
				w.debounce(&timersMu, timers, name, func() {
					w.removeHook(name)
				})
			} else {
				w.debounce(&timersMu, timers, name, func() {
					w.processFile(name)
				})
			}

		case err, ok := <-fsw.Errors:
			if !ok {
				stopTimers()
				return nil
			}
			w.logger.Warn("actions: watcher: fsnotify error", "error", err)
		}
	}
}

// Hooks returns a sorted snapshot of the current hooks.
func (w *HookWatcher) Hooks() []api.HookInfo {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sortedHooksLocked()
}

// Reload re-scans the hooks directory, replaces the list with the result and
// returns it. It reports through the same callbacks as a file event: onIntegrity
// once per hook whose digest changed, then onChange. It works with or without
// Watch running.
//
// A missing directory is an empty list. Any other failure to read the directory
// is returned, with the list left as it was and no callback fired.
func (w *HookWatcher) Reload() ([]api.HookInfo, error) {
	w.changeMu.Lock()
	defer w.changeMu.Unlock()
	return w.rescan()
}

// rescan is Reload's body. The caller holds changeMu.
func (w *HookWatcher) rescan() ([]api.HookInfo, error) {
	scanned, failed, err := scanHooks(w.hooksDir, w.logger, w.hashFile)
	if err != nil {
		return nil, fmt.Errorf("actions: watcher: scan %s: %w", w.hooksDir, err)
	}

	next := make(map[string]api.HookInfo, len(scanned)+len(failed))
	for _, h := range scanned {
		next[h.Name] = h
	}

	type digestChange struct{ name, oldChecksum, newChecksum string }
	var changes []digestChange

	w.mu.Lock()
	// A hook the scan could not read keeps its entry, as it does in processFile.
	// Dropping it would remove it from the executor and the capability manifest
	// on one transient read error, with no later event to bring it back.
	for _, name := range failed {
		if h, ok := w.hooks[name]; ok {
			next[name] = h
		}
	}
	for _, h := range scanned {
		if old, ok := w.hooks[h.Name]; ok && old.Checksum != h.Checksum {
			changes = append(changes, digestChange{h.Name, old.Checksum, h.Checksum})
		}
	}
	w.hooks = next
	hooks := w.sortedHooksLocked()
	w.mu.Unlock()

	if w.onIntegrity != nil {
		for _, c := range changes {
			w.onIntegrity(c.name, c.oldChecksum, c.newChecksum)
		}
	}
	w.onChange(hooks)
	return hooks, nil
}

// debounce resets or creates a per-file debounce timer. The timer runs fn under
// changeMu, so fn must not take it.
func (w *HookWatcher) debounce(timersMu *sync.Mutex, timers map[string]*time.Timer, name string, fn func()) {
	timersMu.Lock()
	defer timersMu.Unlock()

	if t, ok := timers[name]; ok {
		t.Stop()
	}
	timers[name] = time.AfterFunc(w.debouncePeriod, func() {
		w.changeMu.Lock()
		defer w.changeMu.Unlock()
		fn()
	})
}

// initialScan brings the list in line with the directory when Watch starts, so
// it also prunes a hook removed since an earlier Reload. A scan that fails still
// reports the current list once.
func (w *HookWatcher) initialScan() {
	w.changeMu.Lock()
	defer w.changeMu.Unlock()

	if _, err := w.rescan(); err != nil {
		w.logger.Warn("actions: watcher: initial scan failed", "error", err)
		w.onChange(w.Hooks())
	}
}

// processFile handles a file create/write/chmod event. It runs from debounce's
// timer, under changeMu.
func (w *HookWatcher) processFile(name string) {
	fullPath := filepath.Join(w.hooksDir, name)

	fi, err := os.Stat(fullPath)
	if err != nil {
		// A file that is gone was removed between event and processing. Any
		// other failure says nothing about the hook, and no later event would
		// bring back an entry dropped for it, so it stays, as it does in a scan.
		if errors.Is(err, fs.ErrNotExist) {
			w.removeHook(name)
			return
		}
		w.logger.Warn("actions: watcher: stat failed", "file", name, "error", err)
		return
	}

	// A file that stopped being a hook leaves the list, as it would at a
	// restart. Only regular files go on to the hash: opening a FIFO blocks until
	// a writer appears.
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		w.removeHook(name)
		return
	}

	if strings.HasSuffix(name, ".json") {
		return
	}

	checksum, err := w.hashFile(fullPath)
	if err != nil {
		w.logger.Warn("actions: watcher: hash failed", "file", name, "error", err)
		return
	}

	w.mu.Lock()
	existing, existed := w.hooks[name]
	if existed && existing.Checksum != checksum && w.onIntegrity != nil {
		w.mu.Unlock()
		w.onIntegrity(name, existing.Checksum, checksum)
		w.mu.Lock()
	}

	h := api.HookInfo{
		Name:     name,
		Source:   "local",
		Checksum: checksum,
	}

	// Load sidecar metadata.
	sidecarPath := fullPath + ".json"
	if data, err := readSidecar(sidecarPath); err == nil {
		var meta hookMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			w.logger.Warn("actions: watcher: sidecar parse failed", "file", sidecarPath, "error", err)
		} else {
			h.Description = meta.Description
			h.Parameters = meta.Parameters
			h.Timeout = meta.Timeout
			h.Sandbox = meta.Sandbox
		}
	}

	w.hooks[name] = h
	hooks := w.sortedHooksLocked()
	w.mu.Unlock()

	w.onChange(hooks)
}

// removeHook removes a hook from the map and notifies onChange. It is a no-op for
// a name the watcher does not list. It runs from debounce's timer, under changeMu.
func (w *HookWatcher) removeHook(name string) {
	w.mu.Lock()
	_, existed := w.hooks[name]
	if !existed {
		w.mu.Unlock()
		return
	}
	delete(w.hooks, name)
	hooks := w.sortedHooksLocked()
	w.mu.Unlock()

	w.onChange(hooks)
}

// sortedHooksLocked returns a sorted copy of the hooks map. Caller must hold w.mu.
func (w *HookWatcher) sortedHooksLocked() []api.HookInfo {
	hooks := make([]api.HookInfo, 0, len(w.hooks))
	for _, h := range w.hooks {
		hooks = append(hooks, h)
	}
	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Name < hooks[j].Name
	})
	return hooks
}
