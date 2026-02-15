package actions

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/plexsphere/plexd/internal/api"
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

	mu    sync.Mutex
	hooks map[string]api.HookInfo // name -> hook info
}

// NewHookWatcher creates a new HookWatcher.
func NewHookWatcher(hooksDir string, onChange HookChangeCallback, onIntegrity IntegrityAlertCallback, logger *slog.Logger) *HookWatcher {
	return &HookWatcher{
		hooksDir:       hooksDir,
		logger:         logger.With("component", "actions"),
		onChange:        onChange,
		onIntegrity:    onIntegrity,
		debouncePeriod: 200 * time.Millisecond,
		hooks:          make(map[string]api.HookInfo),
	}
}

// Watch monitors the hooks directory for changes. It blocks until ctx is cancelled.
// Returns nil on clean shutdown via context cancellation.
func (w *HookWatcher) Watch(ctx context.Context) error {
	if err := os.MkdirAll(w.hooksDir, 0o755); err != nil {
		return err
	}

	// Initial scan.
	w.initialScan()

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer fsw.Close()

	if err := fsw.Add(w.hooksDir); err != nil {
		return err
	}

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

// debounce resets or creates a per-file debounce timer.
func (w *HookWatcher) debounce(timersMu *sync.Mutex, timers map[string]*time.Timer, name string, fn func()) {
	timersMu.Lock()
	defer timersMu.Unlock()

	if t, ok := timers[name]; ok {
		t.Stop()
	}
	timers[name] = time.AfterFunc(w.debouncePeriod, fn)
}

// initialScan reads all hooks from the directory on startup.
func (w *HookWatcher) initialScan() {
	entries, err := os.ReadDir(w.hooksDir)
	if err != nil {
		w.logger.Warn("actions: watcher: initial scan failed", "error", err)
		w.onChange([]api.HookInfo{})
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			w.logger.Warn("actions: watcher: stat failed", "file", name, "error", err)
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			continue
		}
		w.loadHookFile(name)
	}

	w.mu.Lock()
	hooks := w.sortedHooksLocked()
	w.mu.Unlock()
	w.onChange(hooks)
}

// processFile handles a file create/write/chmod event.
func (w *HookWatcher) processFile(name string) {
	fullPath := filepath.Join(w.hooksDir, name)

	fi, err := os.Stat(fullPath)
	if err != nil {
		// File may have been removed between event and processing.
		w.removeHook(name)
		return
	}

	if fi.IsDir() {
		return
	}

	if fi.Mode().Perm()&0o111 == 0 {
		return
	}

	if strings.HasSuffix(name, ".json") {
		return
	}

	checksum, err := integrity.HashFile(fullPath)
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
	if data, err := os.ReadFile(sidecarPath); err == nil {
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

// loadHookFile hashes a hook file and stores it in the hooks map.
// Used during initial scan; does not call onChange (the caller batches notifications).
func (w *HookWatcher) loadHookFile(name string) {
	fullPath := filepath.Join(w.hooksDir, name)

	checksum, err := integrity.HashFile(fullPath)
	if err != nil {
		w.logger.Warn("actions: watcher: hash failed", "file", name, "error", err)
		return
	}

	h := api.HookInfo{
		Name:     name,
		Source:   "local",
		Checksum: checksum,
	}

	// Load sidecar metadata.
	sidecarPath := fullPath + ".json"
	if data, err := os.ReadFile(sidecarPath); err == nil {
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

	w.mu.Lock()
	w.hooks[name] = h
	w.mu.Unlock()
}

// removeHook removes a hook from the map and notifies onChange.
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
