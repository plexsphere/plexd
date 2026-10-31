//go:build unix

package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
	"github.com/plexsphere/plexd/internal/integrity"
)

// noopHookVerifier always returns verified=true for testing.
type noopHookVerifier struct{}

func (noopHookVerifier) VerifyHook(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func TestWatcher_InitialScan(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "alpha.sh", "#!/bin/sh\necho alpha\n")
	writeExecutable(t, dir, "beta.sh", "#!/bin/sh\necho beta\n")

	rec := &hookRecorder{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	_, initial := rec.waitFor(t, 0, anyHooks, "onChange was not called for initial scan")

	if len(initial) != 2 {
		t.Fatalf("initial scan hooks = %d, want 2", len(initial))
	}
	if initial[0].Name != "alpha.sh" {
		t.Errorf("hooks[0].Name = %q, want %q", initial[0].Name, "alpha.sh")
	}
	if initial[1].Name != "beta.sh" {
		t.Errorf("hooks[1].Name = %q, want %q", initial[1].Name, "beta.sh")
	}
	if initial[0].Source != "local" {
		t.Errorf("hooks[0].Source = %q, want %q", initial[0].Source, "local")
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_NewFileRegistered(t *testing.T) {
	dir := t.TempDir()

	rec := &hookRecorder{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	initial, _ := rec.waitFor(t, 0, anyHooks, "onChange was not called for initial scan")

	// Create executable file
	writeExecutable(t, dir, "new-hook", "#!/bin/sh\necho hello\n")

	_, hooks := rec.waitFor(t, initial+1, namesAre("new-hook"), "new-hook was not registered")
	if hooks[0].Source != "local" {
		t.Errorf("hook Source = %q, want %q", hooks[0].Source, "local")
	}
	if hooks[0].Checksum == "" {
		t.Error("hook Checksum is empty")
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_ModifiedFileUpdatesChecksum(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "myhook", "#!/bin/sh\necho v1\n")

	rec := &hookRecorder{}

	var intMu sync.Mutex
	var integrityAlerts []struct{ name, oldSum, newSum string }
	onIntegrity := func(hookName, oldChecksum, newChecksum string) {
		intMu.Lock()
		defer intMu.Unlock()
		integrityAlerts = append(integrityAlerts, struct{ name, oldSum, newSum string }{hookName, oldChecksum, newChecksum})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, rec.onChange, onIntegrity, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	initial, hooks := rec.waitFor(t, 0, namesAre("myhook"), "no initial scan callback")
	oldChecksum := hooks[0].Checksum

	// Modify the file
	writeExecutable(t, dir, "myhook", "#!/bin/sh\necho v2\n")

	// processFile calls onIntegrity before onChange, so the alert is recorded
	// by the time the updated hook is.
	rec.waitFor(t, initial+1, func(hooks []api.HookInfo) bool {
		return len(hooks) == 1 && hooks[0].Name == "myhook" && hooks[0].Checksum != oldChecksum
	}, "hook checksum was not updated after modification")

	intMu.Lock()
	if len(integrityAlerts) < 1 {
		intMu.Unlock()
		t.Fatal("onIntegrity was not called")
	}
	alert := integrityAlerts[0]
	intMu.Unlock()

	if alert.name != "myhook" {
		t.Errorf("integrity alert name = %q, want %q", alert.name, "myhook")
	}
	if alert.oldSum != oldChecksum {
		t.Errorf("integrity alert oldChecksum = %q, want %q", alert.oldSum, oldChecksum)
	}
	if alert.newSum == oldChecksum {
		t.Error("integrity alert newChecksum should differ from old")
	}

	// The watcher's state, not only a past callback, holds the new checksum.
	if hooks := w.Hooks(); len(hooks) != 1 || hooks[0].Checksum == oldChecksum {
		t.Error("hook checksum was not updated after modification")
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}

	// The last callback is what executor.SetHooks would be left holding.
	if last := rec.last(); len(last) != 1 || last[0].Checksum == oldChecksum {
		t.Errorf("last callback = %v, want myhook with a new checksum", last)
	}
}

func TestWatcher_DeletedFileUnregistered(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "to-delete", "#!/bin/sh\necho delete me\n")

	rec := &hookRecorder{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// The initial scan runs once the watch is in place, so a deletion from
	// here on is reported.
	initial, _ := rec.waitFor(t, 0, namesAre("to-delete"), "initial scan did not report to-delete")

	// Delete the file
	if err := os.Remove(filepath.Join(dir, "to-delete")); err != nil {
		t.Fatal(err)
	}

	rec.waitFor(t, initial+1, namesAre(), "onChange was not called with empty hooks after deletion")

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_ChangeDuringStartupNoticed(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "present-at-start", "#!/bin/sh\necho present\n")

	rec := &hookRecorder{}
	var once sync.Once
	onChange := func(hooks []api.HookInfo) {
		rec.onChange(hooks)
		// The first callback is the initial scan's, made before Watch's event
		// loop starts. A hook removed and a hook added here land where a
		// watcher that scans before it watches would never see them.
		once.Do(func() {
			if err := os.Remove(filepath.Join(dir, "present-at-start")); err != nil {
				t.Errorf("remove during startup: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "added-at-start"), []byte("#!/bin/sh\necho added\n"), 0o755); err != nil {
				t.Errorf("add during startup: %v", err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	initial, _ := rec.waitFor(t, 0, namesAre("present-at-start"), "initial scan did not report present-at-start")
	rec.waitFor(t, initial+1, namesAre("added-at-start"), "a hook removed and a hook added during startup were not both reported")

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

// vanishedHookError is the error fsnotify's kqueue backend (macOS and the BSDs)
// returns from Add when a file it listed in the directory is gone before it
// opens it.
func vanishedHookError(dir string) error {
	path := filepath.Join(dir, "vanished")
	return fmt.Errorf("%q: %w", path, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrNotExist})
}

func TestWatcher_RetriesWhenAHookVanishesDuringSetup(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "survivor", "#!/bin/sh\necho survivor\n")

	rec := &hookRecorder{}
	logs := &syncBuffer{}
	w := NewHookWatcher(dir, rec.onChange, nil, slog.New(slog.NewTextHandler(logs, nil)))
	w.watchDir = func(ctx context.Context, dir string, onRetry func(error)) (*fsnotify.Watcher, error) {
		onRetry(vanishedHookError(dir))
		return fsutil.WatchDir(ctx, dir, onRetry)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	initial, _ := rec.waitFor(t, 0, namesAre("survivor"), "initial scan did not run after the retried setup")

	writeExecutable(t, dir, "added-later", "#!/bin/sh\necho later\n")
	rec.waitFor(t, initial+1, namesAre("added-later", "survivor"), "a hook added after the retried setup was not reported")

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}

	want := `level=WARN msg="actions: watcher: a hook vanished while the watch was set up; retrying" component=actions error=`
	if got := logs.String(); !strings.Contains(got, want) {
		t.Errorf("log = %q, want it to contain %q", got, want)
	}
}

func TestWatcher_SetupErrorScansThenStops(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())
	setupErr := fmt.Errorf("%q: %w", dir, &fs.PathError{Op: "open", Path: dir, Err: fs.ErrPermission})
	w.watchDir = func(context.Context, string, func(error)) (*fsnotify.Watcher, error) {
		return nil, setupErr
	}

	// The timeout turns a Watch that bypasses the seam into a failure instead
	// of a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.Watch(ctx); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Watch() error = %v, want fs.ErrPermission", err)
	}
	// The hooks on disk are still reported once, as before the watch.
	if got := rec.count(); got != 1 {
		t.Fatalf("onChange calls = %d, want 1", got)
	}
	if got := hookNames(rec.last()); !slices.Equal(got, []string{"kept"}) {
		t.Errorf("hooks after a failed set-up = %v, want [kept]", got)
	}
}

func TestWatcher_CancelDuringSetup(t *testing.T) {
	dir := t.TempDir()

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	// The timeout turns a Watch that bypasses the seam into a failure instead
	// of a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	called := false
	w.watchDir = func(ctx context.Context, _ string, _ func(error)) (*fsnotify.Watcher, error) {
		called = true
		cancel()
		return nil, ctx.Err()
	}

	if err := w.Watch(ctx); err != nil {
		t.Fatalf("Watch() error = %v, want nil", err)
	}
	if !called {
		t.Fatal("Watch did not set up its watch through w.watchDir")
	}
	if got := rec.count(); got != 0 {
		t.Errorf("onChange calls = %d, want 0", got)
	}
}

func TestWatcher_NonExecutableIgnored(t *testing.T) {
	dir := t.TempDir()

	var mu sync.Mutex
	var received [][]api.HookInfo
	onChange := func(hooks []api.HookInfo) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]api.HookInfo, len(hooks))
		copy(cp, hooks)
		received = append(received, cp)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Wait for initial scan
	time.Sleep(200 * time.Millisecond)

	// Create non-executable file
	if err := os.WriteFile(filepath.Join(dir, "not-executable"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Wait for debounce + processing
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	for _, hooks := range received {
		for _, h := range hooks {
			if h.Name == "not-executable" {
				mu.Unlock()
				t.Fatal("non-executable file was registered as hook")
			}
		}
	}
	mu.Unlock()

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_JsonSidecarIgnored(t *testing.T) {
	dir := t.TempDir()

	var mu sync.Mutex
	var received [][]api.HookInfo
	onChange := func(hooks []api.HookInfo) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]api.HookInfo, len(hooks))
		copy(cp, hooks)
		received = append(received, cp)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Wait for initial scan
	time.Sleep(200 * time.Millisecond)

	// Create an executable .json file
	writeExecutable(t, dir, "something.json", `{"description": "sidecar"}`)

	// Wait for debounce + processing
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	for _, hooks := range received {
		for _, h := range hooks {
			if h.Name == "something.json" {
				mu.Unlock()
				t.Fatal(".json file was registered as hook")
			}
		}
	}
	mu.Unlock()

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_ShutdownClean(t *testing.T) {
	dir := t.TempDir()

	onChange := func(hooks []api.HookInfo) {}

	ctx, cancel := context.WithCancel(context.Background())

	w := NewHookWatcher(dir, onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Let watcher start
	time.Sleep(100 * time.Millisecond)

	cancel()

	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit after context cancellation")
	}

	// goleak via TestMain verifies no goroutine leaks
}

func TestWatcher_Debounce(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "debounce-hook", "#!/bin/sh\necho v0\n")

	var mu sync.Mutex
	callCount := 0
	onChange := func(hooks []api.HookInfo) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Wait for initial scan
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	countAfterInit := callCount
	mu.Unlock()

	// Write to the file multiple times rapidly
	for i := 0; i < 10; i++ {
		writeExecutable(t, dir, "debounce-hook", "#!/bin/sh\necho v"+string(rune('1'+i))+"\n")
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for debounce to settle
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	callsAfterWrites := callCount - countAfterInit
	mu.Unlock()

	// We wrote 10 times but with debounce, onChange should have been called
	// fewer than 10 times.
	if callsAfterWrites >= 10 {
		t.Errorf("onChange called %d times after 10 rapid writes, expected fewer (debounce not working)", callsAfterWrites)
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_SidecarUpdate(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "deploy.sh", "#!/bin/sh\necho deploy\n")

	// Create initial sidecar
	meta := hookMetadata{Description: "Initial description"}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.sh.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	rec := &hookRecorder{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	initial, hooks := rec.waitFor(t, 0, namesAre("deploy.sh"), "no initial scan callback")
	if hooks[0].Description != "Initial description" {
		t.Fatalf("initial description = %q, want %q", hooks[0].Description, "Initial description")
	}

	// Update sidecar
	meta2 := hookMetadata{Description: "Updated description"}
	data2, err := json.Marshal(meta2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.sh.json"), data2, 0o644); err != nil {
		t.Fatal(err)
	}

	rec.waitFor(t, initial+1, func(hooks []api.HookInfo) bool {
		return len(hooks) == 1 && hooks[0].Name == "deploy.sh" && hooks[0].Description == "Updated description"
	}, `description after sidecar update was not reported as "Updated description"`)

	// The watcher's state, not only a past callback, holds the update.
	hooks = w.Hooks()
	if len(hooks) != 1 || hooks[0].Description != "Updated description" {
		t.Errorf("description after sidecar update = %v, want %q", hooks, "Updated description")
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}

	// The last callback is what executor.SetHooks would be left holding.
	if last := rec.last(); len(last) != 1 || last[0].Description != "Updated description" {
		t.Errorf("description in the last callback = %v, want %q", last, "Updated description")
	}
}

func TestWatcher_FullLifecycle(t *testing.T) {
	dir := t.TempDir()

	rec := &hookRecorder{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Initial scan (empty dir).
	i, initial := rec.waitFor(t, 0, anyHooks, "no initial callback")
	if len(initial) != 0 {
		t.Fatalf("initial hooks = %v, want empty", hookNames(initial))
	}

	// Phase 1: Add hook-a.
	writeExecutable(t, dir, "hook-a", "#!/bin/sh\necho a\n")
	i, _ = rec.waitFor(t, i+1, namesAre("hook-a"), "after adding hook-a, hooks are not [hook-a]")

	// Phase 2: Add hook-b.
	writeExecutable(t, dir, "hook-b", "#!/bin/sh\necho b\n")
	i, hooks := rec.waitFor(t, i+1, namesAre("hook-a", "hook-b"), "after adding hook-b, hooks are not [hook-a hook-b]")
	checksumA := hooks[0].Checksum

	// Phase 3: Modify hook-a.
	writeExecutable(t, dir, "hook-a", "#!/bin/sh\necho a-v2\n")
	i, _ = rec.waitFor(t, i+1, func(hooks []api.HookInfo) bool {
		return slices.Equal(hookNames(hooks), []string{"hook-a", "hook-b"}) && hooks[0].Checksum != checksumA
	}, "after modifying hook-a, hooks are not [hook-a hook-b] with hook-a's new checksum")

	// Phase 4: Remove hook-a.
	if err := os.Remove(filepath.Join(dir, "hook-a")); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, i+1, namesAre("hook-b"), "after removing hook-a, hooks are not [hook-b]")
	if got := hookNames(w.Hooks()); !slices.Equal(got, []string{"hook-b"}) {
		t.Fatalf("after removing hook-a, Hooks() = %v, want [hook-b]", got)
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}

	// The last callback is what executor.SetHooks would be left holding.
	if got := hookNames(rec.last()); !slices.Equal(got, []string{"hook-b"}) {
		t.Errorf("last callback = %v, want [hook-b]", got)
	}
}

func TestWatcher_CapabilitiesReReport(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{Enabled: boolPtr(true), HooksDir: dir}
	cfg.ApplyDefaults()

	executor := NewExecutor(cfg, &mockReporter{}, noopHookVerifier{}, testLogger())
	executor.RegisterBuiltin("health_check", "Check health", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "ok", "", 0, nil
	})

	// Verify initial state: only builtins, no hooks.
	builtins, hooks := executor.Capabilities()
	if len(builtins) != 1 {
		t.Fatalf("initial builtins = %d, want 1", len(builtins))
	}
	if len(hooks) != 0 {
		t.Fatalf("initial hooks = %d, want 0", len(hooks))
	}

	// Wire the watcher to executor.SetHooks (same as up.go wiring).
	w := NewHookWatcher(dir, executor.SetHooks, nil, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Add a hook. Written before the watch is in place, it is in the initial
	// scan, which runs after the watch; written after, it arrives as an event.
	writeExecutable(t, dir, "deploy", "#!/bin/sh\necho deploying\n")
	waitFor(t, 5*time.Second, func() bool {
		_, hooks := executor.Capabilities()
		return len(hooks) == 1
	})

	// Verify capabilities now include the hook.
	builtins, hooks = executor.Capabilities()
	if len(builtins) != 1 {
		t.Errorf("builtins after hook add = %d, want 1", len(builtins))
	}
	if len(hooks) != 1 {
		t.Fatalf("hooks after hook add = %d, want 1", len(hooks))
	}
	if hooks[0].Name != "deploy" {
		t.Errorf("hook name = %q, want %q", hooks[0].Name, "deploy")
	}

	// Remove the hook. Capabilities lists it, so the watch is in place.
	if err := os.Remove(filepath.Join(dir, "deploy")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		_, hooks := executor.Capabilities()
		return len(hooks) == 0
	})

	// Verify capabilities no longer include the hook.
	builtins, hooks = executor.Capabilities()
	if len(builtins) != 1 {
		t.Errorf("builtins after hook remove = %d, want 1", len(builtins))
	}
	if len(hooks) != 0 {
		t.Errorf("hooks after hook remove = %d, want 0", len(hooks))
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_HooksSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "charlie", "#!/bin/sh\necho charlie\n")
	writeExecutable(t, dir, "alpha", "#!/bin/sh\necho alpha\n")
	writeExecutable(t, dir, "bravo", "#!/bin/sh\necho bravo\n")

	rec := &hookRecorder{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// The initial scan fills the map before its callback.
	rec.waitFor(t, 0, anyHooks, "onChange was not called for initial scan")

	hooks := w.Hooks()
	if len(hooks) != 3 {
		t.Fatalf("Hooks() len = %d, want 3", len(hooks))
	}
	if hooks[0].Name != "alpha" {
		t.Errorf("hooks[0].Name = %q, want %q", hooks[0].Name, "alpha")
	}
	if hooks[1].Name != "bravo" {
		t.Errorf("hooks[1].Name = %q, want %q", hooks[1].Name, "bravo")
	}
	if hooks[2].Name != "charlie" {
		t.Errorf("hooks[2].Name = %q, want %q", hooks[2].Name, "charlie")
	}

	// Verify checksums are present
	for _, h := range hooks {
		if h.Checksum == "" {
			t.Errorf("hook %q has empty checksum", h.Name)
		}
		wantChecksum, err := integrity.HashFile(filepath.Join(dir, h.Name))
		if err != nil {
			t.Fatalf("HashFile(%q) error = %v", h.Name, err)
		}
		if h.Checksum != wantChecksum {
			t.Errorf("hook %q checksum = %q, want %q", h.Name, h.Checksum, wantChecksum)
		}
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}

func TestWatcher_ReloadFindsAHookWrittenWithNoWatchRunning(t *testing.T) {
	dir := t.TempDir()

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	path := writeExecutable(t, dir, "deploy", "#!/bin/sh\necho deploy\n")
	want, err := integrity.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	hooks, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	wantHooks(t, "Reload()", hooks, "deploy")
	if hooks[0].Checksum != want {
		t.Errorf("checksum = %q, want %q", hooks[0].Checksum, want)
	}
	wantHooks(t, "Hooks()", w.Hooks(), "deploy")
	if got := rec.count(); got != 1 {
		t.Fatalf("onChange calls = %d, want 1", got)
	}
	wantHooks(t, "onChange", rec.last(), "deploy")
}

func TestWatcher_ReloadDropsAHookDeletedWithNoWatchRunning(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "deleted", "#!/bin/sh\necho deleted\n")
	writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	hooks, err := w.Reload()
	if err != nil {
		t.Fatalf("first Reload() error = %v", err)
	}
	wantHooks(t, "first Reload()", hooks, "deleted", "kept")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	hooks, err = w.Reload()
	if err != nil {
		t.Fatalf("second Reload() error = %v", err)
	}
	wantHooks(t, "second Reload()", hooks, "kept")
	wantHooks(t, "Hooks()", w.Hooks(), "kept")
	wantHooks(t, "onChange", rec.last(), "kept")
}

// hashingVerifier is a HookVerifier that hashes the hook file, as
// integrity.Verifier does, and records the digest each run was verified against.
type hashingVerifier struct {
	mu       sync.Mutex
	expected []string
}

func (v *hashingVerifier) VerifyHook(_ context.Context, _, hookPath, expectedChecksum string) (bool, error) {
	v.mu.Lock()
	v.expected = append(v.expected, expectedChecksum)
	v.mu.Unlock()

	result, err := integrity.VerifyFile(hookPath, expectedChecksum, true)
	if err != nil {
		return false, err
	}
	return result.OK, nil
}

func (v *hashingVerifier) expectedChecksums() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.expected)
}

func TestWatcher_ReloadOfAnEditedHookReportsTheNewDigestAndLeavesThePin(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "deploy", "#!/bin/sh\necho v1\n")
	first, err := integrity.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Enabled: boolPtr(true), HooksDir: dir}
	cfg.ApplyDefaults()
	reporter := &mockReporter{}
	verifier := &hashingVerifier{}
	executor := NewExecutor(cfg, reporter, verifier, testLogger())

	alerts := &integrityRecorder{}
	w := NewHookWatcher(dir, executor.SetHooks, alerts.onIntegrity, testLogger())

	// The first reload pins the digest, as the boot scan does.
	if _, err := w.Reload(); err != nil {
		t.Fatalf("first Reload() error = %v", err)
	}
	if got := alerts.all(); len(got) != 0 {
		t.Fatalf("alerts after the first reload = %v, want none", got)
	}

	writeExecutable(t, dir, "deploy", "#!/bin/sh\necho v2\n")
	edited, err := integrity.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	hooks, err := w.Reload()
	if err != nil {
		t.Fatalf("second Reload() error = %v", err)
	}
	wantHooks(t, "second Reload()", hooks, "deploy")
	if hooks[0].Checksum != edited {
		t.Errorf("reloaded checksum = %q, want the edited digest %q", hooks[0].Checksum, edited)
	}
	want := []integrityAlert{{"deploy", first, edited}}
	if got := alerts.all(); !slices.Equal(got, want) {
		t.Errorf("alerts = %v, want %v", got, want)
	}

	// The manifest reads the live digest, which is how the control plane sees
	// the drift.
	if _, reported := executor.Capabilities(); len(reported) != 1 || reported[0].Checksum != edited {
		t.Errorf("Capabilities() hooks = %v, want deploy with the edited digest", reported)
	}

	mustExecute(t, executor, "node-1", pendingHookExec("exec-edited", "deploy"))
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed})
	wantErr := "integrity check failed for hook: deploy"
	if got := cbs[len(cbs)-1].Error; !strings.Contains(got, wantErr) {
		t.Errorf("terminal error = %q, want it to contain %q", got, wantErr)
	}
	if got := verifier.expectedChecksums(); !slices.Equal(got, []string{first}) {
		t.Errorf("verified against %v, want the first digest %q", got, first)
	}

	// A reload that finds nothing new raises no second alert.
	if _, err := w.Reload(); err != nil {
		t.Fatalf("third Reload() error = %v", err)
	}
	if got := alerts.all(); len(got) != 1 {
		t.Errorf("alerts after a reload with no edit = %v, want the one from the edit", got)
	}
}

// replaceWithFile swaps the directory at dir for a regular file, so reading it
// fails with ENOTDIR.
func replaceWithFile(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWatcher_ReloadErrorLeavesTheListAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hooks")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, dir, "deploy", "#!/bin/sh\necho deploy\n")

	rec := &hookRecorder{}
	alerts := &integrityRecorder{}
	w := NewHookWatcher(dir, rec.onChange, alerts.onIntegrity, testLogger())

	before, err := w.Reload()
	if err != nil {
		t.Fatalf("first Reload() error = %v", err)
	}
	wantHooks(t, "first Reload()", before, "deploy")
	calls := rec.count()

	replaceWithFile(t, dir)

	hooks, err := w.Reload()
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("Reload() error = %v, want ENOTDIR", err)
	}
	if want := "actions: watcher: scan " + dir + ": "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Reload() error = %q, want the prefix %q", err, want)
	}
	if hooks != nil {
		t.Errorf("Reload() hooks = %v, want nil", hooks)
	}
	if got := w.Hooks(); !reflect.DeepEqual(got, before) {
		t.Errorf("Hooks() after the failed scan = %v, want %v", got, before)
	}
	if got := rec.count(); got != calls {
		t.Errorf("onChange calls = %d, want %d: a failed scan fires no callback", got, calls)
	}
	if got := alerts.all(); len(got) != 0 {
		t.Errorf("alerts = %v, want none", got)
	}
}

func TestWatcher_ReloadOfAMissingDirectoryIsAnEmptyList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hooks")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, dir, "deploy", "#!/bin/sh\necho deploy\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	if _, err := w.Reload(); err != nil {
		t.Fatalf("first Reload() error = %v", err)
	}
	wantHooks(t, "Hooks() before the directory is removed", w.Hooks(), "deploy")

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	hooks, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v, want nil", err)
	}
	if hooks == nil {
		t.Fatal("Reload() hooks = nil, want a non-nil empty list")
	}
	wantHooks(t, "Reload()", hooks)
	wantHooks(t, "Hooks()", w.Hooks())
	if got := rec.count(); got != 2 {
		t.Fatalf("onChange calls = %d, want 2", got)
	}
	wantHooks(t, "onChange", rec.last())
}

func TestWatcher_ReloadKeepsAHookThatFailsToHash(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "flaky", "#!/bin/sh\necho flaky\n")
	if err := os.WriteFile(filepath.Join(dir, "flaky.json"), []byte(`{"description":"from the sidecar"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, dir, "steady", "#!/bin/sh\necho steady\n")

	rec := &hookRecorder{}
	alerts := &integrityRecorder{}
	logs := &syncBuffer{}
	w := NewHookWatcher(dir, rec.onChange, alerts.onIntegrity, slog.New(slog.NewTextHandler(logs, nil)))

	before, err := w.Reload()
	if err != nil {
		t.Fatalf("first Reload() error = %v", err)
	}
	wantHooks(t, "first Reload()", before, "flaky", "steady")
	flaky := before[0]
	if flaky.Description != "from the sidecar" {
		t.Fatalf("description = %q, want the sidecar's", flaky.Description)
	}

	// flaky is edited too, so a retained entry cannot be told from a fresh one
	// by accident. never-listed has no entry to keep.
	writeExecutable(t, dir, "flaky", "#!/bin/sh\necho edited\n")
	writeExecutable(t, dir, "never-listed", "#!/bin/sh\necho never\n")
	writeExecutable(t, dir, "added", "#!/bin/sh\necho added\n")
	w.hashFile = func(path string) (string, error) {
		switch filepath.Base(path) {
		case "flaky", "never-listed":
			return "", fmt.Errorf("read %s: %w", path, syscall.EIO)
		}
		return integrity.HashFile(path)
	}

	hooks, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	wantHooks(t, "Reload()", hooks, "added", "flaky", "steady")
	if !reflect.DeepEqual(hooks[1], flaky) {
		t.Errorf("flaky after a failed hash = %+v, want the previous entry %+v", hooks[1], flaky)
	}
	wantHooks(t, "onChange", rec.last(), "added", "flaky", "steady")
	if got := alerts.all(); len(got) != 0 {
		t.Errorf("alerts = %v, want none: an unread hook has no new digest", got)
	}
	for _, file := range []string{"flaky", "never-listed"} {
		want := `level=WARN msg="actions: discovery: hash failed" component=actions file=` + file + " "
		if got := logs.String(); !strings.Contains(got, want) {
			t.Errorf("log = %q, want it to contain %q", got, want)
		}
	}
}

func TestWatcher_ReloadDropsAFileThatVanishesDuringTheScan(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "steady", "#!/bin/sh\necho steady\n")
	writeExecutable(t, dir, "vanishing", "#!/bin/sh\necho vanishing\n")

	logs := &syncBuffer{}
	w := NewHookWatcher(dir, (&hookRecorder{}).onChange, nil, slog.New(slog.NewTextHandler(logs, nil)))

	hooks, err := w.Reload()
	if err != nil {
		t.Fatalf("first Reload() error = %v", err)
	}
	wantHooks(t, "first Reload()", hooks, "steady", "vanishing")

	// The file goes away after the directory was listed and stat'ed, so only
	// the hash notices.
	w.hashFile = func(path string) (string, error) {
		if filepath.Base(path) == "vanishing" {
			if err := os.Remove(path); err != nil {
				t.Errorf("remove during the scan: %v", err)
			}
		}
		return integrity.HashFile(path)
	}

	hooks, err = w.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	wantHooks(t, "Reload()", hooks, "steady")
	if got := logs.String(); strings.Contains(got, "hash failed") {
		t.Errorf("log = %q, want no hash warning for a file that is gone", got)
	}
}

func TestWatcher_ProcessFileKeepsAHookThatFailsToHash(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "deploy", "#!/bin/sh\necho v1\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	before, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	calls := rec.count()

	writeExecutable(t, dir, "deploy", "#!/bin/sh\necho v2\n")
	w.hashFile = func(string) (string, error) {
		return "", fmt.Errorf("read %s: %w", path, syscall.EIO)
	}
	w.processFile("deploy")

	if got := w.Hooks(); !reflect.DeepEqual(got, before) {
		t.Errorf("Hooks() after a failed hash = %v, want %v", got, before)
	}
	if got := rec.count(); got != calls {
		t.Errorf("onChange calls = %d, want %d", got, calls)
	}
}

// Only a file that is gone leaves the list. A link to itself fails the stat with
// ELOOP, which stands for any failure that says nothing about the hook and, unlike
// a permission error, also fails for root.
func TestWatcher_ProcessFileRemovesOnlyAHookThatIsGone(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "deploy", "#!/bin/sh\necho v1\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	before, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	calls := rec.count()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, path); err != nil {
		t.Fatal(err)
	}
	w.processFile("deploy")

	if got := w.Hooks(); !reflect.DeepEqual(got, before) {
		t.Errorf("Hooks() after a failed stat = %v, want %v", got, before)
	}
	if got := rec.count(); got != calls {
		t.Errorf("onChange calls = %d, want %d", got, calls)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.processFile("deploy")

	wantHooks(t, "Hooks() after the file went", w.Hooks())
}

// A scan and a file event judge a symlink by the same mode. If they disagreed, the
// list would flip with whichever saw the link last, and every flip is a PUT.
func TestWatcher_ScanAndFileEventAgreeOnASymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeExecutable(t, t.TempDir(), "real", "#!/bin/sh\necho real\n")
	if err := os.Symlink(target, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}

	w := NewHookWatcher(dir, func([]api.HookInfo) {}, nil, testLogger())

	for _, tc := range []struct {
		name string
		mode os.FileMode
		want []string
	}{
		{"executable target", 0o755, []string{"linked"}},
		{"target lost its executable bit", 0o644, nil},
		{"target got it back", 0o755, []string{"linked"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(target, tc.mode); err != nil {
				t.Fatal(err)
			}

			hooks, err := w.Reload()
			if err != nil {
				t.Fatalf("Reload() error = %v", err)
			}
			wantHooks(t, "Reload()", hooks, tc.want...)

			w.processFile("linked")
			wantHooks(t, "Hooks() after a file event", w.Hooks(), tc.want...)
		})
	}
}

func TestWatcher_InitialScanPrunesAHookDeletedAfterAReload(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "deleted", "#!/bin/sh\necho deleted\n")
	writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())

	hooks, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	wantHooks(t, "Reload()", hooks, "deleted", "kept")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	startWatch(t, w)

	_, initial := rec.waitFor(t, 1, anyHooks, "onChange was not called for the initial scan")
	wantHooks(t, "the initial scan's onChange", initial, "kept")
	wantHooks(t, "Hooks()", w.Hooks(), "kept")
}

func TestWatcher_InitialScanFailureReportsTheCurrentList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hooks")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, dir, "deploy", "#!/bin/sh\necho deploy\n")

	rec := &hookRecorder{}
	logs := &syncBuffer{}
	w := NewHookWatcher(dir, rec.onChange, nil, slog.New(slog.NewTextHandler(logs, nil)))

	if _, err := w.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	calls := rec.count()

	replaceWithFile(t, dir)
	w.initialScan()

	if got := rec.count(); got != calls+1 {
		t.Fatalf("onChange calls = %d, want %d", got, calls+1)
	}
	wantHooks(t, "onChange", rec.last(), "deploy")
	want := `level=WARN msg="actions: watcher: initial scan failed" component=actions error=`
	if got := logs.String(); !strings.Contains(got, want) {
		t.Errorf("log = %q, want it to contain %q", got, want)
	}
}

func TestWatcher_ClearedExecutableBitLeavesTheList(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "cleared", "#!/bin/sh\necho cleared\n")
	writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())
	w.debouncePeriod = time.Millisecond

	startWatch(t, w)

	initial, _ := rec.waitFor(t, 0, namesAre("cleared", "kept"), "initial scan did not report both hooks")

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	rec.waitFor(t, initial+1, namesAre("kept"), "a hook that lost its executable bit stayed listed")
	wantHooks(t, "Hooks()", w.Hooks(), "kept")
}

func TestWatcher_HookReplacedByAFIFOLeavesTheList(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "replaced", "#!/bin/sh\necho replaced\n")
	writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")

	rec := &hookRecorder{}
	w := NewHookWatcher(dir, rec.onChange, nil, testLogger())
	w.debouncePeriod = time.Millisecond
	// Opening the FIFO would block until a writer appears, so the seam turns a
	// watcher that hashes it into a failure instead of a hang.
	w.hashFile = func(path string) (string, error) {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&fs.ModeNamedPipe != 0 {
			t.Errorf("hashed the FIFO at %s", path)
			return "", errors.New("refusing to open a FIFO")
		}
		return integrity.HashFile(path)
	}

	startWatch(t, w)

	initial, _ := rec.waitFor(t, 0, namesAre("kept", "replaced"), "initial scan did not report both hooks")

	// A rename over the hook leaves the name in place, so on inotify the only
	// event is the one that sends processFile to the FIFO.
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fifo, path); err != nil {
		t.Fatal(err)
	}

	rec.waitFor(t, initial+1, namesAre("kept"), "a hook replaced by a FIFO stayed listed")
	wantHooks(t, "Hooks()", w.Hooks(), "kept")
}

func TestWatcher_ReloadSkipsAnExecutableFIFO(t *testing.T) {
	tests := []struct {
		name string
		fifo string
	}{
		{name: "in place of a hook", fifo: "pipe"},
		{name: "in place of a sidecar", fifo: "kept.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")
			fifo := filepath.Join(dir, tt.fifo)
			if err := syscall.Mkfifo(fifo, 0o755); err != nil {
				t.Fatal(err)
			}

			w := NewHookWatcher(dir, (&hookRecorder{}).onChange, nil, testLogger())

			type result struct {
				hooks []api.HookInfo
				err   error
			}
			done := make(chan result, 1)
			go func() {
				hooks, err := w.Reload()
				done <- result{hooks, err}
			}()

			select {
			case res := <-done:
				if res.err != nil {
					t.Fatalf("Reload() error = %v", res.err)
				}
				wantHooks(t, "Reload()", res.hooks, "kept")
			case <-time.After(5 * time.Second):
				// Becoming the FIFO's writer ends the blocked read, so the
				// leak check does not report this failure a second time.
				if f, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
					_ = f.Close()
				}
				<-done
				t.Fatal("Reload blocked on a FIFO")
			}
		})
	}
}

// processFile reads the sidecar with mu and changeMu held, so a read that blocks
// would stop every later event and every reload behind it.
func TestWatcher_ProcessFileSkipsAFIFOSidecar(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")
	fifo := filepath.Join(dir, "kept.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewHookWatcher(dir, (&hookRecorder{}).onChange, nil, testLogger())

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.processFile("kept")
	}()

	select {
	case <-done:
		wantHooks(t, "Hooks()", w.Hooks(), "kept")
	case <-time.After(5 * time.Second):
		// Becoming the FIFO's writer ends the blocked read, so the leak check
		// does not report this failure a second time.
		if f, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
			_ = f.Close()
		}
		<-done
		t.Fatal("processFile blocked on a FIFO sidecar")
	}
}

// TestWatcher_LastOnChangeCarriesTheNewestList holds one delivery back while
// more hooks change and a Reload runs around it. Without changeMu the writers
// around it deliver newer lists first, and the list held back lands last and
// stays in the executor. Each case holds back a different writer, because each
// takes changeMu in a place of its own.
func TestWatcher_LastOnChangeCarriesTheNewestList(t *testing.T) {
	// stallBound is how long the held delivery waits for the writers around it.
	// With changeMu in place they cannot finish first, so a passing run waits
	// all of it. A host too slow to finish in time can only hide a missing lock,
	// never fail a correct build.
	const stallBound = 50 * time.Millisecond
	// deadlock bounds waits that end at once unless the watcher is stuck.
	const deadlock = 30 * time.Second
	const changedHooks = 16

	type startTimer func(name string, fn func())

	tests := []struct {
		name string
		// write starts the writer whose delivery is held back.
		write func(t *testing.T, w *HookWatcher, onTimer startTimer)
	}{
		{
			name: "file event",
			write: func(_ *testing.T, w *HookWatcher, onTimer startTimer) {
				onTimer("first", func() { w.processFile("first") })
			},
		},
		{
			name: "reload",
			write: func(t *testing.T, w *HookWatcher, _ startTimer) {
				if _, err := w.Reload(); err != nil {
					t.Errorf("Reload() error = %v", err)
				}
			},
		},
		{
			name: "initial scan",
			write: func(_ *testing.T, w *HookWatcher, _ startTimer) {
				w.initialScan()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			doomed := writeExecutable(t, dir, "doomed", "#!/bin/sh\necho doomed\n")
			writeExecutable(t, dir, "kept", "#!/bin/sh\necho kept\n")

			rec := &hookRecorder{}
			var armed atomic.Bool
			var heldBack []string
			stalled := make(chan struct{})
			release := make(chan struct{})
			delivered := make(chan struct{})
			onChange := func(hooks []api.HookInfo) {
				if !armed.CompareAndSwap(true, false) {
					rec.onChange(hooks)
					return
				}
				heldBack = hookNames(hooks)
				close(stalled)
				<-release
				rec.onChange(hooks)
				close(delivered)
			}

			w := NewHookWatcher(dir, onChange, nil, testLogger())
			w.debouncePeriod = time.Millisecond
			if _, err := w.Reload(); err != nil {
				t.Fatalf("Reload() error = %v", err)
			}

			// The timers run through w.debounce, as Watch's event loop has them
			// run, which is where changeMu is taken for a file event. Driving it
			// directly fixes how many there are, which fsnotify would not.
			var timersMu sync.Mutex
			timers := make(map[string]*time.Timer)
			onTimer := func(name string, fn func()) {
				w.debounce(&timersMu, timers, name, fn)
			}

			writeExecutable(t, dir, "first", "#!/bin/sh\necho first\n")
			armed.Store(true)
			go tt.write(t, w, onTimer)
			select {
			case <-stalled:
			case <-time.After(deadlock):
				t.Fatal("no delivery reached the stall")
			}

			// The held delivery predates all of this.
			var around sync.WaitGroup
			want := []string{"first"}
			if err := os.Remove(doomed); err != nil {
				t.Fatal(err)
			}
			around.Add(1)
			onTimer("doomed", func() {
				defer around.Done()
				w.removeHook("doomed")
			})
			for i := range changedHooks {
				name := fmt.Sprintf("hook-%02d", i)
				writeExecutable(t, dir, name, "#!/bin/sh\necho "+name+"\n")
				want = append(want, name)
				around.Add(1)
				onTimer(name, func() {
					defer around.Done()
					w.processFile(name)
				})
			}
			want = append(want, "kept")
			around.Add(1)
			go func() {
				defer around.Done()
				if _, err := w.Reload(); err != nil {
					t.Errorf("Reload() error = %v", err)
				}
			}()

			settled := make(chan struct{})
			go func() {
				around.Wait()
				close(settled)
			}()
			select {
			case <-settled:
			case <-time.After(stallBound):
			}
			close(release)

			for _, done := range []<-chan struct{}{delivered, settled} {
				select {
				case <-done:
				case <-time.After(deadlock):
					t.Fatal("the writers did not finish")
				}
			}

			// The stall is only a test of ordering while the list it holds is
			// older than the final one.
			if !slices.Equal(heldBack, []string{"doomed", "first", "kept"}) {
				t.Fatalf("held-back list = %v, want [doomed first kept]", heldBack)
			}
			wantHooks(t, "the last onChange", rec.last(), want...)
			wantHooks(t, "Hooks()", w.Hooks(), want...)
		})
	}
}

// startWatch runs w.Watch until the test ends. A test that needs the watch to
// be in place waits for the initial scan's callback, which comes after it.
func startWatch(t *testing.T, w *HookWatcher) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Watch(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Watch() error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("watcher did not exit")
		}
	})
}

// wantHooks fails the test unless hooks carries exactly the names in want, in
// that order. No names accepts an empty list.
func wantHooks(t *testing.T, what string, hooks []api.HookInfo, want ...string) {
	t.Helper()
	if got := hookNames(hooks); !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// integrityAlert is one onIntegrity call.
type integrityAlert struct {
	name, oldChecksum, newChecksum string
}

// integrityRecorder is an onIntegrity callback that records every alert a
// HookWatcher raises, in call order.
type integrityRecorder struct {
	mu     sync.Mutex
	alerts []integrityAlert
}

func (r *integrityRecorder) onIntegrity(name, oldChecksum, newChecksum string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, integrityAlert{name, oldChecksum, newChecksum})
}

func (r *integrityRecorder) all() []integrityAlert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.alerts)
}

// hookRecorder is an onChange callback that records every hook list a
// HookWatcher reports, in call order.
type hookRecorder struct {
	mu    sync.Mutex
	calls [][]api.HookInfo
}

func (r *hookRecorder) onChange(hooks []api.HookInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, slices.Clone(hooks))
}

func (r *hookRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// last returns the newest callback, or nil before the first.
func (r *hookRecorder) last() []api.HookInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return nil
	}
	return r.calls[len(r.calls)-1]
}

// waitFor waits up to 5 s for a callback at index from or later that match
// accepts, and returns its index and hook list. Otherwise it fails the test
// with msg and the hook names of the last callback.
func (r *hookRecorder) waitFor(t *testing.T, from int, match func([]api.HookInfo) bool, msg string) (int, []api.HookInfo) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		for i := from; i < len(r.calls); i++ {
			if match(r.calls[i]) {
				hooks := r.calls[i]
				r.mu.Unlock()
				return i, hooks
			}
		}
		last := "none"
		if n := len(r.calls); n > 0 {
			last = fmt.Sprint(hookNames(r.calls[n-1]))
		}
		r.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("%s (last callback: %s)", msg, last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// anyHooks accepts every callback.
func anyHooks([]api.HookInfo) bool { return true }

// namesAre accepts a callback whose hook names are exactly want, in order. No
// names accepts an empty hook list.
func namesAre(want ...string) func([]api.HookInfo) bool {
	return func(hooks []api.HookInfo) bool {
		return slices.Equal(hookNames(hooks), want)
	}
}

func hookNames(hooks []api.HookInfo) []string {
	names := make([]string, len(hooks))
	for i, h := range hooks {
		names[i] = h.Name
	}
	return names
}

// syncBuffer is a bytes.Buffer that is safe to write from the watcher's
// goroutines while a test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
