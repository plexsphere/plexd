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
	"slices"
	"strings"
	"sync"
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

	mu.Lock()
	defer mu.Unlock()

	if len(received) < 1 {
		t.Fatal("onChange was not called for initial scan")
	}

	initial := received[0]
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

	// Create executable file
	writeExecutable(t, dir, "new-hook", "#!/bin/sh\necho hello\n")

	// Wait for debounce + processing
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	// Initial call (empty) + at least one call with the new hook
	found := false
	for _, hooks := range received {
		for _, h := range hooks {
			if h.Name == "new-hook" {
				found = true
				if h.Source != "local" {
					t.Errorf("hook Source = %q, want %q", h.Source, "local")
				}
				if h.Checksum == "" {
					t.Error("hook Checksum is empty")
				}
			}
		}
	}
	mu.Unlock()

	if !found {
		t.Fatal("new-hook was not registered")
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

	var mu sync.Mutex
	var received [][]api.HookInfo
	onChange := func(hooks []api.HookInfo) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]api.HookInfo, len(hooks))
		copy(cp, hooks)
		received = append(received, cp)
	}

	var intMu sync.Mutex
	var integrityAlerts []struct{ name, oldSum, newSum string }
	onIntegrity := func(hookName, oldChecksum, newChecksum string) {
		intMu.Lock()
		defer intMu.Unlock()
		integrityAlerts = append(integrityAlerts, struct{ name, oldSum, newSum string }{hookName, oldChecksum, newChecksum})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, onChange, onIntegrity, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Wait for initial scan
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	if len(received) < 1 {
		mu.Unlock()
		t.Fatal("no initial scan callback")
	}
	oldChecksum := received[0][0].Checksum
	mu.Unlock()

	// Modify the file
	writeExecutable(t, dir, "myhook", "#!/bin/sh\necho v2\n")

	// Wait for debounce + processing
	time.Sleep(500 * time.Millisecond)

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

	// Verify the hook was updated in onChange
	mu.Lock()
	var latestChecksum string
	for _, hooks := range received {
		for _, h := range hooks {
			if h.Name == "myhook" {
				latestChecksum = h.Checksum
			}
		}
	}
	mu.Unlock()

	if latestChecksum == oldChecksum {
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

	mu.Lock()
	if len(received) < 1 || len(received[0]) < 1 {
		mu.Unlock()
		t.Fatal("no initial scan callback")
	}
	initialDesc := received[0][0].Description
	mu.Unlock()

	if initialDesc != "Initial description" {
		t.Fatalf("initial description = %q, want %q", initialDesc, "Initial description")
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

	// Wait for debounce + processing
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	var latestDesc string
	for _, hooks := range received {
		for _, h := range hooks {
			if h.Name == "deploy.sh" {
				latestDesc = h.Description
			}
		}
	}
	mu.Unlock()

	if latestDesc != "Updated description" {
		t.Errorf("description after sidecar update = %q, want %q", latestDesc, "Updated description")
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

func TestWatcher_FullLifecycle(t *testing.T) {
	dir := t.TempDir()

	type event struct {
		op    string // "initial", "update"
		names []string
	}

	var mu sync.Mutex
	var events []event

	onChange := func(hooks []api.HookInfo) {
		mu.Lock()
		defer mu.Unlock()
		names := make([]string, len(hooks))
		for i, h := range hooks {
			names[i] = h.Name
		}
		op := "update"
		if len(events) == 0 {
			op = "initial"
		}
		events = append(events, event{op: op, names: names})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Wait for initial scan (empty dir).
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	if len(events) < 1 {
		mu.Unlock()
		t.Fatal("no initial callback")
	}
	if len(events[0].names) != 0 {
		mu.Unlock()
		t.Fatalf("initial hooks = %v, want empty", events[0].names)
	}
	mu.Unlock()

	// Phase 1: Add hook-a.
	writeExecutable(t, dir, "hook-a", "#!/bin/sh\necho a\n")
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	lastNames := events[len(events)-1].names
	mu.Unlock()
	if len(lastNames) != 1 || lastNames[0] != "hook-a" {
		t.Fatalf("after adding hook-a, hooks = %v, want [hook-a]", lastNames)
	}

	// Phase 2: Add hook-b.
	writeExecutable(t, dir, "hook-b", "#!/bin/sh\necho b\n")
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	lastNames = events[len(events)-1].names
	mu.Unlock()
	if len(lastNames) != 2 {
		t.Fatalf("after adding hook-b, hooks count = %d, want 2", len(lastNames))
	}

	// Phase 3: Modify hook-a.
	writeExecutable(t, dir, "hook-a", "#!/bin/sh\necho a-v2\n")
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	lastNames = events[len(events)-1].names
	mu.Unlock()
	if len(lastNames) != 2 {
		t.Fatalf("after modifying hook-a, hooks count = %d, want 2", len(lastNames))
	}

	// Phase 4: Remove hook-a.
	if err := os.Remove(filepath.Join(dir, "hook-a")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	lastNames = events[len(events)-1].names
	mu.Unlock()
	if len(lastNames) != 1 || lastNames[0] != "hook-b" {
		t.Fatalf("after removing hook-a, hooks = %v, want [hook-b]", lastNames)
	}

	// Verify ordering: callbacks should be in chronological order.
	mu.Lock()
	totalEvents := len(events)
	mu.Unlock()
	if totalEvents < 4 {
		t.Errorf("total callbacks = %d, want at least 4 (initial + add + add + modify/remove)", totalEvents)
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

	// Wait for initial scan.
	time.Sleep(200 * time.Millisecond)

	// Add a hook.
	writeExecutable(t, dir, "deploy", "#!/bin/sh\necho deploying\n")
	time.Sleep(500 * time.Millisecond)

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

	// Remove the hook.
	if err := os.Remove(filepath.Join(dir, "deploy")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

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

	onChange := func(hooks []api.HookInfo) {}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewHookWatcher(dir, onChange, nil, testLogger())

	watchDone := make(chan error, 1)
	go func() { watchDone <- w.Watch(ctx) }()

	// Wait for initial scan
	time.Sleep(200 * time.Millisecond)

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
