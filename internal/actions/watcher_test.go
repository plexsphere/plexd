package actions

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
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

	// Delete the file
	if err := os.Remove(filepath.Join(dir, "to-delete")); err != nil {
		t.Fatal(err)
	}

	// Wait for debounce + processing
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	// Find the last callback with an empty hooks list
	var foundEmpty bool
	for i := len(received) - 1; i >= 0; i-- {
		if len(received[i]) == 0 {
			foundEmpty = true
			break
		}
	}
	mu.Unlock()

	if !foundEmpty {
		t.Fatal("onChange was not called with empty hooks after deletion")
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

	cfg := Config{Enabled: true, HooksDir: dir}
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
