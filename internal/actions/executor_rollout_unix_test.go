//go:build unix

package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
)

// rolloutScript is the script of a rolled-out hook that prints which version
// ran, so a test can tell the bytes of one version from the next.
func rolloutScript(version string) string {
	return "#!/bin/sh\necho rollout " + version + "\n"
}

// hexDigest is the lowercase hex SHA-256 of script, the form of a rollout pin.
func hexDigest(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
}

// installRollout installs script as version of the rolled-out hook name in dir
// the way the installer does: SwapRolloutHook writes the file atomically and
// pins the digest. It then reports the file to the executor as the rollout
// watcher would. It returns the pinned digest.
func installRollout(t *testing.T, exec *Executor, dir, name string, version int, script string) string {
	t.Helper()
	checksum := hexDigest(script)
	swap := func() error {
		return fsutil.WriteFileAtomic(dir, name, []byte(script), 0o755)
	}
	if err := exec.SwapRolloutHook(name, version, checksum, swap); err != nil {
		t.Fatalf("SwapRolloutHook(%s, %d): %v", name, version, err)
	}
	exec.SetRolloutHooks([]api.HookInfo{{Name: name, Source: api.HookSourceRollout, Checksum: checksum}})
	return checksum
}

// newRolloutExecutor returns an executor over hooksDir and rolloutDir that
// verifies hooks with the real integrity verifier, which files its violations
// with violations.
func newRolloutExecutor(t *testing.T, hooksDir, rolloutDir string, violations *recordingViolationReporter) (*Executor, *integrationReporter) {
	t.Helper()
	cfg := integrationConfig(hooksDir)
	cfg.RolloutHooksDir = rolloutDir
	reporter := &integrationReporter{}
	exec := NewExecutor(cfg, reporter, newRealVerifier(t, violations), testLogger())
	exec.hookOwnerUID = uint32(os.Getuid())
	return exec, reporter
}

// dispatchToTerminal dispatches entry and returns its terminal callback,
// failing the test unless ack and started came first.
func dispatchToTerminal(t *testing.T, exec *Executor, reporter *integrationReporter, entry api.NodeStateExecution) api.ExecutionCallbackRequest {
	t.Helper()
	before := len(reporter.getCallbacks())
	mustExecute(t, exec, "node-1", entry)
	integrationWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= before+3
	})
	cbs := reporter.getCallbacks()[before:]
	assertStatuses(t, cbs[:2], []string{api.ExecutionStatusAck, api.ExecutionStatusStarted})
	return cbs[2]
}

// wantOutput fails the test unless the run succeeded and printed want.
func wantOutput(t *testing.T, terminal api.ExecutionCallbackRequest, want string) {
	t.Helper()
	wantSucceeded(t, terminal)
	if got := strings.TrimSpace(decodeInline(t, terminal.Output)); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

// wantRejected fails the test unless Execute rejected the dispatch with reason,
// which ends the walk with a failed callback that carries no exit code.
func wantRejected(t *testing.T, terminal api.ExecutionCallbackRequest, reason string) {
	t.Helper()
	if terminal.Status != api.ExecutionStatusFailed || terminal.Error != reason {
		t.Errorf("terminal = %s %q, want %s %q", terminal.Status, terminal.Error, api.ExecutionStatusFailed, reason)
	}
	if terminal.ExitCode != nil {
		t.Errorf("terminal exit_code = %d, want none for a run that never started", *terminal.ExitCode)
	}
}

// listedHooks returns the hooks Capabilities reports.
func listedHooks(exec *Executor) []api.HookInfo {
	_, hooks := exec.Capabilities()
	return hooks
}

// TestExecutor_RolloutCapabilitiesMerge checks the merged list Capabilities
// reports and Execute resolves against. A rolled-out hook is listed once it
// has a pin, with the pin's version, and a hand-placed hook of the same name
// takes its place. Each case runs with the pins recorded before and after the
// rollout snapshot arrives, because the list is recomputed on every change.
func TestExecutor_RolloutCapabilitiesMerge(t *testing.T) {
	tests := []struct {
		name    string
		local   []api.HookInfo
		rollout []api.HookInfo
		pins    map[string]int // hook name → pinned version
		want    []api.HookInfo
	}{
		{
			name:    "pinned rollout entry",
			local:   []api.HookInfo{{Name: "zeta", Source: api.HookSourceLocal, Checksum: "local-zeta"}},
			rollout: []api.HookInfo{{Name: "backup-db", Source: api.HookSourceRollout, Checksum: "rollout-backup", Description: "nightly"}},
			pins:    map[string]int{"backup-db": 2},
			want: []api.HookInfo{
				{Name: "backup-db", Source: api.HookSourceRollout, Checksum: "rollout-backup", Description: "nightly", Version: 2},
				{Name: "zeta", Source: api.HookSourceLocal, Checksum: "local-zeta"},
			},
		},
		{
			name: "unpinned rollout entry",
			rollout: []api.HookInfo{
				{Name: "backup-db", Source: api.HookSourceRollout, Checksum: "rollout-backup"},
				{Name: "stray", Source: api.HookSourceRollout, Checksum: "rollout-stray"},
			},
			pins: map[string]int{"backup-db": 1},
			want: []api.HookInfo{
				{Name: "backup-db", Source: api.HookSourceRollout, Checksum: "rollout-backup", Version: 1},
			},
		},
		{
			name:    "same name in both sets",
			local:   []api.HookInfo{{Name: "backup-db", Source: api.HookSourceLocal, Checksum: "local-backup"}},
			rollout: []api.HookInfo{{Name: "backup-db", Source: api.HookSourceRollout, Checksum: "rollout-backup"}},
			pins:    map[string]int{"backup-db": 3},
			want: []api.HookInfo{
				{Name: "backup-db", Source: api.HookSourceLocal, Checksum: "local-backup"},
			},
		},
		{
			// The run path picks directory and pin by Source, so a mislabeled
			// entry must not pick the other set's.
			name:    "the set decides the source",
			local:   []api.HookInfo{{Name: "alpha", Source: api.HookSourceRollout, Checksum: "local-alpha"}},
			rollout: []api.HookInfo{{Name: "beta", Checksum: "rollout-beta"}},
			pins:    map[string]int{"alpha": 4, "beta": 1},
			want: []api.HookInfo{
				{Name: "alpha", Source: api.HookSourceLocal, Checksum: "local-alpha"},
				{Name: "beta", Source: api.HookSourceRollout, Checksum: "rollout-beta", Version: 1},
			},
		},
	}

	for _, tt := range tests {
		for _, pinsFirst := range []bool{true, false} {
			order := "snapshot then pins"
			if pinsFirst {
				order = "pins then snapshot"
			}
			t.Run(tt.name+"/"+order, func(t *testing.T) {
				exec := newTestExecutor(Config{}, &mockReporter{}, &mockVerifier{ok: true})
				pin := func() {
					for name, version := range tt.pins {
						if err := exec.SwapRolloutHook(name, version, "pin-"+name, nil); err != nil {
							t.Fatalf("SwapRolloutHook(%s): %v", name, err)
						}
					}
				}

				exec.SetHooks(tt.local)
				if pinsFirst {
					pin()
					exec.SetRolloutHooks(tt.rollout)
				} else {
					exec.SetRolloutHooks(tt.rollout)
					pin()
				}

				if got := listedHooks(exec); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Capabilities() hooks = %+v, want %+v", got, tt.want)
				}
			})
		}
	}
}

// TestExecutor_RolloutHookRunsFromTheRolloutDirectory checks that a rolled-out
// hook runs from RolloutHooksDir under its own sidecar and is verified against
// its pin, not the digest the watcher reported.
func TestExecutor_RolloutHookRunsFromTheRolloutDirectory(t *testing.T) {
	requireHookScripts(t)

	t.Run("succeeds with its output", func(t *testing.T) {
		hooksDir, rolloutDir := t.TempDir(), t.TempDir()
		// A sidecar of the same name in hooks_dir would refuse the run if the
		// executor read it.
		writeRawSidecar(t, hooksDir, "backup-db", `{"sandbox":"container"}`)
		writeRawSidecar(t, rolloutDir, "backup-db", `{"timeout":"30s","sandbox":"none"}`)

		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{HooksDir: hooksDir, RolloutHooksDir: rolloutDir}, reporter, verifier)
		pin := installRollout(t, exec, rolloutDir, "backup-db", 1, rolloutScript("v1"))
		exec.SetRolloutHooks([]api.HookInfo{{Name: "backup-db", Source: api.HookSourceRollout, Checksum: "digest-the-watcher-computed"}})

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-run", "backup-db"))
		wantSucceeded(t, terminal)
		if got := strings.TrimSpace(decodeInline(t, terminal.Output)); got != "rollout v1" {
			t.Errorf("output = %q, want %q", got, "rollout v1")
		}
		if got := verifier.getChecksums(); !reflect.DeepEqual(got, []string{pin}) {
			t.Errorf("verified checksums = %v, want the pin [%s]", got, pin)
		}
	})

	t.Run("bounded by its sidecar timeout", func(t *testing.T) {
		hooksDir, rolloutDir := t.TempDir(), t.TempDir()
		writeRawSidecar(t, rolloutDir, "slow", `{"timeout":"200ms"}`)

		reporter := &mockReporter{}
		exec := newTestExecutor(Config{HooksDir: hooksDir, RolloutHooksDir: rolloutDir}, reporter, &mockVerifier{ok: true})
		installRollout(t, exec, rolloutDir, "slow", 1, sleepHook)

		entry := pendingHookExec("exec-rollout-timeout", "slow")
		entry.ExpiresAt = time.Now().Add(time.Minute)
		wantTimedOut(t, runToTerminal(t, exec, reporter, entry), "action timed out: hook timeout 200ms")
	})

	t.Run("a hand-placed hook of the same name runs instead", func(t *testing.T) {
		hooksDir, rolloutDir := t.TempDir(), t.TempDir()
		writeExecutable(t, hooksDir, "backup-db", "#!/bin/sh\necho hand-placed\n")

		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{HooksDir: hooksDir, RolloutHooksDir: rolloutDir}, reporter, verifier)
		exec.SetHooks([]api.HookInfo{{Name: "backup-db", Source: api.HookSourceLocal, Checksum: "local-digest"}})
		installRollout(t, exec, rolloutDir, "backup-db", 1, rolloutScript("v1"))

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-shadowed", "backup-db"))
		wantSucceeded(t, terminal)
		if got := strings.TrimSpace(decodeInline(t, terminal.Output)); got != "hand-placed" {
			t.Errorf("output = %q, want %q", got, "hand-placed")
		}
		if got := verifier.getChecksums(); !reflect.DeepEqual(got, []string{"local-digest"}) {
			t.Errorf("verified checksums = %v, want the first-discovery pin [local-digest]", got)
		}
	})
}

// TestExecutor_RolloutHookTamperedFailsPreDispatch checks that a local edit of
// a rolled-out file is refused like any other tampering: the pin is the
// delivered checksum, so the watcher's rehash of the edited file does not
// make it runnable, and the refusal files one hook_checksum violation.
func TestExecutor_RolloutHookTamperedFailsPreDispatch(t *testing.T) {
	requireHookScripts(t)
	hooksDir, rolloutDir := t.TempDir(), t.TempDir()
	violations := &recordingViolationReporter{}
	exec, reporter := newRolloutExecutor(t, hooksDir, rolloutDir, violations)
	installRollout(t, exec, rolloutDir, "backup-db", 2, rolloutScript("v2"))

	path := filepath.Join(rolloutDir, "backup-db")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("echo tampered\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// The rollout watcher rehashes the edited file.
	edited := hexDigest(rolloutScript("v2") + "echo tampered\n")
	exec.SetRolloutHooks([]api.HookInfo{{Name: "backup-db", Source: api.HookSourceRollout, Checksum: edited}})

	want := []api.HookInfo{{Name: "backup-db", Source: api.HookSourceRollout, Checksum: edited, Version: 2}}
	if got := listedHooks(exec); !reflect.DeepEqual(got, want) {
		t.Errorf("Capabilities() hooks = %+v, want %+v", got, want)
	}

	wantFailed(t, dispatchToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-tampered", "backup-db")),
		"integrity check failed for hook: backup-db")

	reports := violations.getReports()
	if len(reports) != 1 {
		t.Fatalf("violations = %+v, want exactly one", reports)
	}
	if reports[0].Kind != api.IntegrityKindHookChecksum || reports[0].DetectedBy != api.IntegrityDetectorPreDispatch {
		t.Errorf("violation = %s detected by %s, want %s detected by %s",
			reports[0].Kind, reports[0].DetectedBy, api.IntegrityKindHookChecksum, api.IntegrityDetectorPreDispatch)
	}
}

// TestExecutor_RolloutSwapRunsTheNewVersion checks that a swapped version runs
// on the next dispatch with no restart, and that its pin moves with it, so
// the new bytes file no violation.
func TestExecutor_RolloutSwapRunsTheNewVersion(t *testing.T) {
	requireHookScripts(t)
	hooksDir, rolloutDir := t.TempDir(), t.TempDir()
	violations := &recordingViolationReporter{}
	exec, reporter := newRolloutExecutor(t, hooksDir, rolloutDir, violations)

	installRollout(t, exec, rolloutDir, "backup-db", 1, rolloutScript("v1"))
	wantOutput(t, dispatchToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-v1", "backup-db")), "rollout v1")

	v2 := installRollout(t, exec, rolloutDir, "backup-db", 2, rolloutScript("v2"))
	want := []api.HookInfo{{Name: "backup-db", Source: api.HookSourceRollout, Checksum: v2, Version: 2}}
	if got := listedHooks(exec); !reflect.DeepEqual(got, want) {
		t.Errorf("Capabilities() hooks = %+v, want %+v", got, want)
	}
	wantOutput(t, dispatchToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-v2", "backup-db")), "rollout v2")

	if got := violations.getReports(); len(got) != 0 {
		t.Errorf("violations = %+v, want none", got)
	}
}

// TestExecutor_RolloutSwapMovesTheListedChecksum checks that a swap moves the
// listed checksum with the pin. Until the rollout watcher rescans the new
// file, Capabilities must pair the new version with the digest of the bytes
// the swap wrote, not with the old file's, which the control plane would read
// as drift. The watcher's snapshot itself stays as the watcher handed it over.
func TestExecutor_RolloutSwapMovesTheListedChecksum(t *testing.T) {
	rolloutDir := t.TempDir()
	exec := newTestExecutor(Config{HooksDir: t.TempDir(), RolloutHooksDir: rolloutDir}, &mockReporter{}, &mockVerifier{ok: true})
	v1, v2 := hexDigest(rolloutScript("v1")), hexDigest(rolloutScript("v2"))
	write := func(script string) func() error {
		return func() error { return fsutil.WriteFileAtomic(rolloutDir, "backup-db", []byte(script), 0o755) }
	}
	if err := exec.SwapRolloutHook("backup-db", 1, v1, write(rolloutScript("v1"))); err != nil {
		t.Fatalf("SwapRolloutHook(version 1): %v", err)
	}
	if err := exec.SwapRolloutHook("rotate-logs", 3, "rotate-logs-pin", nil); err != nil {
		t.Fatalf("SwapRolloutHook(rotate-logs): %v", err)
	}
	// The rollout watcher scans version 1.
	scanned := []api.HookInfo{
		{Name: "backup-db", Source: api.HookSourceRollout, Checksum: v1},
		{Name: "rotate-logs", Source: api.HookSourceRollout, Checksum: "rotate-logs-scanned"},
	}
	exec.SetRolloutHooks(scanned)

	if err := exec.SwapRolloutHook("backup-db", 2, v2, write(rolloutScript("v2"))); err != nil {
		t.Fatalf("SwapRolloutHook(version 2): %v", err)
	}

	want := []api.HookInfo{
		{Name: "backup-db", Source: api.HookSourceRollout, Checksum: v2, Version: 2},
		{Name: "rotate-logs", Source: api.HookSourceRollout, Checksum: "rotate-logs-scanned", Version: 3},
	}
	if got := listedHooks(exec); !reflect.DeepEqual(got, want) {
		t.Errorf("Capabilities() hooks before the rescan = %+v, want %+v", got, want)
	}
	if scanned[0].Checksum != v1 {
		t.Errorf("the watcher's snapshot holds checksum %s for backup-db, want it untouched at %s", scanned[0].Checksum, v1)
	}
}

// TestExecutor_RolloutSwapDoesNotWaitForARunningHook checks that a run holds
// the swap lock only until its process has started. A swap or a removal of a
// hook that is running returns at once and leaves the run going; held for the
// whole run, the lock would stall every rollout pass for as long as the hook
// runs.
func TestExecutor_RolloutSwapDoesNotWaitForARunningHook(t *testing.T) {
	requireHookScripts(t)
	rolloutDir := t.TempDir()
	started := filepath.Join(t.TempDir(), "started")
	reporter := &mockReporter{}
	exec := newTestExecutor(Config{HooksDir: t.TempDir(), RolloutHooksDir: rolloutDir}, reporter, &mockVerifier{ok: true})
	// Shutdown kills the run, so neither the hook nor a swap stuck behind it
	// outlives the test.
	t.Cleanup(func() { exec.Shutdown(context.Background()) })
	installRollout(t, exec, rolloutDir, "slow", 1, fmt.Sprintf("#!/bin/sh\n: > %q\nexec sleep 60\n", started))

	mustExecute(t, exec, "node-1", pendingHookExec("exec-rollout-running", "slow"))
	waitFor(t, 5*time.Second, func() bool {
		_, err := os.Stat(started)
		return err == nil
	})

	returnsWhileRunning := func(what string, fn func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s blocked behind a running hook", what)
		}
	}
	returnsWhileRunning("SwapRolloutHook", func() error {
		return exec.SwapRolloutHook("slow", 2, hexDigest(rolloutScript("v2")), func() error {
			return fsutil.WriteFileAtomic(rolloutDir, "slow", []byte(rolloutScript("v2")), 0o755)
		})
	})
	returnsWhileRunning("RemoveRolloutHook", func() error {
		return exec.RemoveRolloutHook("slow", func() error { return os.Remove(filepath.Join(rolloutDir, "slow")) })
	})
	if !exec.IsActive("exec-rollout-running") {
		t.Error("the run ended before the swap and the removal returned, so they never overlapped it")
	}

	exec.Shutdown(context.Background())
}

// TestExecutor_RolloutDispatchDuringSwap checks the swap lock. A dispatch that
// arrives while a swap is writing must wait for the swap and then verify the
// new bytes against the new pin. Without the lock it would verify against the
// old pin, running version 1 or filing a false tamper alert for version 2.
func TestExecutor_RolloutDispatchDuringSwap(t *testing.T) {
	requireHookScripts(t)
	hooksDir, rolloutDir := t.TempDir(), t.TempDir()
	violations := &recordingViolationReporter{}
	exec, reporter := newRolloutExecutor(t, hooksDir, rolloutDir, violations)
	installRollout(t, exec, rolloutDir, "backup-db", 1, rolloutScript("v1"))

	entered := make(chan struct{})
	release := make(chan struct{})
	swapped := make(chan error, 1)
	go func() {
		swapped <- exec.SwapRolloutHook("backup-db", 2, hexDigest(rolloutScript("v2")), func() error {
			close(entered)
			<-release
			return fsutil.WriteFileAtomic(rolloutDir, "backup-db", []byte(rolloutScript("v2")), 0o755)
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("swap did not start")
	}

	// Execute returns once the run is claimed, with the swap still held open.
	before := len(reporter.getCallbacks())
	mustExecute(t, exec, "node-1", pendingHookExec("exec-rollout-during-swap", "backup-db"))
	close(release)
	if err := <-swapped; err != nil {
		t.Fatalf("SwapRolloutHook: %v", err)
	}

	integrationWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= before+3
	})
	cbs := reporter.getCallbacks()[before:]
	assertStatuses(t, cbs, []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusSucceeded})
	wantOutput(t, cbs[2], "rollout v2")

	if got := violations.getReports(); len(got) != 0 {
		t.Errorf("violations = %+v, want none", got)
	}
}

// TestExecutor_RolloutSwapFailureKeepsThePin checks that a failed swap leaves
// what runs as it was and hands its error back to the caller.
func TestExecutor_RolloutSwapFailureKeepsThePin(t *testing.T) {
	requireHookScripts(t)
	errSwap := errors.New("disk full")

	t.Run("replacing a pinned version", func(t *testing.T) {
		hooksDir, rolloutDir := t.TempDir(), t.TempDir()
		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{HooksDir: hooksDir, RolloutHooksDir: rolloutDir}, reporter, verifier)
		v1 := installRollout(t, exec, rolloutDir, "backup-db", 1, rolloutScript("v1"))
		before := listedHooks(exec)

		err := exec.SwapRolloutHook("backup-db", 2, hexDigest(rolloutScript("v2")), func() error { return errSwap })
		if !errors.Is(err, errSwap) {
			t.Fatalf("SwapRolloutHook error = %v, want %v", err, errSwap)
		}
		if got := listedHooks(exec); !reflect.DeepEqual(got, before) {
			t.Errorf("Capabilities() hooks = %+v, want unchanged %+v", got, before)
		}

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-swap-failed", "backup-db"))
		wantSucceeded(t, terminal)
		if got := verifier.getChecksums(); !reflect.DeepEqual(got, []string{v1}) {
			t.Errorf("verified checksums = %v, want the version 1 pin [%s]", got, v1)
		}
	})

	t.Run("a first install", func(t *testing.T) {
		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{HooksDir: t.TempDir(), RolloutHooksDir: t.TempDir()}, reporter, verifier)
		// The file landed before the swap failed, and the watcher reported it.
		exec.SetRolloutHooks([]api.HookInfo{{Name: "backup-db", Source: api.HookSourceRollout, Checksum: "partial"}})

		err := exec.SwapRolloutHook("backup-db", 1, hexDigest(rolloutScript("v1")), func() error { return errSwap })
		if !errors.Is(err, errSwap) {
			t.Fatalf("SwapRolloutHook error = %v, want %v", err, errSwap)
		}
		if got := listedHooks(exec); len(got) != 0 {
			t.Errorf("Capabilities() hooks = %+v, want none", got)
		}

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-never-pinned", "backup-db"))
		wantRejected(t, terminal, "unknown_action")
		wantNoVerification(t, verifier)
	})
}

// TestExecutor_RolloutHookRemoved checks that RemoveRolloutHook takes a hook
// out of dispatch as soon as it returns, before the watcher reports the file
// gone, and that a failed removal keeps the hook as it was.
func TestExecutor_RolloutHookRemoved(t *testing.T) {
	requireHookScripts(t)

	t.Run("rejected as unknown_action", func(t *testing.T) {
		hooksDir, rolloutDir := t.TempDir(), t.TempDir()
		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{HooksDir: hooksDir, RolloutHooksDir: rolloutDir}, reporter, verifier)
		installRollout(t, exec, rolloutDir, "backup-db", 1, rolloutScript("v1"))

		remove := func() error { return os.Remove(filepath.Join(rolloutDir, "backup-db")) }
		if err := exec.RemoveRolloutHook("backup-db", remove); err != nil {
			t.Fatalf("RemoveRolloutHook: %v", err)
		}
		if got := listedHooks(exec); len(got) != 0 {
			t.Errorf("Capabilities() hooks = %+v, want none", got)
		}

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-removed", "backup-db"))
		wantRejected(t, terminal, "unknown_action")
		wantNoVerification(t, verifier)
	})

	t.Run("a failed removal keeps the pin", func(t *testing.T) {
		hooksDir, rolloutDir := t.TempDir(), t.TempDir()
		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{HooksDir: hooksDir, RolloutHooksDir: rolloutDir}, reporter, verifier)
		v1 := installRollout(t, exec, rolloutDir, "backup-db", 1, rolloutScript("v1"))
		before := listedHooks(exec)

		errRemove := errors.New("read-only file system")
		if err := exec.RemoveRolloutHook("backup-db", func() error { return errRemove }); !errors.Is(err, errRemove) {
			t.Fatalf("RemoveRolloutHook error = %v, want %v", err, errRemove)
		}
		if got := listedHooks(exec); !reflect.DeepEqual(got, before) {
			t.Errorf("Capabilities() hooks = %+v, want unchanged %+v", got, before)
		}

		wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-rollout-kept", "backup-db")))
		if got := verifier.getChecksums(); !reflect.DeepEqual(got, []string{v1}) {
			t.Errorf("verified checksums = %v, want [%s]", got, v1)
		}
	})
}
