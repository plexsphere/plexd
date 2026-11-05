//go:build unix

package actions

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
)

// skipIfRoot skips a test that needs a directory of mode 0555 to refuse a
// write, which it does not for root.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes, so a mode 0555 directory cannot refuse the write")
	}
}

// readOnly sets dir to mode 0555 and gives it back write permission when the
// test ends, so t.TempDir can remove it.
func readOnly(t *testing.T, dir string) {
	t.Helper()
	chmod(t, dir, 0o555)
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Errorf("restore %s: %v", dir, err)
		}
	})
}

// wantMode fails the test unless the file at path has permission bits mode.
func wantMode(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Errorf("%s mode = %04o, want %04o", filepath.Base(path), got, mode)
	}
}

// TestNewRolloutInstaller_RefusesHooksDirUnderAnotherSpelling checks that
// the installer refuses hooks_dir as its directory however the two paths
// spell it: through a symlink at <data_dir>/hooks, through a symlinked data
// dir, or as a hooks_dir relative to the working directory. Accepted, Load
// would remove the operator's hooks as strays.
func TestNewRolloutInstaller_RefusesHooksDirUnderAnotherSpelling(t *testing.T) {
	tests := []struct {
		name string
		// layout builds the directories under base and returns hooks_dir and
		// the data dir.
		layout func(t *testing.T, base string) (hooksDir, dataDir string)
	}{
		{
			name: "the rollout directory is a symlink to hooks_dir",
			layout: func(t *testing.T, base string) (string, string) {
				mkdir(t, filepath.Join(base, "etc"))
				hooksDir := filepath.Join(base, "etc", "hooks")
				mkdir(t, hooksDir)
				dataDir := filepath.Join(base, "data")
				mkdir(t, dataDir)
				symlink(t, hooksDir, filepath.Join(dataDir, "hooks"))
				return hooksDir, dataDir
			},
		},
		{
			name: "the data dir is a symlink to hooks_dir's parent",
			layout: func(t *testing.T, base string) (string, string) {
				mkdir(t, filepath.Join(base, "etc"))
				hooksDir := filepath.Join(base, "etc", "hooks")
				mkdir(t, hooksDir)
				dataDir := filepath.Join(base, "data")
				symlink(t, filepath.Join(base, "etc"), dataDir)
				return hooksDir, dataDir
			},
		},
		{
			name: "hooks_dir relative to the working directory",
			layout: func(t *testing.T, base string) (string, string) {
				dataDir := filepath.Join(base, "data")
				mkdir(t, dataDir)
				mkdir(t, filepath.Join(dataDir, "hooks"))
				t.Chdir(base)
				return filepath.Join("data", "hooks"), dataDir
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hooksDir, dataDir := tt.layout(t, t.TempDir())
			hand := writeHandPlaced(t, hooksDir, "operator-hook", "#!/bin/sh\necho hand-placed\n")
			cfg := Config{HooksDir: hooksDir, RolloutHooksDir: filepath.Join(dataDir, "hooks")}
			exec := newTestExecutor(Config{}, &mockReporter{}, &mockVerifier{ok: true})

			inst, err := NewRolloutInstaller(cfg, dataDir, rolloutTestNodeID, newFakeHookFetcher(), &api.Ed25519Verifier{}, exec, testLogger())
			if err == nil {
				t.Errorf("NewRolloutInstaller(hooks_dir %q, rollout directory %q) = nil error, want the refusal", cfg.HooksDir, cfg.RolloutHooksDir)
				// plexd up runs Load next, which removes every file the
				// record does not list.
				_ = inst.Load()
			} else {
				if want := "is hooks_dir; plexd would remove hand-placed hooks as strays"; !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want it to say %q", err, want)
				}
				if inst != nil {
					t.Errorf("installer = %v, want nil with the error", inst)
				}
			}

			got, err := os.ReadFile(filepath.Join(hooksDir, "operator-hook"))
			if err != nil || string(got) != string(hand) {
				t.Errorf("hand-placed hook = %q, %v; want it kept as %q", got, err, hand)
			}
		})
	}
}

// TestRolloutInstaller_InstallFileModes checks the modes of what an install
// writes: the script 0755, the sidecar 0644, and the record, which only plexd
// reads, 0600.
func TestRolloutInstaller_InstallFileModes(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 1)

	wantMode(t, filepath.Join(h.rolloutDir, "backup-db"), 0o755)
	wantMode(t, filepath.Join(h.rolloutDir, "backup-db.json"), 0o644)
	wantMode(t, filepath.Join(h.dataDir, rolloutRecordFile), 0o600)
}

// TestRolloutInstaller_InstalledHookRuns checks that a hook the installer put
// in place runs through the executor once the rollout watcher reports it,
// verified against the delivered checksum by the real integrity verifier, and
// that a new version runs on the next dispatch with no restart.
func TestRolloutInstaller_InstalledHookRuns(t *testing.T) {
	requireHookScripts(t)
	h := newRolloutHarness(t, nil)
	violations := &recordingViolationReporter{}
	var reporter *integrationReporter
	h.newExec = func(cfg Config) *Executor {
		exec, rep := newRolloutExecutor(t, cfg.HooksDir, cfg.RolloutHooksDir, violations)
		reporter = rep
		return exec
	}
	h.open(nil)
	watcher := NewRolloutHookWatcher(h.rolloutDir, h.exec.SetRolloutHooks, nil, testLogger())
	h.inst.SetOnChange(func() {
		if _, err := watcher.Reload(); err != nil {
			t.Errorf("rollout watcher reload: %v", err)
		}
	})
	h.load()

	h.pass(h.publish("backup-db", 1, func(p *api.HookVersionPayload) { p.TimeoutSeconds = 30 }))

	hooks := listedHooks(h.exec)
	if len(hooks) != 1 || hooks[0].Name != "backup-db" || hooks[0].Source != api.HookSourceRollout ||
		hooks[0].Version != 1 || hooks[0].Timeout != "30s" {
		t.Fatalf("Capabilities() hooks = %+v, want backup-db from the rollout at version 1 with timeout 30s", hooks)
	}
	wantOutput(t, dispatchToTerminal(t, h.exec, reporter, pendingHookExec("exec-installed-v1", "backup-db")), "backup-db v1")

	h.pass(h.publish("backup-db", 2, nil))
	wantOutput(t, dispatchToTerminal(t, h.exec, reporter, pendingHookExec("exec-installed-v2", "backup-db")), "backup-db v2")

	if got := violations.getReports(); len(got) != 0 {
		t.Errorf("violations = %+v, want none", got)
	}
}

// TestRolloutInstaller_ScriptWriteFailure checks a script write that fails
// inside the swap. The atomic write renames before it syncs the directory, so
// it can fail after the new bytes landed: that version is then installed,
// pinned, recorded and runnable as if the write had succeeded, because the
// new bytes under the old pin would fail every dispatch as tampered. A write
// that fails before anything landed keeps the old version pinned and
// runnable.
func TestRolloutInstaller_ScriptWriteFailure(t *testing.T) {
	requireHookScripts(t)
	errSync := errors.New("sync rollout directory: input/output error")

	// setup returns a harness over the real executor and integrity verifier
	// that rescans the rollout directory after a pass that changed something,
	// as plexd up wires it, with backup-db version 1 installed. From then on
	// writeScript writes the script of backup-db.
	setup := func(t *testing.T, writeScript func(dir, name string, data []byte, perm os.FileMode) error) (*rolloutHarness, *integrationReporter, *recordingViolationReporter) {
		t.Helper()
		h := newRolloutHarness(t, nil)
		violations := &recordingViolationReporter{}
		var reporter *integrationReporter
		h.newExec = func(cfg Config) *Executor {
			exec, rep := newRolloutExecutor(t, cfg.HooksDir, cfg.RolloutHooksDir, violations)
			reporter = rep
			return exec
		}
		h.open(nil)
		watcher := NewRolloutHookWatcher(h.rolloutDir, h.exec.SetRolloutHooks, nil, testLogger())
		h.inst.SetOnChange(func() {
			if _, err := watcher.Reload(); err != nil {
				t.Errorf("rollout watcher reload: %v", err)
			}
		})
		h.load()
		h.install("backup-db", 1)
		h.inst.writeFile = func(dir, name string, data []byte, perm os.FileMode) error {
			if dir == h.rolloutDir && name == "backup-db" {
				return writeScript(dir, name, data, perm)
			}
			return fsutil.WriteFileAtomic(dir, name, data, perm)
		}
		return h, reporter, violations
	}

	// wantListed fails the test unless Capabilities lists backup-db alone, at
	// version with that version's checksum.
	wantListed := func(t *testing.T, h *rolloutHarness, version int) {
		t.Helper()
		hooks := listedHooks(h.exec)
		want := scriptHex(versionScript("backup-db", version))
		if len(hooks) != 1 || hooks[0].Name != "backup-db" || hooks[0].Version != version || hooks[0].Checksum != want {
			t.Errorf("Capabilities() hooks = %+v, want backup-db at version %d with checksum %s", hooks, version, want)
		}
	}

	t.Run("the script landed before the failure", func(t *testing.T) {
		h, reporter, violations := setup(t, func(dir, name string, data []byte, perm os.FileMode) error {
			if err := fsutil.WriteFileAtomic(dir, name, data, perm); err != nil {
				return err
			}
			return errSync
		})

		h.pass(h.publish("backup-db", 2, nil))

		h.wantErrors()
		h.wantInstalled("backup-db", 2)
		h.wantSavedRecord(recorded("backup-db", 2))
		wantListed(t, h, 2)
		recs := h.logs.wantLogged(t, "actions: rollout: script written but not synced", "WARN", 1)
		if len(recs) == 1 && (recs[0]["name"] != "backup-db" || recs[0]["version"] != float64(2) || recs[0]["error"] != errSync.Error()) {
			t.Errorf("WARN = %v, want name backup-db, version 2 and the write's error", recs[0])
		}
		wantOutput(t, dispatchToTerminal(t, h.exec, reporter, pendingHookExec("exec-written-not-synced", "backup-db")), "backup-db v2")
		if got := violations.getReports(); len(got) != 0 {
			t.Errorf("violations = %+v, want none", got)
		}
	})

	t.Run("nothing landed", func(t *testing.T) {
		h, reporter, violations := setup(t, func(string, string, []byte, os.FileMode) error { return errSync })

		h.pass(h.publish("backup-db", 2, nil))

		h.wantErrors(api.HookRolloutError{
			Name: "backup-db", Version: 2, Code: api.HookRolloutCodeInstallFailed, Detail: errSync.Error(),
		})
		h.wantInstalled("backup-db", 1)
		h.wantSavedRecord(recorded("backup-db", 1))
		wantListed(t, h, 1)
		h.logs.wantLogged(t, "actions: rollout: script written but not synced", "WARN", 0)
		wantOutput(t, dispatchToTerminal(t, h.exec, reporter, pendingHookExec("exec-not-written", "backup-db")), "backup-db v1")
		if got := violations.getReports(); len(got) != 0 {
			t.Errorf("violations = %+v, want none", got)
		}
	})
}

// TestRolloutInstaller_ReadOnlyRolloutDirKeepsVersion1 checks that an install
// the rollout directory refuses gets install_failed and leaves the installed
// version on disk, pinned and recorded.
func TestRolloutInstaller_ReadOnlyRolloutDirKeepsVersion1(t *testing.T) {
	skipIfRoot(t)
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 1)
	readOnly(t, h.rolloutDir)

	h.pass(h.publish("backup-db", 2, nil))

	errs := h.inst.Errors()
	if len(errs) != 1 || errs[0].Name != "backup-db" || errs[0].Version != 2 || errs[0].Code != api.HookRolloutCodeInstallFailed {
		t.Fatalf("Errors() = %+v, want one install_failed for backup-db version 2", errs)
	}
	if !strings.Contains(errs[0].Detail, "permission denied") {
		t.Errorf("detail = %q, want the write's error", errs[0].Detail)
	}
	h.wantInstalled("backup-db", 1)
	h.wantSavedRecord(recorded("backup-db", 1))
	if got := h.rolloutFiles(); !reflect.DeepEqual(got, []string{"backup-db", "backup-db.json"}) {
		t.Errorf("rollout directory = %v, want version 1's script and sidecar alone", got)
	}
}

// TestRolloutInstaller_RecordNotSaved checks that a record the data dir
// refuses costs nothing at run time: the hook stays installed and pinned, the
// failure is logged at ERROR, and the record lands at the end of the first
// pass after the data dir is writable again.
func TestRolloutInstaller_RecordNotSaved(t *testing.T) {
	skipIfRoot(t)
	h := newRolloutHarness(t, nil)
	h.load()
	entry := h.publish("backup-db", 1, nil)
	chmod(t, h.dataDir, 0o555)
	t.Cleanup(func() { _ = os.Chmod(h.dataDir, 0o755) })

	h.pass(entry)

	h.wantInstalled("backup-db", 1)
	h.wantErrors()
	h.logs.wantLogged(t, "actions: rollout: record not saved", "ERROR", 1)
	if _, err := os.Stat(filepath.Join(h.dataDir, rolloutRecordFile)); !os.IsNotExist(err) {
		t.Fatalf("record: Stat error %v, want none written", err)
	}

	chmod(t, h.dataDir, 0o755)
	h.pass(entry)

	h.wantFetches(hookFetchCall{"backup-db", 1})
	h.wantSavedRecord(recorded("backup-db", 1))
	h.logs.wantLogged(t, "actions: rollout: record not saved", "ERROR", 1)
	h.wantInstalled("backup-db", 1)
}

// TestRolloutInstaller_LoadCannotCreateDirectory checks that Load returns an
// error when the rollout directory cannot be created, that the next pass
// reports the listed version as install_failed, and that the pass after the
// parent becomes writable installs it.
func TestRolloutInstaller_LoadCannotCreateDirectory(t *testing.T) {
	skipIfRoot(t)
	h := newRolloutHarness(t, nil)
	readOnly(t, h.dataDir)

	if err := h.inst.Load(); err == nil {
		t.Fatal("Load = nil, want an error for a rollout directory it cannot create")
	}

	entry := h.publish("backup-db", 1, nil)
	h.pass(entry)

	errs := h.inst.Errors()
	if len(errs) != 1 || errs[0].Name != "backup-db" || errs[0].Code != api.HookRolloutCodeInstallFailed {
		t.Fatalf("Errors() = %+v, want one install_failed for backup-db", errs)
	}
	h.wantNotInstalled("backup-db")

	chmod(t, h.dataDir, 0o755)
	h.pass(entry)

	h.wantInstalled("backup-db", 1)
	h.wantSavedRecord(recorded("backup-db", 1))
	h.wantErrors()
}

// TestRolloutInstaller_Load checks what Load restores at start: the record as
// far as the disk still backs it, a pin for each surviving entry, and a
// rollout directory with nothing else in it.
func TestRolloutInstaller_Load(t *testing.T) {
	t.Run("missing record starts empty", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()

		if len(h.inst.record) != 0 {
			t.Errorf("record = %+v, want empty", h.inst.record)
		}
		if got := h.pins(); len(got) != 0 {
			t.Errorf("pins = %v, want none", got)
		}
		info, err := os.Stat(h.rolloutDir)
		if err != nil || !info.IsDir() {
			t.Errorf("rollout directory: Stat = %v, %v; want Load to create it", info, err)
		}
		h.logs.wantLogged(t, "actions: rollout: record unreadable; starting empty", "WARN", 0)
	})

	corrupt := map[string]string{
		"not JSON":           `{"hooks":[`,
		"name off grammar":   `{"hooks":[{"name":"../escape","version":1,"checksum":"` + scriptHex("x") + `"}]}`,
		"version 0":          `{"hooks":[{"name":"backup-db","version":0,"checksum":"` + scriptHex("x") + `"}]}`,
		"uppercase checksum": `{"hooks":[{"name":"backup-db","version":1,"checksum":"` + strings.ToUpper(scriptHex("x")) + `"}]}`,
		"wire checksum":      `{"hooks":[{"name":"backup-db","version":1,"checksum":"` + scriptWire("x") + `"}]}`,
		"name twice": `{"hooks":[{"name":"backup-db","version":1,"checksum":"` + scriptHex("x") + `"},` +
			`{"name":"backup-db","version":2,"checksum":"` + scriptHex("x") + `"}]}`,
	}
	for name, content := range corrupt {
		t.Run("corrupt record starts empty: "+name, func(t *testing.T) {
			h := newRolloutHarness(t, nil)
			h.load()
			entry := h.install("backup-db", 1)
			if err := os.WriteFile(filepath.Join(h.dataDir, rolloutRecordFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}

			h.open(nil)
			h.load()

			h.logs.wantLogged(t, "actions: rollout: record unreadable; starting empty", "WARN", 1)
			h.wantNotInstalled("backup-db")
			if got := h.rolloutFiles(); len(got) != 0 {
				t.Errorf("rollout directory = %v, want the files the record no longer vouches for removed", got)
			}

			// The next pass fetches the listed version again.
			h.pass(entry)
			h.wantInstalled("backup-db", 1)
			h.wantSavedRecord(recorded("backup-db", 1))
		})
	}

	t.Run("entry whose script is missing is dropped", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		alpha := h.install("alpha", 1)
		h.install("beta", 2, alpha)
		if err := os.Remove(filepath.Join(h.rolloutDir, "alpha")); err != nil {
			t.Fatal(err)
		}

		h.open(nil)
		h.load()

		h.wantNotInstalled("alpha")
		h.wantInstalled("beta", 2)
		h.wantSavedRecord(recorded("beta", 2))
		if got := h.rolloutFiles(); !reflect.DeepEqual(got, []string{"beta", "beta.json"}) {
			t.Errorf("rollout directory = %v, want beta's script and sidecar alone", got)
		}
	})

	t.Run("strays and temporary leftovers are removed", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		h.install("backup-db", 1)
		for _, stray := range []string{".tmp-backup-db-123", ".tmp-hook_rollouts.json-9", "hand-copied", "orphan.json"} {
			if err := os.WriteFile(filepath.Join(h.rolloutDir, stray), []byte("stray"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		symlink(t, filepath.Join(h.rolloutDir, "backup-db"), filepath.Join(h.rolloutDir, "link"))
		mkdir(t, filepath.Join(h.rolloutDir, "subdir"))

		h.open(nil)
		h.load()

		if got, want := h.rolloutFiles(), []string{"backup-db", "backup-db.json", "subdir"}; !reflect.DeepEqual(got, want) {
			t.Errorf("rollout directory = %v, want %v", got, want)
		}
		h.wantInstalled("backup-db", 1)
		h.logs.wantLogged(t, "actions: rollout: stray file removed", "INFO", 5)
	})

	t.Run("every surviving entry is pinned before Load returns", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		alpha := h.install("alpha", 1)
		beta := h.install("beta", 2, alpha)
		fetches := h.fetcher.getCalls()

		h.open(nil)
		if got := h.pins(); len(got) != 0 {
			t.Fatalf("pins of a new executor = %v, want none", got)
		}
		h.load()

		for name, version := range map[string]int{"alpha": 1, "beta": 2} {
			want := rolloutPin{version: version, checksum: scriptHex(versionScript(name, version))}
			if pin, ok := h.pin(name); !ok || pin != want {
				t.Errorf("pin of %s = %+v (present %v), want %+v", name, pin, ok, want)
			}
		}

		// The pull that follows finds both installed and fetches nothing.
		h.pass(alpha, beta)
		h.wantFetches(fetches...)
		h.wantErrors()
	})
}

// TestRolloutInstaller_FailedRemovalIsRetried checks that a withdrawn hook
// whose unlink fails stays recorded and pinned, is logged at WARN, and is
// removed on the next pass that can.
func TestRolloutInstaller_FailedRemovalIsRetried(t *testing.T) {
	skipIfRoot(t)
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 1)
	readOnly(t, h.rolloutDir)

	h.pass()

	h.wantInstalled("backup-db", 1)
	h.wantSavedRecord(recorded("backup-db", 1))
	h.logs.wantLogged(t, "actions: rollout: hook not removed", "WARN", 1)
	h.logs.wantLogged(t, "actions: rollout: hook removed", "INFO", 0)

	chmod(t, h.rolloutDir, 0o755)
	h.pass()

	h.wantNotInstalled("backup-db")
	h.wantSavedRecord()
	h.logs.wantLogged(t, "actions: rollout: hook removed", "INFO", 1)
}

// TestRolloutInstaller_DanglingLinkInHooksDirCollides checks that a listed
// name blocks the rollout when hooks_dir holds any directory entry of it, as
// os.Lstat finds them: a dangling link reports collision and fetches nothing,
// although os.Stat would find the name free.
func TestRolloutInstaller_DanglingLinkInHooksDirCollides(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	link := filepath.Join(h.hooksDir, "backup-db")
	symlink(t, filepath.Join(h.hooksDir, "missing-target"), link)

	h.pass(h.publish("backup-db", 1, nil))

	h.wantErrors(api.HookRolloutError{
		Name: "backup-db", Version: 1, Code: api.HookRolloutCodeCollision, Detail: "hooks_dir holds a hook of this name",
	})
	h.wantFetches()
	h.wantNotInstalled("backup-db")
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("hand-placed link: Lstat error %v, want it kept", err)
	}
}

// TestRolloutInstaller_HooksDirUnreadable checks that a collision check that
// fails for any reason but a missing file reports install_failed and fetches
// nothing: plexd cannot tell whether an operator's hook holds the name.
func TestRolloutInstaller_HooksDirUnreadable(t *testing.T) {
	skipIfRoot(t)
	h := newRolloutHarness(t, nil)
	h.load()
	chmod(t, h.hooksDir, 0o000)
	t.Cleanup(func() { _ = os.Chmod(h.hooksDir, 0o755) })

	h.pass(h.publish("backup-db", 1, nil))

	errs := h.inst.Errors()
	if len(errs) != 1 || errs[0].Code != api.HookRolloutCodeInstallFailed || !strings.HasPrefix(errs[0].Detail, "check hooks_dir: ") {
		t.Fatalf("Errors() = %+v, want one install_failed whose detail starts with %q", errs, "check hooks_dir: ")
	}
	if !strings.Contains(errs[0].Detail, "permission denied") {
		t.Errorf("detail = %q, want the Lstat error", errs[0].Detail)
	}
	h.wantFetches()
	h.wantNotInstalled("backup-db")
}
