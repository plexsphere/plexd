//go:build unix

package actions

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// okHook is a hook script that does nothing and succeeds.
const okHook = "#!/bin/sh\nexit 0\n"

// sleepHook outlives every bound the timeout tests set. The exec makes the
// script the sleep, so the kill at the limit leaves no child behind.
const sleepHook = "#!/bin/sh\nexec sleep 60\n"

// cappedMsg is the log message of a run the ceiling cut short.
const cappedMsg = "run deadline capped by max_action_timeout"

// writeRawSidecar writes content as the sidecar of the hook name in dir, for
// the sidecars writeSidecar cannot marshal.
func writeRawSidecar(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeMarkerHook writes a hook that creates a marker file outside dir, and
// returns the marker's path, so a test can tell whether the script ran.
func writeMarkerHook(t *testing.T, dir, name string) string {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "ran")
	writeExecutable(t, dir, name, fmt.Sprintf("#!/bin/sh\n: > %q\n", marker))
	return marker
}

func markerExists(t *testing.T, marker string) bool {
	t.Helper()
	_, err := os.Stat(marker)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// newHookExecutor returns an executor whose snapshot lists the named hooks.
func newHookExecutor(cfg Config, names ...string) (*Executor, *mockReporter, *mockVerifier) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(cfg, reporter, verifier)
	hooks := make([]api.HookInfo, len(names))
	for i, name := range names {
		hooks[i] = api.HookInfo{Name: name, Checksum: "abc123"}
	}
	exec.SetHooks(hooks)
	return exec, reporter, verifier
}

// runToTerminal dispatches entry and returns its terminal callback, failing the
// test unless ack and started came first.
func runToTerminal(t *testing.T, exec *Executor, reporter *mockReporter, entry api.NodeStateExecution) api.ExecutionCallbackRequest {
	t.Helper()
	before := len(reporter.getCallbacks())
	mustExecute(t, exec, "node-1", entry)
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= before+3
	})
	cbs := reporter.getCallbacks()[before:]
	assertStatuses(t, cbs[:2], []string{api.ExecutionStatusAck, api.ExecutionStatusStarted})
	return cbs[2]
}

// wantSucceeded fails the test unless the run succeeded.
func wantSucceeded(t *testing.T, terminal api.ExecutionCallbackRequest) {
	t.Helper()
	if terminal.Status != api.ExecutionStatusSucceeded {
		t.Errorf("terminal = %s %q, want %s", terminal.Status, terminal.Error, api.ExecutionStatusSucceeded)
	}
}

// wantFailed fails the test unless the run failed with exit code 1 and exactly
// this error, which is how every refusal ends.
func wantFailed(t *testing.T, terminal api.ExecutionCallbackRequest, want string) {
	t.Helper()
	if terminal.Status != api.ExecutionStatusFailed {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
	}
	if terminal.ExitCode == nil || *terminal.ExitCode != 1 {
		t.Errorf("terminal exit_code = %v, want pointer to 1", terminal.ExitCode)
	}
	if terminal.Error != want {
		t.Errorf("terminal error = %q, want %q", terminal.Error, want)
	}
}

// wantTimedOut fails the test unless a limit ended the run with this error.
func wantTimedOut(t *testing.T, terminal api.ExecutionCallbackRequest, want string) {
	t.Helper()
	if terminal.Status != api.ExecutionStatusFailed {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
	}
	if terminal.Error != want {
		t.Errorf("terminal error = %q, want %q", terminal.Error, want)
	}
}

func wantNoVerification(t *testing.T, verifier *mockVerifier) {
	t.Helper()
	if got := verifier.getChecksums(); len(got) != 0 {
		t.Errorf("verifications = %v, want none", got)
	}
}

func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	// An explicit chmod, because the mode given to os.WriteFile goes through the
	// umask, and 0002 turns 0757 into 0755.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// captureLogs sends the executor's log to the returned buffer.
func captureLogs(exec *Executor) *syncBuffer {
	logs := &syncBuffer{}
	exec.logger = slog.New(slog.NewTextHandler(logs, nil))
	return logs
}

// logLines returns the lines of logs whose message is msg.
func logLines(logs *syncBuffer, msg string) []string {
	var lines []string
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, `msg="`+msg+`"`) {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestParseHookTimeout(t *testing.T) {
	valid := []struct {
		timeout string
		want    time.Duration
	}{
		{"", 0},
		{"0s", 0},
		{"24h", 24 * time.Hour},
	}
	for _, tt := range valid {
		t.Run("valid "+tt.timeout, func(t *testing.T) {
			got, err := ParseHookTimeout(tt.timeout)
			if err != nil {
				t.Fatalf("ParseHookTimeout(%q): %v", tt.timeout, err)
			}
			if got != tt.want {
				t.Errorf("ParseHookTimeout(%q) = %s, want %s", tt.timeout, got, tt.want)
			}
		})
	}

	_, parseErr := time.ParseDuration("30")
	invalid := []struct {
		timeout string
		want    string
	}{
		{"30", parseErr.Error()},
		{"-1s", "timeout -1s is outside the range 0 to 24h0m0s"},
		{"25h", "timeout 25h0m0s is outside the range 0 to 24h0m0s"},
	}
	for _, tt := range invalid {
		t.Run("invalid "+tt.timeout, func(t *testing.T) {
			got, err := ParseHookTimeout(tt.timeout)
			if err == nil {
				t.Fatalf("ParseHookTimeout(%q) = %s, want an error", tt.timeout, got)
			}
			if err.Error() != tt.want {
				t.Errorf("ParseHookTimeout(%q) error = %q, want %q", tt.timeout, err, tt.want)
			}
		})
	}
}

func TestCheckHookFile_MissingMatchesErrNotExist(t *testing.T) {
	dir := t.TempDir()
	symlink(t, filepath.Join(dir, "gone"), filepath.Join(dir, "dangling"))

	tests := []struct {
		what, dir, name string
	}{
		{"missing file", dir, "absent"},
		{"dangling link", dir, "dangling"},
		{"missing directory", filepath.Join(dir, "absent-dir"), "deploy"},
	}
	for _, tt := range tests {
		t.Run(tt.what, func(t *testing.T) {
			err := checkHookFile(tt.dir, tt.name, uint32(os.Getuid()))
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("checkHookFile() = %v, want fs.ErrNotExist", err)
			}
			if errors.Is(err, errHookRefused) {
				t.Errorf("checkHookFile() = %v, want no refusal", err)
			}
		})
	}
}

func TestCheckHookFile_LinkLoopIsRefusedWithItsCause(t *testing.T) {
	dir := t.TempDir()
	symlink(t, "b", filepath.Join(dir, "a"))
	symlink(t, "a", filepath.Join(dir, "b"))

	err := checkHookFile(dir, "a", uint32(os.Getuid()))
	if !errors.Is(err, errHookRefused) {
		t.Fatalf("checkHookFile() = %v, want errHookRefused", err)
	}
	if want := "hook refused: a: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("checkHookFile() = %q, want the prefix %q", err, want)
	}
	if want := "too many links"; !strings.Contains(err.Error(), want) {
		t.Errorf("checkHookFile() = %q, want the cause %q", err, want)
	}
}

// The violations half uses the real verifier and a well-formed digest that
// differs from the file: a mock records no violations and a malformed digest
// files none, so neither could tell a refusal from a verification. The control
// proves this setup does file one when the verifier is reached.
func TestExecutor_HookFileWrongOwner(t *testing.T) {
	wrongUID := uint32(os.Getuid()) + 1

	t.Run("no verifier call", func(t *testing.T) {
		dir := t.TempDir()
		writeExecutable(t, dir, "deploy", okHook)
		exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")
		exec.hookOwnerUID = wrongUID

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-owner", "deploy"))

		wantFailed(t, terminal, fmt.Sprintf("hook refused: deploy is owned by uid %d, not root", os.Getuid()))
		wantNoVerification(t, verifier)
	})

	violationsFor := func(t *testing.T, ownerUID uint32) []api.IntegrityViolationReport {
		t.Helper()
		dir := t.TempDir()
		writeExecutable(t, dir, "deploy", okHook)
		violations := &recordingViolationReporter{}
		cfg := Config{HooksDir: dir}
		cfg.ApplyDefaults()
		reporter := &mockReporter{}
		exec := NewExecutor(cfg, reporter, newRealVerifier(t, violations), testLogger())
		exec.hookOwnerUID = ownerUID
		exec.SetHooks([]api.HookInfo{{Name: "deploy", Checksum: strings.Repeat("a", 64)}})

		runToTerminal(t, exec, reporter, pendingHookExec("exec-owner-violation", "deploy"))
		return violations.getReports()
	}

	t.Run("no integrity violation", func(t *testing.T) {
		if got := violationsFor(t, wrongUID); len(got) != 0 {
			t.Errorf("violations = %v, want none", got)
		}
	})

	t.Run("control: the right owner reaches the verifier", func(t *testing.T) {
		if got := violationsFor(t, uint32(os.Getuid())); len(got) != 1 {
			t.Errorf("violations = %v, want one", got)
		}
	})
}

func TestExecutor_HookFileWritableModes(t *testing.T) {
	for _, tt := range []struct {
		mode fs.FileMode
		want string
	}{
		{0o775, "hook refused: deploy is group- or other-writable (mode 0775)"},
		{0o757, "hook refused: deploy is group- or other-writable (mode 0757)"},
	} {
		t.Run(fmt.Sprintf("%04o", tt.mode), func(t *testing.T) {
			dir := t.TempDir()
			chmod(t, writeExecutable(t, dir, "deploy", okHook), tt.mode)
			exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

			terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-mode", "deploy"))

			wantFailed(t, terminal, tt.want)
			wantNoVerification(t, verifier)
		})
	}
}

func TestExecutor_HookFileUsableModes(t *testing.T) {
	for _, mode := range []fs.FileMode{0o755, 0o700, 0o555} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			dir := t.TempDir()
			chmod(t, writeExecutable(t, dir, "deploy", okHook), mode)
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

			wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-mode", "deploy")))
		})
	}
}

func TestExecutor_HookFileSymlinkInsideTheDirectory(t *testing.T) {
	for _, tt := range []struct {
		what, target string
	}{
		{"same directory", "real"},
		{"subdirectory", "sub/real"},
	} {
		t.Run(tt.what, func(t *testing.T) {
			dir := t.TempDir()
			mkdir(t, filepath.Join(dir, "sub"))
			target := writeExecutable(t, dir, tt.target, okHook)
			symlink(t, tt.target, filepath.Join(dir, "deploy"))
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

			wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-link-ok", "deploy")))

			// The target decides, not the link, which is never a regular file.
			chmod(t, target, 0o775)
			wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-link-mode", "deploy")),
				"hook refused: deploy is group- or other-writable (mode 0775)")
		})
	}
}

func TestExecutor_HookFileSymlinkOutOfTheDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "hooks")
	mkdir(t, dir)
	sibling := filepath.Join(base, "hooks-other")
	mkdir(t, sibling)
	other := writeExecutable(t, t.TempDir(), "real", okHook)
	writeExecutable(t, sibling, "real", okHook)
	writeExecutable(t, base, "real", okHook)

	for _, tt := range []struct {
		what, target string
	}{
		{"another directory", other},
		{"through dot dot", "../real"},
		// Shares the directory's prefix, so a string comparison would let it pass.
		{"sibling directory", "../hooks-other/real"},
	} {
		t.Run(tt.what, func(t *testing.T) {
			link := filepath.Join(dir, "deploy")
			symlink(t, tt.target, link)
			t.Cleanup(func() { _ = os.Remove(link) })
			exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

			terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-link-out", "deploy"))

			wantFailed(t, terminal, "hook refused: deploy resolves outside the hooks directory")
			wantNoVerification(t, verifier)
		})
	}
}

func TestExecutor_HookFileHooksDirIsASymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	mkdir(t, real)
	writeExecutable(t, real, "deploy", okHook)
	link := filepath.Join(base, "link")
	symlink(t, real, link)
	exec, reporter, _ := newHookExecutor(Config{HooksDir: link}, "deploy")

	wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-dir-link", "deploy")))
}

// hooks_dir may be relative to plexd's working directory. A link with an
// absolute target resolves to an absolute path, which must still compare with
// the directory it sits in.
func TestExecutor_HookFileRelativeHooksDirAbsoluteLink(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "hooks")
	mkdir(t, dir)
	mkdir(t, filepath.Join(dir, "sub"))
	target := writeExecutable(t, dir, "sub/real", okHook)
	symlink(t, target, filepath.Join(dir, "deploy"))
	sidecar := writeRawSidecar(t, dir, "sub/real", `{"timeout":"1m"}`)
	symlink(t, sidecar, filepath.Join(dir, "deploy.json"))
	t.Chdir(base)
	exec, reporter, _ := newHookExecutor(Config{HooksDir: "hooks"}, "deploy")

	wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-relative-dir", "deploy")))
}

func TestExecutor_HookFileDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	symlink(t, filepath.Join(dir, "gone"), filepath.Join(dir, "deploy"))
	exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

	terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-dangling", "deploy"))

	wantFailed(t, terminal, "hook not found: deploy")
	wantNoVerification(t, verifier)
}

func TestExecutor_HookFileReplacedByAFIFO(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "deploy", okHook)
	exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o755); err != nil {
		t.Fatal(err)
	}

	terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-fifo", "deploy"))

	wantFailed(t, terminal, "hook refused: deploy is not a regular file")
	wantNoVerification(t, verifier)
}

func TestExecutor_HookFileFixedWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "deploy", okHook)
	chmod(t, path, 0o775)
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

	wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-before-fix", "deploy")),
		"hook refused: deploy is group- or other-writable (mode 0775)")

	chmod(t, path, 0o755)
	wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-after-fix", "deploy")))
}

func TestNewExecutor_RequiresRoot(t *testing.T) {
	exec := NewExecutor(Config{}, &mockReporter{}, &mockVerifier{ok: true}, testLogger())
	if exec.hookOwnerUID != 0 {
		t.Errorf("hookOwnerUID = %d, want 0", exec.hookOwnerUID)
	}
}

// pendingHookExec's one hour deadline is past the default ceiling, so every
// dispatch here runs under a capped bound. The control shows that a run under
// that bound logs the capped line, so its absence after a refusal means
// something.
func TestExecutor_HookRefusedLog(t *testing.T) {
	for _, tt := range []struct {
		what    string
		mode    fs.FileMode
		sidecar string
		want    string
	}{
		{"by the file check", 0o775, "", "hook refused: deploy is group- or other-writable (mode 0775)"},
		{"by the sidecar", 0o755, `{"sandbox":"container"}`, `hook refused: sandbox level "container" is not implemented; plexd runs hooks at level none only`},
	} {
		t.Run("refused "+tt.what, func(t *testing.T) {
			dir := t.TempDir()
			chmod(t, writeExecutable(t, dir, "deploy", okHook), tt.mode)
			if tt.sidecar != "" {
				writeRawSidecar(t, dir, "deploy", tt.sidecar)
			}
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")
			logs := captureLogs(exec)

			wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-refused", "deploy")), tt.want)

			lines := logLines(logs, "hook refused")
			if len(lines) != 1 {
				t.Fatalf("hook refused lines = %q, want one", lines)
			}
			for _, want := range []string{
				"level=WARN",
				"execution_id=exec-refused",
				"hook=deploy",
				fmt.Sprintf("error=%q", tt.want),
			} {
				if !strings.Contains(lines[0], want) {
					t.Errorf("hook refused line = %q, want it to contain %q", lines[0], want)
				}
			}
			if lines := logLines(logs, cappedMsg); len(lines) != 0 {
				t.Errorf("capped lines = %q, want none for a refused run", lines)
			}
		})
	}

	t.Run("control: a run under the same bound logs the capped line", func(t *testing.T) {
		dir := t.TempDir()
		writeExecutable(t, dir, "deploy", okHook)
		exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")
		logs := captureLogs(exec)

		wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-capped", "deploy")))

		if lines := logLines(logs, cappedMsg); len(lines) != 1 {
			t.Errorf("capped lines = %q, want one", lines)
		}
	})

	t.Run("an integrity failure logs none", func(t *testing.T) {
		dir := t.TempDir()
		writeExecutable(t, dir, "deploy", okHook)
		exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")
		verifier.ok = false
		logs := captureLogs(exec)

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-tampered", "deploy"))

		wantFailed(t, terminal, "integrity check failed for hook: deploy")
		if lines := logLines(logs, "hook refused"); len(lines) != 0 {
			t.Errorf("hook refused lines = %q, want none", lines)
		}
	})

	// A name validateHookName rejects is no refusal, and the run never starts,
	// so neither line is logged.
	t.Run("an invalid name logs neither", func(t *testing.T) {
		dir := t.TempDir()
		writeExecutable(t, dir, "deploy..v2", okHook)
		exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy..v2")
		logs := captureLogs(exec)

		terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-invalid-name", "deploy..v2"))

		wantFailed(t, terminal, "invalid hook name: deploy..v2")
		for _, msg := range []string{"hook refused", cappedMsg} {
			if lines := logLines(logs, msg); len(lines) != 0 {
				t.Errorf("%s lines = %q, want none", msg, lines)
			}
		}
	})
}

func TestRunBound(t *testing.T) {
	const (
		short = time.Second
		mid   = time.Minute
		long  = time.Hour
	)
	tests := []struct {
		what                         string
		remaining, declared, ceiling time.Duration
		bound                        time.Duration
		label                        string
		capped                       bool
	}{
		{"dispatch deadline smallest", short, mid, long, short, "", false},
		{"declared smallest", long, short, mid, short, "hook timeout 1s", false},
		{"ceiling smallest", long, mid, short, short, "max_action_timeout 1s", true},
		{"none declared, deadline smaller", short, 0, mid, short, "", false},
		{"none declared, ceiling smaller", mid, 0, short, short, "max_action_timeout 1s", true},
		{"deadline ties declared", mid, mid, long, mid, "", false},
		{"deadline ties ceiling", mid, long, mid, mid, "", false},
		{"declared ties ceiling", long, mid, mid, mid, "hook timeout 1m0s", false},
		{"all three tie", mid, mid, mid, mid, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.what, func(t *testing.T) {
			bound, label, capped := runBound(tt.remaining, tt.declared, tt.ceiling)
			if bound != tt.bound || label != tt.label || capped != tt.capped {
				t.Errorf("runBound(%s, %s, %s) = (%s, %q, %t), want (%s, %q, %t)",
					tt.remaining, tt.declared, tt.ceiling, bound, label, capped, tt.bound, tt.label, tt.capped)
			}
		})
	}
}

func TestExecutor_HookTimeoutDeclared(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "slow", sleepHook)
	writeRawSidecar(t, dir, "slow", `{"timeout":"200ms"}`)
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "slow")
	entry := pendingHookExec("exec-declared", "slow")
	entry.ExpiresAt = time.Now().Add(time.Minute)

	wantTimedOut(t, runToTerminal(t, exec, reporter, entry), "action timed out: hook timeout 200ms")
}

func TestExecutor_HookTimeoutDispatchDeadlineKeepsTheBareError(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "slow", sleepHook)
	writeRawSidecar(t, dir, "slow", `{"timeout":"1m"}`)
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "slow")
	entry := pendingHookExec("exec-deadline", "slow")
	entry.ExpiresAt = time.Now().Add(100 * time.Millisecond)

	wantTimedOut(t, runToTerminal(t, exec, reporter, entry), "action timed out")
}

func TestExecutor_HookTimeoutCappedByMaxActionTimeout(t *testing.T) {
	// requested is the smaller of the dispatch deadline and the declared
	// timeout, so each case sets a different one smaller.
	for _, tt := range []struct {
		what      string
		expiresIn time.Duration
		requested func(time.Duration) bool
	}{
		{"dispatch deadline requested", time.Minute, func(d time.Duration) bool { return d > 59*time.Second && d < time.Minute }},
		{"declared timeout requested", time.Hour, func(d time.Duration) bool { return d == time.Minute }},
	} {
		t.Run(tt.what, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "slow", sleepHook)
			writeRawSidecar(t, dir, "slow", `{"timeout":"1m"}`)
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir, MaxActionTimeout: 200 * time.Millisecond}, "slow")
			logs := captureLogs(exec)
			entry := pendingHookExec("exec-capped", "slow")
			entry.ExpiresAt = time.Now().Add(tt.expiresIn)

			wantTimedOut(t, runToTerminal(t, exec, reporter, entry), "action timed out: max_action_timeout 200ms")

			lines := logLines(logs, cappedMsg)
			if len(lines) != 1 {
				t.Fatalf("capped lines = %q, want one", lines)
			}
			for _, want := range []string{"level=WARN", "execution_id=exec-capped", "action=slow", "ceiling=200ms", "requested="} {
				if !strings.Contains(lines[0], want) {
					t.Errorf("capped line = %q, want it to contain %q", lines[0], want)
				}
			}
			_, value, _ := strings.Cut(lines[0], "requested=")
			requested, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil {
				t.Fatalf("capped line = %q: requested: %v", lines[0], err)
			}
			if !tt.requested(requested) {
				t.Errorf("requested = %s, want the smaller of the deadline and 1m", requested)
			}
		})
	}
}

// The ceiling set no bound here, so the line the test above sees is its doing.
func TestExecutor_HookTimeoutUncappedLogsNoCappedLine(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "deploy", okHook)
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")
	logs := captureLogs(exec)
	entry := pendingHookExec("exec-uncapped", "deploy")
	entry.ExpiresAt = time.Now().Add(time.Minute)

	wantSucceeded(t, runToTerminal(t, exec, reporter, entry))

	if lines := logLines(logs, cappedMsg); len(lines) != 0 {
		t.Errorf("capped lines = %q, want none under the 10m default ceiling", lines)
	}
}

func TestExecutor_HookTimeoutNoneDeclared(t *testing.T) {
	for _, sidecar := range []string{"", `{}`, `{"timeout":"0s"}`, `null`} {
		for _, tt := range []struct {
			what      string
			ceiling   time.Duration
			expiresIn time.Duration
			want      string
		}{
			{"dispatch deadline", 10 * time.Minute, 100 * time.Millisecond, "action timed out"},
			{"ceiling", 200 * time.Millisecond, time.Minute, "action timed out: max_action_timeout 200ms"},
		} {
			t.Run(fmt.Sprintf("sidecar %q bounded by the %s", sidecar, tt.what), func(t *testing.T) {
				dir := t.TempDir()
				writeExecutable(t, dir, "slow", sleepHook)
				if sidecar != "" {
					writeRawSidecar(t, dir, "slow", sidecar)
				}
				exec, reporter, _ := newHookExecutor(Config{HooksDir: dir, MaxActionTimeout: tt.ceiling}, "slow")
				entry := pendingHookExec("exec-none-declared", "slow")
				entry.ExpiresAt = time.Now().Add(tt.expiresIn)

				wantTimedOut(t, runToTerminal(t, exec, reporter, entry), tt.want)
			})
		}
	}
}

// The builtin watches its context, so a 1ms bound would end it with ctx.Err
// and fail the test. A builtin that ignored its context would pass either way.
func TestExecutor_BuiltinNeverReadsASidecar(t *testing.T) {
	for _, sidecar := range []string{`{"timeout":"1ms"}`, `{"sandbox":"container"}`} {
		t.Run(sidecar, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "deploy", okHook)
			writeRawSidecar(t, dir, "deploy", sidecar)
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")
			exec.RegisterBuiltin("deploy", "Deploy", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
				select {
				case <-ctx.Done():
					return "", "", 1, ctx.Err()
				case <-time.After(50 * time.Millisecond):
					return "done", "", 0, nil
				}
			})

			wantSucceeded(t, runToTerminal(t, exec, reporter, pendingExec("exec-builtin", "deploy")))
		})
	}
}

func TestExecutor_HookSandboxLevelNoneRuns(t *testing.T) {
	for _, sidecar := range []string{`{"sandbox":"none"}`, `{"sandbox":""}`, `{"description":"no sandbox key"}`} {
		t.Run(sidecar, func(t *testing.T) {
			dir := t.TempDir()
			marker := writeMarkerHook(t, dir, "deploy")
			writeRawSidecar(t, dir, "deploy", sidecar)
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

			wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-sandbox-none", "deploy")))
			if !markerExists(t, marker) {
				t.Error("the hook did not run")
			}
		})
	}
}

func TestExecutor_HookSandboxLevelRefused(t *testing.T) {
	for _, level := range []string{"namespaced", "container", "strict"} {
		t.Run(level, func(t *testing.T) {
			dir := t.TempDir()
			marker := writeMarkerHook(t, dir, "deploy")
			writeRawSidecar(t, dir, "deploy", fmt.Sprintf(`{"sandbox":%q}`, level))
			exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

			terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-sandbox", "deploy"))

			wantFailed(t, terminal, fmt.Sprintf("hook refused: sandbox level %q is not implemented; plexd runs hooks at level none only", level))
			if markerExists(t, marker) {
				t.Error("the hook ran")
			}
			wantNoVerification(t, verifier)
		})
	}
}

// A sidecar value has no length limit, and an error over 4096 characters would
// strand the execution at started, so a refusal quotes at most 64 characters.
func TestExecutor_HookSidecarLongValues(t *testing.T) {
	for _, tt := range []struct {
		what, sidecar, want string
	}{
		{
			"5000 character sandbox",
			`{"sandbox":"` + strings.Repeat("x", 5000) + `"}`,
			fmt.Sprintf("hook refused: sandbox level %q is not implemented; plexd runs hooks at level none only", strings.Repeat("x", 64)),
		},
		{
			"5000 character timeout",
			`{"timeout":"` + strings.Repeat("9", 5000) + `"}`,
			fmt.Sprintf("hook refused: sidecar deploy.json declares an unusable timeout %q: want a duration from 0 to 24h", strings.Repeat("9", 64)),
		},
		{
			// The JSON escape decodes to a NUL byte.
			"NUL in sandbox",
			`{"sandbox":"a\u0000b"}`,
			`hook refused: sandbox level "a\x00b" is not implemented; plexd runs hooks at level none only`,
		},
	} {
		t.Run(tt.what, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "deploy", okHook)
			writeRawSidecar(t, dir, "deploy", tt.sidecar)
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

			terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-long", "deploy"))

			wantFailed(t, terminal, tt.want)
			if n := len(terminal.Error); n > 512 {
				t.Errorf("terminal error is %d bytes, want at most 512", n)
			}
			if strings.ContainsRune(terminal.Error, 0) {
				t.Errorf("terminal error = %q, want the NUL escaped", terminal.Error)
			}
		})
	}
}

func TestExecutor_HookSidecarMalformed(t *testing.T) {
	for _, tt := range []struct {
		what, sidecar, want string
	}{
		{"trailing comma", `{"sandbox":"container",}`, ""},
		{"empty file", "", "hook refused: sidecar deploy.json: unexpected end of JSON input"},
		{"number timeout", `{"timeout":30}`, ""},
	} {
		t.Run(tt.what, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "deploy", okHook)
			writeRawSidecar(t, dir, "deploy", tt.sidecar)
			exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

			terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-malformed", "deploy"))

			if terminal.Status != api.ExecutionStatusFailed {
				t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
			}
			if prefix := "hook refused: sidecar deploy.json: "; !strings.HasPrefix(terminal.Error, prefix) {
				t.Errorf("terminal error = %q, want the prefix %q", terminal.Error, prefix)
			}
			if tt.want != "" && terminal.Error != tt.want {
				t.Errorf("terminal error = %q, want %q", terminal.Error, tt.want)
			}
			wantNoVerification(t, verifier)
		})
	}
}

func TestExecutor_HookSidecarUnusableTimeout(t *testing.T) {
	for _, timeout := range []string{"30", "-1s", "25h"} {
		t.Run(timeout, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "deploy", okHook)
			writeRawSidecar(t, dir, "deploy", fmt.Sprintf(`{"timeout":%q}`, timeout))
			exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

			wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-timeout", "deploy")),
				fmt.Sprintf("hook refused: sidecar deploy.json declares an unusable timeout %q: want a duration from 0 to 24h", timeout))
		})
	}
}

func TestExecutor_HookSidecarUnreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a file at mode 0")
	}
	dir := t.TempDir()
	writeExecutable(t, dir, "deploy", okHook)
	chmod(t, writeRawSidecar(t, dir, "deploy", `{}`), 0)
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

	terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-unreadable", "deploy"))

	if terminal.Status != api.ExecutionStatusFailed {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
	}
	if prefix := "hook refused: sidecar deploy.json: "; !strings.HasPrefix(terminal.Error, prefix) {
		t.Errorf("terminal error = %q, want the prefix %q", terminal.Error, prefix)
	}
	_, err := loadHookDeclaration(dir, "deploy", uint32(os.Getuid()))
	if !errors.Is(err, errHookRefused) || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("loadHookDeclaration() = %v, want errHookRefused wrapping fs.ErrPermission", err)
	}
}

func TestExecutor_HookSidecarReplacedByAFIFO(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "deploy", okHook)
	if err := syscall.Mkfifo(filepath.Join(dir, "deploy.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

	wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-sidecar-fifo", "deploy")),
		"hook refused: deploy.json is not a regular file")
}

// The checks run at dispatch only, so a refused hook stays listed and the
// dispatch's error says why it did not run.
func TestExecutor_HookSidecarRefusalKeepsTheHookListed(t *testing.T) {
	for _, sidecar := range []string{`{"sandbox":"container"}`, `{"sandbox":"container",}`} {
		t.Run(sidecar, func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "deploy", okHook)
			writeRawSidecar(t, dir, "deploy", sidecar)
			reporter := &mockReporter{}
			exec := newTestExecutor(Config{HooksDir: dir}, reporter, &mockVerifier{ok: true})
			w := NewHookWatcher(dir, exec.SetHooks, nil, testLogger())
			if _, err := w.Reload(); err != nil {
				t.Fatalf("Reload() error = %v", err)
			}

			terminal := runToTerminal(t, exec, reporter, pendingHookExec("exec-listed", "deploy"))

			if !strings.HasPrefix(terminal.Error, "hook refused: ") {
				t.Fatalf("terminal error = %q, want a refusal", terminal.Error)
			}
			_, hooks := exec.Capabilities()
			wantHooks(t, "Capabilities()", hooks, "deploy")
			wantHooks(t, "Hooks()", w.Hooks(), "deploy")
		})
	}
}

func TestExecutor_HookSidecarFileChecks(t *testing.T) {
	t.Run("wrong owner", func(t *testing.T) {
		dir := t.TempDir()
		writeExecutable(t, dir, "deploy", okHook)
		writeRawSidecar(t, dir, "deploy", `{}`)
		exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")
		exec.hookOwnerUID = uint32(os.Getuid()) + 1

		wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-sidecar-owner", "deploy")),
			fmt.Sprintf("hook refused: deploy.json is owned by uid %d, not root", os.Getuid()))
		wantNoVerification(t, verifier)
	})

	for _, mode := range []fs.FileMode{0o664, 0o646} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			dir := t.TempDir()
			writeExecutable(t, dir, "deploy", okHook)
			chmod(t, writeRawSidecar(t, dir, "deploy", `{}`), mode)
			exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

			wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-sidecar-mode", "deploy")),
				fmt.Sprintf("hook refused: deploy.json is group- or other-writable (mode %04o)", mode))
			wantNoVerification(t, verifier)
		})
	}
}

func TestExecutor_HookSidecarSymlinkOutOfTheDirectory(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "deploy", okHook)
	outside := writeRawSidecar(t, t.TempDir(), "deploy", `{}`)
	symlink(t, outside, filepath.Join(dir, "deploy.json"))
	exec, reporter, verifier := newHookExecutor(Config{HooksDir: dir}, "deploy")

	wantFailed(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-sidecar-out", "deploy")),
		"hook refused: deploy.json resolves outside the hooks directory")
	wantNoVerification(t, verifier)
}

func TestExecutor_HookSidecarDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "deploy", okHook)
	symlink(t, filepath.Join(dir, "gone.json"), filepath.Join(dir, "deploy.json"))
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")

	wantSucceeded(t, runToTerminal(t, exec, reporter, pendingHookExec("exec-sidecar-dangling", "deploy")))
}
