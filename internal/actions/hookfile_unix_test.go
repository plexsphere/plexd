//go:build unix

package actions

import (
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

func TestExecutor_HookRefusedLog(t *testing.T) {
	t.Run("a refused run logs one line", func(t *testing.T) {
		dir := t.TempDir()
		chmod(t, writeExecutable(t, dir, "deploy", okHook), 0o775)
		exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "deploy")
		logs := captureLogs(exec)

		runToTerminal(t, exec, reporter, pendingHookExec("exec-refused", "deploy"))

		lines := logLines(logs, "hook refused")
		if len(lines) != 1 {
			t.Fatalf("hook refused lines = %q, want one", lines)
		}
		for _, want := range []string{
			"level=WARN",
			"execution_id=exec-refused",
			"hook=deploy",
			`error="hook refused: deploy is group- or other-writable (mode 0775)"`,
		} {
			if !strings.Contains(lines[0], want) {
				t.Errorf("hook refused line = %q, want it to contain %q", lines[0], want)
			}
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
}
