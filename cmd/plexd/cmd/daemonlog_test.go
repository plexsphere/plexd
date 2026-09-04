package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/packaging"
)

// renameSkipReason is why the rotation tests do not run on Windows: os.OpenFile
// there opens without FILE_SHARE_DELETE, and Windows refuses to rename a file
// another handle holds open, so the rotation the writer follows cannot be
// staged. The writer itself only ever runs on macOS, where launchd owns the
// log file and newsyslog renames it.
const renameSkipReason = "windows opens files without FILE_SHARE_DELETE, so a file the writer holds open cannot be renamed"

// writeLine writes one line through w and fails the test unless all of it was
// written.
func writeLine(t *testing.T, w *reopeningLogFile, line string) {
	t.Helper()

	n, err := w.Write([]byte(line))
	if err != nil {
		t.Fatalf("Write(%q) = _, %v, want no error", line, err)
	}
	if n != len(line) {
		t.Fatalf("Write(%q) = %d, want %d", line, n, len(line))
	}
}

// readLogFile returns the contents of path, failing the test if it cannot be
// read.
func readLogFile(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return string(b)
}

// newTestLogFile returns a writer over a path inside a fresh temp dir, along
// with that path.
func newTestLogFile(t *testing.T) (*reopeningLogFile, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "plexd.log")
	w := newReopeningLogFile(path)
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
	return w, path
}

// TestReopeningLogFile_FollowsRename is the rotation newsyslog performs: the
// file is renamed out of the way and the writer has to put the next line into
// the file that takes its place.
func TestReopeningLogFile_FollowsRename(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip(renameSkipReason)
	}

	w, path := newTestLogFile(t)

	writeLine(t, w, "a\n")
	if err := os.Rename(path, path+".0"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	writeLine(t, w, "b\n")

	if got := readLogFile(t, path); got != "b\n" {
		t.Errorf("%s = %q, want %q", path, got, "b\n")
	}
	if got := readLogFile(t, path+".0"); got != "a\n" {
		t.Errorf("%s = %q, want %q", path+".0", got, "a\n")
	}
}

// TestReopeningLogFile_RecreatesRemovedFile covers the operator who deletes the
// log file instead of rotating it: nothing is at the path, so the writer
// creates it rather than writing into the unlinked file it still holds.
func TestReopeningLogFile_RecreatesRemovedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip(renameSkipReason)
	}

	w, path := newTestLogFile(t)

	writeLine(t, w, "a\n")
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	writeLine(t, w, "b\n")

	if got := readLogFile(t, path); got != "b\n" {
		t.Errorf("%s = %q, want %q", path, got, "b\n")
	}
}

// TestReopeningLogFile_CreatesMissingFile covers the first write of a daemon
// whose log file has not been created yet.
func TestReopeningLogFile_CreatesMissingFile(t *testing.T) {
	w, path := newTestLogFile(t)

	n, err := w.Write([]byte("a\n"))
	if err != nil {
		t.Fatalf("Write = _, %v, want no error", err)
	}
	if n != 2 {
		t.Errorf("Write = %d, want 2", n)
	}
	if got := readLogFile(t, path); got != "a\n" {
		t.Errorf("%s = %q, want %q", path, got, "a\n")
	}
}

// TestReopeningLogFile_ReportsUnopenablePath pins that a path the writer
// cannot open fails the write rather than diverting it to stderr, which for
// this writer is the same file and after a rotation the unlinked one.
func TestReopeningLogFile_ReportsUnopenablePath(t *testing.T) {
	// A directory cannot be opened for writing on any platform plexd runs on.
	w := newReopeningLogFile(t.TempDir())
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	n, err := w.Write([]byte("x\n"))
	if err == nil {
		t.Fatal("Write = _, nil, want the open error")
	}
	if n != 0 {
		t.Errorf("Write = %d, want 0", n)
	}
}

// TestReopeningLogFile_RefusesSymlink covers the reopen an unprivileged member
// of the admin group can stage on macOS: /Library/Logs lets them replace the
// daemon log with a symlink, and the daemon must not append to its target as
// root.
func TestReopeningLogFile_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW has no counterpart on windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	w := newReopeningLogFile(path)
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	if _, err := w.Write([]byte("x\n")); err == nil {
		t.Fatal("Write = _, nil, want the open to refuse the symlink")
	}
	if got := readLogFile(t, target); got != "" {
		t.Errorf("%s = %q, want the symlink target untouched", target, got)
	}
}

// TestReopeningLogFile_Close covers the three states Close is reached in: no
// file opened yet, a file held, and a writer already closed.
func TestReopeningLogFile_Close(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plexd.log")

	unused := newReopeningLogFile(path)
	if err := unused.Close(); err != nil {
		t.Errorf("Close() before any write = %v, want nil", err)
	}

	w := newReopeningLogFile(path)
	writeLine(t, w, "a\n")
	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close() = %v, want nil", err)
	}
}

// TestReopeningLogFile_ConcurrentWrites exercises the lock the slog handler
// needs: every goroutine's line has to land in the file exactly once.
func TestReopeningLogFile_ConcurrentWrites(t *testing.T) {
	w, path := newTestLogFile(t)

	const goroutines, perGoroutine = 8, 20

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				if _, err := fmt.Fprintf(w, "line %d-%d\n", g, i); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	got := strings.Split(strings.TrimSuffix(readLogFile(t, path), "\n"), "\n")
	sort.Strings(got)

	want := make([]string, 0, goroutines*perGoroutine)
	for g := range goroutines {
		for i := range perGoroutine {
			want = append(want, fmt.Sprintf("line %d-%d", g, i))
		}
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("wrote %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestDaemonLogWriter_MatchesStderrFile is the launchd case: stderr is the file
// at the path, so the daemon logs through the reopening writer.
func TestDaemonLogWriter_MatchesStderrFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plexd.log")
	stderr, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = stderr.Close() }()

	w := daemonLogWriter(stderr, path)
	if w == nil {
		t.Fatal("daemonLogWriter() = nil, want a writer when stderr is the file at path")
	}
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	writeLine(t, w, "hello\n")
	if got := readLogFile(t, path); got != "hello\n" {
		t.Errorf("%s = %q, want %q", path, got, "hello\n")
	}
}

// TestDaemonLogWriter_DifferentFile is the plist that redirects the daemon's
// output somewhere other than the file plexd would follow.
func TestDaemonLogWriter_DifferentFile(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other.log")
	path := filepath.Join(dir, "plexd.log")

	stderr, err := os.Create(other)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = stderr.Close() }()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if w := daemonLogWriter(stderr, path); w != nil {
		t.Errorf("daemonLogWriter() = %v, want nil for a different file", w)
	}
}

// TestDaemonLogWriter_MissingPath is a console run on a host that has no
// daemon log file at all.
func TestDaemonLogWriter_MissingPath(t *testing.T) {
	dir := t.TempDir()
	stderr, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = stderr.Close() }()

	if w := daemonLogWriter(stderr, filepath.Join(dir, "absent.log")); w != nil {
		t.Errorf("daemonLogWriter() = %v, want nil for a missing path", w)
	}
}

// TestDaemonLogWriter_SymlinkedPath is the symlink an unprivileged member of
// the admin group can leave at the path on macOS. launchd follows it, so
// stderr is the target and the identity check matches, but every reopen the
// writer performs refuses the symlink. Installing the writer there would send
// every record into a failing write that slog discards, so the daemon has to
// keep logging through stderr instead.
func TestDaemonLogWriter_SymlinkedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW has no counterpart on windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// launchd opens StandardErrorPath through the symlink, so stderr is the
	// target file the path resolves to.
	stderr, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = stderr.Close() }()

	if w := daemonLogWriter(stderr, path); w != nil {
		t.Errorf("daemonLogWriter() = %v, want nil for a symlinked path", w)
	}
}

// TestDaemonLogWriter_NilStderr covers a process started without a stderr:
// Stat has to report an error rather than panic.
func TestDaemonLogWriter_NilStderr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plexd.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if w := daemonLogWriter((*os.File)(nil), path); w != nil {
		t.Errorf("daemonLogWriter() = %v, want nil without a stderr", w)
	}
}

// restoreDaemonLogGlobals saves the process state useDaemonLogFile reads and
// writes, and puts it back when the test ends.
func restoreDaemonLogGlobals(t *testing.T) {
	t.Helper()

	logDir, handler, stderr := packaging.DefaultLogDir, newLogHandler, os.Stderr
	t.Cleanup(func() {
		packaging.DefaultLogDir, newLogHandler, os.Stderr = logDir, handler, stderr
	})
}

// installDaemonLogFile calls useDaemonLogFile where the test expects it to
// swap the handler, and closes the writer it installed when the test ends. It
// has to be called after t.TempDir(): cleanups run last-in first-out, and the
// file the writer holds must be closed before the directory holding it is
// removed, which Windows refuses while a handle on the file is open.
func installDaemonLogFile(t *testing.T) {
	t.Helper()

	w := useDaemonLogFile()
	if w == nil {
		t.Fatal("useDaemonLogFile() = nil, want the writer when stderr is the daemon log file")
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
}

// TestUseDaemonLogFile_NoOpWithoutLogDir is Linux and Windows, where the
// service manager keeps the daemon's output itself. Swapping the handler there
// would take the Windows service's output off the Event Log, which is the only
// sink a process without a console has.
func TestUseDaemonLogFile_NoOpWithoutLogDir(t *testing.T) {
	restoreDaemonLogGlobals(t)

	packaging.DefaultLogDir = ""
	before := reflect.ValueOf(newLogHandler).Pointer()

	if w := useDaemonLogFile(); w != nil {
		t.Errorf("useDaemonLogFile() = %v, want nil where the platform keeps no daemon log file", w)
	}

	if reflect.ValueOf(newLogHandler).Pointer() != before {
		t.Error("newLogHandler was swapped where the platform keeps no daemon log file")
	}
}

// TestUseDaemonLogFile_NoOpForConsoleRun is plexd up in a terminal: stderr is
// not the daemon log file, so the handler keeps writing to the terminal.
func TestUseDaemonLogFile_NoOpForConsoleRun(t *testing.T) {
	restoreDaemonLogGlobals(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, packaging.DaemonLogFile), nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	console, err := os.Create(filepath.Join(dir, "console"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = console.Close() }()

	packaging.DefaultLogDir = dir
	os.Stderr = console
	before := reflect.ValueOf(newLogHandler).Pointer()

	if w := useDaemonLogFile(); w != nil {
		t.Errorf("useDaemonLogFile() = %v, want nil for a run whose stderr is not the daemon log file", w)
	}

	if reflect.ValueOf(newLogHandler).Pointer() != before {
		t.Error("newLogHandler was swapped for a run whose stderr is not the daemon log file")
	}
}

// TestUseDaemonLogFile_SwapsHandlerWhenStderrIsTheLogFile is the launchd case,
// end to end: the path is built from the same constants launchd's plist is,
// so the logger setupLogger returns writes through the reopening writer.
func TestUseDaemonLogFile_SwapsHandlerWhenStderrIsTheLogFile(t *testing.T) {
	restoreDaemonLogGlobals(t)

	dir := t.TempDir()
	path := filepath.Join(dir, packaging.DaemonLogFile)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = f.Close() }()

	packaging.DefaultLogDir = dir
	os.Stderr = f

	installDaemonLogFile(t)
	setupLogger("info").Info("hello")

	if got := readLogFile(t, path); !strings.Contains(got, "hello") {
		t.Errorf("%s = %q, want it to hold the line the daemon logger wrote", path, got)
	}
}

// TestUseDaemonLogFile_HandlerHonoursLevel pins that the swapped handler keeps
// the level setupLogger selected, which is what the plain stderr handler does.
func TestUseDaemonLogFile_HandlerHonoursLevel(t *testing.T) {
	restoreDaemonLogGlobals(t)

	dir := t.TempDir()
	path := filepath.Join(dir, packaging.DaemonLogFile)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = f.Close() }()

	packaging.DefaultLogDir = dir
	os.Stderr = f

	installDaemonLogFile(t)
	if newLogHandler(slog.LevelWarn).Enabled(t.Context(), slog.LevelInfo) {
		t.Error("the swapped handler logs below its level")
	}
}
