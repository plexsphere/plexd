package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/plexsphere/plexd/internal/packaging"
)

// reopeningLogFile is an io.Writer over a log file that a rotation tool
// renames away and recreates (newsyslog on macOS). Before every write it
// checks that the file it holds is still the one at path, and reopens the
// path when it is not, so the write lands in the file that replaced it.
type reopeningLogFile struct {
	path string

	mu   sync.Mutex
	f    *os.File
	info os.FileInfo
}

// newReopeningLogFile returns a writer over path. It opens nothing yet; the
// first Write does.
func newReopeningLogFile(path string) *reopeningLogFile {
	return &reopeningLogFile{path: path}
}

// Write writes p to the file at the writer's path, after reopening that path
// when the file the writer holds is no longer the one sitting there. A path
// that cannot be opened fails the write.
//
// There is deliberately no fallback to stderr. The writer only exists where
// stderr already is this path (see daemonLogWriter), so after the first
// rotation fd 2 refers to the renamed file, which newsyslog's J flag unlinks
// once it has compressed it. Writing there would put the line into an inode no
// name resolves to and keep that inode alive, growing, for the life of the
// process. Reporting the failure loses the same line and nothing else.
//
// The cost is one os.Stat per write. The daemon logs a few lines per second at
// most, which makes the syscall cheaper than the state a shared rotation
// signal would need, and cheaper than the lines a stale descriptor loses.
func (w *reopeningLogFile) Write(p []byte) (int, error) {
	// slog handlers are called from every goroutine that logs, so the file and
	// the identity it was opened with are only ever touched under the lock.
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureCurrent(); err != nil {
		return 0, err
	}
	return w.f.Write(p)
}

// ensureCurrent makes the held file the one that is at the writer's path right
// now, opening the path when it holds none. The caller holds w.mu.
func (w *reopeningLogFile) ensureCurrent() error {
	if w.f != nil {
		// The held side of the comparison comes from the open handle, which
		// pins the file it was opened on; the other side is resolved from the
		// path, which after a rotation is the new file. An os.Stat error means
		// nothing is at the path at all, which is just as stale.
		cur, err := os.Stat(w.path)
		if err != nil || !os.SameFile(w.info, cur) {
			_ = w.f.Close()
			w.f, w.info = nil, nil
		}
	}
	if w.f != nil {
		return nil
	}

	// daemonLogOpenFlags refuses a symlink: the daemon runs as root and
	// /Library/Logs is group-writable by admin, so the path this reopens on
	// every rotation is one an unprivileged admin-group user can replace.
	f, err := os.OpenFile(w.path, daemonLogOpenFlags, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f, w.info = f, info
	return nil
}

// Close closes the file the writer holds, if it holds one. A writer that never
// opened a file, and a second Close, both return nil.
func (w *reopeningLogFile) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f, w.info = nil, nil
	return err
}

// daemonLogWriter returns the writer the daemon logs through when stderr is
// the file at path, and nil when it is not. It answers nil for a console run
// and for a service definition that points the daemon's output somewhere else,
// where following path would move the output off the descriptor the service
// manager set up.
func daemonLogWriter(stderr *os.File, path string) *reopeningLogFile {
	// A nil *os.File reports os.ErrInvalid here instead of panicking, so this
	// covers a process started without a stderr as well.
	sinfo, err := stderr.Stat()
	if err != nil {
		return nil
	}
	// Lstat, not Stat: daemonLogOpenFlags refuses a symlink, so a symlinked
	// path would install a writer whose every write fails on ELOOP, and
	// slog.Logger drops what a handler could not write. Answering nil leaves
	// the handler on stderr, which launchd already opened through the symlink,
	// so the daemon keeps logging. For a path that is not a symlink Lstat
	// describes the same file Stat would.
	//
	// This runs once, at startup. A symlink planted after the writer is
	// installed is not covered: the reopen refuses it on every write from then
	// on, which loses the daemon's local log rather than redirecting it. That
	// is the safe half of the trade and the deliberate one, but it is silent -
	// there is no channel left to report it on once the log file is gone.
	pinfo, err := os.Lstat(path)
	if err != nil || pinfo.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if !os.SameFile(sinfo, pinfo) {
		return nil
	}
	return newReopeningLogFile(path)
}

// useDaemonLogFile swaps newLogHandler to write through a reopeningLogFile
// when the process's stderr is the service manager's daemon log file. That is
// the macOS case: launchd points StandardOutPath and StandardErrorPath at the
// file, and the newsyslog rule plexd install writes rotates it by renaming it,
// with neither a pid file nor a signal to tell the daemon to reopen it.
//
// Output that does not come from the handler still goes to fd 2, and after a
// rotation stays in the renamed file: a Go panic trace, and the missing-config
// warning root.go writes before the logger exists. Both are acceptable there,
// since a trace ends the process and the next start opens the current file.
//
// It returns the writer it installed, so the caller can close the file it
// holds once the daemon is done, and nil when it left the handler alone.
func useDaemonLogFile() *reopeningLogFile {
	// Empty on Linux and Windows, where journald and the Event Log keep the
	// daemon's output and no such file exists. Leaving early keeps the stat
	// off those platforms entirely.
	if packaging.DefaultLogDir == "" {
		return nil
	}

	w := daemonLogWriter(os.Stderr, filepath.Join(packaging.DefaultLogDir, packaging.DaemonLogFile))
	if w == nil {
		return nil
	}
	newLogHandler = func(lvl slog.Level) slog.Handler {
		return slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl})
	}
	return w
}
