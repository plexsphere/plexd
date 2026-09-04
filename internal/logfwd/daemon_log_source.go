package logfwd

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// daemonLogTailBytes bounds what the first collection reads from a daemon
// log that predates the source: 64 KiB is several hundred lines.
const daemonLogTailBytes = 64 << 10

// DaemonLogSource tails the file a service manager writes the daemon's own
// output to and reads the time and level slog's text handler put on each
// line. On macOS that file is launchd's StandardErrorPath.
//
// Rotation needs no handling of its own: newsyslog renames the file and
// creates a new one, and the file source underneath sees a different file
// through its os.SameFile check and reads the new file from its start.
type DaemonLogSource struct {
	inner  *FileSource
	path   string
	unit   string
	logger *slog.Logger

	primed bool
	now    func() time.Time // time.Now; a test injects a clock
}

// NewDaemonLogSource creates a DaemonLogSource for the daemon log at path.
// Entries carry unit as their unit and hostname as their host.
func NewDaemonLogSource(path, unit, hostname string, logger *slog.Logger) *DaemonLogSource {
	inner := NewFileSource(path, hostname, logger)
	// What this source reads is reported as the daemon's own output, so the
	// file it opens has to be the one the daemon writes and not one somebody
	// else put there. /Library/Logs is writable by the admin group on macOS
	// and the daemon reads as root, so every open this source performs refuses
	// a symlink. The write side refuses the same substitution through
	// daemonLogOpenFlags.
	inner.openFlags = daemonLogReadFlags
	return &DaemonLogSource{
		inner:  inner,
		path:   path,
		unit:   unit,
		logger: logger,
		now:    time.Now,
	}
}

// Collect reads the lines the daemon log gained since the previous call and
// takes each entry's timestamp and severity from the slog tokens on its line.
// The first call reads at most the last daemonLogTailBytes and keeps only
// lines it can date inside systemLogWindow, so a restart forwards recent
// output instead of the whole file. A symlink at the path is refused by the
// open itself (see NewDaemonLogSource), so nothing is forwarded from it.
func (s *DaemonLogSource) Collect(ctx context.Context) ([]api.LogEntry, error) {
	first := !s.primed
	if first {
		s.primed = true
		if err := s.inner.seekTail(s.path, daemonLogTailBytes); err != nil {
			// Without the offset the file is read from its start, which is
			// noisy but still correct, so the collection goes ahead.
			s.logger.Warn("logfwd: daemonlog: tail failed",
				slog.String("path", s.path),
				slog.Any("error", err),
			)
		}
	}

	entries, err := s.inner.Collect(ctx)

	cutoff := s.now().Add(-systemLogWindow)
	kept := entries[:0]
	for _, entry := range entries {
		// The forwarder logs through the same handler that writes this file,
		// so its own diagnostics would come back as input to its next
		// collection.
		if strings.Contains(entry.Message, selfLogMarker) {
			continue
		}
		entry.Source = "daemonlog"
		entry.Unit = s.unit
		ts, severity, ok := parseSlogLine(entry.Message)
		if ok {
			entry.Timestamp = ts
			entry.Severity = severity
		}
		// The tail offset can fall inside a line and the tail can reach back
		// past the window, so the first collection keeps only the lines it can
		// date inside it. Later collections start at a line boundary and
		// forward everything, an unparsable line included.
		if first && (!ok || ts.Before(cutoff)) {
			continue
		}
		kept = append(kept, entry)
	}

	if len(kept) == 0 {
		return nil, err
	}
	return kept, err
}

// parseSlogLine reads the time= and level= tokens slog.TextHandler writes at
// the start of every record. ok is false for any other line.
func parseSlogLine(line string) (ts time.Time, severity string, ok bool) {
	rest, found := strings.CutPrefix(line, "time=")
	if !found {
		return time.Time{}, "", false
	}

	stamp, rest, _ := strings.Cut(rest, " ")
	ts, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return time.Time{}, "", false
	}

	rest, found = strings.CutPrefix(rest, "level=")
	if !found {
		return time.Time{}, "", false
	}

	level, _, _ := strings.Cut(rest, " ")
	// slog renders a level with an offset as INFO+2 or DEBUG-4. Only the name
	// in front of the offset carries the severity.
	if i := strings.IndexAny(level, "+-"); i >= 0 {
		level = level[:i]
	}

	return ts, slogLevelSeverity(level), true
}

// slogLevelSeverity maps a slog level name to a syslog severity: DEBUG to
// debug, INFO to info, WARN to warning, ERROR to err. Anything else is info.
func slogLevelSeverity(level string) string {
	switch level {
	case "DEBUG":
		return "debug"
	case "INFO":
		return "info"
	case "WARN":
		return "warning"
	case "ERROR":
		return "err"
	default:
		return "info"
	}
}
