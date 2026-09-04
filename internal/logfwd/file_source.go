package logfwd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// MaxLineBytes is the maximum line length before truncation.
const MaxLineBytes = 16384

const truncatedSuffix = "[truncated]"

// fileState tracks read position and file identity for a single file.
type fileState struct {
	offset int64
	info   os.FileInfo
}

// FileSource implements LogSource by reading from log files matching a glob pattern.
type FileSource struct {
	pattern  string
	hostname string
	logger   *slog.Logger
	states   map[string]fileState

	// openFlags are added to every open this source performs, so a caller
	// that reads a file somebody else may substitute can constrain what the
	// open accepts. Zero for a plain glob source; DaemonLogSource sets
	// daemonLogReadFlags. The flags belong here rather than in a check in
	// front of the read, because only the open itself sees the file the read
	// will return.
	openFlags int
}

// NewFileSource creates a new FileSource.
// pattern is a glob expression (e.g., "/var/log/app/*.log").
func NewFileSource(pattern, hostname string, logger *slog.Logger) *FileSource {
	return &FileSource{
		pattern:  pattern,
		hostname: hostname,
		logger:   logger,
		states:   make(map[string]fileState),
	}
}

// Collect reads new lines from all files matching the glob pattern.
func (s *FileSource) Collect(ctx context.Context) ([]api.LogEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("logfwd: file: %w", err)
	}

	matches, err := filepath.Glob(s.pattern)
	if err != nil {
		return nil, fmt.Errorf("logfwd: file: glob %q: %w", s.pattern, err)
	}

	var entries []api.LogEntry
	for _, path := range matches {
		if err := ctx.Err(); err != nil {
			return entries, fmt.Errorf("logfwd: file: %w", err)
		}

		fileEntries, err := s.readFile(path)
		if err != nil {
			s.logger.Warn("logfwd: file: read failed",
				slog.String("path", path),
				slog.Any("error", err),
			)
			continue // Skip unreadable files.
		}
		entries = append(entries, fileEntries...)
	}

	return entries, nil
}

// readFile reads new lines from a single file, tracking offset and detecting rotation.
func (s *FileSource) readFile(path string) ([]api.LogEntry, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|s.openFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Stat through the open handle rather than the path. A FileInfo from
	// os.Stat carries its identity lazily on Windows: os.SameFile resolves it
	// by reopening the path the FileInfo was made from, and after a rotation
	// that path holds the new file, so both sides of the comparison resolve to
	// the same file and the rotation goes unnoticed. A handle pins the file it
	// was opened on, on every platform.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	state, exists := s.states[path]

	// Detect file rotation: a different file now carries this path, or the file
	// is smaller than our offset. The !exists test comes first so os.SameFile
	// never sees a nil state.info.
	if !exists || !os.SameFile(state.info, info) || info.Size() < state.offset {
		state = fileState{offset: 0}
	}
	state.info = info

	// No new data.
	if info.Size() == state.offset {
		s.states[path] = state
		return nil, nil
	}

	if state.offset > 0 {
		if _, err := f.Seek(state.offset, 0); err != nil {
			return nil, err
		}
	}

	var entries []api.LogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, MaxLineBytes+len(truncatedSuffix)+1), MaxLineBytes*2)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > MaxLineBytes {
			line = line[:MaxLineBytes] + truncatedSuffix
		}
		if line == "" {
			continue
		}
		entries = append(entries, api.LogEntry{
			Timestamp: time.Now(),
			Source:    "file",
			Unit:      path,
			Message:   line,
			Severity:  "info",
			Hostname:  s.hostname,
		})
	}

	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("scan %s: %w", path, err)
	}

	// Update offset to current position.
	pos, err := f.Seek(0, 1) // Seek(0, io.SeekCurrent)
	if err == nil {
		state.offset = pos
	}
	s.states[path] = state

	return entries, nil
}

// seekTail records path at an offset window bytes before its end, so the
// first Collect reads only that tail of a file that predates the source. A
// file shorter than window is read from its start. A missing file is not an
// error: Collect finds it later and reads it from the start. The offset can
// fall inside a line, so the first line the next Collect scans may be a
// fragment, which the caller drops.
func (s *FileSource) seekTail(path string, window int64) error {
	f, err := os.OpenFile(path, os.O_RDONLY|s.openFlags, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	// Stat through the open handle for the same reason readFile does: the
	// FileInfo goes into the state that os.SameFile later compares.
	info, err := f.Stat()
	if err != nil {
		return err
	}

	s.states[path] = fileState{offset: max(0, info.Size()-window), info: info}

	return nil
}
