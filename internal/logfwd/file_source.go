package logfwd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// MaxLineBytes is the maximum line length before truncation.
const MaxLineBytes = 16384

const truncatedSuffix = "[truncated]"

// fileState tracks read position and inode for a single file.
type fileState struct {
	offset int64
	inode  uint64
}

// FileSource implements LogSource by reading from log files matching a glob pattern.
type FileSource struct {
	pattern  string
	hostname string
	logger   *slog.Logger
	states   map[string]fileState
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("unsupported file stat type for %s", path)
	}

	state, exists := s.states[path]

	// Detect file rotation: inode changed or file is smaller than our offset.
	if exists && (stat.Ino != state.inode || info.Size() < state.offset) {
		state = fileState{offset: 0, inode: stat.Ino}
	} else if !exists {
		state = fileState{offset: 0, inode: stat.Ino}
	}

	// No new data.
	if info.Size() == state.offset {
		s.states[path] = state
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

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
