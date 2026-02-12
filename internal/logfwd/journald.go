package logfwd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// JournalEntry represents a single entry read from the systemd journal.
type JournalEntry struct {
	Timestamp time.Time
	Message   string
	Priority  int
	Unit      string
}

// JournalReader abstracts systemd journal access for testability.
type JournalReader interface {
	ReadEntries(ctx context.Context) ([]JournalEntry, error)
}

// priorityToSeverity maps syslog priority levels (0-7) to severity strings.
var priorityToSeverity = [8]string{
	"emerg",   // 0
	"alert",   // 1
	"crit",    // 2
	"err",     // 3
	"warning", // 4
	"notice",  // 5
	"info",    // 6
	"debug",   // 7
}

// mapSeverity converts a syslog priority (0-7) to a severity string.
// Out-of-range values default to "info".
func mapSeverity(priority int) string {
	if priority < 0 || priority > 7 {
		return "info"
	}
	return priorityToSeverity[priority]
}

// JournaldSource implements LogSource by reading from the systemd journal.
type JournaldSource struct {
	reader   JournalReader
	hostname string
	logger   *slog.Logger
}

// NewJournaldSource creates a new JournaldSource.
func NewJournaldSource(reader JournalReader, hostname string, logger *slog.Logger) *JournaldSource {
	return &JournaldSource{
		reader:   reader,
		hostname: hostname,
		logger:   logger,
	}
}

// Collect reads journal entries and maps them to api.LogEntry values.
func (s *JournaldSource) Collect(ctx context.Context) ([]api.LogEntry, error) {
	entries, err := s.reader.ReadEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("logfwd: journald: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	logs := make([]api.LogEntry, len(entries))
	for i, e := range entries {
		logs[i] = api.LogEntry{
			Timestamp: e.Timestamp,
			Source:    "journald",
			Unit:      e.Unit,
			Message:   e.Message,
			Severity:  mapSeverity(e.Priority),
			Hostname:  s.hostname,
		}
	}
	return logs, nil
}
