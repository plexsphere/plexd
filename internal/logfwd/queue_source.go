package logfwd

import (
	"context"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// queueSourceCapacity bounds the entries a QueueSource holds between two
// collections. At the policy connection logger's limit of 5 lines a second
// that is 200 s of lines.
const queueSourceCapacity = 1000

// QueueSource implements LogSource for lines plexd hands it directly rather
// than writes to a log a platform source reads back. Where plexd has no
// platform log source, as on Linux without journalctl, the policy connection
// logger forwards its lines through it. Entries carry source and unit plexd.
//
// It is safe for concurrent use.
type QueueSource struct {
	hostname string

	mu      sync.Mutex
	entries []api.LogEntry
}

// NewQueueSource creates an empty QueueSource whose entries carry hostname as
// their host.
func NewQueueSource(hostname string) *QueueSource {
	return &QueueSource{hostname: hostname}
}

// Add queues a line logged at ts with severity. Beyond queueSourceCapacity
// entries it drops the oldest.
func (s *QueueSource) Add(ts time.Time, severity, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, api.LogEntry{
		Timestamp: ts,
		Source:    "plexd",
		Unit:      "plexd",
		Message:   message,
		Severity:  severity,
		Hostname:  s.hostname,
	})
	if over := len(s.entries) - queueSourceCapacity; over > 0 {
		s.entries = s.entries[over:]
	}
}

// Collect returns the queued entries and empties the queue. It returns nil
// when nothing is queued.
func (s *QueueSource) Collect(_ context.Context) ([]api.LogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		return nil, nil
	}
	entries := s.entries
	s.entries = nil
	return entries, nil
}
