package auditfwd

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ProcessSource implements AuditSource by emitting a single "plexd_started"
// audit entry on the first Collect call. Subsequent calls return nil.
type ProcessSource struct {
	hostname string
	once     sync.Once
	entry    []api.AuditEntry
}

// NewProcessSource creates a new ProcessSource.
func NewProcessSource(hostname string) *ProcessSource {
	pid := os.Getpid()
	subject, _ := json.Marshal(map[string]int{"pid": pid})
	object, _ := json.Marshal("plexd")
	return &ProcessSource{
		hostname: hostname,
		entry: []api.AuditEntry{
			{
				Timestamp: time.Now(),
				Source:    "process",
				EventType: "process_start",
				Subject:   subject,
				Object:    object,
				Action:    "start",
				Result:    "success",
				Hostname:  hostname,
			},
		},
	}
}

// Collect returns the startup entry on the first call, nil thereafter.
func (s *ProcessSource) Collect(_ context.Context) ([]api.AuditEntry, error) {
	var result []api.AuditEntry
	s.once.Do(func() {
		result = s.entry
	})
	return result, nil
}
