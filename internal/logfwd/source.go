package logfwd

import (
	"context"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// systemLogWindow is how far back the first collection of a platform log
// source reaches, matching journalctl's --since=60 seconds ago.
const systemLogWindow = 60 * time.Second

// LogSource collects log entries from a specific source.
type LogSource interface {
	Collect(ctx context.Context) ([]api.LogEntry, error)
}

// LogReporter abstracts the control plane log reporting API.
type LogReporter interface {
	ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error
}
