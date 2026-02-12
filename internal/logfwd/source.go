package logfwd

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
)

// LogSource collects log entries from a specific source.
type LogSource interface {
	Collect(ctx context.Context) ([]api.LogEntry, error)
}

// LogReporter abstracts the control plane log reporting API.
type LogReporter interface {
	ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error
}
