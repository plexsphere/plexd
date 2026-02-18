package logfwd

import (
	"context"
	"log/slog"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// MultiReporter dispatches log batches to both a platform and a local reporter
// in parallel. The platform reporter's error is returned; local reporter errors
// are logged but do not affect the return value.
type MultiReporter struct {
	platform LogReporter
	local    LogReporter
	logger   *slog.Logger
}

// NewMultiReporter creates a MultiReporter that sends logs to both reporters.
func NewMultiReporter(platform, local LogReporter, logger *slog.Logger) *MultiReporter {
	return &MultiReporter{
		platform: platform,
		local:    local,
		logger:   logger,
	}
}

// ReportLogs sends the log batch to both reporters concurrently.
// Only the platform reporter's error is returned.
func (m *MultiReporter) ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var platformErr error
	var localErr error

	go func() {
		defer wg.Done()
		platformErr = m.platform.ReportLogs(ctx, nodeID, batch)
	}()

	go func() {
		defer wg.Done()
		localErr = m.local.ReportLogs(ctx, nodeID, batch)
	}()

	wg.Wait()

	if localErr != nil {
		m.logger.Warn("local log report failed", "component", "logfwd", "error", localErr)
	}

	return platformErr
}
