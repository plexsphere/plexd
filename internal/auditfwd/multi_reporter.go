package auditfwd

import (
	"context"
	"log/slog"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// MultiReporter dispatches audit batches to both a platform and a local
// reporter in parallel. The platform error is always returned; a local
// failure is logged but does not affect the caller.
type MultiReporter struct {
	platform AuditReporter
	local    AuditReporter
	logger   *slog.Logger
}

// NewMultiReporter creates a MultiReporter that fans out to platform and local.
func NewMultiReporter(platform, local AuditReporter, logger *slog.Logger) *MultiReporter {
	return &MultiReporter{
		platform: platform,
		local:    local,
		logger:   logger,
	}
}

// ReportAudit sends the batch to both reporters concurrently.
// Only the platform error is returned; a local error is logged at the level
// failureLevel gives.
func (m *MultiReporter) ReportAudit(ctx context.Context, nodeID string, batch api.AuditBatch) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var platformErr error
	var localErr error

	go func() {
		defer wg.Done()
		platformErr = m.platform.ReportAudit(ctx, nodeID, batch)
	}()

	go func() {
		defer wg.Done()
		localErr = m.local.ReportAudit(ctx, nodeID, batch)
	}()

	wg.Wait()

	if localErr != nil {
		m.logger.Log(ctx, failureLevel(localErr), "local audit report failed", "component", "auditfwd", "error", localErr)
	}

	return platformErr
}
