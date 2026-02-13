package auditfwd

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
)

// AuditSource collects audit entries from a specific source.
type AuditSource interface {
	Collect(ctx context.Context) ([]api.AuditEntry, error)
}

// AuditReporter abstracts the control plane audit reporting API.
type AuditReporter interface {
	ReportAudit(ctx context.Context, nodeID string, batch api.AuditBatch) error
}
