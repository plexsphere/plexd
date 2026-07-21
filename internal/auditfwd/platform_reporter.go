package auditfwd

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// dropLogInterval is the shortest gap between two summaries of the running
// dropped-record count. Dropping is invisible to Forwarder.flush — it takes the
// success path either way, so Status() keeps reporting a fresh last report and
// no errors — which makes this log the only signal an operator gets. Announcing
// a persistent drop condition once and then falling silent would leave the
// audit trail disappearing with nothing to notice it by.
const dropLogInterval = 5 * time.Minute

// IngestClient is the control-plane seam a PlatformReporter reports wire audit
// events through. It is defined here (rather than reused from the api package)
// so the auditfwd package owns the exact shape it depends on.
type IngestClient interface {
	ReportAudit(ctx context.Context, nodeID string, events []api.AuditEvent) (*api.IngestReceipt, error)
}

// wireSources maps an internal audit source to the source value the audit
// ingest contract accepts. plexd's own process_start event is reported under
// the distinct "plexd" source so it stays attributable upstream instead of
// being conflated with real kernel auditd records. A source absent from this
// map is not part of the contract and its entries are skipped.
var wireSources = map[string]string{
	"auditd":    "auditd",
	"k8s-audit": "k8s",
	"process":   "plexd",
}

// PlatformReporter implements AuditReporter by converting each audit entry into
// a wire AuditEvent and posting them to the platform ingest endpoint through an
// IngestClient.
type PlatformReporter struct {
	client IngestClient
	logger *slog.Logger

	// notProvisioned records that the platform last refused ingest with a 501
	// observability_ingest_not_provisioned problem. It guards the transition and
	// recovery logs so a steady stream of 501s is only announced once.
	notProvisioned bool

	// dropped is the running count of audit records this reporter discarded, and
	// lastDropLog when that count was last summarized. Both are touched only from
	// the forwarder's single flush goroutine.
	dropped     int
	lastDropLog time.Time
}

// NewPlatformReporter creates a PlatformReporter that reports through client.
func NewPlatformReporter(client IngestClient, logger *slog.Logger) *PlatformReporter {
	return &PlatformReporter{
		client: client,
		logger: logger,
	}
}

// recordDrop adds n discarded records to the running count and summarizes it at
// most once per dropLogInterval, so a drop condition that persists stays visible
// instead of being announced once and then falling silent.
func (r *PlatformReporter) recordDrop(n int, reason string) {
	r.dropped += n
	if !r.lastDropLog.IsZero() && time.Since(r.lastDropLog) < dropLogInterval {
		return
	}
	r.lastDropLog = time.Now()
	r.logger.Warn("dropping audit records",
		"component", "auditfwd",
		"reason", reason,
		"dropped", n,
		"dropped_total", r.dropped,
	)
}

// ReportAudit converts the batch into wire audit events and posts them through
// the ingest client. An entry whose source is not part of the contract is
// skipped (Warn); an entry with an empty action or result, or a zero timestamp,
// is skipped (Debug), as the contract requires all three and would 400 the whole
// batch. When no events survive, it returns nil without calling the client (the
// ingest contract rejects an empty array). Every record the reporter discards is
// counted and periodically summarized, because dropping is invisible to the
// forwarder's own status.
func (r *PlatformReporter) ReportAudit(ctx context.Context, nodeID string, batch api.AuditBatch) error {
	events := make([]api.AuditEvent, 0, len(batch))
	for _, e := range batch {
		source, ok := wireSources[e.Source]
		if !ok {
			r.logger.Warn("auditfwd: skipping audit entry with unknown source",
				"component", "auditfwd", "source", e.Source)
			r.recordDrop(1, "source outside the audit ingest contract")
			continue
		}
		if e.Action == "" || e.Result == "" {
			r.logger.Debug("auditfwd: skipping audit entry with empty action or result",
				"component", "auditfwd", "source", e.Source)
			r.recordDrop(1, "empty action or result")
			continue
		}
		if e.Timestamp.IsZero() {
			r.logger.Debug("auditfwd: skipping audit entry with zero timestamp",
				"component", "auditfwd", "source", e.Source)
			r.recordDrop(1, "zero timestamp")
			continue
		}
		events = append(events, api.AuditEvent{
			Source:    source,
			Action:    e.Action,
			Outcome:   e.Result,
			Timestamp: e.Timestamp,
		})
	}

	if len(events) == 0 {
		return nil
	}

	return r.send(ctx, nodeID, events)
}

// send posts events through the ingest client, halving the batch and re-sending
// each half when the platform refuses it as too large (413). Only the size is
// refused, not the content, so splitting eventually fits; a lone event that is
// still refused cannot be split any further and is dropped. Without this the
// forwarders — which chunk by record count, never by bytes — would draw the
// identical 413 on every flush and lose the audit trail permanently.
//
// A split that partially succeeds and then hits a transient failure returns the
// error for the whole chunk, so Forwarder.flush re-buffers records the platform
// already accepted. Duplicating a record upstream is the lesser evil against
// losing one, and the ingest contract carries no idempotency key to do better.
func (r *PlatformReporter) send(ctx context.Context, nodeID string, events []api.AuditEvent) error {
	err := r.post(ctx, nodeID, events)
	if !api.IsIngestTooLarge(err) {
		return err
	}
	if len(events) == 1 {
		r.recordDrop(1, "single audit event over the platform ingest size limit")
		return nil
	}
	mid := len(events) / 2
	if err := r.send(ctx, nodeID, events[:mid]); err != nil {
		return err
	}
	return r.send(ctx, nodeID, events[mid:])
}

// post is a single ingest attempt. A 501 observability_ingest_not_provisioned
// refusal and a permanent batch refusal (400 ingest_batch_malformed) are treated
// as a drop (return nil) so the batch is not re-buffered and re-sent forever;
// any other client error, 413 included, is returned unchanged for the caller to
// classify.
func (r *PlatformReporter) post(ctx context.Context, nodeID string, events []api.AuditEvent) error {
	receipt, err := r.client.ReportAudit(ctx, nodeID, events)
	if err != nil {
		if api.IsIngestNotProvisioned(err) {
			if !r.notProvisioned {
				r.logger.Info("platform observability ingest not provisioned; dropping audit events",
					"component", "auditfwd")
				r.notProvisioned = true
			}
			r.recordDrop(len(events), "platform observability ingest not provisioned")
			return nil
		}
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && api.IsIngestPermanentlyRefused(err) {
			r.logger.Warn("platform ingest refused batch permanently; dropping",
				"component", "auditfwd", "status", apiErr.StatusCode, "code", apiErr.Code)
			r.recordDrop(len(events), "platform refused the batch as malformed")
			return nil
		}
		return err
	}

	r.logger.Debug("audit events reported to platform",
		"component", "auditfwd",
		"accepted_at", receipt.AcceptedAt,
	)
	if receipt.Records != len(events) {
		r.logger.Warn("platform ingest accepted a different record count than sent",
			"component", "auditfwd",
			"sent", len(events),
			"accepted", receipt.Records,
		)
	}
	if r.notProvisioned {
		r.logger.Info("platform observability ingest provisioning recovered",
			"component", "auditfwd")
		r.notProvisioned = false
	}
	return nil
}
