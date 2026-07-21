package logfwd

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
// no errors — which makes this log the only signal an operator gets that log
// lines are disappearing.
const dropLogInterval = 5 * time.Minute

// IngestClient is the control-plane seam a PlatformReporter reports wire log
// lines through. It is defined here (rather than reused from the api package)
// so the logfwd package owns the exact shape it depends on.
type IngestClient interface {
	ReportLogs(ctx context.Context, nodeID string, lines []api.LogLine) (*api.IngestReceipt, error)
}

// wireSeverities is the closed set of severities the logs ingest contract
// accepts. A record carrying anything else is coerced to "info" before it is
// sent (defensive: no current producer emits one).
var wireSeverities = map[string]bool{
	"emerg":   true,
	"alert":   true,
	"crit":    true,
	"err":     true,
	"warning": true,
	"notice":  true,
	"info":    true,
	"debug":   true,
}

// PlatformReporter implements LogReporter by converting each log entry into a
// wire LogLine and posting them to the platform ingest endpoint through an
// IngestClient.
type PlatformReporter struct {
	client IngestClient
	logger *slog.Logger

	// notProvisioned records that the platform last refused ingest with a 501
	// observability_ingest_not_provisioned problem. It guards the transition and
	// recovery logs so a steady stream of 501s is only announced once.
	notProvisioned bool

	// dropped is the running count of log lines this reporter discarded, and
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

// recordDrop adds n discarded lines to the running count and summarizes it at
// most once per dropLogInterval, so a drop condition that persists stays visible
// instead of being announced once and then falling silent.
func (r *PlatformReporter) recordDrop(n int, reason string) {
	r.dropped += n
	if !r.lastDropLog.IsZero() && time.Since(r.lastDropLog) < dropLogInterval {
		return
	}
	r.lastDropLog = time.Now()
	r.logger.Warn("dropping log lines",
		"component", "logfwd",
		"reason", reason,
		"dropped", n,
		"dropped_total", r.dropped,
	)
}

// ReportLogs converts the batch into wire log lines and posts them through the
// ingest client. An entry with an empty message or a zero timestamp is skipped
// (the contract requires both and would 400 the whole batch); a severity
// outside the wire set is coerced to "info". When no lines survive, it returns
// nil without calling the client (the ingest contract rejects an empty array).
// Every line the reporter discards is counted and periodically summarized,
// because dropping is invisible to the forwarder's own status.
func (r *PlatformReporter) ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error {
	lines := make([]api.LogLine, 0, len(batch))
	for _, e := range batch {
		if e.Message == "" {
			r.logger.Debug("logfwd: skipping log entry with empty message",
				"component", "logfwd", "source", e.Source)
			r.recordDrop(1, "empty message")
			continue
		}
		if e.Timestamp.IsZero() {
			r.logger.Debug("logfwd: skipping log entry with zero timestamp",
				"component", "logfwd", "source", e.Source)
			r.recordDrop(1, "zero timestamp")
			continue
		}
		lines = append(lines, toLogLine(e))
	}

	if len(lines) == 0 {
		return nil
	}

	return r.send(ctx, nodeID, lines)
}

// send posts lines through the ingest client, halving the batch and re-sending
// each half when the platform refuses it as too large (413). Only the size is
// refused, not the content, so splitting eventually fits; a lone line that is
// still refused cannot be split any further and is dropped. Without this the
// forwarder — which chunks by line count, never by bytes — would draw the
// identical 413 on every flush and lose every log line permanently.
//
// A split that partially succeeds and then hits a transient failure returns the
// error for the whole chunk, so Forwarder.flush re-buffers lines the platform
// already accepted. Duplicating a line upstream is the lesser evil against
// losing one, and the ingest contract carries no idempotency key to do better.
func (r *PlatformReporter) send(ctx context.Context, nodeID string, lines []api.LogLine) error {
	err := r.post(ctx, nodeID, lines)
	if !api.IsIngestTooLarge(err) {
		return err
	}
	if len(lines) == 1 {
		r.recordDrop(1, "single log line over the platform ingest size limit")
		return nil
	}
	mid := len(lines) / 2
	if err := r.send(ctx, nodeID, lines[:mid]); err != nil {
		return err
	}
	return r.send(ctx, nodeID, lines[mid:])
}

// post is a single ingest attempt. A 501 observability_ingest_not_provisioned
// refusal and a permanent batch refusal (400 ingest_batch_malformed) are treated
// as a drop (return nil) so the batch is not re-buffered and re-sent forever;
// any other client error, 413 included, is returned unchanged for the caller to
// classify.
func (r *PlatformReporter) post(ctx context.Context, nodeID string, lines []api.LogLine) error {
	receipt, err := r.client.ReportLogs(ctx, nodeID, lines)
	if err != nil {
		if api.IsIngestNotProvisioned(err) {
			if !r.notProvisioned {
				r.logger.Info("platform observability ingest not provisioned; dropping logs",
					"component", "logfwd")
				r.notProvisioned = true
			}
			r.recordDrop(len(lines), "platform observability ingest not provisioned")
			return nil
		}
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && api.IsIngestPermanentlyRefused(err) {
			r.logger.Warn("platform ingest refused batch permanently; dropping",
				"component", "logfwd", "status", apiErr.StatusCode, "code", apiErr.Code)
			r.recordDrop(len(lines), "platform refused the batch as malformed")
			return nil
		}
		return err
	}

	r.logger.Debug("logs reported to platform",
		"component", "logfwd",
		"accepted_at", receipt.AcceptedAt,
	)
	if receipt.Records != len(lines) {
		r.logger.Warn("platform ingest accepted a different record count than sent",
			"component", "logfwd",
			"sent", len(lines),
			"accepted", receipt.Records,
		)
	}
	if r.notProvisioned {
		r.logger.Info("platform observability ingest provisioning recovered",
			"component", "logfwd")
		r.notProvisioned = false
	}
	return nil
}

// toLogLine converts an internal LogEntry to a wire LogLine. Source is dropped
// (the wire contract has no such field); a severity outside the accepted set is
// coerced to "info".
func toLogLine(e api.LogEntry) api.LogLine {
	severity := e.Severity
	if !wireSeverities[severity] {
		severity = "info"
	}
	return api.LogLine{
		Severity:  severity,
		Unit:      e.Unit,
		Hostname:  e.Hostname,
		Message:   e.Message,
		Timestamp: e.Timestamp,
	}
}
