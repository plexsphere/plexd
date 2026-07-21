package metrics

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// dropLogInterval is the shortest gap between two summaries of the running
// dropped-sample count. Dropping is invisible to Manager.flush — it takes the
// success path either way — which makes this log the only signal an operator
// gets that metrics are disappearing.
const dropLogInterval = 5 * time.Minute

// IngestClient is the control-plane seam a PlatformReporter reports flattened
// metric samples through. It is defined here (rather than reused from the api
// package) so the metrics package owns the exact shape it depends on.
type IngestClient interface {
	ReportMetrics(ctx context.Context, nodeID string, samples []api.MetricSample) (*api.IngestReceipt, error)
}

// PlatformReporter implements MetricsReporter by flattening each metric point
// into wire samples and posting them to the platform ingest endpoint through an
// IngestClient.
type PlatformReporter struct {
	client IngestClient
	logger *slog.Logger

	// notProvisioned records that the platform last refused ingest with a 501
	// observability_ingest_not_provisioned problem. It guards the transition and
	// recovery logs so a steady stream of 501s is only announced once.
	notProvisioned bool

	// dropped is the running count of wire samples this reporter discarded, and
	// lastDropLog when that count was last summarized. Both are touched only from
	// the manager's single flush goroutine.
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

// recordDrop adds n discarded samples to the running count and summarizes it at
// most once per dropLogInterval, so a drop condition that persists stays visible
// instead of being announced once and then falling silent.
func (r *PlatformReporter) recordDrop(n int, reason string) {
	r.dropped += n
	if !r.lastDropLog.IsZero() && time.Since(r.lastDropLog) < dropLogInterval {
		return
	}
	r.lastDropLog = time.Now()
	r.logger.Warn("dropping metric samples",
		"component", "metrics",
		"reason", reason,
		"dropped", n,
		"dropped_total", r.dropped,
	)
}

// ReportMetrics flattens the batch into wire samples and posts them through the
// ingest client. Points that fail conversion are logged and skipped. When no
// samples survive, it returns nil without calling the client (the ingest
// contract rejects an empty array). Every sample the reporter discards is
// counted and periodically summarized, because dropping is invisible to the
// manager's own status.
func (r *PlatformReporter) ReportMetrics(ctx context.Context, nodeID string, batch api.MetricBatch) error {
	samples := make([]api.MetricSample, 0, len(batch))
	for _, p := range batch {
		s, err := toSamples(p, r.logger)
		if err != nil {
			r.logger.Warn("metrics: skipping unconvertible point", "component", "metrics", "error", err)
			r.recordDrop(1, "unconvertible metric point")
			continue
		}
		samples = append(samples, s...)
	}

	if len(samples) == 0 {
		return nil
	}

	return r.send(ctx, nodeID, samples)
}

// send posts samples through the ingest client, halving the batch and re-sending
// each half when the platform refuses it as too large (413). Only the size is
// refused, not the content, so splitting eventually fits; a lone sample that is
// still refused cannot be split any further and is dropped. Without this the
// manager — which chunks by point count, never by bytes, and fans a single point
// out into up to ten wire samples — would draw the identical 413 on every flush
// and lose every metric permanently.
//
// A split that partially succeeds and then hits a transient failure returns the
// error for the whole chunk, so Manager.flush re-buffers samples the platform
// already accepted. Duplicating a sample upstream is the lesser evil against
// losing one, and the ingest contract carries no idempotency key to do better.
func (r *PlatformReporter) send(ctx context.Context, nodeID string, samples []api.MetricSample) error {
	err := r.post(ctx, nodeID, samples)
	if !api.IsIngestTooLarge(err) {
		return err
	}
	if len(samples) == 1 {
		r.recordDrop(1, "single metric sample over the platform ingest size limit")
		return nil
	}
	mid := len(samples) / 2
	if err := r.send(ctx, nodeID, samples[:mid]); err != nil {
		return err
	}
	return r.send(ctx, nodeID, samples[mid:])
}

// post is a single ingest attempt. A 501 observability_ingest_not_provisioned
// refusal and a permanent batch refusal (400 ingest_batch_malformed) are treated
// as a drop (return nil) so the batch is not re-buffered and re-sent forever;
// any other client error, 413 included, is returned unchanged for the caller to
// classify.
func (r *PlatformReporter) post(ctx context.Context, nodeID string, samples []api.MetricSample) error {
	receipt, err := r.client.ReportMetrics(ctx, nodeID, samples)
	if err != nil {
		if api.IsIngestNotProvisioned(err) {
			if !r.notProvisioned {
				r.logger.Info("platform observability ingest not provisioned; dropping metrics",
					"component", "metrics")
				r.notProvisioned = true
			}
			r.recordDrop(len(samples), "platform observability ingest not provisioned")
			return nil
		}
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && api.IsIngestPermanentlyRefused(err) {
			r.logger.Warn("platform ingest refused batch permanently; dropping",
				"component", "metrics", "status", apiErr.StatusCode, "code", apiErr.Code)
			r.recordDrop(len(samples), "platform refused the batch as malformed")
			return nil
		}
		return err
	}

	r.logger.Debug("metrics reported to platform",
		"component", "metrics",
		"accepted_at", receipt.AcceptedAt,
	)
	if receipt.Records != len(samples) {
		r.logger.Warn("platform ingest accepted a different record count than sent",
			"component", "metrics",
			"sent", len(samples),
			"accepted", receipt.Records,
		)
	}
	if r.notProvisioned {
		r.logger.Info("platform observability ingest provisioning recovered",
			"component", "metrics")
		r.notProvisioned = false
	}
	return nil
}
