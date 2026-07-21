package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ingestResult is a single scripted response from the fake ingest client.
type ingestResult struct {
	receipt *api.IngestReceipt
	err     error
}

// fakeIngestClient records ReportMetrics calls and returns scripted results.
// The i-th call returns script[i]; once the script is exhausted the last entry
// repeats.
type fakeIngestClient struct {
	mu     sync.Mutex
	calls  [][]api.MetricSample
	script []ingestResult
}

func (f *fakeIngestClient) ReportMetrics(_ context.Context, _ string, samples []api.MetricSample) (*api.IngestReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := len(f.calls)
	f.calls = append(f.calls, samples)
	res := f.script[min(idx, len(f.script)-1)]
	return res.receipt, res.err
}

func (f *fakeIngestClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func countLog(ch *capturingHandler, level slog.Level, substr string) int {
	n := 0
	for _, r := range ch.getRecords() {
		if r.Level == level && strings.Contains(r.Message, substr) {
			n++
		}
	}
	return n
}

func hasLog(ch *capturingHandler, level slog.Level, substr string) bool {
	return countLog(ch, level, substr) > 0
}

// systemBatch returns a one-point batch that flattens to exactly 10 samples.
func systemBatch(t *testing.T) api.MetricBatch {
	t.Helper()
	return api.MetricBatch{
		{
			Timestamp: time.Now(),
			Group:     GroupSystem,
			Data: mustData(t, SystemStats{
				CPUUsagePercent:  50,
				MemoryUsedBytes:  1,
				MemoryTotalBytes: 2,
				DiskUsedBytes:    3,
				DiskTotalBytes:   4,
				NetworkRxBytes:   5,
				NetworkTxBytes:   6,
				LoadAvg1:         0.1,
				LoadAvg5:         0.2,
				LoadAvg15:        0.3,
			}),
		},
	}
}

func TestPlatformReporter_SkipsUnconvertiblePointsNoCall(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{{receipt: &api.IngestReceipt{}}}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := api.MetricBatch{
		{Timestamp: time.Now(), Group: "bogus", Data: json.RawMessage("{}")},
		{Timestamp: time.Now(), Group: GroupSystem, Data: nil}, // empty data
	}

	if err := r.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportMetrics() error = %v, want nil", err)
	}
	if client.callCount() != 0 {
		t.Errorf("client called %d times, want 0 (no samples survived)", client.callCount())
	}
	if !hasLog(ch, slog.LevelWarn, "unconvertible") {
		t.Error("expected a Warn log about skipping an unconvertible point")
	}
}

func TestPlatformReporter_SendsOnlyConvertibleSamples(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 10}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := append(systemBatch(t),
		api.MetricPoint{Timestamp: time.Now(), Group: "bogus", Data: json.RawMessage("{}")},
	)

	if err := r.ReportMetrics(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportMetrics() error = %v, want nil", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("client called %d times, want 1", client.callCount())
	}
	if got := len(client.calls[0]); got != 10 {
		t.Errorf("sent %d samples, want 10 (bogus point dropped)", got)
	}
	if !hasLog(ch, slog.LevelWarn, "unconvertible") {
		t.Error("expected a Warn log about skipping the unconvertible point")
	}
}

func TestPlatformReporter_NotProvisionedDropsAndLogsOnce(t *testing.T) {
	notProv := &api.APIError{
		StatusCode: 501,
		Code:       "observability_ingest_not_provisioned",
		Message:    "ingest not provisioned",
	}
	client := &fakeIngestClient{script: []ingestResult{
		{err: notProv},
		{err: notProv},
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 10}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	// Two consecutive 501s both drop the batch (return nil).
	for i := 0; i < 2; i++ {
		if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != nil {
			t.Fatalf("call %d: error = %v, want nil (dropped)", i, err)
		}
	}
	// Third call succeeds and clears the flag.
	if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != nil {
		t.Fatalf("recovery call: error = %v, want nil", err)
	}

	if n := countLog(ch, slog.LevelInfo, "not provisioned"); n != 1 {
		t.Errorf("transition Info logs = %d, want exactly 1", n)
	}
	if n := countLog(ch, slog.LevelInfo, "recovered"); n != 1 {
		t.Errorf("recovery Info logs = %d, want exactly 1", n)
	}
	if client.callCount() != 3 {
		t.Errorf("client called %d times, want 3", client.callCount())
	}
}

func TestPlatformReporter_UpstreamErrorsPropagate(t *testing.T) {
	bufErr := &api.APIError{StatusCode: 503, Code: "ingest_buffer_unavailable", Message: "unavailable"}
	deadlineErr := fmt.Errorf("post metrics: %w", context.DeadlineExceeded)

	cases := []struct {
		name string
		err  error
		is   error // additional errors.Is target, nil to skip
	}{
		{"503 buffer unavailable", bufErr, nil},
		{"wrapped deadline exceeded", deadlineErr, context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeIngestClient{script: []ingestResult{{err: tc.err}}}
			r := NewPlatformReporter(client, discardLogger())

			err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t))
			if err != tc.err {
				t.Fatalf("error = %v, want it returned unchanged (%v)", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("errors.Is(%v, %v) = false, want true", err, tc.is)
			}
		})
	}
}

func TestPlatformReporter_PermanentRefusalDrops(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 400, Code: "ingest_batch_malformed", Message: "bad"}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	// A verdict on the batch bytes must drop the batch (return nil) so the
	// manager does not re-buffer and re-POST the identical bytes forever.
	if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != nil {
		t.Fatalf("error = %v, want nil (dropped)", err)
	}
	if !hasLog(ch, slog.LevelWarn, "refused batch permanently") {
		t.Error("expected a Warn log about the permanent refusal")
	}
	if r.dropped != 10 {
		t.Errorf("dropped = %d, want the 10 discarded samples counted", r.dropped)
	}
}

// TestPlatformReporter_HeaderLevelRefusalsPropagate pins that a refusal faulting
// the transport rather than the batch bytes is retryable. Neither condition is
// in the batch: X-Plexsphere-Sent-At is re-stamped from the wall clock on every
// attempt, and Content-Encoding: gzip is a property of the deployment. Dropping
// them would discard every sample buffered until an operator fixes the gateway
// or the node's clock converges.
func TestPlatformReporter_HeaderLevelRefusalsPropagate(t *testing.T) {
	cases := []struct {
		name string
		err  *api.APIError
	}{
		{"415 unsupported encoding", &api.APIError{StatusCode: 415, Code: "ingest_encoding_unsupported", Message: "no"}},
		{"400 invalid sent-at", &api.APIError{StatusCode: 400, Code: "ingest_sent_at_invalid", Message: "skewed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeIngestClient{script: []ingestResult{{err: tc.err}}}
			r := NewPlatformReporter(client, discardLogger())

			if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != tc.err {
				t.Fatalf("error = %v, want it returned unchanged (%v)", err, tc.err)
			}
		})
	}
}

// TestPlatformReporter_TooLargeBatchIsSplit verifies that a 413 halves the batch
// instead of discarding it. The manager chunks by point count, never by bytes,
// so an oversized chunk shape would otherwise repeat identically on every flush
// and lose every metric permanently.
func TestPlatformReporter_TooLargeBatchIsSplit(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 413, Message: "too large"}},
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 5}},
	}}
	r := NewPlatformReporter(client, discardLogger())

	// The one system point flattens to 10 samples: refused whole, accepted as
	// two halves of 5.
	if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != nil {
		t.Fatalf("ReportMetrics() error = %v, want nil", err)
	}
	var sizes []int
	for _, call := range client.calls {
		sizes = append(sizes, len(call))
	}
	if len(sizes) != 3 || sizes[0] != 10 || sizes[1] != 5 || sizes[2] != 5 {
		t.Fatalf("call sizes = %v, want [10 5 5]", sizes)
	}
	if r.dropped != 0 {
		t.Errorf("dropped = %d, want 0 (every sample was accepted after the split)", r.dropped)
	}
}

// TestPlatformReporter_OversizedSingleSampleDropped verifies that the split
// terminates: a sample the platform refuses on its own cannot be made to fit, so
// it is dropped and counted rather than split forever.
func TestPlatformReporter_OversizedSingleSampleDropped(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 413, Message: "too large"}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != nil {
		t.Fatalf("ReportMetrics() error = %v, want nil (dropped)", err)
	}
	if r.dropped != 10 {
		t.Errorf("dropped = %d, want all 10 samples dropped one by one", r.dropped)
	}
	if !hasLog(ch, slog.LevelWarn, "dropping metric samples") {
		t.Error("expected a Warn summarizing the dropped samples")
	}
}

func TestPlatformReporter_RecordCountMismatchWarns(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 7}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != nil {
		t.Fatalf("ReportMetrics() error = %v", err)
	}
	if !hasLog(ch, slog.LevelWarn, "different record count") {
		t.Error("expected a Warn log about the record-count mismatch")
	}
}

func TestPlatformReporter_SuccessLogsAcceptedAtNoWarn(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 10}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	if err := r.ReportMetrics(context.Background(), "node-1", systemBatch(t)); err != nil {
		t.Fatalf("ReportMetrics() error = %v", err)
	}
	if !hasLog(ch, slog.LevelDebug, "reported to platform") {
		t.Error("expected a Debug log recording the accepted_at receipt")
	}
	if hasLog(ch, slog.LevelWarn, "different record count") {
		t.Error("did not expect a record-count Warn when records match")
	}
}
