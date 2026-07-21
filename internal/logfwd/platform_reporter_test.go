package logfwd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// fakeIngestClient records ReportLogs calls and returns scripted results. The
// i-th call returns script[i]; once the script is exhausted the last entry
// repeats.
type fakeIngestClient struct {
	mu     sync.Mutex
	calls  [][]api.LogLine
	script []ingestResult
}

func (f *fakeIngestClient) ReportLogs(_ context.Context, _ string, lines []api.LogLine) (*api.IngestReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := len(f.calls)
	f.calls = append(f.calls, lines)
	res := f.script[min(idx, len(f.script)-1)]
	return res.receipt, res.err
}

func (f *fakeIngestClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// countLog counts captured records with the given level and exact message.
func countLog(h *capturingHandler, level slog.Level, msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if r.Level == level && r.Message == msg {
			n++
		}
	}
	return n
}

func hasLog(h *capturingHandler, level slog.Level, msg string) bool {
	return countLog(h, level, msg) > 0
}

func logEntry(source, message, severity string, ts time.Time) api.LogEntry {
	return api.LogEntry{
		Timestamp: ts,
		Source:    source,
		Unit:      "test.service",
		Message:   message,
		Severity:  severity,
		Hostname:  "test-host",
	}
}

func TestPlatformReporter_MappingDropsSourceCarriesFields(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	r := NewPlatformReporter(client, discardLogger())

	ts := time.Now()
	batch := api.LogBatch{logEntry("journald", "hello", "warning", ts)}

	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("client called %d times, want 1", client.callCount())
	}
	got := client.calls[0]
	if len(got) != 1 {
		t.Fatalf("sent %d lines, want 1", len(got))
	}
	// LogLine has no Source field, so an equal struct proves source was dropped
	// and the other five fields were carried unchanged.
	want := api.LogLine{
		Severity:  "warning",
		Unit:      "test.service",
		Hostname:  "test-host",
		Message:   "hello",
		Timestamp: ts,
	}
	if got[0] != want {
		t.Errorf("line = %+v, want %+v", got[0], want)
	}
}

func TestPlatformReporter_EmptyMessageSkippedRestSurvives(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	now := time.Now()
	batch := api.LogBatch{
		logEntry("journald", "", "info", now),
		logEntry("journald", "kept", "info", now),
	}

	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("client called %d times, want 1", client.callCount())
	}
	if got := len(client.calls[0]); got != 1 {
		t.Errorf("sent %d lines, want 1 (empty-message entry dropped)", got)
	}
	if client.calls[0][0].Message != "kept" {
		t.Errorf("surviving line message = %q, want %q", client.calls[0][0].Message, "kept")
	}
	if !hasLog(ch, slog.LevelDebug, "logfwd: skipping log entry with empty message") {
		t.Error("expected a Debug log about skipping the empty-message entry")
	}
}

func TestPlatformReporter_OutOfSetSeverityMapsToInfo(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 3}},
	}}
	r := NewPlatformReporter(client, discardLogger())

	now := time.Now()
	batch := api.LogBatch{
		logEntry("journald", "a", "6", now),       // numeric priority leaked through
		logEntry("journald", "b", "verbose", now), // never a wire severity
		logEntry("journald", "c", "err", now),     // in-set: must pass through
	}

	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}
	got := client.calls[0]
	wantSeverity := []string{"info", "info", "err"}
	for i, want := range wantSeverity {
		if got[i].Severity != want {
			t.Errorf("line %d severity = %q, want %q", i, got[i].Severity, want)
		}
	}
}

func TestPlatformReporter_AllSkippedNoCall(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{{receipt: &api.IngestReceipt{}}}}
	r := NewPlatformReporter(client, discardLogger())

	now := time.Now()
	batch := api.LogBatch{
		logEntry("journald", "", "info", now),
		logEntry("journald", "", "info", now),
	}

	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v, want nil", err)
	}
	if client.callCount() != 0 {
		t.Errorf("client called %d times, want 0 (no lines survived)", client.callCount())
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
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := api.LogBatch{logEntry("journald", "x", "info", time.Now())}

	// Two consecutive 501s both drop the batch (return nil).
	for i := 0; i < 2; i++ {
		if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("call %d: error = %v, want nil (dropped)", i, err)
		}
	}
	// Third call succeeds and clears the flag.
	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("recovery call: error = %v, want nil", err)
	}

	if n := countLog(ch, slog.LevelInfo, "platform observability ingest not provisioned; dropping logs"); n != 1 {
		t.Errorf("transition Info logs = %d, want exactly 1", n)
	}
	if n := countLog(ch, slog.LevelInfo, "platform observability ingest provisioning recovered"); n != 1 {
		t.Errorf("recovery Info logs = %d, want exactly 1", n)
	}
	if client.callCount() != 3 {
		t.Errorf("client called %d times, want 3", client.callCount())
	}
}

func TestPlatformReporter_UpstreamErrorsPropagate(t *testing.T) {
	bufErr := &api.APIError{StatusCode: 503, Code: "ingest_buffer_unavailable", Message: "unavailable"}
	deadlineErr := fmt.Errorf("post logs: %w", context.DeadlineExceeded)

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

			err := r.ReportLogs(context.Background(), "node-1", api.LogBatch{logEntry("journald", "x", "info", time.Now())})
			if err != tc.err {
				t.Fatalf("error = %v, want it returned unchanged (%v)", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("errors.Is(%v, %v) = false, want true", err, tc.is)
			}
		})
	}
}

func TestPlatformReporter_ZeroTimestampSkippedRestSurvives(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := api.LogBatch{
		logEntry("journald", "poison", "info", time.Time{}), // zero ts -> skip
		logEntry("journald", "kept", "info", time.Now()),    // kept
	}

	// A zero timestamp would 400 the whole batch (ingest_batch_malformed), so the
	// offending record must be dropped rather than poisoning every good record.
	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}
	if got := len(client.calls[0]); got != 1 {
		t.Fatalf("sent %d lines, want 1 (zero-timestamp entry dropped)", got)
	}
	if client.calls[0][0].Message != "kept" {
		t.Errorf("surviving line message = %q, want %q", client.calls[0][0].Message, "kept")
	}
	if !hasLog(ch, slog.LevelDebug, "logfwd: skipping log entry with zero timestamp") {
		t.Error("expected a Debug log about skipping the zero-timestamp entry")
	}
}

func TestPlatformReporter_PermanentRefusalDrops(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 400, Code: "ingest_batch_malformed", Message: "bad"}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	// A verdict on the batch bytes must drop the batch (return nil) so the
	// forwarder does not re-buffer and re-POST the identical bytes forever.
	if err := r.ReportLogs(context.Background(), "node-1", api.LogBatch{logEntry("journald", "x", "info", time.Now())}); err != nil {
		t.Fatalf("error = %v, want nil (dropped)", err)
	}
	if !hasLog(ch, slog.LevelWarn, "platform ingest refused batch permanently; dropping") {
		t.Error("expected a Warn log about the permanent refusal")
	}
	if r.dropped != 1 {
		t.Errorf("dropped = %d, want the discarded line counted", r.dropped)
	}
}

// TestPlatformReporter_HeaderLevelRefusalsPropagate pins that a refusal faulting
// the transport rather than the batch bytes is retryable. Neither condition is
// in the batch: X-Plexsphere-Sent-At is re-stamped from the wall clock on every
// attempt, and Content-Encoding: gzip is a property of the deployment. Dropping
// them would discard every line buffered until an operator fixes the gateway or
// the node's clock converges.
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

			batch := api.LogBatch{logEntry("journald", "x", "info", time.Now())}
			if err := r.ReportLogs(context.Background(), "node-1", batch); err != tc.err {
				t.Fatalf("error = %v, want it returned unchanged (%v)", err, tc.err)
			}
		})
	}
}

// TestPlatformReporter_TooLargeBatchIsSplit verifies that a 413 halves the batch
// instead of discarding it. The forwarder chunks by line count, never by bytes,
// so an oversized chunk shape would otherwise repeat identically on every flush
// and lose every log line permanently.
func TestPlatformReporter_TooLargeBatchIsSplit(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 413, Message: "too large"}},
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 2}},
	}}
	r := NewPlatformReporter(client, discardLogger())

	batch := api.LogBatch{}
	for i := 0; i < 4; i++ {
		batch = append(batch, logEntry("journald", fmt.Sprintf("line-%d", i), "info", time.Now()))
	}
	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v, want nil", err)
	}
	var sizes []int
	for _, call := range client.calls {
		sizes = append(sizes, len(call))
	}
	if len(sizes) != 3 || sizes[0] != 4 || sizes[1] != 2 || sizes[2] != 2 {
		t.Fatalf("call sizes = %v, want [4 2 2]", sizes)
	}
	if r.dropped != 0 {
		t.Errorf("dropped = %d, want 0 (every line was accepted after the split)", r.dropped)
	}
}

// TestPlatformReporter_OversizedSingleLineDropped verifies that the split
// terminates: a line the platform refuses on its own cannot be made to fit, so
// it is dropped and counted rather than split forever.
func TestPlatformReporter_OversizedSingleLineDropped(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 413, Message: "too large"}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := api.LogBatch{
		logEntry("journald", "a", "info", time.Now()),
		logEntry("journald", "b", "info", time.Now()),
	}
	if err := r.ReportLogs(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportLogs() error = %v, want nil (dropped)", err)
	}
	if r.dropped != 2 {
		t.Errorf("dropped = %d, want both lines dropped one by one", r.dropped)
	}
	if !hasLog(ch, slog.LevelWarn, "dropping log lines") {
		t.Error("expected a Warn summarizing the dropped lines")
	}
}

func TestPlatformReporter_RecordCountMismatchWarns(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 5}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	if err := r.ReportLogs(context.Background(), "node-1", api.LogBatch{logEntry("journald", "x", "info", time.Now())}); err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}
	if !hasLog(ch, slog.LevelWarn, "platform ingest accepted a different record count than sent") {
		t.Error("expected a Warn log about the record-count mismatch")
	}
}

func TestPlatformReporter_SuccessLogsAcceptedAtNoWarn(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	if err := r.ReportLogs(context.Background(), "node-1", api.LogBatch{logEntry("journald", "x", "info", time.Now())}); err != nil {
		t.Fatalf("ReportLogs() error = %v", err)
	}
	if !hasLog(ch, slog.LevelDebug, "logs reported to platform") {
		t.Error("expected a Debug log recording the accepted_at receipt")
	}
	if hasLog(ch, slog.LevelWarn, "platform ingest accepted a different record count than sent") {
		t.Error("did not expect a record-count Warn when records match")
	}
}
