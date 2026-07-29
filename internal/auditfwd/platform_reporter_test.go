package auditfwd

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

// fakeIngestClient records ReportAudit calls and returns scripted results. The
// i-th call returns script[i]; once the script is exhausted the last entry
// repeats.
type fakeIngestClient struct {
	mu     sync.Mutex
	calls  [][]api.AuditEvent
	script []ingestResult
}

func (f *fakeIngestClient) ReportAudit(_ context.Context, _ string, events []api.AuditEvent) (*api.IngestReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := len(f.calls)
	f.calls = append(f.calls, events)
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

func auditEntry(source, action, result string, ts time.Time) api.AuditEntry {
	return api.AuditEntry{
		Timestamp: ts,
		Source:    source,
		EventType: "test",
		Action:    action,
		Result:    result,
		Hostname:  "test-host",
	}
}

func TestPlatformReporter_SourceMapping(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 3}},
	}}
	r := NewPlatformReporter(client, discardLogger())

	ts := time.Now()
	batch := api.AuditBatch{
		auditEntry("auditd", "execve", "success", ts),
		auditEntry("k8s-audit", "get", "allow", ts),
		auditEntry("process", "start", "success", ts),
	}

	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportAudit() error = %v", err)
	}
	got := client.calls[0]
	// The ingest contract's source enum is closed at auditd and k8s. plexd's own
	// process entry has no value in that set, and a record naming one outside it
	// does not fail on its own line — it refuses the whole batch with 400
	// ingest_batch_malformed, taking the real audit records down with it. So it
	// is skipped here rather than sent under an invented source.
	wantSource := []string{"auditd", "k8s"}
	if len(got) != len(wantSource) {
		t.Fatalf("sent %d events, want %d", len(got), len(wantSource))
	}
	for i, want := range wantSource {
		if got[i].Source != want {
			t.Errorf("event %d source = %q, want %q", i, got[i].Source, want)
		}
	}
	// Action, Outcome, and Timestamp are carried through the conversion.
	if got[0].Action != "execve" || got[0].Outcome != "success" || !got[0].Timestamp.Equal(ts) {
		t.Errorf("event 0 = %+v, want action=execve outcome=success ts=%v", got[0], ts)
	}
}

func TestPlatformReporter_UnknownSourceAndEmptyFieldsSkipped(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	now := time.Now()
	batch := api.AuditBatch{
		auditEntry("mystery", "x", "y", now),           // unknown source -> Warn skip
		auditEntry("auditd", "", "success", now),       // empty action -> Debug skip
		auditEntry("auditd", "execve", "", now),        // empty result -> Debug skip
		auditEntry("auditd", "execve", "success", now), // kept
	}

	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportAudit() error = %v", err)
	}
	if got := len(client.calls[0]); got != 1 {
		t.Fatalf("sent %d events, want 1 (three entries skipped)", got)
	}
	if client.calls[0][0].Action != "execve" || client.calls[0][0].Outcome != "success" {
		t.Errorf("surviving event = %+v, want action=execve outcome=success", client.calls[0][0])
	}
	if !hasLog(ch, slog.LevelWarn, "auditfwd: skipping audit entry with unknown source") {
		t.Error("expected a Warn log about the unknown source")
	}
	if n := countLog(ch, slog.LevelDebug, "auditfwd: skipping audit entry with empty action or result"); n != 2 {
		t.Errorf("Debug skip logs = %d, want 2 (empty action and empty result)", n)
	}
}

func TestPlatformReporter_AllSkippedNoCall(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{{receipt: &api.IngestReceipt{}}}}
	r := NewPlatformReporter(client, discardLogger())

	now := time.Now()
	batch := api.AuditBatch{
		auditEntry("mystery", "x", "y", now), // unknown source
		auditEntry("auditd", "", "", now),    // empty action and result
	}

	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportAudit() error = %v, want nil", err)
	}
	if client.callCount() != 0 {
		t.Errorf("client called %d times, want 0 (no events survived)", client.callCount())
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

	batch := api.AuditBatch{auditEntry("auditd", "execve", "success", time.Now())}

	// Two consecutive 501s both drop the batch (return nil).
	for i := 0; i < 2; i++ {
		if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
			t.Fatalf("call %d: error = %v, want nil (dropped)", i, err)
		}
	}
	// Third call succeeds and clears the flag.
	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("recovery call: error = %v, want nil", err)
	}

	if n := countLog(ch, slog.LevelInfo, "platform observability ingest not provisioned; dropping audit events"); n != 1 {
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
	deadlineErr := fmt.Errorf("post audit: %w", context.DeadlineExceeded)

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

			err := r.ReportAudit(context.Background(), "node-1", api.AuditBatch{auditEntry("auditd", "execve", "success", time.Now())})
			if err != tc.err {
				t.Fatalf("error = %v, want it returned unchanged (%v)", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("errors.Is(%v, %v) = false, want true", err, tc.is)
			}
		})
	}
}

func TestPlatformReporter_ZeroTimestampSkipped(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := api.AuditBatch{
		auditEntry("auditd", "execve", "success", time.Time{}), // zero ts -> skip
		auditEntry("auditd", "execve", "success", time.Now()),  // kept
	}

	// A zero timestamp would 400 the whole batch (ingest_batch_malformed), so the
	// offending record must be dropped rather than poisoning every good record.
	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportAudit() error = %v", err)
	}
	if got := len(client.calls[0]); got != 1 {
		t.Fatalf("sent %d events, want 1 (zero-timestamp entry dropped)", got)
	}
	if !hasLog(ch, slog.LevelDebug, "auditfwd: skipping audit entry with zero timestamp") {
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
	if err := r.ReportAudit(context.Background(), "node-1", api.AuditBatch{auditEntry("auditd", "execve", "success", time.Now())}); err != nil {
		t.Fatalf("error = %v, want nil (dropped)", err)
	}
	if !hasLog(ch, slog.LevelWarn, "platform ingest refused batch permanently; dropping") {
		t.Error("expected a Warn log about the permanent refusal")
	}
	if r.dropped != 1 {
		t.Errorf("dropped = %d, want the discarded audit record counted", r.dropped)
	}
}

// TestPlatformReporter_HeaderLevelRefusalsPropagate pins that a refusal faulting
// the transport rather than the batch bytes is retryable. Neither condition is
// in the batch: X-Plexsphere-Sent-At is re-stamped from the wall clock on every
// attempt, and Content-Encoding: gzip is a property of the deployment. Dropping
// them would discard the audit trail buffered until an operator fixes the
// gateway or the node's clock converges.
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

			batch := api.AuditBatch{auditEntry("auditd", "execve", "success", time.Now())}
			if err := r.ReportAudit(context.Background(), "node-1", batch); err != tc.err {
				t.Fatalf("error = %v, want it returned unchanged (%v)", err, tc.err)
			}
		})
	}
}

// TestPlatformReporter_TooLargeBatchIsSplit verifies that a 413 halves the batch
// instead of discarding it. The forwarder chunks by record count, never by
// bytes, so an oversized chunk shape would otherwise repeat identically on every
// flush and lose the audit trail permanently.
func TestPlatformReporter_TooLargeBatchIsSplit(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 413, Message: "too large"}},
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 2}},
	}}
	r := NewPlatformReporter(client, discardLogger())

	batch := api.AuditBatch{}
	for i := 0; i < 4; i++ {
		batch = append(batch, auditEntry("auditd", "execve", "success", time.Now()))
	}
	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportAudit() error = %v, want nil", err)
	}
	var sizes []int
	for _, call := range client.calls {
		sizes = append(sizes, len(call))
	}
	if len(sizes) != 3 || sizes[0] != 4 || sizes[1] != 2 || sizes[2] != 2 {
		t.Fatalf("call sizes = %v, want [4 2 2]", sizes)
	}
	if r.dropped != 0 {
		t.Errorf("dropped = %d, want 0 (every record was accepted after the split)", r.dropped)
	}
}

// TestPlatformReporter_OversizedSingleEventDropped verifies that the split
// terminates: an event the platform refuses on its own cannot be made to fit, so
// it is dropped and counted rather than split forever.
func TestPlatformReporter_OversizedSingleEventDropped(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{err: &api.APIError{StatusCode: 413, Message: "too large"}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := api.AuditBatch{
		auditEntry("auditd", "execve", "success", time.Now()),
		auditEntry("auditd", "connect", "failure", time.Now()),
	}
	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportAudit() error = %v, want nil (dropped)", err)
	}
	if r.dropped != 2 {
		t.Errorf("dropped = %d, want both records dropped one by one", r.dropped)
	}
	if !hasLog(ch, slog.LevelWarn, "dropping audit records") {
		t.Error("expected a Warn summarizing the dropped records")
	}
}

// TestPlatformReporter_SkippedEntriesAreCounted verifies that a record dropped
// before it ever reaches the wire — a source outside the ingest contract — is
// counted too. The forwarder takes the success path either way, so the count and
// its periodic summary are the only signal that the audit trail is incomplete.
func TestPlatformReporter_SkippedEntriesAreCounted(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 1}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	batch := api.AuditBatch{
		auditEntry("selinux", "avc", "denied", time.Now()), // source outside the contract
		auditEntry("auditd", "execve", "success", time.Now()),
	}
	if err := r.ReportAudit(context.Background(), "node-1", batch); err != nil {
		t.Fatalf("ReportAudit() error = %v", err)
	}
	if r.dropped != 1 {
		t.Errorf("dropped = %d, want the out-of-contract record counted", r.dropped)
	}
	if !hasLog(ch, slog.LevelWarn, "dropping audit records") {
		t.Error("expected a Warn summarizing the dropped record")
	}
}

func TestPlatformReporter_RecordCountMismatchWarns(t *testing.T) {
	client := &fakeIngestClient{script: []ingestResult{
		{receipt: &api.IngestReceipt{AcceptedAt: time.Now(), Records: 5}},
	}}
	ch := &capturingHandler{}
	r := NewPlatformReporter(client, slog.New(ch))

	if err := r.ReportAudit(context.Background(), "node-1", api.AuditBatch{auditEntry("auditd", "execve", "success", time.Now())}); err != nil {
		t.Fatalf("ReportAudit() error = %v", err)
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

	if err := r.ReportAudit(context.Background(), "node-1", api.AuditBatch{auditEntry("auditd", "execve", "success", time.Now())}); err != nil {
		t.Fatalf("ReportAudit() error = %v", err)
	}
	if !hasLog(ch, slog.LevelDebug, "audit events reported to platform") {
		t.Error("expected a Debug log recording the accepted_at receipt")
	}
	if hasLog(ch, slog.LevelWarn, "platform ingest accepted a different record count than sent") {
		t.Error("did not expect a record-count Warn when records match")
	}
}
