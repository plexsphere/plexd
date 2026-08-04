package reconcile

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// recordingHandler keeps every emitted record so a test can pin both log cadence
// — that an unchanged verdict costs no line across repeated pulls — and the
// attributes each line carries.
type recordingHandler struct {
	mu      sync.Mutex
	records []loggedRecord
}

// loggedRecord is one emitted record, flattened to the level, the message, and
// the attributes the observer attached.
type loggedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]slog.Value
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{}
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, rec slog.Record) error {
	attrs := make(map[string]slog.Value, rec.NumAttrs())
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value
		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, loggedRecord{level: rec.Level, msg: rec.Message, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// all returns every record captured so far.
func (h *recordingHandler) all() []loggedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]loggedRecord(nil), h.records...)
}

// count returns how many records carry msg.
func (h *recordingHandler) count(msg string) int {
	n := 0
	for _, rec := range h.all() {
		if rec.msg == msg {
			n++
		}
	}
	return n
}

// last returns the most recent record carrying msg.
func (h *recordingHandler) last(t *testing.T, msg string) loggedRecord {
	t.Helper()
	records := h.all()
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].msg == msg {
			return records[i]
		}
	}
	t.Fatalf("no record with message %q; got %v", msg, records)
	return loggedRecord{}
}

// newTestObserver wires an observer onto a recording handler.
func newTestObserver() (*ReachabilityObserver, *recordingHandler) {
	logs := newRecordingHandler()
	return NewReachabilityObserver(slog.New(logs)), logs
}

// observe feeds one pull carrying the given raw reachability block.
func observe(o *ReachabilityObserver, block string) {
	o.Handle(context.Background(), &api.NodeStateSnapshot{Reachability: json.RawMessage(block)})
}

// wantString asserts that the record carries key with the given string value.
func wantString(t *testing.T, rec loggedRecord, key, want string) {
	t.Helper()
	got, ok := rec.attrs[key]
	if !ok {
		t.Fatalf("record %q carries no %q attribute: %v", rec.msg, key, rec.attrs)
	}
	if got.String() != want {
		t.Errorf("%s = %q, want %q", key, got.String(), want)
	}
}

const (
	verdictChanged = "reachability verdict changed"
	blockMalformed = "reachability block malformed"
)

func TestReachabilityObserver_FirstVerdictLogs(t *testing.T) {
	observer, logs := newTestObserver()

	observe(observer, `{"state":"never_reported","changed_at":"2026-01-01T00:00:00Z"}`)

	if got := logs.count(verdictChanged); got != 1 {
		t.Fatalf("verdict lines = %d, want 1", got)
	}
	rec := logs.last(t, verdictChanged)
	if rec.level != slog.LevelInfo {
		t.Errorf("level = %v, want %v", rec.level, slog.LevelInfo)
	}
	wantString(t, rec, "state", api.ReachabilityNeverReported)
	// The first observation has nothing to compare against, so previous is empty
	// rather than absent.
	wantString(t, rec, "previous", "")
	if _, ok := rec.attrs["changed_at"]; !ok {
		t.Errorf("record carries no changed_at attribute: %v", rec.attrs)
	}
	// The block carried no last_heartbeat_at, which is the shape of a node whose
	// first heartbeat was never admitted.
	if _, ok := rec.attrs["last_heartbeat_at"]; ok {
		t.Errorf("last_heartbeat_at present for a block that omits it: %v", rec.attrs)
	}
}

func TestReachabilityObserver_UnchangedVerdictIsSilent(t *testing.T) {
	observer, logs := newTestObserver()

	const block = `{"state":"healthy","last_heartbeat_at":"2026-01-01T00:00:00Z","changed_at":"2026-01-01T00:00:00Z"}`
	for range 3 {
		observe(observer, block)
	}

	if got := logs.count(verdictChanged); got != 1 {
		t.Fatalf("verdict lines = %d across three identical pulls, want 1", got)
	}
}

func TestReachabilityObserver_ChangeLogsBothVerdicts(t *testing.T) {
	observer, logs := newTestObserver()

	observe(observer, `{"state":"never_reported","changed_at":"2026-01-01T00:00:00Z"}`)
	observe(observer, `{"state":"healthy","last_heartbeat_at":"2026-01-02T03:04:05Z","changed_at":"2026-01-02T03:04:05Z"}`)

	if got := logs.count(verdictChanged); got != 2 {
		t.Fatalf("verdict lines = %d, want 2", got)
	}
	rec := logs.last(t, verdictChanged)
	wantString(t, rec, "state", api.ReachabilityHealthy)
	wantString(t, rec, "previous", api.ReachabilityNeverReported)
	// A heartbeat has been admitted by now, so the field is present and carried.
	got, ok := rec.attrs["last_heartbeat_at"]
	if !ok {
		t.Fatalf("record carries no last_heartbeat_at attribute: %v", rec.attrs)
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !got.Time().Equal(want) {
		t.Errorf("last_heartbeat_at = %v, want %v", got.Time(), want)
	}
}

func TestReachabilityObserver_UnknownVerdictLoggedVerbatim(t *testing.T) {
	observer, logs := newTestObserver()

	// A fifth verdict a later control plane introduces. It must reach the log
	// unchanged: the vocabulary is the control plane's, and rejecting a value
	// this build does not know is the failure this observer exists to avoid.
	observe(observer, `{"state":"quarantined","changed_at":"2026-01-01T00:00:00Z"}`)

	if got := logs.count(verdictChanged); got != 1 {
		t.Fatalf("verdict lines = %d, want 1", got)
	}
	wantString(t, logs.last(t, verdictChanged), "state", "quarantined")
}

func TestReachabilityObserver_EmptyVerdict(t *testing.T) {
	// An empty state is what a corrupt control-plane row passes through. Reached
	// from a real verdict it is a change like any other.
	observer, logs := newTestObserver()

	observe(observer, `{"state":"healthy","changed_at":"2026-01-01T00:00:00Z"}`)
	observe(observer, `{"state":"","changed_at":"2026-01-02T00:00:00Z"}`)

	if got := logs.count(verdictChanged); got != 2 {
		t.Fatalf("verdict lines = %d, want 2", got)
	}
	rec := logs.last(t, verdictChanged)
	wantString(t, rec, "state", "")
	wantString(t, rec, "previous", api.ReachabilityHealthy)

	// Observed first, it equals the initial remembered verdict and produces no
	// line. That falls out of comparing against the last verdict, and is
	// acceptable for a diagnostic.
	fresh, freshLogs := newTestObserver()
	observe(fresh, `{"state":"","changed_at":"2026-01-01T00:00:00Z"}`)
	if got := freshLogs.count(verdictChanged); got != 0 {
		t.Errorf("verdict lines = %d for a first-observed empty verdict, want 0", got)
	}
}

func TestReachabilityObserver_AbsentBlockKeepsVerdict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block json.RawMessage
	}{
		{name: "nil", block: nil},
		{name: "empty", block: json.RawMessage{}},
		{name: "null", block: json.RawMessage(`null`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observer, logs := newTestObserver()

			observe(observer, `{"state":"healthy","changed_at":"2026-01-01T00:00:00Z"}`)
			observer.Handle(context.Background(), &api.NodeStateSnapshot{Reachability: tc.block})
			// The verdict either side of the absent block is the same one, so a
			// forgotten verdict would show up as a second line here.
			observe(observer, `{"state":"healthy","changed_at":"2026-01-01T00:00:00Z"}`)

			if got := logs.count(verdictChanged); got != 1 {
				t.Errorf("verdict lines = %d, want 1", got)
			}
			if got := logs.count(blockMalformed); got != 0 {
				t.Errorf("malformed warnings = %d, want 0", got)
			}
		})
	}
}

func TestReachabilityObserver_MalformedBlockWarnsOnce(t *testing.T) {
	observer, logs := newTestObserver()

	// state is a string on the wire; a number fails the decode with a
	// *json.UnmarshalTypeError.
	observe(observer, `{"state":5}`)
	if got := logs.count(blockMalformed); got != 1 {
		t.Fatalf("malformed warnings = %d, want 1", got)
	}
	rec := logs.last(t, blockMalformed)
	if rec.level != slog.LevelWarn {
		t.Errorf("level = %v, want %v", rec.level, slog.LevelWarn)
	}
	if _, ok := rec.attrs["error"]; !ok {
		t.Errorf("record carries no error attribute: %v", rec.attrs)
	}

	// A block the control plane serves broken stays broken, so the warning must
	// not repeat once per reconcile interval.
	observe(observer, `{"state":5}`)
	observe(observer, `{"state":5}`)
	if got := logs.count(blockMalformed); got != 1 {
		t.Fatalf("malformed warnings = %d across three failing pulls, want 1", got)
	}
	if got := logs.count(verdictChanged); got != 0 {
		t.Fatalf("verdict lines = %d, want 0", got)
	}

	// A successful decode reports its verdict and re-arms the warning.
	observe(observer, `{"state":"healthy","changed_at":"2026-01-01T00:00:00Z"}`)
	if got := logs.count(verdictChanged); got != 1 {
		t.Fatalf("verdict lines = %d after recovery, want 1", got)
	}
	observe(observer, `{"state":5}`)
	if got := logs.count(blockMalformed); got != 2 {
		t.Errorf("malformed warnings = %d after re-arming, want 2", got)
	}
}
