//go:build windows

package logfwd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
)

// collectEvents reads until the reader has returned want records or five
// seconds have passed. The Event Log service accepts a record before it is
// queryable, so a single read right after the write can come back empty.
func collectEvents(t *testing.T, reader *WevtapiReader, want int) []EventRecord {
	t.Helper()

	var got []EventRecord
	deadline := time.Now().Add(5 * time.Second)
	for {
		records, err := reader.ReadEvents(context.Background())
		if err != nil {
			t.Fatalf("ReadEvents() error = %v", err)
		}
		got = append(got, records...)
		if len(got) >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// assertRecent fails when the timestamp is more than a minute away from now in
// either direction, which is what a record written during the test must be.
func assertRecent(t *testing.T, timestamp time.Time) {
	t.Helper()

	if delta := time.Since(timestamp); delta < -time.Minute || delta > time.Minute {
		t.Errorf("Timestamp = %v, off by %v from now", timestamp, delta)
	}
}

func TestWevtapiReader_ReadsOwnEvents(t *testing.T) {
	// An unregistered source writes to the Application channel without a
	// registry entry of its own. Event Viewer cannot render a description for
	// it, but the XML carries the insertion string the reader needs.
	source := fmt.Sprintf("plexd-logfwd-test-%d", os.Getpid())
	elog, err := eventlog.Open(source)
	if err != nil {
		t.Fatalf("eventlog.Open(%q) error = %v", source, err)
	}
	defer elog.Close()

	// The marker keeps the messages of one run apart from those a run with the
	// same process id may have left in the channel.
	marker := fmt.Sprintf("%016x", rand.Uint64())
	messages := []string{"info " + marker, "warning " + marker, "error " + marker}
	if err := elog.Info(1, messages[0]); err != nil {
		t.Fatalf("Info() error = %v", err)
	}
	if err := elog.Warning(1, messages[1]); err != nil {
		t.Fatalf("Warning() error = %v", err)
	}
	if err := elog.Error(1, messages[2]); err != nil {
		t.Fatalf("Error() error = %v", err)
	}

	reader := NewWevtapiReader(source, discardLogger())
	got := collectEvents(t, reader, len(messages))
	if len(got) != len(messages) {
		t.Fatalf("len(records) = %d, want %d: %+v", len(got), len(messages), got)
	}

	wantLevels := []int{4, 3, 2}
	for i, record := range got {
		if record.Level != wantLevels[i] {
			t.Errorf("records[%d].Level = %d, want %d", i, record.Level, wantLevels[i])
		}
		if record.Provider != source {
			t.Errorf("records[%d].Provider = %q, want %q", i, record.Provider, source)
		}
		if record.Message != messages[i] {
			t.Errorf("records[%d].Message = %q, want %q", i, record.Message, messages[i])
		}
		assertRecent(t, record.Timestamp)
		if i > 0 && record.RecordID <= got[i-1].RecordID {
			t.Errorf("records[%d].RecordID = %d, want above %d", i, record.RecordID, got[i-1].RecordID)
		}
	}

	last := got[len(got)-1]
	if reader.cursor != last.RecordID {
		t.Errorf("cursor = %d, want %d", reader.cursor, last.RecordID)
	}

	// The cursor is past every event of the source, so the next read has
	// nothing left to return.
	records, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents() error = %v", err)
	}
	if records != nil {
		t.Fatalf("records = %+v, want none", records)
	}

	const followUp = "again "
	if err := elog.Info(1, followUp+marker); err != nil {
		t.Fatalf("Info() error = %v", err)
	}

	got = collectEvents(t, reader, 1)
	if len(got) != 1 {
		t.Fatalf("len(records) = %d, want 1: %+v", len(got), got)
	}
	if got[0].Level != 4 {
		t.Errorf("records[0].Level = %d, want 4", got[0].Level)
	}
	if got[0].Message != followUp+marker {
		t.Errorf("records[0].Message = %q, want %q", got[0].Message, followUp+marker)
	}
	if got[0].RecordID <= last.RecordID {
		t.Errorf("records[0].RecordID = %d, want above %d", got[0].RecordID, last.RecordID)
	}
	if reader.cursor != got[0].RecordID {
		t.Errorf("cursor = %d, want %d", reader.cursor, got[0].RecordID)
	}
}

func TestWevtapiReader_UnknownProviderIsEmpty(t *testing.T) {
	reader := NewWevtapiReader(fmt.Sprintf("plexd-logfwd-none-%d", os.Getpid()), discardLogger())

	records, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents() error = %v", err)
	}
	if records != nil {
		t.Errorf("records = %+v, want none", records)
	}
	// A read without a record keeps the cursor at zero, so the next read asks
	// for the time window again.
	if reader.cursor != 0 {
		t.Errorf("cursor = %d, want 0", reader.cursor)
	}
}

func TestWevtapiReader_MissingChannel(t *testing.T) {
	reader := &WevtapiReader{
		channel:  "plexd-logfwd-no-such-channel",
		provider: "plexd",
		logger:   discardLogger(),
	}

	records, err := reader.ReadEvents(context.Background())
	if records != nil {
		t.Errorf("records = %+v, want none", records)
	}
	if err == nil {
		t.Fatal("ReadEvents() error = nil, want the channel to be missing")
	}
	if !errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND) {
		t.Errorf("ReadEvents() error = %v, want ERROR_EVT_CHANNEL_NOT_FOUND", err)
	}
	if !strings.HasPrefix(err.Error(), "logfwd: eventlog: EvtQuery:") {
		t.Errorf("ReadEvents() error = %q, want the EvtQuery prefix", err)
	}
}

func TestWevtapiReader_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	records, err := NewWevtapiReader("plexd", discardLogger()).ReadEvents(ctx)
	if records != nil {
		t.Errorf("records = %+v, want none", records)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ReadEvents() error = %v, want context.Canceled", err)
	}
}

// TestRenderEvents_ReportsDroppedEvents covers the batch the Event Log service
// cannot render, which is what a service restart or memory pressure mid-read
// produces. The events are dropped for good, since the cursor moves past them
// with the batch around them, so the count of them is the only trace left and
// it has to reach the log rather than be swallowed.
func TestRenderEvents_ReportsDroppedEvents(t *testing.T) {
	var buf bytes.Buffer

	// A zero handle is not an event handle, so EvtRender rejects it the way it
	// rejects every handle of a batch the service could not serve.
	records := renderEvents([]uintptr{0, 0}, slog.New(slog.NewTextHandler(&buf, nil)))
	if len(records) != 0 {
		t.Fatalf("renderEvents() = %+v, want no record from an unrenderable handle", records)
	}
	if !strings.Contains(buf.String(), "events dropped") {
		t.Errorf("log does not report the dropped events: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "dropped=2") {
		t.Errorf("log does not count both dropped events: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "EvtRender") {
		t.Errorf("log does not carry the error behind the drops: %q", buf.String())
	}
}
