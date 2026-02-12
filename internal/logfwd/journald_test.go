package logfwd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type mockJournalReader struct {
	entries []JournalEntry
	err     error
}

func (m *mockJournalReader) ReadEntries(_ context.Context) ([]JournalEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.entries, nil
}

func TestJournaldSource_Collect_MapsFieldsCorrectly(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	reader := &mockJournalReader{
		entries: []JournalEntry{
			{Timestamp: ts, Message: "hello world", Priority: 6, Unit: "plexd.service"},
		},
	}
	src := NewJournaldSource(reader, "test-host", discardLogger())

	logs, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}

	entry := logs[0]
	if entry.Source != "journald" {
		t.Errorf("Source = %q, want %q", entry.Source, "journald")
	}
	if entry.Unit != "plexd.service" {
		t.Errorf("Unit = %q, want %q", entry.Unit, "plexd.service")
	}
	if entry.Message != "hello world" {
		t.Errorf("Message = %q, want %q", entry.Message, "hello world")
	}
	if entry.Severity != "info" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "info")
	}
	if entry.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", entry.Hostname, "test-host")
	}
	if !entry.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", entry.Timestamp, ts)
	}
}

func TestJournaldSource_Collect_MapsPriorityToSeverity(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	entries := make([]JournalEntry, 8)
	for i := 0; i < 8; i++ {
		entries[i] = JournalEntry{Timestamp: ts, Message: "msg", Priority: i, Unit: "test.service"}
	}
	reader := &mockJournalReader{entries: entries}
	src := NewJournaldSource(reader, "host", discardLogger())

	logs, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(logs) != 8 {
		t.Fatalf("len(logs) = %d, want 8", len(logs))
	}

	want := []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
	for i, w := range want {
		if logs[i].Severity != w {
			t.Errorf("Priority %d: Severity = %q, want %q", i, logs[i].Severity, w)
		}
	}
}

func TestJournaldSource_Collect_HandlesMissingUnit(t *testing.T) {
	reader := &mockJournalReader{
		entries: []JournalEntry{
			{Timestamp: time.Now(), Message: "no unit", Priority: 6, Unit: ""},
		},
	}
	src := NewJournaldSource(reader, "host", discardLogger())

	logs, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}
	if logs[0].Unit != "" {
		t.Errorf("Unit = %q, want empty", logs[0].Unit)
	}
}

func TestJournaldSource_Collect_HandlesReaderError(t *testing.T) {
	reader := &mockJournalReader{
		err: errors.New("journal unavailable"),
	}
	src := NewJournaldSource(reader, "host", discardLogger())

	logs, err := src.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
	if logs != nil {
		t.Errorf("logs = %v, want nil", logs)
	}
	if !strings.Contains(err.Error(), "logfwd: journald:") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "logfwd: journald:")
	}
}

func TestJournaldSource_Collect_ReturnsEmptyOnNoEntries(t *testing.T) {
	reader := &mockJournalReader{
		entries: []JournalEntry{},
	}
	src := NewJournaldSource(reader, "host", discardLogger())

	logs, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if logs != nil {
		t.Errorf("logs = %v, want nil", logs)
	}
}

func TestMapSeverity_OutOfRange(t *testing.T) {
	if got := mapSeverity(-1); got != "info" {
		t.Errorf("mapSeverity(-1) = %q, want %q", got, "info")
	}
	if got := mapSeverity(8); got != "info" {
		t.Errorf("mapSeverity(8) = %q, want %q", got, "info")
	}
	if got := mapSeverity(100); got != "info" {
		t.Errorf("mapSeverity(100) = %q, want %q", got, "info")
	}
}
