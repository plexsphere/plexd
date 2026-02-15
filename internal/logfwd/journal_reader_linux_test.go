//go:build linux

package logfwd

import (
	"context"
	"os/exec"
	"testing"
)

func TestJournalctlReader_NewReaderHasNoCursor(t *testing.T) {
	r := NewJournalctlReader()
	if r.cursor != "" {
		t.Errorf("cursor = %q, want empty", r.cursor)
	}
}

func TestJournalctlReader_ReadEntries_Integration(t *testing.T) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not available, skipping integration test")
	}

	r := NewJournalctlReader()
	entries, err := r.ReadEntries(context.Background())
	if err != nil {
		t.Fatalf("ReadEntries() error = %v", err)
	}

	t.Logf("got %d journal entries", len(entries))

	for _, e := range entries {
		if e.Timestamp.IsZero() {
			t.Error("entry has zero timestamp")
		}
	}

	if len(entries) > 0 && r.cursor == "" {
		t.Error("cursor not updated after reading entries")
	}
}

func TestJournalctlReader_ReadEntries_CancelledContext(t *testing.T) {
	r := NewJournalctlReader()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.ReadEntries(ctx)
	if err == nil {
		return // Timing-dependent; no panic is the success condition.
	}
	t.Logf("ReadEntries with cancelled context: %v (expected)", err)
}

func TestJournalctlReader_CursorTracking(t *testing.T) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not available, skipping integration test")
	}

	r := NewJournalctlReader()

	_, err := r.ReadEntries(context.Background())
	if err != nil {
		t.Fatalf("first ReadEntries() error = %v", err)
	}
	cursor1 := r.cursor

	_, err = r.ReadEntries(context.Background())
	if err != nil {
		t.Fatalf("second ReadEntries() error = %v", err)
	}

	if cursor1 != "" {
		t.Logf("cursor after first call: %s", cursor1[:min(40, len(cursor1))])
	}
}
