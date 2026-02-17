package logfwd

import (
	"fmt"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func makeEntry(msg string) api.LogEntry {
	return api.LogEntry{
		Timestamp: time.Now(),
		Source:    "test",
		Unit:      "test",
		Message:   msg,
		Severity:  "info",
		Hostname:  "test-host",
	}
}

func TestRingBuffer_DefaultCapacity(t *testing.T) {
	rb := NewRingBuffer(0)
	if rb.cap != DefaultRingBufferCapacity {
		t.Errorf("expected default capacity %d, got %d", DefaultRingBufferCapacity, rb.cap)
	}
}

func TestRingBuffer_WriteAndRecent(t *testing.T) {
	rb := NewRingBuffer(5)

	rb.Write(makeEntry("a"))
	rb.Write(makeEntry("b"))
	rb.Write(makeEntry("c"))

	lines := rb.RecentLines(10)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "a" || lines[1] != "b" || lines[2] != "c" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestRingBuffer_Overflow(t *testing.T) {
	rb := NewRingBuffer(3)

	for i := 0; i < 5; i++ {
		rb.Write(makeEntry(fmt.Sprintf("msg-%d", i)))
	}

	if rb.Len() != 3 {
		t.Errorf("expected len 3, got %d", rb.Len())
	}

	lines := rb.RecentLines(3)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Should have the 3 most recent: msg-2, msg-3, msg-4
	if lines[0] != "msg-2" || lines[1] != "msg-3" || lines[2] != "msg-4" {
		t.Errorf("unexpected lines after overflow: %v", lines)
	}
}

func TestRingBuffer_RecentSubset(t *testing.T) {
	rb := NewRingBuffer(10)

	for i := 0; i < 7; i++ {
		rb.Write(makeEntry(fmt.Sprintf("line-%d", i)))
	}

	lines := rb.RecentLines(3)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "line-4" || lines[1] != "line-5" || lines[2] != "line-6" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestRingBuffer_Empty(t *testing.T) {
	rb := NewRingBuffer(5)
	lines := rb.RecentLines(5)
	if lines != nil {
		t.Errorf("expected nil for empty buffer, got %v", lines)
	}
}

func TestRingBuffer_WriteBatch(t *testing.T) {
	rb := NewRingBuffer(5)
	batch := []api.LogEntry{
		makeEntry("x"),
		makeEntry("y"),
		makeEntry("z"),
	}
	rb.WriteBatch(batch)
	if rb.Len() != 3 {
		t.Errorf("expected len 3, got %d", rb.Len())
	}
	lines := rb.RecentLines(3)
	if lines[0] != "x" || lines[1] != "y" || lines[2] != "z" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestRingBuffer_RecentZero(t *testing.T) {
	rb := NewRingBuffer(5)
	rb.Write(makeEntry("a"))
	lines := rb.RecentLines(0)
	if lines != nil {
		t.Errorf("expected nil for n=0, got %v", lines)
	}
}
