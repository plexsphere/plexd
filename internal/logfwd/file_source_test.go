package logfwd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSource_GlobMatch(t *testing.T) {
	dir := t.TempDir()
	// Create 3 log files.
	for _, name := range []string{"app1.log", "app2.log", "app3.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("line from "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Create a non-matching file.
	if err := os.WriteFile(filepath.Join(dir, "data.txt"), []byte("ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(filepath.Join(dir, "*.log"), "host", discardLogger())
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	for _, e := range entries {
		if e.Source != "file" {
			t.Errorf("Source = %q, want %q", e.Source, "file")
		}
		if e.Severity != "info" {
			t.Errorf("Severity = %q, want %q", e.Severity, "info")
		}
		if e.Hostname != "host" {
			t.Errorf("Hostname = %q, want %q", e.Hostname, "host")
		}
		if !strings.HasPrefix(e.Message, "line from ") {
			t.Errorf("unexpected message: %q", e.Message)
		}
	}
}

func TestFileSource_OffsetTracking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(path, "host", discardLogger())

	// First collect.
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("first Collect: len = %d, want 1", len(entries))
	}
	if entries[0].Message != "first" {
		t.Errorf("first Collect: Message = %q, want %q", entries[0].Message, "first")
	}

	// Second collect with no new data.
	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("second Collect: len = %d, want 0 (no new data)", len(entries))
	}

	// Append new data.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("second\nthird\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Third collect should only get new lines.
	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("third Collect() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("third Collect: len = %d, want 2", len(entries))
	}
	if entries[0].Message != "second" {
		t.Errorf("third Collect[0]: Message = %q, want %q", entries[0].Message, "second")
	}
	if entries[1].Message != "third" {
		t.Errorf("third Collect[1]: Message = %q, want %q", entries[1].Message, "third")
	}
}

func TestFileSource_LineTruncation16KiB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")

	// Write a line exceeding MaxLineBytes.
	bigLine := strings.Repeat("x", MaxLineBytes+100)
	if err := os.WriteFile(path, []byte(bigLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(path, "host", discardLogger())
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	msg := entries[0].Message
	if !strings.HasSuffix(msg, truncatedSuffix) {
		t.Errorf("message does not have truncated suffix")
	}
	// Truncated message should be MaxLineBytes + suffix length.
	expectedLen := MaxLineBytes + len(truncatedSuffix)
	if len(msg) != expectedLen {
		t.Errorf("len(message) = %d, want %d", len(msg), expectedLen)
	}
}

func TestFileSource_FileRotationDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotated.log")

	// Write initial content.
	if err := os.WriteFile(path, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(path, "host", discardLogger())

	// First collect reads "original".
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Message != "original" {
		t.Fatalf("first Collect: unexpected entries: %v", entries)
	}

	// Simulate rotation: remove and recreate.
	os.Remove(path)
	if err := os.WriteFile(path, []byte("rotated\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Second collect should read from beginning of new file.
	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Message != "rotated" {
		t.Fatalf("second Collect: expected 'rotated', got %v", entries)
	}
}

func TestFileSource_FileRotationDetection_SameSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotated.log")

	if err := os.WriteFile(path, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(path, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Message != "original" {
		t.Fatalf("first Collect: unexpected entries: %v", entries)
	}

	// Rotate by rename, so the old file keeps its inode and the replacement
	// cannot reuse it. "replaced\n" is the same 9 bytes as "original\n", so only
	// the identity check can reveal the rotation.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replaced\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Message != "replaced" {
		t.Fatalf("second Collect: expected 'replaced', got %v", entries)
	}
}

func TestFileSource_EmptyGlobReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	src := NewFileSource(filepath.Join(dir, "*.nonexistent"), "host", discardLogger())
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("len(entries) = %d, want 0", len(entries))
	}
}

func TestFileSource_SkipsEmptyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gaps.log")
	if err := os.WriteFile(path, []byte("line1\n\n\nline2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(path, "host", discardLogger())
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2 (skipping empty lines)", len(entries))
	}
}

func TestFileSource_UnitIsFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(path, "host", discardLogger())
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Unit != path {
		t.Errorf("Unit = %q, want %q", entries[0].Unit, path)
	}
}

func TestFileSource_ContextCancelled(t *testing.T) {
	src := NewFileSource("/tmp/*.log", "host", discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := src.Collect(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestFileSource_UnreadableFileSkipped(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.log")
	bad := filepath.Join(dir, "bad.log")

	if err := os.WriteFile(good, []byte("good line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("bad line\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(filepath.Join(dir, "*.log"), "host", discardLogger())
	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Should have at least the good file's entries.
	found := false
	for _, e := range entries {
		if e.Message == "good line" {
			found = true
		}
	}
	if !found {
		t.Error("expected entry from good.log")
	}
}
