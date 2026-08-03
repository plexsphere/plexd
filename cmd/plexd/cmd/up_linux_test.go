//go:build linux

package cmd

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeJournalctlStub creates an executable journalctl stub in a temporary
// directory and points $PATH at it, so the availability probe resolves
// deterministically regardless of the host.
func writeJournalctlStub(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	stub := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write journalctl stub: %v", err)
	}
	t.Setenv("PATH", dir)
}

func TestNewJournalReader_ReturnsReaderWhenJournalctlPresent(t *testing.T) {
	writeJournalctlStub(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	if reader := newJournalReader(logger); reader == nil {
		t.Fatal("newJournalReader() = nil, want a reader when journalctl is on PATH")
	}
	if buf.Len() != 0 {
		t.Errorf("log output = %q, want none when journalctl is available", buf.String())
	}
}

func TestNewJournalReader_ReturnsNilWhenJournalctlMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	if reader := newJournalReader(logger); reader != nil {
		t.Errorf("newJournalReader() = %v, want nil when journalctl is missing", reader)
	}

	out := buf.String()
	if !strings.Contains(out, "journald not available") {
		t.Errorf("log output = %q, want a journald-not-available notice", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("log output = %q, want the notice at INFO level", out)
	}
}
