//go:build linux

package cmd

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
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

func TestNewSystemLogSource_ReturnsJournaldSourceWhenJournalctlPresent(t *testing.T) {
	writeJournalctlStub(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	src := newSystemLogSource("host", logger)
	if src == nil {
		t.Fatal("newSystemLogSource() = nil, want a source when journalctl is on PATH")
	}
	if _, ok := src.(*logfwd.JournaldSource); !ok {
		t.Errorf("newSystemLogSource() = %T, want *logfwd.JournaldSource", src)
	}
	if buf.Len() != 0 {
		t.Errorf("log output = %q, want none when journalctl is available", buf.String())
	}
}

func TestNewSystemLogSource_ReturnsNilWhenJournalctlMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	if src := newSystemLogSource("host", logger); src != nil {
		t.Errorf("newSystemLogSource() = %v, want nil when journalctl is missing", src)
	}

	out := buf.String()
	if !strings.Contains(out, "journald not available") {
		t.Errorf("log output = %q, want a journald-not-available notice", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("log output = %q, want the notice at INFO level", out)
	}
}

func TestNewSystemReader_Linux(t *testing.T) {
	reader := newSystemReader(discardLogger())
	if reader == nil {
		t.Fatal("newSystemReader() = nil, want the procfs reader on Linux")
	}
	if _, ok := reader.(*metrics.LinuxSystemReader); !ok {
		t.Errorf("newSystemReader() = %T, want *metrics.LinuxSystemReader", reader)
	}
}
