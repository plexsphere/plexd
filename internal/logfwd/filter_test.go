package logfwd

import (
	"context"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// staticSource is a test LogSource that returns fixed entries.
type staticSource struct {
	entries []api.LogEntry
}

func (s *staticSource) Collect(_ context.Context) ([]api.LogEntry, error) {
	return s.entries, nil
}

func testLogEntries() []api.LogEntry {
	return []api.LogEntry{
		{Timestamp: time.Now(), Source: "journald", Unit: "sshd.service", Message: "accepted", Severity: "info", Hostname: "h"},
		{Timestamp: time.Now(), Source: "journald", Unit: "cron.service", Message: "cron ran", Severity: "debug", Hostname: "h"},
		{Timestamp: time.Now(), Source: "journald", Unit: "sshd.service", Message: "key error", Severity: "err", Hostname: "h"},
		{Timestamp: time.Now(), Source: "journald", Unit: "nginx.service", Message: "started", Severity: "warning", Hostname: "h"},
		{Timestamp: time.Now(), Source: "journald", Unit: "plexd.service", Message: "connected", Severity: "notice", Hostname: "h"},
	}
}

func TestLogFilter_EmptyConfigPassesAll(t *testing.T) {
	entries := testLogEntries()
	src := &staticSource{entries: entries}
	fs := NewFilteringSource(src, FilterConfig{})

	result, err := fs.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(result) != len(entries) {
		t.Errorf("len(result) = %d, want %d", len(result), len(entries))
	}
}

func TestLogFilter_SeverityFilter(t *testing.T) {
	entries := testLogEntries()
	src := &staticSource{entries: entries}
	fs := NewFilteringSource(src, FilterConfig{MinSeverity: "warning"})

	result, err := fs.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// "warning" priority=4; info=6 and debug=7 should be dropped, notice=5 should be dropped.
	// Only entries with severity <= warning (emerg, alert, crit, err, warning) pass.
	for _, e := range result {
		pri, ok := severityPriority[e.Severity]
		if !ok {
			t.Errorf("unknown severity %q", e.Severity)
			continue
		}
		if pri > severityPriority["warning"] {
			t.Errorf("entry with severity %q (pri=%d) should have been filtered", e.Severity, pri)
		}
	}
	// We should have err=3 and warning=4 entries (2 of 5).
	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2 (err + warning)", len(result))
	}
}

func TestLogFilter_SeverityFilter_DropsDebug(t *testing.T) {
	entries := []api.LogEntry{
		{Severity: "info", Message: "keep"},
		{Severity: "debug", Message: "drop"},
	}
	src := &staticSource{entries: entries}
	fs := NewFilteringSource(src, FilterConfig{MinSeverity: "info"})

	result, err := fs.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1", len(result))
	}
	if result[0].Message != "keep" {
		t.Errorf("Message = %q, want %q", result[0].Message, "keep")
	}
}

func TestLogFilter_UnitIncludeFilter(t *testing.T) {
	entries := testLogEntries()
	src := &staticSource{entries: entries}
	fs := NewFilteringSource(src, FilterConfig{IncludeUnits: []string{"sshd.service"}})

	result, err := fs.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("len(result) = %d, want 2 (two sshd entries)", len(result))
	}
	for _, e := range result {
		if e.Unit != "sshd.service" {
			t.Errorf("Unit = %q, want %q", e.Unit, "sshd.service")
		}
	}
}

func TestLogFilter_UnitExcludeFilter(t *testing.T) {
	entries := testLogEntries()
	src := &staticSource{entries: entries}
	fs := NewFilteringSource(src, FilterConfig{ExcludeUnits: []string{"cron.service", "nginx.service"}})

	result, err := fs.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	// 5 total - 2 excluded = 3
	if len(result) != 3 {
		t.Fatalf("len(result) = %d, want 3", len(result))
	}
	for _, e := range result {
		if e.Unit == "cron.service" || e.Unit == "nginx.service" {
			t.Errorf("excluded unit %q should not be in results", e.Unit)
		}
	}
}

func TestLogFilter_CombinedFilters(t *testing.T) {
	entries := testLogEntries()
	src := &staticSource{entries: entries}
	// Include sshd only, minimum severity warning.
	fs := NewFilteringSource(src, FilterConfig{
		MinSeverity:  "warning",
		IncludeUnits: []string{"sshd.service"},
	})

	result, err := fs.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	// sshd entries: info (dropped - too low) and err (kept).
	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1 (only sshd err entry)", len(result))
	}
	if result[0].Severity != "err" {
		t.Errorf("Severity = %q, want %q", result[0].Severity, "err")
	}
}

func TestLogFilter_IncludeAndExclude(t *testing.T) {
	entries := []api.LogEntry{
		{Unit: "sshd.service", Severity: "info", Message: "a"},
		{Unit: "sshd.service", Severity: "info", Message: "b"},
		{Unit: "nginx.service", Severity: "info", Message: "c"},
	}
	src := &staticSource{entries: entries}
	// Include sshd but also exclude it — exclude wins (entry won't match include then gets excluded).
	// Actually: include matches sshd, then exclude checks — sshd is in exclude, so it's excluded.
	fs := NewFilteringSource(src, FilterConfig{
		IncludeUnits: []string{"sshd.service", "nginx.service"},
		ExcludeUnits: []string{"sshd.service"},
	})

	result, err := fs.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1 (only nginx after exclude)", len(result))
	}
	if result[0].Unit != "nginx.service" {
		t.Errorf("Unit = %q, want %q", result[0].Unit, "nginx.service")
	}
}

func TestFilterConfig_IsEmpty(t *testing.T) {
	if fc := (FilterConfig{}); !fc.IsEmpty() {
		t.Error("empty FilterConfig should be empty")
	}
	if fc := (FilterConfig{MinSeverity: "info"}); fc.IsEmpty() {
		t.Error("FilterConfig with MinSeverity should not be empty")
	}
	if fc := (FilterConfig{IncludeUnits: []string{"a"}}); fc.IsEmpty() {
		t.Error("FilterConfig with IncludeUnits should not be empty")
	}
	if fc := (FilterConfig{ExcludeUnits: []string{"b"}}); fc.IsEmpty() {
		t.Error("FilterConfig with ExcludeUnits should not be empty")
	}
}
