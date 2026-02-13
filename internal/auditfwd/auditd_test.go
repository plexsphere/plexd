package auditfwd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type mockAuditdReader struct {
	entries []AuditdEntry
	err     error
}

func (m *mockAuditdReader) ReadEvents(ctx context.Context) ([]AuditdEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.entries, nil
}

func TestAuditdSource_Collect_MapsFieldsCorrectly(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	reader := &mockAuditdReader{
		entries: []AuditdEntry{
			{
				Timestamp: ts,
				Type:      "SYSCALL",
				UID:       1000,
				GID:       1000,
				PID:       4321,
				Syscall:   "open",
				Object:    "/etc/passwd",
				Path:      "/etc/passwd",
				Success:   true,
				Raw:       `type=SYSCALL msg=audit(1718452800.000:100): arch=c000003e syscall=2`,
			},
		},
	}
	src := NewAuditdSource(reader, "test-host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Source != "auditd" {
		t.Errorf("Source = %q, want %q", entry.Source, "auditd")
	}
	if entry.EventType != "SYSCALL" {
		t.Errorf("EventType = %q, want %q", entry.EventType, "SYSCALL")
	}
	if entry.Action != "open" {
		t.Errorf("Action = %q, want %q", entry.Action, "open")
	}
	if entry.Result != "success" {
		t.Errorf("Result = %q, want %q", entry.Result, "success")
	}
	if entry.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", entry.Hostname, "test-host")
	}
	if !entry.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", entry.Timestamp, ts)
	}
	if entry.Raw != `type=SYSCALL msg=audit(1718452800.000:100): arch=c000003e syscall=2` {
		t.Errorf("Raw = %q, want original raw string", entry.Raw)
	}

	// Subject should be a structured JSON object with uid, gid, pid.
	var subj auditdSubject
	if err := json.Unmarshal(entry.Subject, &subj); err != nil {
		t.Fatalf("Subject is not valid JSON: %v", err)
	}
	if subj.UID != 1000 {
		t.Errorf("Subject.UID = %d, want 1000", subj.UID)
	}
	if subj.GID != 1000 {
		t.Errorf("Subject.GID = %d, want 1000", subj.GID)
	}
	if subj.PID != 4321 {
		t.Errorf("Subject.PID = %d, want 4321", subj.PID)
	}

	var obj string
	if err := json.Unmarshal(entry.Object, &obj); err != nil {
		t.Errorf("Object is not valid JSON: %v", err)
	}
	if obj != "/etc/passwd" {
		t.Errorf("Object = %q, want %q", obj, "/etc/passwd")
	}
}

func TestAuditdSource_Collect_ResultFailure(t *testing.T) {
	reader := &mockAuditdReader{
		entries: []AuditdEntry{
			{
				Timestamp: time.Now(),
				Type:      "SYSCALL",
				UID:       0,
				GID:       0,
				PID:       1,
				Syscall:   "open",
				Object:    "/etc/shadow",
				Success:   false,
				Raw:       "raw",
			},
		},
	}
	src := NewAuditdSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries[0].Result != "failure" {
		t.Errorf("Result = %q, want %q", entries[0].Result, "failure")
	}
}

func TestAuditdSource_Collect_ActionFallbackToType(t *testing.T) {
	reader := &mockAuditdReader{
		entries: []AuditdEntry{
			{
				Timestamp: time.Now(),
				Type:      "USER_AUTH",
				UID:       1000,
				GID:       1000,
				PID:       5678,
				Syscall:   "",
				Object:    "sshd",
				Success:   true,
				Raw:       "raw",
			},
		},
	}
	src := NewAuditdSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries[0].Action != "USER_AUTH" {
		t.Errorf("Action = %q, want %q (fallback to Type when Syscall is empty)", entries[0].Action, "USER_AUTH")
	}
}

func TestAuditdSource_Collect_HandlesReaderError(t *testing.T) {
	reader := &mockAuditdReader{
		err: errors.New("auditd unavailable"),
	}
	src := NewAuditdSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
	if !strings.Contains(err.Error(), "auditfwd: auditd:") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "auditfwd: auditd:")
	}
}

func TestAuditdSource_Collect_ReturnsEmptyOnNoEntries(t *testing.T) {
	reader := &mockAuditdReader{
		entries: []AuditdEntry{},
	}
	src := NewAuditdSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
}

func TestAuditdSource_Collect_MultipleEntries(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	reader := &mockAuditdReader{
		entries: []AuditdEntry{
			{Timestamp: ts, Type: "SYSCALL", UID: 0, GID: 0, PID: 1, Syscall: "open", Object: "/etc/shadow", Success: true, Raw: "raw1"},
			{Timestamp: ts, Type: "USER_AUTH", UID: 1000, GID: 1000, PID: 2, Syscall: "authenticate", Object: "sshd", Success: false, Raw: "raw2"},
		},
	}
	src := NewAuditdSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].EventType != "SYSCALL" {
		t.Errorf("entries[0].EventType = %q, want %q", entries[0].EventType, "SYSCALL")
	}
	if entries[1].EventType != "USER_AUTH" {
		t.Errorf("entries[1].EventType = %q, want %q", entries[1].EventType, "USER_AUTH")
	}
}
