package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/plexsphere/plexd/internal/auditfwd"
)

func writeAuditLine(t *testing.T, f *os.File, event k8sAuditEvent) {
	t.Helper()
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal audit event: %v", err)
	}
	if _, err := fmt.Fprintf(f, "%s\n", data); err != nil {
		t.Fatalf("write audit line: %v", err)
	}
}

func sampleEvent(verb, resource, namespace, name, user string) k8sAuditEvent {
	return k8sAuditEvent{
		Kind:       "Event",
		Level:      "Metadata",
		Verb:       verb,
		RequestURI: "/api/v1/namespaces/" + namespace + "/" + resource,
		User: auditfwd.K8sUser{
			Username: user,
			Groups:   []string{"system:masters"},
		},
		ObjectRef: &k8sAuditObjectRef{
			Resource:  resource,
			Namespace: namespace,
			Name:      name,
		},
		ResponseStatus:          &k8sResponseStatus{Code: 200},
		RequestReceivedTimestamp: "2025-01-15T10:30:00.000000Z",
		StageTimestamp:           "2025-01-15T10:30:01.000000Z",
	}
}

func TestK8sAuditLogReader_ImplementsInterface(t *testing.T) {
	var _ auditfwd.K8sAuditReader = &K8sAuditLogReader{}
}

func TestK8sAuditLogReader_ReadEvents_ParsesJSONLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	writeAuditLine(t, f, sampleEvent("create", "pods", "default", "web-1", "admin"))
	writeAuditLine(t, f, sampleEvent("get", "services", "kube-system", "coredns", "kubelet"))
	f.Close()

	reader := NewK8sAuditLogReader(logPath, testLogger())
	entries, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Verify first entry.
	e := entries[0]
	if e.Verb != "create" {
		t.Errorf("entry[0].Verb = %q, want %q", e.Verb, "create")
	}
	if e.User.Username != "admin" {
		t.Errorf("entry[0].User.Username = %q, want %q", e.User.Username, "admin")
	}
	if e.ObjectRef.Resource != "pods" {
		t.Errorf("entry[0].ObjectRef.Resource = %q, want %q", e.ObjectRef.Resource, "pods")
	}
	if e.ObjectRef.Namespace != "default" {
		t.Errorf("entry[0].ObjectRef.Namespace = %q, want %q", e.ObjectRef.Namespace, "default")
	}
	if e.ObjectRef.Name != "web-1" {
		t.Errorf("entry[0].ObjectRef.Name = %q, want %q", e.ObjectRef.Name, "web-1")
	}
	if e.ResponseStatus != 200 {
		t.Errorf("entry[0].ResponseStatus = %d, want %d", e.ResponseStatus, 200)
	}
	if e.Timestamp.IsZero() {
		t.Error("entry[0].Timestamp is zero")
	}
	if e.Raw == "" {
		t.Error("entry[0].Raw is empty")
	}

	// Verify second entry.
	e2 := entries[1]
	if e2.Verb != "get" {
		t.Errorf("entry[1].Verb = %q, want %q", e2.Verb, "get")
	}
	if e2.User.Username != "kubelet" {
		t.Errorf("entry[1].User.Username = %q, want %q", e2.User.Username, "kubelet")
	}
}

func TestK8sAuditLogReader_ReadEvents_TracksPosition(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	writeAuditLine(t, f, sampleEvent("create", "pods", "default", "web-1", "admin"))
	f.Close()

	reader := NewK8sAuditLogReader(logPath, testLogger())

	// First read should return one entry.
	entries, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("first ReadEvents: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("first read: expected 1 entry, got %d", len(entries))
	}

	// Second read with no new data should return empty.
	entries, err = reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("second ReadEvents: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("second read: expected 0 entries, got %d", len(entries))
	}

	// Append a new entry and read again.
	f, err = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	writeAuditLine(t, f, sampleEvent("delete", "pods", "default", "web-1", "admin"))
	f.Close()

	entries, err = reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("third ReadEvents: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("third read: expected 1 entry, got %d", len(entries))
	}
	if entries[0].Verb != "delete" {
		t.Errorf("third read entry.Verb = %q, want %q", entries[0].Verb, "delete")
	}
}

func TestK8sAuditLogReader_ReadEvents_MissingFile(t *testing.T) {
	reader := NewK8sAuditLogReader("/nonexistent/audit.log", testLogger())
	_, err := reader.ReadEvents(context.Background())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestK8sAuditLogReader_ReadEvents_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("create empty file: %v", err)
	}

	reader := NewK8sAuditLogReader(logPath, testLogger())
	entries, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestK8sAuditLogReader_ReadEvents_HandlesRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	// Write two events to advance the offset.
	writeAuditLine(t, f, sampleEvent("create", "pods", "default", "web-1", "admin"))
	writeAuditLine(t, f, sampleEvent("get", "pods", "default", "web-2", "admin"))
	f.Close()

	reader := NewK8sAuditLogReader(logPath, testLogger())
	entries, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("first ReadEvents: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("first read: expected 2 entries, got %d", len(entries))
	}

	// Truncate the file and write a single new event (shorter than before).
	f, err = os.Create(logPath) // Create truncates.
	if err != nil {
		t.Fatalf("truncate file: %v", err)
	}
	writeAuditLine(t, f, sampleEvent("delete", "pods", "default", "web-3", "admin"))
	f.Close()

	entries, err = reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents after truncation: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("after truncation: expected 1 entry, got %d", len(entries))
	}
	if entries[0].Verb != "delete" {
		t.Errorf("after truncation: entry.Verb = %q, want %q", entries[0].Verb, "delete")
	}
}

func TestK8sAuditLogReader_ReadEvents_SkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	writeAuditLine(t, f, sampleEvent("create", "pods", "default", "web-1", "admin"))
	fmt.Fprintln(f, "this is not valid json")
	fmt.Fprintln(f, "{broken json")
	writeAuditLine(t, f, sampleEvent("get", "services", "kube-system", "coredns", "kubelet"))
	f.Close()

	reader := NewK8sAuditLogReader(logPath, testLogger())
	entries, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (skipping malformed), got %d", len(entries))
	}
	if entries[0].Verb != "create" {
		t.Errorf("entry[0].Verb = %q, want %q", entries[0].Verb, "create")
	}
	if entries[1].Verb != "get" {
		t.Errorf("entry[1].Verb = %q, want %q", entries[1].Verb, "get")
	}
}

func TestK8sAuditLogReader_ReadEvents_HandlesNilObjectRef(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	evt := k8sAuditEvent{
		Kind:                    "Event",
		Level:                   "Metadata",
		Verb:                    "create",
		RequestURI:              "/api/v1/namespaces/default/pods",
		User:                    auditfwd.K8sUser{Username: "admin"},
		ObjectRef:               nil,
		ResponseStatus:          &k8sResponseStatus{Code: 201},
		RequestReceivedTimestamp: "2025-01-15T10:30:00.000000Z",
		StageTimestamp:           "2025-01-15T10:30:01.000000Z",
	}
	writeAuditLine(t, f, evt)
	f.Close()

	reader := NewK8sAuditLogReader(logPath, testLogger())
	entries, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.ObjectRef.Resource != "" {
		t.Errorf("ObjectRef.Resource = %q, want empty", e.ObjectRef.Resource)
	}
	if e.ResponseStatus != 201 {
		t.Errorf("ResponseStatus = %d, want 201", e.ResponseStatus)
	}
}

func TestK8sAuditLogReader_ReadEvents_HandlesNilResponseStatus(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	evt := k8sAuditEvent{
		Kind:       "Event",
		Level:      "Metadata",
		Verb:       "watch",
		RequestURI: "/api/v1/pods",
		User:       auditfwd.K8sUser{Username: "system:apiserver"},
		ObjectRef: &k8sAuditObjectRef{
			Resource:  "pods",
			Namespace: "default",
		},
		ResponseStatus:          nil,
		RequestReceivedTimestamp: "2025-01-15T10:30:00.000000Z",
		StageTimestamp:           "2025-01-15T10:30:01.000000Z",
	}
	writeAuditLine(t, f, evt)
	f.Close()

	reader := NewK8sAuditLogReader(logPath, testLogger())
	entries, err := reader.ReadEvents(context.Background())
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.ResponseStatus != 0 {
		t.Errorf("ResponseStatus = %d, want 0", e.ResponseStatus)
	}
	if e.Verb != "watch" {
		t.Errorf("Verb = %q, want %q", e.Verb, "watch")
	}
}
