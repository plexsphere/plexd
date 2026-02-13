package auditfwd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type mockK8sAuditReader struct {
	entries []K8sAuditEntry
	err     error
}

func (m *mockK8sAuditReader) ReadEvents(ctx context.Context) ([]K8sAuditEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.entries, nil
}

func TestK8sAuditSource_Collect_MapsFieldsCorrectly(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	reader := &mockK8sAuditReader{
		entries: []K8sAuditEntry{
			{
				Timestamp: ts,
				Verb:      "create",
				User:      K8sUser{Username: "system:serviceaccount:default:deployer", Groups: []string{"system:serviceaccounts"}},
				ObjectRef: K8sObjectRef{Resource: "pods", Namespace: "production", Name: "web-abc123"},
				RequestURI:     "/api/v1/namespaces/production/pods",
				ResponseStatus: 201,
				Raw:            `{"apiVersion":"audit.k8s.io/v1","kind":"Event"}`,
			},
		},
	}
	src := NewK8sAuditSource(reader, "k8s-node-1", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Source != "k8s-audit" {
		t.Errorf("Source = %q, want %q", entry.Source, "k8s-audit")
	}
	if entry.EventType != "create" {
		t.Errorf("EventType = %q, want %q", entry.EventType, "create")
	}
	if entry.Action != "create" {
		t.Errorf("Action = %q, want %q", entry.Action, "create")
	}
	if entry.Result != "success" {
		t.Errorf("Result = %q, want %q", entry.Result, "success")
	}
	if entry.Hostname != "k8s-node-1" {
		t.Errorf("Hostname = %q, want %q", entry.Hostname, "k8s-node-1")
	}
	if !entry.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", entry.Timestamp, ts)
	}
	if entry.Raw != `{"apiVersion":"audit.k8s.io/v1","kind":"Event"}` {
		t.Errorf("Raw = %q, want original raw string", entry.Raw)
	}

	// Subject should be a K8sUser JSON object.
	var subj K8sUser
	if err := json.Unmarshal(entry.Subject, &subj); err != nil {
		t.Fatalf("Subject is not valid JSON: %v", err)
	}
	if subj.Username != "system:serviceaccount:default:deployer" {
		t.Errorf("Subject.Username = %q, want %q", subj.Username, "system:serviceaccount:default:deployer")
	}
	if len(subj.Groups) != 1 || subj.Groups[0] != "system:serviceaccounts" {
		t.Errorf("Subject.Groups = %v, want [system:serviceaccounts]", subj.Groups)
	}

	// Object should be "namespace/resource/name" as a JSON string.
	var obj string
	if err := json.Unmarshal(entry.Object, &obj); err != nil {
		t.Errorf("Object is not valid JSON: %v", err)
	}
	if obj != "production/pods/web-abc123" {
		t.Errorf("Object = %q, want %q", obj, "production/pods/web-abc123")
	}
}

func TestK8sAuditSource_Collect_ResultMapping(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantResult string
	}{
		{"200 OK maps to success", 200, "success"},
		{"201 Created maps to success", 201, "success"},
		{"204 No Content maps to success", 204, "success"},
		{"299 maps to success", 299, "success"},
		{"300 maps to failure", 300, "failure"},
		{"400 Bad Request maps to failure", 400, "failure"},
		{"403 Forbidden maps to failure", 403, "failure"},
		{"404 Not Found maps to failure", 404, "failure"},
		{"500 Internal Server Error maps to failure", 500, "failure"},
		{"199 maps to failure", 199, "failure"},
		{"0 maps to failure", 0, "failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &mockK8sAuditReader{
				entries: []K8sAuditEntry{
					{
						Timestamp:      time.Now(),
						Verb:           "get",
						User:           K8sUser{Username: "admin"},
						ObjectRef:      K8sObjectRef{Resource: "pods", Namespace: "default", Name: "test"},
						ResponseStatus: tt.statusCode,
						Raw:            "raw",
					},
				},
			}
			src := NewK8sAuditSource(reader, "host", discardLogger())

			entries, err := src.Collect(context.Background())
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			if entries[0].Result != tt.wantResult {
				t.Errorf("Result = %q, want %q for status code %d", entries[0].Result, tt.wantResult, tt.statusCode)
			}
		})
	}
}

func TestK8sAuditSource_Collect_HandlesReaderError(t *testing.T) {
	reader := &mockK8sAuditReader{
		err: errors.New("k8s api unavailable"),
	}
	src := NewK8sAuditSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
	if !strings.Contains(err.Error(), "auditfwd: k8s-audit:") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "auditfwd: k8s-audit:")
	}
}

func TestK8sAuditSource_Collect_ReturnsEmptyOnNoEntries(t *testing.T) {
	reader := &mockK8sAuditReader{
		entries: []K8sAuditEntry{},
	}
	src := NewK8sAuditSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
}

func TestK8sAuditSource_Collect_MultipleEntries(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	reader := &mockK8sAuditReader{
		entries: []K8sAuditEntry{
			{Timestamp: ts, Verb: "create", User: K8sUser{Username: "admin"}, ObjectRef: K8sObjectRef{Resource: "pods", Namespace: "default", Name: "web-1"}, ResponseStatus: 201, Raw: "raw1"},
			{Timestamp: ts, Verb: "delete", User: K8sUser{Username: "admin"}, ObjectRef: K8sObjectRef{Resource: "configmaps", Namespace: "kube-system", Name: "cfg-1"}, ResponseStatus: 200, Raw: "raw2"},
		},
	}
	src := NewK8sAuditSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].EventType != "create" {
		t.Errorf("entries[0].EventType = %q, want %q", entries[0].EventType, "create")
	}
	if entries[1].EventType != "delete" {
		t.Errorf("entries[1].EventType = %q, want %q", entries[1].EventType, "delete")
	}
}

func TestK8sAuditSource_Collect_EmptyNamespace(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	reader := &mockK8sAuditReader{
		entries: []K8sAuditEntry{
			{Timestamp: ts, Verb: "list", User: K8sUser{Username: "admin"}, ObjectRef: K8sObjectRef{Resource: "nodes"}, ResponseStatus: 200, Raw: "raw"},
		},
	}
	src := NewK8sAuditSource(reader, "host", discardLogger())

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	var obj string
	if err := json.Unmarshal(entries[0].Object, &obj); err != nil {
		t.Errorf("Object is not valid JSON: %v", err)
	}
	// With empty namespace and name, should be just the resource.
	if obj != "nodes" {
		t.Errorf("Object = %q, want %q", obj, "nodes")
	}
}
