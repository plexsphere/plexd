package kubernetes

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/plexsphere/plexd/internal/auditfwd"
)

// k8sAuditEvent is the JSON structure of a single Kubernetes audit log event.
type k8sAuditEvent struct {
	Kind                    string              `json:"kind"`
	Level                   string              `json:"level"`
	Verb                    string              `json:"verb"`
	RequestURI              string              `json:"requestURI"`
	User                    auditfwd.K8sUser    `json:"user"`
	ObjectRef               *k8sAuditObjectRef  `json:"objectRef,omitempty"`
	ResponseStatus          *k8sResponseStatus  `json:"responseStatus,omitempty"`
	RequestReceivedTimestamp string              `json:"requestReceivedTimestamp"`
	StageTimestamp           string              `json:"stageTimestamp"`
}

// k8sAuditObjectRef is the JSON structure for the object reference in a
// Kubernetes audit event.
type k8sAuditObjectRef struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// k8sResponseStatus is the JSON structure for the response status in a
// Kubernetes audit event.
type k8sResponseStatus struct {
	Code int `json:"code"`
}

// K8sAuditLogReader implements auditfwd.K8sAuditReader by reading Kubernetes
// audit log files in JSON-lines format. It tracks the file position between
// reads so only new entries are returned on each call.
type K8sAuditLogReader struct {
	path   string
	offset int64
	logger *slog.Logger
}

// NewK8sAuditLogReader creates a new reader for the audit log at the given path.
func NewK8sAuditLogReader(path string, logger *slog.Logger) *K8sAuditLogReader {
	return &K8sAuditLogReader{
		path:   path,
		logger: logger,
	}
}

// ReadEvents reads new audit log entries since the last call. It returns only
// entries appended after the previously recorded offset. If the file does not
// exist, it returns nil, nil. If the file has been truncated (current size is
// smaller than the stored offset), it resets to the beginning.
func (r *K8sAuditLogReader) ReadEvents(_ context.Context) ([]auditfwd.K8sAuditEntry, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: audit-reader: open %s: %w", r.path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("kubernetes: audit-reader: stat: %w", err)
	}

	// Handle file truncation: reset offset if the file is smaller.
	if info.Size() < r.offset {
		r.logger.Warn("kubernetes: audit-reader: file truncated, resetting offset",
			"path", r.path, "previous_offset", r.offset, "file_size", info.Size())
		r.offset = 0
	}

	if _, err := f.Seek(r.offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("kubernetes: audit-reader: seek: %w", err)
	}

	var entries []auditfwd.K8sAuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var evt k8sAuditEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			r.logger.Warn("kubernetes: audit-reader: skipping malformed line",
				"error", err, "line_length", len(line))
			continue
		}

		entry := auditfwd.K8sAuditEntry{
			Verb:       evt.Verb,
			User:       evt.User,
			RequestURI: evt.RequestURI,
			Raw:        line,
		}

		if evt.ObjectRef != nil {
			entry.ObjectRef = auditfwd.K8sObjectRef{
				Resource:  evt.ObjectRef.Resource,
				Namespace: evt.ObjectRef.Namespace,
				Name:      evt.ObjectRef.Name,
			}
		}

		if evt.ResponseStatus != nil {
			entry.ResponseStatus = evt.ResponseStatus.Code
		}

		if ts, err := time.Parse(time.RFC3339Nano, evt.StageTimestamp); err == nil {
			entry.Timestamp = ts
		} else if ts, err := time.Parse(time.RFC3339Nano, evt.RequestReceivedTimestamp); err == nil {
			entry.Timestamp = ts
		}

		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("kubernetes: audit-reader: scan: %w", err)
	}

	// Update offset to current file position.
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: audit-reader: tell: %w", err)
	}
	r.offset = pos

	return entries, nil
}
