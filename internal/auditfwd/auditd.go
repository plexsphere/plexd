package auditfwd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// AuditdEntry represents a single entry read from the Linux audit subsystem.
type AuditdEntry struct {
	Timestamp time.Time
	Type      string
	UID       int
	GID       int
	PID       int
	Syscall   string
	Object    string
	Path      string
	Success   bool
	Raw       string
}

// auditdSubject is the structured JSON representation of an auditd subject.
type auditdSubject struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
	PID int `json:"pid"`
}

// AuditdReader abstracts Linux auditd access for testability.
type AuditdReader interface {
	ReadEvents(ctx context.Context) ([]AuditdEntry, error)
}

// AuditdSource implements AuditSource by reading from the Linux audit subsystem.
type AuditdSource struct {
	reader   AuditdReader
	hostname string
	logger   *slog.Logger
}

// NewAuditdSource creates a new AuditdSource.
func NewAuditdSource(reader AuditdReader, hostname string, logger *slog.Logger) *AuditdSource {
	return &AuditdSource{
		reader:   reader,
		hostname: hostname,
		logger:   logger,
	}
}

// auditdResult maps the Success field to "success" or "failure".
func auditdResult(success bool) string {
	if success {
		return "success"
	}
	return "failure"
}

// auditdAction returns Syscall if non-empty, otherwise falls back to Type.
func auditdAction(syscall, typ string) string {
	if syscall != "" {
		return syscall
	}
	return typ
}

// Collect reads auditd entries and maps them to api.AuditEntry values.
func (s *AuditdSource) Collect(ctx context.Context) ([]api.AuditEntry, error) {
	entries, err := s.reader.ReadEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("auditfwd: auditd: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	audits := make([]api.AuditEntry, len(entries))
	for i, e := range entries {
		subjectJSON, _ := json.Marshal(auditdSubject{
			UID: e.UID,
			GID: e.GID,
			PID: e.PID,
		})
		objectJSON, _ := json.Marshal(e.Object)

		audits[i] = api.AuditEntry{
			Timestamp: e.Timestamp,
			Source:    "auditd",
			EventType: e.Type,
			Subject:   subjectJSON,
			Object:    objectJSON,
			Action:    auditdAction(e.Syscall, e.Type),
			Result:    auditdResult(e.Success),
			Hostname:  s.hostname,
			Raw:       e.Raw,
		}
	}
	return audits, nil
}
