package auditfwd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// K8sUser represents the user identity from a Kubernetes audit event.
type K8sUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups,omitempty"`
}

// K8sObjectRef represents the target object of a Kubernetes audit event.
type K8sObjectRef struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// K8sAuditEntry represents a single Kubernetes audit log entry.
type K8sAuditEntry struct {
	Timestamp      time.Time
	Verb           string
	User           K8sUser
	ObjectRef      K8sObjectRef
	RequestURI     string
	ResponseStatus int
	Raw            string
}

// K8sAuditReader abstracts Kubernetes audit log access for testability.
type K8sAuditReader interface {
	ReadEvents(ctx context.Context) ([]K8sAuditEntry, error)
}

// K8sAuditSource implements AuditSource by reading Kubernetes audit logs.
type K8sAuditSource struct {
	reader   K8sAuditReader
	hostname string
	logger   *slog.Logger
}

// NewK8sAuditSource creates a new K8sAuditSource.
func NewK8sAuditSource(reader K8sAuditReader, hostname string, logger *slog.Logger) *K8sAuditSource {
	return &K8sAuditSource{
		reader:   reader,
		hostname: hostname,
		logger:   logger,
	}
}

// formatObjectRef builds the object reference string from a K8sObjectRef.
func formatObjectRef(ref K8sObjectRef) string {
	obj := ref.Resource
	if ref.Namespace != "" {
		obj = ref.Namespace + "/" + obj
	}
	if ref.Name != "" {
		obj = obj + "/" + ref.Name
	}
	return obj
}

// k8sResult maps an HTTP status code to "success" (2xx) or "failure" (non-2xx).
func k8sResult(statusCode int) string {
	if statusCode >= 200 && statusCode < 300 {
		return "success"
	}
	return "failure"
}

// Collect reads Kubernetes audit entries and maps them to api.AuditEntry values.
func (s *K8sAuditSource) Collect(ctx context.Context) ([]api.AuditEntry, error) {
	entries, err := s.reader.ReadEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("auditfwd: k8s-audit: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	audits := make([]api.AuditEntry, len(entries))
	for i, e := range entries {
		subjectJSON, _ := json.Marshal(e.User)
		objectJSON, _ := json.Marshal(formatObjectRef(e.ObjectRef))

		audits[i] = api.AuditEntry{
			Timestamp: e.Timestamp,
			Source:    "k8s-audit",
			EventType: e.Verb,
			Subject:   subjectJSON,
			Object:    objectJSON,
			Action:    e.Verb,
			Result:    k8sResult(e.ResponseStatus),
			Hostname:  s.hostname,
			Raw:       e.Raw,
		}
	}
	return audits, nil
}
