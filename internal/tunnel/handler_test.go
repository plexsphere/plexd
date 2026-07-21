package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReporter records calls to ReportSessionStarted and ReportSessionEnded.
type mockReporter struct {
	mu           sync.Mutex
	startedCalls []sessionStartedCall
	endedCalls   []sessionEndedCall
}

type sessionStartedCall struct {
	SessionID  string
	TargetHost string
	TargetPort int
}

type sessionEndedCall struct {
	SessionID    string
	TargetHost   string
	TargetPort   int
	BytesIn      int64
	BytesOut     int64
	TerminatedBy string
}

func (r *mockReporter) ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startedCalls = append(r.startedCalls, sessionStartedCall{
		SessionID:  sessionID,
		TargetHost: targetHost,
		TargetPort: targetPort,
	})
}

func (r *mockReporter) ReportSessionEnded(ctx context.Context, sessionID, targetHost string, targetPort int, bytesIn, bytesOut int64, terminatedBy string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endedCalls = append(r.endedCalls, sessionEndedCall{
		SessionID:    sessionID,
		TargetHost:   targetHost,
		TargetPort:   targetPort,
		BytesIn:      bytesIn,
		BytesOut:     bytesOut,
		TerminatedBy: terminatedBy,
	})
}

func testEnvelope(eventType string, payload any) api.SignedEnvelope {
	data, _ := json.Marshal(payload)
	return api.SignedEnvelope{
		EventType: eventType,
		EventID:   "evt-1",
		Payload:   data,
	}
}

func TestSSEHandler_SSHSessionSetup(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	mgr := newTestManager(t, Config{})
	reporter := &mockReporter{}

	handler := HandleSSHSessionSetup(mgr, reporter)

	setup := api.SSHSessionSetup{
		SessionID:     "sess-setup-1",
		TargetHost:    host,
		TargetPort:    port,
		AuthorizedKey: "ssh-ed25519 AAAAC3...",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	envelope := testEnvelope(api.EventSSHSessionSetup, setup)

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("HandleSSHSessionSetup() error: %v", err)
	}

	if mgr.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 1 {
		t.Fatalf("expected 1 ReportSessionStarted call, got %d", len(reporter.startedCalls))
	}
	got := reporter.startedCalls[0]
	if got.SessionID != "sess-setup-1" {
		t.Errorf("ReportSessionStarted session_id = %q, want %q", got.SessionID, "sess-setup-1")
	}
	if got.TargetHost != host {
		t.Errorf("ReportSessionStarted target_host = %q, want %q", got.TargetHost, host)
	}
	if got.TargetPort != port {
		t.Errorf("ReportSessionStarted target_port = %d, want %d", got.TargetPort, port)
	}
}

func TestSSEHandler_SSHSessionSetup_MalformedPayload(t *testing.T) {
	mgr := newTestManager(t, Config{})
	reporter := &mockReporter{}

	handler := HandleSSHSessionSetup(mgr, reporter)

	envelope := api.SignedEnvelope{
		EventType: api.EventSSHSessionSetup,
		EventID:   "evt-bad",
		Payload:   json.RawMessage("not json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("expected error for malformed payload")
	}

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 0 {
		t.Errorf("expected 0 ReportSessionStarted calls, got %d", len(reporter.startedCalls))
	}
}

func TestSSEHandler_SessionRevoked(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	mgr := newTestManager(t, Config{})

	// Create a session first.
	setup := api.SSHSessionSetup{
		SessionID:  "sess-revoke-1",
		TargetHost: host,
		TargetPort: port,
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	_, err := mgr.CreateSession(context.Background(), setup)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount()=1, got %d", mgr.ActiveCount())
	}

	// Revoke it via handler. HandleSessionRevoked only closes the session; the
	// session_ended row is emitted by the manager's on-closed callback, so the
	// handler takes no reporter.
	handler := HandleSessionRevoked(mgr)

	payload := struct {
		SessionID string `json:"session_id"`
	}{SessionID: "sess-revoke-1"}
	envelope := testEnvelope(api.EventSessionRevoked, payload)

	err = handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("HandleSessionRevoked() error: %v", err)
	}

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0 after revocation, got %d", mgr.ActiveCount())
	}
}

func TestSSEHandler_SessionRevoked_UnknownSession(t *testing.T) {
	mgr := newTestManager(t, Config{})

	handler := HandleSessionRevoked(mgr)

	payload := struct {
		SessionID string `json:"session_id"`
	}{SessionID: "nonexistent"}
	envelope := testEnvelope(api.EventSessionRevoked, payload)

	err := handler(context.Background(), envelope)
	if err != nil {
		t.Fatalf("HandleSessionRevoked() for unknown session should not error, got: %v", err)
	}

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
}

func TestSSEHandler_SessionRevoked_MalformedPayload(t *testing.T) {
	mgr := newTestManager(t, Config{})

	handler := HandleSessionRevoked(mgr)

	envelope := api.SignedEnvelope{
		EventType: api.EventSessionRevoked,
		EventID:   "evt-bad-revoke",
		Payload:   json.RawMessage("not json"),
	}

	err := handler(context.Background(), envelope)
	if err == nil {
		t.Fatal("expected error for malformed payload")
	}
}

func TestTerminatedByFromReason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{"expired maps to ttl_expired", "expired", api.TerminatedByTTLExpired},
		{"revoked maps to operator_revoke", "revoked", api.TerminatedByOperatorRevoke},
		{"other maps to plexd_close", "shutdown", api.TerminatedByPlexdClose},
		{"empty maps to plexd_close", "", api.TerminatedByPlexdClose},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TerminatedByFromReason(tt.reason); got != tt.want {
				t.Errorf("TerminatedByFromReason(%q) = %q, want %q", tt.reason, got, tt.want)
			}
		})
	}
}
