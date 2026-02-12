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

// mockReporter records calls to ReportReady and ReportClosed.
type mockReporter struct {
	mu          sync.Mutex
	readyCalls  []tunnelReadyCall
	closedCalls []tunnelClosedCall
}

type tunnelReadyCall struct {
	SessionID  string
	ListenAddr string
}

type tunnelClosedCall struct {
	SessionID string
	Reason    string
}

func (r *mockReporter) ReportReady(ctx context.Context, sessionID, listenAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readyCalls = append(r.readyCalls, tunnelReadyCall{SessionID: sessionID, ListenAddr: listenAddr})
}

func (r *mockReporter) ReportClosed(ctx context.Context, sessionID, reason string, duration time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closedCalls = append(r.closedCalls, tunnelClosedCall{SessionID: sessionID, Reason: reason})
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
	if len(reporter.readyCalls) != 1 {
		t.Fatalf("expected 1 ReportReady call, got %d", len(reporter.readyCalls))
	}
	if reporter.readyCalls[0].SessionID != "sess-setup-1" {
		t.Errorf("ReportReady session_id = %q, want %q", reporter.readyCalls[0].SessionID, "sess-setup-1")
	}
	if reporter.readyCalls[0].ListenAddr == "" {
		t.Error("ReportReady listen_addr is empty")
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
	if len(reporter.readyCalls) != 0 {
		t.Errorf("expected 0 ReportReady calls, got %d", len(reporter.readyCalls))
	}
}

func TestSSEHandler_SessionRevoked(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustAtoi(t, portStr)

	mgr := newTestManager(t, Config{})
	reporter := &mockReporter{}

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

	// Revoke it via handler.
	handler := HandleSessionRevoked(mgr, reporter)

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

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.closedCalls) != 1 {
		t.Fatalf("expected 1 ReportClosed call, got %d", len(reporter.closedCalls))
	}
	if reporter.closedCalls[0].SessionID != "sess-revoke-1" {
		t.Errorf("ReportClosed session_id = %q, want %q", reporter.closedCalls[0].SessionID, "sess-revoke-1")
	}
	if reporter.closedCalls[0].Reason != "revoked" {
		t.Errorf("ReportClosed reason = %q, want %q", reporter.closedCalls[0].Reason, "revoked")
	}
}

func TestSSEHandler_SessionRevoked_UnknownSession(t *testing.T) {
	mgr := newTestManager(t, Config{})
	reporter := &mockReporter{}

	handler := HandleSessionRevoked(mgr, reporter)

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

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.closedCalls) != 0 {
		t.Errorf("expected 0 ReportClosed calls for unknown session, got %d", len(reporter.closedCalls))
	}
}

func TestSSEHandler_SessionRevoked_MalformedPayload(t *testing.T) {
	mgr := newTestManager(t, Config{})
	reporter := &mockReporter{}

	handler := HandleSessionRevoked(mgr, reporter)

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
