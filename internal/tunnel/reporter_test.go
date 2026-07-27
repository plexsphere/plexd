package tunnel

import (
	"context"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReporter records calls to ReportSessionStarted and ReportSessionEnded.
// startedErr, when set, is returned from every ReportSessionStarted so a test
// can drive the undelivered-row path.
type mockReporter struct {
	mu           sync.Mutex
	startedCalls []sessionStartedCall
	endedCalls   []sessionEndedCall
	startedErr   error
}

type sessionStartedCall struct {
	SessionID        string
	TargetHost       string
	TargetPort       int
	ListenerEndpoint string
}

type sessionEndedCall struct {
	SessionID    string
	TargetHost   string
	TargetPort   int
	BytesIn      int64
	BytesOut     int64
	TerminatedBy string
}

func (r *mockReporter) ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int, listenerEndpoint string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startedCalls = append(r.startedCalls, sessionStartedCall{
		SessionID:        sessionID,
		TargetHost:       targetHost,
		TargetPort:       targetPort,
		ListenerEndpoint: listenerEndpoint,
	})
	return r.startedErr
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

func TestTerminatedByFromReason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{"expired maps to ttl_expired", reasonExpired, api.TerminatedByTTLExpired},
		{"idle maps to idle_timeout", reasonIdle, api.TerminatedByIdleTimeout},
		{"drained maps to plexd_close", reasonDrained, api.TerminatedByPlexdClose},
		{"shutdown maps to plexd_close", reasonShutdown, api.TerminatedByPlexdClose},
		{"empty maps to plexd_close", "", api.TerminatedByPlexdClose},
		// The node never asserts an operator action: a drained entry is
		// indistinguishable from a block the control plane failed to serve.
		{"revoked is not a reason the node produces", "revoked", api.TerminatedByPlexdClose},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TerminatedByFromReason(tt.reason); got != tt.want {
				t.Errorf("TerminatedByFromReason(%q) = %q, want %q", tt.reason, got, tt.want)
			}
		})
	}
}
