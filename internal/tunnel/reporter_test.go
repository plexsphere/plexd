package tunnel

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReporter records calls to ReportSessionStarted and ReportSessionEnded,
// and the ssh command rows. startedErr, when set, is returned from every
// ReportSessionStarted so a test can drive the undelivered-row path;
// commandStartedErr and commandExitedErr do the same for the command rows.
type mockReporter struct {
	mu                sync.Mutex
	startedCalls      []sessionStartedCall
	endedCalls        []sessionEndedCall
	commandCalls      []commandCall
	startedErr        error
	commandStartedErr error
	commandExitedErr  error
}

// commandCall is one ssh command row: a started row, or an exited row with its
// exit code and completion time.
type commandCall struct {
	SessionID   string
	Command     string
	Exited      bool
	ExitCode    int
	StartedAt   time.Time
	CompletedAt time.Time
}

// sessionStartedCall is one started row. User is set for an ssh entry, the
// target for a tcp one.
type sessionStartedCall struct {
	SessionID        string
	Kind             string
	User             string
	TargetHost       string
	TargetPort       int
	ListenerEndpoint string
}

type sessionEndedCall struct {
	SessionID    string
	Kind         string
	TargetHost   string
	TargetPort   int
	BytesIn      int64
	BytesOut     int64
	TerminatedBy string
}

func (r *mockReporter) ReportSessionStarted(ctx context.Context, entry api.NodeStateSession, listenerEndpoint string) error {
	call := sessionStartedCall{
		SessionID:        entry.SessionID,
		Kind:             entry.Kind,
		ListenerEndpoint: listenerEndpoint,
	}
	if entry.Target.TCP != nil {
		call.TargetHost, call.TargetPort = entry.Target.TCP.Host, entry.Target.TCP.Port
	}
	if entry.Target.SSH != nil {
		call.User = entry.Target.SSH.User
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startedCalls = append(r.startedCalls, call)
	return r.startedErr
}

func (r *mockReporter) ReportSessionEnded(ctx context.Context, sessionID string, info *ClosedSessionInfo, terminatedBy string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endedCalls = append(r.endedCalls, sessionEndedCall{
		SessionID:    sessionID,
		Kind:         info.Kind,
		TargetHost:   info.TargetHost,
		TargetPort:   info.TargetPort,
		BytesIn:      info.BytesIn,
		BytesOut:     info.BytesOut,
		TerminatedBy: terminatedBy,
	})
}

func (r *mockReporter) ReportSSHCommandStarted(_ context.Context, sessionID, command string, startedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commandCalls = append(r.commandCalls, commandCall{SessionID: sessionID, Command: command, StartedAt: startedAt})
	return r.commandStartedErr
}

func (r *mockReporter) ReportSSHCommandExited(ctx context.Context, sessionID, command string, exitCode int, startedAt, completedAt time.Time) error {
	// Like a real post, one on a cancelled context delivers nothing.
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commandCalls = append(r.commandCalls, commandCall{
		SessionID:   sessionID,
		Command:     command,
		Exited:      true,
		ExitCode:    exitCode,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
	})
	return r.commandExitedErr
}

// fakeLauncher is a SessionLauncher that records every request and runs an
// optional hook instead of a process. Like the real one it closes the files it
// was handed before it returns.
type fakeLauncher struct {
	mu    sync.Mutex
	calls []launchCall
	run   func(ctx context.Context, req LaunchRequest, files []*os.File) (int, error)
}

type launchCall struct {
	req   LaunchRequest
	files int
}

func (l *fakeLauncher) Launch(ctx context.Context, req LaunchRequest, files []*os.File) (int, error) {
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	l.mu.Lock()
	l.calls = append(l.calls, launchCall{req: req, files: len(files)})
	run := l.run
	l.mu.Unlock()
	if run == nil {
		return 0, nil
	}
	return run(ctx, req, files)
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
