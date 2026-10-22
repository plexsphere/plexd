package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockHeartbeatClient struct {
	mu        sync.Mutex
	calls     int
	requests  []api.HeartbeatRequest
	responses []*api.HeartbeatResponse
	errors    []error
}

func (m *mockHeartbeatClient) Heartbeat(_ context.Context, _ string, req api.HeartbeatRequest) (*api.HeartbeatResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := m.calls
	m.calls++
	m.requests = append(m.requests, req)

	var err error
	if idx < len(m.errors) && m.errors[idx] != nil {
		err = m.errors[idx]
	}
	if err != nil {
		return nil, err
	}

	if idx < len(m.responses) {
		return m.responses[idx], nil
	}
	return &api.HeartbeatResponse{}, nil
}

func (m *mockHeartbeatClient) getRequests() []api.HeartbeatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]api.HeartbeatRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *mockHeartbeatClient) getCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type mockReconcileTrigger struct {
	mu    sync.Mutex
	calls int
}

func (m *mockReconcileTrigger) TriggerReconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
}

func (m *mockReconcileTrigger) getCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// ---------------------------------------------------------------------------
// Config tests
// ---------------------------------------------------------------------------

func TestHeartbeatConfig_ApplyDefaults(t *testing.T) {
	cfg := HeartbeatConfig{NodeID: "node-1"}
	cfg.ApplyDefaults()

	if cfg.Interval != 30*time.Second {
		t.Errorf("Interval = %v, want %v", cfg.Interval, 30*time.Second)
	}

	// Existing value is preserved.
	cfg2 := HeartbeatConfig{NodeID: "node-1", Interval: 5 * time.Second}
	cfg2.ApplyDefaults()
	if cfg2.Interval != 5*time.Second {
		t.Errorf("Interval = %v, want %v", cfg2.Interval, 5*time.Second)
	}
}

func TestHeartbeatConfig_Validate(t *testing.T) {
	cfg := HeartbeatConfig{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty NodeID")
	}
	if err.Error() != "agent: heartbeat config: NodeID is required" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "agent: heartbeat config: NodeID is required")
	}

	cfg.NodeID = "node-1"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// Service tests
// ---------------------------------------------------------------------------

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHeartbeatService_SendsAtInterval(t *testing.T) {
	client := &mockHeartbeatClient{}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: 50 * time.Millisecond}
	svc := NewHeartbeatService(cfg, client, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	calls := client.getCalls()
	// Expect immediate heartbeat + at least 2 ticker heartbeats.
	if calls < 3 {
		t.Errorf("heartbeat calls = %d, want >= 3", calls)
	}
}

func TestHeartbeatService_ReconcileTrigger(t *testing.T) {
	client := &mockHeartbeatClient{
		responses: []*api.HeartbeatResponse{
			{Reconcile: true},
		},
	}

	rt := &mockReconcileTrigger{}
	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())
	svc.SetReconcileTrigger(rt)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}
}

func TestHeartbeatService_RotateKeys(t *testing.T) {
	client := &mockHeartbeatClient{
		responses: []*api.HeartbeatResponse{
			{RotateKeys: true},
		},
	}

	var mu sync.Mutex
	rotated := 0

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())
	svc.SetOnRotateKeys(func() {
		mu.Lock()
		rotated++
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	mu.Lock()
	got := rotated
	mu.Unlock()

	if got != 1 {
		t.Errorf("onRotateKeys calls = %d, want 1", got)
	}
}

func TestHeartbeatService_TransientError(t *testing.T) {
	client := &mockHeartbeatClient{
		errors: []error{
			&api.APIError{StatusCode: 500, Message: "internal server error"},
			nil,
			nil,
		},
	}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: 50 * time.Millisecond}
	svc := NewHeartbeatService(cfg, client, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	calls := client.getCalls()
	// Heartbeats must continue past the first error.
	if calls < 3 {
		t.Errorf("heartbeat calls = %d, want >= 3 (should survive transient error)", calls)
	}
}

func TestHeartbeatService_ContextCancellation(t *testing.T) {
	client := &mockHeartbeatClient{}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := svc.Run(ctx); err != nil {
			t.Errorf("Run() = %v, want nil", err)
		}
	}()

	// Give the immediate heartbeat time to fire.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK: Run exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	if calls := client.getCalls(); calls != 1 {
		t.Errorf("heartbeat calls = %d, want 1", calls)
	}
}

func TestHeartbeatService_BuildRequest(t *testing.T) {
	client := &mockHeartbeatClient{}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())
	svc.SetBuildRequest(func() api.HeartbeatRequest {
		return api.HeartbeatRequest{
			BinaryChecksum: "abc123",
			BinaryVersion:  "1.2.3",
			NATSummary:     map[string]any{},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	reqs := client.getRequests()
	if len(reqs) == 0 {
		t.Fatal("expected at least one heartbeat request")
	}
	if reqs[0].BinaryChecksum != "abc123" {
		t.Errorf("request BinaryChecksum = %q, want %q", reqs[0].BinaryChecksum, "abc123")
	}
	if reqs[0].BinaryVersion != "1.2.3" {
		t.Errorf("request BinaryVersion = %q, want %q", reqs[0].BinaryVersion, "1.2.3")
	}
}

// TestHeartbeatService_ClockSkew verifies that a clock_skew rejection logs an
// operator-facing error naming clock synchronization and does not trigger an
// immediate retry — the next attempt is the next interval tick.
func TestHeartbeatService_ClockSkew(t *testing.T) {
	client := &mockHeartbeatClient{
		errors: []error{
			&api.APIError{StatusCode: 400, Code: "clock_skew", Message: "client_now outside tolerance"},
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	// Exactly one send within the window — no immediate retry on skew.
	if calls := client.getCalls(); calls != 1 {
		t.Errorf("heartbeat calls = %d, want 1 (no immediate retry on clock skew)", calls)
	}

	logged := buf.String()
	if !strings.Contains(logged, "level=ERROR") {
		t.Errorf("expected ERROR-level log, got: %s", logged)
	}
	if !strings.Contains(logged, "clock skew") || !strings.Contains(logged, "synchronize") {
		t.Errorf("expected log naming clock skew and synchronization, got: %s", logged)
	}
}

// ---------------------------------------------------------------------------
// Credential refusal tests
// ---------------------------------------------------------------------------

const (
	heartbeatRefusedMsg      = "agent: heartbeat: credential refused"
	heartbeatParkedMsg       = "agent: heartbeat: node credential refused, the Node was removed from the control plane or its credential revoked; control-plane calls suspended"
	heartbeatProbeRefusedMsg = "agent: heartbeat: probe refused"
	heartbeatResumedMsg      = "agent: heartbeat: node credential accepted again, control-plane calls resumed"
	heartbeatClockSkewMsg    = "agent: heartbeat: rejected for clock skew, synchronize the system clock via NTP"
	heartbeatSendFailedMsg   = "agent: heartbeat: send failed"
)

// credentialCallback records every call of the credential-refused callback.
type credentialCallback struct {
	mu    sync.Mutex
	calls []bool
}

func (c *credentialCallback) record(refused bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, refused)
}

func (c *credentialCallback) get() []bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// refusal is a heartbeat refused with 401 and the given problem code.
func refusal(code string) error {
	return &api.APIError{StatusCode: 401, Code: code, Message: "node credential is not accepted"}
}

// newRefusalTestService builds a service whose heartbeats are answered, call
// by call, with errs (nil for an accepted heartbeat), with a recording
// credential-refused callback and a Debug logger.
func newRefusalTestService(interval time.Duration, errs ...error) (*HeartbeatService, *mockHeartbeatClient, *credentialCallback, *lockedBuffer) {
	client := &mockHeartbeatClient{errors: errs}
	logger, logs := newDebugLogger()
	svc := NewHeartbeatService(HeartbeatConfig{NodeID: "node-1", Interval: interval}, client, logger)
	cb := &credentialCallback{}
	svc.SetOnCredentialRefused(cb.record)
	return svc, client, cb, logs
}

// recordsAt returns the records in logs logged at one of levels, named as the
// text handler writes them (DEBUG, INFO, WARN, ERROR).
func recordsAt(logs string, levels ...string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		for _, level := range levels {
			if strings.Contains(line, " level="+level+" ") {
				out = append(out, line)
				break
			}
		}
	}
	return out
}

func TestHeartbeatService_WarnsBelowCredentialRefusedThreshold(t *testing.T) {
	svc, _, cb, logs := newRefusalTestService(30*time.Second, refusal("nsk_invalid"), refusal("nsk_invalid"))
	ctx := context.Background()

	svc.sendHeartbeat(ctx)
	svc.sendHeartbeat(ctx)

	if got := cb.get(); len(got) != 0 {
		t.Errorf("callback calls = %v after two refusals, want none", got)
	}
	if got := svc.nextDelay(); got != 30*time.Second {
		t.Errorf("nextDelay() = %v after two refusals, want the 30s interval", got)
	}
	got := logs.String()
	warns := recordsAt(got, "WARN")
	if len(warns) != 2 {
		t.Fatalf("Warn records = %d, want 2; logs:\n%s", len(warns), got)
	}
	for i, line := range warns {
		for _, want := range []string{`msg="` + heartbeatRefusedMsg + `"`, fmt.Sprintf("consecutive=%d", i+1), "threshold=3", "error="} {
			if !strings.Contains(line, want) {
				t.Errorf("Warn record %d = %q, want it to contain %q", i+1, line, want)
			}
		}
	}
	if errs := recordsAt(got, "ERROR"); len(errs) != 0 {
		t.Errorf("Error records = %q below the threshold, want none", errs)
	}
}

func TestHeartbeatService_ParksAtCredentialRefusedThreshold(t *testing.T) {
	svc, _, cb, logs := newRefusalTestService(30*time.Second,
		refusal("unauthorized"),
		refusal("unauthorized"),
		&api.APIError{StatusCode: 401, Code: "nsk_invalid"},
	)
	ctx := context.Background()

	for range CredentialRefusedThreshold {
		svc.sendHeartbeat(ctx)
	}

	if got := cb.get(); !slices.Equal(got, []bool{true}) {
		t.Errorf("callback calls = %v, want [true]", got)
	}
	if got := svc.nextDelay(); got != time.Minute {
		t.Errorf("nextDelay() = %v after parking, want 1m (twice the interval)", got)
	}
	got := logs.String()
	if errs := recordsAt(got, "ERROR"); len(errs) != 1 {
		t.Fatalf("Error records = %d, want 1; logs:\n%s", len(errs), got)
	}
	line := logLine(t, got, heartbeatParkedMsg)
	for _, want := range []string{
		"level=ERROR",
		"node_id=node-1",
		"code=nsk_invalid",
		"consecutive=3",
		"next_probe=1m0s",
		`enrol_again="run 'plexd deregister', provide a fresh bootstrap token, and restart plexd"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("park record = %q, want it to contain %q", line, want)
		}
	}
}

func TestHeartbeatService_ProbeDelayDoublesUpToCap(t *testing.T) {
	t.Run("from twice the interval", func(t *testing.T) {
		errs := slices.Repeat([]error{refusal("nsk_invalid")}, CredentialRefusedThreshold+7)
		svc, _, cb, logs := newRefusalTestService(30*time.Second, errs...)
		ctx := context.Background()

		for range CredentialRefusedThreshold {
			svc.sendHeartbeat(ctx)
		}
		parked := len(logs.String())

		for i, want := range []time.Duration{
			2 * time.Minute,
			4 * time.Minute,
			8 * time.Minute,
			16 * time.Minute,
			32 * time.Minute,
			time.Hour,
			time.Hour,
		} {
			svc.sendHeartbeat(ctx)
			if got := svc.nextDelay(); got != want {
				t.Errorf("nextDelay() after refused probe %d = %v, want %v", i+1, got, want)
			}
		}

		if got := cb.get(); !slices.Equal(got, []bool{true}) {
			t.Errorf("callback calls = %v, want only the park's [true]", got)
		}
		probes := logs.String()[parked:]
		if above := recordsAt(probes, "INFO", "WARN", "ERROR"); len(above) != 0 {
			t.Errorf("records above Debug while probing = %q, want none", above)
		}
		if n := countLogLines(probes, heartbeatProbeRefusedMsg); n != 7 {
			t.Errorf("probe refused records = %d, want 7", n)
		}
	})

	t.Run("first probe capped", func(t *testing.T) {
		errs := slices.Repeat([]error{refusal("nsk_invalid")}, CredentialRefusedThreshold)
		svc, _, _, _ := newRefusalTestService(40*time.Minute, errs...)

		for range CredentialRefusedThreshold {
			svc.sendHeartbeat(context.Background())
		}

		if got := svc.nextDelay(); got != MaxCredentialProbeInterval {
			t.Errorf("nextDelay() after parking with a 40m interval = %v, want %v", got, MaxCredentialProbeInterval)
		}
	})
}

func TestHeartbeatService_ResumesOnAcceptedProbe(t *testing.T) {
	svc, _, cb, logs := newRefusalTestService(30*time.Second,
		refusal("nsk_invalid"),
		refusal("nsk_invalid"),
		refusal("nsk_invalid"),
		refusal("nsk_invalid"), // a refused probe
		nil,                    // the accepted probe
		refusal("nsk_invalid"),
		refusal("nsk_invalid"),
	)
	ctx := context.Background()

	for range CredentialRefusedThreshold + 2 {
		svc.sendHeartbeat(ctx)
	}

	if got := cb.get(); !slices.Equal(got, []bool{true, false}) {
		t.Errorf("callback calls = %v, want [true false]", got)
	}
	if got := svc.nextDelay(); got != 30*time.Second {
		t.Errorf("nextDelay() after the accepted probe = %v, want the 30s interval", got)
	}
	line := logLine(t, logs.String(), heartbeatResumedMsg)
	if !strings.Contains(line, "level=INFO") {
		t.Errorf("resume record = %q, want level=INFO", line)
	}

	// The count starts over: two more refusals are below the threshold again.
	svc.sendHeartbeat(ctx)
	svc.sendHeartbeat(ctx)

	if got := cb.get(); !slices.Equal(got, []bool{true, false}) {
		t.Errorf("callback calls = %v after two refusals past the resume, want no new call", got)
	}
	if got := svc.nextDelay(); got != 30*time.Second {
		t.Errorf("nextDelay() = %v after two refusals past the resume, want the 30s interval", got)
	}
	got := logs.String()
	if n := countLogLines(got, heartbeatParkedMsg); n != 1 {
		t.Errorf("park records = %d, want 1", n)
	}
	if n := countLogLines(got, heartbeatResumedMsg); n != 1 {
		t.Errorf("resume records = %d, want 1", n)
	}
	if warns := recordsAt(got, "WARN"); len(warns) != 4 || !strings.Contains(warns[3], "consecutive=2") {
		t.Errorf("Warn records = %q, want four, the last with consecutive=2", warns)
	}
}

func TestHeartbeatService_AcceptedHeartbeatResetsRefusals(t *testing.T) {
	svc, _, cb, logs := newRefusalTestService(30*time.Second,
		refusal("nsk_invalid"),
		refusal("nsk_invalid"),
		nil,
		refusal("nsk_invalid"),
		refusal("nsk_invalid"),
	)
	ctx := context.Background()

	for range 5 {
		svc.sendHeartbeat(ctx)
	}

	if got := cb.get(); len(got) != 0 {
		t.Errorf("callback calls = %v, want none: the accepted heartbeat reset the count", got)
	}
	if got := svc.nextDelay(); got != 30*time.Second {
		t.Errorf("nextDelay() = %v, want the 30s interval", got)
	}
	if n := countLogLines(logs.String(), heartbeatParkedMsg); n != 0 {
		t.Errorf("park records = %d, want 0", n)
	}
}

func TestHeartbeatService_OtherFailuresKeepRefusalCount(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "transport error", err: errors.New("dial tcp: connection refused")},
		{name: "500", err: &api.APIError{StatusCode: 500}},
		{name: "400 clock_skew", err: &api.APIError{StatusCode: 400, Code: "clock_skew"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, cb, logs := newRefusalTestService(30*time.Second,
				refusal("nsk_invalid"),
				refusal("nsk_invalid"),
				tt.err,
				refusal("nsk_invalid"),
			)
			ctx := context.Background()

			for range 3 {
				svc.sendHeartbeat(ctx)
			}
			if got := cb.get(); len(got) != 0 {
				t.Errorf("callback calls = %v after two refusals and a failure, want none", got)
			}

			svc.sendHeartbeat(ctx)

			if got := cb.get(); !slices.Equal(got, []bool{true}) {
				t.Errorf("callback calls = %v on the third refusal, want [true]: the failure must not reset the count", got)
			}
			if got := svc.nextDelay(); got != time.Minute {
				t.Errorf("nextDelay() = %v, want 1m after parking", got)
			}
			if line := logLine(t, logs.String(), heartbeatParkedMsg); !strings.Contains(line, "consecutive=3") {
				t.Errorf("park record = %q, want consecutive=3", line)
			}
		})
	}
}

func TestHeartbeatService_ParksOnRefusalWithoutCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "no code", err: &api.APIError{StatusCode: 401}},
		{name: "wrapped", err: fmt.Errorf("heartbeat: %w", &api.APIError{StatusCode: 401})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := slices.Repeat([]error{tt.err}, CredentialRefusedThreshold)
			svc, _, cb, logs := newRefusalTestService(30*time.Second, errs...)

			for range CredentialRefusedThreshold {
				svc.sendHeartbeat(context.Background())
			}

			if got := cb.get(); !slices.Equal(got, []bool{true}) {
				t.Errorf("callback calls = %v, want [true]", got)
			}
			if line := logLine(t, logs.String(), heartbeatParkedMsg); !strings.Contains(line, `code=""`) {
				t.Errorf("park record = %q, want code=\"\"", line)
			}
		})
	}
}

func TestHeartbeatService_ParksWithoutCallback(t *testing.T) {
	client := &mockHeartbeatClient{errors: []error{
		refusal("nsk_invalid"),
		refusal("nsk_invalid"),
		refusal("nsk_invalid"),
		nil,
	}}
	svc := NewHeartbeatService(HeartbeatConfig{NodeID: "node-1", Interval: 30 * time.Second}, client, testLogger())
	ctx := context.Background()

	for range CredentialRefusedThreshold {
		svc.sendHeartbeat(ctx)
	}
	if got := svc.nextDelay(); got != time.Minute {
		t.Errorf("nextDelay() = %v after parking, want 1m", got)
	}

	svc.sendHeartbeat(ctx)
	if got := svc.nextDelay(); got != 30*time.Second {
		t.Errorf("nextDelay() = %v after the accepted probe, want the 30s interval", got)
	}
}

func TestHeartbeatService_OtherFailuresWhileParkedBackOff(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{name: "400 clock_skew", err: &api.APIError{StatusCode: 400, Code: "clock_skew"}, wantMsg: heartbeatClockSkewMsg},
		{name: "transport error", err: errors.New("dial tcp: connection refused"), wantMsg: heartbeatSendFailedMsg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, cb, logs := newRefusalTestService(30*time.Second,
				refusal("nsk_invalid"),
				refusal("nsk_invalid"),
				refusal("nsk_invalid"),
				tt.err,
			)
			ctx := context.Background()

			for range CredentialRefusedThreshold + 1 {
				svc.sendHeartbeat(ctx)
			}

			if got := svc.nextDelay(); got != 2*time.Minute {
				t.Errorf("nextDelay() = %v after a failed probe, want 2m (doubled)", got)
			}
			if got := cb.get(); !slices.Equal(got, []bool{true}) {
				t.Errorf("callback calls = %v, want only the park's [true]", got)
			}
			line := logLine(t, logs.String(), tt.wantMsg)
			for _, want := range []string{"level=ERROR", "error="} {
				if !strings.Contains(line, want) {
					t.Errorf("failure record = %q, want it to contain %q", line, want)
				}
			}
		})
	}
}

// TestHeartbeatService_RunBacksOffWhileParked runs the real loop against a
// control plane that refuses every heartbeat: after the park the delays grow
// from 20ms, so the window holds about six sends where the old fixed ticker
// sent about thirty.
func TestHeartbeatService_RunBacksOffWhileParked(t *testing.T) {
	errs := slices.Repeat([]error{refusal("nsk_invalid")}, 100)
	svc, client, cb, _ := newRefusalTestService(10*time.Millisecond, errs...)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}

	if calls := client.getCalls(); calls > 8 {
		t.Errorf("heartbeat calls = %d within 300ms, want at most 8 once parked", calls)
	}
	if got := cb.get(); !slices.Equal(got, []bool{true}) {
		t.Errorf("callback calls = %v, want [true]", got)
	}
}

func TestHeartbeatService_ContextCancellationWhileParked(t *testing.T) {
	errs := slices.Repeat([]error{refusal("nsk_invalid")}, CredentialRefusedThreshold+1)
	svc, client, cb, _ := newRefusalTestService(time.Hour, errs...)

	for range CredentialRefusedThreshold {
		svc.sendHeartbeat(context.Background())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := svc.Run(ctx); err != nil {
			t.Errorf("Run() = %v, want nil", err)
		}
	}()

	select {
	case <-done:
		// OK: Run exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on a done context while parked")
	}

	// Run still sends its immediate heartbeat, which is a probe here.
	if calls := client.getCalls(); calls != CredentialRefusedThreshold+1 {
		t.Errorf("heartbeat calls = %d, want %d", calls, CredentialRefusedThreshold+1)
	}
	if got := cb.get(); !slices.Equal(got, []bool{true}) {
		t.Errorf("callback calls = %v, want [true]: still parked", got)
	}
}
