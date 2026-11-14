package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/plexsphere/plexd/internal/api"
)

// fakePlexdHookRunner is a PlexdHookRunner that records its calls and answers
// with what the test scripted. The script is set before the first dispatch and
// never changed afterwards, so only the recorded calls need the lock.
type fakePlexdHookRunner struct {
	// startErr is what Start returns. With startBlocks set, Start instead
	// waits for its context to end and returns the context's error.
	startErr    error
	startBlocks bool
	// result and waitErr are what Wait returns. With waitBlocks set, Wait
	// instead waits for its context to end and returns the context's error.
	result     PlexdHookResult
	waitErr    error
	waitBlocks bool
	// stopOutput and stopErr are what Stop returns.
	stopOutput string
	stopErr    error

	// startEntered and waitEntered receive one signal per call, so a test can
	// act on a run that is inside Start or Wait.
	startEntered chan struct{}
	waitEntered  chan struct{}

	mu     sync.Mutex
	starts []PlexdHookRun
	waits  []fakePlexdHookWait
	stops  []fakePlexdHookStop
}

// fakePlexdHookWait records one Wait call.
type fakePlexdHookWait struct {
	executionID string
	bound       time.Duration
}

// fakePlexdHookStop records one Stop call and the context it got.
type fakePlexdHookStop struct {
	executionID string
	// ctxErr is the error of Stop's context when Stop was called.
	ctxErr error
	// budget is what was left of Stop's context deadline, 0 for none.
	budget time.Duration
}

func newFakePlexdHookRunner() *fakePlexdHookRunner {
	return &fakePlexdHookRunner{
		startEntered: make(chan struct{}, 4),
		waitEntered:  make(chan struct{}, 4),
	}
}

func (f *fakePlexdHookRunner) Start(ctx context.Context, run PlexdHookRun) error {
	f.mu.Lock()
	f.starts = append(f.starts, run)
	f.mu.Unlock()
	f.startEntered <- struct{}{}
	if f.startBlocks {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.startErr
}

func (f *fakePlexdHookRunner) Wait(ctx context.Context, executionID string, bound time.Duration) (PlexdHookResult, error) {
	f.mu.Lock()
	f.waits = append(f.waits, fakePlexdHookWait{executionID: executionID, bound: bound})
	f.mu.Unlock()
	f.waitEntered <- struct{}{}
	if f.waitBlocks {
		<-ctx.Done()
		return PlexdHookResult{}, ctx.Err()
	}
	return f.result, f.waitErr
}

func (f *fakePlexdHookRunner) Stop(ctx context.Context, executionID string) (string, error) {
	call := fakePlexdHookStop{executionID: executionID, ctxErr: ctx.Err()}
	if deadline, ok := ctx.Deadline(); ok {
		call.budget = time.Until(deadline)
	}
	f.mu.Lock()
	f.stops = append(f.stops, call)
	f.mu.Unlock()
	return f.stopOutput, f.stopErr
}

// calls returns copies of the recorded calls.
func (f *fakePlexdHookRunner) calls() ([]PlexdHookRun, []fakePlexdHookWait, []fakePlexdHookStop) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.starts), slices.Clone(f.waits), slices.Clone(f.stops)
}

// wantNoRunnerCalls fails the test unless the runner was never called.
func (f *fakePlexdHookRunner) wantNoRunnerCalls(t *testing.T) {
	t.Helper()
	starts, waits, stops := f.calls()
	if len(starts)+len(waits)+len(stops) != 0 {
		t.Errorf("runner calls: %d Start, %d Wait, %d Stop, want none", len(starts), len(waits), len(stops))
	}
}

// plexdHookLogs records the log records an executor writes, with the
// attributes of each, so a test can assert on a line's level and fields.
type plexdHookLogs struct {
	mu      sync.Mutex
	records []plexdHookLogRecord
}

type plexdHookLogRecord struct {
	level slog.Level
	attrs map[string]any
}

// lines returns the records logged with msg.
func (l *plexdHookLogs) lines(msg string) []plexdHookLogRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []plexdHookLogRecord
	for _, r := range l.records {
		if r.attrs["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// plexdHookLogHandler is the slog.Handler writing into plexdHookLogs.
type plexdHookLogHandler struct {
	logs  *plexdHookLogs
	attrs []slog.Attr
}

func (h plexdHookLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h plexdHookLogHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]any{"msg": r.Message}
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.Resolve().Any()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Resolve().Any()
		return true
	})
	h.logs.mu.Lock()
	defer h.logs.mu.Unlock()
	h.logs.records = append(h.logs.records, plexdHookLogRecord{level: r.Level, attrs: attrs})
	return nil
}

func (h plexdHookLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return plexdHookLogHandler{logs: h.logs, attrs: append(slices.Clone(h.attrs), attrs...)}
}

func (h plexdHookLogHandler) WithGroup(string) slog.Handler { return h }

// newPlexdHookExecutor returns an executor whose plexd_hook entries run
// through runner, unless runner is nil, and whose log lines land in the
// returned recorder. The test's cleanup shuts the executor down, so a run a
// failing test left inside the runner does not outlive it.
func newPlexdHookExecutor(t *testing.T, cfg Config, reporter *mockReporter, runner *fakePlexdHookRunner) (*Executor, *plexdHookLogs) {
	t.Helper()
	exec := newTestExecutor(cfg, reporter, &mockVerifier{ok: true})
	logs := &plexdHookLogs{}
	exec.logger = slog.New(plexdHookLogHandler{logs: logs})
	if runner != nil {
		exec.SetPlexdHookRunner(runner)
	}
	t.Cleanup(func() { exec.Shutdown(context.Background()) })
	return exec, logs
}

// pendingPlexdHookExec is pendingExec for a plexd_hook entry.
func pendingPlexdHookExec(executionID, hook string) api.NodeStateExecution {
	entry := pendingExec(executionID, hook)
	entry.Type = api.ActionKindPlexdHook
	return entry
}

// startedPlexdHookExec is the plexd_hook entry an earlier agent process
// claimed: the control plane serves it at started.
func startedPlexdHookExec(executionID, hook string) api.NodeStateExecution {
	entry := pendingPlexdHookExec(executionID, hook)
	entry.Status = api.ExecutionStatusStarted
	return entry
}

// dispatchPlexdHook dispatches entry, waits until its run has left the
// executor, and returns every callback the reporter recorded.
func dispatchPlexdHook(t *testing.T, exec *Executor, reporter *mockReporter, entry api.NodeStateExecution) []api.ExecutionCallbackRequest {
	t.Helper()
	mustExecute(t, exec, "node-1", entry)
	waitFor(t, 5*time.Second, func() bool { return exec.ActiveCount() == 0 })
	return reporter.getCallbacks()
}

// wantPlexdHookTerminal fails the test unless the callbacks walk ack, started
// and status, and the terminal carries exitCode, nil meaning no exit_code key,
// and errMsg.
func wantPlexdHookTerminal(t *testing.T, cbs []api.ExecutionCallbackRequest, status string, exitCode *int, errMsg string) api.ExecutionCallbackRequest {
	t.Helper()
	assertStatuses(t, cbs, []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, status})
	terminal := cbs[len(cbs)-1]
	wantExitCode(t, terminal, exitCode)
	if terminal.Error != errMsg {
		t.Errorf("terminal error = %q, want %q", terminal.Error, errMsg)
	}
	return terminal
}

// wantExitCode fails the test unless the callback carries want as exit_code,
// nil meaning the key is omitted.
func wantExitCode(t *testing.T, cb api.ExecutionCallbackRequest, want *int) {
	t.Helper()
	switch {
	case want == nil && cb.ExitCode != nil:
		t.Errorf("exit_code = %d, want the key omitted", *cb.ExitCode)
	case want != nil && cb.ExitCode == nil:
		t.Errorf("exit_code omitted, want %d", *want)
	case want != nil && *cb.ExitCode != *want:
		t.Errorf("exit_code = %d, want %d", *cb.ExitCode, *want)
	}
}

func intPtr(v int) *int { return &v }

func TestPlexdHook_SucceededReportsExitCodeAndLog(t *testing.T) {
	runner := newFakePlexdHookRunner()
	runner.result = PlexdHookResult{Succeeded: true, ExitCode: intPtr(0), Output: "target=/srv/override\n"}
	reporter := &mockReporter{}
	exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

	cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-ok", "e2e-pinned"))

	terminal := wantPlexdHookTerminal(t, cbs, api.ExecutionStatusSucceeded, intPtr(0), "")
	if got := decodeInline(t, terminal.Output); got != "target=/srv/override\n" {
		t.Errorf("inline output = %q, want the pod's log", got)
	}

	starts, waits, stops := runner.calls()
	if len(starts) != 1 || starts[0].ExecutionID != "exec-hook-ok" || starts[0].Hook != "e2e-pinned" {
		t.Fatalf("Start calls = %+v, want one for exec-hook-ok and e2e-pinned", starts)
	}
	if len(waits) != 1 || waits[0].executionID != "exec-hook-ok" {
		t.Fatalf("Wait calls = %+v, want one for exec-hook-ok", waits)
	}
	if waits[0].bound != starts[0].Deadline {
		t.Errorf("Wait bound = %v, want the Deadline Start got, %v", waits[0].bound, starts[0].Deadline)
	}
	if len(stops) != 0 {
		t.Errorf("Stop calls = %+v, want none", stops)
	}
}

func TestPlexdHook_ExitCodeOfTheHookContainer(t *testing.T) {
	for _, tc := range []struct {
		name         string
		result       PlexdHookResult
		wantStatus   string
		wantExitCode int
	}{
		{
			name:         "container exits 3",
			result:       PlexdHookResult{ExitCode: intPtr(3), Output: "boom\n"},
			wantStatus:   api.ExecutionStatusFailed,
			wantExitCode: 3,
		},
		{
			name:         "completed job without an exit code",
			result:       PlexdHookResult{Succeeded: true, Output: "done\n"},
			wantStatus:   api.ExecutionStatusSucceeded,
			wantExitCode: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := newFakePlexdHookRunner()
			runner.result = tc.result
			reporter := &mockReporter{}
			exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

			cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-exit", "e2e-fail"))

			terminal := wantPlexdHookTerminal(t, cbs, tc.wantStatus, intPtr(tc.wantExitCode), "")
			if got := decodeInline(t, terminal.Output); got != tc.result.Output {
				t.Errorf("inline output = %q, want %q", got, tc.result.Output)
			}
		})
	}
}

// A run that failed without an exit code carries its cause as the error, and
// a Wait error with a live context carries its text, both cut like every
// error of this path.
func TestPlexdHook_FailureWithoutExitCodeCarriesItsCause(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  PlexdHookResult
		waitErr error
		want    string
	}{
		{
			name:   "job failed without a pod",
			result: PlexdHookResult{Reason: "plexd hook job failed: BackoffLimitExceeded: Job has reached the specified backoff limit"},
			want:   "plexd hook job failed: BackoffLimitExceeded: Job has reached the specified backoff limit",
		},
		{
			name:    "wait error",
			waitErr: errors.New("get job: kubernetes: unauthorized"),
			want:    "get job: kubernetes: unauthorized",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := newFakePlexdHookRunner()
			runner.result = tc.result
			runner.waitErr = tc.waitErr
			reporter := &mockReporter{}
			exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

			cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-cause", "e2e-fail"))

			wantPlexdHookTerminal(t, cbs, api.ExecutionStatusFailed, nil, tc.want)
		})
	}
}

// Without a runner, outside a cluster, a plexd_hook entry is a type this node
// cannot run, which is what unsupported_action_type says.
func TestPlexdHook_WithoutRunnerUnsupportedActionType(t *testing.T) {
	reporter := &mockReporter{}
	exec, _ := newPlexdHookExecutor(t, Config{}, reporter, nil)

	cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-no-runner", "e2e-pinned"))

	wantPlexdHookTerminal(t, cbs, api.ExecutionStatusFailed, nil, "unsupported_action_type")
}

func TestPlexdHook_UnknownHookIsUnknownAction(t *testing.T) {
	runner := newFakePlexdHookRunner()
	runner.startErr = fmt.Errorf("plexd hook %q: %w", "e2e-missing", ErrPlexdHookNotFound)
	reporter := &mockReporter{}
	exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

	cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-missing", "e2e-missing"))

	terminal := wantPlexdHookTerminal(t, cbs, api.ExecutionStatusFailed, nil, "unknown_action")
	if terminal.Output != nil {
		t.Errorf("terminal output = %+v, want none", terminal.Output)
	}
	if _, waits, _ := runner.calls(); len(waits) != 0 {
		t.Errorf("Wait calls = %+v, want none for a hook that does not exist", waits)
	}
}

// The disabled gate sits ahead of the type switch, so a plexd_hook entry is
// rejected like every other kind and the runner is never asked.
func TestPlexdHook_ActionsDisabledNeverCallsRunner(t *testing.T) {
	runner := newFakePlexdHookRunner()
	reporter := &mockReporter{}
	exec, _ := newPlexdHookExecutor(t, Config{Enabled: boolPtr(false)}, reporter, runner)
	d := NewDispatcher(exec, "node-1", testLogger())

	d.Handle(context.Background(), snapshot(pendingPlexdHookExec("exec-hook-disabled", "e2e-pinned")))

	wantPlexdHookTerminal(t, reporter.getCallbacks(), api.ExecutionStatusFailed, nil, "actions_disabled")
	runner.wantNoRunnerCalls(t)
}

func TestPlexdHook_StartErrorCarriedAndCut(t *testing.T) {
	t.Run("carried", func(t *testing.T) {
		runner := newFakePlexdHookRunner()
		runner.startErr = errors.New("create job: kubernetes: unauthorized")
		reporter := &mockReporter{}
		exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

		cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-start-err", "e2e-pinned"))

		wantPlexdHookTerminal(t, cbs, api.ExecutionStatusFailed, nil, "create job: kubernetes: unauthorized")
		if _, waits, _ := runner.calls(); len(waits) != 0 {
			t.Errorf("Wait calls = %+v, want none after a failed Start", waits)
		}
	})

	t.Run("cut on a rune boundary", func(t *testing.T) {
		// Three-byte runes from the first byte on: a cut at 1024 bytes lands
		// inside one, which the precondition below proves.
		long := strings.Repeat("€", 1666) + "ab"
		if len(long) != 5000 {
			t.Fatalf("test message is %d bytes, want 5000", len(long))
		}
		if utf8.ValidString(long[:maxPlexdHookErrorBytes]) {
			t.Fatal("a byte cut of the test message is valid UTF-8, so it proves nothing")
		}

		runner := newFakePlexdHookRunner()
		runner.startErr = errors.New(long)
		reporter := &mockReporter{}
		exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

		cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-start-long", "e2e-pinned"))

		assertStatuses(t, cbs, []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed})
		got := cbs[2].Error
		if len(got) > 1024 {
			t.Errorf("error is %d bytes, want at most 1024", len(got))
		}
		if len(got) < 1024-utf8.UTFMax {
			t.Errorf("error is %d bytes, want it cut no shorter than the rune boundary below 1024", len(got))
		}
		if !utf8.ValidString(got) {
			t.Error("error is not valid UTF-8")
		}
		if !strings.HasPrefix(long, got) {
			t.Error("error is not a prefix of the Start error's text")
		}
		wantExitCode(t, cbs[2], nil)
	})
}

func TestPlexdHook_TimedOutNamesItsLimit(t *testing.T) {
	const ceiling = DefaultMaxActionTimeout
	for _, tc := range []struct {
		name       string
		expiresIn  time.Duration
		reason     string
		want       string
		wantCapped bool
	}{
		{
			name:      "expires_at",
			expiresIn: 5 * time.Minute,
			want:      "action timed out",
		},
		{
			name:       "max_action_timeout",
			expiresIn:  time.Hour,
			want:       "action timed out: max_action_timeout 10m0s",
			wantCapped: true,
		},
		{
			name:      "expires_at with a reason",
			expiresIn: 5 * time.Minute,
			reason:    "hook container never started: ImagePullBackOff",
			want:      "action timed out; hook container never started: ImagePullBackOff",
		},
		{
			name:       "max_action_timeout with a reason",
			expiresIn:  time.Hour,
			reason:     "hook container never started: ImagePullBackOff",
			want:       "action timed out: max_action_timeout 10m0s; hook container never started: ImagePullBackOff",
			wantCapped: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := newFakePlexdHookRunner()
			runner.result = PlexdHookResult{TimedOut: true, Reason: tc.reason}
			reporter := &mockReporter{}
			exec, logs := newPlexdHookExecutor(t, Config{MaxActionTimeout: ceiling}, reporter, runner)
			entry := pendingPlexdHookExec("exec-hook-timeout", "e2e-slow")
			entry.ExpiresAt = time.Now().Add(tc.expiresIn)

			cbs := dispatchPlexdHook(t, exec, reporter, entry)

			wantPlexdHookTerminal(t, cbs, api.ExecutionStatusFailed, nil, tc.want)

			starts, waits, _ := runner.calls()
			if len(starts) != 1 || len(waits) != 1 {
				t.Fatalf("calls: %d Start, %d Wait, want one each", len(starts), len(waits))
			}
			capped := logs.lines("run deadline capped by max_action_timeout")
			if !tc.wantCapped {
				if starts[0].Deadline > tc.expiresIn || starts[0].Deadline < tc.expiresIn-time.Minute {
					t.Errorf("Start Deadline = %v, want what is left of expires_at, %v", starts[0].Deadline, tc.expiresIn)
				}
				if len(capped) != 0 {
					t.Errorf("capped warnings = %d, want none under expires_at", len(capped))
				}
				return
			}
			if starts[0].Deadline != ceiling || waits[0].bound != ceiling {
				t.Errorf("Start Deadline = %v, Wait bound = %v, want both %v", starts[0].Deadline, waits[0].bound, ceiling)
			}
			if len(capped) != 1 {
				t.Fatalf("capped warnings = %d, want 1", len(capped))
			}
			line := capped[0]
			if line.level != slog.LevelWarn {
				t.Errorf("capped warning level = %v, want %v", line.level, slog.LevelWarn)
			}
			if line.attrs["execution_id"] != "exec-hook-timeout" || line.attrs["action"] != "e2e-slow" {
				t.Errorf("capped warning attrs = %v, want execution_id and action of the run", line.attrs)
			}
			if line.attrs["ceiling"] != ceiling {
				t.Errorf("capped warning ceiling = %v, want %v", line.attrs["ceiling"], ceiling)
			}
			if requested, _ := line.attrs["requested"].(time.Duration); requested <= ceiling || requested > tc.expiresIn {
				t.Errorf("capped warning requested = %v, want what was left of expires_at, %v", line.attrs["requested"], tc.expiresIn)
			}
		})
	}
}

// The claim handshake can use up the whole deadline. Such a run gets no Job,
// as a script hook gets no process.
func TestPlexdHook_DeadlineLapsedDuringClaimStartsNoJob(t *testing.T) {
	runner := newFakePlexdHookRunner()
	reporter := &mockReporter{callbackDelay: 60 * time.Millisecond}
	exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)
	entry := pendingPlexdHookExec("exec-hook-lapsed", "e2e-pinned")
	entry.ExpiresAt = time.Now().Add(50 * time.Millisecond)

	cbs := dispatchPlexdHook(t, exec, reporter, entry)

	wantPlexdHookTerminal(t, cbs, api.ExecutionStatusFailed, nil, "execution deadline lapsed before the run started")
	runner.wantNoRunnerCalls(t)
}

func TestPlexdHook_ParametersReachTheRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params map[string]json.RawMessage
		want   map[string]string
	}{
		{name: "null", params: nil, want: map[string]string{}},
		{
			name:   "number and string",
			params: map[string]json.RawMessage{"count": json.RawMessage(`3`), "name": json.RawMessage(`"a"`)},
			want:   map[string]string{"count": "3", "name": "a"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := newFakePlexdHookRunner()
			runner.result = PlexdHookResult{Succeeded: true}
			reporter := &mockReporter{}
			exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)
			entry := pendingPlexdHookExec("exec-hook-params", "e2e-pinned")
			entry.Parameters = tc.params

			dispatchPlexdHook(t, exec, reporter, entry)

			starts, _, _ := runner.calls()
			if len(starts) != 1 {
				t.Fatalf("Start calls = %d, want 1", len(starts))
			}
			got := starts[0].Parameters
			if got == nil {
				t.Fatal("Parameters is nil, want a non-nil map")
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("Parameters = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPlexdHook_OutputSizes(t *testing.T) {
	t.Run("empty log", func(t *testing.T) {
		runner := newFakePlexdHookRunner()
		runner.result = PlexdHookResult{Succeeded: true, ExitCode: intPtr(0)}
		reporter := &mockReporter{}
		exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

		cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-quiet", "e2e-pinned"))

		terminal := wantPlexdHookTerminal(t, cbs, api.ExecutionStatusSucceeded, intPtr(0), "")
		if terminal.Output != nil {
			t.Errorf("terminal output = %+v, want none for an empty log", terminal.Output)
		}
	})

	t.Run("over the inline ceiling", func(t *testing.T) {
		log := strings.Repeat("x", 20*1024)
		runner := newFakePlexdHookRunner()
		runner.result = PlexdHookResult{Succeeded: true, ExitCode: intPtr(0), Output: log}
		reporter := &mockReporter{}
		exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

		mustExecute(t, exec, "node-1", pendingPlexdHookExec("exec-hook-big", "e2e-pinned"))
		waitFor(t, 5*time.Second, func() bool { return exec.ActiveCount() == 0 })

		cbs := reporter.getCallbacks()
		assertStatuses(t, cbs, []string{
			api.ExecutionStatusAck,
			api.ExecutionStatusStarted,
			api.ExecutionStatusStarted,
			api.ExecutionStatusSucceeded,
		})
		if declared := cbs[2].DeclaredOutputBytes; declared != int64(len(log)) {
			t.Errorf("declared_output_bytes = %d, want %d", declared, len(log))
		}
		uploads := reporter.getUploads()
		if len(uploads) != 1 || string(uploads[0].data) != log {
			t.Fatalf("uploads = %d, want the 20 KiB log once", len(uploads))
		}
		terminal := cbs[3]
		if terminal.Output == nil || terminal.Output.ObjectKey != "exec-output/exec-hook-big" {
			t.Fatalf("terminal output = %+v, want the uploaded object's key", terminal.Output)
		}
		if terminal.Output.Inline != "" {
			t.Error("terminal carries inline output beside the object key")
		}
		sum := sha256.Sum256([]byte(log))
		if want := hex.EncodeToString(sum[:]); terminal.Output.SHA256 != want {
			t.Errorf("sha256 = %q, want %q", terminal.Output.SHA256, want)
		}
	})

	t.Run("over max_output_bytes", func(t *testing.T) {
		const limit = 4096
		log := strings.Repeat("y", limit+904)
		runner := newFakePlexdHookRunner()
		runner.result = PlexdHookResult{Succeeded: true, ExitCode: intPtr(0), Output: log}
		reporter := &mockReporter{}
		exec, _ := newPlexdHookExecutor(t, Config{MaxOutputBytes: limit}, reporter, runner)

		cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-long", "e2e-pinned"))

		terminal := wantPlexdHookTerminal(t, cbs, api.ExecutionStatusSucceeded, intPtr(0), "")
		got := decodeInline(t, terminal.Output)
		if len(got) != limit {
			t.Errorf("inline output is %d bytes, want %d", len(got), limit)
		}
		if !strings.HasSuffix(got, "...[truncated]") {
			t.Error("inline output does not end in the truncation mark")
		}
		if want := log[:limit-len(truncationSuffix)]; !strings.HasPrefix(got, want) {
			t.Error("inline output does not start with the head of the log")
		}
	})
}

func TestPlexdHook_JobDeletedOnFreshRun(t *testing.T) {
	runner := newFakePlexdHookRunner()
	runner.waitErr = ErrPlexdHookJobNotFound
	reporter := &mockReporter{}
	exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

	cbs := dispatchPlexdHook(t, exec, reporter, pendingPlexdHookExec("exec-hook-deleted", "e2e-pinned"))

	wantPlexdHookTerminal(t, cbs, api.ExecutionStatusFailed, nil, "plexd hook job deleted before it finished")
}

func TestPlexdHook_CancelDuringWaitStopsTheJob(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stopErr    error
		wantOutput string
		wantLogged bool
	}{
		{name: "stop succeeds", wantOutput: "slow-started\n"},
		{name: "stop fails", stopErr: context.DeadlineExceeded, wantLogged: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := newFakePlexdHookRunner()
			runner.waitBlocks = true
			runner.stopOutput = "slow-started\n"
			runner.stopErr = tc.stopErr
			reporter := &mockReporter{}
			exec, logs := newPlexdHookExecutor(t, Config{}, reporter, runner)

			mustExecute(t, exec, "node-1", pendingPlexdHookExec("exec-hook-cancel", "e2e-slow"))
			waitStarted(t, runner.waitEntered)
			if !exec.Cancel("exec-hook-cancel") {
				t.Fatal("Cancel() = false, want true for a run in flight")
			}
			waitFor(t, 5*time.Second, func() bool { return exec.ActiveCount() == 0 })

			terminal := wantPlexdHookTerminal(t, reporter.getCallbacks(), api.ExecutionStatusCancelled, nil, "")
			if tc.wantOutput == "" {
				if terminal.Output != nil {
					t.Errorf("terminal output = %+v, want none after a failed Stop", terminal.Output)
				}
			} else if got := decodeInline(t, terminal.Output); got != tc.wantOutput {
				t.Errorf("inline output = %q, want the log Stop read, %q", got, tc.wantOutput)
			}

			_, _, stops := runner.calls()
			if len(stops) != 1 || stops[0].executionID != "exec-hook-cancel" {
				t.Fatalf("Stop calls = %+v, want one for exec-hook-cancel", stops)
			}
			if stops[0].ctxErr != nil {
				t.Errorf("Stop got an ended context (%v), want one detached from the cancelled run", stops[0].ctxErr)
			}
			if stops[0].budget <= 0 || stops[0].budget > plexdHookStopTimeout {
				t.Errorf("Stop context deadline in %v, want within %v", stops[0].budget, plexdHookStopTimeout)
			}
			if got := len(logs.lines("plexd hook job delete failed")); (got == 1) != tc.wantLogged {
				t.Errorf("delete failed warnings = %d, want logged: %v", got, tc.wantLogged)
			}

			exec.mu.Lock()
			pending := len(exec.cancelRequested)
			exec.mu.Unlock()
			if pending != 0 {
				t.Errorf("cancelRequested holds %d ids after the run ended, want none", pending)
			}
		})
	}
}

// Start honours its context, so a cancel during Start ends it with the
// context's error. That is a cancel, not a failure of the run.
func TestPlexdHook_CancelDuringStartStopsTheJob(t *testing.T) {
	runner := newFakePlexdHookRunner()
	runner.startBlocks = true
	reporter := &mockReporter{}
	exec, _ := newPlexdHookExecutor(t, Config{}, reporter, runner)

	mustExecute(t, exec, "node-1", pendingPlexdHookExec("exec-hook-cancel-start", "e2e-slow"))
	waitStarted(t, runner.startEntered)
	if !exec.Cancel("exec-hook-cancel-start") {
		t.Fatal("Cancel() = false, want true for a run in flight")
	}
	waitFor(t, 5*time.Second, func() bool { return exec.ActiveCount() == 0 })

	cbs := reporter.getCallbacks()
	wantPlexdHookTerminal(t, cbs, api.ExecutionStatusCancelled, nil, "")
	if got := countStatus(cbs, api.ExecutionStatusFailed); got != 0 {
		t.Errorf("failed callbacks = %d, want none for a cancelled Start", got)
	}
	_, waits, stops := runner.calls()
	if len(stops) != 1 {
		t.Errorf("Stop calls = %d, want 1", len(stops))
	}
	if len(waits) != 0 {
		t.Errorf("Wait calls = %d, want none after a cancelled Start", len(waits))
	}
}

// A Job outlives the agent, so a shutdown leaves it running and reports
// nothing: the entry stays at started for the next agent process to resume.
func TestPlexdHook_ShutdownLeavesTheJobRunning(t *testing.T) {
	runner := newFakePlexdHookRunner()
	runner.waitBlocks = true
	reporter := &mockReporter{}
	exec, logs := newPlexdHookExecutor(t, Config{}, reporter, runner)

	mustExecute(t, exec, "node-1", pendingPlexdHookExec("exec-hook-shutdown", "e2e-slow"))
	waitStarted(t, runner.waitEntered)

	done := make(chan struct{})
	go func() {
		exec.Shutdown(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return")
	}

	assertStatuses(t, reporter.getCallbacks(), []string{api.ExecutionStatusAck, api.ExecutionStatusStarted})
	if _, _, stops := runner.calls(); len(stops) != 0 {
		t.Errorf("Stop calls = %+v, want none on shutdown", stops)
	}
	lines := logs.lines("leaving the plexd hook job running; the next agent start resumes it")
	if len(lines) != 1 {
		t.Fatalf("leave-running lines = %d, want 1", len(lines))
	}
	if lines[0].level != slog.LevelInfo || lines[0].attrs["execution_id"] != "exec-hook-shutdown" {
		t.Errorf("leave-running line = %v at %v, want info with the execution_id", lines[0].attrs, lines[0].level)
	}
	if got := len(logs.lines("action completed")); got != 0 {
		t.Errorf("action completed lines = %d, want none for a run left running", got)
	}
}

func TestCutPlexdHookError(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  string
		want string
	}{
		{name: "short", msg: "create job: kubernetes: unauthorized", want: "create job: kubernetes: unauthorized"},
		{name: "exactly the limit", msg: strings.Repeat("a", 1024), want: strings.Repeat("a", 1024)},
		{name: "ascii over the limit", msg: strings.Repeat("a", 1500), want: strings.Repeat("a", 1024)},
		// 1023 ASCII bytes and then a two-byte rune that crosses the limit.
		{name: "two-byte rune across the limit", msg: strings.Repeat("a", 1023) + "äb", want: strings.Repeat("a", 1023)},
		// 1020 ASCII bytes and then a four-byte rune ending at the limit.
		{name: "four-byte rune at the limit", msg: strings.Repeat("a", 1020) + "😀b", want: strings.Repeat("a", 1020) + "😀"},
		// 1021 ASCII bytes and then a four-byte rune whose last byte is the
		// first over the limit: the deepest back-off a rune needs.
		{name: "four-byte rune across the limit", msg: strings.Repeat("a", 1021) + "😀", want: strings.Repeat("a", 1021)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cutPlexdHookError(tc.msg)
			if got != tc.want {
				t.Errorf("cutPlexdHookError() is %d bytes, want %d", len(got), len(tc.want))
			}
			if !utf8.ValidString(got) {
				t.Error("cutPlexdHookError() is not valid UTF-8")
			}
		})
	}
}
