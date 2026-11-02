//go:build unix

package actions

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// cancelMsg is the log message of a cancel the dispatcher forwarded.
const cancelMsg = "cancel requested; stopping the run"

// wantLogFields fails the test unless line carries every field in want.
func wantLogFields(t *testing.T, line string, want ...string) {
	t.Helper()
	for _, field := range want {
		if !strings.Contains(line, field) {
			t.Errorf("log line %q lacks %q", line, field)
		}
	}
}

// A cancel ends a hook the way its deadline or shutdown does: SIGKILL to its
// process group, children included, with what it printed kept as the output.
func TestExecutor_CancelKillsHookProcessGroup(t *testing.T) {
	tk := newTicker(t)
	dir := t.TempDir()
	// The child starts after the hook printed, so its first tick shows the
	// hook under way and its output written.
	writeExecutable(t, dir, "ticker", fmt.Sprintf(
		"#!/bin/sh\necho before\n( trap '' TERM; exec 3>>%q; while [ -e %q ]; do echo tick >&3; sleep 0.1; done ) &\nwait\n",
		tk.ticks, tk.alive))
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "ticker")

	// Execute returns before the hook is started, so the test waits for the
	// tick rather than cancelling a run that has not begun.
	mustExecute(t, exec, "node-1", pendingHookExec("exec-cancel-hook", "ticker"))
	waitFor(t, 5*time.Second, func() bool {
		return tk.size(t) > 0
	})

	if !exec.Cancel("exec-cancel-hook") {
		t.Fatal("Cancel() = false, want true for a hook in flight")
	}
	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
	})
	terminal := cbs[2]
	if terminal.Error != "" {
		t.Errorf("terminal error = %q, want empty for a cancel", terminal.Error)
	}
	if terminal.ExitCode == nil || *terminal.ExitCode != -1 {
		t.Errorf("terminal exit_code = %v, want pointer to -1 for a killed hook", terminal.ExitCode)
	}
	if got := decodeInline(t, terminal.Output); !strings.Contains(got, "before") {
		t.Errorf("output = %q, want what the hook printed before the kill", got)
	}
	tk.wantStopped(t)
}

// The output of a cancelled hook takes the upload leg like any other once it
// is past the inline ceiling, because that leg runs on the detached report
// context.
func TestExecutor_CancelledHookUploadsOverCeilingOutput(t *testing.T) {
	const lines, lineBytes = 400, 50
	dir := t.TempDir()
	printed := filepath.Join(t.TempDir(), "printed")
	// The marker is written once all of the output is, then the hook waits to
	// be killed. 400 lines of 50 bytes are past the 16 KiB inline ceiling.
	writeExecutable(t, dir, "loud", fmt.Sprintf(
		"#!/bin/sh\ni=0\nwhile [ $i -lt %d ]; do echo %s; i=$((i+1)); done\n: > %q\nexec sleep 60\n",
		lines, strings.Repeat("x", lineBytes-1), printed))
	exec, reporter, _ := newHookExecutor(Config{HooksDir: dir}, "loud")

	mustExecute(t, exec, "node-1", pendingHookExec("exec-cancel-loud", "loud"))
	waitFor(t, 5*time.Second, func() bool {
		return markerExists(t, printed)
	})

	if !exec.Cancel("exec-cancel-loud") {
		t.Fatal("Cancel() = false, want true for a hook in flight")
	}
	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
	})
	if got := cbs[2].DeclaredOutputBytes; got != lines*lineBytes {
		t.Errorf("declared_output_bytes = %d, want %d", got, lines*lineBytes)
	}
	if uploads := reporter.getUploads(); len(uploads) != 1 || len(uploads[0].data) != lines*lineBytes {
		t.Errorf("uploads = %d, want one of %d bytes", len(uploads), lines*lineBytes)
	}
	terminal := cbs[3]
	if terminal.Output == nil || terminal.Output.ObjectKey != "exec-output/exec-cancel-loud" {
		t.Errorf("terminal output = %+v, want the uploaded object's key", terminal.Output)
	}
}

// The block repeats a cancel request on every pull until the run's report
// drains the entry. The dispatcher forwards and logs it once, and sends nothing
// for it on any pull.
func TestDispatcher_CancelLoggedOnce(t *testing.T) {
	logs := &syncBuffer{}
	h := newCancelHarness(t, slog.New(slog.NewTextHandler(logs, nil)))
	// The run outlives the end of its context until the test releases it, so
	// the repeated request lands on a run the executor still holds: only the
	// cancelled set keeps it from being forwarded and logged again.
	h.exec.RegisterBuiltin("test.linger", "Lingering action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		h.started <- struct{}{}
		<-ctx.Done()
		<-h.release.ch
		return "partial", "", 1, ctx.Err()
	})
	entry := pendingExec("exec-cancel", "test.linger")
	h.d.Handle(context.Background(), snapshot(entry))
	waitStarted(t, h.started)
	entry.Status = api.ExecutionStatusStarted
	entry = withCancelRequest(entry)

	h.d.Handle(context.Background(), snapshot(entry))
	h.d.Handle(context.Background(), snapshot(entry))
	if !h.exec.IsActive("exec-cancel") {
		t.Fatal("the stopped run left the executor before the repeated request; the test proves nothing")
	}
	if got := len(h.reporter.getCallbacks()); got != 2 {
		t.Errorf("callbacks while the stopped run is held = %d, want 2 (ack, started)", got)
	}

	h.release.open()
	waitFor(t, 5*time.Second, func() bool {
		return h.exec.ActiveCount() == 0
	})
	h.d.Handle(context.Background(), snapshot(entry))

	assertStatuses(t, h.reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
	})
	lines := logLines(logs, cancelMsg)
	if len(lines) != 1 {
		t.Fatalf("%q logged %d times, want once: %q", cancelMsg, len(lines), lines)
	}
	wantLogFields(t, lines[0],
		"level=INFO",
		"execution_id=exec-cancel",
		"action=test.linger",
		"cancel_requested_at=2026-01-01T00:01:00.000Z",
	)
}

func TestDispatcher_CancelRequestOnWaitingEntryWarns(t *testing.T) {
	const msg = "execution entry carries a cancel request but never started; not starting it"
	logs := &syncBuffer{}
	reporter := &mockReporter{}
	exec := newTestExecutor(Config{}, reporter, &mockVerifier{ok: true})
	d := NewDispatcher(exec, "node-1", slog.New(slog.NewTextHandler(logs, nil)))
	pending := withCancelRequest(pendingExec("exec-pending", "test.echo"))
	acked := withCancelRequest(pendingExec("exec-acked", "test.echo"))
	acked.Status = api.ExecutionStatusAck

	// The second pull finds both settled, so it warns about neither again.
	d.Handle(context.Background(), snapshot(pending, acked))
	d.Handle(context.Background(), snapshot(pending, acked))

	lines := logLines(logs, msg)
	if len(lines) != 2 {
		t.Fatalf("%q logged %d times, want once per entry: %q", msg, len(lines), lines)
	}
	wantLogFields(t, lines[0], "level=WARN", "execution_id=exec-pending", "action=test.echo", "status=pending")
	wantLogFields(t, lines[1], "level=WARN", "execution_id=exec-acked", "action=test.echo", "status=ack")
	if cbs := reporter.getCallbacks(); len(cbs) != 0 {
		t.Errorf("callbacks = %v, want none", cbs)
	}
}

// An entry without an id is dropped before anything reads its cancel request,
// so the request reaches no run.
func TestDispatcher_CancelRequestWithoutExecutionIDDropped(t *testing.T) {
	const msg = "execution entry carries no execution_id; dropping"
	logs := &syncBuffer{}
	h := newCancelHarness(t, slog.New(slog.NewTextHandler(logs, nil)))
	running := h.startRun(t, "exec-running")
	anonymous := withCancelRequest(pendingExec("", "test.block"))
	anonymous.Status = api.ExecutionStatusStarted

	h.d.Handle(context.Background(), snapshot(running, anonymous))

	if lines := logLines(logs, msg); len(lines) != 1 {
		t.Errorf("%q logged %d times, want once: %q", msg, len(lines), lines)
	}
	if lines := logLines(logs, cancelMsg); len(lines) != 0 {
		t.Errorf("%q logged %q, want no cancel forwarded", cancelMsg, lines)
	}
	if !h.exec.IsActive(running.ExecutionID) {
		t.Fatal("the run left the executor on a cancel request that named no execution")
	}

	h.release.open()
	waitFor(t, 5*time.Second, func() bool {
		return h.exec.ActiveCount() == 0
	})
	assertStatuses(t, h.reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}
