package actions

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/plexsphere/plexd/internal/api"
)

// PlexdHookRun is what the executor hands a PlexdHookRunner to start one run of
// a dispatched PlexdHook.
type PlexdHookRun struct {
	ExecutionID string
	// Hook is the PlexdHook's metadata.name: the entry's action.
	Hook string
	// Parameters are the dispatch's parameters, through flattenParams. It is
	// never nil.
	Parameters map[string]string
	// Deadline is the run's bound, as runBound computed it.
	Deadline time.Duration
}

// PlexdHookResult is the outcome of a run the runner followed to its end.
type PlexdHookResult struct {
	Succeeded bool
	// ExitCode is the hook container's exit code; nil when it never terminated.
	ExitCode *int
	TimedOut bool
	// Reason says why a run without an exit code failed.
	Reason string
	// Output is the pod's log.
	Output string
}

// PlexdHookRunner runs a dispatched PlexdHook outside the agent's process. The
// executor runs a plexd_hook entry through it, and only when one is set: a
// plexd outside a cluster has none and rejects the entry as
// unsupported_action_type. Every method addresses the run by its execution id.
type PlexdHookRunner interface {
	// Start creates the run's Job. A Job that already exists is not an error.
	Start(ctx context.Context, run PlexdHookRun) error
	// Wait returns once the Job is over, or deletes it when bound runs out.
	Wait(ctx context.Context, executionID string, bound time.Duration) (PlexdHookResult, error)
	// Stop reads the log so far and deletes the Job.
	Stop(ctx context.Context, executionID string) (output string, err error)
}

// ErrPlexdHookNotFound reports that the PlexdHook a dispatch names does not
// exist. The executor reports it as unknown_action.
var ErrPlexdHookNotFound = errors.New("actions: plexd hook not found")

// ErrPlexdHookJobNotFound reports that the Job of a run is gone. On a resumed
// run that means the run did not survive the restart.
var ErrPlexdHookJobNotFound = errors.New("actions: plexd hook job not found")

// errNotResumable reports that Resume has no run to follow for an entry: it is
// not a plexd_hook entry, or no runner is set. The dispatcher then reports the
// entry lost to the restart, as it does for every other kind.
var errNotResumable = errors.New("actions: execution not resumable")

// plexdHookStopTimeout bounds the Stop of a cancelled run. The run's own
// context has ended by then, so Stop runs on a detached context, which needs a
// deadline of its own so an unreachable API server cannot hold the run open.
const plexdHookStopTimeout = 10 * time.Second

// maxPlexdHookErrorBytes caps the error of a PlexdHook run's terminal report.
// The contract allows 4096 code points, and a kubelet image pull message alone
// runs to several hundred bytes, so a reason built around one is cut here.
const maxPlexdHookErrorBytes = 1024

// plexdHookJobDeletedError is the terminal error of a fresh run whose Job was
// deleted by someone else before it finished.
const plexdHookJobDeletedError = "plexd hook job deleted before it finished"

// SetPlexdHookRunner sets the runner plexd_hook entries run through. plexd up
// calls it once, before the reconciler starts, when it runs in a pod that can
// create Jobs, and never again. Without it the executor rejects a plexd_hook
// entry as unsupported_action_type, and the dispatcher reports a started one
// lost.
func (e *Executor) SetPlexdHookRunner(r PlexdHookRunner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.plexdHooks = r
}

// Resume follows the run of a plexd_hook entry the control plane holds at
// started, which an earlier agent process claimed. Its Job outlived that
// process, so the run is not lost: Resume takes an active slot for it and
// waits for the Job the way the original run would have. It sends no claim
// callback, because the entry is already at started. A Job that is gone is
// reported as an execution lost to an agent restart.
//
// It returns errNotResumable when the entry is not a plexd_hook entry or no
// runner is set, ErrDispatchDeferred under the backpressure Execute defers on,
// and nil once the run is going.
func (e *Executor) Resume(ctx context.Context, nodeID string, entry api.NodeStateExecution) error {
	e.mu.Lock()
	if entry.Type != api.ActionKindPlexdHook || e.plexdHooks == nil {
		e.mu.Unlock()
		return errNotResumable
	}
	if reason := e.backpressure(entry.ExecutionID); reason != "" {
		e.mu.Unlock()
		return e.deferDispatch(entry, reason)
	}
	actionCtx, cancel := context.WithCancel(ctx)
	e.active[entry.ExecutionID] = cancel
	// Added under mu, which Shutdown takes to set shuttingDown before it
	// waits, so Shutdown cannot stop waiting ahead of this run.
	e.wg.Add(1)
	e.mu.Unlock()

	e.logger.Info("resuming plexd hook run after a restart",
		"execution_id", entry.ExecutionID,
		"action", entry.Action,
	)

	params := flattenParams(entry.Parameters)
	go func() {
		defer e.wg.Done()
		e.runPlexdHook(actionCtx, nodeID, entry, params, cancel, true)
	}()
	return nil
}

// runPlexdHook runs a plexd_hook entry through the runner and reports its
// outcome. A fresh run starts the Job and waits for it; a resumed run waits
// for the Job an earlier agent process started. The run's bound is what
// runBound makes of the dispatch deadline and max_action_timeout, as for every
// other kind, and the runner enforces it.
//
// The Job outlives the agent, so a run whose context ends is not over. When
// Start or Wait returns an error and ctx has ended, the run asks
// cancelRequested which of the two ended it. A cancel stops the Job, keeping
// the log it had so far, and reports cancelled. A shutdown leaves the Job
// running and reports nothing: the entry stays at started, and the next agent
// process resumes it.
//
// DECISION: a result Wait returned without an error is reported as it is,
// even when ctx ended meanwhile. The Job is over by then, and Cancel promises
// the real outcome for a run whose result is already computed.
func (e *Executor) runPlexdHook(ctx context.Context, nodeID string, entry api.NodeStateExecution, params map[string]string, cancel context.CancelFunc, resumed bool) {
	defer e.releaseRun(entry.ExecutionID, cancel)
	defer e.reportPanic(ctx, nodeID, entry.ExecutionID)

	id := entry.ExecutionID
	e.mu.Lock()
	runner := e.plexdHooks
	e.mu.Unlock()

	// A fresh run whose deadline the claim handshake used up gets no Job, as
	// in runAction. A resumed run is past that point: its Job exists, and a
	// bound of zero has Wait collect it and delete it at once.
	remaining := time.Until(entry.ExpiresAt)
	if remaining <= 0 {
		if !resumed {
			e.failLapsed(ctx, nodeID, entry)
			return
		}
		remaining = 0
	}
	bound, label, capped := runBound(remaining, 0, e.cfg.MaxActionTimeout)

	start := time.Now()

	var startErr, waitErr error
	var res PlexdHookResult
	if !resumed {
		startErr = runner.Start(ctx, PlexdHookRun{
			ExecutionID: id,
			Hook:        entry.Action,
			Parameters:  params,
			Deadline:    bound,
		})
	}
	if startErr == nil {
		res, waitErr = runner.Wait(ctx, id, bound)
		// Logged only once the run got as far as Wait: a run that never got a
		// Job was not cut short by the ceiling.
		if capped {
			e.logger.Warn("run deadline capped by max_action_timeout",
				"execution_id", id,
				"action", entry.Action,
				"ceiling", e.cfg.MaxActionTimeout,
				"requested", remaining,
			)
		}
	}

	var terminal api.ExecutionCallbackRequest
	output := res.Output
	if (startErr != nil || waitErr != nil) && ctx.Err() != nil {
		e.mu.Lock()
		_, cancelRequested := e.cancelRequested[id]
		e.mu.Unlock()
		if !cancelRequested {
			e.logger.Info("leaving the plexd hook job running; the next agent start resumes it",
				"execution_id", id,
			)
			return
		}
		terminal = api.ExecutionCallbackRequest{Status: api.ExecutionStatusCancelled}
		output = e.stopPlexdHook(ctx, runner, id)
	} else {
		terminal = plexdHookTerminal(startErr, waitErr, res, label, resumed)
	}

	duration := time.Since(start)

	// The terminal callback is the only transition out of started, so it is
	// sent on a context detached from the run's, as runAction sends it.
	reportCtx, cancelReport := context.WithTimeout(context.WithoutCancel(ctx), terminalReportTimeout)
	defer cancelReport()

	terminal.Output = e.terminalOutput(reportCtx, nodeID, id, combineOutput(output, "", e.cfg.MaxOutputBytes))

	// This goroutine is the run's last owner, so an undelivered report is
	// logged by sendTerminal and left to server-side expiry.
	_ = e.sendTerminal(reportCtx, nodeID, id, terminal)

	e.logger.Info("action completed",
		"execution_id", id,
		"status", terminal.Status,
		"duration", duration,
	)
}

// stopPlexdHook stops the Job of a cancelled run and returns the log Stop read
// from it, or "" when Stop failed: a failed Stop leaves the Job to its
// activeDeadlineSeconds backstop, and whatever it read is not known to be the
// run's.
func (e *Executor) stopPlexdHook(ctx context.Context, runner PlexdHookRunner, executionID string) string {
	stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(ctx), plexdHookStopTimeout)
	defer cancelStop()

	output, err := runner.Stop(stopCtx, executionID)
	if err != nil {
		e.logger.Warn("plexd hook job delete failed",
			"execution_id", executionID,
			"error", err,
		)
		return ""
	}
	return output
}

// plexdHookTerminal maps what Start and Wait returned onto the terminal
// callback of a run whose context did not end them, without its output. A
// failure without an exit code carries its cause as the error; one with an
// exit code carries none, as for a script hook that exits non-zero.
func plexdHookTerminal(startErr, waitErr error, res PlexdHookResult, label string, resumed bool) api.ExecutionCallbackRequest {
	failed := func(msg string) api.ExecutionCallbackRequest {
		return api.ExecutionCallbackRequest{
			Status: api.ExecutionStatusFailed,
			Error:  cutPlexdHookError(msg),
		}
	}

	switch {
	case errors.Is(startErr, ErrPlexdHookNotFound):
		return failed("unknown_action")
	case startErr != nil:
		return failed(startErr.Error())
	case errors.Is(waitErr, ErrPlexdHookJobNotFound) && resumed:
		return failed(orphanedRunError)
	case errors.Is(waitErr, ErrPlexdHookJobNotFound):
		return failed(plexdHookJobDeletedError)
	case waitErr != nil:
		return failed(waitErr.Error())
	case res.Succeeded:
		exitCode := 0
		if res.ExitCode != nil {
			exitCode = *res.ExitCode
		}
		return api.ExecutionCallbackRequest{Status: api.ExecutionStatusSucceeded, ExitCode: &exitCode}
	case res.TimedOut:
		msg := actionTimedOutError
		if label != "" {
			msg += ": " + label
		}
		if res.Reason != "" {
			msg += "; " + res.Reason
		}
		return failed(msg)
	case res.ExitCode != nil:
		exitCode := *res.ExitCode
		return api.ExecutionCallbackRequest{Status: api.ExecutionStatusFailed, ExitCode: &exitCode}
	default:
		return failed(res.Reason)
	}
}

// cutPlexdHookError cuts msg to maxPlexdHookErrorBytes at the start of the rune
// that crosses the limit, so a cut UTF-8 message stays valid UTF-8. A rune is
// at most utf8.UTFMax bytes long, so the search backs off no further than
// that.
func cutPlexdHookError(msg string) string {
	if len(msg) <= maxPlexdHookErrorBytes {
		return msg
	}
	cut := maxPlexdHookErrorBytes
	for i := 1; i < utf8.UTFMax && !utf8.RuneStart(msg[cut]); i++ {
		cut--
	}
	return msg[:cut]
}
