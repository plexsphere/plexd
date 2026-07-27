package actions

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// waitDelayAfterKill is the grace period for a process to exit after context
// cancellation before it is forcibly killed. This gives child processes time
// to handle SIGTERM and flush buffers.
const waitDelayAfterKill = 500 * time.Millisecond

// truncationSuffix is appended to output that was truncated due to exceeding MaxOutputBytes.
const truncationSuffix = "\n...[truncated]"

// inlineOutputCeiling is the control plane's inline output cap: outputs of at
// most this many bytes travel base64-encoded inline on the terminal callback,
// while larger outputs take the presigned upload leg.
const inlineOutputCeiling = 16 * 1024

// Bounded retry for the terminal callback, the only transition out of started.
const (
	terminalCallbackAttempts = 3
	terminalCallbackBackoff  = 500 * time.Millisecond
)

// orphanedRunError is the terminal error reported for an execution the control
// plane still holds at started but whose run did not survive an agent restart.
const orphanedRunError = "execution lost to an agent restart"

// deadlineLapsedError is the terminal error reported for an execution whose
// absolute deadline ran out while the claim handshake was still in flight, so
// the run never started.
const deadlineLapsedError = "execution deadline lapsed before the run started"

// ErrDispatchDeferred reports that a dispatch has not been settled: local
// backpressure prevented it — shutdown, a run already in flight under the same
// id, or a saturated concurrency slot — or a transient control-plane failure cut
// a callback sequence short before it resolved the execution. It is not a
// failure of the execution: the pull's executions block redelivers the entry, so
// the caller must retry it on a later cycle instead of suppressing it.
var ErrDispatchDeferred = errors.New("actions: dispatch deferred")

// errClaimRefused reports that the control plane refused a transition of the
// claim handshake. The refusal is deliberate and permanent, so the execution is
// settled: the node neither runs it nor reports a terminal status.
var errClaimRefused = errors.New("actions: claim refused")

// terminalReportTimeout bounds the whole terminal-report leg — the over-ceiling
// upload plus the bounded retry loop. That leg runs on a context detached from
// the action's own cancellation, because shutdown cancels the action context yet
// the terminal transition out of started must still be delivered; a detached
// context needs its own deadline so an unreachable control plane cannot pin
// shutdown open. It exceeds the retry loop's backoff budget so the retries are
// actually attempted.
const terminalReportTimeout = 5 * time.Second

// dispatchCallbackTimeout bounds a single leg of a pre-run callback sequence —
// the claim handshake and the rejection walk. Both run synchronously on the
// reconcile goroutine, ahead of peer, policy, and bridge convergence, and both
// are only bounded by the client's request timeout per leg otherwise. FailOrphan
// states the invariant they share: an unreachable control plane must not pin a
// reconciliation cycle open. Every sequence it cuts short leaves its execution
// unsettled, so the next pull redelivers the entry.
//
// The bound is per leg, not per sequence. One deadline spanning a whole sequence
// starves its later legs against a control plane that is slow rather than
// unreachable: the ack consumes it and the started call inherits a sliver, so a
// transition the control plane commits but cannot answer in time reads to the
// next pull as an execution abandoned by a node that never restarted. A sequence
// is therefore bounded by its leg count times this timeout.
const dispatchCallbackTimeout = 5 * time.Second

// ActionReporter abstracts control plane communication for testability.
type ActionReporter interface {
	ExecutionCallback(ctx context.Context, nodeID, executionID string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error)
	UploadExecutionOutput(ctx context.Context, uploadURL string, output []byte) error
}

// HookVerifier abstracts hook integrity verification for testability.
type HookVerifier interface {
	VerifyHook(ctx context.Context, nodeID, hookPath, expectedChecksum string) (bool, error)
}

// builtinEntry pairs a BuiltinFunc with its metadata for capability reporting.
type builtinEntry struct {
	fn          BuiltinFunc
	description string
	params      []api.ActionParam
}

// Executor orchestrates action execution, concurrency control, and result reporting.
type Executor struct {
	cfg      Config
	reporter ActionReporter
	verifier HookVerifier
	logger   *slog.Logger

	mu           sync.Mutex
	wg           sync.WaitGroup
	active       map[string]context.CancelFunc // executionID → cancel
	builtins     map[string]builtinEntry       // action name → builtin
	hooks        []api.HookInfo                // discovered hooks snapshot
	pinned       map[string]string             // hook name → digest at first discovery
	shuttingDown bool
}

// NewExecutor creates an Executor with the given configuration, reporter, verifier, and logger.
func NewExecutor(cfg Config, reporter ActionReporter, verifier HookVerifier, logger *slog.Logger) *Executor {
	return &Executor{
		cfg:      cfg,
		reporter: reporter,
		verifier: verifier,
		logger:   logger.With("component", "actions"),
		active:   make(map[string]context.CancelFunc),
		builtins: make(map[string]builtinEntry),
		pinned:   make(map[string]string),
	}
}

// RegisterBuiltin stores a builtin action for execution.
func (e *Executor) RegisterBuiltin(name, description string, params []api.ActionParam, fn BuiltinFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.builtins[name] = builtinEntry{
		fn:          fn,
		description: description,
		params:      params,
	}
}

// SetHooks sets the discovered hooks snapshot and pins the integrity anchor of
// every hook this process has not seen before.
//
// The snapshot itself is refreshed by HookWatcher, which re-hashes a hook on
// every write, so verifying an execution against the snapshot digest would
// compare a file with a hash of itself and pass for any bytes an attacker with
// write access to the hooks directory puts there. The pin is therefore recorded
// once, at first discovery — the digest this node also reports to the control
// plane — and never updated: a hook whose bytes change afterwards fails
// verification and stays unrunnable until the agent restarts and re-attests it.
func (e *Executor) SetHooks(hooks []api.HookInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks = hooks
	for _, h := range hooks {
		if _, pinned := e.pinned[h.Name]; !pinned {
			e.pinned[h.Name] = h.Checksum
		}
	}
}

// Capabilities returns builtin action metadata and hooks for capability reporting.
func (e *Executor) Capabilities() ([]api.ActionInfo, []api.HookInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()

	actions := make([]api.ActionInfo, 0, len(e.builtins))
	for name, entry := range e.builtins {
		actions = append(actions, api.ActionInfo{
			Name:        name,
			Description: entry.description,
			Parameters:  entry.params,
		})
	}

	hooks := make([]api.HookInfo, len(e.hooks))
	copy(hooks, e.hooks)

	return actions, hooks
}

// ActiveCount returns the number of currently running actions.
func (e *Executor) ActiveCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.active)
}

// IsActive reports whether this executor is running the given execution right
// now. It is the authoritative answer to "did this agent lose that run?", which
// a caller tracking dispatches by id cannot answer on its own.
func (e *Executor) IsActive(executionID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, active := e.active[executionID]
	return active
}

// Execute is the main entry point for action execution. It returns
// ErrDispatchDeferred when the execution is left unresolved — local
// backpressure, or a transient control-plane failure during the claim handshake
// or a rejection walk — and nil once the run has been accepted or the execution
// settled with a callback.
func (e *Executor) Execute(ctx context.Context, nodeID string, entry api.NodeStateExecution) error {
	e.mu.Lock()

	if e.shuttingDown {
		e.mu.Unlock()
		return e.deferDispatch(entry, "shutting_down")
	}

	if _, exists := e.active[entry.ExecutionID]; exists {
		e.mu.Unlock()
		return e.deferDispatch(entry, "already_active")
	}

	if len(e.active) >= e.cfg.MaxConcurrent {
		e.mu.Unlock()
		return e.deferDispatch(entry, "max_concurrent_reached")
	}

	// The declared type picks the registry: a builtin never resolves against a
	// hook of the same name and vice versa, so a mistyped entry is unresolvable
	// rather than silently routed to the other kind. A type outside the roster
	// is reported as such rather than as unknown_action: the action itself may
	// well be registered, and naming the wrong cause sends the operator auditing
	// the action registry instead of the type field.
	var known bool
	switch entry.Type {
	case api.ActionKindBuiltin:
		_, known = e.builtins[entry.Action]
	case api.ActionKindHook:
		_, known = lookupHook(e.hooks, entry.Action)
	default:
		e.mu.Unlock()
		return e.reject(ctx, nodeID, entry, "unsupported_action_type")
	}
	if !known {
		e.mu.Unlock()
		return e.reject(ctx, nodeID, entry, "unknown_action")
	}

	actionCtx, cancel := context.WithCancel(ctx)
	e.active[entry.ExecutionID] = cancel
	e.mu.Unlock()

	if err := e.claim(ctx, nodeID, entry); err != nil {
		cancel()
		e.mu.Lock()
		delete(e.active, entry.ExecutionID)
		e.mu.Unlock()
		if errors.Is(err, errClaimRefused) {
			return nil
		}
		return err
	}

	params := flattenParams(entry.Parameters)

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.runAction(actionCtx, nodeID, entry, params, cancel)
	}()
	return nil
}

// claim drives an execution from the status its pull entry declared to started,
// the point from which a terminal callback is legal, before any work begins.
// Starting the run only once started is recorded is what keeps the pull's ack
// status unambiguous: an entry the block still reports at ack has not executed,
// so redelivering it after a restart cannot repeat a non-idempotent action.
//
// It returns errClaimRefused when the control plane refuses a transition — that
// refusal is deliberate and permanent, so the execution is settled without a run
// and without a terminal report — and ErrDispatchDeferred when a transient
// failure interrupts the handshake, which leaves the execution exactly where it
// was for the next pull to redeliver.
func (e *Executor) claim(ctx context.Context, nodeID string, entry api.NodeStateExecution) error {
	// Only a pending entry still owes the ack. An entry the pull already reports
	// at ack has that transition recorded on the control plane, and repeating it
	// would be a non-terminal self-edge answered 409.
	statuses := []string{api.ExecutionStatusStarted}
	if entry.Status == api.ExecutionStatusPending {
		statuses = []string{api.ExecutionStatusAck, api.ExecutionStatusStarted}
	}

	for _, status := range statuses {
		legCtx, cancel := context.WithTimeout(ctx, dispatchCallbackTimeout)
		cb := api.ExecutionCallbackRequest{Status: status}
		_, err := e.reporter.ExecutionCallback(legCtx, nodeID, entry.ExecutionID, cb)
		cancel()
		if err != nil {
			if callbackRefused(err) {
				e.logger.Error("claim callback refused; aborting execution",
					"execution_id", entry.ExecutionID,
					"status", status,
					"error", err,
				)
				return errClaimRefused
			}
			e.logger.Warn("claim callback failed; deferring the dispatch",
				"execution_id", entry.ExecutionID,
				"status", status,
				"error", err,
			)
			return ErrDispatchDeferred
		}
	}
	return nil
}

// deferDispatch logs a deferral and returns the sentinel. A deferral is
// transient and carries no callback: reporting it would fail an execution the
// control plane will redeliver on the next pull.
func (e *Executor) deferDispatch(entry api.NodeStateExecution, reason string) error {
	e.logger.Warn("dispatch deferred",
		"execution_id", entry.ExecutionID,
		"action", entry.Action,
		"reason", reason,
	)
	return ErrDispatchDeferred
}

// lookupHook returns the discovered hook record with the given name.
func lookupHook(hooks []api.HookInfo, name string) (api.HookInfo, bool) {
	for _, h := range hooks {
		if h.Name == name {
			return h, true
		}
	}
	return api.HookInfo{}, false
}

// flattenParams renders a pull entry's JSON parameter object into the flat
// string map builtins and hooks consume. A JSON string is unquoted so an
// ordinary parameter keeps its exact text; every other value — number, bool,
// null, array, object — travels as the JSON text the control plane sent. The
// entry keeps those values as raw JSON rather than decoding them into any: a
// number decoded into any becomes a float64, which silently rewrites every
// integer beyond 2^53 (an epoch in nanoseconds, a snowflake id) before it ever
// reaches the action. A nil object flattens to an empty map.
func flattenParams(params map[string]json.RawMessage) map[string]string {
	flat := make(map[string]string, len(params))
	for name, raw := range params {
		// The string case is recognised by its opening quote, not by whether
		// unmarshalling into a string succeeds: decoding a JSON null into a
		// string succeeds and leaves it empty, which would render null as "".
		if len(raw) > 0 && raw[0] == '"' {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				flat[name] = s
				continue
			}
		}
		flat[name] = string(raw)
	}
	return flat
}

// Shutdown cancels all running actions, prevents new ones from starting,
// and waits for all in-flight goroutines to drain.
func (e *Executor) Shutdown(_ context.Context) {
	e.mu.Lock()
	e.shuttingDown = true
	cancels := make([]context.CancelFunc, 0, len(e.active))
	for _, cancel := range e.active {
		cancels = append(cancels, cancel)
	}
	e.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}

	e.wg.Wait()
}

// reject fails an execution the node will not run, carrying reason as the error
// string of the terminal callback. The control plane reaches a terminal status
// only from started, so the rejection walks every legal edge from the status the
// pull entry declared.
//
// It returns nil once the walk has settled the execution — delivered in full, or
// refused, which is deliberate and permanent. A transient failure cuts the walk
// short and returns ErrDispatchDeferred: the execution is then still unresolved,
// and continuing the walk would only earn a 409 on the next leg because the
// control plane never recorded the one that failed. The caller must let the next
// pull redeliver the entry instead of suppressing it.
func (e *Executor) reject(ctx context.Context, nodeID string, entry api.NodeStateExecution, reason string) error {
	e.logger.Warn("action rejected",
		"execution_id", entry.ExecutionID,
		"action", entry.Action,
		"reason", reason,
	)

	for _, status := range rejectSequence(entry.Status) {
		legCtx, cancel := context.WithTimeout(ctx, dispatchCallbackTimeout)
		cb := api.ExecutionCallbackRequest{Status: status}
		if status == api.ExecutionStatusFailed {
			cb.Error = reason
		}
		_, err := e.reporter.ExecutionCallback(legCtx, nodeID, entry.ExecutionID, cb)
		cancel()
		if err != nil {
			if callbackRefused(err) {
				e.logger.Error("callback refused for rejected execution",
					"execution_id", entry.ExecutionID,
					"status", status,
					"error", err,
				)
				return nil
			}
			e.logger.Warn("failed to send callback for rejected execution",
				"execution_id", entry.ExecutionID,
				"status", status,
				"error", err,
			)
			return ErrDispatchDeferred
		}
	}
	return nil
}

// rejectSequence returns the callback statuses that drive an execution from the
// status its pull entry declared to the terminal failed, along the closed edge
// roster pending → ack → started → failed.
func rejectSequence(status string) []string {
	switch status {
	case api.ExecutionStatusAck:
		return []string{api.ExecutionStatusStarted, api.ExecutionStatusFailed}
	case api.ExecutionStatusStarted:
		return []string{api.ExecutionStatusFailed}
	default:
		return []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed}
	}
}

// FailOrphan reports an execution the control plane still holds at started but
// whose run this agent no longer owns — the process restarted mid-run. Actions
// are not idempotent, so the run is not repeated; started → failed is a legal
// edge, so the single terminal callback settles the execution. The report runs
// under its own deadline so an unreachable control plane cannot pin a
// reconciliation cycle open.
//
// It returns ErrDispatchDeferred when the report was not delivered. That leaves
// the execution exactly where it was — at started, with no terminal recorded —
// so the caller must let the next pull redeliver the entry rather than treat it
// as settled.
func (e *Executor) FailOrphan(ctx context.Context, nodeID, executionID string) error {
	e.logger.Warn("execution lost to an agent restart; reporting failed",
		"execution_id", executionID,
	)

	reportCtx, cancel := context.WithTimeout(ctx, terminalReportTimeout)
	defer cancel()

	return e.sendTerminal(reportCtx, nodeID, executionID, api.ExecutionCallbackRequest{
		Status: api.ExecutionStatusFailed,
		Error:  orphanedRunError,
	})
}

// callbackRefused reports whether an execution-callback error carries one of the
// RFC 9457 problem codes with which the control plane refuses a transition. Only
// those codes mean the refusal is deliberate and permanent, so the node must stop
// driving the execution rather than double-report it. Matching on the bare 403 or
// 409 status instead would let an intermediary's 403 (WAF, proxy challenge) or a
// 409 raised for an unrelated reason abort an action that never ran and is never
// reported.
func callbackRefused(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.Code {
	case api.CodeNSKNodeMismatch, api.CodeInvalidStateTransition, api.CodeExecutionAlreadyTerminal:
		return true
	}
	return false
}

// terminalOutcome maps the result of an action execution to a terminal callback
// status and, for failures without a meaningful exit code, an error message.
func terminalOutcome(runErr error, exitCode int, timeoutCtx, parentCtx context.Context) (status, errMsg string) {
	if runErr != nil {
		if timeoutCtx.Err() == context.DeadlineExceeded {
			return api.ExecutionStatusFailed, "action timed out"
		}
		if parentCtx.Err() == context.Canceled {
			return api.ExecutionStatusCancelled, ""
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return api.ExecutionStatusFailed, ""
		}
		return api.ExecutionStatusFailed, runErr.Error()
	}
	if exitCode != 0 {
		return api.ExecutionStatusFailed, ""
	}
	return api.ExecutionStatusSucceeded, ""
}

func (e *Executor) runAction(ctx context.Context, nodeID string, entry api.NodeStateExecution, params map[string]string, cancel context.CancelFunc) {
	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.active, entry.ExecutionID)
		e.mu.Unlock()
	}()

	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			e.logger.Error("panic in action execution",
				"execution_id", entry.ExecutionID,
				"panic", fmt.Sprintf("%v", r),
				"stack", string(stack),
			)
			terminal := api.ExecutionCallbackRequest{
				Status: api.ExecutionStatusFailed,
				Error:  fmt.Sprintf("panic: %v", r),
			}
			if _, err := e.reporter.ExecutionCallback(ctx, nodeID, entry.ExecutionID, terminal); err != nil {
				e.logger.Warn("failed to send panic terminal callback",
					"execution_id", entry.ExecutionID,
					"error", err,
				)
			}
		}
	}()

	// The entry carries an absolute deadline, not a relative timeout: the run
	// gets whatever is left of it, clamped to the configured maximum. Execute's
	// claim handshake runs synchronously ahead of this, so a slow control plane
	// can consume the whole remainder. Handing the run an already-lapsed
	// deadline would kill a hook at Start while a builtin that does not watch its
	// context would run to completion and report succeeded past its own
	// deadline — so settle it instead. The started transition is already
	// recorded, so the execution still owes its terminal callback.
	remaining := time.Until(entry.ExpiresAt)
	if remaining <= 0 {
		e.logger.Warn("execution deadline lapsed before the run started",
			"execution_id", entry.ExecutionID,
			"expires_at", entry.ExpiresAt,
		)
		lapsedCtx, cancelLapsed := context.WithTimeout(context.WithoutCancel(ctx), terminalReportTimeout)
		defer cancelLapsed()
		// Nothing is left to do with an undelivered report here: sendTerminal has
		// logged it and spent its retries, and this goroutine is the last owner
		// of the run. The control plane expires the execution instead.
		_ = e.sendTerminal(lapsedCtx, nodeID, entry.ExecutionID, api.ExecutionCallbackRequest{
			Status: api.ExecutionStatusFailed,
			Error:  deadlineLapsedError,
		})
		return
	}
	timeout := min(remaining, e.cfg.MaxActionTimeout)

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	start := time.Now()

	var stdout, stderr string
	var exitCode int
	var runErr error

	if entry.Type == api.ActionKindBuiltin {
		stdout, stderr, exitCode, runErr = e.runBuiltin(timeoutCtx, entry.Action, params)
	} else {
		stdout, stderr, exitCode, runErr = e.runHook(timeoutCtx, nodeID, entry, params)
	}

	duration := time.Since(start)
	status, errMsg := terminalOutcome(runErr, exitCode, timeoutCtx, ctx)

	// The terminal callback is the only transition out of started and must be
	// delivered even when shutdown has already cancelled ctx (Shutdown cancels
	// every actionCtx directly). Detach the report leg from that cancellation,
	// keeping a bounded deadline of its own. terminalOutcome above still reads
	// ctx to recognise the cancellation it reports.
	reportCtx, cancelReport := context.WithTimeout(context.WithoutCancel(ctx), terminalReportTimeout)
	defer cancelReport()

	terminal := api.ExecutionCallbackRequest{
		Status:   status,
		ExitCode: &exitCode,
		Error:    errMsg,
		Output:   e.terminalOutput(reportCtx, nodeID, entry.ExecutionID, combineOutput(stdout, stderr, e.cfg.MaxOutputBytes)),
	}

	// As above: the run is over and this goroutine is its last owner, so an
	// undelivered report is logged by sendTerminal and left to server-side expiry.
	_ = e.sendTerminal(reportCtx, nodeID, entry.ExecutionID, terminal)

	e.logger.Info("action completed",
		"execution_id", entry.ExecutionID,
		"status", status,
		"duration", duration,
	)
}

// sendTerminal posts the terminal callback, retrying a transient failure with
// exponential backoff. The terminal callback is the only transition out of
// started, so giving up after one attempt leaves the invocation pinned at
// started on the control plane forever — the node has already dropped its
// active entry and keeps no pending terminal across a restart. A refusal is
// deliberate and permanent, so it stops the retry immediately.
//
// It returns ErrDispatchDeferred once the attempts are spent without the report
// landing, for the callers that can still act on an undelivered terminal.
func (e *Executor) sendTerminal(ctx context.Context, nodeID, executionID string, terminal api.ExecutionCallbackRequest) error {
	backoff := terminalCallbackBackoff
	for attempt := 1; ; attempt++ {
		_, err := e.reporter.ExecutionCallback(ctx, nodeID, executionID, terminal)
		if err == nil {
			return nil
		}

		refused := callbackRefused(err)
		if !refused && attempt < terminalCallbackAttempts {
			select {
			case <-time.After(backoff):
				backoff *= 2
				continue
			case <-ctx.Done():
			}
		}

		e.logger.Warn("failed to send terminal callback",
			"execution_id", executionID,
			"attempts", attempt,
			"error", err,
		)

		// A refusal is deliberate and permanent — a foreign node, an illegal
		// edge, an execution the control plane already settled — so no later
		// attempt is answered differently and the execution is settled as far as
		// this node is concerned. Deferring it instead would have the caller
		// redeliver the entry on every pull for the life of the process.
		if refused {
			return nil
		}
		return ErrDispatchDeferred
	}
}

// combineOutput joins captured stdout and stderr into a single body: stdout
// first, both separated by a newline when present, and whichever stream is
// empty dropped entirely. Each stream is captured under its own MaxOutputBytes
// limit, so the joined body is truncated back to limit — without that a hook
// saturating both streams would produce twice the configured per-action cap,
// which is then held three times over while it is uploaded and hashed. Config
// validation keeps limit well above len(truncationSuffix).
func combineOutput(stdout, stderr string, limit int64) string {
	var combined string
	switch {
	case stdout != "" && stderr != "":
		combined = stdout + "\n" + stderr
	case stdout != "":
		combined = stdout
	default:
		combined = stderr
	}
	if int64(len(combined)) <= limit {
		return combined
	}
	return combined[:limit-int64(len(truncationSuffix))] + truncationSuffix
}

// terminalOutput builds the ExecutionOutput for a terminal callback. Empty
// output is omitted; output within the inline ceiling travels base64 inline;
// larger output takes the presigned upload leg, falling back to truncated
// inline output if any step of that leg fails.
func (e *Executor) terminalOutput(ctx context.Context, nodeID, executionID, combined string) *api.ExecutionOutput {
	if combined == "" {
		return nil
	}
	if len(combined) <= inlineOutputCeiling {
		return &api.ExecutionOutput{Inline: base64.StdEncoding.EncodeToString([]byte(combined))}
	}

	output, err := e.uploadOutput(ctx, nodeID, executionID, combined)
	if err != nil {
		e.logger.Warn("over-ceiling output upload failed; falling back to truncated inline",
			"execution_id", executionID,
			"error", err,
		)
		truncated := combined[:inlineOutputCeiling-len(truncationSuffix)] + truncationSuffix
		return &api.ExecutionOutput{Inline: base64.StdEncoding.EncodeToString([]byte(truncated))}
	}
	return output
}

// uploadOutput runs the over-ceiling upload leg: it declares the output byte
// count to mint a one-time presigned PUT URL, derives the object key from that
// URL's path, uploads the raw bytes, and returns the object reference (key plus
// lowercase-hex SHA-256) for the terminal callback.
func (e *Executor) uploadOutput(ctx context.Context, nodeID, executionID, combined string) (*api.ExecutionOutput, error) {
	declare := api.ExecutionCallbackRequest{
		Status:              api.ExecutionStatusStarted,
		DeclaredOutputBytes: int64(len(combined)),
	}
	resp, err := e.reporter.ExecutionCallback(ctx, nodeID, executionID, declare)
	if err != nil {
		return nil, fmt.Errorf("declare output: %w", err)
	}
	if resp == nil || resp.OutputUploadURL == "" {
		return nil, fmt.Errorf("declare output: empty upload url")
	}

	// The presigned URL is a bearer credential, and url.Error renders it in full.
	// Every error on this leg is redacted before it reaches a log line.
	parsed, err := url.Parse(resp.OutputUploadURL)
	if err != nil {
		return nil, fmt.Errorf("parse upload url: %w", api.RedactURLError(err))
	}
	objectKey := strings.TrimPrefix(parsed.Path, "/")

	if err := e.reporter.UploadExecutionOutput(ctx, resp.OutputUploadURL, []byte(combined)); err != nil {
		return nil, fmt.Errorf("upload output: %w", err)
	}

	sum := sha256.Sum256([]byte(combined))
	return &api.ExecutionOutput{
		ObjectKey: objectKey,
		SHA256:    hex.EncodeToString(sum[:]),
	}, nil
}

// RunLocal executes a built-in action synchronously and returns the output.
// This is used by the local node API for CLI-triggered action execution.
// Only built-in actions are supported: hooks are arbitrary operator scripts, and
// dispatch from the pull's executions block is the only path the control plane
// authorizes server-side.
func (e *Executor) RunLocal(ctx context.Context, action string, params map[string]string) (string, string, int, error) {
	e.mu.Lock()
	_, ok := e.builtins[action]
	e.mu.Unlock()

	if !ok {
		return "", "", 1, fmt.Errorf("unknown builtin action: %s", action)
	}

	return e.runBuiltin(ctx, action, params)
}

func (e *Executor) runBuiltin(ctx context.Context, name string, params map[string]string) (string, string, int, error) {
	e.mu.Lock()
	entry, ok := e.builtins[name]
	e.mu.Unlock()

	if !ok {
		return "", "", 1, fmt.Errorf("builtin not found: %s", name)
	}

	return entry.fn(ctx, params)
}

// validateHookName rejects hook names containing path separators or traversal sequences.
func validateHookName(name string) error {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid hook name: %s", name)
	}
	return nil
}

func (e *Executor) runHook(ctx context.Context, nodeID string, entry api.NodeStateExecution, params map[string]string) (string, string, int, error) {
	if err := validateHookName(entry.Action); err != nil {
		return "", "", 1, err
	}

	// The pull entry carries no checksum, so hook trust anchors on the pinned
	// digest — the one recorded when this process first discovered the hook, not
	// the one the watcher last recomputed. A hook whose on-disk bytes drift
	// after discovery is therefore refused and files an integrity violation.
	// Execute already gated the lookup; this is the backstop for a hooks
	// snapshot that changed in between.
	e.mu.Lock()
	_, known := lookupHook(e.hooks, entry.Action)
	pinnedChecksum := e.pinned[entry.Action]
	e.mu.Unlock()
	if !known {
		return "", "", 1, fmt.Errorf("hook not discovered: %s", entry.Action)
	}

	hookPath := filepath.Join(e.cfg.HooksDir, entry.Action)

	if _, err := os.Stat(hookPath); errors.Is(err, os.ErrNotExist) {
		return "", "", 1, fmt.Errorf("hook not found: %s", entry.Action)
	}

	ok, err := e.verifier.VerifyHook(ctx, nodeID, hookPath, pinnedChecksum)
	if err != nil {
		return "", "", 1, fmt.Errorf("integrity verification error: %w", err)
	}
	if !ok {
		return "", "", 1, fmt.Errorf("integrity check failed for hook: %s", entry.Action)
	}

	cmd := exec.CommandContext(ctx, hookPath)
	cmd.WaitDelay = waitDelayAfterKill
	cmd.Env = e.buildHookEnv(nodeID, entry.ExecutionID, params)

	stdoutW := newLimitedWriter(e.cfg.MaxOutputBytes)
	stderrW := newLimitedWriter(e.cfg.MaxOutputBytes)
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	runErr := cmd.Run()

	stdout := collectOutput(stdoutW)
	stderr := collectOutput(stderrW)

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return stdout, stderr, exitErr.ExitCode(), runErr
		}
		return stdout, stderr, 1, runErr
	}

	return stdout, stderr, 0, nil
}

// buildHookEnv constructs the minimal environment for hook execution.
func (e *Executor) buildHookEnv(nodeID, executionID string, params map[string]string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"PLEXD_NODE_ID=" + nodeID,
		"PLEXD_EXECUTION_ID=" + executionID,
	}
	for name, value := range params {
		envName := "PLEXD_PARAM_" + sanitizeParamName(name)
		env = append(env, envName+"="+value)
	}
	return env
}

// limitedWriter is an io.Writer that discards bytes beyond a maximum limit,
// preventing unbounded memory allocation during command execution (REQ-003).
type limitedWriter struct {
	buf []byte
	max int64
}

func newLimitedWriter(max int64) *limitedWriter {
	return &limitedWriter{max: max}
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.max - int64(len(w.buf))
	if remaining > 0 {
		n := int64(len(p))
		if n > remaining {
			n = remaining
		}
		w.buf = append(w.buf, p[:n]...)
	}
	// Always report all bytes as written so the command doesn't stall.
	return len(p), nil
}

func (w *limitedWriter) String() string {
	return string(w.buf)
}

// truncated reports whether the writer hit its capacity limit.
func (w *limitedWriter) truncated() bool {
	return int64(len(w.buf)) >= w.max
}

var nonAlphanumUnderscore = regexp.MustCompile(`[^A-Za-z0-9_]`)

func sanitizeParamName(name string) string {
	return strings.ToUpper(nonAlphanumUnderscore.ReplaceAllString(name, "_"))
}

// collectOutput returns the writer's content, appending a truncation indicator
// if the output exceeded the writer's capacity.
func collectOutput(w *limitedWriter) string {
	if w.truncated() {
		return w.String() + truncationSuffix
	}
	return w.String()
}
