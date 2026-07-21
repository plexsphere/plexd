package actions

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// terminalReportTimeout bounds the whole terminal-report leg — the over-ceiling
// upload plus the bounded retry loop. That leg runs on a context detached from
// the action's own cancellation, because shutdown cancels the action context yet
// the terminal transition out of started must still be delivered; a detached
// context needs its own deadline so an unreachable control plane cannot pin
// shutdown open. It exceeds the retry loop's backoff budget so the retries are
// actually attempted.
const terminalReportTimeout = 5 * time.Second

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

// SetHooks sets the discovered hooks snapshot.
func (e *Executor) SetHooks(hooks []api.HookInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks = hooks
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

// Execute is the main entry point for action execution.
func (e *Executor) Execute(ctx context.Context, nodeID string, req api.ActionRequest) {
	e.mu.Lock()

	if e.shuttingDown {
		e.mu.Unlock()
		e.reject(ctx, nodeID, req, "shutting_down")
		return
	}

	if _, exists := e.active[req.ExecutionID]; exists {
		e.mu.Unlock()
		e.reject(ctx, nodeID, req, "duplicate_execution_id")
		return
	}

	if len(e.active) >= e.cfg.MaxConcurrent {
		e.mu.Unlock()
		e.reject(ctx, nodeID, req, "max_concurrent_reached")
		return
	}

	// Look up the action: builtins first, then hooks.
	_, isBuiltin := e.builtins[req.Action]
	var isHook bool
	if !isBuiltin {
		for _, h := range e.hooks {
			if h.Name == req.Action {
				isHook = true
				break
			}
		}
	}

	if !isBuiltin && !isHook {
		e.mu.Unlock()
		e.reject(ctx, nodeID, req, "unknown_action")
		return
	}

	actionCtx, cancel := context.WithCancel(ctx)
	e.active[req.ExecutionID] = cancel
	e.mu.Unlock()

	ack := api.ExecutionCallbackRequest{Status: api.ExecutionStatusAck}
	if _, err := e.reporter.ExecutionCallback(ctx, nodeID, req.ExecutionID, ack); err != nil {
		if callbackRefused(err) {
			// The server refused the execution (foreign node or illegal
			// transition). Running it anyway would double-report, so abort.
			e.logger.Error("ack callback refused; aborting execution",
				"execution_id", req.ExecutionID,
				"error", err,
			)
			cancel()
			e.mu.Lock()
			delete(e.active, req.ExecutionID)
			e.mu.Unlock()
			return
		}
		e.logger.Warn("failed to send ack callback",
			"execution_id", req.ExecutionID,
			"error", err,
		)
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.runAction(actionCtx, nodeID, req, cancel)
	}()
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

func (e *Executor) reject(ctx context.Context, nodeID string, req api.ActionRequest, reason string) {
	e.logger.Warn("action rejected",
		"execution_id", req.ExecutionID,
		"action", req.Action,
		"reason", reason,
	)

	ack := api.ExecutionCallbackRequest{Status: api.ExecutionStatusAck}
	if _, err := e.reporter.ExecutionCallback(ctx, nodeID, req.ExecutionID, ack); err != nil {
		if callbackRefused(err) {
			// The server refused the execution; skip the failed terminal.
			e.logger.Error("ack callback refused for rejected execution",
				"execution_id", req.ExecutionID,
				"error", err,
			)
			return
		}
		e.logger.Warn("failed to send ack callback for rejected execution",
			"execution_id", req.ExecutionID,
			"error", err,
		)
	}

	failed := api.ExecutionCallbackRequest{
		Status: api.ExecutionStatusFailed,
		Error:  reason,
	}
	if _, err := e.reporter.ExecutionCallback(ctx, nodeID, req.ExecutionID, failed); err != nil {
		e.logger.Warn("failed to send failed callback for rejected execution",
			"execution_id", req.ExecutionID,
			"error", err,
		)
	}
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

func (e *Executor) runAction(ctx context.Context, nodeID string, req api.ActionRequest, cancel context.CancelFunc) {
	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.active, req.ExecutionID)
		e.mu.Unlock()
	}()

	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			e.logger.Error("panic in action execution",
				"execution_id", req.ExecutionID,
				"panic", fmt.Sprintf("%v", r),
				"stack", string(stack),
			)
			terminal := api.ExecutionCallbackRequest{
				Status: api.ExecutionStatusFailed,
				Error:  fmt.Sprintf("panic: %v", r),
			}
			if _, err := e.reporter.ExecutionCallback(ctx, nodeID, req.ExecutionID, terminal); err != nil {
				e.logger.Warn("failed to send panic terminal callback",
					"execution_id", req.ExecutionID,
					"error", err,
				)
			}
		}
	}()

	// Report that the action has begun. A 403/409 refusal means the server has
	// rejected the transition; stop without running or terminal-reporting. The
	// deferred cleanup still removes the active entry.
	started := api.ExecutionCallbackRequest{Status: api.ExecutionStatusStarted}
	if _, err := e.reporter.ExecutionCallback(ctx, nodeID, req.ExecutionID, started); err != nil {
		if callbackRefused(err) {
			e.logger.Error("started callback refused; skipping execution",
				"execution_id", req.ExecutionID,
				"error", err,
			)
			return
		}
		e.logger.Warn("failed to send started callback",
			"execution_id", req.ExecutionID,
			"error", err,
		)
	}

	// Parse timeout, clamped to the configured maximum.
	timeout := e.cfg.MaxActionTimeout
	if req.Timeout != "" {
		if parsed, err := time.ParseDuration(req.Timeout); err == nil {
			timeout = min(parsed, e.cfg.MaxActionTimeout)
		}
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	start := time.Now()

	var stdout, stderr string
	var exitCode int
	var runErr error

	e.mu.Lock()
	_, isBuiltin := e.builtins[req.Action]
	e.mu.Unlock()

	if isBuiltin {
		stdout, stderr, exitCode, runErr = e.runBuiltin(timeoutCtx, req.Action, req.Parameters)
	} else {
		stdout, stderr, exitCode, runErr = e.runHook(timeoutCtx, nodeID, req)
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
		Output:   e.terminalOutput(reportCtx, nodeID, req.ExecutionID, combineOutput(stdout, stderr, e.cfg.MaxOutputBytes)),
	}

	e.sendTerminal(reportCtx, nodeID, req.ExecutionID, terminal)

	e.logger.Info("action completed",
		"execution_id", req.ExecutionID,
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
func (e *Executor) sendTerminal(ctx context.Context, nodeID, executionID string, terminal api.ExecutionCallbackRequest) {
	backoff := terminalCallbackBackoff
	for attempt := 1; ; attempt++ {
		_, err := e.reporter.ExecutionCallback(ctx, nodeID, executionID, terminal)
		if err == nil {
			return
		}

		retry := !callbackRefused(err) && attempt < terminalCallbackAttempts
		if retry {
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
		return
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
// Only built-in actions are supported; hook execution requires control plane checksum.
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

func (e *Executor) runHook(ctx context.Context, nodeID string, req api.ActionRequest) (string, string, int, error) {
	if err := validateHookName(req.Action); err != nil {
		return "", "", 1, err
	}

	hookPath := filepath.Join(e.cfg.HooksDir, req.Action)

	if _, err := os.Stat(hookPath); errors.Is(err, os.ErrNotExist) {
		return "", "", 1, fmt.Errorf("hook not found: %s", req.Action)
	}

	ok, err := e.verifier.VerifyHook(ctx, nodeID, hookPath, req.Checksum)
	if err != nil {
		return "", "", 1, fmt.Errorf("integrity verification error: %w", err)
	}
	if !ok {
		return "", "", 1, fmt.Errorf("integrity check failed for hook: %s", req.Action)
	}

	cmd := exec.CommandContext(ctx, hookPath)
	cmd.WaitDelay = waitDelayAfterKill
	cmd.Env = e.buildHookEnv(nodeID, req)

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
func (e *Executor) buildHookEnv(nodeID string, req api.ActionRequest) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"PLEXD_NODE_ID=" + nodeID,
		"PLEXD_EXECUTION_ID=" + req.ExecutionID,
	}
	for name, value := range req.Parameters {
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
