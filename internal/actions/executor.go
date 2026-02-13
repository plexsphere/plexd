package actions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// ActionReporter abstracts control plane communication for testability.
type ActionReporter interface {
	AckExecution(ctx context.Context, nodeID, executionID string, ack api.ExecutionAck) error
	ReportResult(ctx context.Context, nodeID, executionID string, result api.ExecutionResult) error
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

	ack := api.ExecutionAck{
		ExecutionID: req.ExecutionID,
		Status:      "accepted",
	}
	if err := e.reporter.AckExecution(ctx, nodeID, req.ExecutionID, ack); err != nil {
		e.logger.Warn("failed to send accepted ack",
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

	ack := api.ExecutionAck{
		ExecutionID: req.ExecutionID,
		Status:      "rejected",
		Reason:      reason,
	}
	if err := e.reporter.AckExecution(ctx, nodeID, req.ExecutionID, ack); err != nil {
		e.logger.Warn("failed to send rejected ack",
			"execution_id", req.ExecutionID,
			"error", err,
		)
	}
}

// determineStatus maps the result of an action execution to a status string.
func determineStatus(runErr error, exitCode int, timeoutCtx, parentCtx context.Context) string {
	if runErr != nil {
		if timeoutCtx.Err() == context.DeadlineExceeded {
			return "timeout"
		}
		if parentCtx.Err() == context.Canceled {
			return "cancelled"
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return "failed"
		}
		return "error"
	}
	if exitCode != 0 {
		return "failed"
	}
	return "success"
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
			e.logger.Error("panic in action execution",
				"execution_id", req.ExecutionID,
				"panic", fmt.Sprintf("%v", r),
			)
			result := api.ExecutionResult{
				ExecutionID: req.ExecutionID,
				Status:      "error",
				Stderr:      fmt.Sprintf("panic: %v", r),
				FinishedAt:  time.Now().UTC(),
				TriggeredBy: req.TriggeredBy,
			}
			if err := e.reporter.ReportResult(ctx, nodeID, req.ExecutionID, result); err != nil {
				e.logger.Warn("failed to report panic result",
					"execution_id", req.ExecutionID,
					"error", err,
				)
			}
		}
	}()

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
	status := determineStatus(runErr, exitCode, timeoutCtx, ctx)

	result := api.ExecutionResult{
		ExecutionID: req.ExecutionID,
		Status:      status,
		ExitCode:    exitCode,
		Stdout:      stdout,
		Stderr:      stderr,
		Duration:    duration.String(),
		FinishedAt:  time.Now().UTC(),
		TriggeredBy: req.TriggeredBy,
	}

	if err := e.reporter.ReportResult(ctx, nodeID, req.ExecutionID, result); err != nil {
		e.logger.Warn("failed to report result",
			"execution_id", req.ExecutionID,
			"error", err,
		)
	}

	e.logger.Info("action completed",
		"execution_id", req.ExecutionID,
		"status", status,
		"duration", duration,
	)
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
