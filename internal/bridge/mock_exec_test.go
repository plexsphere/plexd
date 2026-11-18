package bridge

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// execCall records a single method invocation on mockCommandExecutor.
type execCall struct {
	Method string
	Name   string
	Args   []string

	// HasDeadline records whether the call's context carried a deadline, and
	// DeadlineIn how far away that deadline was when the call was made. Both
	// are zero for a context without one.
	HasDeadline bool
	DeadlineIn  time.Duration
}

// newExecCall records a call to method under ctx.
func newExecCall(ctx context.Context, method, name string, args []string) execCall {
	c := execCall{Method: method, Name: name, Args: args}
	if d, ok := ctx.Deadline(); ok {
		c.HasDeadline = true
		c.DeadlineIn = time.Until(d)
	}
	return c
}

// mockRunResult pairs output and error for sequential Run results.
type mockRunResult struct {
	Output []byte
	Err    error
}

// mockCommandHandle is a test double for CommandHandle. It counts the calls
// to Stop.
type mockCommandHandle struct {
	stopErr error

	mu    sync.Mutex
	stops int
}

func (h *mockCommandHandle) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stops++
	return h.stopErr
}

// stopCalls returns how often Stop was called.
func (h *mockCommandHandle) stopCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stops
}

// mockCommandExecutor is a test double for CommandExecutor.
// It records all calls and supports configurable return values and errors.
//
// Two modes for Run results:
//  1. Map-based: set runOutputs/runErrors keyed by "name arg1 arg2 ...".
//  2. Sequential: set runResults to a list of mockRunResult consumed in order.
//
// Sequential mode takes precedence when runResults is non-empty.
type mockCommandExecutor struct {
	mu       sync.Mutex
	callList []execCall

	// Map-based mode: keyed by "name arg1 arg2...".
	runOutputs map[string][]byte
	runErrors  map[string]error

	// Sequential mode: consumed in order.
	runResults []mockRunResult
	runIndex   int

	// startHandle is the handle returned by Start.
	startHandle CommandHandle
	// startErr is the error returned by Start.
	startErr error
}

func newMockCommandExecutor() *mockCommandExecutor {
	return &mockCommandExecutor{
		runOutputs: make(map[string][]byte),
		runErrors:  make(map[string]error),
	}
}

// commandKey builds a lookup key from name and args.
func commandKey(name string, args ...string) string {
	key := name
	for _, a := range args {
		key += " " + a
	}
	return key
}

func (m *mockCommandExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callList = append(m.callList, newExecCall(ctx, "Run", name, args))

	// Sequential mode takes precedence.
	if len(m.runResults) > 0 && m.runIndex < len(m.runResults) {
		r := m.runResults[m.runIndex]
		m.runIndex++
		return r.Output, r.Err
	}

	key := commandKey(name, args...)
	out := m.runOutputs[key]
	err := m.runErrors[key]
	return out, err
}

func (m *mockCommandExecutor) Start(ctx context.Context, name string, args ...string) (CommandHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callList = append(m.callList, newExecCall(ctx, "Start", name, args))

	return m.startHandle, m.startErr
}

// execCallsFor returns all recorded calls for the given method name.
func (m *mockCommandExecutor) execCallsFor(method string) []execCall {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []execCall
	for _, c := range m.callList {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

// allCalls returns a copy of all recorded calls.
func (m *mockCommandExecutor) allCalls() []execCall {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]execCall, len(m.callList))
	copy(result, m.callList)
	return result
}

// callLines renders each recorded call as its method, its command name and
// its arguments, for comparing whole command lines.
func callLines(calls []execCall) [][]string {
	lines := make([][]string, 0, len(calls))
	for _, c := range calls {
		lines = append(lines, append([]string{c.Method, c.Name}, c.Args...))
	}
	return lines
}

// assertCallDeadline fails t unless call ran under a context whose deadline
// was more than lo and at most hi away. A zero hi wants no deadline at all.
func assertCallDeadline(t *testing.T, call execCall, lo, hi time.Duration) {
	t.Helper()

	line := strings.Join(append([]string{call.Name}, call.Args...), " ")
	if hi == 0 {
		if call.HasDeadline {
			t.Errorf("%s ran under a deadline %v away, want none", line, call.DeadlineIn)
		}
		return
	}
	if !call.HasDeadline {
		t.Errorf("%s ran without a deadline, want one in (%v, %v]", line, lo, hi)
		return
	}
	if call.DeadlineIn <= lo || call.DeadlineIn > hi {
		t.Errorf("%s ran under a deadline %v away, want one in (%v, %v]", line, call.DeadlineIn, lo, hi)
	}
}

// Verify mockCommandExecutor satisfies CommandExecutor at compile time.
var _ CommandExecutor = (*mockCommandExecutor)(nil)

// Verify mockCommandHandle satisfies CommandHandle at compile time.
var _ CommandHandle = (*mockCommandHandle)(nil)
