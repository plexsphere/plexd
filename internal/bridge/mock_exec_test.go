package bridge

import (
	"context"
	"sync"
)

// execCall records a single method invocation on mockCommandExecutor.
type execCall struct {
	Method string
	Name   string
	Args   []string
}

// mockRunResult pairs output and error for sequential Run results.
type mockRunResult struct {
	Output []byte
	Err    error
}

// mockCommandHandle is a test double for CommandHandle.
type mockCommandHandle struct {
	stopErr error
}

func (h *mockCommandHandle) Stop() error {
	return h.stopErr
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

func (m *mockCommandExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callList = append(m.callList, execCall{Method: "Run", Name: name, Args: args})

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

func (m *mockCommandExecutor) Start(_ context.Context, name string, args ...string) (CommandHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callList = append(m.callList, execCall{Method: "Start", Name: name, Args: args})

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

// Verify mockCommandExecutor satisfies CommandExecutor at compile time.
var _ CommandExecutor = (*mockCommandExecutor)(nil)

// Verify mockCommandHandle satisfies CommandHandle at compile time.
var _ CommandHandle = (*mockCommandHandle)(nil)
