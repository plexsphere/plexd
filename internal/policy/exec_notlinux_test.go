//go:build darwin || windows

package policy

import (
	"context"
	"sync"
)

// runnerCall records one invocation: the binary, its arguments and its stdin.
type runnerCall struct {
	Name  string
	Args  []string
	Stdin string
}

// recordingRunner is a commandRunner that records calls and answers from maps
// keyed by commandKey; an unmapped key yields nil output and nil error. It
// also records whether each context carried a deadline, so a test can assert
// that the controller bounds every host command it runs.
type recordingRunner struct {
	mu        sync.Mutex
	calls     []runnerCall
	outputs   map[string][]byte
	errs      map[string]error
	deadlines []bool
}

// newRecordingRunner returns a runner with empty answer maps, so a test only
// fills in the commands whose output or error it cares about.
func newRecordingRunner() *recordingRunner {
	return &recordingRunner{
		outputs: make(map[string][]byte),
		errs:    make(map[string]error),
	}
}

// Run records the call and answers from the maps. Its signature matches
// commandRunner, so a test wires it in as the controller's runner.
func (r *recordingRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, runnerCall{Name: name, Args: args, Stdin: string(stdin)})
	_, hasDeadline := ctx.Deadline()
	r.deadlines = append(r.deadlines, hasDeadline)

	key := commandKey(name, args...)
	return r.outputs[key], r.errs[key]
}

// callsFor returns the recorded calls whose Name equals name.
func (r *recordingRunner) callsFor(name string) []runnerCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []runnerCall
	for _, c := range r.calls {
		if c.Name == name {
			result = append(result, c)
		}
	}
	return result
}

// commandKey joins name and args with single spaces, the same shape
// internal/bridge/mock_exec_test.go uses.
func commandKey(name string, args ...string) string {
	key := name
	for _, a := range args {
		key += " " + a
	}
	return key
}
