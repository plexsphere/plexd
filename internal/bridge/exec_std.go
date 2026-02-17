package bridge

import (
	"context"
	"os/exec"
)

// StdCommandExecutor implements CommandExecutor using os/exec.
type StdCommandExecutor struct{}

// NewStdCommandExecutor returns a new StdCommandExecutor.
func NewStdCommandExecutor() *StdCommandExecutor {
	return &StdCommandExecutor{}
}

// Run executes the named command with the given arguments and returns its
// combined stdout/stderr output.
func (e *StdCommandExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Start launches the named command asynchronously and returns a handle
// that can be used to stop it.
func (e *StdCommandExecutor) Start(ctx context.Context, name string, args ...string) (CommandHandle, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &execHandle{cmd: cmd}, nil
}

// execHandle wraps an os/exec.Cmd for the CommandHandle interface.
type execHandle struct {
	cmd *exec.Cmd
}

// Stop kills the running process.
func (h *execHandle) Stop() error {
	if h.cmd.Process == nil {
		return nil
	}
	return h.cmd.Process.Kill()
}
