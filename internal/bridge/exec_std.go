package bridge

import (
	"context"
	"errors"
	"os"
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
// that can be used to stop it. The process is waited for as soon as it
// exits, whether it ends by itself, through Stop or with ctx, so it leaves no
// zombie behind and the goroutine os/exec watches ctx with ends with it.
func (e *StdCommandExecutor) Start(ctx context.Context, name string, args ...string) (CommandHandle, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	h := &execHandle{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(h.done)
	}()
	return h, nil
}

// execHandle wraps an os/exec.Cmd for the CommandHandle interface.
type execHandle struct {
	cmd *exec.Cmd
	// done is closed once the process was waited for.
	done chan struct{}
}

// Stop kills the running process and returns once it was waited for. A
// process that already exited is no error, so Stop may be called again.
func (h *execHandle) Stop() error {
	if err := h.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	<-h.done
	return nil
}
