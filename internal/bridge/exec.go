package bridge

import "context"

// CommandExecutor abstracts command execution for testability.
type CommandExecutor interface {
	// Run executes a command and returns its combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// Start starts a command without waiting for it to complete.
	// Returns a CommandHandle that can be used to stop the process.
	Start(ctx context.Context, name string, args ...string) (CommandHandle, error)
}

// CommandHandle represents a running process.
type CommandHandle interface {
	// Stop terminates the process.
	Stop() error
}
