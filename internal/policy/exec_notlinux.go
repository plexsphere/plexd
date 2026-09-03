//go:build darwin || windows

package policy

import (
	"bytes"
	"context"
	"os/exec"
)

// commandRunner runs one host command with the given stdin and returns its
// combined stdout and stderr. It is a seam: execCommand drives the real
// binary, tests record the arguments and the stdin instead.
type commandRunner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// execCommand is the commandRunner that drives a real binary.
func execCommand(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}
