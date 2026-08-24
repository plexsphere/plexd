package actions

import (
	"io"
	"log/slog"
	"runtime"
	"testing"

	"go.uber.org/goleak"
)

// TestMain lives here rather than beside the integration tests so goroutine
// leak checking still covers this package on Windows, where the hook-script
// tests do not build.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// requireHookScripts skips a test that runs a hook script. Hooks are discovered
// by their executable bit and executed directly, so they are shell scripts with
// a #!/bin/sh line; Windows has neither the mode bit nor the interpreter.
func requireHookScripts(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("hook scripts need the executable bit and /bin/sh, which windows lacks")
	}
}
