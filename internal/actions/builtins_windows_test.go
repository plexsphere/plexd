//go:build windows

package actions

import (
	"context"
	"errors"
	"testing"
)

func TestBuiltinServiceReloadConfig_Unsupported(t *testing.T) {
	fn := ServiceReloadConfig()
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if !errors.Is(err, errReloadSignalUnsupported) {
		t.Fatalf("expected errReloadSignalUnsupported, got %v", err)
	}
	if want := "actions: reload config: reload signal not supported on windows; restart the service instead"; err.Error() != want {
		t.Errorf("error text = %q, want %q", err.Error(), want)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout, got %q", stdout)
	}
	if stderr != "" {
		t.Errorf("expected empty stderr, got %q", stderr)
	}
}
