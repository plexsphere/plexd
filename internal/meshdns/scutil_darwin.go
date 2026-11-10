//go:build darwin

package meshdns

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// The tools flushDNSCache runs: Apple's documented way to empty the DNS
// cache is dscacheutil -flushcache followed by a HUP to mDNSResponder.
const (
	dscacheutilPath = "/usr/bin/dscacheutil"
	killallPath     = "/usr/bin/killall"
)

// NewScutilRegistrar returns the Registrar for macOS hosts, which writes the
// mesh resolver's entries into configd's dynamic store with scutil. It runs
// nothing until the first Apply or Revert.
func NewScutilRegistrar(logger *slog.Logger) *ScutilRegistrar {
	if logger == nil {
		logger = slog.Default()
	}
	return &ScutilRegistrar{
		logger: logger.With("component", "meshdns"),
		run:    execScutil,
		flush:  flushDNSCache,
	}
}

// execScutil runs scutil with script on stdin and returns its combined
// output.
func execScutil(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, scutilPath)
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

// flushDNSCache empties the host's DNS cache. mDNSResponder keeps one cache
// for the whole host, so a negative answer the host's own servers gave for a
// mesh name before plexd registered would otherwise outlive the registration.
func flushDNSCache(ctx context.Context) error {
	if err := exec.CommandContext(ctx, dscacheutilPath, "-flushcache").Run(); err != nil {
		return fmt.Errorf("dscacheutil -flushcache: %w", err)
	}
	if err := exec.CommandContext(ctx, killallPath, "-HUP", "mDNSResponder").Run(); err != nil {
		return fmt.Errorf("killall -HUP mDNSResponder: %w", err)
	}
	return nil
}
