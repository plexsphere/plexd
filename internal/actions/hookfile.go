package actions

import (
	"fmt"
	"time"
)

// MaxHookTimeout is the largest timeout a sidecar can declare, the contract's
// 86400 seconds as a duration.
const MaxHookTimeout = 24 * time.Hour

// ParseHookTimeout parses a sidecar's timeout. The empty string means none
// declared and is checked first, because time.ParseDuration refuses it. The
// manifest and the run both call this, so they agree on what a usable timeout
// is.
func ParseHookTimeout(timeout string) (time.Duration, error) {
	if timeout == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(timeout)
	if err != nil {
		return 0, err
	}
	if d < 0 || d > MaxHookTimeout {
		return 0, fmt.Errorf("timeout %s is outside the range 0 to %s", d, MaxHookTimeout)
	}
	return d, nil
}
