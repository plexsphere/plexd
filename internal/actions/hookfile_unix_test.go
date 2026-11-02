//go:build unix

package actions

import (
	"testing"
	"time"
)

func TestParseHookTimeout(t *testing.T) {
	valid := []struct {
		timeout string
		want    time.Duration
	}{
		{"", 0},
		{"0s", 0},
		{"24h", 24 * time.Hour},
	}
	for _, tt := range valid {
		t.Run("valid "+tt.timeout, func(t *testing.T) {
			got, err := ParseHookTimeout(tt.timeout)
			if err != nil {
				t.Fatalf("ParseHookTimeout(%q): %v", tt.timeout, err)
			}
			if got != tt.want {
				t.Errorf("ParseHookTimeout(%q) = %s, want %s", tt.timeout, got, tt.want)
			}
		})
	}

	_, parseErr := time.ParseDuration("30")
	invalid := []struct {
		timeout string
		want    string
	}{
		{"30", parseErr.Error()},
		{"-1s", "timeout -1s is outside the range 0 to 24h0m0s"},
		{"25h", "timeout 25h0m0s is outside the range 0 to 24h0m0s"},
	}
	for _, tt := range invalid {
		t.Run("invalid "+tt.timeout, func(t *testing.T) {
			got, err := ParseHookTimeout(tt.timeout)
			if err == nil {
				t.Fatalf("ParseHookTimeout(%q) = %s, want an error", tt.timeout, got)
			}
			if err.Error() != tt.want {
				t.Errorf("ParseHookTimeout(%q) error = %q, want %q", tt.timeout, err, tt.want)
			}
		})
	}
}
