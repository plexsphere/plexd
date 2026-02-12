// Package logfwd provides log forwarding from plexd mesh nodes to the control plane.
package logfwd

import (
	"errors"
	"time"
)

// DefaultCollectInterval is the default interval between log collection cycles.
const DefaultCollectInterval = 10 * time.Second

// DefaultReportInterval is the default interval between reporting logs to the control plane.
const DefaultReportInterval = 30 * time.Second

// DefaultBatchSize is the default maximum number of log entries per report batch.
const DefaultBatchSize = 200

// Config holds the configuration for log forwarding.
type Config struct {
	// Enabled controls whether log forwarding is active.
	// Default: true (set by ApplyDefaults).
	Enabled bool

	// CollectInterval is the interval between collection cycles.
	// Must be at least 5s.
	CollectInterval time.Duration

	// ReportInterval is the interval between reporting to the control plane.
	// Must be >= CollectInterval.
	ReportInterval time.Duration

	// BatchSize is the maximum number of log entries per report batch.
	// Must be at least 1. Default: 200.
	BatchSize int
}

// ApplyDefaults sets default values for zero-valued fields.
// On a zero-valued Config, Enabled defaults to true.
// To disable log forwarding, set Enabled=false before or after calling ApplyDefaults.
func (c *Config) ApplyDefaults() {
	// Enabled defaults to true for zero-valued Config. Since bool zero is false,
	// we use a heuristic: if all fields are zero, the caller wants defaults (including Enabled=true).
	// If any field is non-zero, the caller constructed the config explicitly and we respect Enabled as-is.
	if c.CollectInterval == 0 && c.ReportInterval == 0 && c.BatchSize == 0 {
		c.Enabled = true
	}
	if c.CollectInterval == 0 {
		c.CollectInterval = DefaultCollectInterval
	}
	if c.ReportInterval == 0 {
		c.ReportInterval = DefaultReportInterval
	}
	if c.BatchSize == 0 {
		c.BatchSize = DefaultBatchSize
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.CollectInterval < 5*time.Second {
		return errors.New("logfwd: config: CollectInterval must be at least 5s")
	}
	if c.ReportInterval < c.CollectInterval {
		return errors.New("logfwd: config: ReportInterval must be >= CollectInterval")
	}
	if c.BatchSize < 1 {
		return errors.New("logfwd: config: BatchSize must be at least 1")
	}
	return nil
}
