// Package metrics provides metrics collection and reporting for plexd mesh nodes.
package metrics

import (
	"errors"
	"time"
)

// DefaultCollectInterval is the default interval between metric collection cycles.
const DefaultCollectInterval = 30 * time.Second

// DefaultReportInterval is the default interval between reporting metrics to the control plane.
const DefaultReportInterval = 60 * time.Second

// DefaultBatchSize is the default maximum number of metric points per report batch.
const DefaultBatchSize = 100

// Config holds the configuration for metrics collection and reporting.
type Config struct {
	// Enabled controls whether metrics collection is active.
	// Default: true (set by ApplyDefaults).
	Enabled bool

	// CollectInterval is the interval between collection cycles.
	// Must be at least 5s.
	CollectInterval time.Duration

	// ReportInterval is the interval between reporting to the control plane.
	// Must be at least 10s and >= CollectInterval.
	ReportInterval time.Duration

	// BatchSize is the maximum number of metric points per report batch.
	// Must be > 0. Default: 100.
	BatchSize int
}

// ApplyDefaults sets default values for zero-valued fields.
// On a zero-valued Config, Enabled defaults to true.
// To disable metrics, set Enabled=false before or after calling ApplyDefaults.
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
		return errors.New("metrics: config: CollectInterval must be at least 5s")
	}
	if c.ReportInterval < 10*time.Second {
		return errors.New("metrics: config: ReportInterval must be at least 10s")
	}
	if c.ReportInterval < c.CollectInterval {
		return errors.New("metrics: config: ReportInterval must be >= CollectInterval")
	}
	if c.BatchSize <= 0 {
		return errors.New("metrics: config: BatchSize must be > 0")
	}
	return nil
}
