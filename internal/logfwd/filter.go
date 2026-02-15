package logfwd

import (
	"context"

	"github.com/plexsphere/plexd/internal/api"
)

// severityPriority maps severity strings to numeric priority (lower = more severe).
var severityPriority = map[string]int{
	"emerg":   0,
	"alert":   1,
	"crit":    2,
	"err":     3,
	"warning": 4,
	"notice":  5,
	"info":    6,
	"debug":   7,
}

// FilterConfig defines log filtering rules.
type FilterConfig struct {
	// MinSeverity drops entries below this severity level.
	// Empty string means no severity filtering.
	MinSeverity string

	// IncludeUnits, if non-empty, only passes entries matching one of these unit names.
	IncludeUnits []string

	// ExcludeUnits drops entries matching any of these unit names.
	ExcludeUnits []string
}

// IsEmpty returns true if no filtering rules are configured.
func (fc *FilterConfig) IsEmpty() bool {
	return fc.MinSeverity == "" && len(fc.IncludeUnits) == 0 && len(fc.ExcludeUnits) == 0
}

// FilteringSource wraps a LogSource and applies filter rules to its output.
type FilteringSource struct {
	inner  LogSource
	config FilterConfig
}

// NewFilteringSource creates a filtering wrapper around a LogSource.
func NewFilteringSource(inner LogSource, config FilterConfig) *FilteringSource {
	return &FilteringSource{inner: inner, config: config}
}

// Collect reads from the inner source and applies filters.
func (f *FilteringSource) Collect(ctx context.Context) ([]api.LogEntry, error) {
	entries, err := f.inner.Collect(ctx)
	if err != nil {
		return nil, err
	}

	if f.config.IsEmpty() {
		return entries, nil
	}

	filtered := make([]api.LogEntry, 0, len(entries))
	for _, e := range entries {
		if f.match(e) {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

// match returns true if the entry passes all configured filters.
func (f *FilteringSource) match(e api.LogEntry) bool {
	// Severity filter.
	if f.config.MinSeverity != "" {
		minPri, ok := severityPriority[f.config.MinSeverity]
		if ok {
			entryPri, ok2 := severityPriority[e.Severity]
			if !ok2 {
				entryPri = severityPriority["info"] // Default unknown severity to info.
			}
			if entryPri > minPri {
				return false
			}
		}
	}

	// Include units filter.
	if len(f.config.IncludeUnits) > 0 {
		matched := false
		for _, u := range f.config.IncludeUnits {
			if e.Unit == u {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Exclude units filter.
	for _, u := range f.config.ExcludeUnits {
		if e.Unit == u {
			return false
		}
	}

	return true
}
