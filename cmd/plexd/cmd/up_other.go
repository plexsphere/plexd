//go:build !linux

package cmd

import (
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
)

// newSystemReader returns nil on non-Linux platforms.
func newSystemReader() metrics.SystemReader {
	return nil
}

// newJournalReader returns nil on non-Linux platforms.
func newJournalReader() logfwd.JournalReader {
	return nil
}
