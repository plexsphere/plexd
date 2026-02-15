//go:build linux

package cmd

import (
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
)

// newSystemReader creates a LinuxSystemReader on Linux.
func newSystemReader() metrics.SystemReader {
	return metrics.NewLinuxSystemReader("", "")
}

// newJournalReader creates a JournalctlReader on Linux.
func newJournalReader() logfwd.JournalReader {
	return logfwd.NewJournalctlReader()
}
