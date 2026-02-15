//go:build linux

package logfwd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// JournalctlReader implements JournalReader by running the journalctl subprocess.
// It tracks cursor position to avoid re-reading entries across collection cycles.
type JournalctlReader struct {
	cursor string
}

// NewJournalctlReader creates a new JournalctlReader.
func NewJournalctlReader() *JournalctlReader {
	return &JournalctlReader{}
}

// ReadEntries runs journalctl and parses JSON output.
// On the first call, it reads entries from the last 60 seconds.
// Subsequent calls read entries after the stored cursor.
func (r *JournalctlReader) ReadEntries(ctx context.Context) ([]JournalEntry, error) {
	args := []string{"--output=json", "--no-pager", "-n", "1000"}
	if r.cursor != "" {
		args = append(args, "--after-cursor="+r.cursor)
	} else {
		args = append(args, "--since=60 seconds ago")
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.Output()
	if err != nil {
		// Check if journalctl is not found.
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("logfwd: journal: journalctl not found: %w", err)
		}
		return nil, fmt.Errorf("logfwd: journal: %w", err)
	}

	var entries []JournalEntry
	scanner := bufio.NewScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue // Skip malformed lines.
		}

		entry := JournalEntry{}

		if msg, ok := raw["MESSAGE"].(string); ok {
			entry.Message = msg
		}
		if unit, ok := raw["_SYSTEMD_UNIT"].(string); ok {
			entry.Unit = unit
		}
		if priStr, ok := raw["PRIORITY"].(string); ok {
			if pri, err := strconv.Atoi(priStr); err == nil {
				entry.Priority = pri
			}
		}

		// Parse __REALTIME_TIMESTAMP (microseconds since epoch).
		if tsStr, ok := raw["__REALTIME_TIMESTAMP"].(string); ok {
			if usec, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
				entry.Timestamp = time.Unix(0, usec*1000) // usec to nsec
			}
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now()
		}

		// Track cursor for next call.
		if cursor, ok := raw["__CURSOR"].(string); ok {
			r.cursor = cursor
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
