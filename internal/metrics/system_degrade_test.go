package metrics

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestDegradeLog_WarnOnceThenDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := newDegradeLog(logger)

	readErr := errors.New("sysctl denied")
	d.report("cpu", readErr)
	d.report("cpu", readErr)
	d.report("disk", readErr)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("len(lines) = %d, want 3 (output: %q)", len(lines), buf.String())
	}

	var warnCPU, warnDisk, debugCPU int
	for _, line := range lines {
		if !strings.Contains(line, "component=metrics") {
			t.Errorf("line missing component=metrics: %q", line)
		}
		if !strings.Contains(line, "error=") {
			t.Errorf("line missing error=: %q", line)
		}
		switch {
		case strings.Contains(line, "level=WARN") && strings.Contains(line, "metric=cpu"):
			warnCPU++
		case strings.Contains(line, "level=WARN") && strings.Contains(line, "metric=disk"):
			warnDisk++
		case strings.Contains(line, "level=DEBUG") && strings.Contains(line, "metric=cpu"):
			debugCPU++
		default:
			t.Errorf("unexpected line: %q", line)
		}
	}

	if warnCPU != 1 {
		t.Errorf("WARN lines for metric=cpu = %d, want 1", warnCPU)
	}
	if warnDisk != 1 {
		t.Errorf("WARN lines for metric=disk = %d, want 1", warnDisk)
	}
	if debugCPU != 1 {
		t.Errorf("DEBUG lines for metric=cpu = %d, want 1", debugCPU)
	}
}

func TestDegradeLog_NilLogger(t *testing.T) {
	newDegradeLog(nil).report("cpu", errors.New("x"))
}
