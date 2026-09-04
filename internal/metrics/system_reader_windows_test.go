//go:build windows

package metrics

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ SystemReader = (*WindowsSystemReader)(nil)

// newTestWindowsReader returns a reader logging into the returned buffer.
func newTestWindowsReader(t *testing.T) (*WindowsSystemReader, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewWindowsSystemReader(logger, "", ""), &buf
}

// countLogLines counts the logged lines carrying both the level and the metric.
func countLogLines(buf *bytes.Buffer, level, metric string) int {
	n := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "level="+level) && strings.Contains(line, "metric="+metric) {
			n++
		}
	}
	return n
}

func TestWindowsSystemReader_ReadStats(t *testing.T) {
	reader, _ := newTestWindowsReader(t)
	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}

	if stats.MemoryTotalBytes == 0 {
		t.Error("MemoryTotalBytes = 0, want > 0")
	}
	if stats.MemoryUsedBytes == 0 {
		t.Error("MemoryUsedBytes = 0, want > 0")
	}
	if stats.DiskTotalBytes == 0 {
		t.Error("DiskTotalBytes = 0, want > 0")
	}
	if stats.DiskUsedBytes == 0 {
		t.Error("DiskUsedBytes = 0, want > 0")
	}
}

func TestWindowsSystemReader_CPUPercentRange(t *testing.T) {
	reader, _ := newTestWindowsReader(t)
	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.CPUUsagePercent < 0 || stats.CPUUsagePercent > 100 {
		t.Errorf("CPUUsagePercent = %v, want [0.0, 100.0]", stats.CPUUsagePercent)
	}
}

func TestWindowsSystemReader_LoadAvgZero(t *testing.T) {
	// Windows keeps no load average, so the three fields stay at their zero
	// value and are never reported as unavailable.
	reader, _ := newTestWindowsReader(t)
	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.LoadAvg1 != 0 {
		t.Errorf("LoadAvg1 = %v, want 0", stats.LoadAvg1)
	}
	if stats.LoadAvg5 != 0 {
		t.Errorf("LoadAvg5 = %v, want 0", stats.LoadAvg5)
	}
	if stats.LoadAvg15 != 0 {
		t.Errorf("LoadAvg15 = %v, want 0", stats.LoadAvg15)
	}
}

func TestWindowsSystemReader_ContextCancelled(t *testing.T) {
	reader, _ := newTestWindowsReader(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stats, err := reader.ReadStats(ctx)
	if stats != nil {
		t.Errorf("stats = %v, want nil", stats)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ReadStats() error = %v, want context.Canceled", err)
	}
}

func TestWindowsSystemReader_DefaultMountPoint(t *testing.T) {
	reader := NewWindowsSystemReader(discardLogger(), "", "")
	want := os.Getenv("SystemDrive") + `\`
	if reader.mountPoint != want {
		t.Errorf("mountPoint = %q, want %q", reader.mountPoint, want)
	}
}

func TestWindowsSystemReader_SpecificInterface(t *testing.T) {
	// A non-existent adapter leaves the counters at zero without failing the
	// whole reading.
	reader := NewWindowsSystemReader(discardLogger(), "", "nonexistent0")
	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.NetworkRxBytes != 0 {
		t.Errorf("NetworkRxBytes = %d, want 0 (nonexistent adapter)", stats.NetworkRxBytes)
	}
	if stats.NetworkTxBytes != 0 {
		t.Errorf("NetworkTxBytes = %d, want 0 (nonexistent adapter)", stats.NetworkTxBytes)
	}
}

func TestMemoryStatusExSize(t *testing.T) {
	if got := unsafe.Sizeof(memoryStatusEx{}); got != 64 {
		t.Errorf("sizeof(memoryStatusEx) = %d, want 64", got)
	}
}

func TestWindowsSystemReader_CPUFromSystemTimes(t *testing.T) {
	reader, _ := newTestWindowsReader(t)
	// Between the two samples kernel advances by 100 and user by 100, of which
	// 50 were idle.
	samples := [][3]uint64{{100, 400, 200}, {150, 500, 300}}
	calls := 0
	reader.systemTimes = func() (uint64, uint64, uint64, error) {
		i := calls
		if i >= len(samples) {
			i = len(samples) - 1
		}
		calls++
		return samples[i][0], samples[i][1], samples[i][2], nil
	}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if math.Abs(stats.CPUUsagePercent-75.0) > 0.01 {
		t.Errorf("CPUUsagePercent = %v, want 75.0", stats.CPUUsagePercent)
	}
}

// TestWindowsSystemReader_CPUCounterSkew pins the two ways the unsigned
// GetSystemTimes deltas can leave the [0, 100] range: an idle delta above the
// busy window, which an idle host reaches on a tick of skew between the
// per-processor counters, and counters that go backwards when a processor
// leaves the group.
func TestWindowsSystemReader_CPUCounterSkew(t *testing.T) {
	tests := []struct {
		name     string
		samples  [][3]uint64
		wantPct  float64
		wantWarn int
	}{
		{
			// Idle host: kernel advances by 100 and user not at all, while the
			// idle sum advances by 101.
			name:    "idle delta above the window",
			samples: [][3]uint64{{100, 400, 200}, {201, 500, 200}},
			wantPct: 0,
		},
		{
			name:     "kernel counter goes backwards",
			samples:  [][3]uint64{{100, 500, 200}, {150, 400, 300}},
			wantPct:  0,
			wantWarn: 1,
		},
		{
			name:     "idle counter goes backwards",
			samples:  [][3]uint64{{100, 400, 200}, {50, 500, 300}},
			wantPct:  0,
			wantWarn: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader, buf := newTestWindowsReader(t)
			samples := tc.samples
			calls := 0
			reader.systemTimes = func() (uint64, uint64, uint64, error) {
				i := calls
				if i >= len(samples) {
					i = len(samples) - 1
				}
				calls++
				return samples[i][0], samples[i][1], samples[i][2], nil
			}

			stats, err := reader.ReadStats(context.Background())
			if err != nil {
				t.Fatalf("ReadStats() error = %v", err)
			}
			if stats.CPUUsagePercent != tc.wantPct {
				t.Errorf("CPUUsagePercent = %v, want %v", stats.CPUUsagePercent, tc.wantPct)
			}
			if got := countLogLines(buf, "WARN", "cpu"); got != tc.wantWarn {
				t.Errorf("WARN cpu lines = %d, want %d:\n%s", got, tc.wantWarn, buf.String())
			}
		})
	}
}

func TestWindowsSystemReader_SystemTimesFailure(t *testing.T) {
	reader, buf := newTestWindowsReader(t)
	reader.systemTimes = func() (uint64, uint64, uint64, error) {
		return 0, 0, 0, windows.ERROR_ACCESS_DENIED
	}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.CPUUsagePercent != 0 {
		t.Errorf("CPUUsagePercent = %v, want 0", stats.CPUUsagePercent)
	}
	if got := countLogLines(buf, "WARN", "cpu"); got != 1 {
		t.Errorf("WARN cpu lines = %d, want 1:\n%s", got, buf.String())
	}
}

func TestWindowsSystemReader_MemoryStatusFailure(t *testing.T) {
	reader, buf := newTestWindowsReader(t)
	reader.memoryStatus = func() (uint64, uint64, error) {
		return 0, 0, errors.New("kernel32 unavailable")
	}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.MemoryTotalBytes != 0 {
		t.Errorf("MemoryTotalBytes = %d, want 0", stats.MemoryTotalBytes)
	}
	if stats.MemoryUsedBytes != 0 {
		t.Errorf("MemoryUsedBytes = %d, want 0", stats.MemoryUsedBytes)
	}
	if got := countLogLines(buf, "WARN", "memory"); got != 1 {
		t.Errorf("WARN memory lines = %d, want 1:\n%s", got, buf.String())
	}
}

func TestWindowsSystemReader_DiskFailure(t *testing.T) {
	reader, buf := newTestWindowsReader(t)
	reader.mountPoint = `Q:\plexd-missing\`

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.DiskTotalBytes != 0 {
		t.Errorf("DiskTotalBytes = %d, want 0", stats.DiskTotalBytes)
	}
	if stats.DiskUsedBytes != 0 {
		t.Errorf("DiskUsedBytes = %d, want 0", stats.DiskUsedBytes)
	}
	if got := countLogLines(buf, "WARN", "disk"); got != 1 {
		t.Errorf("WARN disk lines = %d, want 1:\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), "GetDiskFreeSpaceEx") {
		t.Errorf("log misses the failing call:\n%s", buf.String())
	}
}

func TestWindowsSystemReader_IfTableFailure(t *testing.T) {
	reader, buf := newTestWindowsReader(t)
	reader.ifTable = func() ([]ifCounters, error) { return nil, windows.ERROR_NOT_SUPPORTED }

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.NetworkRxBytes != 0 {
		t.Errorf("NetworkRxBytes = %d, want 0", stats.NetworkRxBytes)
	}
	if stats.NetworkTxBytes != 0 {
		t.Errorf("NetworkTxBytes = %d, want 0", stats.NetworkTxBytes)
	}
	if got := countLogLines(buf, "WARN", "network"); got != 1 {
		t.Errorf("WARN network lines = %d, want 1:\n%s", got, buf.String())
	}
}

func TestWindowsSystemReader_NetworkExcludesLoopback(t *testing.T) {
	reader, _ := newTestWindowsReader(t)
	reader.ifTable = func() ([]ifCounters, error) {
		return []ifCounters{
			{name: "Loopback Pseudo-Interface 1", loopback: true, rx: 5, tx: 6},
			{name: "Ethernet", rx: 100, tx: 200},
			{name: "Wi-Fi", rx: 10, tx: 20},
		}, nil
	}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.NetworkRxBytes != 110 {
		t.Errorf("NetworkRxBytes = %d, want 110", stats.NetworkRxBytes)
	}
	if stats.NetworkTxBytes != 220 {
		t.Errorf("NetworkTxBytes = %d, want 220", stats.NetworkTxBytes)
	}
}

func TestWindowsSystemReader_NamedInterface(t *testing.T) {
	reader, _ := newTestWindowsReader(t)
	reader.netIface = "Ethernet"
	reader.ifTable = func() ([]ifCounters, error) {
		return []ifCounters{
			{name: "Ethernet", rx: 100, tx: 200},
			{name: "Wi-Fi", rx: 10, tx: 20},
		}, nil
	}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.NetworkRxBytes != 100 {
		t.Errorf("NetworkRxBytes = %d, want 100", stats.NetworkRxBytes)
	}
	if stats.NetworkTxBytes != 200 {
		t.Errorf("NetworkTxBytes = %d, want 200", stats.NetworkTxBytes)
	}
}
