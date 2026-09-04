//go:build darwin

package metrics

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

var _ SystemReader = (*DarwinSystemReader)(nil)

// fakeMach serves prepared Mach counters instead of calling the host port.
type fakeMach struct {
	loads   []cpuLoadInfo
	calls   int
	loadErr error
	vm      vmStatistics64
	vmErr   error
}

func (f *fakeMach) cpuLoad() (cpuLoadInfo, error) {
	if f.loadErr != nil {
		return cpuLoadInfo{}, f.loadErr
	}
	if len(f.loads) == 0 {
		return cpuLoadInfo{}, nil
	}
	i := f.calls
	if i >= len(f.loads) {
		i = len(f.loads) - 1
	}
	f.calls++
	return f.loads[i], nil
}

func (f *fakeMach) vmStatistics() (vmStatistics64, error) {
	if f.vmErr != nil {
		return vmStatistics64{}, f.vmErr
	}
	return f.vm, nil
}

// newTestDarwinReader returns a reader logging into the returned buffer.
func newTestDarwinReader(t *testing.T) (*DarwinSystemReader, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewDarwinSystemReader(logger, "/", ""), &buf
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

func TestDarwinSystemReader_ReadStats(t *testing.T) {
	reader, _ := newTestDarwinReader(t)
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

func TestDarwinSystemReader_CPUPercentRange(t *testing.T) {
	reader, _ := newTestDarwinReader(t)
	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.CPUUsagePercent < 0 || stats.CPUUsagePercent > 100 {
		t.Errorf("CPUUsagePercent = %v, want [0.0, 100.0]", stats.CPUUsagePercent)
	}
}

func TestDarwinSystemReader_LoadAvgPopulated(t *testing.T) {
	reader, _ := newTestDarwinReader(t)
	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.LoadAvg1 < 0 {
		t.Errorf("LoadAvg1 = %v, want >= 0", stats.LoadAvg1)
	}
	if stats.LoadAvg5 < 0 {
		t.Errorf("LoadAvg5 = %v, want >= 0", stats.LoadAvg5)
	}
	if stats.LoadAvg15 < 0 {
		t.Errorf("LoadAvg15 = %v, want >= 0", stats.LoadAvg15)
	}
}

func TestDarwinSystemReader_ContextCancelled(t *testing.T) {
	reader, _ := newTestDarwinReader(t)
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

func TestDarwinSystemReader_DefaultMountPoint(t *testing.T) {
	reader := NewDarwinSystemReader(discardLogger(), "", "")
	if reader.mountPoint != "/" {
		t.Errorf("mountPoint = %q, want %q", reader.mountPoint, "/")
	}
}

func TestDarwinSystemReader_SpecificInterface(t *testing.T) {
	// A non-existent interface leaves the counters at zero without failing the
	// whole reading.
	reader := NewDarwinSystemReader(discardLogger(), "/", "nonexistent0")
	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.NetworkRxBytes != 0 {
		t.Errorf("NetworkRxBytes = %d, want 0 (nonexistent interface)", stats.NetworkRxBytes)
	}
	if stats.NetworkTxBytes != 0 {
		t.Errorf("NetworkTxBytes = %d, want 0 (nonexistent interface)", stats.NetworkTxBytes)
	}
}

func TestMachHost_Real(t *testing.T) {
	m, err := openMachHost()
	if err != nil {
		t.Fatalf("openMachHost() error = %v", err)
	}

	load, err := m.cpuLoad()
	if err != nil {
		t.Fatalf("cpuLoad() error = %v", err)
	}
	var ticks uint64
	for _, v := range load.Ticks {
		ticks += uint64(v)
	}
	if ticks == 0 {
		t.Error("cpuLoad() ticks sum = 0, want > 0")
	}

	vm, err := m.vmStatistics()
	if err != nil {
		t.Fatalf("vmStatistics() error = %v", err)
	}
	if vm.FreeCount+vm.ActiveCount+vm.WireCount == 0 {
		t.Error("vmStatistics() free+active+wire = 0, want > 0")
	}

	if got := unsafe.Sizeof(vmStatistics64{}); got != 152 {
		t.Errorf("sizeof(vmStatistics64) = %d, want 152", got)
	}
}

func TestDarwinSystemReader_CPUTickWrap(t *testing.T) {
	reader, _ := newTestDarwinReader(t)
	reader.mach = &fakeMach{loads: []cpuLoadInfo{
		{Ticks: [4]uint32{0xFFFFFFF0, 0, 0x10, 0}},
		{Ticks: [4]uint32{0x10, 0, 0x20, 0}},
	}}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	// User ticks advanced by 0x20 across the wrap, idle ticks by 0x10.
	if math.Abs(stats.CPUUsagePercent-66.67) > 0.01 {
		t.Errorf("CPUUsagePercent = %v, want 66.67", stats.CPUUsagePercent)
	}
}

func TestDarwinSystemReader_CPUZeroDelta(t *testing.T) {
	reader, buf := newTestDarwinReader(t)
	reader.mach = &fakeMach{loads: []cpuLoadInfo{{Ticks: [4]uint32{100, 200, 300, 400}}}}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.CPUUsagePercent != 0 {
		t.Errorf("CPUUsagePercent = %v, want 0", stats.CPUUsagePercent)
	}
	if strings.Contains(buf.String(), "metric=cpu") {
		t.Errorf("log contains a cpu report, want none:\n%s", buf.String())
	}
}

func TestDarwinSystemReader_MachCallFailure(t *testing.T) {
	reader, buf := newTestDarwinReader(t)
	reader.mach = &fakeMach{
		loadErr: errors.New("kern_return_t 5"),
		vmErr:   errors.New("kern_return_t 5"),
	}

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.CPUUsagePercent != 0 {
		t.Errorf("CPUUsagePercent = %v, want 0", stats.CPUUsagePercent)
	}
	if stats.MemoryUsedBytes != 0 {
		t.Errorf("MemoryUsedBytes = %d, want 0", stats.MemoryUsedBytes)
	}
	if stats.MemoryTotalBytes == 0 {
		t.Error("MemoryTotalBytes = 0, want > 0")
	}
	if got := countLogLines(buf, "WARN", "cpu"); got != 1 {
		t.Errorf("WARN cpu lines = %d, want 1:\n%s", got, buf.String())
	}
	if got := countLogLines(buf, "WARN", "memory"); got != 1 {
		t.Errorf("WARN memory lines = %d, want 1:\n%s", got, buf.String())
	}
}

func TestDarwinSystemReader_MachUnavailable(t *testing.T) {
	reader, buf := newTestDarwinReader(t)
	reader.mach = nil
	reader.machErr = errors.New("mach host port unavailable: dlopen failed")

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.CPUUsagePercent != 0 {
		t.Errorf("CPUUsagePercent = %v, want 0", stats.CPUUsagePercent)
	}
	if stats.MemoryUsedBytes != 0 {
		t.Errorf("MemoryUsedBytes = %d, want 0", stats.MemoryUsedBytes)
	}
	if stats.MemoryTotalBytes == 0 {
		t.Error("MemoryTotalBytes = 0, want > 0")
	}

	if _, err := reader.ReadStats(context.Background()); err != nil {
		t.Fatalf("second ReadStats() error = %v", err)
	}
	for _, tc := range []struct {
		level, metric string
	}{
		{"WARN", "cpu"},
		{"WARN", "memory"},
		{"DEBUG", "cpu"},
		{"DEBUG", "memory"},
	} {
		if got := countLogLines(buf, tc.level, tc.metric); got != 1 {
			t.Errorf("%s %s lines = %d, want 1:\n%s", tc.level, tc.metric, got, buf.String())
		}
	}
}

func TestDarwinSystemReader_MemsizeUnavailable(t *testing.T) {
	reader, buf := newTestDarwinReader(t)
	reader.sysctlUint64 = func(string) (uint64, error) { return 0, unix.ENOENT }

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

func TestDarwinSystemReader_StatfsFailure(t *testing.T) {
	reader, buf := newTestDarwinReader(t)
	reader.mountPoint = filepath.Join(t.TempDir(), "missing")

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
	if !strings.Contains(buf.String(), "no such file or directory") {
		t.Errorf("log misses the statfs reason:\n%s", buf.String())
	}
}

func TestDarwinSystemReader_IfListFailure(t *testing.T) {
	reader, buf := newTestDarwinReader(t)
	reader.ifList = func() ([]byte, error) { return nil, unix.EINVAL }

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

func TestDarwinSystemReader_NamedInterfaceMissing(t *testing.T) {
	reader, buf := newTestDarwinReader(t)
	reader.netIface = "nonexistent0"

	stats, err := reader.ReadStats(context.Background())
	if err != nil {
		t.Fatalf("ReadStats() error = %v", err)
	}
	if stats.NetworkRxBytes != 0 || stats.NetworkTxBytes != 0 {
		t.Errorf("network counters = %d/%d, want 0/0", stats.NetworkRxBytes, stats.NetworkTxBytes)
	}
	if got := countLogLines(buf, "WARN", "network"); got != 1 {
		t.Errorf("WARN network lines = %d, want 1:\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), `nonexistent0\" not found`) {
		t.Errorf("log misses the missing interface name:\n%s", buf.String())
	}
}

func TestParseLoadAvg(t *testing.T) {
	raw := make([]byte, 24)
	binary.NativeEndian.PutUint32(raw[0:], 2048)
	binary.NativeEndian.PutUint32(raw[4:], 4096)
	binary.NativeEndian.PutUint32(raw[8:], 6144)
	binary.NativeEndian.PutUint64(raw[16:], 2048)

	loads, err := parseLoadAvg(raw)
	if err != nil {
		t.Fatalf("parseLoadAvg() error = %v", err)
	}
	want := [3]float64{1, 2, 3}
	if loads != want {
		t.Errorf("parseLoadAvg() = %v, want %v", loads, want)
	}
}

func TestParseLoadAvg_Short(t *testing.T) {
	_, err := parseLoadAvg(make([]byte, 8))
	if err == nil {
		t.Fatal("parseLoadAvg() error = nil, want error")
	}
	if got, want := err.Error(), "vm.loadavg: unexpected length 8"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestParseLoadAvg_ZeroScale(t *testing.T) {
	raw := make([]byte, 24)
	binary.NativeEndian.PutUint32(raw[0:], 2048)

	_, err := parseLoadAvg(raw)
	if err == nil {
		t.Fatal("parseLoadAvg() error = nil, want error")
	}
	if got, want := err.Error(), "vm.loadavg: zero fscale"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// ifInfoMessage serialises one RTM_IFINFO2 message followed by a 16-byte
// sockaddr_dl carrying name.
func ifInfoMessage(h unix.IfMsghdr2, name string) []byte {
	h.Msglen = unix.SizeofIfMsghdr2 + 16
	h.Type = unix.RTM_IFINFO2

	msg := make([]byte, 0, int(h.Msglen))
	msg = append(msg, (*[unix.SizeofIfMsghdr2]byte)(unsafe.Pointer(&h))[:]...)
	sdl := make([]byte, 16)
	sdl[5] = byte(len(name))
	copy(sdl[8:], name)
	return append(msg, sdl...)
}

func TestParseIfList(t *testing.T) {
	lo := unix.IfMsghdr2{Addrs: unix.RTA_IFP, Flags: unix.IFF_LOOPBACK}
	lo.Data.Ibytes = 5
	lo.Data.Obytes = 6
	en := unix.IfMsghdr2{Addrs: unix.RTA_IFP}
	en.Data.Ibytes = 100
	en.Data.Obytes = 200

	// A message of another type sits between the two, which also leaves the
	// second header at an offset that is not 8-byte aligned.
	other := make([]byte, 12)
	binary.NativeEndian.PutUint16(other[0:], 12)
	other[3] = unix.RTM_IFINFO

	buf := ifInfoMessage(lo, "lo0")
	buf = append(buf, other...)
	buf = append(buf, ifInfoMessage(en, "en0")...)

	rows, err := parseIfList(buf)
	if err != nil {
		t.Fatalf("parseIfList() error = %v", err)
	}
	want := []ifCounters{
		{name: "lo0", loopback: true, rx: 5, tx: 6},
		{name: "en0", loopback: false, rx: 100, tx: 200},
	}
	if len(rows) != len(want) {
		t.Fatalf("len(rows) = %d, want %d: %+v", len(rows), len(want), rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("rows[%d] = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestParseIfList_Empty(t *testing.T) {
	rows, err := parseIfList(nil)
	if err != nil {
		t.Fatalf("parseIfList() error = %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("len(rows) = %d, want 0", len(rows))
	}
}

func TestParseIfList_Truncated(t *testing.T) {
	buf := make([]byte, 8)
	binary.NativeEndian.PutUint16(buf[0:], 200)
	buf[3] = unix.RTM_IFINFO2

	_, err := parseIfList(buf)
	if err == nil {
		t.Fatal("parseIfList() error = nil, want error")
	}
	if got, want := err.Error(), "iflist: truncated message at offset 0"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestParseIfList_NoName(t *testing.T) {
	h := unix.IfMsghdr2{}
	h.Data.Ibytes = 7
	h.Data.Obytes = 8

	rows, err := parseIfList(ifInfoMessage(h, ""))
	if err != nil {
		t.Fatalf("parseIfList() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	want := ifCounters{name: "", loopback: false, rx: 7, tx: 8}
	if rows[0] != want {
		t.Errorf("rows[0] = %+v, want %+v", rows[0], want)
	}
}
