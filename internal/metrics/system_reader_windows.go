//go:build windows

package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// x/sys/windows carries no binding for GetSystemTimes and GlobalMemoryStatusEx,
// so both are resolved from kernel32 at first use. NewLazySystemDLL loads the
// library from System32 only, which keeps a DLL of the same name next to the
// binary out of the search path.
var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// memoryStatusEx is the MEMORYSTATUSEX layout GlobalMemoryStatusEx fills in.
// Length holds the size of the structure, 64 bytes, and is set before the call.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// getSystemTimes returns the system-wide idle, kernel and user times in 100ns
// units. The kernel time includes the idle time, so the busy time is kernel
// plus user minus idle.
func getSystemTimes() (idle, kernel, user uint64, err error) {
	if err := procGetSystemTimes.Find(); err != nil {
		return 0, 0, 0, err
	}

	var idleFT, kernelFT, userFT windows.Filetime
	r1, _, lastErr := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleFT)),
		uintptr(unsafe.Pointer(&kernelFT)),
		uintptr(unsafe.Pointer(&userFT)),
	)
	if r1 == 0 {
		return 0, 0, 0, fmt.Errorf("GetSystemTimes: %w", lastErr)
	}

	ticks := func(ft windows.Filetime) uint64 {
		return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	}
	return ticks(idleFT), ticks(kernelFT), ticks(userFT), nil
}

// globalMemoryStatusEx returns the total and the available physical memory in
// bytes.
func globalMemoryStatusEx() (total, avail uint64, err error) {
	if err := procGlobalMemoryStatusEx.Find(); err != nil {
		return 0, 0, err
	}

	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r1, _, lastErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r1 == 0 {
		return 0, 0, fmt.Errorf("GlobalMemoryStatusEx: %w", lastErr)
	}
	return ms.TotalPhys, ms.AvailPhys, nil
}

// diskFreeSpace returns the capacity and the free bytes of the volume holding
// path.
func diskFreeSpace(path string) (total, free uint64, err error) {
	dir, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}

	var freeToCaller, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(dir, &freeToCaller, &total, &totalFree); err != nil {
		return 0, 0, fmt.Errorf("GetDiskFreeSpaceEx %s: %w", path, err)
	}
	return total, totalFree, nil
}

// winipcfgIfTable reads the interface table through the IP Helper API and
// reduces it to byte counters. GetIfTable2Ex frees the native table itself.
func winipcfgIfTable() ([]ifCounters, error) {
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil {
		return nil, fmt.Errorf("GetIfTable2Ex: %w", err)
	}

	// The rows are walked by index because Alias reads a fixed-size array out
	// of the row and needs an addressable receiver.
	counters := make([]ifCounters, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		counters = append(counters, ifCounters{
			name:     row.Alias(),
			loopback: row.Type == winipcfg.IfTypeSoftwareLoopback,
			rx:       row.InOctets,
			tx:       row.OutOctets,
		})
	}
	return counters, nil
}

// defaultWindowsMountPoint returns the root of the system volume, the rule
// diskRootPath applies in internal/actions.
func defaultWindowsMountPoint() string {
	if drive := os.Getenv("SystemDrive"); drive != "" {
		return drive + `\`
	}
	return `C:\`
}

// WindowsSystemReader reads system metrics from kernel32 and the IP Helper API
// on Windows.
type WindowsSystemReader struct {
	mountPoint string
	netIface   string
	degrade    *degradeLog

	// Seams over the operating system, replaced in tests.
	systemTimes   func() (idle, kernel, user uint64, err error)
	memoryStatus  func() (total, avail uint64, err error)
	diskFreeSpace func(path string) (total, free uint64, err error)
	ifTable       func() ([]ifCounters, error)
}

// NewWindowsSystemReader creates a new WindowsSystemReader.
// mountPoint is the filesystem path for disk stats (e.g., "C:\"); empty means the root of %SystemDrive%.
// netIface is the network adapter for rx/tx bytes (e.g., "Ethernet"); empty means sum all non-loopback adapters.
// Every source the reader touches is readable by an unprivileged process.
func NewWindowsSystemReader(logger *slog.Logger, mountPoint, netIface string) *WindowsSystemReader {
	if mountPoint == "" {
		mountPoint = defaultWindowsMountPoint()
	}

	return &WindowsSystemReader{
		mountPoint:    mountPoint,
		netIface:      netIface,
		degrade:       newDegradeLog(logger),
		systemTimes:   getSystemTimes,
		memoryStatus:  globalMemoryStatusEx,
		diskFreeSpace: diskFreeSpace,
		ifTable:       winipcfgIfTable,
	}
}

// ReadStats reads system metrics from kernel32 and the IP Helper API. Like the
// macOS reader it is best-effort by design: the four sources fail
// independently, so a failing one leaves its fields at zero and is logged once
// at warn level and at debug level afterwards, while the remaining fields are
// still reported. Windows keeps no load average, so LoadAvg1, LoadAvg5 and
// LoadAvg15 always stay 0 and nothing is reported for them. A cancelled context
// is the only error ReadStats returns.
func (r *WindowsSystemReader) ReadStats(ctx context.Context) (*SystemStats, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("metrics: system: %w", err)
	}

	stats := &SystemStats{}

	cpuPct, err := r.readCPU(ctx)
	switch {
	case err != nil && ctx.Err() != nil:
		// Cancellation during the sample interval surfaces to the caller.
		return nil, fmt.Errorf("metrics: system: %w", ctx.Err())
	case err != nil:
		r.degrade.report("cpu", err)
	default:
		stats.CPUUsagePercent = cpuPct
	}

	if err := r.readMemory(stats); err != nil {
		r.degrade.report("memory", err)
	}
	if err := r.readDisk(stats); err != nil {
		r.degrade.report("disk", err)
	}
	if err := r.readNetwork(stats); err != nil {
		r.degrade.report("network", err)
	}

	return stats, nil
}

// readCPU calculates CPU usage percentage by sampling the system times twice
// with a cpuSampleInterval delay.
func (r *WindowsSystemReader) readCPU(ctx context.Context) (float64, error) {
	idle1, kernel1, user1, err := r.systemTimes()
	if err != nil {
		return 0, err
	}

	timer := time.NewTimer(cpuSampleInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
	}

	idle2, kernel2, user2, err := r.systemTimes()
	if err != nil {
		return 0, err
	}

	// GetSystemTimes sums the per-processor counters, and the sum is neither an
	// atomic snapshot across processors nor monotonic: a processor leaving the
	// group takes its accumulated ticks out of the sum. Every delta is
	// therefore checked before it is taken, because the counters are unsigned
	// and an underflow would report a CPU usage of about 1.8e21.
	if kernel2 < kernel1 || user2 < user1 || idle2 < idle1 {
		return 0, fmt.Errorf("GetSystemTimes: counters went backwards")
	}

	// The kernel delta already contains the idle delta, so the two deltas add
	// up to the whole elapsed time of every processor.
	total := (kernel2 - kernel1) + (user2 - user1)
	if total == 0 {
		return 0, nil
	}
	// A processor whose idle ticks land in the second sample but whose busy
	// ticks land in the first leaves an idle delta above the window; the host
	// was idle, so the busy time is zero rather than negative.
	idle := idle2 - idle1
	if idle > total {
		idle = total
	}
	return float64(total-idle) / float64(total) * 100.0, nil
}

// readMemory reads the physical memory counters from GlobalMemoryStatusEx.
func (r *WindowsSystemReader) readMemory(stats *SystemStats) error {
	total, avail, err := r.memoryStatus()
	if err != nil {
		return err
	}
	stats.MemoryTotalBytes = total
	if total >= avail {
		stats.MemoryUsedBytes = total - avail
	}
	return nil
}

// readDisk reads disk usage of the configured mount point.
func (r *WindowsSystemReader) readDisk(stats *SystemStats) error {
	total, free, err := r.diskFreeSpace(r.mountPoint)
	if err != nil {
		return err
	}
	stats.DiskTotalBytes = total
	if total >= free {
		stats.DiskUsedBytes = total - free
	}
	return nil
}

// readNetwork reads the adapter byte counters from the interface table.
func (r *WindowsSystemReader) readNetwork(stats *SystemStats) error {
	rows, err := r.ifTable()
	if err != nil {
		return err
	}
	rx, tx, found := sumIfCounters(rows, r.netIface)
	if !found && r.netIface != "" {
		return fmt.Errorf("interface %q not found", r.netIface)
	}
	stats.NetworkRxBytes = rx
	stats.NetworkTxBytes = tx
	return nil
}
