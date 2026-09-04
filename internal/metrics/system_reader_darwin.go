//go:build darwin

package metrics

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DarwinSystemReader reads system metrics from sysctl, statfs, the routing
// socket and the Mach host port on macOS.
type DarwinSystemReader struct {
	mountPoint string
	netIface   string
	degrade    *degradeLog

	// mach is nil when the host port could not be opened; machErr then holds
	// the reason and is reported on every reading of cpu and memory.
	mach    machStats
	machErr error

	// Seams over the operating system, replaced in tests.
	sysctlUint64 func(name string) (uint64, error)
	sysctlUint32 func(name string) (uint32, error)
	sysctlRaw    func(name string) ([]byte, error)
	statfs       func(path string, st *unix.Statfs_t) error
	ifList       func() ([]byte, error)
}

// NewDarwinSystemReader creates a new DarwinSystemReader.
// mountPoint is the filesystem path for disk stats (e.g., "/"); empty means "/".
// netIface is the network interface for rx/tx bytes (e.g., "en0"); empty means sum all non-loopback interfaces.
// Every source the reader touches is readable by an unprivileged process.
func NewDarwinSystemReader(logger *slog.Logger, mountPoint, netIface string) *DarwinSystemReader {
	if mountPoint == "" {
		mountPoint = "/"
	}

	r := &DarwinSystemReader{
		mountPoint: mountPoint,
		netIface:   netIface,
		degrade:    newDegradeLog(logger),
		sysctlUint64: func(name string) (uint64, error) {
			return unix.SysctlUint64(name)
		},
		sysctlUint32: unix.SysctlUint32,
		sysctlRaw: func(name string) ([]byte, error) {
			return unix.SysctlRaw(name)
		},
		statfs: unix.Statfs,
		ifList: func() ([]byte, error) {
			return syscall.RouteRIB(syscall.NET_RT_IFLIST2, 0) //nolint:staticcheck // x/net/route is not a dependency and sysctl by name cannot address net.route
		},
	}

	mach, err := openMachHost()
	if err != nil {
		r.machErr = fmt.Errorf("mach host port unavailable: %w", err)
	} else {
		r.mach = mach
	}
	return r
}

// ReadStats reads system metrics from sysctl, statfs, the routing socket and
// the Mach host port. Unlike the Linux reader it is best-effort by design: the
// five sources fail independently on macOS, so a failing one leaves its fields
// at zero and is logged once at warn level and at debug level afterwards, while
// the remaining fields are still reported. A cancelled context is the only
// error ReadStats returns.
func (r *DarwinSystemReader) ReadStats(ctx context.Context) (*SystemStats, error) {
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
	if err := r.readLoadAvg(stats); err != nil {
		r.degrade.report("load", err)
	}
	if err := r.readDisk(stats); err != nil {
		r.degrade.report("disk", err)
	}
	if err := r.readNetwork(stats); err != nil {
		r.degrade.report("network", err)
	}

	return stats, nil
}

// readCPU calculates CPU usage percentage by sampling the Mach tick counters
// twice with a cpuSampleInterval delay.
func (r *DarwinSystemReader) readCPU(ctx context.Context) (float64, error) {
	if r.mach == nil {
		return 0, r.machErr
	}

	t1, err := r.mach.cpuLoad()
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

	t2, err := r.mach.cpuLoad()
	if err != nil {
		return 0, err
	}

	// The per-state delta is computed in uint32, so a counter that wraps at
	// 2^32 between the two samples still yields the elapsed ticks.
	var total, idle uint64
	for _, state := range [...]int{cpuStateUser, cpuStateSystem, cpuStateIdle, cpuStateNice} {
		delta := uint64(t2.Ticks[state] - t1.Ticks[state])
		total += delta
		if state == cpuStateIdle {
			idle = delta
		}
	}
	if total == 0 {
		return 0, nil
	}
	return float64(total-idle) / float64(total) * 100.0, nil
}

// readMemory reads the total memory from sysctl and the page counters from the
// Mach host port. The total is written before the page counters are read, so an
// unavailable host port still reports the size of the machine.
func (r *DarwinSystemReader) readMemory(stats *SystemStats) error {
	total, err := r.sysctlUint64("hw.memsize")
	if err != nil {
		return fmt.Errorf("sysctl hw.memsize: %w", err)
	}
	stats.MemoryTotalBytes = total

	if r.mach == nil {
		return r.machErr
	}
	vm, err := r.mach.vmStatistics()
	if err != nil {
		return err
	}
	pageSize, err := r.sysctlUint32("hw.pagesize")
	if err != nil {
		return fmt.Errorf("sysctl hw.pagesize: %w", err)
	}

	// App memory plus wired plus compressed, the figure Activity Monitor shows
	// as "Memory Used" and the counterpart of Linux's MemTotal - MemAvailable.
	// top counts the file cache as used and reports a higher number.
	var anon uint64
	if vm.InternalPageCount > vm.PurgeableCount {
		anon = uint64(vm.InternalPageCount) - uint64(vm.PurgeableCount)
	}
	used := (anon + uint64(vm.WireCount) + uint64(vm.CompressorPageCount)) * uint64(pageSize)
	if used > total {
		used = total
	}
	stats.MemoryUsedBytes = used
	return nil
}

// parseLoadAvg decodes the vm.loadavg sysctl, a struct loadavg holding three
// fixed-point values and the scale they are expressed in.
func parseLoadAvg(raw []byte) ([3]float64, error) {
	// struct loadavg { fixpt_t ldavg[3]; long fscale; }: three uint32 at offset
	// 0, 4 and 8, then an int64 at offset 16 on both darwin architectures.
	const size = 24
	if len(raw) < size {
		return [3]float64{}, fmt.Errorf("vm.loadavg: unexpected length %d", len(raw))
	}
	// fscale is 2048 on every macOS release so far, but the kernel reports it.
	fscale := int64(binary.NativeEndian.Uint64(raw[16:]))
	if fscale == 0 {
		return [3]float64{}, fmt.Errorf("vm.loadavg: zero fscale")
	}

	var loads [3]float64
	for i := range loads {
		loads[i] = float64(binary.NativeEndian.Uint32(raw[4*i:])) / float64(fscale)
	}
	return loads, nil
}

// readLoadAvg reads the 1, 5 and 15 minute load averages from sysctl.
func (r *DarwinSystemReader) readLoadAvg(stats *SystemStats) error {
	raw, err := r.sysctlRaw("vm.loadavg")
	if err != nil {
		return fmt.Errorf("sysctl vm.loadavg: %w", err)
	}
	loads, err := parseLoadAvg(raw)
	if err != nil {
		return err
	}
	stats.LoadAvg1 = loads[0]
	stats.LoadAvg5 = loads[1]
	stats.LoadAvg15 = loads[2]
	return nil
}

// readDisk reads disk usage of the configured mount point via statfs.
func (r *DarwinSystemReader) readDisk(stats *SystemStats) error {
	var st unix.Statfs_t
	if err := r.statfs(r.mountPoint, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", r.mountPoint, err)
	}
	stats.DiskTotalBytes = st.Blocks * uint64(st.Bsize)
	stats.DiskUsedBytes = (st.Blocks - st.Bfree) * uint64(st.Bsize)
	return nil
}

// parseIfList decodes a NET_RT_IFLIST2 buffer into per-interface counters. The
// buffer is a sequence of routing messages; every message carries its length in
// the first two bytes and its type in the fourth, which is enough to walk past
// the ones that are not interface information.
func parseIfList(buf []byte) ([]ifCounters, error) {
	rows := []ifCounters{}

	for off := 0; off < len(buf); {
		if len(buf)-off < 4 {
			return nil, fmt.Errorf("iflist: truncated message at offset %d", off)
		}
		msglen := int(binary.NativeEndian.Uint16(buf[off:]))
		if msglen < 4 || off+msglen > len(buf) {
			return nil, fmt.Errorf("iflist: truncated message at offset %d", off)
		}
		if buf[off+3] != unix.RTM_IFINFO2 || msglen < unix.SizeofIfMsghdr2 {
			off += msglen
			continue
		}

		// The header is copied out instead of being cast in place: interface
		// messages routinely start at offsets that are not 8-byte aligned,
		// and IfMsghdr2 holds uint64 fields.
		var h unix.IfMsghdr2
		copy((*[unix.SizeofIfMsghdr2]byte)(unsafe.Pointer(&h))[:], buf[off:off+unix.SizeofIfMsghdr2])

		// The interface name follows the header as a sockaddr_dl: Nlen sits at
		// byte 5, the name itself starts at byte 8.
		name := ""
		if h.Addrs&unix.RTA_IFP != 0 && msglen >= unix.SizeofIfMsghdr2+8 {
			sdl := buf[off+unix.SizeofIfMsghdr2 : off+msglen]
			if nlen := int(sdl[5]); 8+nlen <= len(sdl) {
				name = string(sdl[8 : 8+nlen])
			}
		}

		rows = append(rows, ifCounters{
			name:     name,
			loopback: h.Flags&unix.IFF_LOOPBACK != 0,
			rx:       h.Data.Ibytes,
			tx:       h.Data.Obytes,
		})
		off += msglen
	}

	return rows, nil
}

// readNetwork reads the interface byte counters from the routing socket.
func (r *DarwinSystemReader) readNetwork(stats *SystemStats) error {
	buf, err := r.ifList()
	if err != nil {
		return fmt.Errorf("sysctl NET_RT_IFLIST2: %w", err)
	}
	rows, err := parseIfList(buf)
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
