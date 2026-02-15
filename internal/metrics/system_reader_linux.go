//go:build linux

package metrics

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// cpuSampleInterval is the delay between two /proc/stat reads for CPU usage calculation.
const cpuSampleInterval = 100 * time.Millisecond

// LinuxSystemReader reads system metrics from /proc and syscall on Linux.
type LinuxSystemReader struct {
	mountPoint string
	netIface   string
}

// NewLinuxSystemReader creates a new LinuxSystemReader.
// mountPoint is the filesystem path for disk stats (e.g., "/").
// netIface is the network interface for rx/tx bytes (e.g., "eth0"); empty means sum all interfaces.
func NewLinuxSystemReader(mountPoint, netIface string) *LinuxSystemReader {
	if mountPoint == "" {
		mountPoint = "/"
	}
	return &LinuxSystemReader{
		mountPoint: mountPoint,
		netIface:   netIface,
	}
}

// ReadStats reads system metrics from /proc and syscall.
func (r *LinuxSystemReader) ReadStats(ctx context.Context) (*SystemStats, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("metrics: system: %w", err)
	}

	stats := &SystemStats{}

	cpuPct, err := r.readCPU(ctx)
	if err != nil {
		return nil, fmt.Errorf("metrics: system: read /proc/stat: %w", err)
	}
	stats.CPUUsagePercent = cpuPct

	if err := r.readMeminfo(stats); err != nil {
		return nil, fmt.Errorf("metrics: system: read /proc/meminfo: %w", err)
	}

	if err := r.readLoadAvg(stats); err != nil {
		return nil, fmt.Errorf("metrics: system: read /proc/loadavg: %w", err)
	}

	if err := r.readDisk(stats); err != nil {
		return nil, fmt.Errorf("metrics: system: statfs %s: %w", r.mountPoint, err)
	}

	if err := r.readNetDev(stats); err != nil {
		return nil, fmt.Errorf("metrics: system: read /proc/net/dev: %w", err)
	}

	return stats, nil
}

// cpuTimes holds raw CPU tick values from /proc/stat.
type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

func (c cpuTimes) busy() uint64 {
	return c.total() - c.idle - c.iowait
}

// readCPU calculates CPU usage percentage by sampling /proc/stat twice with a 100ms delay.
func (r *LinuxSystemReader) readCPU(ctx context.Context) (float64, error) {
	t1, err := parseProcStat()
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

	t2, err := parseProcStat()
	if err != nil {
		return 0, err
	}

	totalDelta := t2.total() - t1.total()
	if totalDelta == 0 {
		return 0, nil
	}
	busyDelta := t2.busy() - t1.busy()
	pct := float64(busyDelta) / float64(totalDelta) * 100.0
	return pct, nil
}

func parseProcStat() (cpuTimes, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return cpuTimes{}, fmt.Errorf("unexpected /proc/stat cpu line: %s", line)
		}
		var t cpuTimes
		vals := []*uint64{&t.user, &t.nice, &t.system, &t.idle, &t.iowait, &t.irq, &t.softirq, &t.steal}
		for i, ptr := range vals {
			if i+1 >= len(fields) {
				break
			}
			v, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return cpuTimes{}, fmt.Errorf("parse /proc/stat field %d: %w", i, err)
			}
			*ptr = v
		}
		return t, nil
	}
	return cpuTimes{}, fmt.Errorf("/proc/stat: cpu line not found")
}

// readMeminfo reads MemTotal and MemAvailable from /proc/meminfo.
func (r *LinuxSystemReader) readMeminfo(stats *SystemStats) error {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return err
	}
	defer f.Close()

	var memTotal, memAvailable uint64
	found := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() && found < 2 {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					memTotal = v * 1024 // kB to bytes
					found++
				}
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					memAvailable = v * 1024
					found++
				}
			}
		}
	}

	stats.MemoryTotalBytes = memTotal
	if memTotal >= memAvailable {
		stats.MemoryUsedBytes = memTotal - memAvailable
	}
	return nil
}

// readLoadAvg reads /proc/loadavg for 1, 5, 15 minute load averages.
func (r *LinuxSystemReader) readLoadAvg(stats *SystemStats) error {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return fmt.Errorf("unexpected /proc/loadavg format")
	}
	stats.LoadAvg1, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return fmt.Errorf("parse load_avg_1: %w", err)
	}
	stats.LoadAvg5, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return fmt.Errorf("parse load_avg_5: %w", err)
	}
	stats.LoadAvg15, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return fmt.Errorf("parse load_avg_15: %w", err)
	}
	return nil
}

// readDisk reads disk usage via syscall.Statfs.
func (r *LinuxSystemReader) readDisk(stats *SystemStats) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(r.mountPoint, &st); err != nil {
		return err
	}
	stats.DiskTotalBytes = st.Blocks * uint64(st.Bsize)
	stats.DiskUsedBytes = (st.Blocks - st.Bfree) * uint64(st.Bsize)
	return nil
}

// readNetDev reads /proc/net/dev for network rx/tx bytes.
func (r *LinuxSystemReader) readNetDev(stats *SystemStats) error {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return err
	}
	defer f.Close()

	var totalRx, totalTx uint64
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // Skip header lines.
		}
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])

		// Skip loopback.
		if iface == "lo" {
			continue
		}

		// If a specific interface is configured, only count that one.
		if r.netIface != "" && iface != r.netIface {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		totalRx += rx
		totalTx += tx
	}

	stats.NetworkRxBytes = totalRx
	stats.NetworkTxBytes = totalTx
	return nil
}
