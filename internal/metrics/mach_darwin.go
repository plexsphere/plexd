//go:build darwin

package metrics

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

// libSystemPath is the shared library that exports the Mach host calls. It is
// present on every macOS installation and is already mapped into the process.
const libSystemPath = "/usr/lib/libSystem.B.dylib"

// Flavors accepted by host_statistics and host_statistics64.
const (
	hostCPULoadInfo = 3 // HOST_CPU_LOAD_INFO
	hostVMInfo64    = 4 // HOST_VM_INFO64
)

// CPU states indexing cpuLoadInfo.Ticks.
const (
	cpuStateUser   = 0
	cpuStateSystem = 1
	cpuStateIdle   = 2
	cpuStateNice   = 3
)

// cpuLoadInfo is the host_cpu_load_info_data_t layout: cumulative tick counters
// for the four CPU states, summed over all cores.
type cpuLoadInfo struct {
	Ticks [4]uint32
}

// vmStatistics64 is the vm_statistics64 layout from <mach/vm_statistics.h>.
// Field order and width have to match the C struct exactly, because the kernel
// fills the memory by offset.
type vmStatistics64 struct {
	FreeCount                          uint32
	ActiveCount                        uint32
	InactiveCount                      uint32
	WireCount                          uint32
	ZeroFillCount                      uint64
	Reactivations                      uint64
	Pageins                            uint64
	Pageouts                           uint64
	Faults                             uint64
	CowFaults                          uint64
	Lookups                            uint64
	Hits                               uint64
	Purges                             uint64
	PurgeableCount                     uint32
	SpeculativeCount                   uint32
	Decompressions                     uint64
	Compressions                       uint64
	Swapins                            uint64
	Swapouts                           uint64
	CompressorPageCount                uint32
	ThrottledCount                     uint32
	ExternalPageCount                  uint32
	InternalPageCount                  uint32
	TotalUncompressedPagesInCompressor uint64
}

// machStats reads the host counters that sysctl does not expose. The reader
// holds the interface so tests can substitute a fake.
type machStats interface {
	cpuLoad() (cpuLoadInfo, error)
	vmStatistics() (vmStatistics64, error)
}

// machHost calls the Mach host statistics functions of libSystem through
// purego, which needs no cgo and therefore survives the CGO_ENABLED=0 release
// build.
type machHost struct {
	host             uint32
	hostStatistics   func(host uint32, flavor int32, info unsafe.Pointer, count *uint32) int32
	hostStatistics64 func(host uint32, flavor int32, info unsafe.Pointer, count *uint32) int32
}

var _ machStats = (*machHost)(nil)

// openMachHost loads libSystem, binds the host statistics symbols and acquires
// the host port. The port is a send right that stays valid for the lifetime of
// the process, so it is fetched once.
func openMachHost() (*machHost, error) {
	lib, err := purego.Dlopen(libSystemPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("dlopen %s: %w", libSystemPath, err)
	}

	m := &machHost{}
	var machHostSelf func() uint32
	for _, sym := range []struct {
		name string
		fn   any
	}{
		{"mach_host_self", &machHostSelf},
		{"host_statistics", &m.hostStatistics},
		{"host_statistics64", &m.hostStatistics64},
	} {
		if err := bindMachFunc(lib, sym.name, sym.fn); err != nil {
			return nil, err
		}
	}

	m.host = machHostSelf()
	return m, nil
}

// bindMachFunc points fn at the symbol name exported by lib. It resolves the
// address with purego.Dlsym instead of purego.RegisterLibFunc because the
// latter panics on a missing symbol, and openMachHost has to degrade to an
// error its caller can report.
func bindMachFunc(lib uintptr, name string, fn any) error {
	addr, err := purego.Dlsym(lib, name)
	if err != nil {
		return fmt.Errorf("dlsym %s: %w", name, err)
	}
	purego.RegisterFunc(fn, addr)
	return nil
}

// cpuLoad returns the cumulative CPU tick counters of the host.
func (m *machHost) cpuLoad() (cpuLoadInfo, error) {
	var info cpuLoadInfo
	count := uint32(4) // HOST_CPU_LOAD_INFO_COUNT, in 32-bit words.
	if kr := m.hostStatistics(m.host, hostCPULoadInfo, unsafe.Pointer(&info), &count); kr != 0 {
		return cpuLoadInfo{}, fmt.Errorf("host_statistics(HOST_CPU_LOAD_INFO): kern_return_t %d", kr)
	}
	return info, nil
}

// vmStatistics returns the virtual memory page counters of the host.
func (m *machHost) vmStatistics() (vmStatistics64, error) {
	var info vmStatistics64
	count := uint32(unsafe.Sizeof(vmStatistics64{}) / 4) // HOST_VM_INFO64_COUNT.
	if kr := m.hostStatistics64(m.host, hostVMInfo64, unsafe.Pointer(&info), &count); kr != 0 {
		return vmStatistics64{}, fmt.Errorf("host_statistics64(HOST_VM_INFO64): kern_return_t %d", kr)
	}
	return info, nil
}
