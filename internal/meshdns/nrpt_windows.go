//go:build windows

package meshdns

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// The two stores the DNS Client reads rules from, under HKEY_LOCAL_MACHINE,
// and the values plexd writes into each rule, as NetBird's Windows
// configurator writes them. The Group Policy store replaces the local one
// while its key exists.
const (
	nrptLocalPath  = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptPolicyPath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

	nrptVersion       = 2
	nrptConfigOptions = 0x8

	// regOptionVolatile is REG_OPTION_VOLATILE: the key lives in memory
	// only, so a reboot clears it.
	regOptionVolatile = 0x1
	// rpForce is RP_FORCE: RefreshPolicyEx reapplies every policy, changed
	// or not.
	rpForce = 0x1
)

// golang.org/x/sys/windows/registry creates only non-volatile keys
// (registry.CreateKey), so the volatile rule keys go through RegCreateKeyExW.
// The userenv.dll and dnsapi.dll calls have no binding in x/sys. Each call
// runs Find first, because LazyProc.Call panics on a missing procedure.
var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modUserenv  = windows.NewLazySystemDLL("userenv.dll")
	modDNSAPI   = windows.NewLazySystemDLL("dnsapi.dll")

	procRegCreateKeyExW          = modAdvapi32.NewProc("RegCreateKeyExW")
	procGenerateGPNotification   = modUserenv.NewProc("GenerateGPNotification")
	procRefreshPolicyEx          = modUserenv.NewProc("RefreshPolicyEx")
	procRegisterGPNotification   = modUserenv.NewProc("RegisterGPNotification")
	procUnregisterGPNotification = modUserenv.NewProc("UnregisterGPNotification")
	procDNSFlushResolverCache    = modDNSAPI.NewProc("DnsFlushResolverCache")
)

// NewNRPTRegistrar returns the Registrar for Windows hosts, which writes the
// mesh resolver's rules into the Name Resolution Policy Table and the search
// domain into the mesh adapter's search list. It touches nothing on the host
// until the first Apply or Revert.
func NewNRPTRegistrar(logger *slog.Logger) *NRPTRegistrar {
	if logger == nil {
		logger = slog.Default()
	}
	return &NRPTRegistrar{
		logger: logger.With("component", "meshdns"),
		host:   winNRPTHost{},
	}
}

// winNRPTHost is the nrptHost of a real Windows host.
type winNRPTHost struct{}

// nrptStorePath returns the registry path of store under HKEY_LOCAL_MACHINE.
func nrptStorePath(store nrptStore) string {
	if store == nrptPolicy {
		return nrptPolicyPath
	}
	return nrptLocalPath
}

func (winNRPTHost) policyStoreExists() (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptPolicyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_ = k.Close()
	return true, nil
}

func (winNRPTHost) listRules(store nrptStore) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptStorePath(store), registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	return k.ReadSubKeyNames(-1)
}

func (winNRPTHost) readRule(store nrptStore, name string) ([]string, string, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptStorePath(store)+`\`+name, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = k.Close() }()

	version, _, err := k.GetIntegerValue("Version")
	if missingValue(err) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	options, _, err := k.GetIntegerValue("ConfigOptions")
	if missingValue(err) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	namespaces, _, err := k.GetStringsValue("Name")
	if missingValue(err) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	servers, _, err := k.GetStringValue("GenericDNSServers")
	if missingValue(err) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	if version != nrptVersion || options != nrptConfigOptions {
		return nil, "", false, nil
	}
	return namespaces, servers, true, nil
}

// missingValue reports whether err says a value is absent or of another
// type, either of which makes plexd write the rule again.
func missingValue(err error) bool {
	return errors.Is(err, registry.ErrNotExist) || errors.Is(err, registry.ErrUnexpectedType)
}

// writeRule replaces the rule key with a volatile one. The local store's key
// is created when missing, non-volatile, because a volatile parent would make
// Windows refuse every non-volatile rule an operator adds later
// (ERROR_CHILD_MUST_BE_VOLATILE). The Group Policy store's key is only
// opened: creating it would switch the host into Group Policy mode.
func (winNRPTHost) writeRule(store nrptStore, rule nrptRule) error {
	const access = registry.CREATE_SUB_KEY | registry.ENUMERATE_SUB_KEYS
	var parent registry.Key
	var err error
	if store == nrptLocal {
		parent, _, err = registry.CreateKey(registry.LOCAL_MACHINE, nrptLocalPath, access)
	} else {
		parent, err = registry.OpenKey(registry.LOCAL_MACHINE, nrptPolicyPath, access)
	}
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()

	if err := registry.DeleteKey(parent, rule.name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	k, err := createVolatileKey(parent, rule.name)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.SetDWordValue("Version", nrptVersion); err != nil {
		return err
	}
	if err := k.SetStringsValue("Name", rule.namespaces); err != nil {
		return err
	}
	if err := k.SetStringValue("GenericDNSServers", rule.servers); err != nil {
		return err
	}
	return k.SetDWordValue("ConfigOptions", nrptConfigOptions)
}

// createVolatileKey creates the subkey name of parent with
// REG_OPTION_VOLATILE, opened for setting values.
func createVolatileKey(parent registry.Key, name string) (registry.Key, error) {
	if err := procRegCreateKeyExW.Find(); err != nil {
		return 0, err
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var key windows.Handle
	var disposition uint32
	ret, _, _ := procRegCreateKeyExW.Call(
		uintptr(parent),
		uintptr(unsafe.Pointer(name16)),
		0, // Reserved
		0, // lpClass
		regOptionVolatile,
		uintptr(registry.QUERY_VALUE|registry.SET_VALUE),
		0, // lpSecurityAttributes
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if ret != 0 {
		return 0, windows.Errno(ret)
	}
	return registry.Key(key), nil
}

func (winNRPTHost) deleteRule(store nrptStore, name string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptStorePath(store)+`\`+name)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

func (winNRPTHost) policyStoreEmpty() (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptPolicyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = k.Close() }()
	info, err := k.Stat()
	if err != nil {
		return false, err
	}
	return info.SubKeyCount == 0 && info.ValueCount == 0, nil
}

func (winNRPTHost) deletePolicyStore() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptPolicyPath)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

// setSearchList sets the adapter's per-interface IPv4 search list, as
// WireGuard for Windows does for its own search domains. The mesh is IPv4,
// and the adapter carries no DNS server for the call to clear.
func (winNRPTHost) setSearchList(iface string, domains []string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(ifaces, func(ifi net.Interface) bool { return ifi.Name == iface })
	if i < 0 {
		return errAdapterGone
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(ifaces[i].Index))
	if err != nil {
		return err
	}
	return luid.SetDNS(windows.AF_INET, nil, domains)
}

// generateGPNotification broadcasts a machine policy change without running
// the policy engine. Per Tailscale's code it refuses any caller but
// LocalSystem. It returns a Win32 error code.
func (winNRPTHost) generateGPNotification() error {
	if err := procGenerateGPNotification.Find(); err != nil {
		return err
	}
	product, err := windows.UTF16PtrFromString("plexd")
	if err != nil {
		return err
	}
	ret, _, _ := procGenerateGPNotification.Call(1, uintptr(unsafe.Pointer(product)), 0)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}

// refreshPolicy runs the machine policy engine, which on a domain-joined
// host contacts a domain controller.
func (winNRPTHost) refreshPolicy() error {
	if err := procRefreshPolicyEx.Find(); err != nil {
		return err
	}
	ret, _, callErr := procRefreshPolicyEx.Call(1, rpForce)
	if ret == 0 {
		return falseResult("RefreshPolicyEx", callErr)
	}
	return nil
}

func (winNRPTHost) flush() error {
	if err := procDNSFlushResolverCache.Find(); err != nil {
		return err
	}
	ret, _, callErr := procDNSFlushResolverCache.Call()
	if ret == 0 {
		return falseResult("DnsFlushResolverCache", callErr)
	}
	return nil
}

// watchPolicy registers an auto-reset event for machine policy changes and
// calls onChange from a goroutine whenever it is signalled. The stop event
// comes first in the wait, because the wait reports the lowest signalled
// index, so a stop wins over a change. The returned stop function waits for
// the goroutine, and with it a running onChange, before it unregisters and
// closes both events.
func (winNRPTHost) watchPolicy(onChange func()) (func(), error) {
	for _, proc := range []*windows.LazyProc{procRegisterGPNotification, procUnregisterGPNotification} {
		if err := proc.Find(); err != nil {
			return nil, err
		}
	}
	done, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	changed, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(done)
		return nil, err
	}
	if ret, _, callErr := procRegisterGPNotification.Call(uintptr(changed), 1); ret == 0 {
		_ = windows.CloseHandle(changed)
		_ = windows.CloseHandle(done)
		return nil, falseResult("RegisterGPNotification", callErr)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			event, err := windows.WaitForMultipleObjects([]windows.Handle{done, changed}, false, windows.INFINITE)
			if err != nil || event != windows.WAIT_OBJECT_0+1 {
				return
			}
			onChange()
		}
	})
	return func() {
		_ = windows.SetEvent(done)
		wg.Wait()
		_, _, _ = procUnregisterGPNotification.Call(uintptr(changed))
		_ = windows.CloseHandle(changed)
		_ = windows.CloseHandle(done)
	}, nil
}

// falseResult returns the error of a call that returned FALSE: its last
// error, or a plain statement when that is 0.
func falseResult(name string, callErr error) error {
	var errno windows.Errno
	if callErr == nil || (errors.As(callErr, &errno) && errno == 0) {
		return fmt.Errorf("%s returned FALSE", name)
	}
	return callErr
}
