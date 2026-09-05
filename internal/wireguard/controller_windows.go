//go:build windows

package wireguard

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/plexsphere/plexd/internal/wintundll"
)

// plexd's adapters carry their own tunnel type in the Wintun registry, so an
// operator reading the host's adapters can tell them from the ones another
// WireGuard application created.
func init() {
	tun.WintunTunnelType = "plexd"
}

// adapterVisibleTimeout bounds how long CreateInterface waits for a fresh
// adapter to resolve by name, adapterVisiblePoll is the interval between
// attempts. The wait exists because Windows settles the IP stack a moment after
// the adapter appears, while the callers that run next resolve it by name and
// never retry: the route controller's LookupLUID and the WFP enforcer's
// lookupWinIface.
const (
	adapterVisibleTimeout = 10 * time.Second
	adapterVisiblePoll    = 200 * time.Millisecond
)

// wintunDevice is what a Wintun tun device offers beyond tun.Device: the
// adapter's LUID, which is how the IP Helper API addresses an interface, and a
// hook to tell the running device about an MTU change. Both are methods on
// wireguard-go's *tun.NativeTun; the interface exists so a test can supply
// them.
type wintunDevice interface {
	LUID() uint64
	ForceMTU(int)
}

// ipConfigurator programs an interface's addresses and MTU through the IP
// Helper API. It is a seam: production drives the real API, tests record the
// calls, which is what makes the controller testable without Administrator.
type ipConfigurator interface {
	AddIPAddress(luid uint64, prefix netip.Prefix) error
	SetMTU(luid uint64, mtu int) error
}

// WindowsController implements WGController on Windows. It creates a Wintun
// adapter with wireguard-go's tun.CreateTUN, runs it through UserspaceBackend,
// and programs the address and the MTU through the IP Helper API.
//
// Unlike macOS, the adapter carries the configured interface name, so there is
// no kernel name to map and the controller does not implement OSInterfaceNamer:
// the readiness check resolves the configured name directly.
type WindowsController struct {
	backend *UserspaceBackend
	logger  *slog.Logger

	mu       sync.Mutex
	adapters map[string]*wintunAdapter

	// createTUN, ensureDLL and ipcfg are seams: production wires them to
	// wireguard-go, the embedded driver and the IP Helper API, tests to fakes.
	// lookup is the seam for the visibility wait, production net.InterfaceByName,
	// and visibleTimeout bounds that wait.
	createTUN      func(name string, mtu int) (tun.Device, error)
	ensureDLL      func() (string, bool, error)
	ipcfg          ipConfigurator
	lookup         func(name string) (*net.Interface, error)
	visibleTimeout time.Duration
}

// wintunAdapter is one live adapter: the LUID the IP Helper API addresses it
// by, and the running device's MTU hook.
type wintunAdapter struct {
	luid     uint64
	forceMTU func(int)
}

// NewWindowsController returns a controller wired to the real Wintun adapter,
// the embedded driver and the host's IP Helper API.
func NewWindowsController(logger *slog.Logger) *WindowsController {
	return &WindowsController{
		backend:  NewUserspaceBackend(logger),
		logger:   logger,
		adapters: make(map[string]*wintunAdapter),
		createTUN: func(name string, mtu int) (tun.Device, error) {
			return tun.CreateTUNWithRequestedGUID(name, adapterGUID(name), mtu)
		},
		ensureDLL:      ensureDLLBesideExecutable,
		ipcfg:          winipcfgConfigurator{},
		lookup:         net.InterfaceByName,
		visibleTimeout: adapterVisibleTimeout,
	}
}

// ensureDLLBesideExecutable writes the embedded Wintun driver into the
// directory of the running executable, the only place besides System32 that
// its loader searches.
func ensureDLLBesideExecutable() (string, bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	return wintundll.Ensure(filepath.Dir(exe))
}

// adapterGUID derives the adapter's GUID from the interface name. Wintun mints
// a fresh GUID when none is requested, and Windows then treats every run's
// adapter as a new network, registering another profile ("Network 2", "Network
// 3", ...) and applying that profile's firewall category to it. Deriving the
// GUID from the name keeps one profile for the life of the interface.
func adapterGUID(name string) *windows.GUID {
	sum := sha256.Sum256([]byte("plexd wintun adapter: " + name))
	return &windows.GUID{
		Data1: binary.LittleEndian.Uint32(sum[0:4]),
		Data2: binary.LittleEndian.Uint16(sum[4:6]),
		Data3: binary.LittleEndian.Uint16(sum[6:8]),
		Data4: [8]byte(sum[8:16]),
	}
}

// winipcfgConfigurator programs the real IP Helper API.
type winipcfgConfigurator struct{}

// AddIPAddress assigns a unicast address to the interface, which is
// CreateUnicastIpAddressEntry. Windows installs the on-link route for the
// address's own prefix with it.
func (winipcfgConfigurator) AddIPAddress(luid uint64, prefix netip.Prefix) error {
	return winipcfg.LUID(luid).AddIPAddress(prefix)
}

// SetMTU sets the interface MTU for both address families, which is
// SetIpInterfaceEntry. wireguard-go's Windows tun keeps its MTU in a field of
// its own and never programs the interface, so this is the only thing that
// does.
func (winipcfgConfigurator) SetMTU(luid uint64, mtu int) error {
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, err := winipcfg.LUID(luid).IPInterface(family)
		if err != nil {
			// IPv6 can be unbound from an adapter, and then it has no row to
			// set. IPv4 missing is a real failure.
			if family == windows.AF_INET6 && errors.Is(err, windows.ERROR_NOT_FOUND) {
				continue
			}
			return err
		}
		row.NLMTU = uint32(mtu)
		if err := row.Set(); err != nil {
			return err
		}
	}
	return nil
}

// CreateInterface provisions the driver, creates a Wintun adapter, and starts a
// wireguard-go device on it with the given private key and listen port.
//
// Creating an adapter requires Administrator. It returns once the IP stack
// resolves the adapter by name, because what Manager.Setup and
// SiteToSiteManager.AddTunnel call next resolves it in one attempt and never
// retries: the route controller's LookupLUID and the WFP enforcer's
// lookupWinIface. A device whose adapter never becomes visible goes away
// again, because it would fail those calls with an error that does not name
// the cause.
func (c *WindowsController) CreateInterface(name string, privateKey []byte, listenPort int) error {
	if err := c.createAdapter(name, privateKey, listenPort); err != nil {
		return err
	}

	// The adapter is recorded by now, so the wait runs without the lock.
	// Holding it for up to visibleTimeout would block every other method on
	// this controller — the ConfigureAddress and SetMTU of another interface,
	// and the DeleteInterface a teardown makes — on a call that only polls.
	if err := c.waitAdapterVisible(name); err != nil {
		_ = c.DeleteInterface(name)
		return err
	}

	return nil
}

// createAdapter is the part of CreateInterface that touches the controller's
// state. The lock is held for all of it, so two concurrent creations of one
// name cannot both pass the duplicate check.
func (c *WindowsController) createAdapter(name string, privateKey []byte, listenPort int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.adapters[name]; ok {
		return fmt.Errorf("wireguard: create interface: %w", os.ErrExist)
	}

	// The driver is written out before the first adapter is created, while it is
	// not yet loaded into this process: replacing a loaded DLL would fail.
	path, wrote, err := c.ensureDLL()
	if err != nil {
		return fmt.Errorf("wireguard: create interface: provision wintun.dll: %w", err)
	}
	if wrote {
		c.logger.Info("wintun.dll installed", "component", "wireguard", "path", path)
	} else {
		c.logger.Debug("wintun.dll present", "component", "wireguard", "path", path)
	}

	// device.DefaultMTU is 1420, what the Linux kernel gives a WireGuard link,
	// so a Config.MTU of 0 ("system default") means the same on both platforms.
	tdev, err := c.createTUN(name, device.DefaultMTU)
	if err != nil {
		// Without a hint an operator reads only "Access is denied." or "The
		// specified module could not be found." in the warning plexd up logs,
		// neither of which says what to change.
		switch {
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return fmt.Errorf("wireguard: create interface: create %s: %w (creating a Wintun adapter requires Administrator)", name, err)
		case errors.Is(err, windows.ERROR_MOD_NOT_FOUND):
			return fmt.Errorf("wireguard: create interface: create %s: %w (wintun.dll is missing beside plexd.exe)", name, err)
		}
		return fmt.Errorf("wireguard: create interface: create %s: %w", name, err)
	}

	wd, ok := tdev.(wintunDevice)
	if !ok {
		tdev.Close()
		return errors.New("wireguard: create interface: tun device is not a wintun device")
	}
	luid := wd.LUID()

	// CreateTUN records the MTU in wireguard-go's own field without programming
	// the interface, and Manager.Setup calls SetMTU only when the configuration
	// asks for one. Without this the adapter would keep the driver's default
	// while the device encapsulated for 1420.
	if err := c.ipcfg.SetMTU(luid, device.DefaultMTU); err != nil {
		tdev.Close()
		return fmt.Errorf("wireguard: create interface: set default mtu: %w", err)
	}

	// The backend takes ownership of tdev here: it closes the tun on every error
	// it returns, and its errors already carry this method's prefix.
	if err := c.backend.CreateDevice(name, tdev, privateKey, listenPort); err != nil {
		return err
	}

	c.adapters[name] = &wintunAdapter{luid: luid, forceMTU: wd.ForceMTU}

	c.logger.Info("wintun adapter created",
		"component", "wireguard",
		"interface", name,
		"luid", luid,
	)

	return nil
}

// waitAdapterVisible polls for the adapter's name until the IP stack resolves
// it, bounded by visibleTimeout. The device runs before Windows has finished
// wiring the adapter in, so this turns that race into a bounded delay; it
// costs nothing when the adapter is visible at once, which is the ordinary
// case.
func (c *WindowsController) waitAdapterVisible(name string) error {
	start := time.Now()
	deadline := start.Add(c.visibleTimeout)
	for {
		_, err := c.lookup(name)
		if err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("wireguard: create interface: adapter %s not visible to the IP stack within %s: %w", name, c.visibleTimeout, err)
		}
		time.Sleep(adapterVisiblePoll)
	}

	// One poll of elapsed time is what separates an adapter that resolved at
	// once from one that took a wait worth logging.
	if waited := time.Since(start); waited >= adapterVisiblePoll {
		c.logger.Debug("wintun adapter visible after wait",
			"component", "wireguard",
			"interface", name,
			"waited", waited,
		)
	}

	return nil
}

// DeleteInterface stops the device and releases the adapter.
// It is idempotent: deleting an interface that does not exist returns nil.
func (c *WindowsController) DeleteInterface(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Closing the device closes the tun, which ends the Wintun session and
	// closes the adapter; Windows then removes it with its addresses and routes.
	// The adapter is scoped to the handles that own it, so it also goes away if
	// the process dies without reaching this.
	if err := c.backend.DeleteDevice(name); err != nil {
		return err
	}

	if _, ok := c.adapters[name]; !ok {
		return nil
	}
	delete(c.adapters, name)

	c.logger.Debug("wintun adapter released",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// ConfigureAddress assigns a CIDR address to the interface.
func (c *WindowsController) ConfigureAddress(name string, address string) error {
	ad, err := c.adapter(name, "configure address")
	if err != nil {
		return err
	}

	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return fmt.Errorf("wireguard: configure address: parse %q: %w", address, err)
	}

	// No route call follows: the address carries its prefix length, and Windows
	// installs the on-link route for that prefix itself, the way Linux does when
	// an address is added. macOS needs the route added by hand; Windows does
	// not. Routes for peer AllowedIPs beyond this prefix belong to the bridge
	// controllers, as they do on Linux.
	if err := c.ipcfg.AddIPAddress(ad.luid, prefix); err != nil {
		if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("wireguard: configure address: add %s: %w", address, err)
		}
		// CreateTUN reuses an adapter of the same name, which keeps its
		// addresses, so re-adding one is success: the idempotency
		// NetlinkRouteController grants EEXIST on Linux.
		c.logger.Debug("address already exists",
			"component", "wireguard",
			"interface", name,
			"address", address,
		)
	}

	c.logger.Debug("address configured",
		"component", "wireguard",
		"interface", name,
		"address", address,
	)

	return nil
}

// SetMTU sets the MTU on the interface and on the running device.
func (c *WindowsController) SetMTU(name string, mtu int) error {
	ad, err := c.adapter(name, "set mtu")
	if err != nil {
		return err
	}

	if err := c.ipcfg.SetMTU(ad.luid, mtu); err != nil {
		return fmt.Errorf("wireguard: set mtu: %w", err)
	}

	// No OS event reaches wireguard-go's Windows tun, so the running device is
	// told directly, and only once the interface itself took the value.
	ad.forceMTU(mtu)

	c.logger.Debug("mtu configured",
		"component", "wireguard",
		"interface", name,
		"mtu", mtu,
	)

	return nil
}

// SetInterfaceUp reports the interface as up. A Wintun adapter's media state is
// connected from the moment CreateTUN starts its session, so there is no flag
// to raise; the lookup is what keeps the contract for a name that was never
// created.
func (c *WindowsController) SetInterfaceUp(name string) error {
	if _, err := c.adapter(name, "set interface up"); err != nil {
		return err
	}

	c.logger.Debug("interface up",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// AddPeer adds or updates a peer on the interface.
func (c *WindowsController) AddPeer(iface string, cfg PeerConfig) error {
	return c.backend.AddPeer(iface, cfg)
}

// RemovePeer removes a peer from the interface by public key.
func (c *WindowsController) RemovePeer(iface string, publicKey []byte) error {
	return c.backend.RemovePeer(iface, publicKey)
}

// SetPrivateKey replaces the interface's private key without touching its
// listen port or peers.
func (c *WindowsController) SetPrivateKey(name string, privateKey []byte) error {
	return c.backend.SetPrivateKey(name, privateKey)
}

// adapter resolves the live adapter for a configured name, for the methods that
// address it through the IP Helper API. op names the operation for the error.
func (c *WindowsController) adapter(name, op string) (*wintunAdapter, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ad, ok := c.adapters[name]
	if !ok {
		return nil, fmt.Errorf("wireguard: %s: %w", op, os.ErrNotExist)
	}
	return ad, nil
}
