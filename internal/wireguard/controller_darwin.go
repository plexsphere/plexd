//go:build darwin

package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Absolute paths, because launchd starts the daemon with a minimal
// environment and neither tool is guaranteed to be on its PATH.
const (
	ifconfigPath = "/sbin/ifconfig"
	routePath    = "/sbin/route"

	// commandTimeout bounds one ifconfig or route invocation. Both are
	// ioctl wrappers that return immediately; the timeout exists so a wedged
	// host cannot stall interface setup forever.
	commandTimeout = 10 * time.Second
)

// utunNameRE matches a configured interface name that already names a utun
// unit. Such a name is passed to the kernel unchanged, so an operator can pin
// the unit; anything else becomes "utun" and the kernel picks the next free
// one.
var utunNameRE = regexp.MustCompile(`^utun[0-9]+$`)

// commandRunner runs a command and returns its combined stdout and stderr. It
// is a seam so the controller is testable without root: execCommand drives the
// real binaries, and tests record the arguments instead.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// DarwinController implements WGController on macOS. It creates a utun device
// with wireguard-go's tun.CreateTUN, runs it through UserspaceBackend, and
// programs the address, the on-link route, the MTU and the interface flag with
// ifconfig(8) and route(8).
//
// The kernel names the device utunN and refuses any other name. Everything the
// manager and the backend see is keyed by the configured name, so wg show
// plexd0 works; the utunN name is used only for the host tooling and for the
// readiness check, which reaches it through OSInterfaceName.
type DarwinController struct {
	backend *UserspaceBackend
	logger  *slog.Logger

	mu    sync.Mutex
	utuns map[string]string // configured name -> kernel utunN name

	// createTUN and run are seams: production wires them to tun.CreateTUN and
	// execCommand, tests to a fake tun and a recording runner.
	createTUN func(name string, mtu int) (tun.Device, error)
	run       commandRunner
}

// NewDarwinController returns a controller wired to the real utun device and
// the host's ifconfig and route binaries.
func NewDarwinController(logger *slog.Logger) *DarwinController {
	return &DarwinController{
		backend:   NewUserspaceBackend(logger),
		logger:    logger,
		utuns:     make(map[string]string),
		createTUN: tun.CreateTUN,
		run:       execCommand,
	}
}

// execCommand is the commandRunner that drives a real binary.
func execCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// CreateInterface creates a utun device, starts a wireguard-go device on it
// with the given private key and listen port, and records the kernel's name
// for the interface.
//
// Creating a utun requires root. The lock is held for the whole call so two
// concurrent creations of one name cannot both pass the duplicate check.
func (c *DarwinController) CreateInterface(name string, privateKey []byte, listenPort int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.utuns[name]; ok {
		return fmt.Errorf("wireguard: create interface: %w", os.ErrExist)
	}

	tunName := "utun"
	if utunNameRE.MatchString(name) {
		tunName = name
	}

	// device.DefaultMTU is 1420, what the Linux kernel gives a WireGuard link,
	// so a Config.MTU of 0 ("system default") means the same on both
	// platforms. SetMTU overrides it when the configuration asks.
	tdev, err := c.createTUN(tunName, device.DefaultMTU)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			// Without the hint an operator reads only "operation not
			// permitted" in the warning plexd up logs, which does not say
			// what to change.
			return fmt.Errorf("wireguard: create interface: create %s: %w (creating a utun device requires root)", tunName, err)
		}
		return fmt.Errorf("wireguard: create interface: create %s: %w", tunName, err)
	}

	osName, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return fmt.Errorf("wireguard: create interface: utun name: %w", err)
	}

	// The backend takes ownership of tdev here: it closes the tun on every
	// error it returns, and its errors already carry this method's prefix.
	if err := c.backend.CreateDevice(name, tdev, privateKey, listenPort); err != nil {
		return err
	}

	c.utuns[name] = osName

	c.logger.Info("utun device created",
		"component", "wireguard",
		"interface", name,
		"utun", osName,
	)

	return nil
}

// DeleteInterface stops the device and releases the utun.
// It is idempotent: deleting an interface that does not exist returns nil.
func (c *DarwinController) DeleteInterface(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Closing the device closes the tun, and the kernel then destroys the utun
	// with its addresses and routes, so no ifconfig or route delete is needed.
	if err := c.backend.DeleteDevice(name); err != nil {
		return err
	}

	osName, ok := c.utuns[name]
	if !ok {
		return nil
	}
	delete(c.utuns, name)

	c.logger.Debug("utun device released",
		"component", "wireguard",
		"interface", name,
		"utun", osName,
	)

	return nil
}

// ConfigureAddress assigns a CIDR address to the interface and installs the
// route for its prefix.
func (c *DarwinController) ConfigureAddress(name string, address string) error {
	osName, err := c.osName(name, "configure address")
	if err != nil {
		return err
	}

	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return fmt.Errorf("wireguard: configure address: parse %q: %w", address, err)
	}

	// A utun is point-to-point, so the inet form takes the destination address
	// after the local one; for a mesh address the two are the same. The inet6
	// form takes none.
	if prefix.Addr().Is4() {
		_, err = c.runTool("configure address", ifconfigPath, osName, "inet", prefix.String(), prefix.Addr().String(), "alias")
	} else {
		_, err = c.runTool("configure address", ifconfigPath, osName, "inet6", prefix.String(), "alias")
	}
	if err != nil {
		return err
	}

	if err := c.addOnLinkRoute(osName, prefix); err != nil {
		return err
	}

	c.logger.Debug("address configured",
		"component", "wireguard",
		"interface", name,
		"utun", osName,
		"address", address,
	)

	return nil
}

// addOnLinkRoute installs the route for the address's own prefix. Adding an
// address to a Linux WireGuard link gives that route for free, but a macOS
// utun is point-to-point and the alias installs only a host route, so without
// this every packet for the mesh would leave through the default route.
//
// A host prefix needs no route: the alias already installed it. Routes for
// peer AllowedIPs beyond this prefix belong to the bridge controllers, as they
// do on Linux.
func (c *DarwinController) addOnLinkRoute(osName string, prefix netip.Prefix) error {
	if prefix.Bits() >= prefix.Addr().BitLen() {
		return nil
	}

	family := "-inet"
	if !prefix.Addr().Is4() {
		family = "-inet6"
	}
	network := prefix.Masked().String()

	out, err := c.runTool("configure address", routePath, "-n", "add", family, network, "-interface", osName)
	if err == nil {
		return nil
	}

	// route(8) reports an existing route as "File exists". Re-adding one is a
	// success, the idempotency NetlinkRouteController grants EEXIST on Linux.
	if bytes.Contains(out, []byte("File exists")) {
		c.logger.Debug("route already exists",
			"component", "wireguard",
			"utun", osName,
			"prefix", network,
		)
		return nil
	}

	return err
}

// SetInterfaceUp raises the interface flag on the utun. The kernel's route
// message reaches the running wireguard-go device as tun.EventUp, where the
// device is already up and the state change is a no-op.
func (c *DarwinController) SetInterfaceUp(name string) error {
	osName, err := c.osName(name, "set interface up")
	if err != nil {
		return err
	}

	if _, err := c.runTool("set interface up", ifconfigPath, osName, "up"); err != nil {
		return err
	}

	c.logger.Debug("interface brought up",
		"component", "wireguard",
		"interface", name,
		"utun", osName,
	)

	return nil
}

// SetMTU sets the MTU on the utun. wireguard-go re-reads it from the
// tun.EventMTUUpdate the kernel emits.
func (c *DarwinController) SetMTU(name string, mtu int) error {
	osName, err := c.osName(name, "set mtu")
	if err != nil {
		return err
	}

	if _, err := c.runTool("set mtu", ifconfigPath, osName, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}

	c.logger.Debug("mtu configured",
		"component", "wireguard",
		"interface", name,
		"utun", osName,
		"mtu", mtu,
	)

	return nil
}

// AddPeer adds or updates a peer on the interface.
func (c *DarwinController) AddPeer(iface string, cfg PeerConfig) error {
	return c.backend.AddPeer(iface, cfg)
}

// RemovePeer removes a peer from the interface by public key.
func (c *DarwinController) RemovePeer(iface string, publicKey []byte) error {
	return c.backend.RemovePeer(iface, publicKey)
}

// SetPrivateKey replaces the interface's private key without touching its
// listen port or peers.
func (c *DarwinController) SetPrivateKey(name string, privateKey []byte) error {
	return c.backend.SetPrivateKey(name, privateKey)
}

// OSInterfaceName returns the kernel's utunN name for the interface created
// under the configured name, and false when no such interface exists.
func (c *DarwinController) OSInterfaceName(name string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	osName, ok := c.utuns[name]
	return osName, ok
}

// osName resolves the configured name to the kernel's, for the methods that
// hand a name to ifconfig or route. op names the operation for the error.
func (c *DarwinController) osName(name, op string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	osName, ok := c.utuns[name]
	if !ok {
		return "", fmt.Errorf("wireguard: %s: %w", op, os.ErrNotExist)
	}
	return osName, nil
}

// runTool runs one host command under a timeout and returns its combined
// output, which the caller reads even on failure. A failure carries the
// command line and the tool's own message, because "exit status 1" alone says
// nothing an operator can act on.
func (c *DarwinController) runTool(op string, argv ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := c.run(ctx, argv[0], argv[1:]...)
	if err == nil {
		return out, nil
	}

	if detail := strings.TrimSpace(string(out)); detail != "" {
		return out, fmt.Errorf("wireguard: %s: %s: %w: %s", op, strings.Join(argv, " "), err, detail)
	}
	return out, fmt.Errorf("wireguard: %s: %s: %w", op, strings.Join(argv, " "), err)
}
