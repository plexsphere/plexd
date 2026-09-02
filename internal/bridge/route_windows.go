//go:build windows

package bridge

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// ipRouter programs routes and the IPv4 forwarding flag through the IP Helper
// API, keyed by interface LUID. It is a seam: production drives winipcfg,
// tests record the calls, which is what makes the controller testable without
// Administrator.
type ipRouter interface {
	// LookupLUID resolves an interface's friendly name — the Name column of
	// Get-NetAdapter, and the name a Wintun adapter is created under — to the
	// LUID the IP Helper API addresses it by.
	LookupLUID(iface string) (uint64, error)

	// AddRoute adds an on-link route for prefix, with no next hop.
	AddRoute(luid uint64, prefix netip.Prefix) error

	// DeleteRoute removes the on-link route for prefix.
	DeleteRoute(luid uint64, prefix netip.Prefix) error

	// Forwarding reads the interface's IPv4 forwarding flag.
	Forwarding(luid uint64) (bool, error)

	// SetForwarding writes the interface's IPv4 forwarding flag.
	SetForwarding(luid uint64, enabled bool) error
}

// winipcfgRouter drives the real IP Helper API.
type winipcfgRouter struct{}

// routeNextHop returns the unspecified address of the prefix's family, which
// is how an on-link route is expressed: the destination is reached over the
// interface itself rather than through a gateway. It is the same next hop
// wireguard-windows uses for its own routes.
func routeNextHop(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// LookupLUID resolves an interface name through the interface table. Go
// matches the adapter's friendly name on Windows, which is the name the
// configuration carries and the one a Wintun adapter is created under.
func (winipcfgRouter) LookupLUID(iface string) (uint64, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, err
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(ifi.Index))
	if err != nil {
		return 0, err
	}
	return uint64(luid), nil
}

// AddRoute is CreateIpForwardEntry2 with metric 0, the Windows equivalent of
// the link-scoped route the Linux controller adds through netlink.
func (winipcfgRouter) AddRoute(luid uint64, prefix netip.Prefix) error {
	return winipcfg.LUID(luid).AddRoute(prefix, routeNextHop(prefix), 0)
}

// DeleteRoute is DeleteIpForwardEntry2. winipcfg looks the row up first, so a
// route that is not there surfaces as ERROR_NOT_FOUND.
func (winipcfgRouter) DeleteRoute(luid uint64, prefix netip.Prefix) error {
	return winipcfg.LUID(luid).DeleteRoute(prefix, routeNextHop(prefix))
}

// Forwarding reads the IPv4 interface row, which is GetIpInterfaceEntry.
func (winipcfgRouter) Forwarding(luid uint64) (bool, error) {
	row, err := winipcfg.LUID(luid).IPInterface(windows.AF_INET)
	if err != nil {
		return false, err
	}
	return row.ForwardingEnabled, nil
}

// SetForwarding writes the IPv4 interface row, which is SetIpInterfaceEntry.
// This is what "netsh interface ipv4 set interface <name> forwarding=enabled"
// does: a per-interface flag, no registry value and no reboot.
func (winipcfgRouter) SetForwarding(luid uint64, enabled bool) error {
	row, err := winipcfg.LUID(luid).IPInterface(windows.AF_INET)
	if err != nil {
		return err
	}
	row.ForwardingEnabled = enabled
	return row.Set()
}

// forwardingKnob is what the ledger saves per interface: the LUID resolved
// when forwarding was enabled, so teardown needs no second lookup, and the
// flag's value before plexd touched it.
type forwardingKnob struct {
	luid   uint64
	before bool
}

// WindowsRouteController implements RouteController on Windows through the IP
// Helper API. Every method needs Administrator, which the LocalSystem service
// satisfies.
//
// NAT masquerade is delegated to the NATController the firewall backend
// supplies; a controller built with none reports NAT as unavailable rather
// than letting a gateway come up claiming a masquerade it does not have.
type WindowsRouteController struct {
	ip     ipRouter
	nat    NATController
	logger *slog.Logger

	mu     sync.Mutex
	ledger *forwardingLedger[forwardingKnob]
}

// NewWindowsRouteController returns a controller driving the host's IP Helper
// API. nat may be nil, which makes AddNATMasquerade fail with
// ErrNATUnavailable.
func NewWindowsRouteController(logger *slog.Logger, nat NATController) *WindowsRouteController {
	return &WindowsRouteController{
		ip:     winipcfgRouter{},
		nat:    nat,
		logger: logger,
		ledger: newForwardingLedger[forwardingKnob](),
	}
}

// AddRoute adds a route for the given CIDR subnet via the given interface.
// Idempotent: adding an existing route returns nil.
func (c *WindowsRouteController) AddRoute(subnet, iface string) error {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("bridge: add route: parse CIDR %q: %w", subnet, err)
	}

	luid, err := c.ip.LookupLUID(iface)
	if err != nil {
		return fmt.Errorf("bridge: add route: lookup interface %q: %w", iface, err)
	}

	if err := c.ip.AddRoute(luid, prefix.Masked()); err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			c.logger.Debug("route already exists, idempotent success",
				"component", "bridge",
				"subnet", subnet,
				"interface", iface,
			)
			return nil
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("bridge: add route %q via %q: %w (bridge mode on Windows requires Administrator)", subnet, iface, err)
		}
		return fmt.Errorf("bridge: add route %q via %q: %w", subnet, iface, err)
	}

	c.logger.Debug("route added",
		"component", "bridge",
		"subnet", subnet,
		"interface", iface,
	)
	return nil
}

// RemoveRoute removes the route for the given CIDR subnet via the given
// interface. Idempotent: removing a non-existent route returns nil.
func (c *WindowsRouteController) RemoveRoute(subnet, iface string) error {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("bridge: remove route: parse CIDR %q: %w", subnet, err)
	}

	luid, err := c.ip.LookupLUID(iface)
	if err != nil {
		return fmt.Errorf("bridge: remove route: lookup interface %q: %w", iface, err)
	}

	if err := c.ip.DeleteRoute(luid, prefix.Masked()); err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			c.logger.Debug("route not found, idempotent success",
				"component", "bridge",
				"subnet", subnet,
				"interface", iface,
			)
			return nil
		}
		return fmt.Errorf("bridge: remove route %q via %q: %w", subnet, iface, err)
	}

	c.logger.Debug("route removed",
		"component", "bridge",
		"subnet", subnet,
		"interface", iface,
	)
	return nil
}

// EnableForwarding switches IPv4 forwarding on for both interfaces. Each flag
// goes through the ledger, because the access adapter is claimed by the bridge
// manager and the user-access manager alike and the first of them to tear down
// must not switch forwarding off under the other.
func (c *WindowsRouteController) EnableForwarding(meshIface, accessIface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	pair := forwardingPair{meshIface, accessIface}

	for _, name := range []string{meshIface, accessIface} {
		luid, err := c.ip.LookupLUID(name)
		if err != nil {
			return fmt.Errorf("bridge: enable forwarding: lookup interface %q: %w", name, err)
		}

		var before bool
		if !c.ledger.held(name) {
			before, err = c.ip.Forwarding(luid)
			if err != nil {
				return fmt.Errorf("bridge: enable forwarding: read forwarding on %q: %w", name, err)
			}
		}

		if err := c.ip.SetForwarding(luid, true); err != nil {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				return fmt.Errorf("bridge: enable forwarding: set forwarding on %q: %w (bridge mode on Windows requires Administrator)", name, err)
			}
			return fmt.Errorf("bridge: enable forwarding: set forwarding on %q: %w", name, err)
		}

		// Recorded only once the write succeeded, so a failure leaves nothing
		// for a later disable to restore. An earlier interface in this loop
		// keeps its entry, exactly as the Linux controller leaves its first
		// sysctl written.
		c.ledger.acquire(name, pair, forwardingKnob{luid: luid, before: before})
	}

	c.logger.Debug("IP forwarding enabled",
		"component", "bridge",
		"mesh_iface", meshIface,
		"access_iface", accessIface,
	)
	return nil
}

// DisableForwarding restores each interface's forwarding flag to the value it
// had before the first pair enabled it, once the last pair has let go. Both
// interfaces are attempted even when one fails. Idempotent: a pair that never
// enabled forwarding writes nothing.
func (c *WindowsRouteController) DisableForwarding(meshIface, accessIface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	pair := forwardingPair{meshIface, accessIface}

	var (
		errs     []error
		restored []string
	)
	for _, name := range []string{meshIface, accessIface} {
		knob, last := c.ledger.release(name, pair)
		if !last {
			continue
		}
		if err := c.ip.SetForwarding(knob.luid, knob.before); err != nil {
			errs = append(errs, fmt.Errorf("bridge: disable forwarding: set forwarding on %q: %w", name, err))
			continue
		}
		restored = append(restored, name)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	c.logger.Debug("IP forwarding disabled",
		"component", "bridge",
		"mesh_iface", meshIface,
		"access_iface", accessIface,
		"restored", restored,
	)
	return nil
}

// AddNATMasquerade configures NAT masquerading on the given interface through
// the firewall backend, and reports NAT as unavailable when there is none.
func (c *WindowsRouteController) AddNATMasquerade(iface string) error {
	if c.nat == nil {
		return fmt.Errorf("bridge: add NAT masquerade on %q: %w; set bridge.enable_nat: false to run the bridge without NAT",
			iface, ErrNATUnavailable)
	}
	return c.nat.AddNATMasquerade(iface)
}

// RemoveNATMasquerade removes NAT masquerading from the given interface.
// Idempotent: with no backend there is nothing that could have been added.
func (c *WindowsRouteController) RemoveNATMasquerade(iface string) error {
	if c.nat == nil {
		c.logger.Debug("NAT masquerade backend absent, nothing to remove",
			"component", "bridge",
			"interface", iface,
		)
		return nil
	}
	return c.nat.RemoveNATMasquerade(iface)
}
