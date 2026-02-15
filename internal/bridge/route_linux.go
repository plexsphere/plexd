//go:build linux

package bridge

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

// natTableName is the nftables table name used by plexd for bridge NAT masquerade.
const natTableName = "plexd-nat"

// natChainName is the nftables chain name for postrouting NAT masquerade.
const natChainName = "postrouting"

// NetlinkRouteController implements RouteController using Linux netlink for
// route management, sysctl for IP forwarding, and nftables for NAT masquerade.
type NetlinkRouteController struct {
	logger *slog.Logger
}

// NewNetlinkRouteController returns a new NetlinkRouteController.
func NewNetlinkRouteController(logger *slog.Logger) *NetlinkRouteController {
	return &NetlinkRouteController{logger: logger}
}

// EnableForwarding enables IPv4 forwarding for the given interfaces via sysctl.
func (c *NetlinkRouteController) EnableForwarding(meshIface, accessIface string) error {
	for _, iface := range []string{meshIface, accessIface} {
		if err := setSysctl(iface, "1"); err != nil {
			return fmt.Errorf("bridge: enable forwarding: %w", err)
		}
	}

	c.logger.Debug("IP forwarding enabled",
		"component", "bridge",
		"mesh_iface", meshIface,
		"access_iface", accessIface,
	)
	return nil
}

// DisableForwarding disables IPv4 forwarding for the given interfaces via sysctl.
func (c *NetlinkRouteController) DisableForwarding(meshIface, accessIface string) error {
	for _, iface := range []string{meshIface, accessIface} {
		if err := setSysctl(iface, "0"); err != nil {
			return fmt.Errorf("bridge: disable forwarding: %w", err)
		}
	}

	c.logger.Debug("IP forwarding disabled",
		"component", "bridge",
		"mesh_iface", meshIface,
		"access_iface", accessIface,
	)
	return nil
}

// validateIfaceName checks that the interface name is safe for use in filesystem paths.
// It rejects names containing path traversal characters.
func validateIfaceName(name string) error {
	for _, c := range name {
		if c == '/' || c == '.' || c == '\x00' {
			return fmt.Errorf("bridge: invalid interface name %q: contains prohibited character", name)
		}
	}
	if name == "" {
		return fmt.Errorf("bridge: invalid interface name: empty")
	}
	return nil
}

// setSysctl writes a value to the per-interface IPv4 forwarding sysctl.
func setSysctl(iface, value string) error {
	if err := validateIfaceName(iface); err != nil {
		return err
	}
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", iface)
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("sysctl %s: %w", path, err)
	}
	return nil
}

// AddRoute adds a route for the given CIDR subnet via the given interface.
// Idempotent: adding an existing route returns nil.
func (c *NetlinkRouteController) AddRoute(subnet, iface string) error {
	_, dst, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("bridge: add route: parse CIDR %q: %w", subnet, err)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("bridge: add route: lookup interface %q: %w", iface, err)
	}

	route := &netlink.Route{
		Dst:       dst,
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}

	if err := netlink.RouteAdd(route); err != nil {
		// EEXIST means the route already exists — idempotent success.
		if errors.Is(err, syscall.EEXIST) {
			c.logger.Debug("route already exists, idempotent success",
				"component", "bridge",
				"subnet", subnet,
				"interface", iface,
			)
			return nil
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

// RemoveRoute removes the route for the given CIDR subnet via the given interface.
// Idempotent: removing a non-existent route returns nil.
func (c *NetlinkRouteController) RemoveRoute(subnet, iface string) error {
	_, dst, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("bridge: remove route: parse CIDR %q: %w", subnet, err)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("bridge: remove route: lookup interface %q: %w", iface, err)
	}

	route := &netlink.Route{
		Dst:       dst,
		LinkIndex: link.Attrs().Index,
	}

	if err := netlink.RouteDel(route); err != nil {
		// ESRCH means the route does not exist — idempotent success.
		if errors.Is(err, syscall.ESRCH) {
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

// AddNATMasquerade configures NAT masquerading on the given interface using nftables.
// Creates a postrouting chain with a masquerade rule matching traffic on the interface.
// Idempotent: re-adding an existing masquerade is a no-op (table/chain are re-added atomically).
func (c *NetlinkRouteController) AddNATMasquerade(iface string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("bridge: add NAT masquerade: %w", err)
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   natTableName,
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     natChainName,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// Flush existing rules in the chain to make this idempotent.
	conn.FlushChain(chain)

	// Match outgoing interface name and apply masquerade.
	// nft equivalent: oifname "eth1" masquerade
	ifaceData := ifaceNameBytes(iface)
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifaceData,
			},
			&expr.Counter{},
			&expr.Masq{},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("bridge: add NAT masquerade on %q: %w", iface, err)
	}

	c.logger.Debug("NAT masquerade configured",
		"component", "bridge",
		"interface", iface,
	)
	return nil
}

// RemoveNATMasquerade removes NAT masquerading from the given interface by
// deleting the plexd-nat nftables table.
// Idempotent: removing a non-existent table returns nil.
func (c *NetlinkRouteController) RemoveNATMasquerade(iface string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("bridge: remove NAT masquerade: %w", err)
	}

	// List tables to find our NAT table. If it doesn't exist, return nil.
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("bridge: remove NAT masquerade: list tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == natTableName {
			conn.DelTable(t)
			if err := conn.Flush(); err != nil {
				return fmt.Errorf("bridge: remove NAT masquerade on %q: %w", iface, err)
			}
			c.logger.Debug("NAT masquerade removed",
				"component", "bridge",
				"interface", iface,
			)
			return nil
		}
	}

	// Table does not exist — idempotent success.
	c.logger.Debug("NAT masquerade table not found, idempotent success",
		"component", "bridge",
		"interface", iface,
	)
	return nil
}

// ifaceNameBytes returns the interface name as a null-terminated byte slice
// for nftables expression matching. The name is padded to 16 bytes (IFNAMSIZ).
func ifaceNameBytes(name string) []byte {
	buf := make([]byte, 16)
	copy(buf, name)
	// Null terminator is already present since make() zero-initializes.
	return buf[:len(name)+1]
}

