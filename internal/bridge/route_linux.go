//go:build linux

package bridge

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/vishvananda/netlink"
)

// natTableName is the nftables table name used by plexd for bridge NAT masquerade.
const natTableName = "plexd-nat"

// natChainName is the nftables chain name for postrouting NAT masquerade.
const natChainName = "postrouting"

// meshNATTableName is the nftables table that holds the mesh source rewrites.
// It is a table of its own because AddNATMasquerade flushes the chain of
// natTableName and RemoveNATMasquerade deletes that table whole, so the
// table cannot hold a second translation.
const meshNATTableName = "plexd-mesh-nat"

// meshNATChainName is the chain of meshNATTableName that holds the rewrites.
const meshNATChainName = "postrouting"

// NetlinkRouteController implements RouteController using Linux netlink for
// route management, sysctl for IP forwarding, and nftables for NAT masquerade.
// It implements MeshSourceRewriter through nftables as well.
type NetlinkRouteController struct {
	logger *slog.Logger
}

// Compile-time check that NetlinkRouteController implements MeshSourceRewriter.
var _ MeshSourceRewriter = (*NetlinkRouteController)(nil)

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

// AddMeshSourceRewrite masquerades packets that arrive on fromIface and leave
// through meshIface, which gives them the address of meshIface. The rule lives
// in the IPv4 table plexd-mesh-nat, in the chain postrouting (type nat, hook
// postrouting, priority srcnat); both are added when they are missing. The
// rule carries fromIface as a comment in its user data, by which
// RemoveMeshSourceRewrite finds it again.
// Idempotent: a rule that carries fromIface is left alone, whatever meshIface
// it names.
func (c *NetlinkRouteController) AddMeshSourceRewrite(fromIface, meshIface string) error {
	// ifaceNameBytes panics on a name that does not fit IFNAMSIZ with its
	// terminator; no kernel interface carries such a name.
	for _, name := range []string{fromIface, meshIface} {
		if name == "" || len(name) >= syscall.IFNAMSIZ {
			return fmt.Errorf("bridge: add mesh source rewrite: invalid interface name %q", name)
		}
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("bridge: add mesh source rewrite: %w", err)
	}

	chain, rules, err := meshSourceRewriteRules(conn)
	if err != nil {
		return fmt.Errorf("bridge: add mesh source rewrite: %w", err)
	}
	if findMeshSourceRewrite(rules, fromIface) != nil {
		c.logger.Debug("mesh source rewrite already present, idempotent success",
			"component", "bridge",
			"from_iface", fromIface,
			"mesh_iface", meshIface,
		)
		return nil
	}

	if chain == nil {
		table := conn.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   meshNATTableName,
		})
		chain = conn.AddChain(&nftables.Chain{
			Name:     meshNATChainName,
			Table:    table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource,
		})
	}

	// nft equivalent: iifname "wg-ua-a0a0a0e1" oifname "plexd0" counter
	// masquerade comment "wg-ua-a0a0a0e1"
	conn.AddRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		Exprs:    meshSourceRewriteExprs(fromIface, meshIface),
		UserData: meshSourceRewriteTag(fromIface),
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("bridge: add mesh source rewrite from %q to %q: %w", fromIface, meshIface, err)
	}

	c.logger.Debug("mesh source rewrite added",
		"component", "bridge",
		"from_iface", fromIface,
		"mesh_iface", meshIface,
	)
	return nil
}

// RemoveMeshSourceRewrite deletes the rule AddMeshSourceRewrite added for
// fromIface. meshIface is not needed to find it and is only logged.
// Idempotent: a missing rule, chain or table returns nil.
func (c *NetlinkRouteController) RemoveMeshSourceRewrite(fromIface, meshIface string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("bridge: remove mesh source rewrite: %w", err)
	}

	_, rules, err := meshSourceRewriteRules(conn)
	if err != nil {
		return fmt.Errorf("bridge: remove mesh source rewrite: %w", err)
	}
	rule := findMeshSourceRewrite(rules, fromIface)
	if rule == nil {
		c.logger.Debug("mesh source rewrite not found, idempotent success",
			"component", "bridge",
			"from_iface", fromIface,
			"mesh_iface", meshIface,
		)
		return nil
	}

	if err := conn.DelRule(rule); err != nil {
		return fmt.Errorf("bridge: remove mesh source rewrite from %q: %w", fromIface, err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("bridge: remove mesh source rewrite from %q: %w", fromIface, err)
	}

	c.logger.Debug("mesh source rewrite removed",
		"component", "bridge",
		"from_iface", fromIface,
		"mesh_iface", meshIface,
	)
	return nil
}

// ResetMeshSourceRewrite deletes the table plexd-mesh-nat with every rewrite
// in it. It touches neither the table plexd-nat nor the policy table plexd.
// Idempotent: a missing table returns nil.
func (c *NetlinkRouteController) ResetMeshSourceRewrite() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("bridge: reset mesh source rewrite: %w", err)
	}

	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("bridge: reset mesh source rewrite: list tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == meshNATTableName {
			conn.DelTable(t)
			if err := conn.Flush(); err != nil {
				return fmt.Errorf("bridge: reset mesh source rewrite: %w", err)
			}
			c.logger.Debug("mesh source rewrite table removed",
				"component", "bridge",
				"table", meshNATTableName,
			)
			return nil
		}
	}

	// Table does not exist — idempotent success.
	c.logger.Debug("mesh source rewrite table not found, idempotent success",
		"component", "bridge",
		"table", meshNATTableName,
	)
	return nil
}

// meshSourceRewriteRules returns the chain that holds the mesh source
// rewrites and its rules, or a nil chain and no rules when the table or the
// chain does not exist.
func meshSourceRewriteRules(conn *nftables.Conn) (*nftables.Chain, []*nftables.Rule, error) {
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, nil, fmt.Errorf("list chains: %w", err)
	}
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name != meshNATTableName || ch.Name != meshNATChainName {
			continue
		}
		rules, err := conn.GetRules(ch.Table, ch)
		if err != nil {
			return nil, nil, fmt.Errorf("list rules: %w", err)
		}
		return ch, rules, nil
	}
	return nil, nil, nil
}

// findMeshSourceRewrite returns the rule of rules that carries the tag of
// fromIface, or nil when none does.
func findMeshSourceRewrite(rules []*nftables.Rule, fromIface string) *nftables.Rule {
	tag := meshSourceRewriteTag(fromIface)
	for _, r := range rules {
		if bytes.Equal(r.UserData, tag) {
			return r
		}
	}
	return nil
}

// meshSourceRewriteTag returns the user data that tags the rewrite of
// fromIface: a comment TLV in the encoding of libnftnl, so nft list ruleset
// shows it as comment "<fromIface>". The rule is found again by comparing the
// bytes, which needs no parsing of user data another program may have written.
func meshSourceRewriteTag(fromIface string) []byte {
	return userdata.AppendString(nil, userdata.TypeComment, fromIface)
}

// meshSourceRewriteExprs returns the expressions of the rule that masquerades
// packets arriving on fromIface and leaving through meshIface.
// nft equivalent: iifname "<fromIface>" oifname "<meshIface>" counter masquerade
// Each name is compared with its terminating NUL, which is an exact match: the
// kernel loads an interface name padded with zeros to IFNAMSIZ.
func meshSourceRewriteExprs(fromIface, meshIface string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceNameBytes(fromIface)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceNameBytes(meshIface)},
		&expr.Counter{},
		&expr.Masq{},
	}
}

// ifaceNameBytes returns the interface name as a null-terminated byte slice
// for nftables expression matching. The name is padded to 16 bytes (IFNAMSIZ).
func ifaceNameBytes(name string) []byte {
	buf := make([]byte, 16)
	copy(buf, name)
	// Null terminator is already present since make() zero-initializes.
	return buf[:len(name)+1]
}

