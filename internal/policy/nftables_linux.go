//go:build linux

package policy

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// tableName is the nftables table name used by plexd for mesh policy enforcement.
const tableName = "plexd"

// NftablesController implements FirewallController using the Linux nftables subsystem
// via the google/nftables netlink library. It manages a single IPv4 filter table
// ("plexd") and creates/destroys chains within it.
type NftablesController struct {
	logger *slog.Logger
}

// NewNftablesController returns a new NftablesController.
func NewNftablesController(logger *slog.Logger) *NftablesController {
	return &NftablesController{logger: logger}
}

// EnsureChain creates the named nftables chain if it does not already exist.
// The chain is created as a base chain with a forward hook in the plexd filter
// table so that the kernel evaluates its rules for forwarded traffic.
func (c *NftablesController) EnsureChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: ensure chain: %w", err)
	}

	table := c.ensureTable(conn)
	conn.AddChain(&nftables.Chain{
		Name:     chain,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: ensure chain %q: %w", chain, err)
	}

	c.logger.Debug("nftables chain ensured",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// ApplyRules replaces all rules in the named chain atomically. It flushes the
// chain first, then adds each FirewallRule as an nftables rule with appropriate
// match expressions and verdict.
func (c *NftablesController) ApplyRules(chain string, rules []FirewallRule) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: apply rules: %w", err)
	}

	table := c.ensureTable(conn)
	nftChain := conn.AddChain(&nftables.Chain{
		Name:     chain,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	// Flush existing rules in the chain before adding new ones.
	conn.FlushChain(nftChain)

	for _, rule := range rules {
		exprs, err := buildRuleExprs(rule)
		if err != nil {
			return fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
		}
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: nftChain,
			Exprs: exprs,
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: apply rules to chain %q: %w", chain, err)
	}

	c.logger.Debug("nftables rules applied",
		"component", "policy",
		"chain", chain,
		"count", len(rules),
	)
	return nil
}

// FlushChain removes all rules from the named chain.
func (c *NftablesController) FlushChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: flush chain: %w", err)
	}

	table := c.ensureTable(conn)
	nftChain := &nftables.Chain{
		Name:  chain,
		Table: table,
	}
	conn.FlushChain(nftChain)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: flush chain %q: %w", chain, err)
	}

	c.logger.Debug("nftables chain flushed",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// DeleteChain deletes the named chain. It is idempotent: deleting a
// non-existent chain returns nil.
func (c *NftablesController) DeleteChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: delete chain: %w", err)
	}

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableName,
	}

	// List existing chains to check if the target chain exists.
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("policy: nftables: delete chain: list chains: %w", err)
	}

	for _, ch := range chains {
		if ch.Table.Name == tableName && ch.Name == chain {
			conn.DelChain(ch)
			if err := conn.Flush(); err != nil {
				return fmt.Errorf("policy: nftables: delete chain %q: %w", chain, err)
			}
			c.logger.Debug("nftables chain deleted",
				"component", "policy",
				"chain", chain,
			)
			return nil
		}
	}

	// Chain does not exist — idempotent success.
	c.logger.Debug("nftables chain not found, nothing to delete",
		"component", "policy",
		"chain", chain,
		"table", table.Name,
	)
	return nil
}

// ensureTable adds the plexd IPv4 filter table to the connection batch.
// AddTable is idempotent in nftables — adding an existing table is a no-op.
func (c *NftablesController) ensureTable(conn *nftables.Conn) *nftables.Table {
	return conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableName,
	})
}

// buildRuleExprs converts a FirewallRule into nftables match expressions and a verdict.
func buildRuleExprs(rule FirewallRule) ([]expr.Any, error) {
	var exprs []expr.Any

	// Match input interface name if specified.
	if rule.Interface != "" {
		ifaceData := ifaceNameBytes(rule.Interface)
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifaceData,
			},
		)
	}

	// Match source IP if specified and not the wildcard "0.0.0.0/0".
	if rule.SrcIP != "" && rule.SrcIP != "0.0.0.0/0" {
		srcExprs, err := buildIPMatchExprs(rule.SrcIP, 12) // IPv4 src offset
		if err != nil {
			return nil, fmt.Errorf("source IP %q: %w", rule.SrcIP, err)
		}
		exprs = append(exprs, srcExprs...)
	}

	// Match destination IP if specified and not the wildcard "0.0.0.0/0".
	if rule.DstIP != "" && rule.DstIP != "0.0.0.0/0" {
		dstExprs, err := buildIPMatchExprs(rule.DstIP, 16) // IPv4 dst offset
		if err != nil {
			return nil, fmt.Errorf("destination IP %q: %w", rule.DstIP, err)
		}
		exprs = append(exprs, dstExprs...)
	}

	// Match protocol if specified.
	if rule.Protocol != "" {
		proto, err := protocolNumber(rule.Protocol)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{proto},
			},
		)
	}

	// Match destination port if specified.
	if rule.Port > 0 {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TCP/UDP destination port offset
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes(uint16(rule.Port)),
			},
		)
	}

	// Append counter for observability.
	exprs = append(exprs, &expr.Counter{})

	// Append verdict.
	switch rule.Action {
	case "allow":
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	case "deny":
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	default:
		return nil, fmt.Errorf("unsupported action %q", rule.Action)
	}

	return exprs, nil
}

// buildIPMatchExprs creates payload + cmp expressions to match an IPv4 address.
// offset is 12 for source and 16 for destination in the IPv4 header.
// The address may be a single IP ("10.0.0.1") or CIDR ("10.0.0.0/24").
// For a /32 or bare IP, an exact match is used. For other prefix lengths,
// a bitwise mask + compare is used.
func buildIPMatchExprs(addr string, offset uint32) ([]expr.Any, error) {
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		// Try as a plain IP without CIDR notation — normalize to /32.
		parsed := net.ParseIP(addr)
		if parsed == nil {
			return nil, fmt.Errorf("invalid IP address %q", addr)
		}
		ip = parsed.To4()
		if ip == nil {
			return nil, fmt.Errorf("non-IPv4 address %q", addr)
		}
		ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	} else {
		ip = ip.To4()
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("non-IPv4 CIDR %q", addr)
	}

	payload := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          4,
	}

	// Exact match for /32 or bare IP.
	if ones == 32 {
		return []expr.Any{
			payload,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip,
			},
		}, nil
	}

	// Subnet match: payload → bitwise(mask) → cmp(network address).
	return []expr.Any{
		payload,
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte(ipNet.Mask),
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipNet.IP.To4(),
		},
	}, nil
}

// protocolNumber maps a protocol string to its IP protocol number.
func protocolNumber(proto string) (byte, error) {
	switch proto {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", proto)
	}
}

// portBytes encodes a port number as 2 big-endian bytes for nftables matching.
func portBytes(port uint16) []byte {
	return []byte{byte(port >> 8), byte(port)}
}

// ifaceNameBytes returns the interface name as a null-terminated byte slice
// for nftables expression matching. The name is padded to 16 bytes (IFNAMSIZ).
func ifaceNameBytes(name string) []byte {
	buf := make([]byte, 16)
	copy(buf, name)
	// Null terminator is already present since make() zero-initializes.
	return buf[:len(name)+1]
}
