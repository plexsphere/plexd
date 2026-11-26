//go:build linux

package wireguard

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// mssTableName is the nftables table that holds the clamp of forwarded TCP.
// It is a table of its own because the policy table cannot hold the rules:
// a node with policy.enabled: false has no policy table, and the clamp has
// to stay with the mesh interface. The bridge NAT and the mesh source rewrite keep tables
// of their own for the same kind of reason (internal/bridge/route_linux.go).
const mssTableName = "plexd-mss"

// mssChainName is the chain of mssTableName that holds the two clamp rules.
const mssChainName = "forward"

// tcpOptionMaxseg is the kind of the TCP MSS option (RFC 9293, 3.1).
const tcpOptionMaxseg = 2

// Compile-time check that NetlinkController implements MSSClamper.
var _ MSSClamper = (*NetlinkController)(nil)

// ClampMSS lowers the MSS option of every forwarded IPv4 TCP SYN that enters
// or leaves the interface name to mss when the SYN announces more. It writes
// the table ip plexd-mss in one batch: the table, its forward chain, a flush
// of that chain and the two rules of clampMSSExprs. The flush makes a second
// call replace the rules of the first instead of adding two more, and makes
// the call rewrite a table that a killed process left behind, whose rules
// may name another interface or value. The table holds the clamp of one
// interface, the mesh interface, because only the mesh manager clamps.
//
// An mss outside 1 to 65535 returns an error before any netlink call.
func (c *NetlinkController) ClampMSS(name string, mss int) error {
	if mss < 1 || mss > 65535 {
		return fmt.Errorf("wireguard: clamp mss: invalid mss %d", mss)
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("wireguard: clamp mss: %w", err)
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   mssTableName,
	})
	policy := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{
		Name:     mssChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
		Policy:   &policy,
	})
	conn.FlushChain(chain)
	for _, in := range []bool{true, false} {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: clampMSSExprs(name, in, uint16(mss)),
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("wireguard: clamp mss on %q: %w", name, err)
	}

	c.logger.Debug("mss clamp configured",
		"component", "wireguard",
		"interface", name,
		"mss", mss,
	)
	return nil
}

// UnclampMSS deletes the table ip plexd-mss with both rules. A table that is
// not there returns nil, so a repeated call and a call for an interface that
// was never clamped succeed. The table is looked up first, as
// RemoveNATMasquerade in internal/bridge does, because the delete of a
// missing table fails the whole batch.
func (c *NetlinkController) UnclampMSS(name string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("wireguard: unclamp mss: %w", err)
	}

	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("wireguard: unclamp mss: list tables: %w", err)
	}

	for _, t := range tables {
		if t.Name != mssTableName {
			continue
		}
		conn.DelTable(t)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("wireguard: unclamp mss on %q: %w", name, err)
		}
		c.logger.Debug("mss clamp removed",
			"component", "wireguard",
			"interface", name,
		)
		return nil
	}
	return nil
}

// clampMSSExprs returns the expressions of one clamp rule: for the SYNs that
// enter the interface iface when in is true, and for those that leave it
// otherwise. nft lists the rule that enters plexd0 at mss 1332 as
//
//	iifname "plexd0" tcp flags & (syn | rst) == syn tcp option maxseg size > 1332 counter tcp option maxseg size set 1332
//
// and its expressions, in the form nft --debug=netlink prints them with the
// data abbreviated, are
//
//	[ meta load iifname => reg 1 ]
//	[ cmp eq reg 1 "plexd0" padded to 16 bytes ]
//	[ meta load l4proto => reg 1 ]
//	[ cmp eq reg 1 0x06 ]
//	[ payload load 1b @ transport header + 13 => reg 1 ]
//	[ bitwise reg 1 = ( reg 1 & 0x06 ) ^ 0x00 ]
//	[ cmp eq reg 1 0x02 ]
//	[ exthdr load tcpopt 2b @ 2 + 2 => reg 1 ]
//	[ cmp gt reg 1 <mss, big-endian 2 bytes> ]
//	[ counter ]
//	[ immediate reg 1 <mss, big-endian 2 bytes> ]
//	[ exthdr write tcpopt reg 1 => 2b @ 2 + 2 ]
//
// The rule matches only a SYN whose MSS option announces more than mss, so
// its counter counts the SYNs it lowered. A SYN without the option fails the
// option load and keeps the default of 536 a host assumes then, and a SYN
// with RST set is left alone. The kernel updates the TCP checksum when it
// writes the option. The values compare as big-endian bytes, which orders
// them as numbers.
//
// The chain hooks forward, so the rules leave the node's own connections
// alone: their MSS already comes from the interface MTU. A forwarded packet
// on another interface fails the first comparison, and one on the mesh
// interface pays the protocol and flag comparisons; only a SYN reads its
// options.
func clampMSSExprs(iface string, in bool, mss uint16) []expr.Any {
	key := expr.MetaKeyOIFNAME
	if in {
		key = expr.MetaKeyIIFNAME
	}
	value := binaryutil.BigEndian.PutUint16(mss)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mssIfname(iface)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		// The flags are byte 13 of the TCP header. SYN is 0x02, RST 0x04.
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        13,
			Len:           1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x06},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
		// The MSS value follows the option's kind and length bytes.
		&expr.Exthdr{
			Op:           expr.ExthdrOpTcpopt,
			Type:         tcpOptionMaxseg,
			Offset:       2,
			Len:          2,
			DestRegister: 1,
		},
		&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: value},
		&expr.Counter{},
		&expr.Immediate{Register: 1, Data: value},
		&expr.Exthdr{
			Op:             expr.ExthdrOpTcpopt,
			Type:           tcpOptionMaxseg,
			Offset:         2,
			Len:            2,
			SourceRegister: 1,
		},
	}
}

// mssIfname returns name zero-padded to IFNAMSIZ, 16 bytes, the form nft
// generates for an exact interface name. The bridge and policy packages
// compare the name and a single NUL instead; both forms match the exact name
// in the kernel, which loads an interface name zero-padded to IFNAMSIZ. A
// name of 16 bytes or more, which no link carries, loses its tail and
// matches nothing.
func mssIfname(name string) []byte {
	buf := make([]byte, unix.IFNAMSIZ)
	copy(buf, name)
	return buf
}
