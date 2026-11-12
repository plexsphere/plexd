//go:build linux

package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// tableName is the nftables table name used by plexd for mesh policy enforcement.
const tableName = "plexd"

// ctDirectionReply is IP_CT_DIR_REPLY, the value the kernel loads for
// "ct direction" when a packet travels against its connection's first packet.
const ctDirectionReply = 1

// NftablesController implements FirewallController using the Linux nftables subsystem
// via the google/nftables netlink library. It manages one inet filter table
// ("plexd"), which matches IPv4 and IPv6 alike, and gives every configured
// chain name two base chains in it: one on the input hook for traffic
// addressed to the node and one on the forward hook for traffic it routes.
// Both chains hold the same rules.
type NftablesController struct {
	logger *slog.Logger
}

// NewNftablesController returns a new NftablesController.
func NewNftablesController(logger *slog.Logger) *NftablesController {
	return &NftablesController{logger: logger}
}

// chainNames derives the names of the two base chains a configured chain name
// stands for.
func chainNames(chain string) (input, forward string) {
	return chain + "-input", chain + "-forward"
}

// baseChains returns the two base chains of a configured chain name in table,
// for adding to or naming in a batch.
func baseChains(table *nftables.Table, chain string) (input, forward *nftables.Chain) {
	inputName, forwardName := chainNames(chain)
	policy := nftables.ChainPolicyAccept
	input = &nftables.Chain{
		Name:     inputName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	}
	forward = &nftables.Chain{
		Name:     forwardName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	}
	return input, forward
}

// Probe reports whether the nftables backend is usable, without changing any
// kernel state. It dumps the inet table list: nfnetlink gates every message on
// CAP_NET_ADMIN, dumps included, so a dropped capability or an nf_tables
// subsystem the kernel does not offer is reported here rather than on the first
// EnsureChain — which by then has already added a table to its batch.
//
// A read is deliberate: the caller runs this before registration, so it must not
// leave a table behind on a node that goes on to fail startup for another
// reason.
func (c *NftablesController) Probe() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: probe: %w", err)
	}

	if _, err := conn.ListTablesOfFamily(nftables.TableFamilyINet); err != nil {
		return fmt.Errorf("policy: nftables: probe: %w", err)
	}

	c.logger.Debug("nftables backend probed", "component", "policy")
	return nil
}

// EnsureChain creates the two base chains of the named chain if they do not
// already exist: one on the input hook, so the kernel evaluates its rules for
// traffic addressed to the node, and one on the forward hook, for traffic the
// node routes.
func (c *NftablesController) EnsureChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: ensure chain: %w", err)
	}

	// A plexd before the inet table kept its chain in the IPv4 table of the
	// same name and leaves it behind when it crashes. That chain hooks
	// forward and ends in a drop, so it would still drop what the new chains
	// accept: it goes in the same batch that adds them.
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("policy: nftables: ensure chain: list tables: %w", err)
	}
	legacy := false
	for _, t := range tables {
		if t.Name == tableName {
			conn.DelTable(t)
			legacy = true
			break
		}
	}

	table := c.ensureTable(conn)
	input, forward := baseChains(table, chain)
	conn.AddChain(input)
	conn.AddChain(forward)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: ensure chain %q: %w", chain, err)
	}

	if legacy {
		c.logger.Info("removed the IPv4 nftables table an earlier plexd left behind",
			"component", "policy",
			"table", "ip "+tableName,
		)
	}
	c.logger.Debug("nftables chain ensured",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// ApplyRules replaces all rules in both base chains of the named chain
// atomically. It flushes the two chains and writes the same list into each in
// one batch: first the connection tracking rules of every interface the rules
// name, then each FirewallRule as an nftables rule with its match expressions
// and verdict.
//
// DECISION: only packets in the reply direction of a tracked connection bypass
// the rules. Every packet in a connection's original direction is matched
// against the rules, so a revoked rule cuts an established inbound or
// forwarded connection at its next packet, as a stateless chain would, while
// the replies to a connection the node or a host behind it opened pass
// without a rule of their own. Accepting every established packet instead
// would keep a revoked connection alive until conntrack forgets it.
func (c *NftablesController) ApplyRules(chain string, rules []FirewallRule) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: apply rules: %w", err)
	}

	list, err := chainRuleExprs(rules)
	if err != nil {
		return err
	}

	table := c.ensureTable(conn)
	input, forward := baseChains(table, chain)
	for _, nftChain := range []*nftables.Chain{input, forward} {
		conn.AddChain(nftChain)
		conn.FlushChain(nftChain)
		for _, exprs := range list {
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: nftChain,
				Exprs: exprs,
			})
		}
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

// FlushChain removes all rules from both base chains of the named chain.
func (c *NftablesController) FlushChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: flush chain: %w", err)
	}

	table := c.ensureTable(conn)
	input, forward := baseChains(table, chain)
	conn.FlushChain(input)
	conn.FlushChain(forward)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: flush chain %q: %w", chain, err)
	}

	c.logger.Debug("nftables chain flushed",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// DeleteChain deletes both base chains of the named chain. It is idempotent:
// a chain that does not exist is skipped, and deleting a chain neither of
// whose base chains exists returns nil.
func (c *NftablesController) DeleteChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: delete chain: %w", err)
	}

	// List existing chains to check which of the two exist.
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("policy: nftables: delete chain: list chains: %w", err)
	}

	inputName, forwardName := chainNames(chain)
	found := 0
	for _, ch := range chains {
		if ch.Table.Name == tableName && (ch.Name == inputName || ch.Name == forwardName) {
			conn.DelChain(ch)
			found++
		}
	}

	if found == 0 {
		// Neither chain exists — idempotent success.
		c.logger.Debug("nftables chain not found, nothing to delete",
			"component", "policy",
			"chain", chain,
			"table", tableName,
		)
		return nil
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: delete chain %q: %w", chain, err)
	}
	c.logger.Debug("nftables chain deleted",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// ensureTable adds the plexd inet filter table to the connection batch.
// AddTable is idempotent in nftables — adding an existing table is a no-op.
func (c *NftablesController) ensureTable(conn *nftables.Conn) *nftables.Table {
	return conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
}

// chainRuleExprs translates rules into the list ApplyRules writes into each
// base chain: the two connection tracking rules of every interface the rules
// name, once per interface in order of first appearance, then one rule per
// FirewallRule in the order given.
func chainRuleExprs(rules []FirewallRule) ([][]expr.Any, error) {
	var ifaces []string
	seen := make(map[string]bool)
	ruleExprs := make([][]expr.Any, 0, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("policy: nftables: apply rules: %w", err)
		}
		exprs, err := buildRuleExprs(rule)
		if err != nil {
			return nil, fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
		}
		ruleExprs = append(ruleExprs, exprs)
		if !seen[rule.Interface] {
			seen[rule.Interface] = true
			ifaces = append(ifaces, rule.Interface)
		}
	}

	list := make([][]expr.Any, 0, 2*len(ifaces)+len(ruleExprs))
	for _, iface := range ifaces {
		list = append(list, connTrackExprs(iface)...)
	}
	return append(list, ruleExprs...), nil
}

// ifaceMatchExprs matches the input interface name, or returns nil for an
// empty name, which matches every interface.
func ifaceMatchExprs(iface string) []expr.Any {
	if iface == "" {
		return nil
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifaceNameBytes(iface),
		},
	}
}

// connTrackExprs builds the two rules that open every chain for an interface:
// packets arriving on iface in the reply direction of an established
// connection, and packets related to a tracked connection. The second one
// passes the ICMP errors about a tracked connection in either direction, such
// as a "fragmentation needed" for a flow the node or a host behind it opened.
// The reply-direction DECISION is at ApplyRules.
func connTrackExprs(iface string) [][]expr.Any {
	established := ifaceMatchExprs(iface)
	established = append(established, ctStateExprs(expr.CtStateBitESTABLISHED)...)
	established = append(established,
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{ctDirectionReply},
		},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	related := ifaceMatchExprs(iface)
	related = append(related, ctStateExprs(expr.CtStateBitRELATED)...)
	related = append(related,
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	return [][]expr.Any{established, related}
}

// ctStateExprs matches packets whose conntrack state has the given bit set.
// The kernel loads the state as a host-order 32-bit value.
func ctStateExprs(bit uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(bit),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
	}
}

// buildRuleExprs converts a FirewallRule into nftables match expressions and a verdict.
//
// The inet table sees IPv4 and IPv6 packets alike, so a rule that names an
// address family matches it with meta nfproto before it reads an address out
// of the network header, whose layout the family decides. A rule without
// addresses, the default deny, matches both families.
func buildRuleExprs(rule FirewallRule) ([]expr.Any, error) {
	exprs := ifaceMatchExprs(rule.Interface)

	fam, err := rule.family()
	if err != nil {
		return nil, err
	}
	switch fam {
	case familyIPv4:
		exprs = append(exprs, nfprotoExprs(unix.NFPROTO_IPV4)...)
	case familyIPv6:
		exprs = append(exprs, nfprotoExprs(unix.NFPROTO_IPV6)...)
	}

	src, srcOK, err := parseRuleAddr(rule.SrcIP)
	if err != nil {
		return nil, fmt.Errorf("source IP: %w", err)
	}
	if srcOK {
		exprs = append(exprs, buildIPMatchExprs(src, true)...)
	}

	dst, dstOK, err := parseRuleAddr(rule.DstIP)
	if err != nil {
		return nil, fmt.Errorf("destination IP: %w", err)
	}
	if dstOK {
		exprs = append(exprs, buildIPMatchExprs(dst, false)...)
	}

	// Match protocol if specified.
	if rule.Protocol != "" {
		proto, err := protocolNumber(rule.Protocol, fam)
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
		exprs = append(exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // TCP/UDP destination port offset
			Len:          2,
		})
		if rule.PortTo > rule.Port {
			// Inclusive range match: Port <= dport <= PortTo.
			exprs = append(exprs,
				&expr.Cmp{
					Op:       expr.CmpOpGte,
					Register: 1,
					Data:     portBytes(uint16(rule.Port)),
				},
				&expr.Cmp{
					Op:       expr.CmpOpLte,
					Register: 1,
					Data:     portBytes(uint16(rule.PortTo)),
				},
			)
		} else {
			exprs = append(exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes(uint16(rule.Port)),
			})
		}
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

// nfprotoExprs matches packets of one address family (NFPROTO_IPV4 or
// NFPROTO_IPV6).
func nfprotoExprs(family byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{family},
		},
	}
}

// buildIPMatchExprs creates payload + cmp expressions that match the source
// (source true) or destination address of a packet against prefix. The
// address sits at offset 12 (source) or 16 (destination) of an IPv4 header,
// 4 bytes long, and at offset 8 or 24 of an IPv6 header, 16 bytes long. A
// full-length prefix is compared exactly, a shorter one through a bitwise
// mask. A zero-length prefix is every address of its family and yields no
// expressions: the caller's meta nfproto match is all it needs.
func buildIPMatchExprs(prefix netip.Prefix, source bool) []expr.Any {
	if prefix.Bits() == 0 {
		return nil
	}

	addr := prefix.Masked().Addr()
	var offset uint32
	switch {
	case addr.Is4() && source:
		offset = 12
	case addr.Is4():
		offset = 16
	case source:
		offset = 8
	default:
		offset = 24
	}
	data := addr.AsSlice()
	length := uint32(len(data))

	payload := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          length,
	}

	// Exact match for a full-length prefix.
	if prefix.Bits() == addr.BitLen() {
		return []expr.Any{
			payload,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     data,
			},
		}
	}

	// Subnet match: payload → bitwise(mask) → cmp(network address).
	return []expr.Any{
		payload,
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            length,
			Mask:           []byte(net.CIDRMask(prefix.Bits(), addr.BitLen())),
			Xor:            make([]byte, length),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     data,
		},
	}
}

// protocolNumber maps a protocol string to its IP protocol number. icmp is
// ICMP under IPv4 and ICMPv6 under IPv6; a rule without addresses names
// neither, which Validate refuses before a rule gets here.
func protocolNumber(proto string, fam addrFamily) (byte, error) {
	switch proto {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	case "icmp":
		switch fam {
		case familyIPv4:
			return unix.IPPROTO_ICMP, nil
		case familyIPv6:
			return unix.IPPROTO_ICMPV6, nil
		}
		return 0, errors.New("protocol icmp needs an address to choose between ICMP and ICMPv6")
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
