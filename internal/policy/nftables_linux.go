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
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// tableName is the nftables table name used by plexd for mesh policy enforcement.
const tableName = "plexd"

// netlinkBufferBase and netlinkBufferPerRule size the netlink socket of one
// ApplyRules batch: the base plus the allowance for every rule the batch
// adds. The kernel echoes every rule add back on the socket, and the echoes
// of a batch queue there until the batch is acknowledged, so the default
// buffer of about 208 KiB overflows (ENOBUFS) once a batch adds about 110
// rules, which three chains reach at fewer than 40 policy rules. A rule add
// and its echo took about 2 KiB each on Linux 6.8; the allowance leaves
// four times that.
const (
	netlinkBufferBase    = 1 << 20
	netlinkBufferPerRule = 8 << 10
)

// ctDirectionReply is IP_CT_DIR_REPLY, the value the kernel loads for
// "ct direction" when a packet travels against its connection's first packet.
const ctDirectionReply = 1

// NftablesController implements FirewallController using the Linux nftables subsystem
// via the google/nftables netlink library. It manages one inet filter table
// ("plexd"), which matches IPv4 and IPv6 alike, and gives every configured
// chain name three base chains in it: one on the input hook for traffic
// addressed to the node, one on the forward hook for traffic it routes, and
// one on the output hook for traffic the node's own sockets send. All three
// hold the same rules. The input and forward chains match them against the
// interface a packet arrives on, and the output chain against the interface
// a packet leaves through, behind the foreign-source rule and the relay probe
// exemption.
type NftablesController struct {
	logger *slog.Logger
}

// NewNftablesController returns a new NftablesController.
func NewNftablesController(logger *slog.Logger) *NftablesController {
	return &NftablesController{logger: logger}
}

// ifaceDir selects the interface a rule's interface match reads.
type ifaceDir int

const (
	// dirIn matches the interface a packet arrives on (meta iifname), for the
	// input and forward chains.
	dirIn ifaceDir = iota
	// dirOut matches the interface a packet leaves through (meta oifname), for
	// the output chain.
	dirOut
)

// chainNames derives the names of the three base chains a configured chain
// name stands for.
func chainNames(chain string) (input, forward, output string) {
	return chain + "-input", chain + "-forward", chain + "-output"
}

// baseChains returns the three base chains of a configured chain name in
// table, for adding to or naming in a batch.
func baseChains(table *nftables.Table, chain string) (input, forward, output *nftables.Chain) {
	inputName, forwardName, outputName := chainNames(chain)
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
	output = &nftables.Chain{
		Name:     outputName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	}
	return input, forward, output
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

// EnsureChain creates the three base chains of the named chain in one batch if
// they do not already exist: one on the input hook, so the kernel evaluates
// its rules for traffic addressed to the node, one on the forward hook, for
// traffic the node routes, and one on the output hook, for traffic the node's
// own sockets send.
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
	input, forward, output := baseChains(table, chain)
	conn.AddChain(input)
	conn.AddChain(forward)
	conn.AddChain(output)

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

// ApplyRules replaces all rules in the three base chains of the named chain
// atomically. It builds two lists from the rules before it touches the batch:
// one for the input and forward chains, which matches the interface a packet
// arrives on, and one for the output chain, which matches the interface a
// packet leaves through. Each list opens with the connection tracking rules
// of every interface the rules name, which the output list follows with that
// interface's foreign-source rule and relay probe rule, and then holds each
// FirewallRule as an nftables rule with its match expressions and verdict.
// It flushes the three chains and writes the lists into them in one batch,
// so the three change together or not at all.
//
// DECISION: only packets in the reply direction of a tracked connection bypass
// the rules, in all three chains. Every packet in a connection's original
// direction is matched against the rules, so a revoked rule cuts an
// established connection at its next packet, as a stateless chain would: an
// inbound or forwarded one in the input or forward chain, and one the node's
// own sockets opened in the output chain. The replies pass without a rule of
// their own: those that arrive for a connection the node or a host behind it
// opened, and those the node sends for a connection the policy let in.
// Accepting every established packet instead would keep a revoked connection
// alive until conntrack forgets it.
//
// DECISION: the output chain filters only what the node itself sends from
// an address of the mesh interface (author, 2026-11-12): the packets of its
// own sockets, and the ICMP errors and TCP resets its kernel generates, which
// pass as related or reply traffic. A packet the node forwards into the mesh,
// from a user-access client, a site-to-site peer, a host behind a bridge, or
// a container or Pod masqueraded onto the node's address, takes the forward
// hook, whose chain matches the interface the packet arrived on, so it is not
// filtered on its way out. Some packets reach the output chain with another
// source: IPVS sends a Pod's packet to a Service endpoint behind the mesh
// through the output hook with the Pod's address, and a socket can bind
// another address of the node. Masquerade gives such a packet the mesh
// address only after this hook, at postrouting, so no rule could match it;
// the foreign-source rule (foreignSourceExprs) lets it out unfiltered, as
// forwarded traffic leaves. A packet that leaves with a foreign source is
// dropped by the receiving peer's WireGuard, which accepts from a peer only
// the addresses it allows for that peer. kube-proxy's DNAT of a host-network
// connection to a Service never meets the output chain as plexd0 traffic:
// the filter chains of the output hook see the interface of the route the
// connection started on, and the DNAT reroutes it only for postrouting.
//
// The batch's netlink socket gets buffers sized to the number of rules it
// adds (applyBufferBytes), because the default ones cannot hold the echoes
// of a ruleset of a few dozen policy rules written into three chains.
func (c *NftablesController) ApplyRules(chain string, rules []FirewallRule) error {
	inList, err := chainRuleExprs(rules, dirIn)
	if err != nil {
		return err
	}
	outList, err := chainRuleExprs(rules, dirOut)
	if err != nil {
		return err
	}

	conn, err := nftables.New(nftables.WithSockOptions(sizeSocketBuffers(applyBufferBytes(len(inList), len(outList)))))
	if err != nil {
		return fmt.Errorf("policy: nftables: apply rules: %w", err)
	}

	table := c.ensureTable(conn)
	input, forward, output := baseChains(table, chain)
	for _, fill := range []struct {
		nftChain *nftables.Chain
		list     [][]expr.Any
	}{
		{input, inList},
		{forward, inList},
		{output, outList},
	} {
		conn.AddChain(fill.nftChain)
		conn.FlushChain(fill.nftChain)
		for _, exprs := range fill.list {
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: fill.nftChain,
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

// FlushChain removes all rules from those of the three base chains of the
// named chain that exist. A chain that does not exist is skipped, and a chain
// none of whose base chains exists returns nil, so Enforcer.Teardown reaches
// DeleteChain also where only some of them exist, such as the two chains of a
// plexd before the output chain.
func (c *NftablesController) FlushChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: flush chain: %w", err)
	}

	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("policy: nftables: flush chain: list chains: %w", err)
	}

	inputName, forwardName, outputName := chainNames(chain)
	found := 0
	for _, ch := range chains {
		if ch.Table.Name == tableName && (ch.Name == inputName || ch.Name == forwardName || ch.Name == outputName) {
			conn.FlushChain(ch)
			found++
		}
	}
	if found == 0 {
		c.logger.Debug("nftables chain not found, nothing to flush",
			"component", "policy",
			"chain", chain,
			"table", tableName,
		)
		return nil
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: flush chain %q: %w", chain, err)
	}

	c.logger.Debug("nftables chain flushed",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// DeleteChain deletes the three base chains of the named chain. It is
// idempotent: a chain that does not exist is skipped, and deleting a chain
// none of whose base chains exists returns nil.
func (c *NftablesController) DeleteChain(chain string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("policy: nftables: delete chain: %w", err)
	}

	// List existing chains to check which of the three exist.
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("policy: nftables: delete chain: list chains: %w", err)
	}

	inputName, forwardName, outputName := chainNames(chain)
	found := 0
	for _, ch := range chains {
		if ch.Table.Name == tableName && (ch.Name == inputName || ch.Name == forwardName || ch.Name == outputName) {
			conn.DelChain(ch)
			found++
		}
	}

	if found == 0 {
		// None of the three exists, which DeleteChain treats as success.
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

// applyBufferBytes returns the netlink socket buffer size for an ApplyRules
// batch that writes inRules into the input and the forward chain and
// outRules into the output chain.
func applyBufferBytes(inRules, outRules int) int {
	return netlinkBufferBase + (2*inRules+outRules)*netlinkBufferPerRule
}

// sizeSocketBuffers returns a socket option that raises the netlink socket's
// send and receive buffers to size bytes. The FORCE variants go past the
// host's net.core.wmem_max and rmem_max, which plexd's CAP_NET_ADMIN allows.
// Without that capability it falls back to the plain variants, which the
// host caps.
//
// DECISION: the option never fails. google/nftables v0.3.0 leaves the netlink
// socket open when a socket option returns an error, and a batch that still
// does not fit fails on its own, with the kernel's ENOBUFS or EMSGSIZE in
// ApplyRules's error.
func sizeSocketBuffers(size int) nftables.SockOption {
	return func(conn *netlink.Conn) error {
		raw, err := conn.SyscallConn()
		if err != nil {
			return nil
		}
		_ = raw.Control(func(fd uintptr) {
			for _, opt := range [][2]int{
				{unix.SO_SNDBUFFORCE, unix.SO_SNDBUF},
				{unix.SO_RCVBUFFORCE, unix.SO_RCVBUF},
			} {
				if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt[0], size) != nil {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt[1], size)
				}
			}
		})
		return nil
	}
}

// ensureTable adds the plexd inet filter table to the connection batch.
// AddTable is idempotent in nftables — adding an existing table is a no-op.
func (c *NftablesController) ensureTable(conn *nftables.Conn) *nftables.Table {
	return conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
}

// chainRuleExprs translates rules into the list ApplyRules writes into a base
// chain, with every interface match reading the interface dir selects. The
// list opens, for every interface the rules name, once per interface in order
// of first appearance, with its two connection tracking rules and, for
// dirOut, its foreign-source rule and its relay probe rule. One rule per
// FirewallRule follows, in the order given.
func chainRuleExprs(rules []FirewallRule, dir ifaceDir) ([][]expr.Any, error) {
	var ifaces []string
	seen := make(map[string]bool)
	ruleExprs := make([][]expr.Any, 0, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("policy: nftables: apply rules: %w", err)
		}
		exprs, err := buildRuleExprs(rule, dir)
		if err != nil {
			return nil, fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
		}
		ruleExprs = append(ruleExprs, exprs)
		if !seen[rule.Interface] {
			seen[rule.Interface] = true
			ifaces = append(ifaces, rule.Interface)
		}
	}

	perIface := 2
	if dir == dirOut {
		perIface = 4
	}
	list := make([][]expr.Any, 0, perIface*len(ifaces)+len(ruleExprs))
	for _, iface := range ifaces {
		list = append(list, connTrackExprs(iface, dir)...)
		if dir != dirOut {
			continue
		}
		list = append(list, foreignSourceExprs(iface))
		probe, err := buildRuleExprs(relayProbeRule(iface), dir)
		if err != nil {
			return nil, fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
		}
		list = append(list, probe)
	}
	return append(list, ruleExprs...), nil
}

// foreignSourceExprs builds the rule that lets a packet leave iface without
// meeting the policy rules when its source is not an address of iface:
// oifname "<iface>" fib saddr . oif type != local counter accept. fib asks
// the routing table for the type of the source address on the outgoing
// interface, which is local only for an address assigned to that interface,
// so the node's mesh address is filtered and eth0's, a Pod's or a container's
// is not. The scope DECISION is at ApplyRules.
func foreignSourceExprs(iface string) []expr.Any {
	return append(ifaceMatchExprs(iface, dirOut),
		&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagSADDR: true, FlagOIF: true},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL),
		},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// relayProbeRule returns the rule that lets the node send plexd's relay
// liveness probe out of iface ahead of the policy rules. It names no address,
// so it matches IPv4 and IPv6. The exemption's DECISION is at RelayProbePort.
func relayProbeRule(iface string) FirewallRule {
	return FirewallRule{Interface: iface, Protocol: "udp", Port: RelayProbePort, Action: "allow"}
}

// ifaceMatchExprs matches the name of the interface dir selects, the input
// interface for dirIn and the output interface for dirOut, or returns nil for
// an empty name, which matches every interface.
func ifaceMatchExprs(iface string, dir ifaceDir) []expr.Any {
	if iface == "" {
		return nil
	}
	key := expr.MetaKeyIIFNAME
	if dir == dirOut {
		key = expr.MetaKeyOIFNAME
	}
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifaceNameBytes(iface),
		},
	}
}

// connTrackExprs builds the two rules that open every chain for an interface:
// packets on iface in the reply direction of an established connection, and
// packets related to a tracked connection. dir selects whether iface is the
// interface a packet arrives on or the one it leaves through. The second rule
// passes the ICMP errors about a tracked connection in either direction, such
// as a "fragmentation needed" for a flow the node or a host behind it opened.
// The reply-direction DECISION is at ApplyRules.
func connTrackExprs(iface string, dir ifaceDir) [][]expr.Any {
	established := ifaceMatchExprs(iface, dir)
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

	related := ifaceMatchExprs(iface, dir)
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

// buildRuleExprs converts a FirewallRule into nftables match expressions and a
// verdict. Its interface match reads the interface dir selects.
//
// The inet table sees IPv4 and IPv6 packets alike, so a rule that names an
// address family matches it with meta nfproto before it reads an address out
// of the network header, whose layout the family decides. A rule without
// addresses, the default deny, matches both families.
func buildRuleExprs(rule FirewallRule, dir ifaceDir) ([]expr.Any, error) {
	exprs := ifaceMatchExprs(rule.Interface, dir)

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
