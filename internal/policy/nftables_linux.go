//go:build linux

package policy

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"

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
// four times that. netlinkBufferPerElement is the allowance for every set
// element: a batch of 3 × 15,003 elements failed with EMSGSIZE on 1 MiB
// buffers and passed with 1 MiB plus 256 bytes per element.
const (
	netlinkBufferBase       = 1 << 20
	netlinkBufferPerRule    = 8 << 10
	netlinkBufferPerElement = 256
)

// setElemsPerMessage bounds the elements of one netlink message. AddSet and
// SetAddElements put all elements of a call into one netlink attribute, whose
// length field has 16 bits: 1,303 elements of the IPv4 port shape arrived as
// 42 on Linux 6.8, and neither the call nor Flush returned an error. 256
// elements per message arrive whole.
const setElemsPerMessage = 256

// regConcat is NFT_REG32_00, the first of the kernel's 4-byte registers,
// which golang.org/x/sys/unix does not define. A set rule loads the fields
// of its key into consecutive 4-byte registers from there, and its lookup
// reads the concatenation back from the same register.
const regConcat = 8

// ctDirectionReply is IP_CT_DIR_REPLY, the value the kernel loads for
// "ct direction" when a packet travels against its connection's first packet.
const ctDirectionReply = 1

// nflogGroup is the NFLOG group plexd's log rules write to and its reader
// binds: 28772 is ASCII "pd".
const nflogGroup uint16 = 28772

// NftablesController implements FirewallController using the Linux nftables subsystem
// via the google/nftables netlink library. It manages one inet filter table
// ("plexd"), which matches IPv4 and IPv6 alike, and gives every configured
// chain name three base chains in it: one on the input hook for traffic
// addressed to the node, one on the forward hook for traffic it routes, and
// one on the output hook for traffic the node's own sockets send. All three
// hold the same rules. The input and forward chains match them against the
// interface a packet arrives on, and the output chain against the interface
// a packet leaves through. When every rule names an interface, each chain
// opens with a guard that accepts a packet on any other interface, so only
// traffic on the policy's interfaces meets the rules. The input chain holds
// them behind the round-trip probe exemption, and the output chain behind
// the foreign-source rule and the relay and round-trip probe exemptions.
// The unlogged allows that name an address are looked up in anonymous sets
// rather than walked as a list, unless the kernel refused the sets once
// (listOnly).
//
// A rule with a LogTag gets a log rule in front of it, which sends the first
// packet of each connection it admits to NFLOG group nflogGroup. The
// controller reads that group and hands each record to the sink SetConnSink
// set.
type NftablesController struct {
	logger *slog.Logger

	// openLog opens the reader of the NFLOG group. It is openNflog, which
	// tests replace.
	openLog func(group uint16, sink ConnSink, logger *slog.Logger) (*nflogReader, error)

	// write writes the three lists of an apply into the kernel in one
	// batch. It is writeChains, which tests replace.
	write func(chain string, lists [3][]chainEntry) error

	mu     sync.Mutex // guards sink, reader and listOnly
	sink   ConnSink
	reader *nflogReader
	// listOnly is set once the kernel refused a ruleset with sets and took
	// it as a list. Every later apply writes the list until the process
	// ends.
	listOnly bool
}

// ruleSetsUnavailable is the Warn line ApplyRules logs when the kernel
// refused the rule sets and took the rules as a list.
const ruleSetsUnavailable = "policy rule sets unavailable, rules are installed as a list"

var (
	_ ConnReporter = (*NftablesController)(nil)
	_ DropCounter  = (*NftablesController)(nil)
)

// NewNftablesController returns a new NftablesController.
func NewNftablesController(logger *slog.Logger) *NftablesController {
	c := &NftablesController{logger: logger, openLog: openNflog}
	c.write = c.writeChains
	return c
}

// SetConnSink sets the sink the NFLOG reader hands the connections of logged
// rules to. Without a sink ApplyRules installs no log rule. A reader opened
// for an earlier sink is closed, and the next ApplyRules with a logged rule
// opens one for this sink.
func (c *NftablesController) SetConnSink(sink ConnSink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sink = sink
	c.closeReaderLocked()
}

// prepareLogging returns the rules ApplyRules installs. Rules without a log
// tag come back as they are. For rules with one it makes sure a reader of the
// NFLOG group runs, opening one when none does, and returns them as they are.
// Without a sink, or when the reader cannot be opened, it returns them
// without their log tags, and a failed open is logged at Warn.
//
// DECISION: logging never blocks enforcement (#179). A
// reader that cannot start leaves the logged rules enforced without logging,
// rather than failing the apply. Leaving the log rules out also keeps the
// records away from another process that holds plexd's NFLOG group, which
// would otherwise receive them.
func (c *NftablesController) prepareLogging(rules []FirewallRule) []FirewallRule {
	if !hasLogTags(rules) {
		return rules
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sink == nil {
		return withoutLogTags(rules)
	}
	if c.reader != nil && c.reader.running() {
		return rules
	}
	// A reader whose loop ended still holds the group: closing it lets the
	// new one bind.
	c.closeReaderLocked()
	reader, err := c.openLog(nflogGroup, c.sink, c.logger)
	if err != nil {
		c.logger.Warn(connLogUnavailable,
			"component", "policy",
			"error", err,
		)
		return withoutLogTags(rules)
	}
	c.reader = reader
	return rules
}

// closeLog closes the NFLOG reader, if one is open.
func (c *NftablesController) closeLog() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeReaderLocked()
}

// closeReaderLocked closes the NFLOG reader, if one is open. c.mu must be
// held.
func (c *NftablesController) closeReaderLocked() {
	if c.reader == nil {
		return
	}
	_ = c.reader.Close()
	c.reader = nil
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
	// dirNone matches no interface. A list whose guard names one interface
	// builds every other rule with it: what reaches them is on that
	// interface already.
	dirNone
)

// chainHook selects the base chain a rule list is built for.
type chainHook int

const (
	// hookInput is the chain on the input hook, for what arrives for the
	// node itself.
	hookInput chainHook = iota
	// hookForward is the chain on the forward hook, for what the node routes.
	hookForward
	// hookOutput is the chain on the output hook, for what the node's own
	// sockets send.
	hookOutput
)

// dir returns the interface the chain's interface matches read: the one a
// packet arrives on for the input and forward chains, the one it leaves
// through for the output chain.
func (h chainHook) dir() ifaceDir {
	if h == hookOutput {
		return dirOut
	}
	return dirIn
}

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
// atomically. It builds one list from the rules for each base chain before it
// touches the batch (chainRuleExprs): the input and forward lists match the
// interface a packet arrives on, and the output list the interface a packet
// leaves through. When every rule names an interface, each list opens with a
// guard that accepts a packet on any interface no rule names (guardExprs),
// so traffic outside the policy's interfaces passes one rule instead of all
// of them. Each list goes on with the connection tracking rules of every
// interface the rules name. The input list follows them with that
// interface's round-trip probe rule, and the output list with its
// foreign-source rule, relay probe rule and round-trip probe rule; the
// forward list adds none, so nothing the node forwards passes an exemption.
// Then each list holds the rules in the order given (segmentRules): a rule
// with a LogTag, a deny and a rule without an address as an nftables rule
// with its match expressions and verdict, behind its log rule when it
// carries a LogTag, and every run of consecutive unlogged allows with an
// address and the same Interface as set rules, each of which looks the
// packet up in an anonymous set of the run's addresses, protocols and ports.
// A mesh packet so costs a fixed number of lookups instead of a walk of the
// list. It flushes the three chains, which drops the sets of their old
// rules, and writes each list and its sets into its own chain in one batch,
// so the three change together or not at all.
//
// Before it builds the lists, prepareLogging opens the NFLOG reader a logged
// rule needs, or takes the log tags off when it cannot. A host whose kernel
// cannot load nfnetlink_log fails the open, not the batch.
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
// The batch's netlink socket gets buffers sized to the number of rules and
// set elements it adds (applyBufferBytes), because the default ones cannot
// hold the echoes of a ruleset of a few dozen policy rules written into
// three chains.
//
// A kernel that refuses the sets gets the rule list behind the same guard.
// When a write whose lists hold a set fails, ApplyRules builds the lists
// again without sets and writes once more. When that succeeds, it sets
// listOnly, logs ruleSetsUnavailable at Warn with the first write's error,
// and returns nil; every later apply writes the list. When it fails too,
// ApplyRules returns its error, and the next apply tries the sets again. A
// failed write of lists without a set is not retried. Every write is one
// atomic batch, so a failed one leaves the chains as they were. The retry
// is not tied to an errno: interval concatenations entered mainline in
// Linux 5.6, and what an older kernel answers was not measured.
func (c *NftablesController) ApplyRules(chain string, rules []FirewallRule) error {
	rules = c.prepareLogging(rules)
	// build returns the three lists and whether they hold a set.
	build := func(sets bool) (lists [3][]chainEntry, held bool, err error) {
		segments, err := segmentRules(rules, sets)
		if err != nil {
			return lists, false, err
		}
		for i, hook := range []chainHook{hookInput, hookForward, hookOutput} {
			if lists[i], err = chainRuleExprs(segments, hook); err != nil {
				return lists, false, err
			}
		}
		return lists, slices.ContainsFunc(segments, func(s segment) bool { return s.sets != nil }), nil
	}

	c.mu.Lock()
	sets := !c.listOnly
	c.mu.Unlock()
	lists, held, err := build(sets)
	if err != nil {
		return err
	}
	if err := c.write(chain, lists); err != nil {
		if !held {
			return err
		}
		lists, _, buildErr := build(false)
		if buildErr != nil {
			return buildErr
		}
		if listErr := c.write(chain, lists); listErr != nil {
			return listErr
		}
		c.mu.Lock()
		c.listOnly = true
		c.mu.Unlock()
		c.logger.Warn(ruleSetsUnavailable,
			"component", "policy",
			"chain", chain,
			"error", err,
		)
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
// none of whose base chains exists returns nil. It closes the NFLOG reader
// first, also when no chain exists.
func (c *NftablesController) DeleteChain(chain string) error {
	c.closeLog()

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

// DropCounts returns the packets and bytes the drop rules in the three base
// chains of the named chain dropped. It implements DropCounter. buildRuleExprs
// ends every rule it builds in a counter and a verdict, the guard ends in
// accept without a counter, the set rules end in a counter and accept, and
// the default deny is the only rule the engine gives a drop verdict, so the
// sum is what the default deny dropped. The counters restart when ApplyRules
// replaces the chain: it flushes the three chains and adds every rule again
// with a counter at zero. It reads the counters with one rule dump per base
// chain.
func (c *NftablesController) DropCounts(chain string) (packets, bytes uint64, err error) {
	conn, err := nftables.New()
	if err != nil {
		return 0, 0, fmt.Errorf("policy: nftables: drop counts: %w", err)
	}

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
	inputName, forwardName, outputName := chainNames(chain)
	for _, name := range []string{inputName, forwardName, outputName} {
		rules, getErr := conn.GetRules(table, &nftables.Chain{Name: name, Table: table})
		if getErr != nil {
			return 0, 0, fmt.Errorf("policy: nftables: drop counts: chain %q: %w", name, getErr)
		}
		p, b := sumDropCounters(rules)
		packets += p
		bytes += b
	}
	return packets, bytes, nil
}

// sumDropCounters sums the counters of the rules whose last expression is a
// drop verdict, and ignores every other rule: those that accept, the guard
// and the set rules among them, and the log rules, which end in their log
// expression. A rule's counter is the first counter expression it holds;
// buildRuleExprs gives every rule it builds exactly one.
func sumDropCounters(rules []*nftables.Rule) (packets, bytes uint64) {
	for _, rule := range rules {
		if len(rule.Exprs) == 0 {
			continue
		}
		verdict, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
		if !ok || verdict.Kind != expr.VerdictDrop {
			continue
		}
		for _, e := range rule.Exprs {
			if counter, ok := e.(*expr.Counter); ok {
				packets += counter.Packets
				bytes += counter.Bytes
				break
			}
		}
	}
	return packets, bytes
}

// applyBufferBytes returns the netlink socket buffer size for an ApplyRules
// batch that adds rules rules and elements set elements across the three
// chains.
func applyBufferBytes(rules, elements int) int {
	return netlinkBufferBase + rules*netlinkBufferPerRule + elements*netlinkBufferPerElement
}

// writeChains writes lists, the input, forward and output list in that
// order, into the three base chains of the named chain in one batch: per
// chain AddChain, FlushChain and one AddRule per entry, then one Flush.
//
// An entry with a set gets its own anonymous, constant, interval,
// concatenated set first, so each chain holds its own copy. AddSet carries
// the first setElemsPerMessage elements, and SetAddElements every further
// chunk on a copy of the set that is not anonymous: the library refuses to
// add to an anonymous set, and the copy keeps the name, ID and table that
// address the same set inside the batch. The entry's rule gets a copy of its
// lookup that names the set.
func (c *NftablesController) writeChains(chain string, lists [3][]chainEntry) error {
	rules, elements := 0, 0
	for _, list := range lists {
		rules += len(list)
		for _, entry := range list {
			if entry.set != nil {
				elements += len(entry.set.elems)
			}
		}
	}
	conn, err := nftables.New(nftables.WithSockOptions(sizeSocketBuffers(applyBufferBytes(rules, elements))))
	if err != nil {
		return fmt.Errorf("policy: nftables: apply rules: %w", err)
	}

	table := c.ensureTable(conn)
	input, forward, output := baseChains(table, chain)
	for i, nftChain := range []*nftables.Chain{input, forward, output} {
		conn.AddChain(nftChain)
		conn.FlushChain(nftChain)
		for _, entry := range lists[i] {
			exprs := entry.exprs
			if entry.set != nil {
				set := &nftables.Set{
					Table:         table,
					Anonymous:     true,
					Constant:      true,
					Interval:      true,
					Concatenation: true,
					KeyType:       setKeyType(entry.set.family, entry.set.shape),
				}
				chunks := elementChunks(entry.set.elems)
				var first []nftables.SetElement
				if len(chunks) > 0 {
					first, chunks = chunks[0], chunks[1:]
				}
				if err := conn.AddSet(set, first); err != nil {
					return fmt.Errorf("policy: nftables: apply rules: add set: %w", err)
				}
				named := *set
				named.Anonymous = false
				for _, chunk := range chunks {
					if err := conn.SetAddElements(&named, chunk); err != nil {
						return fmt.Errorf("policy: nftables: apply rules: add set: %w", err)
					}
				}
				exprs = slices.Clone(exprs)
				for k, e := range exprs {
					if lookup, ok := e.(*expr.Lookup); ok {
						bound := *lookup
						bound.SetName, bound.SetID = set.Name, set.ID
						exprs[k] = &bound
					}
				}
			}
			conn.AddRule(&nftables.Rule{Table: table, Chain: nftChain, Exprs: exprs})
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("policy: nftables: apply rules to chain %q: %w", chain, err)
	}
	return nil
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

// setShape names the fields a set's key concatenates. A lookup loads only
// the fields its shape holds, so an any-protocol rule keeps matching a packet
// without a readable transport header, as its single rule does.
type setShape int

const (
	// shapeAddrs is a rule without a protocol: source . destination.
	shapeAddrs setShape = iota
	// shapeProto is a rule with a protocol and no port: source . destination
	// . protocol.
	shapeProto
	// shapePort is a rule with a destination port or port range: source .
	// destination . protocol . destination port.
	shapePort
)

// ruleSet is one set of a run: the elements of one layer of the run's rules
// of one family and shape.
type ruleSet struct {
	family addrFamily
	shape  setShape
	elems  []nftables.SetElement
}

// segment is one piece of the ruleset as ApplyRules writes it: one rule
// (sets is nil, iface its Interface) or a run of rules written as sets (sets
// holds one ruleSet per layer, iface the run's Interface).
type segment struct {
	rule  FirewallRule
	iface string
	sets  []ruleSet
}

// segmentRules validates every rule, then cuts the rules into segments in
// order. A rule joins a run when it is an allow, has no LogTag and names an
// address family. A run is a maximal sequence of consecutive such rules with
// the same Interface. Every other rule is a segment of its own and ends the
// run before it: a log rule needs its rule's own match, and a deny or a rule
// without an address has no place in an accept set. With sets false every
// rule is a segment of its own.
//
// Consecutive allows commute, so a run may be reordered and merged without
// changing a verdict; nothing moves across a logged rule or a deny. A run's
// rules are grouped by family and shape (boxOf), and each group is layered
// (layerBoxes) into sets in the order IPv4 shapeAddrs, shapeProto, shapePort,
// then IPv6 the same.
func segmentRules(rules []FirewallRule, sets bool) ([]segment, error) {
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("policy: nftables: apply rules: %w", err)
		}
	}
	joins := func(rule FirewallRule) bool {
		fam, err := rule.family()
		return sets && err == nil && fam != familyAny && rule.Action == "allow" && rule.LogTag == ""
	}

	var segments []segment
	for i := 0; i < len(rules); {
		rule := rules[i]
		if !joins(rule) {
			segments = append(segments, segment{rule: rule, iface: rule.Interface})
			i++
			continue
		}
		end := i + 1
		for end < len(rules) && joins(rules[end]) && rules[end].Interface == rule.Interface {
			end++
		}

		// groups holds the run's boxes by family, IPv4 then IPv6, and shape.
		var groups [2][3][]ruleBox
		for _, r := range rules[i:end] {
			box, fam, shape, err := boxOf(r)
			if err != nil {
				return nil, fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
			}
			f := 0
			if fam == familyIPv6 {
				f = 1
			}
			groups[f][shape] = append(groups[f][shape], box)
		}
		run := segment{iface: rule.Interface}
		for f, fam := range []addrFamily{familyIPv4, familyIPv6} {
			for shape, boxes := range groups[f] {
				for _, layer := range layerBoxes(boxes) {
					elems := make([]nftables.SetElement, len(layer))
					for k, box := range layer {
						elems[k] = box.element(setShape(shape))
					}
					run.sets = append(run.sets, ruleSet{family: fam, shape: setShape(shape), elems: elems})
				}
			}
		}
		segments = append(segments, run)
		i = end
	}
	return segments, nil
}

// ruleBox is what an allow rule admits, as a box in the space of source,
// destination, protocol and destination port: two prefixes, a protocol
// number and an inclusive port range. A shape the box does not use leaves
// its fields 0.
type ruleBox struct {
	src, dst   netip.Prefix
	proto      byte
	port, last uint16
}

// boxOf returns the box of a rule that names an address family, with that
// family and the rule's shape. An absent address is the zero-length prefix
// of the rule's family. last is PortTo when it is above Port, otherwise
// Port.
func boxOf(rule FirewallRule) (ruleBox, addrFamily, setShape, error) {
	fam, err := rule.family()
	if err != nil {
		return ruleBox{}, familyAny, shapeAddrs, err
	}
	if fam == familyAny {
		return ruleBox{}, familyAny, shapeAddrs, errors.New("a rule without an address has no box")
	}
	prefix := func(field string) (netip.Prefix, error) {
		p, ok, err := parseRuleAddr(field)
		if err != nil || ok {
			return p, err
		}
		if fam == familyIPv4 {
			return netip.PrefixFrom(netip.IPv4Unspecified(), 0), nil
		}
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0), nil
	}

	var box ruleBox
	if box.src, err = prefix(rule.SrcIP); err != nil {
		return ruleBox{}, familyAny, shapeAddrs, fmt.Errorf("source IP: %w", err)
	}
	if box.dst, err = prefix(rule.DstIP); err != nil {
		return ruleBox{}, familyAny, shapeAddrs, fmt.Errorf("destination IP: %w", err)
	}
	if rule.Protocol == "" {
		return box, fam, shapeAddrs, nil
	}
	if box.proto, err = protocolNumber(rule.Protocol, fam); err != nil {
		return ruleBox{}, familyAny, shapeAddrs, err
	}
	if rule.Port == 0 {
		return box, fam, shapeProto, nil
	}
	box.port, box.last = uint16(rule.Port), uint16(rule.Port)
	if rule.PortTo > rule.Port {
		box.last = uint16(rule.PortTo)
	}
	return box, fam, shapePort, nil
}

// contains reports whether b holds every point of o: both prefixes of o
// inside b's, the same protocol, and o's port range inside b's.
func (b ruleBox) contains(o ruleBox) bool {
	return b.src.Bits() <= o.src.Bits() && b.src.Contains(o.src.Addr()) &&
		b.dst.Bits() <= o.dst.Bits() && b.dst.Contains(o.dst.Addr()) &&
		b.proto == o.proto && b.port <= o.port && o.last <= b.last
}

// intersects reports whether b and o share a point: both address prefixes
// overlap, the protocols are equal and the port ranges overlap.
func (b ruleBox) intersects(o ruleBox) bool {
	return b.src.Overlaps(o.src) && b.dst.Overlaps(o.dst) &&
		b.proto == o.proto && b.port <= o.last && o.port <= b.last
}

// layerBoxes places the boxes of one family and shape into layers of
// pairwise disjoint boxes, each of which becomes one set. The kernel refuses
// an element whose first or last point lies inside an element its set
// already holds, and fails the whole batch with EEXIST, which disjoint boxes
// cannot do.
//
// It sorts the boxes stably by source prefix length ascending, destination
// prefix length ascending and port range width descending, so a box that
// contains another comes first. It drops a box that a box already placed
// contains, which admits nothing more, and places every other box in the
// first layer none of whose boxes it intersects, opening a new layer when
// none fits. The comparison is pairwise and so quadratic in the boxes; a
// ruleset of pairwise crossing boxes ends with one set per rule.
func layerBoxes(boxes []ruleBox) [][]ruleBox {
	sorted := slices.Clone(boxes)
	slices.SortStableFunc(sorted, func(a, b ruleBox) int {
		if c := cmp.Compare(a.src.Bits(), b.src.Bits()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.dst.Bits(), b.dst.Bits()); c != 0 {
			return c
		}
		return cmp.Compare(b.last-b.port, a.last-a.port)
	})

	var layers [][]ruleBox
	for _, box := range sorted {
		contained := slices.ContainsFunc(layers, func(layer []ruleBox) bool {
			return slices.ContainsFunc(layer, func(placed ruleBox) bool { return placed.contains(box) })
		})
		if contained {
			continue
		}
		i := slices.IndexFunc(layers, func(layer []ruleBox) bool {
			return !slices.ContainsFunc(layer, box.intersects)
		})
		if i < 0 {
			layers = append(layers, nil)
			i = len(layers) - 1
		}
		layers[i] = append(layers[i], box)
	}
	return layers
}

// element returns the set element of the box for shape. Key concatenates the
// first source address, the first destination address, then for shapeProto
// and shapePort the protocol padded to 4 bytes, then for shapePort the port
// in network byte order padded to 4 bytes. KeyEnd is the same with the last
// address of each prefix and last in place of port.
func (b ruleBox) element(shape setShape) nftables.SetElement {
	key := append(b.src.Addr().AsSlice(), b.dst.Addr().AsSlice()...)
	end := append(lastAddr(b.src).AsSlice(), lastAddr(b.dst).AsSlice()...)
	if shape != shapeAddrs {
		key = append(key, b.proto, 0, 0, 0)
		end = append(end, b.proto, 0, 0, 0)
	}
	if shape == shapePort {
		key = append(key, byte(b.port>>8), byte(b.port), 0, 0)
		end = append(end, byte(b.last>>8), byte(b.last), 0, 0)
	}
	return nftables.SetElement{Key: key, KeyEnd: end}
}

// lastAddr returns the last address of a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := range b {
		switch rest := p.Bits() - 8*i; {
		case rest <= 0:
			b[i] = 0xff
		case rest < 8:
			b[i] |= 0xff >> rest
		}
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

// setKeyType returns the key type of a set of family and shape: the address
// type twice, then the protocol and the service, as far as the shape goes.
func setKeyType(family addrFamily, shape setShape) nftables.SetDatatype {
	addr := nftables.TypeIPAddr
	if family == familyIPv6 {
		addr = nftables.TypeIP6Addr
	}
	types := []nftables.SetDatatype{addr, addr}
	if shape != shapeAddrs {
		types = append(types, nftables.TypeInetProto)
	}
	if shape == shapePort {
		types = append(types, nftables.TypeInetService)
	}
	return nftables.MustConcatSetType(types...)
}

// setLookupExprs builds a set rule: the interface match iface and dir give,
// the family match, the source address into regConcat, the destination
// address into the register after it, for shapeProto and shapePort the
// protocol into the next, for shapePort the destination port into the one
// after, then the lookup, a counter and accept. nft lists it as ip saddr . ip
// daddr . meta l4proto . th dport @set counter accept. The lookup names no
// set yet: writeChains gives each chain's copy its own.
func setLookupExprs(iface string, dir ifaceDir, family addrFamily, shape setShape) []expr.Any {
	nfproto := byte(unix.NFPROTO_IPV4)
	srcOffset, dstOffset, length := uint32(12), uint32(16), uint32(4)
	if family == familyIPv6 {
		nfproto = unix.NFPROTO_IPV6
		srcOffset, dstOffset, length = 8, 24, 16
	}
	// words is the address length in 4-byte registers.
	words := length / 4

	exprs := ifaceMatchExprs(iface, dir)
	exprs = append(exprs, nfprotoExprs(nfproto)...)
	exprs = append(exprs,
		&expr.Payload{DestRegister: regConcat, Base: expr.PayloadBaseNetworkHeader, Offset: srcOffset, Len: length},
		&expr.Payload{DestRegister: regConcat + words, Base: expr.PayloadBaseNetworkHeader, Offset: dstOffset, Len: length},
	)
	if shape != shapeAddrs {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: regConcat + 2*words})
	}
	if shape == shapePort {
		exprs = append(exprs, &expr.Payload{DestRegister: regConcat + 2*words + 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
	}
	return append(exprs,
		&expr.Lookup{SourceRegister: regConcat},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// elementChunks cuts elems into chunks of at most setElemsPerMessage, one
// netlink message each.
func elementChunks(elems []nftables.SetElement) [][]nftables.SetElement {
	return slices.Collect(slices.Chunk(elems, setElemsPerMessage))
}

// chainEntry is one rule of a list: its expressions, and for a set rule the
// set its lookup reads, which set is nil for every other rule.
type chainEntry struct {
	exprs []expr.Any
	set   *ruleSet
}

// chainRuleExprs translates segments into the list ApplyRules writes into the
// base chain hook selects, with every interface match reading the interface
// that chain matches (chainHook.dir).
//
// A list is guarded when the segments name at least one interface and none
// has an empty one. A guarded list starts with the guard (guardExprs), which
// names every interface of the segments in order of first appearance. When
// it names exactly one, every other rule of the list is built without an
// interface match (dirNone); with two or more each keeps the match of its
// rule or run. An unguarded list has no guard, and every rule carries the
// interface match of its rule or run, which is none for an empty one.
// Whether a list is guarded does not decide whether it holds sets.
//
// The list goes on, for every interface, once per interface in order of
// first appearance, with its two connection tracking rules. In the input
// list its round-trip probe rule follows them, and in the output list its
// foreign-source rule, its relay probe rule and its round-trip probe rule;
// the forward list holds the pair alone. Then per segment, in the order
// given, either the rule, with the log rule of a rule that carries a LogTag
// directly in front of it, or the set rules of the run, one per set.
func chainRuleExprs(segments []segment, hook chainHook) ([]chainEntry, error) {
	var ifaces []string
	seen := make(map[string]bool)
	guarded := len(segments) > 0
	for _, s := range segments {
		if s.iface == "" {
			guarded = false
		}
		if !seen[s.iface] {
			seen[s.iface] = true
			ifaces = append(ifaces, s.iface)
		}
	}

	dir := hook.dir()
	var list []chainEntry
	if guarded {
		list = append(list, chainEntry{exprs: guardExprs(ifaces, dir)})
		if len(ifaces) == 1 {
			dir = dirNone
		}
	}

	for _, iface := range ifaces {
		for _, exprs := range connTrackExprs(iface, dir) {
			list = append(list, chainEntry{exprs: exprs})
		}
		var exempt []FirewallRule
		switch hook {
		case hookInput:
			exempt = []FirewallRule{rttProbeRule(iface)}
		case hookOutput:
			list = append(list, chainEntry{exprs: foreignSourceExprs(iface, dir)})
			exempt = []FirewallRule{relayProbeRule(iface), rttProbeRule(iface)}
		}
		for _, rule := range exempt {
			exprs, err := buildRuleExprs(rule, dir)
			if err != nil {
				return nil, fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
			}
			list = append(list, chainEntry{exprs: exprs})
		}
	}

	for _, s := range segments {
		if s.sets != nil {
			for i := range s.sets {
				set := &s.sets[i]
				list = append(list, chainEntry{exprs: setLookupExprs(s.iface, dir, set.family, set.shape), set: set})
			}
			continue
		}
		if s.rule.LogTag != "" {
			logExprs, err := logRuleExprs(s.rule, dir)
			if err != nil {
				return nil, fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
			}
			list = append(list, chainEntry{exprs: logExprs})
		}
		exprs, err := buildRuleExprs(s.rule, dir)
		if err != nil {
			return nil, fmt.Errorf("policy: nftables: apply rules: build expressions: %w", err)
		}
		list = append(list, chainEntry{exprs: exprs})
	}
	return list, nil
}

// guardExprs builds the guard that opens a list whose rules all name an
// interface: meta iifname (dirIn) or oifname (dirOut) != each of ifaces,
// then accept. A packet on any other interface leaves the chain at the
// guard, so the interface is tested once per packet instead of once per
// rule. An accept in a base chain ends that chain only, exactly as falling
// off its end under policy accept does, so the verdict of every packet is
// unchanged: none of the rules behind the guard matches a packet on another
// interface. The guard carries no counter, so traffic that leaves at it
// writes nothing.
func guardExprs(ifaces []string, dir ifaceDir) []expr.Any {
	key := expr.MetaKeyIIFNAME
	if dir == dirOut {
		key = expr.MetaKeyOIFNAME
	}
	exprs := []expr.Any{&expr.Meta{Key: key, Register: 1}}
	for _, iface := range ifaces {
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     ifaceNameBytes(iface),
		})
	}
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

// logRuleExprs builds the log rule of a rule that carries a LogTag: the
// rule's match expressions, a match on the conntrack state new, and a log
// expression that hands the packet to NFLOG group nflogGroup with the tag as
// its prefix. It has no verdict, so evaluation goes on to the rule's own
// accept, which follows it. The state match logs a connection's first packet;
// the later packets of a flow nothing has answered yet are new as well.
func logRuleExprs(rule FirewallRule, dir ifaceDir) ([]expr.Any, error) {
	exprs, err := buildRuleExprs(rule, dir)
	if err != nil {
		return nil, err
	}
	// buildRuleExprs ends every rule with a counter and a verdict, which the
	// log rule leaves out.
	matches := len(exprs) - 2
	exprs = append(exprs[:matches:matches], ctStateExprs(expr.CtStateBitNEW)...)
	return append(exprs, &expr.Log{
		Key:   1<<unix.NFTA_LOG_GROUP | 1<<unix.NFTA_LOG_PREFIX,
		Group: nflogGroup,
		Data:  []byte(rule.LogTag),
	}), nil
}

// foreignSourceExprs builds the rule that lets a packet leave iface without
// meeting the policy rules when its source is not an address of iface:
// oifname "<iface>" fib saddr . oif type != local counter accept. fib asks
// the routing table for the type of the source address on the outgoing
// interface, which is local only for an address assigned to that interface,
// so the node's mesh address is filtered and eth0's, a Pod's or a container's
// is not. dir is dirOut, or dirNone behind a guard that tested iface already.
// The scope DECISION is at ApplyRules.
func foreignSourceExprs(iface string, dir ifaceDir) []expr.Any {
	return append(ifaceMatchExprs(iface, dir),
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

// rttProbeRule returns the rule that passes plexd's round-trip probe on iface
// ahead of the policy rules. The input list holds it for what arrives for the
// node and the output list for what the node sends; the forward list does not
// hold it. It names no address, so it matches IPv4 and IPv6. The exemption's
// DECISION is at RTTProbePort.
func rttProbeRule(iface string) FirewallRule {
	return FirewallRule{Interface: iface, Protocol: "udp", Port: RTTProbePort, Action: "allow"}
}

// ifaceMatchExprs matches the name of the interface dir selects, the input
// interface for dirIn and the output interface for dirOut. It returns nil for
// an empty name, which matches every interface, and for dirNone.
func ifaceMatchExprs(iface string, dir ifaceDir) []expr.Any {
	if iface == "" || dir == dirNone {
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
