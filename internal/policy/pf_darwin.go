//go:build darwin

package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// pfctlPath is absolute because launchd starts the daemon with a minimal
	// environment in which pfctl is not guaranteed to be on the PATH.
	pfctlPath = "/sbin/pfctl"

	// pfAnchor is where plexd's rules live. Apple's /etc/pf.conf evaluates
	// every child of com.apple through its wildcard anchor and nat-anchor
	// lines, so a sub-anchor is reached for filter and nat rules without a
	// change to the main ruleset, which Apple's own services rewrite at will.
	pfAnchor = "com.apple/plexd"

	// pfParentAnchor is the wildcard the main ruleset has to reference for
	// pfAnchor to be evaluated at all. Probe checks it is still there.
	pfParentAnchor = `"com.apple/*"`

	// pfctlTimeout bounds one pfctl invocation.
	pfctlTimeout = 10 * time.Second

	// pfHeader opens the anchor text, so an operator reading the loaded
	// ruleset knows who owns it and that local edits do not survive.
	pfHeader = "# plexd policy anchor. Managed by plexd; edits are overwritten.\n"

	// pfDropLabel is the label every block line carries, so pfctl -sl
	// reports what the deny lines dropped under one name. DropCounts sums the
	// lines of this label.
	pfDropLabel = "plexd-default-deny"
)

// pfTokenRE finds the reference token pfctl -E prints ("Token : 1397...").
var pfTokenRE = regexp.MustCompile(`Token\s*:\s*([0-9]+)`)

// PFController implements FirewallController, ConnReporter, DropCounter and
// bridge.NATController on macOS with pfctl(8). It keeps the desired state
// itself and renders the whole anchor on every change, because pfctl -f
// replaces an anchor's rules wholesale: there is no way to add one rule to it.
type PFController struct {
	run    commandRunner
	logger *slog.Logger

	mu       sync.Mutex
	chains   map[string][]FirewallRule // chain name -> rules; a key exists once EnsureChain ran
	natIface string                    // access interface with masquerade, "" for none
	token    string                    // pf enable reference from pfctl -E, "" while released
	sink     ConnSink                  // where the pflog reader reports, nil for nobody
	reader   *pflogReader              // the pflog reader opened last, nil for none

	// openLog starts a pflog reader. It is a seam: openPflog in production,
	// a fake in tests.
	openLog func() (*pflogReader, error)

	// logMu guards the tags of the logged lines, which the pflog reader looks
	// up without c.mu: pf's number of each logged line in the anchor loaded
	// last, and in the one before it.
	logMu       sync.RWMutex
	logTags     map[uint32]string
	prevLogTags map[uint32]string
}

// NewPFController returns a controller driving the host's pfctl binary.
func NewPFController(logger *slog.Logger) *PFController {
	c := &PFController{
		run:    execCommand,
		logger: logger,
		chains: make(map[string][]FirewallRule),
	}
	c.openLog = c.openPflog
	return c
}

// SetConnSink makes the pflog reader report the connections the logged rules
// admit to sink. It implements ConnReporter. Without a sink, ApplyRules loads
// the logged rules without their log keyword.
func (c *PFController) SetConnSink(sink ConnSink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sink = sink
}

// pfctl runs one pfctl invocation under a timeout and returns its combined
// output, which the caller reads even on failure because Probe inspects it.
// A failure carries the command line and pfctl's own message, because "exit
// status 1" alone says nothing an operator can act on.
func (c *PFController) pfctl(op string, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()

	out, err := c.run(ctx, stdin, pfctlPath, args...)
	if err == nil {
		return out, nil
	}

	detail := strings.TrimSpace(string(out))

	// Every pfctl call that opens /dev/pf fails with "Permission denied" for
	// an unprivileged caller, and that message never names the remedy. The
	// line an operator reads is the one plexd prints as it aborts.
	hint := ""
	if strings.Contains(detail, "Permission denied") {
		hint = " (policy enforcement on macOS requires root)"
	}

	argv := strings.Join(append([]string{pfctlPath}, args...), " ")
	if detail != "" {
		return out, fmt.Errorf("policy: pf: %s: %s: %w: %s%s", op, argv, err, detail, hint)
	}
	return out, fmt.Errorf("policy: pf: %s: %s: %w%s", op, argv, err, hint)
}

// render builds the whole anchor text from the desired state. The nat rule
// comes first because pf requires translation rules ahead of filter rules in
// a file. Chains are rendered in name order so the same state always yields
// the same text. Each chain opens with the relay probe line for every
// interface it mentions, in order of first appearance, and then holds the
// lines renderRule returns for each rule. A chain without rules renders as
// its comment line alone.
//
// The map takes pf's number of each line that starts "pass in log " or "pass
// out log " to the tag of the rule the line came from. A pflog record carries
// that number as its subrulenr. pf numbers the filter rules of an anchor from
// 0 in the order they load, and the header, the chain comments and the nat
// line load none. pfctl loads a line holding a brace list as one rule per
// item, so an ICMP reply mirror takes four numbers, or five for ICMPv6, and
// every other line takes one. pfctl's ruleset optimizer reorders and merges
// rules only within a run of lines alike in action, log and state. A logged
// line differs in log from the lines next to it, and the Enforcer puts the
// logged rules ahead of the others, so the count of rules in front of a
// logged line stays as rendered. TestPFController_RealConnLog proves the
// numbering on a real kernel.
//
// The caller holds c.mu.
func (c *PFController) render() ([]byte, map[uint32]string) {
	var b strings.Builder
	b.WriteString(pfHeader)

	tags := make(map[uint32]string)
	var nr uint32
	filter := func(line, tag string) {
		b.WriteString(line + "\n")
		if strings.HasPrefix(line, "pass in log ") || strings.HasPrefix(line, "pass out log ") {
			tags[nr] = tag
		}
		nr += pfRuleCount(line)
	}

	if c.natIface != "" {
		fmt.Fprintf(&b, "nat on %s inet from any to any -> (%s)\n", c.natIface, c.natIface)
	}

	for _, name := range slices.Sorted(maps.Keys(c.chains)) {
		fmt.Fprintf(&b, "# chain %s\n", name)

		var seen []string
		for _, rule := range c.chains[name] {
			if rule.Interface == "" || slices.Contains(seen, rule.Interface) {
				continue
			}
			seen = append(seen, rule.Interface)
			// The relay probe passes ahead of the rules, as RelayProbePort
			// records. (<if>) is the interface's own addresses as the kernel
			// tracks them, so the line matches what the node sends and not
			// what the Mac forwards out of the interface, and a mesh address
			// assigned after the load needs no reload. The line names no
			// address family, so it covers IPv4 and IPv6. It keeps no state,
			// so it lets nothing back in.
			filter(fmt.Sprintf("pass out quick on %s proto udp from (%s) to any port %d no state", rule.Interface, rule.Interface, RelayProbePort), "")
		}

		for _, rule := range c.chains[name] {
			lines, err := renderRule(rule)
			if err != nil {
				// Unreachable: ApplyRules renders every rule before it stores
				// one. Dropping the rule is still safer than writing a
				// half-formed line pf would reject along with the rest.
				continue
			}
			for _, line := range lines {
				filter(line, rule.LogTag)
			}
		}
	}

	return []byte(b.String()), tags
}

// pfRuleCount returns how many rules pfctl loads for one filter line: a brace
// list loads as one rule per item, and several lists multiply.
func pfRuleCount(line string) uint32 {
	n := uint32(1)
	for rest := line; ; {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			return n
		}
		end := strings.IndexByte(rest[open:], '}')
		if end < 0 {
			return n
		}
		n *= uint32(strings.Count(rest[open:open+end], ",") + 1)
		rest = rest[open+end+1:]
	}
}

// The ICMP types a reply mirror lets the node send: the echo reply and the
// errors a host sends about a packet it received. IPv4 reports a packet too
// big for the path as a code of unreach, IPv6 as a type of its own.
const (
	pfICMPReplies  = "icmp-type { echorep, unreach, timex, paramprob }"
	pfICMP6Replies = "icmp6-type { echorep, unreach, toobig, timex, paramprob }"
)

// renderRule turns one rule into its pf filter lines. Every line is quick,
// which makes the first matching line final, the first-match semantics the
// nftables backend has.
//
// An allow renders, in this order:
//
//   - a pass in line with no state, so a new deny takes effect at once
//     instead of after the last flow expires;
//   - pass out lines for the node's own traffic: tcp with keep state, udp
//     and icmp with no state, and for a rule without a protocol the tcp line
//     and then a no state line for every protocol;
//   - reply mirrors, with source and destination swapped: tcp with flags
//     A/A for a rule naming tcp or no protocol, udp for one naming udp or no
//     protocol, and for every allow the ICMP replies and errors of its
//     family, both families for a rule without addresses.
//
// A rule with a LogTag puts log right after pass in or pass out on the lines
// that see a connection's first packet, so pf hands that packet to pflog0:
//
//   - tcp: a pass in log line with flags S/SA ahead of the unchanged pass in
//     line, so only the SYN logs, and log on the keep state line, which logs
//     only the packet that creates the state;
//   - udp and icmp: log on the pass in line and on the pass out line, which
//     keep no state, so pf logs every packet they pass;
//   - no protocol: the tcp SYN line, then an unlogged tcp pass in line, so the
//     rest of a TCP connection does not log, then the protocol-less pass in
//     line with log; log on the node's own keep state line, then an unlogged
//     tcp pass out line, so the Mac's replies to an inbound TCP connection do
//     not log, then log on the node's protocol-less pass out line.
//
// Mirrors and block lines never log.
//
// A deny renders a block in line and a block out line. The block out line
// names the interface's own addresses in place of an empty source, so the
// default deny drops what the node sends and leaves alone what the Mac
// forwards out of the interface. The engine puts the default deny last, so
// its block lines follow every pass line. Both block lines end in the label
// pfDropLabel, whose counters DropCounts reads.
//
// DECISION: the node's own TCP connections keep state, as the pass out pair
// before #178 did, and its UDP and ICMP flows do not, so #176's decision
// stands. pf consults the state table ahead of the ruleset and a state entry
// is bidirectional, so a stateful UDP or ICMP line would let a flow keep
// running after the rule that allowed it was removed: every further packet
// matches the entry instead of the rules. The implicit flags S/SA pfctl puts
// on a stateful TCP pass line means only the node's own SYN creates an
// entry, never its SYN-ACK to an inbound connection. A revoked rule
// therefore stops the Mac's established outbound TCP connection only when
// that connection ends, and its UDP and ICMP flows at their next packet.
//
// DECISION: replies to what a rule lets in leave through stateless mirror
// lines (author, 2026-11-12, #178). Inbound lines stay stateless so that a
// revoked rule cuts inbound traffic at once, which means pf can tell a reply
// from a new flow only by its shape. flags A/A keeps the Mac from opening a
// TCP connection through a mirror, and the ICMP mirrors carry only replies
// and errors. A UDP mirror, however, lets the Mac send from the rule's port,
// or from any port for a rule without ports, to a peer that may reach it.
// Linux and Windows allow no such thing. The mirrors also carry less than
// Linux's connection tracking does. A reply in a protocol other than tcp,
// udp and icmp matches no mirror, and neither does an ICMP error the Mac
// sends from its own address about traffic it forwards, such as a time
// exceeded for a traceroute through it. Both meet the default deny unless a
// rule allows them from the node's own address.
func renderRule(rule FirewallRule) ([]string, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	// A pf rule without "on" applies to every interface of the host, so a
	// default deny among them would cut the Mac off its own networks.
	if rule.Interface == "" {
		return nil, errors.New("interface name is empty")
	}

	// Validate has parsed both addresses already, so these fail only on what
	// it refused.
	fam, err := rule.family()
	if err != nil {
		return nil, err
	}
	src, err := pfAddress(rule.SrcIP)
	if err != nil {
		return nil, err
	}
	dst, err := pfAddress(rule.DstIP)
	if err != nil {
		return nil, err
	}

	// on opens every line but the ICMP mirrors, which name their family
	// themselves. A rule without a family keyword matches IPv4 and IPv6,
	// which is what the address-less default deny has to cover. A wildcard
	// prefix renders as "any", so the keyword is what keeps 0.0.0.0/0 and
	// ::/0 to their own family.
	on := "quick on " + rule.Interface
	switch fam {
	case familyIPv4:
		on += " inet"
	case familyIPv6:
		on += " inet6"
	}

	proto := ""
	if rule.Protocol != "" {
		p := rule.Protocol
		// ICMP and ICMPv6 are different protocols, and an IPv6 packet never
		// carries protocol 1.
		if p == "icmp" && fam == familyIPv6 {
			p = "icmp6"
		}
		proto = " proto " + p
	}

	port := ""
	switch {
	case rule.Port > 0 && rule.PortTo > rule.Port:
		port = fmt.Sprintf(" port %d:%d", rule.Port, rule.PortTo)
	case rule.Port > 0:
		port = fmt.Sprintf(" port %d", rule.Port)
	}

	// pf's default block policy is drop, what the nftables backend expresses
	// as VerdictDrop. Every block line carries pfDropLabel, not only the
	// default deny's: the engine's only deny is the default deny, and the
	// nftables backend counts every rule with a drop verdict too.
	if rule.Action == "deny" {
		outSrc := src
		if rule.SrcIP == "" {
			outSrc = "(" + rule.Interface + ")"
		}
		label := fmt.Sprintf(" label %q", pfDropLabel)
		return []string{
			fmt.Sprintf("block in %s%s from %s to %s%s%s", on, proto, src, dst, port, label),
			fmt.Sprintf("block out %s%s from %s to %s%s%s", on, proto, outSrc, dst, port, label),
		}, nil
	}

	logged := rule.LogTag != ""
	in, out := "pass in", "pass out"
	if logged {
		in, out = "pass in log", "pass out log"
	}

	var lines []string
	switch rule.Protocol {
	case "tcp":
		if logged {
			lines = append(lines, fmt.Sprintf("%s %s%s from %s to %s%s flags S/SA no state", in, on, proto, src, dst, port))
		}
		lines = append(lines,
			fmt.Sprintf("pass in %s%s from %s to %s%s no state", on, proto, src, dst, port),
			fmt.Sprintf("%s %s proto tcp from %s to %s%s keep state", out, on, src, dst, port),
		)
	case "udp", "icmp":
		lines = append(lines,
			fmt.Sprintf("%s %s%s from %s to %s%s no state", in, on, proto, src, dst, port),
			fmt.Sprintf("%s %s%s from %s to %s%s no state", out, on, proto, src, dst, port),
		)
	case "":
		// Validate refuses a port without a protocol, so no line has one.
		if logged {
			lines = append(lines,
				fmt.Sprintf("%s %s proto tcp from %s to %s flags S/SA no state", in, on, src, dst),
				fmt.Sprintf("pass in %s proto tcp from %s to %s no state", on, src, dst),
			)
		}
		lines = append(lines,
			fmt.Sprintf("%s %s from %s to %s no state", in, on, src, dst),
			fmt.Sprintf("%s %s proto tcp from %s to %s keep state", out, on, src, dst),
		)
		if logged {
			// The TCP packets the Mac sends that create no state, its replies
			// to an inbound connection among them, pass here unlogged, so the
			// logged line below sees the other protocols only. The line below
			// passed them before, so the verdict is the same.
			lines = append(lines, fmt.Sprintf("pass out %s proto tcp from %s to %s no state", on, src, dst))
		}
		lines = append(lines, fmt.Sprintf("%s %s from %s to %s no state", out, on, src, dst))
	}

	if rule.Protocol == "tcp" || rule.Protocol == "" {
		lines = append(lines, fmt.Sprintf("pass out %s proto tcp from %s%s to %s flags A/A no state", on, dst, port, src))
	}
	if rule.Protocol == "udp" || rule.Protocol == "" {
		lines = append(lines, fmt.Sprintf("pass out %s proto udp from %s%s to %s no state", on, dst, port, src))
	}
	if fam != familyIPv6 {
		lines = append(lines, fmt.Sprintf("pass out quick on %s inet proto icmp from %s to %s %s no state", rule.Interface, dst, src, pfICMPReplies))
	}
	if fam != familyIPv4 {
		lines = append(lines, fmt.Sprintf("pass out quick on %s inet6 proto icmp6 from %s to %s %s no state", rule.Interface, dst, src, pfICMP6Replies))
	}

	return lines, nil
}

// pfAddress renders one address field as a pf address. An empty field and a
// zero-length prefix, 0.0.0.0/0 or ::/0, both become "any", the match the
// nftables backend leaves out of a rule entirely; renderRule's family keyword
// keeps a wildcard prefix to its family. A prefix renders masked, and a bare
// address stays bare, as the rule wrote it. The field is parsed by
// parseRuleAddr, which every backend shares, so a rejected address reads the
// same on every platform.
func pfAddress(addr string) (string, error) {
	prefix, ok, err := parseRuleAddr(addr)
	if err != nil {
		return "", err
	}
	if !ok || prefix.Bits() == 0 {
		return "any", nil
	}
	if !strings.Contains(addr, "/") {
		return prefix.Addr().String(), nil
	}
	return prefix.String(), nil
}

// sync writes the current desired state to the kernel. It loads the rendered
// anchor and enables pf afterwards, in that order, so pf never runs with an
// empty plexd anchor in between. Once nothing is left to enforce it flushes
// the anchor and gives the enable reference back, so plexd does not keep pf
// switched on for a host that had it off. The tags of the logged lines change
// only once pf took the new anchor.
//
// The caller holds c.mu and restores the fields it changed when sync fails,
// which keeps the controller's picture at what the kernel last accepted. The
// kernel may then hold newer anchor text than the fields describe; the next
// successful sync overwrites it.
func (c *PFController) sync(op string) error {
	if len(c.chains) == 0 && c.natIface == "" {
		if c.token == "" {
			return nil
		}
		if _, err := c.pfctl(op, nil, "-a", pfAnchor, "-F", "all"); err != nil {
			return err
		}
		c.setLogTags(nil)
		// The reference is dropped even when -X failed: pf then keeps a leaked
		// one, which only means pf stays enabled, and a retry with the same
		// token could never release it either.
		_, err := c.pfctl(op, nil, "-X", c.token)
		c.token = ""
		if err != nil {
			return err
		}
		c.logger.Debug("pf anchor flushed and reference released",
			"component", "policy",
			"anchor", pfAnchor,
		)
		return nil
	}

	text, tags := c.render()
	if _, err := c.pfctl(op, text, "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}
	c.setLogTags(tags)

	if c.token != "" {
		return nil
	}

	out, err := c.pfctl(op, nil, "-E")
	if err != nil {
		return err
	}
	m := pfTokenRE.FindSubmatch(out)
	if m == nil {
		return fmt.Errorf("policy: pf: %s: pfctl -E printed no token: %q", op, strings.TrimSpace(string(out)))
	}
	c.token = string(m[1])

	c.logger.Debug("pf enabled",
		"component", "policy",
		"anchor", pfAnchor,
		"token", c.token,
	)
	return nil
}

// setLogTags records the tags of the logged lines in the anchor pf just took.
// The tags it replaces stay for one more change, so a record pf wrote just
// before the load still finds its line. A load that changes no logged line,
// such as one for a NAT change, keeps both.
func (c *PFController) setLogTags(tags map[uint32]string) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if maps.Equal(tags, c.logTags) {
		return
	}
	c.prevLogTags = c.logTags
	c.logTags = tags
}

// pflogTag returns the tag of the logged line pf numbers nr, in the anchor
// loaded last or in the one before it. The pflog reader calls it and takes
// logMu alone, never c.mu.
func (c *PFController) pflogTag(nr uint32) (string, bool) {
	c.logMu.RLock()
	defer c.logMu.RUnlock()
	if tag, ok := c.logTags[nr]; ok {
		return tag, true
	}
	tag, ok := c.prevLogTags[nr]
	return tag, ok
}

// Probe reports whether the pf backend is usable, without changing any kernel
// state. It reads the main ruleset, which needs the same access to /dev/pf
// every mutating call takes, and checks that the wildcard anchors Apple ships
// are still referenced: without them the kernel never evaluates pfAnchor, and
// plexd would load rules that enforce nothing.
//
// Both commands are reads, so a node that goes on to fail startup for another
// reason leaves nothing behind.
func (c *PFController) Probe() error {
	// The reference has to be recognised per line: pfctl prints a scrub-anchor
	// line for the same wildcard, which contains the filter form as a
	// substring.
	references := func(out []byte, prefix string) bool {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				return true
			}
		}
		return false
	}

	out, err := c.pfctl("probe", nil, "-s", "rules")
	if err != nil {
		return err
	}
	if !references(out, "anchor "+pfParentAnchor) {
		return fmt.Errorf("policy: pf: probe: the main ruleset does not reference anchor %s; restore /etc/pf.conf and run pfctl -f /etc/pf.conf", pfParentAnchor)
	}

	out, err = c.pfctl("probe", nil, "-s", "nat")
	if err != nil {
		return err
	}
	if !references(out, "nat-anchor "+pfParentAnchor) {
		return fmt.Errorf("policy: pf: probe: the main ruleset does not reference nat-anchor %s; restore /etc/pf.conf and run pfctl -f /etc/pf.conf", pfParentAnchor)
	}

	c.logger.Debug("pf backend probed",
		"component", "policy",
		"anchor", pfAnchor,
	)
	return nil
}

// EnsureChain records the named chain, so the anchor carries it even while it
// holds no rules yet. The chain is a comment in the rendered text: pf has no
// user chains, and the name is what ApplyRules, FlushChain and DeleteChain
// address.
func (c *PFController) EnsureChain(chain string) error {
	if chain == "" {
		return errors.New("policy: pf: ensure chain: chain name is empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.chains[chain]; ok {
		c.logger.Debug("pf chain already present",
			"component", "policy",
			"chain", chain,
		)
		return nil
	}

	c.chains[chain] = nil
	if err := c.sync("ensure chain"); err != nil {
		delete(c.chains, chain)
		return err
	}

	c.logger.Debug("pf chain ensured",
		"component", "policy",
		"chain", chain,
		"anchor", pfAnchor,
	)
	return nil
}

// ApplyRules replaces all rules of the named chain. Every rule is rendered
// before anything is stored or run, so a bad rule leaves both the kernel and
// the desired state untouched. A chain that was never ensured is created
// here, as NftablesController.ApplyRules adds its chain itself.
//
// Rules with a LogTag need a pflog reader, which the first such apply opens.
// Without a sink, or with a reader that cannot open, the rules are stored and
// loaded without their tags, so the anchor carries no log keyword and logging
// never stands in the way of enforcement. A failed open logs
// connLogUnavailable, and the next apply tries again.
func (c *PFController) ApplyRules(chain string, rules []FirewallRule) error {
	if chain == "" {
		return errors.New("policy: pf: apply rules: chain name is empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for i, rule := range rules {
		if _, err := renderRule(rule); err != nil {
			return fmt.Errorf("policy: pf: apply rules: rule %d: %w", i, err)
		}
	}

	if hasLogTags(rules) && !c.connLogReady() {
		rules = withoutLogTags(rules)
	}

	// Nil and empty both leave a chain with no rules, which renders as the
	// comment line alone, so the kernel holds no filter rule for it.
	prev, existed := c.chains[chain]
	c.chains[chain] = slices.Clone(rules)
	if err := c.sync("apply rules"); err != nil {
		if existed {
			c.chains[chain] = prev
		} else {
			delete(c.chains, chain)
		}
		return err
	}

	c.logger.Debug("pf rules applied",
		"component", "policy",
		"chain", chain,
		"count", len(rules),
	)
	return nil
}

// connLogReady reports whether a pflog reader runs to report what the logged
// lines of the next load pass, and opens one when none does. A reader whose
// loop ended has released its device already and is replaced.
//
// The caller holds c.mu.
func (c *PFController) connLogReady() bool {
	if c.sink == nil {
		return false
	}
	if c.reader != nil && c.reader.running() {
		return true
	}
	reader, err := c.openLog()
	if err != nil {
		c.logger.Warn(connLogUnavailable,
			"component", "policy",
			"error", err,
		)
		return false
	}
	c.reader = reader
	return true
}

// FlushChain drops the rules of the named chain but keeps the chain itself.
// Idempotent: flushing a chain that was never ensured returns nil.
func (c *PFController) FlushChain(chain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev, ok := c.chains[chain]
	if !ok {
		c.logger.Debug("pf chain not found, nothing to flush",
			"component", "policy",
			"chain", chain,
		)
		return nil
	}

	c.chains[chain] = nil
	if err := c.sync("flush chain"); err != nil {
		c.chains[chain] = prev
		return err
	}

	c.logger.Debug("pf chain flushed",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// DeleteChain forgets the named chain. When it was the last one and no NAT is
// configured, the anchor is flushed and the pf reference released. Once no
// chain is left, no logged line is either, and the pflog reader is closed.
// Idempotent: deleting a chain that was never ensured returns nil.
func (c *PFController) DeleteChain(chain string) error {
	c.mu.Lock()
	err := c.deleteChain(chain)
	var reader *pflogReader
	if err == nil && len(c.chains) == 0 {
		reader, c.reader = c.reader, nil
	}
	c.mu.Unlock()

	// Closing waits for the reader's loop, which notices within a read
	// timeout, so it runs without c.mu.
	if reader != nil {
		reader.close()
	}
	return err
}

// deleteChain is DeleteChain without the reader. The caller holds c.mu.
func (c *PFController) deleteChain(chain string) error {
	prev, ok := c.chains[chain]
	if !ok {
		c.logger.Debug("pf chain not found, nothing to delete",
			"component", "policy",
			"chain", chain,
		)
		return nil
	}

	delete(c.chains, chain)
	if err := c.sync("delete chain"); err != nil {
		c.chains[chain] = prev
		return err
	}

	c.logger.Debug("pf chain deleted",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// DropCounts returns the packets and bytes the block lines of the anchor
// dropped since pf last loaded it. It implements DropCounter. Every change
// reloads the whole anchor, which restarts the counters. pf keeps one anchor,
// so the sum covers every chain in it; plexd keeps one policy chain. A chain
// the controller does not hold is an error.
//
// It runs pfctl -a com.apple/plexd -sl, which prints one line per labelled
// rule, and sums fields 3 and 4 of the lines whose first field is
// pfDropLabel. The column layout, the label, then the evaluations, packets
// and bytes, then the packets and bytes of each direction, comes from
// pfctl(8). TestPFController_RealTraffic proves it on the macos-latest CI
// runner.
func (c *PFController) DropCounts(chain string) (packets, bytes uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.chains[chain]; !ok {
		return 0, 0, fmt.Errorf("policy: pf: drop counts: no chain %q", chain)
	}

	out, err := c.pfctl("drop counts", nil, "-a", pfAnchor, "-sl")
	if err != nil {
		return 0, 0, err
	}
	return sumPFDropLabels(out)
}

// sumPFDropLabels sums fields 3 and 4, the packets and bytes, of every line
// of pfctl -sl output whose first field is pfDropLabel. The output also holds
// pfctl's warnings, such as the ALTQ lines, and the lines of other labels,
// which it skips. A label line with fewer than four fields or a count that is
// not a number, and an output without any label line, are errors.
func sumPFDropLabels(out []byte) (uint64, uint64, error) {
	var packets, bytes uint64
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != pfDropLabel {
			continue
		}
		if len(fields) < 4 {
			return 0, 0, fmt.Errorf("policy: pf: drop counts: line %q has %d fields, want at least 4", line, len(fields))
		}
		p, perr := strconv.ParseUint(fields[2], 10, 64)
		if perr != nil {
			return 0, 0, fmt.Errorf("policy: pf: drop counts: line %q: packets: %w", line, perr)
		}
		b, berr := strconv.ParseUint(fields[3], 10, 64)
		if berr != nil {
			return 0, 0, fmt.Errorf("policy: pf: drop counts: line %q: bytes: %w", line, berr)
		}
		packets += p
		bytes += b
		found = true
	}
	if !found {
		return 0, 0, fmt.Errorf("policy: pf: drop counts: %s -a %s -sl printed no line labelled %q", pfctlPath, pfAnchor, pfDropLabel)
	}
	return packets, bytes, nil
}

// AddNATMasquerade configures NAT for bridge egress on the given interface.
// Everything leaving it is translated, the host's own traffic included, which
// is what oifname masquerade does on Linux. The first call probes the main
// ruleset first, because an anchor the kernel never evaluates translates
// nothing while every command still succeeds. Idempotent: re-adding the same
// interface renders the same text again.
func (c *PFController) AddNATMasquerade(iface string) error {
	// pfctl would take the empty name and fail on a syntax error that never
	// names the interface as the cause.
	if iface == "" {
		return fmt.Errorf("bridge: add NAT masquerade on %q: interface name is empty", iface)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.natIface
	if prev == "" {
		// Nothing else on the bridge path checks that the main ruleset still
		// references nat-anchor "com.apple/*". Enforcer.Preflight is the only
		// other caller of Probe and it returns early with policy.enabled:
		// false, which is exactly the configuration an operator picks who
		// wants bridge routing without enforcement. Without the reference the
		// kernel never evaluates the anchor: the nat rule loads, pfctl -E
		// succeeds, and mesh traffic still leaves the Mac untranslated.
		if err := c.Probe(); err != nil {
			return fmt.Errorf("bridge: add NAT masquerade on %q: %w", iface, err)
		}
	}

	c.natIface = iface
	if err := c.sync("add NAT masquerade"); err != nil {
		c.natIface = prev
		return fmt.Errorf("bridge: add NAT masquerade on %q: %w", iface, err)
	}

	c.logger.Debug("NAT masquerade configured",
		"component", "bridge",
		"interface", iface,
		"anchor", pfAnchor,
	)
	return nil
}

// RemoveNATMasquerade drops the NAT rule. The interface is logged, not
// compared: the controller holds one NAT rule, as the Linux backend deletes
// its whole NAT table regardless of the name it is given. Idempotent:
// removing a masquerade that is not configured returns nil.
func (c *PFController) RemoveNATMasquerade(iface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.natIface == "" {
		c.logger.Debug("NAT masquerade not configured, idempotent success",
			"component", "bridge",
			"interface", iface,
		)
		return nil
	}

	prev := c.natIface
	c.natIface = ""
	if err := c.sync("remove NAT masquerade"); err != nil {
		c.natIface = prev
		return fmt.Errorf("bridge: remove NAT masquerade on %q: %w", iface, err)
	}

	c.logger.Debug("NAT masquerade removed",
		"component", "bridge",
		"interface", iface,
	)
	return nil
}
