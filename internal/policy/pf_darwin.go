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
)

// pfTokenRE finds the reference token pfctl -E prints ("Token : 1397...").
var pfTokenRE = regexp.MustCompile(`Token\s*:\s*([0-9]+)`)

// PFController implements FirewallController and bridge.NATController on
// macOS with pfctl(8). It keeps the desired state itself and renders the
// whole anchor on every change, because pfctl -f replaces an anchor's
// rules wholesale: there is no way to add one rule to it.
type PFController struct {
	run    commandRunner
	logger *slog.Logger

	mu       sync.Mutex
	chains   map[string][]FirewallRule // chain name -> rules; a key exists once EnsureChain ran
	natIface string                    // access interface with masquerade, "" for none
	token    string                    // pf enable reference from pfctl -E, "" while released
}

// NewPFController returns a controller driving the host's pfctl binary.
func NewPFController(logger *slog.Logger) *PFController {
	return &PFController{
		run:    execCommand,
		logger: logger,
		chains: make(map[string][]FirewallRule),
	}
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
// The caller holds c.mu.
func (c *PFController) render() []byte {
	var b strings.Builder
	b.WriteString(pfHeader)

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
			fmt.Fprintf(&b, "pass out quick on %s proto udp from (%s) to any port %d no state\n", rule.Interface, rule.Interface, RelayProbePort)
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
				b.WriteString(line + "\n")
			}
		}
	}

	return []byte(b.String())
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
// A deny renders a block in line and a block out line. The block out line
// names the interface's own addresses in place of an empty source, so the
// default deny drops what the node sends and leaves alone what the Mac
// forwards out of the interface. The engine puts the default deny last, so
// its block lines follow every pass line.
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
	// as VerdictDrop.
	if rule.Action == "deny" {
		outSrc := src
		if rule.SrcIP == "" {
			outSrc = "(" + rule.Interface + ")"
		}
		return []string{
			fmt.Sprintf("block in %s%s from %s to %s%s", on, proto, src, dst, port),
			fmt.Sprintf("block out %s%s from %s to %s%s", on, proto, outSrc, dst, port),
		}, nil
	}

	lines := []string{
		fmt.Sprintf("pass in %s%s from %s to %s%s no state", on, proto, src, dst, port),
	}

	switch rule.Protocol {
	case "tcp":
		lines = append(lines, fmt.Sprintf("pass out %s proto tcp from %s to %s%s keep state", on, src, dst, port))
	case "udp", "icmp":
		lines = append(lines, fmt.Sprintf("pass out %s%s from %s to %s%s no state", on, proto, src, dst, port))
	case "":
		// Validate refuses a port without a protocol, so neither line has one.
		lines = append(lines,
			fmt.Sprintf("pass out %s proto tcp from %s to %s keep state", on, src, dst),
			fmt.Sprintf("pass out %s from %s to %s no state", on, src, dst),
		)
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
// switched on for a host that had it off.
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

	if _, err := c.pfctl(op, c.render(), "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}

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
// configured, the anchor is flushed and the pf reference released.
// Idempotent: deleting a chain that was never ensured returns nil.
func (c *PFController) DeleteChain(chain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
