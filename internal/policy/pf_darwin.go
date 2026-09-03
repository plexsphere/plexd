//go:build darwin

package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
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
// the same text, and each chain opens with a pair of pass out rules per
// interface it mentions, so the node's own outbound connections still get
// through a chain that otherwise ends in a default deny.
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
			// Only TCP keeps state. pf consults the state table ahead of the
			// ruleset and a state entry is bidirectional, so a stateful rule
			// covering every protocol would let an inbound-initiated UDP or
			// ICMP flow keep running after its rule turned into a deny: the
			// node's reply creates the entry and every further packet of that
			// flow matches it. The implicit flags S/SA pfctl puts on a
			// stateful TCP pass rule stops the same happening for TCP, because
			// an outbound SYN-ACK creates no state.
			fmt.Fprintf(&b, "pass out quick on %s inet proto tcp from (%s) to any keep state\n", rule.Interface, rule.Interface)
			fmt.Fprintf(&b, "pass out quick on %s inet from (%s) to any no state\n", rule.Interface, rule.Interface)
		}

		for _, rule := range c.chains[name] {
			line, err := renderRule(rule)
			if err != nil {
				// Unreachable: ApplyRules renders every rule before it stores
				// one. Dropping the rule is still safer than writing a
				// half-formed line pf would reject along with the rest.
				continue
			}
			b.WriteString(line + "\n")
		}
	}

	return []byte(b.String())
}

// renderRule turns one rule into a pf filter line. quick makes the first
// matching rule final, which is the first-match semantics the nftables
// backend has, and no state keeps every packet subject to the current rules,
// so a new deny takes effect at once instead of after the last flow expires.
func renderRule(rule FirewallRule) (string, error) {
	if err := rule.Validate(); err != nil {
		return "", err
	}
	// A pf rule without "on" applies to every interface of the host, so a
	// default deny among them would cut the Mac off its own networks.
	if rule.Interface == "" {
		return "", errors.New("interface name is empty")
	}

	// pf's default block policy is drop, what the nftables backend expresses
	// as VerdictDrop.
	verb := "pass"
	if rule.Action == "deny" {
		verb = "block"
	}

	src, err := pfAddress(rule.SrcIP)
	if err != nil {
		return "", err
	}
	dst, err := pfAddress(rule.DstIP)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s in quick on %s inet", verb, rule.Interface)
	if rule.Protocol != "" {
		fmt.Fprintf(&b, " proto %s", rule.Protocol)
	}
	fmt.Fprintf(&b, " from %s to %s", src, dst)
	switch {
	case rule.Port > 0 && rule.PortTo > rule.Port:
		fmt.Fprintf(&b, " port %d:%d", rule.Port, rule.PortTo)
	case rule.Port > 0:
		fmt.Fprintf(&b, " port %d", rule.Port)
	}
	if verb == "pass" {
		b.WriteString(" no state")
	}

	return b.String(), nil
}

// pfAddress renders one address field as a pf address. An empty field and the
// wildcard prefix both become "any", the match the nftables backend leaves out
// of a rule entirely. The rejection texts are shared with the other backends,
// so a rejected rule reads the same on every platform.
func pfAddress(addr string) (string, error) {
	if addr == "" || addr == "0.0.0.0/0" {
		return "any", nil
	}

	if prefix, err := netip.ParsePrefix(addr); err == nil {
		if !prefix.Addr().Is4() {
			return "", fmt.Errorf(errNonIPv4Address, addr)
		}
		return prefix.Masked().String(), nil
	}

	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf(errInvalidAddress, addr)
	}
	if !parsed.Is4() {
		return "", fmt.Errorf(errNonIPv4Address, addr)
	}
	return parsed.String(), nil
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
