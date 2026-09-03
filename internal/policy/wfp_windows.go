//go:build windows

package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// wfpEngine is the part of *wf.Session's API the controller uses. It is a
// seam: production opens a dynamic WFP session, tests record what would reach
// the filter engine, which is what makes the translation testable without
// Administrator.
type wfpEngine interface {
	AddSublayer(*wf.Sublayer) error
	AddRule(*wf.Rule) error
	DeleteRule(wf.RuleID) error
	Close() error
}

// ifaceIDs is what a rule's interface name resolves to: the index the forward
// layer matches on and the LUID the local-delivery layer matches on.
type ifaceIDs struct {
	index uint32
	luid  uint64
}

const (
	// plexdSublayerWeight puts plexd's sublayer just below the maximum, which
	// wireguard-windows claims for its kill switch, so a tunnel app's
	// block-all still wins over a plexd allow.
	plexdSublayerWeight uint16 = 0xFFFE

	// fwpEFilterNotFound is FWP_E_FILTER_NOT_FOUND from winerror.h: deleting a
	// filter that is already gone. TestWFPController_Real pins the value.
	fwpEFilterNotFound = syscall.Errno(0x80320003)
)

// plexdSublayerID is fixed so an operator can find plexd's filters with
// "netsh wfp show filters". It is {8E9C1058-E9A1-1A2D-00D7-4FAABB4DB753}, the
// first 16 bytes of the SHA-256 of "plexd wfp: plexd policy sublayer" read the
// way adapterGUID reads them (internal/wireguard/controller_windows.go).
var plexdSublayerID = wf.SublayerID(windows.GUID{
	Data1: 0x8E9C1058,
	Data2: 0xE9A1,
	Data3: 0x1A2D,
	Data4: [8]byte{0x00, 0xD7, 0x4F, 0xAA, 0xBB, 0x4D, 0xB7, 0x53},
})

// WFPController implements FirewallController on Windows through the Windows
// Filtering Platform. Filters live in a dynamic session, so they vanish with
// the process; the Wintun adapter vanishes with it too, so nothing arrives
// that they could have filtered.
type WFPController struct {
	logger    *slog.Logger
	meshIface string // configured WireGuard interface name, the NAT source prefix comes from its address

	// Seams: production drives WFP, the IP Helper API and PowerShell; tests
	// wire fakes.
	openEngine  func() (wfpEngine, error)
	lookupIface func(name string) (ifaceIDs, error)
	meshPrefix  func(name string) (netip.Prefix, error)
	run         commandRunner

	mu     sync.Mutex
	engine wfpEngine              // nil while no chain exists
	chains map[string][]wf.RuleID // chain -> filters installed for it
	epoch  uint32                 // bumped per ApplyRules; the high half of every weight
}

// NewWFPController returns a controller driving the host's filter engine, the
// IP Helper API and PowerShell.
func NewWFPController(logger *slog.Logger, meshIface string) *WFPController {
	return &WFPController{
		logger:      logger,
		meshIface:   meshIface,
		openEngine:  openWFPSession,
		lookupIface: lookupWinIface,
		meshPrefix:  meshPrefixOf,
		run:         execCommand,
		chains:      make(map[string][]wf.RuleID),
	}
}

// openWFPSession opens a dynamic session. Everything added through it is
// removed when the session closes or the process dies, so a crashed plexd
// leaves no filter behind that an operator would have to hunt down.
func openWFPSession() (wfpEngine, error) {
	return wf.New(&wf.Options{
		Name:        "plexd",
		Description: "plexd policy enforcement",
		Dynamic:     true,
	})
}

// lookupWinIface resolves an interface's friendly name, the name the
// configuration carries and the one a Wintun adapter is created under, to the
// index and the LUID WFP matches on.
func lookupWinIface(name string) (ifaceIDs, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return ifaceIDs{}, err
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(ifi.Index))
	if err != nil {
		return ifaceIDs{}, err
	}
	return ifaceIDs{index: uint32(ifi.Index), luid: uint64(luid)}, nil
}

// meshPrefixOf returns the IPv4 prefix the interface is on. The mesh address
// is assigned with the mesh CIDR's prefix length, so the on-link prefix of
// that address is the mesh prefix.
func meshPrefixOf(name string) (netip.Prefix, error) {
	ids, err := lookupWinIface(name)
	if err != nil {
		return netip.Prefix{}, err
	}
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return netip.Prefix{}, err
	}
	for i := range rows {
		if uint64(rows[i].InterfaceLUID) != ids.luid {
			continue
		}
		return netip.PrefixFrom(rows[i].Address.Addr(), int(rows[i].OnLinkPrefixLength)).Masked(), nil
	}
	return netip.Prefix{}, fmt.Errorf("interface %q has no IPv4 address", name)
}

// adminHint names the remedy for the one failure an operator can act on. WFP
// answers an unprivileged caller with ERROR_ACCESS_DENIED, whose message never
// mentions the privilege it wanted.
func adminHint(err error) string {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return " (policy enforcement on Windows requires Administrator)"
	}
	return ""
}

// wfpWeight is the weight of filter i of n in the given epoch. Within a
// sublayer WFP evaluates the heaviest filter first and the first terminating
// action wins, so rule 0 has to be the heaviest, and the epoch in the high
// half makes every filter of a newer apply outweigh every filter of an older
// one. The result stays below 2^60 for 2^28 applies, which is what a
// FWP_UINT64 weight accepts.
func wfpWeight(epoch uint32, n, i int) uint64 {
	return uint64(epoch)<<32 | uint64(n-i)
}

// Probe reports whether the WFP backend is usable, without leaving any filter
// engine state behind. It opens and closes a dynamic session, which needs the
// same access to the engine every mutating call takes, and a dynamic session
// with no objects in it drops nothing on close.
func (c *WFPController) Probe() error {
	e, err := c.openEngine()
	if err != nil {
		return fmt.Errorf("policy: wfp: probe: %w%s", err, adminHint(err))
	}
	if err := e.Close(); err != nil {
		return fmt.Errorf("policy: wfp: probe: close session: %w", err)
	}

	c.logger.Debug("wfp backend probed", "component", "policy")
	return nil
}

// ensureEngine opens the session and adds plexd's sublayer once, so every
// chain files its filters into one container an operator can enumerate and
// the session can be closed again when the last chain goes.
//
// The caller holds c.mu.
func (c *WFPController) ensureEngine(op string) error {
	if c.engine != nil {
		return nil
	}

	e, err := c.openEngine()
	if err != nil {
		return fmt.Errorf("policy: wfp: %s: open session: %w%s", op, err, adminHint(err))
	}

	if err := e.AddSublayer(&wf.Sublayer{
		ID:          plexdSublayerID,
		Name:        "plexd policy",
		Description: "plexd network policy filters",
		Weight:      plexdSublayerWeight,
	}); err != nil {
		_ = e.Close()
		return fmt.Errorf("policy: wfp: %s: add sublayer: %w%s", op, err, adminHint(err))
	}

	c.engine = e
	return nil
}

// EnsureChain records the named chain, so the controller carries it even while
// it holds no filters yet. WFP has no chains: the name is what ApplyRules,
// FlushChain and DeleteChain address, and it groups the filters they own.
func (c *WFPController) EnsureChain(chain string) error {
	if chain == "" {
		return errors.New("policy: wfp: ensure chain: chain name is empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureEngine("ensure chain"); err != nil {
		return err
	}

	if _, ok := c.chains[chain]; ok {
		c.logger.Debug("wfp chain already present",
			"component", "policy",
			"chain", chain,
		)
		return nil
	}

	c.chains[chain] = nil
	c.logger.Debug("wfp chain ensured",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// newRuleID mints an identifier for one filter. WFP takes the zero GUID as a
// request for a random one but never hands that one back, so plexd would lose
// the handle it needs to delete the filter again.
func newRuleID() (wf.RuleID, error) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		return wf.RuleID{}, err
	}
	return wf.RuleID(guid), nil
}

// wfpPrefix parses one address field into the prefix an address condition
// matches on. The second result is false for an empty field and for the
// wildcard prefix, which both mean "no condition at all", the match the
// nftables backend leaves out of a rule. The rejection texts are shared with
// the other backends, so a rejected rule reads the same on every platform.
func wfpPrefix(addr string) (netip.Prefix, bool, error) {
	if addr == "" || addr == "0.0.0.0/0" {
		return netip.Prefix{}, false, nil
	}

	if prefix, err := netip.ParsePrefix(addr); err == nil {
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, false, fmt.Errorf(errNonIPv4Address, addr)
		}
		return prefix.Masked(), true, nil
	}

	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf(errInvalidAddress, addr)
	}
	if !parsed.Is4() {
		return netip.Prefix{}, false, fmt.Errorf(errNonIPv4Address, addr)
	}
	return netip.PrefixFrom(parsed, 32), true, nil
}

// buildFilters translates one chain's rules into filters, none of which is
// installed yet: a rule the engine would reject has to fail before the first
// AddRule, or an apply would leave half a ruleset in the kernel.
//
// Every rule yields a filter at the local-delivery layer, which is where the
// five-tuple is available, and a second at the forward layer, so that traffic
// through the node is governed by the same decision. The forward layer carries
// an interface, addresses and a protocol, but no port.
//
// The ruleset is ordered and first-match-terminating, so a rule left out of
// the forward layer is not narrowed to nothing: the traffic it covered is
// re-decided by whatever follows it. A port-scoped deny is therefore installed
// without the port, which blocks a superset of what the rule asked for, and a
// port-scoped allow gets no forward filter, which leaves its traffic to the
// rules below — at worst the default deny. Both directions fail closed.
//
// The caller holds c.mu.
func (c *WFPController) buildFilters(chain string, rules []FirewallRule, epoch uint32) ([]*wf.Rule, error) {
	// One interface is named by most rules of a chain, and every lookup is a
	// syscall.
	resolved := make(map[string]ifaceIDs)

	// unenforceable counts the allow rules the forward layer cannot express,
	// widened the deny rules it can only express without their port.
	unenforceable := 0
	widened := 0

	var filters []*wf.Rule
	for i, rule := range rules {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		// A filter without an interface condition would govern every adapter
		// of the host, so a default deny among the rules would cut the machine
		// off its own networks.
		if rule.Interface == "" {
			return nil, fmt.Errorf("rule %d: interface name is empty", i)
		}
		ids, ok := resolved[rule.Interface]
		if !ok {
			var err error
			if ids, err = c.lookupIface(rule.Interface); err != nil {
				return nil, fmt.Errorf("rule %d: lookup interface %q: %w", i, rule.Interface, err)
			}
			resolved[rule.Interface] = ids
		}

		src, srcOK, err := wfpPrefix(rule.SrcIP)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		dst, dstOK, err := wfpPrefix(rule.DstIP)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}

		// WFP's block is a drop, what the nftables backend expresses as
		// VerdictDrop. HardAction stays false, so a plexd allow is a soft
		// permit the Windows Firewall's own sublayer may still block, while a
		// plexd deny is final.
		action := wf.ActionPermit
		if rule.Action == "deny" {
			action = wf.ActionBlock
		}
		weight := wfpWeight(epoch, len(rules), i)

		var proto wf.IPProto
		switch rule.Protocol {
		case "tcp":
			proto = wf.IPProtoTCP
		case "udp":
			proto = wf.IPProtoUDP
		case "icmp":
			proto = wf.IPProtoICMP
		}

		// Windows delivers a packet locally only when its destination is an
		// address of the arrival interface, so the local interface is the
		// arrival interface, the iifname the Linux chain matches.
		inbound := []*wf.Match{{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: ids.luid}}
		if srcOK {
			inbound = append(inbound, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: src})
		}
		if dstOK {
			inbound = append(inbound, &wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: dst})
		}
		if rule.Protocol != "" {
			inbound = append(inbound, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto})
		}
		switch {
		case rule.Port > 0 && rule.PortTo > rule.Port:
			inbound = append(inbound, &wf.Match{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeRange,
				Value: wf.Range{From: uint16(rule.Port), To: uint16(rule.PortTo)},
			})
		case rule.Port > 0:
			inbound = append(inbound, &wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(rule.Port)})
		}

		id, err := newRuleID()
		if err != nil {
			return nil, fmt.Errorf("rule %d: generate filter id: %w", i, err)
		}
		filters = append(filters, &wf.Rule{
			ID:         id,
			Name:       fmt.Sprintf("plexd %s #%d inbound", chain, i),
			Layer:      wf.LayerALEAuthRecvAcceptV4,
			Sublayer:   plexdSublayerID,
			Weight:     weight,
			Conditions: inbound,
			Action:     action,
		})

		if rule.Port > 0 {
			if rule.Action != "deny" {
				unenforceable++
				continue
			}
			widened++
		}

		forward := []*wf.Match{{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: ids.index}}
		if srcOK {
			forward = append(forward, &wf.Match{Field: wf.FieldIPSourceAddress, Op: wf.MatchTypeEqual, Value: src})
		}
		if dstOK {
			forward = append(forward, &wf.Match{Field: wf.FieldIPDestinationAddress, Op: wf.MatchTypeEqual, Value: dst})
		}
		if rule.Protocol != "" {
			forward = append(forward, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto})
		}

		if id, err = newRuleID(); err != nil {
			return nil, fmt.Errorf("rule %d: generate filter id: %w", i, err)
		}
		filters = append(filters, &wf.Rule{
			ID:         id,
			Name:       fmt.Sprintf("plexd %s #%d forward", chain, i),
			Layer:      wf.LayerIPForwardV4,
			Sublayer:   plexdSublayerID,
			Weight:     weight,
			Conditions: forward,
			Action:     action,
		})
	}

	if unenforceable > 0 {
		// A bridge or relay node forwards mesh traffic, and traffic these
		// rules meant to allow is blocked on that path by the rules below
		// them. Without this line an operator sees transit connections the
		// policy permits fail to arrive and reads it as a routing fault.
		c.logger.Warn("wfp forward path cannot enforce a port, allow rules narrowed away",
			"component", "policy",
			"chain", chain,
			"count", unenforceable,
		)
	}

	if widened > 0 {
		// The counterpart on the deny side, and the louder of the two: the
		// widened rule outweighs every rule below it, so it blocks transit
		// those rules permit — every port of the protocol it names, not just
		// the one it asked for. Without this line an operator sees transit
		// connections the policy permits fail to arrive and reads it as a
		// routing fault.
		c.logger.Warn("wfp forward path cannot enforce a port, deny rules widened to every port",
			"component", "policy",
			"chain", chain,
			"count", widened,
		)
	}

	return filters, nil
}

// deleteFilters removes the given filters and returns the ones that are still
// installed together with the failures. A filter that is already gone is not a
// failure: the desired state is what the call wanted. An ID whose deletion
// failed is kept, so the next cycle of the reconciler deletes it again.
//
// The caller holds c.mu.
func (c *WFPController) deleteFilters(ids []wf.RuleID) ([]wf.RuleID, error) {
	var (
		kept []wf.RuleID
		errs []error
	)
	for _, id := range ids {
		if err := c.engine.DeleteRule(id); err != nil && !errors.Is(err, fwpEFilterNotFound) {
			kept = append(kept, id)
			errs = append(errs, err)
		}
	}
	return kept, errors.Join(errs...)
}

// ApplyRules replaces all filters of the named chain. The new filters are
// installed before the old ones are deleted and outweigh them through the
// epoch, so the chain is never unfiltered in between. A chain that was never
// ensured is created here, as NftablesController.ApplyRules adds its chain
// itself.
func (c *WFPController) ApplyRules(chain string, rules []FirewallRule) error {
	if chain == "" {
		return errors.New("policy: wfp: apply rules: chain name is empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureEngine("apply rules"); err != nil {
		return err
	}

	filters, err := c.buildFilters(chain, rules, c.epoch+1)
	if err != nil {
		return fmt.Errorf("policy: wfp: apply rules: %w", err)
	}

	added := make([]wf.RuleID, 0, len(filters))
	for _, f := range filters {
		if err := c.engine.AddRule(f); err != nil {
			// Half an apply enforces a policy nobody asked for, so every
			// filter this call installed goes again and the chain keeps the
			// ones it had.
			if _, derr := c.deleteFilters(added); derr != nil {
				c.logger.Error("wfp rollback delete failed",
					"component", "policy",
					"filter", f.Name,
					"error", derr,
				)
			}
			return fmt.Errorf("policy: wfp: apply rules: add filter %q: %w%s", f.Name, err, adminHint(err))
		}
		added = append(added, f.ID)
	}

	kept, delErr := c.deleteFilters(c.chains[chain])
	c.chains[chain] = append(added, kept...)
	c.epoch++

	c.logger.Debug("wfp rules applied",
		"component", "policy",
		"chain", chain,
		"count", len(rules),
		"filters", len(added),
	)

	if delErr != nil {
		return fmt.Errorf("policy: wfp: apply rules: delete stale filters: %w", delErr)
	}
	return nil
}

// FlushChain deletes the filters of the named chain but keeps the chain
// itself. Idempotent: flushing a chain that was never ensured returns nil.
func (c *WFPController) FlushChain(chain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ids, ok := c.chains[chain]
	if !ok || c.engine == nil {
		c.logger.Debug("wfp chain not found, nothing to flush",
			"component", "policy",
			"chain", chain,
		)
		return nil
	}

	kept, err := c.deleteFilters(ids)
	c.chains[chain] = kept
	if err != nil {
		return fmt.Errorf("policy: wfp: flush chain %q: %w", chain, err)
	}

	c.logger.Debug("wfp chain flushed",
		"component", "policy",
		"chain", chain,
	)
	return nil
}

// DeleteChain deletes the filters of the named chain and forgets it. When it
// was the last one the session is closed, which drops plexd's sublayer with
// it. Idempotent: deleting a chain that was never ensured returns nil.
func (c *WFPController) DeleteChain(chain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ids, ok := c.chains[chain]
	if !ok || c.engine == nil {
		c.logger.Debug("wfp chain not found, nothing to delete",
			"component", "policy",
			"chain", chain,
		)
		return nil
	}

	kept, err := c.deleteFilters(ids)
	if err != nil {
		// The chain stays, so a retry deletes what is still installed.
		c.chains[chain] = kept
		return fmt.Errorf("policy: wfp: delete chain %q: %w", chain, err)
	}
	delete(c.chains, chain)

	if len(c.chains) == 0 {
		// The session is dropped even when the close failed: it is unusable
		// either way, and the next chain opens a fresh one.
		err := c.engine.Close()
		c.engine = nil
		if err != nil {
			return fmt.Errorf("policy: wfp: delete chain: close session: %w", err)
		}
	}

	c.logger.Debug("wfp chain deleted",
		"component", "policy",
		"chain", chain,
	)
	return nil
}
