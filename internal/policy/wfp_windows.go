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
	"go4.org/netipx"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// errWFPConnLogUnavailable is the error of the connLogUnavailable line the
// controller logs for every apply that holds a logged rule.
var errWFPConnLogUnavailable = errors.New("policy: wfp: connection logging is not available on Windows")

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
// layer matches on and the LUID the local-delivery and connect layers match
// on.
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
// Filtering Platform and bridge.NATController through WinNAT. Filters live in
// a dynamic session, so they vanish with the process; the Wintun adapter
// vanishes with it too, so nothing arrives that they could have filtered.
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
// one. The relay probe permits sit at index -1, which outweighs rule 0. The
// result stays below 2^60 for 2^28 applies, which is what a FWP_UINT64
// weight accepts.
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
// matches on. The second result is false for an empty field and for a
// zero-length prefix, 0.0.0.0/0 or ::/0, which both mean "no address
// condition": the layer a filter sits at already selects the family. The
// parsing and its rejection texts are shared with the other backends, so a
// rejected rule reads the same on every platform.
func wfpPrefix(addr string) (netip.Prefix, bool, error) {
	prefix, ok, err := parseRuleAddr(addr)
	if err != nil || !ok || prefix.Bits() == 0 {
		return netip.Prefix{}, false, err
	}
	return prefix, true, nil
}

// addrMatch is the condition that matches field against prefix. An IPv4
// prefix goes in as an address and mask, an IPv6 prefix as the range from its
// first to its last address, which matches the same packets.
//
// DECISION: github.com/tailscale/wf builds a filter's structs in a bump arena
// that never aligns an allocation. FWP_V6_ADDR_AND_MASK is 17 bytes, so
// every allocation after it in the same filter, FWPM_FILTER0 included, lands
// on an odd address, and under -race checkptr aborts the conversion
// ("misaligned pointer conversion" in toFilter0). A range is two 16-byte
// addresses and an FWP_RANGE0, which keeps every allocation a multiple of 8.
// Upstream's head has the same arena, so there is no version to move to.
func addrMatch(field wf.FieldID, prefix netip.Prefix) *wf.Match {
	if prefix.Addr().Is4() {
		return &wf.Match{Field: field, Op: wf.MatchTypeEqual, Value: prefix}
	}
	return &wf.Match{Field: field, Op: wf.MatchTypeRange, Value: netipx.RangeOfPrefix(prefix)}
}

// wfpLayers is the set of layers the filters of one address family sit at,
// and the suffix that tells their names apart from the other family's.
type wfpLayers struct {
	inbound  wf.LayerID
	outbound wf.LayerID
	forward  wf.LayerID
	suffix   string
}

// wfpFamilies holds the IPv4 layers, whose filter names carry no suffix as
// before IPv6 rules existed, and the IPv6 layers.
var wfpFamilies = [...]wfpLayers{
	{inbound: wf.LayerALEAuthRecvAcceptV4, outbound: wf.LayerALEAuthConnectV4, forward: wf.LayerIPForwardV4},
	{inbound: wf.LayerALEAuthRecvAcceptV6, outbound: wf.LayerALEAuthConnectV6, forward: wf.LayerIPForwardV6, suffix: " v6"},
}

// wfpLayersOf returns the layers a rule of the given family is installed at.
// A WFP layer sees one family only, so a rule without addresses, the default
// deny, is installed at the layers of both.
func wfpLayersOf(fam addrFamily) []wfpLayers {
	switch fam {
	case familyIPv4:
		return wfpFamilies[:1]
	case familyIPv6:
		return wfpFamilies[1:]
	}
	return wfpFamilies[:]
}

// portMatch is the condition that matches field against the rule's port or
// port range. It is nil for a rule that names no port.
func portMatch(field wf.FieldID, rule FirewallRule) *wf.Match {
	switch {
	case rule.Port > 0 && rule.PortTo > rule.Port:
		return &wf.Match{
			Field: field,
			Op:    wf.MatchTypeRange,
			Value: wf.Range{From: uint16(rule.Port), To: uint16(rule.PortTo)},
		}
	case rule.Port > 0:
		return &wf.Match{Field: field, Op: wf.MatchTypeEqual, Value: uint16(rule.Port)}
	}
	return nil
}

// relayProbeFilters returns the permits that let the node send UDP to
// RelayProbePort over one interface, one at the connect layer of each family.
// They carry no address, since the probe goes to whichever peer is relayed.
// Their weight is above rule 0's, so no rule of the chain decides the probe.
func relayProbeFilters(chain string, ids ifaceIDs, epoch uint32, n int) ([]*wf.Rule, error) {
	weight := wfpWeight(epoch, n, -1)

	filters := make([]*wf.Rule, 0, len(wfpFamilies))
	for _, layers := range wfpFamilies {
		id, err := newRuleID()
		if err != nil {
			return nil, err
		}
		filters = append(filters, &wf.Rule{
			ID:       id,
			Name:     fmt.Sprintf("plexd %s relay probe%s", chain, layers.suffix),
			Layer:    layers.outbound,
			Sublayer: plexdSublayerID,
			Weight:   weight,
			Conditions: []*wf.Match{
				{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: ids.luid},
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
				{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(RelayProbePort)},
			},
			Action: wf.ActionPermit,
		})
	}
	return filters, nil
}

// buildFilters translates one chain's rules into filters, none of which is
// installed yet: a rule the engine would reject has to fail before the first
// AddRule, or an apply would leave half a ruleset in the kernel.
//
// Every rule yields up to three filters of its address family, all of the
// same weight. The inbound filter sits at ALE_AUTH_RECV_ACCEPT, the
// local-delivery layer, which is where the five-tuple is available. The
// outbound filter sits at ALE_AUTH_CONNECT, which authorizes the node's own
// outbound connections and the first packet of its other flows. It matches
// the rule's source as the local address and its destination as the remote
// one. The forward filter sits at the family's forward layer, so that traffic
// through the node is governed by the same decision. A rule without addresses
// yields its filters at the IPv4 and at the IPv6 layers. The forward layer
// carries an interface and addresses, but neither a protocol nor a port:
// IPFORWARD_V4 and IPFORWARD_V6 have no IP_PROTOCOL field, and the engine
// refuses a condition on one.
//
// Replies need no outbound filter. Once ALE_AUTH_RECV_ACCEPT authorizes a
// flow, its packets pass in both directions without another classification,
// and ICMP error messages never reach the ALE layers. Microsoft describes both
// in "ALE Stateful Filtering":
// https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering
//
// Forwarded traffic never reaches ALE_AUTH_CONNECT, so what the node forwards
// into the mesh is not filtered on its way out.
//
// Ahead of the rule filters, every interface the rules name gets the relay
// probe permits of relayProbeFilters, once.
//
// The ruleset is ordered and first-match-terminating, so a rule left out of
// the forward layer is not narrowed to nothing: the traffic it covered is
// re-decided by whatever follows it. A deny that names a protocol or a port
// is therefore installed without them, which blocks a superset of what the
// rule asked for, and such an allow gets no forward filter, which leaves its
// traffic to the rules below, at worst the default deny. Both directions
// fail closed.
//
// The caller holds c.mu.
func (c *WFPController) buildFilters(chain string, rules []FirewallRule, epoch uint32) ([]*wf.Rule, error) {
	// One interface is named by most rules of a chain, and every lookup is a
	// syscall.
	resolved := make(map[string]ifaceIDs)

	// unenforceable counts the allow rules the forward layer cannot express,
	// widened the deny rules it can only express without their protocol and
	// port.
	unenforceable := 0
	widened := 0

	var probes, filters []*wf.Rule
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

			p, err := relayProbeFilters(chain, ids, epoch, len(rules))
			if err != nil {
				return nil, fmt.Errorf("rule %d: generate filter id: %w", i, err)
			}
			probes = append(probes, p...)
		}

		fam, err := rule.family()
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
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
			// icmp in an IPv6 rule means ICMPv6. Validate refuses icmp in a
			// rule without an address, so the family is one of the two.
			proto = wf.IPProtoICMP
			if fam == familyIPv6 {
				proto = wf.IPProtoICMPV6
			}
		}

		// The counts are per rule, not per filter: a rule without addresses
		// has a forward filter in each family, but it is still one rule.
		hasForward := true
		if rule.Protocol != "" || rule.Port > 0 {
			if rule.Action != "deny" {
				unenforceable++
				hasForward = false
			} else {
				widened++
			}
		}

		for _, layers := range wfpLayersOf(fam) {
			// Windows delivers a packet locally only when its destination is
			// an address of the arrival interface, so the local interface is
			// the arrival interface, the iifname the Linux chain matches.
			inbound := []*wf.Match{{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: ids.luid}}
			if srcOK {
				inbound = append(inbound, addrMatch(wf.FieldIPRemoteAddress, src))
			}
			if dstOK {
				inbound = append(inbound, addrMatch(wf.FieldIPLocalAddress, dst))
			}
			if rule.Protocol != "" {
				inbound = append(inbound, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto})
			}
			if m := portMatch(wf.FieldIPLocalPort, rule); m != nil {
				inbound = append(inbound, m)
			}

			id, err := newRuleID()
			if err != nil {
				return nil, fmt.Errorf("rule %d: generate filter id: %w", i, err)
			}
			filters = append(filters, &wf.Rule{
				ID:         id,
				Name:       fmt.Sprintf("plexd %s #%d inbound%s", chain, i, layers.suffix),
				Layer:      layers.inbound,
				Sublayer:   plexdSublayerID,
				Weight:     weight,
				Conditions: inbound,
				Action:     action,
			})

			// Windows sends a packet only from an address of the interface
			// it leaves through, so the local interface is the outgoing
			// interface, the oifname the Linux output chain matches. The
			// rule's source is the node's side of the flow here, and its
			// destination the remote side.
			outbound := []*wf.Match{{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: ids.luid}}
			if srcOK {
				outbound = append(outbound, addrMatch(wf.FieldIPLocalAddress, src))
			}
			if dstOK {
				outbound = append(outbound, addrMatch(wf.FieldIPRemoteAddress, dst))
			}
			if rule.Protocol != "" {
				outbound = append(outbound, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto})
			}
			if m := portMatch(wf.FieldIPRemotePort, rule); m != nil {
				outbound = append(outbound, m)
			}

			if id, err = newRuleID(); err != nil {
				return nil, fmt.Errorf("rule %d: generate filter id: %w", i, err)
			}
			filters = append(filters, &wf.Rule{
				ID:         id,
				Name:       fmt.Sprintf("plexd %s #%d outbound%s", chain, i, layers.suffix),
				Layer:      layers.outbound,
				Sublayer:   plexdSublayerID,
				Weight:     weight,
				Conditions: outbound,
				Action:     action,
			})

			if !hasForward {
				continue
			}

			forward := []*wf.Match{{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: ids.index}}
			if srcOK {
				forward = append(forward, addrMatch(wf.FieldIPSourceAddress, src))
			}
			if dstOK {
				forward = append(forward, addrMatch(wf.FieldIPDestinationAddress, dst))
			}

			if id, err = newRuleID(); err != nil {
				return nil, fmt.Errorf("rule %d: generate filter id: %w", i, err)
			}
			filters = append(filters, &wf.Rule{
				ID:         id,
				Name:       fmt.Sprintf("plexd %s #%d forward%s", chain, i, layers.suffix),
				Layer:      layers.forward,
				Sublayer:   plexdSublayerID,
				Weight:     weight,
				Conditions: forward,
				Action:     action,
			})
		}
	}

	if unenforceable > 0 {
		// A bridge or relay node forwards mesh traffic, and traffic these
		// rules meant to allow is blocked on that path by the rules below
		// them. Without this line an operator sees transit connections the
		// policy permits fail to arrive and reads it as a routing fault.
		c.logger.Warn("wfp forward path cannot enforce a protocol or port, allow rules narrowed away",
			"component", "policy",
			"chain", chain,
			"count", unenforceable,
		)
	}

	if widened > 0 {
		// The counterpart on the deny side, and the louder of the two: the
		// widened rule outweighs every rule below it, so it blocks transit
		// those rules permit — every protocol and every port between its
		// addresses, not just the ones it asked for. Without this line an
		// operator sees transit connections the policy permits fail to arrive
		// and reads it as a routing fault.
		c.logger.Warn("wfp forward path cannot enforce a protocol or port, deny rules widened to every protocol and port",
			"component", "policy",
			"chain", chain,
			"count", widened,
		)
	}

	return append(probes, filters...), nil
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

	// DECISION: Windows enforces a logged rule like any other and logs none
	// of its connections (author, 2026-11-12, #179). The filter engine
	// records a classify-allow net event under plexd's filter for each such
	// connection, but on windows-latest a FwpmNetEventSubscribe1
	// subscription delivered none of them, only drop events (measured for
	// PR #182). Reading them is left to a later change, so every apply that
	// holds a logged rule says so with the line the other backends log when
	// they cannot report their connections.
	if hasLogTags(rules) {
		c.logger.Warn(connLogUnavailable,
			"component", "policy",
			"chain", chain,
			"error", errWFPConnLogUnavailable,
		)
	}

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
