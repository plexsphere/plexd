//go:build windows

package policy

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	// netNatExemptPrefix starts the name of every NetNat object that exempts a
	// tunnel's adapter from the bridge NAT, plexd-exempt-<iface>.
	// ResetNATExemptions removes every object whose name starts with it, so
	// netNatName must not.
	netNatExemptPrefix = "plexd-exempt-"

	// psListNetNat prints one line per NetNat object of the host, its name and
	// the source prefix it translates, which is all ExemptFromNAT decides on.
	// A host without an object prints nothing and succeeds.
	psListNetNat = "Get-NetNat | ForEach-Object { $_.Name + '|' + $_.InternalIPInterfaceAddressPrefix }"

	// psResetNetNatExempt removes every exemption object at once, also those
	// a killed process left behind. A host without one hands Remove-NetNat no
	// input, and the pipeline succeeds without removing anything.
	psResetNetNatExempt = "Get-NetNat | Where-Object { $_.Name -like '" + netNatExemptPrefix + "*' } | Remove-NetNat -Confirm:$false"

	// netNatExemptBlocks is the number of /30 blocks an exemption draws from,
	// 169.254.1.0/30 to 169.254.252.252/30. RFC 3927 reserves 169.254.0.0/24
	// and 169.254.255.0/24, and the blocks stay clear of both.
	netNatExemptBlocks = 16128
)

// exemptIfaceName is what an interface name has to look like before it
// becomes part of a PowerShell command. The names plexd gives a tunnel's link,
// such as wg-s2s-a0a0a0e1, fit it, and PowerShell finds nothing in such a name
// to interpret.
var exemptIfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// linkLocalV4 is the range IPv4 address autoconfiguration (RFC 3927) assigns
// from, and the on-link prefix of every address it assigns.
var linkLocalV4 = netip.MustParsePrefix("169.254.0.0/16")

// netNatExemptName is the name of the object that exempts iface.
func netNatExemptName(iface string) string {
	return netNatExemptPrefix + iface
}

// psNewNetNatExempt creates the exemption object of iface for prefix.
// Out-Null drops the created object from the output, so a failure's output
// carries PowerShell's error text alone.
func psNewNetNatExempt(iface string, prefix netip.Prefix) string {
	return "New-NetNat -Name " + netNatExemptName(iface) + " -InternalIPInterfaceAddressPrefix " + prefix.String() + " | Out-Null"
}

// psRemoveNetNatExempt removes the exemption object of iface. Like
// psRemoveNetNat it treats an absent object as a success, so a tunnel whose
// object a reset or an operator already removed still comes down cleanly.
func psRemoveNetNatExempt(iface string) string {
	return psAbsentOK + "Remove-NetNat -Name " + netNatExemptName(iface) + " -Confirm:$false" + psAbsentOKEnd
}

// netNatObject is one line of psListNetNat. Its prefix stays the zero Prefix
// when the line's does not parse, as for an object that names no internal
// prefix, and such an object overlaps nothing: Prefix.Overlaps reports false
// for an invalid prefix.
type netNatObject struct {
	name   string
	prefix netip.Prefix
}

// parseNetNatList reads the output of psListNetNat. PowerShell ends its lines
// in CRLF and may add blank ones, and a line without the separator is no
// object.
func parseNetNatList(out []byte) []netNatObject {
	var objects []netNatObject
	for _, line := range strings.Split(string(out), "\n") {
		name, prefix, ok := strings.Cut(strings.TrimSpace(line), "|")
		if !ok {
			continue
		}
		obj := netNatObject{name: strings.TrimSpace(name)}
		if p, err := netip.ParsePrefix(strings.TrimSpace(prefix)); err == nil {
			obj.prefix = p.Masked()
		}
		objects = append(objects, obj)
	}
	return objects
}

// exemptBlock returns block n of the 16,128 /30 blocks an exemption draws
// from: 169.254.(1+n/64).(4*(n mod 64))/30.
func exemptBlock(n uint32) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{169, 254, byte(1 + n/64), byte(4 * (n % 64))}), 30)
}

// exemptBlockStart is the block the search for iface starts at, the 32-bit
// FNV-1a hash of the name modulo the number of blocks. A tunnel keeps its
// block across restarts while the host's addresses stay the same, and two
// tunnels rarely contend for one.
func exemptBlockStart(iface string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(iface))
	return h.Sum32() % netNatExemptBlocks
}

// hostTakesBlock reports whether the host address p, given with its on-link
// prefix length, rules block out. A host prefix rules out every block it
// overlaps, with one exception. An autoconfiguration address, which Windows
// gives an adapter without an address of its own, as it gives a tunnel's link
// (measured), is on-link to all of 169.254.0.0/16 and so overlaps every
// block, which would leave none free. Every such adapter shares that prefix,
// and Windows routes a block over the adapter that carries it as the more
// specific prefix, so the address rules out only the block that holds it.
// The price is that a neighbour on another link whose autoconfiguration
// address falls inside the chosen block is routed to the tunnel's link, and
// the host no longer reaches it.
func hostTakesBlock(block, p netip.Prefix) bool {
	if p.Masked() == linkLocalV4 {
		return block.Contains(p.Addr())
	}
	return block.Overlaps(p)
}

// freeExemptBlock returns the first block from the start of iface on, taken
// in a circle, that overlaps no listed object's prefix and that no host
// address rules out.
func freeExemptBlock(iface string, objects []netNatObject, host []netip.Prefix) (netip.Prefix, bool) {
	start := exemptBlockStart(iface)
next:
	for i := uint32(0); i < netNatExemptBlocks; i++ {
		block := exemptBlock((start + i) % netNatExemptBlocks)
		for _, obj := range objects {
			if block.Overlaps(obj.prefix) {
				continue next
			}
		}
		for _, p := range host {
			if hostTakesBlock(block, p) {
				continue next
			}
		}
		return block, true
	}
	return netip.Prefix{}, false
}

// ExemptFromNAT keeps the bridge NAT from translating what is forwarded
// between the mesh adapter and the tunnel link iface. It implements
// bridge.NATExempter. WinNAT does not translate between two adapters that
// each carry a NetNat object's prefix, so the link gets a 169.254 /30 of its
// own and an object, plexd-exempt-<iface>, for that /30. The address goes
// with the adapter when the tunnel's link is removed.
//
// Without an object outside plexd-exempt-* that covers the mesh prefix there
// is no bridge NAT to exempt from, and the call creates nothing: measured, an
// object for the link's prefix alone also translates the site's replies to
// connections a mesh node opened, which breaks them.
//
// Idempotent: a link whose object exists is left alone.
func (c *WFPController) ExemptFromNAT(iface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	op := fmt.Sprintf("exempt %q from NAT", iface)

	// The name becomes PowerShell text, so it is checked before anything
	// runs.
	if !exemptIfaceName.MatchString(iface) {
		return fmt.Errorf("bridge: %s: invalid interface name", op)
	}

	meshPrefix, err := c.meshPrefix(c.meshIface)
	if err != nil {
		return fmt.Errorf("bridge: %s: resolve mesh prefix for %q: %w", op, c.meshIface, err)
	}

	out, err := c.powershell(op, psListNetNat)
	if err != nil {
		return err
	}
	objects := parseNetNatList(out)

	name := netNatExemptName(iface)
	covered := false
	for _, obj := range objects {
		if obj.name == name {
			return nil
		}
		if !strings.HasPrefix(obj.name, netNatExemptPrefix) && obj.prefix.Overlaps(meshPrefix) {
			covered = true
		}
	}
	if !covered {
		return nil
	}

	host, err := c.hostPrefixes()
	if err != nil {
		return fmt.Errorf("bridge: %s: read the host's addresses: %w", op, err)
	}
	block, ok := freeExemptBlock(iface, objects, host)
	if !ok {
		return fmt.Errorf("bridge: %s: no free 169.254 /30", op)
	}

	// The block's first host address, with the block's length, so the link
	// is on-link to exactly the prefix the object names.
	addr := netip.PrefixFrom(block.Addr().Next(), block.Bits())
	ids, err := c.lookupIface(iface)
	if err != nil {
		return fmt.Errorf("bridge: %s: add %s: %w", op, addr, err)
	}
	if err := c.addAddress(ids.luid, addr); err != nil {
		return fmt.Errorf("bridge: %s: add %s: %w", op, addr, err)
	}

	if _, err := c.powershell(op, psNewNetNatExempt(iface, block)); err != nil {
		// A client edition, and any host at its limit, refuses a further
		// object, and the address alone exempts nothing, so it goes again.
		// A failed removal is reported with the cause, though the address
		// goes with the link the caller removes next.
		err = fmt.Errorf("%w (a NetNat object covers the mesh prefix %s and this host took no further one; bridge.enable_nat: false serves tunnels without bridge NAT)", err, meshPrefix)
		if rmErr := c.removeAddress(ids.luid, addr); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("bridge: %s: remove %s: %w", op, addr, rmErr))
		}
		return err
	}

	c.logger.Info("tunnel exempted from NAT",
		"component", "bridge",
		"interface", iface,
		"prefix", block,
		"nat", name,
	)
	return nil
}

// UnexemptFromNAT removes the exemption object of iface. It implements
// bridge.NATExempter. The address stays on the link and goes with it, and
// once no adapter carries the object's prefix the object would translate
// nothing anyway (measured). Idempotent: an absent object is a success.
func (c *WFPController) UnexemptFromNAT(iface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	op := fmt.Sprintf("unexempt %q from NAT", iface)
	if !exemptIfaceName.MatchString(iface) {
		return fmt.Errorf("bridge: %s: invalid interface name", op)
	}

	if _, err := c.powershell(op, psRemoveNetNatExempt(iface)); err != nil {
		return err
	}

	c.logger.Debug("NAT exemption removed",
		"component", "bridge",
		"interface", iface,
		"nat", netNatExemptName(iface),
	)
	return nil
}

// ResetNATExemptions removes every exemption object of the host. It
// implements bridge.NATExempter. An object outlives a killed process, so a
// start removes them all before it brings a tunnel up.
func (c *WFPController) ResetNATExemptions() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.powershell("reset NAT exemptions", psResetNetNatExempt); err != nil {
		return err
	}

	c.logger.Debug("NAT exemptions reset", "component", "bridge")
	return nil
}

// addLUIDAddress adds prefix, an address with its on-link prefix length, to
// the adapter luid names.
func addLUIDAddress(luid uint64, prefix netip.Prefix) error {
	return winipcfg.LUID(luid).AddIPAddress(prefix)
}

// deleteLUIDAddress removes prefix from the adapter luid names.
func deleteLUIDAddress(luid uint64, prefix netip.Prefix) error {
	return winipcfg.LUID(luid).DeleteIPAddress(prefix)
}

// hostUnicastPrefixes returns every IPv4 address of the host, each with its
// on-link prefix length, the prefixes an exemption's block must stay clear
// of. The address is kept, not masked, because hostTakesBlock decides an
// autoconfiguration address by it.
func hostUnicastPrefixes() ([]netip.Prefix, error) {
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(rows))
	for i := range rows {
		prefixes = append(prefixes, netip.PrefixFrom(rows[i].Address.Addr(), int(rows[i].OnLinkPrefixLength)))
	}
	return prefixes, nil
}
