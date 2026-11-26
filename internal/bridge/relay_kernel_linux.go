//go:build linux

package bridge

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/plexsphere/plexd/internal/bridge/relaybpf"
)

// errKernelFamiliesDiffer is what forward returns for a session whose partner
// and owner reach the relay over different address families. The program
// rewrites a datagram's addresses in place, so it cannot turn an IPv4
// datagram into an IPv6 one.
var errKernelFamiliesDiffer = errors.New("bridge: relay: kernel forwarding: address families differ")

// relayForwarder is the part of *relaybpf.Forwarder the Linux kernel path
// uses, so the adapter's tests can replace the program with a fake.
type relayForwarder interface {
	Attach(ifindex int) error
	Put(index uint32, s relaybpf.Session) error
	Delete(index uint32) error
	Age(index uint32) (time.Duration, bool, error)
	Ages() (map[uint32]time.Duration, error)
	Counters() (map[string]uint64, error)
	Close() error
}

var _ relayForwarder = (*relaybpf.Forwarder)(nil)

// relayRoute is how this host reaches one address: the source address it
// sends from, unmapped, and the interface it sends through, by index and
// name, with whether that interface carries an Ethernet header.
type relayRoute struct {
	src     netip.Addr
	ifindex int
	name    string
	ether   bool
}

// relayKernelLinux is the kernel path of the relay on Linux. It hands the
// sessions the relay places to the eBPF program of relaybpf and resolves, for
// each session, the source addresses and the interface the program needs.
// Like every relayKernel it is called with Relay.mu held, so it has no lock of
// its own.
type relayKernelLinux struct {
	logger    *slog.Logger
	meshIface string
	// in runs every netlink call, bpf call and sysctl access, because an
	// interface index, a route and /proc/sys/net belong to the network
	// namespace of the calling thread. plexd runs them directly; the real
	// kernel test runs them inside its relay namespace.
	in func(func() error) error

	// Seams, replaced by the adapter's unit tests.
	fwd       relayForwarder
	route     func(netip.Addr) (relayRoute, error)
	readFile  func(path string) ([]byte, error)
	writeFile func(path string, b []byte) error

	// routes caches the route to every address a session uses, so a placed
	// session costs no netlink call when its other direction is installed or
	// it is installed again after a roam. refresh resolves them again.
	routes map[netip.Addr]relayRoute
	// attached holds the interfaces the program is attached to, by index,
	// with the name each had when it was attached.
	attached map[int]string
	// flows holds the session of every index the program holds.
	flows map[uint32]relayKernelFlow
	// ipv6Raised records that raiseIPv6Forwarding wrote 1 to the mesh
	// interface's IPv6 forwarding flag, which close writes back to 0.
	ipv6Raised bool
}

// inValue runs f through in and returns what f returned, for the calls of
// the adapter that return a value.
func inValue[T any](in func(func() error) error, f func() (T, error)) (T, error) {
	var v T
	err := in(func() error {
		var err error
		v, err = f()
		return err
	})
	return v, err
}

// platformRelayKernel returns the constructor of the Linux kernel path, which
// runs every netlink call, bpf call and sysctl access in the namespace of the
// calling thread.
func platformRelayKernel() func(port int, meshIface string, logger *slog.Logger) (relayKernel, error) {
	return func(port int, meshIface string, logger *slog.Logger) (relayKernel, error) {
		return newRelayKernelLinux(port, meshIface, logger, func(f func() error) error { return f() })
	}
}

// newRelayKernelLinux loads the program for a relay on port that asks for its
// routes through meshIface, and sets the IPv6 forwarding flag of meshIface
// while the program runs. Without that flag the program's IPv6 route lookups
// fail and every IPv6 datagram passes to the process; the flag does not make
// the host forward IPv6, which needs conf.all.forwarding. A flag that cannot
// be set fails nothing. in runs every access to the kernel; see
// relayKernelLinux.in.
func newRelayKernelLinux(port int, meshIface string, logger *slog.Logger, in func(func() error) error) (relayKernel, error) {
	mesh, err := inValue(in, func() (netlink.Link, error) { return netlink.LinkByName(meshIface) })
	if err != nil {
		return nil, fmt.Errorf("bridge: relay: kernel forwarding: mesh interface %q: %w", meshIface, err)
	}

	// Configure checked that port fits 16 bits before the relay started.
	fwd, err := inValue(in, func() (*relaybpf.Forwarder, error) {
		return relaybpf.Load(uint16(port), mesh.Attrs().Index)
	})
	if err != nil {
		return nil, fmt.Errorf("bridge: relay: kernel forwarding: %w", err)
	}

	k := &relayKernelLinux{
		logger:    logger,
		meshIface: meshIface,
		in:        in,
		fwd:       fwd,
		route:     resolveRelayRoute,
		readFile:  os.ReadFile,
		writeFile: func(path string, b []byte) error { return os.WriteFile(path, b, 0o644) },
		routes:    make(map[netip.Addr]relayRoute),
		attached:  make(map[int]string),
		flows:     make(map[uint32]relayKernelFlow),
	}
	k.raiseIPv6Forwarding()
	return k, nil
}

// resolveRelayRoute asks the kernel how this host reaches addr, as ip route
// get does. A route without a source address is an error, because the
// program writes that source into every datagram it sends along the route.
func resolveRelayRoute(addr netip.Addr) (relayRoute, error) {
	routes, err := netlink.RouteGet(net.IP(addr.AsSlice()))
	if err != nil {
		return relayRoute{}, err
	}
	if len(routes) == 0 {
		return relayRoute{}, errors.New("no route")
	}
	src, ok := netip.AddrFromSlice(routes[0].Src)
	if !ok {
		return relayRoute{}, errors.New("the route has no source address")
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return relayRoute{}, fmt.Errorf("interface %d: %w", routes[0].LinkIndex, err)
	}
	return relayRoute{
		src:     src.Unmap(),
		ifindex: routes[0].LinkIndex,
		name:    link.Attrs().Name,
		ether:   link.Attrs().EncapType == "ether",
	}, nil
}

// ipv6ForwardingPath returns the path of the IPv6 forwarding flag of iface.
// Callers check the name with validateIfaceName first.
func ipv6ForwardingPath(iface string) string {
	return "/proc/sys/net/ipv6/conf/" + iface + "/forwarding"
}

// raiseIPv6Forwarding writes 1 to the IPv6 forwarding flag of the mesh
// interface when it holds 0, and remembers that it did, so close restores
// what it found. The program asks for its routes through the mesh interface,
// and the kernel refuses an IPv6 lookup through an interface whose flag is 0.
// A flag that cannot be read or written leaves the IPv6 sessions in the
// process and fails nothing.
func (k *relayKernelLinux) raiseIPv6Forwarding() {
	if err := validateIfaceName(k.meshIface); err != nil {
		k.logger.Debug("relay: ipv6 forwarding flag not set on the mesh interface", "error", err)
		return
	}
	path := ipv6ForwardingPath(k.meshIface)
	if err := k.in(func() error {
		b, err := k.readFile(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(b)) != "0" {
			return nil
		}
		if err := k.writeFile(path, []byte("1")); err != nil {
			return err
		}
		k.ipv6Raised = true
		return nil
	}); err != nil {
		k.logger.Debug("relay: ipv6 forwarding flag not set on the mesh interface", "error", err)
	}
}

// forward installs flow as the session of index. It refuses, without
// writing anything, a session the program cannot forward: partner and owner
// in different address families, a link-local address, which names a host
// only together with its interface while the program's route lookup asks
// through the mesh interface, an address without a route, and a route
// through an interface without the 14-byte Ethernet header the program reads
// and writes. Such a session stays in the process.
//
// The program is attached to the partner's interface, the one the partner's
// datagrams arrive on when routing is symmetric. A datagram that arrives on
// an interface without the program stays in the process too, and one that
// arrives on an interface the program is attached to for another partner is
// forwarded when it matches its entry. A datagram for a VLAN interface
// arrives first on the VLAN's parent device, still tagged in the skb's
// metadata, so the program passes it there and sees it again on the VLAN
// interface.
func (k *relayKernelLinux) forward(index uint32, flow relayKernelFlow) error {
	partner := flow.partner.Addr().Unmap()
	owner := flow.owner.Addr().Unmap()
	if partner.Is4() != owner.Is4() {
		return errKernelFamiliesDiffer
	}
	for _, addr := range []netip.Addr{partner, owner} {
		if addr.IsLinkLocalUnicast() {
			return fmt.Errorf("bridge: relay: kernel forwarding: link-local address %s", addr)
		}
	}

	toPartner, err := k.resolve(partner)
	if err != nil {
		return err
	}
	toOwner, err := k.resolve(owner)
	if err != nil {
		return err
	}
	for _, rt := range []relayRoute{toPartner, toOwner} {
		if !rt.ether {
			return fmt.Errorf("bridge: relay: kernel forwarding: interface %s is not Ethernet", rt.name)
		}
	}

	if name, ok := k.attached[toPartner.ifindex]; !ok || name != toPartner.name {
		if err := k.in(func() error { return k.fwd.Attach(toPartner.ifindex) }); err != nil {
			return fmt.Errorf("bridge: relay: kernel forwarding: attach to %s: %w", toPartner.name, err)
		}
		k.attached[toPartner.ifindex] = toPartner.name
		k.logger.Info("relay: kernel forwarding attached", "interface", toPartner.name)
	}

	session := relaybpf.Session{
		Partner:    flow.partner,
		PartnerDst: toPartner.src,
		Owner:      flow.owner,
		OwnerSrc:   toOwner.src,
		OwnerIf:    toOwner.ifindex,
	}
	if err := k.in(func() error { return k.fwd.Put(index, session) }); err != nil {
		return fmt.Errorf("bridge: relay: kernel forwarding: write session: %w", err)
	}
	k.flows[index] = flow
	return nil
}

// resolve returns the route to addr from the cache, and asks the kernel on a
// miss.
func (k *relayKernelLinux) resolve(addr netip.Addr) (relayRoute, error) {
	if rt, ok := k.routes[addr]; ok {
		return rt, nil
	}
	rt, err := inValue(k.in, func() (relayRoute, error) { return k.route(addr) })
	if err != nil {
		return relayRoute{}, fmt.Errorf("bridge: relay: kernel forwarding: route to %s: %w", addr, err)
	}
	k.routes[addr] = rt
	return rt, nil
}

// forget removes the session of index from the program. An index the program
// does not hold is no error. The relay ends the kernel path on an error, so
// the session is dropped from flows either way.
func (k *relayKernelLinux) forget(index uint32) error {
	delete(k.flows, index)
	if err := k.in(func() error { return k.fwd.Delete(index) }); err != nil {
		return fmt.Errorf("bridge: relay: kernel forwarding: %w", err)
	}
	return nil
}

// age returns how long ago the program last forwarded a datagram naming
// index, and false when it does not hold index.
func (k *relayKernelLinux) age(index uint32) (time.Duration, bool, error) {
	var (
		d  time.Duration
		ok bool
	)
	if err := k.in(func() error {
		var err error
		d, ok, err = k.fwd.Age(index)
		return err
	}); err != nil {
		return 0, false, fmt.Errorf("bridge: relay: kernel forwarding: %w", err)
	}
	return d, ok, nil
}

// ages returns age for every index the program holds.
func (k *relayKernelLinux) ages() (map[uint32]time.Duration, error) {
	ages, err := inValue(k.in, k.fwd.Ages)
	if err != nil {
		return nil, fmt.Errorf("bridge: relay: kernel forwarding: %w", err)
	}
	return ages, nil
}

// counters returns the program's counters by name.
func (k *relayKernelLinux) counters() (map[string]uint64, error) {
	counters, err := inValue(k.in, k.fwd.Counters)
	if err != nil {
		return nil, fmt.Errorf("bridge: relay: kernel forwarding: %w", err)
	}
	return counters, nil
}

// refresh resolves again every cached address a session uses, and forgets and
// returns the indices of the sessions that use an address whose route,
// source address or interface changed, or that no longer resolves. The
// program sends a session's datagrams from the source the process resolved
// and matches the partner's against it, so a session the host now reaches
// another way has to be resolved and installed again by its next datagram
// in the process. It returns nil when nothing changed.
//
// It also drops the cached addresses no session uses, and every attachment
// that no cached route names with the same interface name, so an interface
// that went away or was renamed is attached again, and logged, when a session
// needs it. Attaching to an index the Forwarder holds a link for attaches
// nothing more, and Linux 6.6 and later hand out interface indices
// cyclically, so the link of a removed interface is never taken for a new
// one.
func (k *relayKernelLinux) refresh() []uint32 {
	used := make(map[netip.Addr]bool, len(k.routes))
	for _, flow := range k.flows {
		used[flow.partner.Addr().Unmap()] = true
		used[flow.owner.Addr().Unmap()] = true
	}

	changed := make(map[netip.Addr]bool)
	for addr, old := range k.routes {
		if !used[addr] {
			delete(k.routes, addr)
			continue
		}
		rt, err := inValue(k.in, func() (relayRoute, error) { return k.route(addr) })
		if err != nil {
			delete(k.routes, addr)
			changed[addr] = true
			continue
		}
		if rt != old {
			k.routes[addr] = rt
			changed[addr] = true
		}
	}

	var forgotten []uint32
	for index, flow := range k.flows {
		if !changed[flow.partner.Addr().Unmap()] && !changed[flow.owner.Addr().Unmap()] {
			continue
		}
		// A failed delete is not returned: the index leaves flows, and the
		// relay clears its kernel flow all the same, so the next sweep's
		// kernelSync finds it in the program as a stray and forgets it
		// again, and a second error ends the kernel path there.
		_ = k.in(func() error { return k.fwd.Delete(index) })
		delete(k.flows, index)
		forgotten = append(forgotten, index)
	}

	for ifindex, name := range k.attached {
		named := false
		for _, rt := range k.routes {
			if rt.ifindex == ifindex && rt.name == name {
				named = true
				break
			}
		}
		if !named {
			delete(k.attached, ifindex)
		}
	}

	return forgotten
}

// close detaches the program from every interface and frees it, then writes
// the IPv6 forwarding flag back to 0 when raiseIPv6Forwarding set it.
func (k *relayKernelLinux) close() error {
	var errs []error
	if err := k.in(k.fwd.Close); err != nil {
		errs = append(errs, fmt.Errorf("bridge: relay: kernel forwarding: %w", err))
	}
	if k.ipv6Raised {
		path := ipv6ForwardingPath(k.meshIface)
		if err := k.in(func() error { return k.writeFile(path, []byte("0")) }); err != nil {
			errs = append(errs, fmt.Errorf("bridge: relay: kernel forwarding: restore the ipv6 forwarding flag: %w", err))
		}
		k.ipv6Raised = false
	}
	return errors.Join(errs...)
}
