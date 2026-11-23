//go:build linux

package nettest

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The links and addresses of the topology NewMeshLAN builds. N is the node, P
// its mesh peer and L a host on another network N is attached to.
const (
	// MeshLink is N's end of the veth to P. It stands for the mesh
	// interface.
	MeshLink = "nt-mesh"
	// PeerLink is P's end of the veth to N.
	PeerLink = "nt-peer"
	// LANLink is N's end of the veth to L, the other network.
	LANLink = "nt-lan"
	// HostLink is L's end of the veth to N.
	HostLink = "nt-host"
	// NodeMeshIP is N's mesh IP, on MeshLink.
	NodeMeshIP = "10.98.0.1"
	// PeerMeshIP is P's mesh IP, on PeerLink.
	PeerMeshIP = "10.98.0.2"
	// NodeLANIP is N's address on LANLink.
	NodeLANIP = "192.0.2.1"
	// LANHostIP is L's own address, on HostLink.
	LANHostIP = "192.0.2.2"
	// LANMeshSource is a mesh address L holds on its loopback, so L can
	// send from a mesh source.
	LANMeshSource = "10.98.0.3"
	// MeshPrefix is the prefix of the mesh that N and P share.
	MeshPrefix = "10.98.0.0/24"
)

// Netns is a network namespace a test created. It goes away with its last
// handle, link end and socket.
type Netns struct {
	// Name names the namespace in failure messages.
	Name string
	ns   netns.NsHandle
	nl   *netlink.Handle
}

// onLockedThread runs fn on a new goroutine locked to its own thread and
// waits for its result. The goroutine never unlocks, so the runtime ends the
// thread with it and a thread fn moved into a namespace runs nothing else.
func onLockedThread(fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		errc <- fn()
	}()
	return <-errc
}

// NewNetns creates a network namespace and a netlink handle inside it, and
// stops the test when either fails. The test's cleanup closes both. name
// appears in failure messages only.
func NewNetns(t testing.TB, name string) *Netns {
	t.Helper()
	n := &Netns{Name: name}
	if err := onLockedThread(func() error {
		var err error
		n.ns, err = netns.New()
		return err
	}); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	t.Cleanup(func() { _ = n.ns.Close() })
	h, err := netlink.NewHandleAt(n.ns, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("open a netlink handle in namespace %s: %v", name, err)
	}
	n.nl = h
	t.Cleanup(h.Close)
	return n
}

// Do runs fn on a new thread inside the namespace and returns fn's error, so
// the sockets fn opens belong to the namespace.
func (n *Netns) Do(fn func() error) error {
	return onLockedThread(func() error {
		if err := netns.Set(n.ns); err != nil {
			return fmt.Errorf("enter namespace %s: %w", n.Name, err)
		}
		return fn()
	})
}

func (n *Netns) link(t testing.TB, name string) netlink.Link {
	t.Helper()
	link, err := n.nl.LinkByName(name)
	if err != nil {
		t.Fatalf("namespace %s: link %s: %v", n.Name, name, err)
	}
	return link
}

// Addr adds cidr to link and sets link up. It stops the test when either
// fails.
func (n *Netns) Addr(t testing.TB, link, cidr string) {
	t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	l := n.link(t, link)
	if err := n.nl.AddrAdd(l, addr); err != nil {
		t.Fatalf("namespace %s: add %s to %s: %v", n.Name, cidr, link, err)
	}
	if err := n.nl.LinkSetUp(l); err != nil {
		t.Fatalf("namespace %s: set %s up: %v", n.Name, link, err)
	}
}

// Route routes dst through the gateway gw on link. It stops the test when
// the route cannot be added.
func (n *Netns) Route(t testing.TB, link, dst, gw string) {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(dst)
	if err != nil {
		t.Fatalf("parse %s: %v", dst, err)
	}
	if err := n.nl.RouteAdd(&netlink.Route{
		LinkIndex: n.link(t, link).Attrs().Index,
		Dst:       ipNet,
		Gw:        net.ParseIP(gw),
	}); err != nil {
		t.Fatalf("namespace %s: route %s via %s: %v", n.Name, dst, gw, err)
	}
}

// Up sets link up. It stops the test when that fails.
func (n *Netns) Up(t testing.TB, link string) {
	t.Helper()
	if err := n.nl.LinkSetUp(n.link(t, link)); err != nil {
		t.Fatalf("namespace %s: set %s up: %v", n.Name, link, err)
	}
}

// Sysctl writes value to the IPv4 sysctl key inside the namespace, and stops
// the test when the write fails. key is the name below net.ipv4, such as
// conf.nt-lan.rp_filter, so it cannot name an interface whose name holds a
// dot. The write happens on a thread inside the namespace, which sees the
// namespace's own /proc/sys/net.
func (n *Netns) Sysctl(t testing.TB, key, value string) {
	t.Helper()
	path := "/proc/sys/net/ipv4/" + strings.ReplaceAll(key, ".", "/")
	if err := n.Do(func() error {
		return os.WriteFile(path, []byte(value), 0o644)
	}); err != nil {
		t.Fatalf("namespace %s: write %s to %s: %v", n.Name, value, path, err)
	}
}

// Veth creates a veth pair with aName in a and bName in b. Both ends stay
// down until Addr or Up sets them up.
func Veth(t testing.TB, a *Netns, aName string, b *Netns, bName string) {
	t.Helper()
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: aName},
		PeerName:      bName,
		PeerNamespace: netlink.NsFd(b.ns),
	}
	if err := a.nl.LinkAdd(veth); err != nil {
		t.Fatalf("add veth %s-%s: %v", aName, bName, err)
	}
}

// MeshLAN holds the namespaces NewMeshLAN builds.
type MeshLAN struct {
	Node, Peer, LANHost *Netns
}

// NewMeshLAN builds the namespaces of a node N that is attached to the mesh
// and to another network, a mesh peer P and a host L on the other network.
// The real tests of plexd's mesh listeners run a listener in N and show
// which of P's and L's packets reach it.
//
// N holds the mesh IP 10.98.0.1/24 on nt-mesh, a veth to P, which holds
// 10.98.0.2/24 on nt-peer and stands for the mesh. N also holds 192.0.2.1/24
// on nt-lan, a veth to L, which holds 192.0.2.2/24 on nt-host. L holds the
// mesh address 10.98.0.3 on its loopback and routes the mesh IP through N,
// and N routes 10.98.0.3 back to L. So what L sends to the mesh IP arrives
// on nt-lan, from L's own address and from the mesh source alike, and an
// answer to it returns to L. N's loopback is up: without it no client inside
// N reaches N's own addresses, the mesh IP included.
//
// The namespaces, links and addresses go away with the test.
func NewMeshLAN(t testing.TB) MeshLAN {
	t.Helper()
	n := NewNetns(t, "node")
	p := NewNetns(t, "peer")
	l := NewNetns(t, "lan-host")
	Veth(t, n, MeshLink, p, PeerLink)
	Veth(t, n, LANLink, l, HostLink)
	n.Addr(t, MeshLink, NodeMeshIP+"/24")
	n.Addr(t, LANLink, NodeLANIP+"/24")
	n.Up(t, "lo")
	p.Addr(t, PeerLink, PeerMeshIP+"/24")
	l.Addr(t, HostLink, LANHostIP+"/24")
	l.Addr(t, "lo", LANMeshSource+"/32")
	l.Route(t, HostLink, NodeMeshIP+"/32", NodeLANIP)
	n.Route(t, LANLink, LANMeshSource+"/32", LANHostIP)
	return MeshLAN{Node: n, Peer: p, LANHost: l}
}
