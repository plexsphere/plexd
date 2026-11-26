//go:build linux

package bridge

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nettest"
)

// The ports and names of TestRelayKernel_Real.
const (
	// rkRelayPort is the relay's listen port in R.
	rkRelayPort = 51821
	// rkNodePort is the listen port of wg0 on both nodes, and rkRoamPort
	// the one A moves to.
	rkNodePort = 51820
	rkRoamPort = 51830
	// rkMeshPort is the listen port of the mesh link in R. It is set so the
	// link does not take a random port, which could be the relay's.
	rkMeshPort = 51899
	// rkMeshLink is R's mesh interface, a WireGuard link as on a bridge.
	rkMeshLink = "rmesh"
	// rkAppPort is the port of the UDP sockets on the nodes' WireGuard
	// addresses, whose datagrams cross the mesh.
	rkAppPort = 7000
	// rkSize is the payload size of the datagrams of every phase but the
	// MTU phase.
	rkSize = 64
	// rkWait is how long a datagram may take to arrive.
	rkWait = 20 * time.Second
)

// rkNode is a node of TestRelayKernel_Real: a namespace with a kernel
// WireGuard link wg0 whose only peer is the other node, reached through the
// relay, and a UDP socket on its WireGuard address.
type rkNode struct {
	ns   *nettest.Netns
	id   string
	key  wgtypes.Key
	ip   netip.Addr
	conn *net.UDPConn
}

// rkConfigureWG applies cfg to wg0 in the namespace of the calling thread.
func rkConfigureWG(cfg wgtypes.Config) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice("wg0", cfg)
}

// rkNewNode creates wg0 with the address cidr in ns, listening on
// rkNodePort, and the node's UDP socket on that address.
func rkNewNode(t *testing.T, ns *nettest.Netns, id, cidr string) *rkNode {
	t.Helper()
	n := &rkNode{ns: ns, id: id, key: mustKey(t), ip: netip.MustParsePrefix(cidr).Addr()}
	port := rkNodePort
	if err := ns.Do(func() error {
		la := netlink.NewLinkAttrs()
		la.Name = "wg0"
		l := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}
		if err := netlink.LinkAdd(l); err != nil {
			return fmt.Errorf("add wg0: %w", err)
		}
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(l, addr); err != nil {
			return fmt.Errorf("add %s to wg0: %w", cidr, err)
		}
		if err := rkConfigureWG(wgtypes.Config{PrivateKey: &n.key, ListenPort: &port}); err != nil {
			return fmt.Errorf("configure wg0: %w", err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("set wg0 up: %w", err)
		}
		n.conn, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(n.ip, rkAppPort)))
		return err
	}); err != nil {
		t.Fatalf("namespace %s: node %s: %v", ns.Name, id, err)
	}
	t.Cleanup(func() { _ = n.conn.Close() })
	return n
}

// usePeer replaces the peers of n's wg0 with peer, reached at relay. A
// replaced peer has no session, so the next datagram starts a handshake at
// once instead of after WireGuard's rekey timeout.
func (n *rkNode) usePeer(t *testing.T, peer *rkNode, relay netip.AddrPort) {
	t.Helper()
	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:         peer.key.PublicKey(),
			Endpoint:          net.UDPAddrFromAddrPort(relay),
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{{IP: peer.ip.AsSlice(), Mask: net.CIDRMask(32, 32)}},
		}},
	}
	if err := n.ns.Do(func() error { return rkConfigureWG(cfg) }); err != nil {
		t.Fatalf("namespace %s: peer %s at %s: %v", n.ns.Name, peer.id, relay, err)
	}
}

// listenOn moves n's wg0 to port. Its session stays, so its next datagram
// reaches the relay from a new source, as after a NAT rebinding.
func (n *rkNode) listenOn(t *testing.T, port int) {
	t.Helper()
	if err := n.ns.Do(func() error { return rkConfigureWG(wgtypes.Config{ListenPort: &port}) }); err != nil {
		t.Fatalf("namespace %s: listen port %d: %v", n.ns.Name, port, err)
	}
}

// rkPayload returns datagram i of tag, padded to size bytes.
func rkPayload(tag string, i, size int) []byte {
	b := []byte(fmt.Sprintf("%s-%03d.", tag, i))
	for len(b) < size {
		b = append(b, '.')
	}
	return b
}

// rkSend sends count datagrams of tag and size from n to peer across the
// mesh.
func rkSend(t *testing.T, n, peer *rkNode, tag string, count, size int) {
	t.Helper()
	to := netip.AddrPortFrom(peer.ip, rkAppPort)
	for i := range count {
		if _, err := n.conn.WriteToUDPAddrPort(rkPayload(tag, i, size), to); err != nil {
			t.Fatalf("namespace %s: send %s %d to %s: %v", n.ns.Name, tag, i, to, err)
		}
	}
}

// rkExpect reads from n until count distinct datagrams of tag, each of size
// bytes, arrived, and fails the test when they do not within rkWait. A
// datagram of another tag is skipped.
func rkExpect(t *testing.T, n *rkNode, tag string, count, size int) {
	t.Helper()
	deadline := time.Now().Add(rkWait)
	got := make(map[string]bool, count)
	buf := make([]byte, 2048)
	for len(got) < count {
		if err := n.conn.SetReadDeadline(deadline); err != nil {
			t.Fatalf("namespace %s: set the read deadline: %v", n.ns.Name, err)
		}
		m, _, err := n.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("namespace %s: %d of %d datagrams %s arrived within %s: %v", n.ns.Name, len(got), count, tag, rkWait, err)
		}
		if !strings.HasPrefix(string(buf[:m]), tag+"-") {
			continue
		}
		if m != size {
			t.Fatalf("namespace %s: datagram %s of %d bytes, want %d", n.ns.Name, tag, m, size)
		}
		got[string(buf[:m])] = true
	}
}

// rkExchange sends count datagrams from a to b and waits for them, then
// count from b to a.
func rkExchange(t *testing.T, a, b *rkNode, tag string, count int) {
	t.Helper()
	rkSend(t, a, b, tag+"-ab", count, rkSize)
	rkExpect(t, b, tag+"-ab", count, rkSize)
	rkSend(t, b, a, tag+"-ba", count, rkSize)
	rkExpect(t, a, tag+"-ba", count, rkSize)
}

// rkConnect brings a and b into a session through a relay that knows the
// address of neither, and returns once a datagram arrived each way. The relay
// places a first initiation only by sending it to another initiator that is
// waiting (see Relay.fanout), so a's initiation has to wait at the relay
// before b starts its own. Only b's initiation reaches its target, so the two
// handshakes cannot collide.
func rkConnect(t *testing.T, a, b *rkNode, logs *relayLog, tag string) {
	t.Helper()
	waiting := logs.count("reason=no_route")
	rkSend(t, a, b, tag+"-first-ab", 1, rkSize)
	logs.waitFor(t, "reason=no_route", waiting+1)
	rkSend(t, b, a, tag+"-first-ba", 1, rkSize)
	rkExpect(t, a, tag+"-first-ba", 1, rkSize)
	rkExpect(t, b, tag+"-first-ab", 1, rkSize)
}

// rkRelay returns a relay whose socket is bound in rns, with the kernel path
// on rkMeshLink in rns when kernel is set, and its log, which the test
// prints when it fails. Its Stop runs on cleanup.
func rkRelay(t *testing.T, rns *nettest.Netns, kernel bool) (*Relay, *relayLog) {
	t.Helper()
	logger, logs := newRelayLogger()
	r := NewRelay(logger)
	r.listen = func(port int) (relayConn, error) {
		var conn relayConn
		err := rns.Do(func() error {
			var err error
			conn, err = r.listenUDP(port)
			return err
		})
		return conn, err
	}
	if kernel {
		r.meshIface = rkMeshLink
		r.newKernel = func(port int) (relayKernel, error) {
			return newRelayKernelLinux(port, rkMeshLink, r.logger, rns.Do)
		}
	}
	t.Cleanup(func() {
		_ = r.Stop()
		if t.Failed() {
			t.Logf("relay log (kernel path %t):\n%s", kernel, logs)
		}
	})
	return r, logs
}

// rkCounters returns the program's counters, read through the relay as its
// sweep reads them.
func rkCounters(t *testing.T, r *Relay) map[string]uint64 {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.kernelOn() {
		t.Fatalf("the relay forwards in the process, want the kernel path")
	}
	counters, err := r.run.kernel.counters()
	if err != nil {
		t.Fatalf("read the counters: %v", err)
	}
	return counters
}

// rkPrograms returns how many programs are attached at tcx ingress of the
// link name in ns.
func rkPrograms(t *testing.T, ns *nettest.Netns, name string) int {
	t.Helper()
	var n int
	if err := ns.Do(func() error {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		res, err := link.QueryPrograms(link.QueryOptions{Target: l.Attrs().Index, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			return err
		}
		n = len(res.Programs)
		return nil
	}); err != nil {
		t.Fatalf("namespace %s: query the tcx ingress programs of %s: %v", ns.Name, name, err)
	}
	return n
}

// rkSysctl returns the value of the sysctl file path in ns.
func rkSysctl(t *testing.T, ns *nettest.Netns, path string) string {
	t.Helper()
	var b []byte
	if err := ns.Do(func() error {
		var err error
		b, err = os.ReadFile(path)
		return err
	}); err != nil {
		t.Fatalf("namespace %s: read %s: %v", ns.Name, path, err)
	}
	return strings.TrimSpace(string(b))
}

// rkSetMTU sets the MTU of the link name in ns.
func rkSetMTU(t *testing.T, ns *nettest.Netns, name string, mtu int) {
	t.Helper()
	if err := ns.Do(func() error {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		return netlink.LinkSetMTU(l, mtu)
	}); err != nil {
		t.Fatalf("namespace %s: MTU %d on %s: %v", ns.Name, mtu, name, err)
	}
}

// rkAddr6 adds the IPv6 address cidr to the link name in ns without
// duplicate address detection, since a tentative address can be neither
// bound nor routed from.
func rkAddr6(t *testing.T, ns *nettest.Netns, name, cidr string) {
	t.Helper()
	if err := ns.Do(func() error {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return err
		}
		addr.Flags = unix.IFA_F_NODAD
		return netlink.AddrAdd(l, addr)
	}); err != nil {
		t.Fatalf("namespace %s: add %s to %s: %v", ns.Name, cidr, name, err)
	}
}

// rkMesh creates R's mesh interface, a WireGuard link, up, with IPv4
// forwarding on, as a bridge has it.
func rkMesh(t *testing.T, rns *nettest.Netns) {
	t.Helper()
	port := rkMeshPort
	if err := rns.Do(func() error {
		la := netlink.NewLinkAttrs()
		la.Name = rkMeshLink
		l := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}
		if err := netlink.LinkAdd(l); err != nil {
			return err
		}
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.ConfigureDevice(rkMeshLink, wgtypes.Config{ListenPort: &port}); err != nil {
			return err
		}
		return netlink.LinkSetUp(l)
	}); err != nil {
		t.Fatalf("namespace %s: mesh link %s: %v", rns.Name, rkMeshLink, err)
	}
	rns.Sysctl(t, "conf."+rkMeshLink+".forwarding", "1")
}

// rkEthtoolValue is struct ethtool_value of linux/ethtool.h, the argument of
// the ethtool commands that get or set one flag.
type rkEthtoolValue struct {
	cmd  uint32
	data uint32
}

// rkEthtoolIfreq is struct ifreq with a pointer in its union, as SIOCETHTOOL
// takes it. data is a pointer field, not bytes of the union, so the garbage
// collector sees it, as in the ifreqData of golang.org/x/sys/unix.
type rkEthtoolIfreq struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [unsafe.Sizeof(unix.Ifreq{}) - unix.IFNAMSIZ - unsafe.Sizeof(unsafe.Pointer(nil))]byte
}

// rkEthtool runs the ethtool command cmd with data on the link name, in the
// namespace of the calling thread, and returns the data the kernel wrote
// back.
func rkEthtool(name string, cmd, data uint32) (uint32, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	v := rkEthtoolValue{cmd: cmd, data: data}
	ifr := rkEthtoolIfreq{data: unsafe.Pointer(&v)}
	copy(ifr.name[:unix.IFNAMSIZ-1], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return 0, errno
	}
	return v.data, nil
}

// rkTxChecksumOff turns transmit checksum offload off on the links names in
// ns, as ethtool -K <name> tx off does, and checks that it is off.
//
// Kernel WireGuard sends its datagrams with the UDP checksum left to the
// device (CHECKSUM_PARTIAL): the field holds only the sum of the pseudo
// header, and whoever sends the datagram out completes it. A veth with the
// offload on hands such a datagram to its peer as it is, and the receiver
// takes the checksum for valid, so a checksum the program got wrong would go
// unnoticed. With the offload off on R's links, R completes the checksum of
// every datagram the program redirects out of them, and the node's stack
// verifies it and drops the datagram when it is wrong. A partner in a
// container or VM on a bridge host sends such datagrams through a veth or
// virtio-net, which is where a wrong update of a partial checksum shows.
func rkTxChecksumOff(t *testing.T, ns *nettest.Netns, names ...string) {
	t.Helper()
	for _, name := range names {
		var got uint32
		if err := ns.Do(func() error {
			if _, err := rkEthtool(name, unix.ETHTOOL_STXCSUM, 0); err != nil {
				return fmt.Errorf("set: %w", err)
			}
			var err error
			got, err = rkEthtool(name, unix.ETHTOOL_GTXCSUM, 0)
			if err != nil {
				return fmt.Errorf("get: %w", err)
			}
			return nil
		}); err != nil {
			t.Fatalf("namespace %s: tx checksum offload off on %s: %v", ns.Name, name, err)
		}
		if got != 0 {
			t.Fatalf("namespace %s: tx checksum offload on %s reads %d after switching it off, want 0", ns.Name, name, got)
		}
	}
}

// rkSwitch creates the Linux bridge name in ns without VLAN filtering, so it
// passes tagged frames as they are, adds the links named in ports to it and
// sets all of them up.
func rkSwitch(t *testing.T, ns *nettest.Netns, name string, ports ...string) {
	t.Helper()
	filtering := false
	if err := ns.Do(func() error {
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}, VlanFiltering: &filtering}
		if err := netlink.LinkAdd(br); err != nil {
			return fmt.Errorf("add bridge %s: %w", name, err)
		}
		for _, port := range ports {
			l, err := netlink.LinkByName(port)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetMaster(l, br); err != nil {
				return fmt.Errorf("add %s to %s: %w", port, name, err)
			}
			if err := netlink.LinkSetUp(l); err != nil {
				return fmt.Errorf("set %s up: %w", port, err)
			}
		}
		return netlink.LinkSetUp(br)
	}); err != nil {
		t.Fatalf("namespace %s: switch %s: %v", ns.Name, name, err)
	}
}

// rkVLAN creates the VLAN link name with the VLAN id on the link parent in
// ns.
func rkVLAN(t *testing.T, ns *nettest.Netns, parent, name string, id int) {
	t.Helper()
	if err := ns.Do(func() error {
		p, err := netlink.LinkByName(parent)
		if err != nil {
			return err
		}
		return netlink.LinkAdd(&netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{Name: name, ParentIndex: p.Attrs().Index},
			VlanId:    id,
		})
	}); err != nil {
		t.Fatalf("namespace %s: VLAN %d on %s: %v", ns.Name, id, parent, err)
	}
}

// TestRelayKernel_Real proves on a real kernel that the relay's eBPF program
// forwards the transport datagrams of a session the relay placed, and passes
// to the process what it must not forward. Two nodes, A and B, hold kernel
// WireGuard links and reach each other only through a relay in namespace R:
//
//	A: wg0 10.9.0.1, va 10.1.0.2 fd01::2 -- R: ra 10.1.0.1 fd01::1
//	                                         rb 10.2.0.1 fd02::1 -- B: vb 10.2.0.2 fd02::2, wg0 10.9.0.2
//
// R has IPv4 and IPv6 forwarding off, so it does not route between A and B,
// and a WireGuard link rmesh as its mesh interface with IPv4 forwarding on,
// as a bridge has it. The Relay comes from NewRelay; its socket is bound in R
// and its kernel path is newRelayKernelLinux with R's Do, so every netlink
// call, bpf call and sysctl access lands in R. A UDP socket on each node's
// WireGuard address sends the datagrams across the mesh. Transmit checksum
// offload is off on R's links, so R completes the UDP checksum of every
// datagram the program forwards and the nodes verify it (see
// rkTxChecksumOff).
//
// The phases run in order:
//
//  1. A relay without a kernel path connects the pair and leaves no program
//     on ra or rb: the control.
//  2. A relay with the kernel path connects the pair, and the program
//     forwards 20 further datagrams each way. It attached to ra and rb, and
//     the relay counts one active pair.
//  3. A moves to another listen port. Its next datagram misses its entry
//     and reaches the process, which learns the new address and installs the
//     session again, and the program forwards again.
//  4. With the link towards B at 1,400 bytes, the route lookup refuses a
//     datagram that carries a 1,420-byte packet, and the process sends it.
//  5. With forwarding off on rmesh, the route lookup refuses every datagram
//     and the process forwards them all.
//  6. After the relay forgot both nodes, they dial it over IPv6, and the
//     program forwards over IPv6, with the IPv6 forwarding flag of rmesh at
//     1 while the relay runs.
//  7. Stop detaches the program from ra and rb and writes the flag back to
//     0.
//  8. A new relay serves two more nodes through a switch, A2 untagged and B2
//     in VLAN 100, so the program is attached to rs and to rs.100, and B2's
//     datagrams meet it first at rs, tagged. The program forwards 20
//     datagrams each way.
//
// The switch S of phase 8 is a Linux bridge without VLAN filtering, which
// passes tagged frames as they are, and R joins it on rs:
//
//	A2: wg0 10.9.2.1, va2 10.4.0.2 -- S -- R: rs 10.4.0.1, rs.100 10.5.0.1
//	B2: wg0 10.9.2.2, vb2.100 10.5.0.2 -- S
//
// The namespaces are created for the test alone. The gate is a variable
// besides the effective uid, as for TestNetlinkVPNController_RealLinks, and
// CI runs it in the step "Run privileged Linux tests".
func TestRelayKernel_Real(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to load the relay's eBPF program in test network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating network namespaces, WireGuard links and eBPF programs needs root; run with sudo")
	}

	ans := nettest.NewNetns(t, "node-a")
	rns := nettest.NewNetns(t, "relay")
	bns := nettest.NewNetns(t, "node-b")
	nettest.Veth(t, ans, "va", rns, "ra")
	nettest.Veth(t, rns, "rb", bns, "vb")
	ans.Addr(t, "va", "10.1.0.2/24")
	rns.Addr(t, "ra", "10.1.0.1/24")
	rns.Addr(t, "rb", "10.2.0.1/24")
	bns.Addr(t, "vb", "10.2.0.2/24")
	rkAddr6(t, ans, "va", "fd01::2/64")
	rkAddr6(t, rns, "ra", "fd01::1/64")
	rkAddr6(t, rns, "rb", "fd02::1/64")
	rkAddr6(t, bns, "vb", "fd02::2/64")
	ans.Route(t, "va", "0.0.0.0/0", "10.1.0.1")
	ans.Route(t, "va", "::/0", "fd01::1")
	bns.Route(t, "vb", "0.0.0.0/0", "10.2.0.1")
	bns.Route(t, "vb", "::/0", "fd02::1")
	rkTxChecksumOff(t, rns, "ra", "rb")

	// A new namespace takes its IPv4 settings from the host's initial one,
	// so on a host that forwards, as one running Docker does, R would
	// forward too. Writing conf.all.forwarding sets ip_forward and the flag
	// of every link, so it runs before the mesh link exists, whose own flag
	// is set after.
	rns.Sysctl(t, "conf.all.forwarding", "0")
	rkMesh(t, rns)
	// Go decides once per process whether a wildcard listener can be
	// dual-stack, by binding 127.0.0.1 through an IPv6 socket in the
	// namespace of the first such listener. In R that is the relay's, and a
	// new namespace holds 127.0.0.1 only once its loopback link is up.
	// Without it the relay would listen on IPv4 alone.
	rns.Up(t, "lo")
	for path, want := range map[string]string{
		"/proc/sys/net/ipv4/ip_forward":                         "0",
		"/proc/sys/net/ipv4/conf/ra/forwarding":                 "0",
		"/proc/sys/net/ipv4/conf/rb/forwarding":                 "0",
		"/proc/sys/net/ipv4/conf/" + rkMeshLink + "/forwarding": "1",
		"/proc/sys/net/ipv6/conf/all/forwarding":                "0",
		ipv6ForwardingPath(rkMeshLink):                          "0",
	} {
		if got := rkSysctl(t, rns, path); got != want {
			t.Fatalf("namespace %s: %s = %s, want %s", rns.Name, path, got, want)
		}
	}

	a := rkNewNode(t, ans, "node-a", "10.9.0.1/24")
	b := rkNewNode(t, bns, "node-b", "10.9.0.2/24")
	peers := []api.SnapshotPeer{
		{NodeID: a.id, PublicKey: a.key.PublicKey().String()},
		{NodeID: b.id, PublicKey: b.key.PublicKey().String()},
	}
	relayA4 := netip.MustParseAddrPort("10.1.0.1:51821")
	relayB4 := netip.MustParseAddrPort("10.2.0.1:51821")
	relayA6 := netip.MustParseAddrPort("[fd01::1]:51821")
	relayB6 := netip.MustParseAddrPort("[fd02::1]:51821")

	// Phase 1: the control, a relay that forwards in the process.
	control, controlLogs := rkRelay(t, rns, false)
	if err := control.Configure(rkRelayPort, peers); err != nil {
		t.Fatalf("control: Configure: %v", err)
	}
	if got := control.ListenAddr().String(); got != "[::]:51821" {
		t.Fatalf("control: the relay listens on %s, want [::]:51821 for IPv4 and IPv6", got)
	}
	a.usePeer(t, b, relayA4)
	b.usePeer(t, a, relayB4)
	rkConnect(t, a, b, controlLogs, "control")
	rkExchange(t, a, b, "control", 20)
	for _, name := range []string{"ra", "rb"} {
		if n := rkPrograms(t, rns, name); n != 0 {
			t.Fatalf("control: %d programs at tcx ingress of %s, want none", n, name)
		}
	}
	if err := control.Stop(); err != nil {
		t.Fatalf("control: Stop: %v", err)
	}
	if strings.Contains(controlLogs.String(), "kernel forwarding") {
		t.Fatalf("control: the relay without a kernel path logged about one:\n%s", controlLogs)
	}

	// Phase 2: the kernel path over IPv4.
	r, logs := rkRelay(t, rns, true)
	if err := r.Configure(rkRelayPort, peers); err != nil {
		t.Fatalf("kernel: Configure: %v", err)
	}
	if !integLogged(logs.String(), "relay: kernel forwarding started", "listen_port=51821", "mesh_interface="+rkMeshLink) {
		t.Fatalf(`kernel: no "relay: kernel forwarding started" line with listen_port=51821 mesh_interface=%s:%s`, rkMeshLink, logs)
	}
	if got := rkSysctl(t, rns, ipv6ForwardingPath(rkMeshLink)); got != "1" {
		t.Fatalf("kernel: the IPv6 forwarding flag of %s = %s while the relay runs, want 1", rkMeshLink, got)
	}
	a.usePeer(t, b, relayA4)
	b.usePeer(t, a, relayB4)
	rkConnect(t, a, b, logs, "kernel")
	rkExchange(t, a, b, "kernel", 20)
	kernel := rkCounters(t, r)
	t.Logf("kernel path: counters %v", kernel)
	if kernel["forwarded"] < 40 {
		t.Fatalf("kernel: forwarded = %d after 20 datagrams each way, want at least 40", kernel["forwarded"])
	}
	if n := r.ActiveCount(); n != 1 {
		t.Fatalf("kernel: ActiveCount() = %d, want 1", n)
	}
	for _, name := range []string{"ra", "rb"} {
		if !integLogged(logs.String(), "relay: kernel forwarding attached", "interface="+name) {
			t.Fatalf(`kernel: no "relay: kernel forwarding attached" line with interface=%s:%s`, name, logs)
		}
		if n := rkPrograms(t, rns, name); n != 1 {
			t.Fatalf("kernel: %d programs at tcx ingress of %s, want 1", n, name)
		}
	}

	// Phase 3: A roams to another port. Its first datagram misses its
	// entry, and the relay installs both sessions again while it forwards
	// the first datagram each way, before they arrive. Datagrams sent before
	// that pass to the process as well, so the 20 each way follow only
	// then.
	a.listenOn(t, rkRoamPort)
	rkExchange(t, a, b, "roam-first", 1)
	rkExchange(t, a, b, "roam", 20)
	roam := rkCounters(t, r)
	t.Logf("roam: counters %v", roam)
	if roam["mismatch"] < kernel["mismatch"]+1 {
		t.Fatalf("roam: mismatch = %d, want at least %d", roam["mismatch"], kernel["mismatch"]+1)
	}
	if roam["forwarded"] < kernel["forwarded"]+40 {
		t.Fatalf("roam: forwarded = %d after 20 datagrams each way, want at least %d", roam["forwarded"], kernel["forwarded"]+40)
	}
	roamed := netip.AddrPortFrom(netip.MustParseAddr("10.1.0.2"), rkRoamPort).String()
	if !integLogged(logs.String(), "relay: peer address learned", "peer_id="+a.id, "address="+roamed) {
		t.Fatalf(`roam: no "relay: peer address learned" line with peer_id=%s address=%s:%s`, a.id, roamed, logs)
	}

	// Phase 4: the link towards B carries 1,400 bytes. A 1,392-byte payload
	// makes a 1,420-byte packet, which fills wg0, and WireGuard sends it in
	// a datagram of 1,480 bytes, more than rb takes.
	rkSetMTU(t, rns, "rb", 1400)
	rkSetMTU(t, bns, "vb", 1400)
	rkSend(t, a, b, "mtu", 1, 1392)
	rkExpect(t, b, "mtu", 1, 1392)
	mtu := rkCounters(t, r)
	t.Logf("mtu: counters %v", mtu)
	if mtu["fib_frag_needed"] <= roam["fib_frag_needed"] {
		t.Fatalf("mtu: fib_frag_needed = %d, want more than %d", mtu["fib_frag_needed"], roam["fib_frag_needed"])
	}
	rkSetMTU(t, rns, "rb", 1500)
	rkSetMTU(t, bns, "vb", 1500)

	// Phase 5: forwarding off on the mesh interface.
	rns.Sysctl(t, "conf."+rkMeshLink+".forwarding", "0")
	rkExchange(t, a, b, "fwd-off", 20)
	off := rkCounters(t, r)
	t.Logf("forwarding off: counters %v", off)
	if off["fib_fwd_disabled"] <= mtu["fib_fwd_disabled"] {
		t.Fatalf("forwarding off: fib_fwd_disabled = %d, want more than %d", off["fib_fwd_disabled"], mtu["fib_fwd_disabled"])
	}
	if off["forwarded"] != mtu["forwarded"] {
		t.Fatalf("forwarding off: forwarded = %d, want %d as before", off["forwarded"], mtu["forwarded"])
	}
	rns.Sysctl(t, "conf."+rkMeshLink+".forwarding", "1")

	// Phase 6: IPv6. The relay forgets both nodes first: it would otherwise
	// send A's initiation to B's IPv4 address, which it holds as fresh, and
	// the session would mix the families.
	if err := r.Configure(rkRelayPort, nil); err != nil {
		t.Fatalf("ipv6: Configure without peers: %v", err)
	}
	if err := r.Configure(rkRelayPort, peers); err != nil {
		t.Fatalf("ipv6: Configure: %v", err)
	}
	a.usePeer(t, b, relayA6)
	b.usePeer(t, a, relayB6)
	rkConnect(t, a, b, logs, "ipv6")
	rkExchange(t, a, b, "ipv6", 20)
	ipv6 := rkCounters(t, r)
	t.Logf("ipv6: counters %v", ipv6)
	if ipv6["forwarded"] < off["forwarded"]+40 {
		t.Fatalf("ipv6: forwarded = %d after 20 datagrams each way, want at least %d", ipv6["forwarded"], off["forwarded"]+40)
	}
	if got := rkSysctl(t, rns, ipv6ForwardingPath(rkMeshLink)); got != "1" {
		t.Fatalf("ipv6: the IPv6 forwarding flag of %s = %s while the relay runs, want 1", rkMeshLink, got)
	}
	overIPv6 := netip.AddrPortFrom(netip.MustParseAddr("fd01::2"), rkRoamPort).String()
	if !integLogged(logs.String(), "relay: peer address learned", "peer_id="+a.id, "address="+overIPv6) {
		t.Fatalf(`ipv6: no "relay: peer address learned" line with peer_id=%s address=%s:%s`, a.id, overIPv6, logs)
	}

	// Phase 7: Stop.
	if err := r.Stop(); err != nil {
		t.Fatalf("stop: Stop: %v", err)
	}
	if got := rkSysctl(t, rns, ipv6ForwardingPath(rkMeshLink)); got != "0" {
		t.Fatalf("stop: the IPv6 forwarding flag of %s = %s after Stop, want 0", rkMeshLink, got)
	}
	for _, name := range []string{"ra", "rb"} {
		if n := rkPrograms(t, rns, name); n != 0 {
			t.Fatalf("stop: %d programs at tcx ingress of %s after Stop, want none", n, name)
		}
	}

	// Phase 8: a VLAN. The kernel moves the tag of B2's datagrams into the
	// skb's metadata before tcx ingress of rs, where the program is attached
	// for A2, and they match B2's entry there. Redirected from rs, they
	// would leave tagged and A2 would drop them; passed, they reach rs.100
	// untagged and the program forwards them from there.
	sns := nettest.NewNetns(t, "switch")
	a2ns := nettest.NewNetns(t, "node-a2")
	b2ns := nettest.NewNetns(t, "node-b2")
	nettest.Veth(t, rns, "rs", sns, "sr")
	nettest.Veth(t, a2ns, "va2", sns, "sa2")
	nettest.Veth(t, b2ns, "vb2", sns, "sb2")
	rkSwitch(t, sns, "br0", "sr", "sa2", "sb2")
	rkTxChecksumOff(t, rns, "rs")
	rns.Addr(t, "rs", "10.4.0.1/24")
	rkVLAN(t, rns, "rs", "rs.100", 100)
	rns.Addr(t, "rs.100", "10.5.0.1/24")
	a2ns.Addr(t, "va2", "10.4.0.2/24")
	b2ns.Up(t, "vb2")
	rkVLAN(t, b2ns, "vb2", "vb2.100", 100)
	b2ns.Addr(t, "vb2.100", "10.5.0.2/24")
	a2 := rkNewNode(t, a2ns, "node-a2", "10.9.2.1/24")
	b2 := rkNewNode(t, b2ns, "node-b2", "10.9.2.2/24")

	vlan, vlanLogs := rkRelay(t, rns, true)
	if err := vlan.Configure(rkRelayPort, []api.SnapshotPeer{
		{NodeID: a2.id, PublicKey: a2.key.PublicKey().String()},
		{NodeID: b2.id, PublicKey: b2.key.PublicKey().String()},
	}); err != nil {
		t.Fatalf("vlan: Configure: %v", err)
	}
	a2.usePeer(t, b2, netip.MustParseAddrPort("10.4.0.1:51821"))
	b2.usePeer(t, a2, netip.MustParseAddrPort("10.5.0.1:51821"))
	rkConnect(t, a2, b2, vlanLogs, "vlan")
	rkExchange(t, a2, b2, "vlan", 20)
	tagged := rkCounters(t, vlan)
	t.Logf("vlan: counters %v", tagged)
	if tagged["forwarded"] < 40 {
		t.Fatalf("vlan: forwarded = %d after 20 datagrams each way, want at least 40", tagged["forwarded"])
	}
	for _, name := range []string{"rs", "rs.100"} {
		if !integLogged(vlanLogs.String(), "relay: kernel forwarding attached", "interface="+name) {
			t.Fatalf(`vlan: no "relay: kernel forwarding attached" line with interface=%s:%s`, name, vlanLogs)
		}
		if n := rkPrograms(t, rns, name); n != 1 {
			t.Fatalf("vlan: %d programs at tcx ingress of %s, want 1", n, name)
		}
	}
}
