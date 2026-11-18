//go:build linux

package bridge

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testS2SIface is a name no link of the host carries, for the cases that are
// refused before a link is added.
const testS2SIface = "plexd-s2stest0"

// wantNoLink fails the test when a link named name exists. Looking a link up
// needs no privileges.
func wantNoLink(t *testing.T, name string) {
	t.Helper()

	_, err := netlink.LinkByName(name)
	if err == nil {
		t.Errorf("link %s exists, want none", name)
		return
	}
	if _, ok := err.(netlink.LinkNotFoundError); !ok {
		t.Errorf("LinkByName(%q) error = %v, want LinkNotFoundError", name, err)
	}
}

// A malformed key is refused before the link is added, so the cases need no
// privileges and leave no kernel state behind. Without privileges an added
// link would fail with the create error instead, so the parse error is what
// proves the order.
func TestNetlinkVPNController_CreateTunnelInterfaceInvalidKey(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		c := NewNetlinkVPNController(discardLogger())

		wantWGErrPrefix(t, c.CreateTunnelInterface(testS2SIface, key, testVPNPort), "bridge: vpn: parse private key:")
		wantNoLink(t, testS2SIface)
	}
}

// strongSwan binds a connection to an xfrm interface by a non-zero id, so id 0
// is refused before the link is added.
func TestNetlinkVPNController_CreateXfrmInterfaceZeroID(t *testing.T) {
	c := NewNetlinkVPNController(discardLogger())

	err := c.CreateXfrmInterface(testS2SIface, 0)
	wantWGErrPrefix(t, err, "bridge: vpn: create xfrm interface plexd-s2stest0: interface id 0 binds no connection")
	wantNoLink(t, testS2SIface)
}

// An empty list would sweep nothing a caller meant, and an empty prefix would
// match the mesh interface and every user access interface, so both are
// refused before any link is listed.
func TestNetlinkVPNController_RemoveTunnelInterfacesRefused(t *testing.T) {
	tests := []struct {
		name       string
		prefixes   []string
		wantPrefix string
	}{
		{name: "nil list", prefixes: nil, wantPrefix: "bridge: vpn: remove tunnel interfaces: no prefix"},
		{name: "empty list", prefixes: []string{}, wantPrefix: "bridge: vpn: remove tunnel interfaces: no prefix"},
		{name: "empty prefix", prefixes: []string{SiteToSiteWireGuardPrefix, ""}, wantPrefix: "bridge: vpn: remove tunnel interfaces: empty prefix"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewNetlinkVPNController(discardLogger())

			wantWGErrPrefix(t, c.RemoveTunnelInterfaces(tt.prefixes), tt.wantPrefix)
		})
	}
}

// Listing links needs no privileges. Prefixes no link carries delete nothing
// and succeed, which is what a start finds after a clean shutdown.
func TestNetlinkVPNController_RemoveTunnelInterfacesNoMatch(t *testing.T) {
	c := NewNetlinkVPNController(discardLogger())

	if err := c.RemoveTunnelInterfaces([]string{"plexd-nolink-", "plexd-nolink2-"}); err != nil {
		t.Fatalf("RemoveTunnelInterfaces() error = %v, want nil", err)
	}
}

// The sweep takes the three kinds of site-to-site link under one of its
// prefixes and nothing else: not a link of another type under a prefix, and
// not a WireGuard interface under another name, which may be the mesh
// interface or a user access interface.
func TestTunnelLinkMatch(t *testing.T) {
	attrs := func(name string) netlink.LinkAttrs {
		la := netlink.NewLinkAttrs()
		la.Name = name
		return la
	}

	tests := []struct {
		name string
		link netlink.Link
		want bool
	}{
		{name: "wireguard", link: &netlink.Wireguard{LinkAttrs: attrs("wg-s2s-a0a0a0e1")}, want: true},
		{name: "wireguard as generic link", link: &netlink.GenericLink{LinkAttrs: attrs("wg-s2s-a0a0a0e1"), LinkType: "wireguard"}, want: true},
		{name: "xfrm", link: &netlink.Xfrmi{LinkAttrs: attrs("xf-s2s-a0a0a0e2")}, want: true},
		{name: "tun", link: &netlink.Tuntap{LinkAttrs: attrs("ov-s2s-a0a0a0e3")}, want: true},
		{name: "kind under another kind's prefix", link: &netlink.Xfrmi{LinkAttrs: attrs("wg-s2s-a0a0a0e2")}, want: true},
		{name: "dummy under a prefix", link: &netlink.Dummy{LinkAttrs: attrs("wg-s2s-a0a0a0e4")}, want: false},
		{name: "mesh interface", link: &netlink.Wireguard{LinkAttrs: attrs("plexd0")}, want: false},
		{name: "user access interface", link: &netlink.Wireguard{LinkAttrs: attrs(UserAccessInterfacePrefix + "a0a0a0e1")}, want: false},
		{name: "other wireguard interface", link: &netlink.Wireguard{LinkAttrs: attrs("wg-other0")}, want: false},
	}

	match := tunnelLinkMatch(SiteToSiteInterfacePrefixes)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := match(tt.link); got != tt.want {
				t.Errorf("match(%s %q) = %v, want %v", tt.link.Type(), tt.link.Attrs().Name, got, tt.want)
			}
		})
	}
}

// The prefixes are what the interface names and the sweep rest on: one per
// kind, in the order wireguard, ipsec, openvpn, and a name of a prefix and 8
// hex digits fits the kernel's 15 characters.
func TestSiteToSiteInterfacePrefixes(t *testing.T) {
	want := []string{"wg-s2s-", "xf-s2s-", "ov-s2s-"}
	if len(SiteToSiteInterfacePrefixes) != len(want) {
		t.Fatalf("SiteToSiteInterfacePrefixes = %q, want %q", SiteToSiteInterfacePrefixes, want)
	}
	for i, prefix := range SiteToSiteInterfacePrefixes {
		if prefix != want[i] {
			t.Errorf("SiteToSiteInterfacePrefixes[%d] = %q, want %q", i, prefix, want[i])
		}
		if n := len(prefix + "a0a0a0e1"); n > unix.IFNAMSIZ-1 {
			t.Errorf("a name under %q has %d characters, want at most %d", prefix, n, unix.IFNAMSIZ-1)
		}
	}
}

func TestNetlinkVPNController_TunnelPeerHandshakeInvalidKey(t *testing.T) {
	tests := []struct {
		name, publicKey, wantPrefix string
	}{
		{name: "not base64", publicKey: "!!!", wantPrefix: "bridge: vpn: decode public key:"},
		{name: "empty", publicKey: "", wantPrefix: "bridge: vpn: parse public key:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewNetlinkVPNController(discardLogger())

			got, err := c.TunnelPeerHandshake(testS2SIface, tt.publicKey)
			wantWGErrPrefix(t, err, tt.wantPrefix)
			if !got.IsZero() {
				t.Errorf("TunnelPeerHandshake() = %v, want the zero time on error", got)
			}
		})
	}
}

// inOwnNetns runs fn on the test's own goroutine, locked to its thread and
// that thread moved into a fresh network namespace, so every link fn creates
// lands in that namespace and goes with it rather than among the host's
// links, which may include a live plexd's. netlink, wgctrl and /dev/net/tun
// act in the namespace of the thread that opens their socket or descriptor,
// which is this one. Running fn on the test goroutine keeps t.Fatal inside fn
// legal; the namespace is left in a deferred call, which runs on that path
// too.
//
// A goroutine fn starts runs on another thread and so in the original
// namespace. t.Run starts one, so fn must not run subtests.
func inOwnNetns(t *testing.T, fn func()) {
	t.Helper()

	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("open this thread's network namespace: %v", err)
	}
	// unshare(2) rather than netns.New, which also opens the new namespace:
	// nothing needs a handle to it, and a failed open would leave the thread
	// inside it with no way to tell.
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		// The thread is still where it was.
		_ = orig.Close()
		runtime.UnlockOSThread()
		t.Fatalf("create a network namespace: %v", err)
	}
	defer func() {
		err := netns.Set(orig)
		_ = orig.Close()
		if err != nil {
			// The goroutine stays locked, and the runtime ends a thread whose
			// goroutine exits locked, so nothing else runs in the namespace.
			t.Errorf("return to the original network namespace: %v", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	fn()
}

// mustLink returns the link named name, failing the test when there is none.
func mustLink(t *testing.T, name string) netlink.Link {
	t.Helper()

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName(%q): %v", name, err)
	}
	return link
}

// mustKey returns a generated WireGuard private key.
func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return key
}

// The names and ports of TestNetlinkVPNController_RealLinks. The namespace is
// the test's own, so nothing else holds them.
const (
	realXfrmName  = "xf-s2s-a0a0a0e2"
	realXfrmID    = 2694881506 // 0xa0a0a0e2, the last 8 hex digits of the name
	realTunName   = "ov-s2s-a0a0a0e3"
	realWGName    = "wg-s2s-a0a0a1e1"
	realWGPort    = 51930
	realDupName   = "wg-s2s-a0a0a1e2"
	realPeerName  = "wg-s2s-a0a0a1e3"
	realPeerPort  = 51931
	realOtherName = "wg-other0"
)

// TestNetlinkVPNController_RealLinks drives NetlinkVPNController against the
// kernel in a network namespace of its own: the xfrm interface of an ipsec
// tunnel, the tun device of an openvpn tunnel and the WireGuard interface of
// a wireguard tunnel with the key it is given, a listen port another
// interface holds, the handshake read and the sweep a start runs. The
// fake-based tests pin which calls the manager makes; this is the only test
// that proves netlink creates the links as ip link add ... type xfrm dev lo
// if_id and ip tuntap add ... mode tun did when the tunnels were measured.
//
// The steps run in order on the test goroutine, without subtests, since a
// subtest would run in the original namespace (see inOwnNetns).
//
// The gate is a variable besides the effective uid, as for
// TestNftablesController_Real: sudo go test ./... on a developer's machine
// should not create namespaces and links unasked. CI runs it in the step
// "Run privileged Linux tests".
func TestNetlinkVPNController_RealLinks(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to create real tunnel links in a test network namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating a network namespace and links needs root; run with sudo")
	}

	inOwnNetns(t, func() {
		c := NewNetlinkVPNController(discardLogger())

		// The handshake step runs over 127.0.0.1, which a fresh namespace
		// holds on a loopback link that is down; a host's is up.
		lo := mustLink(t, "lo")
		if err := netlink.LinkSetUp(lo); err != nil {
			t.Fatalf("set lo up: %v", err)
		}

		realXfrmInterface(t, c, lo.Attrs().Index)
		realTunDevice(t, c)
		key := realWireGuardKeptKey(t, c)
		realListenPortInUse(t, c)
		realPeerHandshake(t, c, key)
		realSweep(t, c)
	})
}

// realXfrmInterface creates the xfrm interface of an ipsec tunnel and wants
// it of type xfrm, with its id, the loopback link as parent and up. A second
// create under the name fails with os.ErrExist and keeps the interface.
func realXfrmInterface(t *testing.T, c *NetlinkVPNController, loIndex int) {
	t.Helper()

	if err := c.CreateXfrmInterface(realXfrmName, realXfrmID); err != nil {
		t.Fatalf("CreateXfrmInterface: %v", err)
	}

	link := mustLink(t, realXfrmName)
	if got := link.Type(); got != "xfrm" {
		t.Fatalf("type of %s = %q, want xfrm", realXfrmName, got)
	}
	xfrm := link.(*netlink.Xfrmi)
	if xfrm.Ifid != realXfrmID {
		t.Errorf("if_id of %s = %d, want %d", realXfrmName, xfrm.Ifid, uint32(realXfrmID))
	}
	if xfrm.ParentIndex != loIndex {
		t.Errorf("parent index of %s = %d, want %d, the loopback link", realXfrmName, xfrm.ParentIndex, loIndex)
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Errorf("%s is down, want up", realXfrmName)
	}

	if err := c.CreateXfrmInterface(realXfrmName, realXfrmID); !errors.Is(err, os.ErrExist) {
		t.Errorf("second CreateXfrmInterface error = %v, want one wrapping os.ErrExist", err)
	}
	mustLink(t, realXfrmName)
}

// realTunDevice creates the tun device of an openvpn tunnel and wants it of
// type tuntap, persistent, in tun mode without packet information and up. It
// also proves what the doc comment says about a name that is taken: a tun
// device no process holds is taken over, while the name of a link of another
// kind fails and the link keeps it.
func realTunDevice(t *testing.T, c *NetlinkVPNController) {
	t.Helper()

	if err := c.CreateTunInterface(realTunName); err != nil {
		t.Fatalf("CreateTunInterface: %v", err)
	}

	link := mustLink(t, realTunName)
	if got := link.Type(); got != "tuntap" {
		t.Fatalf("type of %s = %q, want tuntap", realTunName, got)
	}
	tun := link.(*netlink.Tuntap)
	if tun.NonPersist {
		t.Errorf("%s is not persistent, want the persist flag set", realTunName)
	}
	if tun.Mode != netlink.TUNTAP_MODE_TUN {
		t.Errorf("mode of %s = %v, want tun", realTunName, tun.Mode)
	}
	if tun.Flags&netlink.TUNTAP_NO_PI == 0 {
		t.Errorf("flags of %s = %#x, want no packet information", realTunName, tun.Flags)
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Errorf("%s is down, want up", realTunName)
	}

	if err := c.CreateTunInterface(realTunName); err != nil {
		t.Errorf("CreateTunInterface over the persistent %s: %v, want it taken over", realTunName, err)
	}
	if err := c.CreateTunInterface(realXfrmName); err == nil {
		t.Errorf("CreateTunInterface(%q) over the xfrm interface = nil, want an error", realXfrmName)
	}
	if got := mustLink(t, realXfrmName).Type(); got != "xfrm" {
		t.Errorf("type of %s after the refused create = %q, want xfrm", realXfrmName, got)
	}
}

// realWireGuardKeptKey creates the WireGuard interface of a wireguard tunnel
// and wants the device to carry the key it was given, so its public key is
// the one the remote site was configured with, and the listen port. It
// returns the key.
func realWireGuardKeptKey(t *testing.T, c *NetlinkVPNController) wgtypes.Key {
	t.Helper()

	key := mustKey(t)
	if err := c.CreateTunnelInterface(realWGName, key[:], realWGPort); err != nil {
		t.Fatalf("CreateTunnelInterface: %v", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		t.Fatalf("wgctrl.New: %v", err)
	}
	defer client.Close()

	dev, err := client.Device(realWGName)
	if err != nil {
		t.Fatalf("Device(%q): %v", realWGName, err)
	}
	if dev.PrivateKey != key {
		t.Errorf("private key of %s differs from the key passed to CreateTunnelInterface", realWGName)
	}
	if dev.PublicKey != key.PublicKey() {
		t.Errorf("public key of %s differs from the public key of the key passed in", realWGName)
	}
	if dev.ListenPort != realWGPort {
		t.Errorf("listen port of %s = %d, want %d", realWGName, dev.ListenPort, realWGPort)
	}
	if mustLink(t, realWGName).Attrs().Flags&net.FlagUp == 0 {
		t.Errorf("%s is down, want up", realWGName)
	}

	return key
}

// realListenPortInUse creates a second WireGuard interface on the port of
// the first and wants an error wrapping ErrListenPortInUse and the kernel's
// EADDRINUSE, and no link left behind.
func realListenPortInUse(t *testing.T, c *NetlinkVPNController) {
	t.Helper()

	dupKey := mustKey(t)
	err := c.CreateTunnelInterface(realDupName, dupKey[:], realWGPort)
	if !errors.Is(err, ErrListenPortInUse) {
		t.Errorf("CreateTunnelInterface on the port of %s error = %v, want one wrapping ErrListenPortInUse", realWGName, err)
	}
	if !errors.Is(err, unix.EADDRINUSE) {
		t.Errorf("CreateTunnelInterface on the port of %s error = %v, want the kernel's EADDRINUSE wrapped", realWGName, err)
	}
	wantNoLink(t, realDupName)
}

// realPeerHandshake gives the interface of realWireGuardKeptKey a second
// interface as its peer over the loopback link and wants TunnelPeerHandshake
// to read the zero time before a handshake, the handshake once one completed,
// and the zero time for a peer the device does not hold.
func realPeerHandshake(t *testing.T, c *NetlinkVPNController, key wgtypes.Key) {
	t.Helper()

	peerKey := mustKey(t)
	if err := c.CreateTunnelInterface(realPeerName, peerKey[:], realPeerPort); err != nil {
		t.Fatalf("CreateTunnelInterface(%q): %v", realPeerName, err)
	}

	pub := key.PublicKey().String()
	peerPub := peerKey.PublicKey().String()

	endpoint := fmt.Sprintf("127.0.0.1:%d", realPeerPort)
	if err := c.ConfigureTunnelPeer(realWGName, peerPub, []string{"10.40.0.2/32"}, endpoint, ""); err != nil {
		t.Fatalf("ConfigureTunnelPeer(%q): %v", realWGName, err)
	}
	if err := c.ConfigureTunnelPeer(realPeerName, pub, []string{"10.40.0.1/32"}, "", ""); err != nil {
		t.Fatalf("ConfigureTunnelPeer(%q): %v", realPeerName, err)
	}

	if got, err := c.TunnelPeerHandshake(realWGName, peerPub); err != nil || !got.IsZero() {
		t.Errorf("TunnelPeerHandshake before a handshake = (%v, %v), want (zero time, nil)", got, err)
	}

	// A persistent keepalive set on a peer of an interface that is up is sent
	// at once, which starts the handshake.
	client, err := wgctrl.New()
	if err != nil {
		t.Fatalf("wgctrl.New: %v", err)
	}
	defer client.Close()
	keepalive := time.Second
	if err := client.ConfigureDevice(realWGName, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:                   peerKey.PublicKey(),
		UpdateOnly:                  true,
		PersistentKeepaliveInterval: &keepalive,
	}}}); err != nil {
		t.Fatalf("set the keepalive on %s: %v", realWGName, err)
	}

	// The kernel completes the handshake on its own after that call returns,
	// so the read is repeated until it does. One round trip over the loopback
	// link is what it takes; the deadline only bounds a handshake that never
	// comes.
	start := time.Now()
	var got time.Time
	for deadline := start.Add(10 * time.Second); got.IsZero() && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
		if got, err = c.TunnelPeerHandshake(realWGName, peerPub); err != nil {
			t.Fatalf("TunnelPeerHandshake: %v", err)
		}
	}
	if got.IsZero() {
		t.Fatalf("TunnelPeerHandshake of %s = zero time 10 s after the keepalive, want the handshake", realWGName)
	}
	if got.Before(start.Add(-time.Second)) || got.After(time.Now().Add(time.Second)) {
		t.Errorf("TunnelPeerHandshake of %s = %v, want a time since %v", realWGName, got, start)
	}

	unknown := mustKey(t).PublicKey().String()
	if got, err := c.TunnelPeerHandshake(realWGName, unknown); err != nil || !got.IsZero() {
		t.Errorf("TunnelPeerHandshake of a peer the device does not hold = (%v, %v), want (zero time, nil)", got, err)
	}
}

// realSweep adds a WireGuard interface named wg-other0 and wants
// RemoveTunnelInterfaces(SiteToSiteInterfacePrefixes) to delete the links of
// all three kinds and to keep wg-other0. A second sweep finds nothing and
// succeeds.
func realSweep(t *testing.T, c *NetlinkVPNController) {
	t.Helper()

	otherKey := mustKey(t)
	if err := c.CreateTunnelInterface(realOtherName, otherKey[:], 0); err != nil {
		t.Fatalf("CreateTunnelInterface(%q): %v", realOtherName, err)
	}

	if err := c.RemoveTunnelInterfaces(SiteToSiteInterfacePrefixes); err != nil {
		t.Fatalf("RemoveTunnelInterfaces: %v", err)
	}

	for _, name := range []string{realXfrmName, realTunName, realWGName, realPeerName} {
		wantNoLink(t, name)
	}
	if got := mustLink(t, realOtherName).Type(); got != "wireguard" {
		t.Errorf("type of %s = %q, want wireguard", realOtherName, got)
	}

	if err := c.RemoveTunnelInterfaces(SiteToSiteInterfacePrefixes); err != nil {
		t.Errorf("second RemoveTunnelInterfaces: %v", err)
	}
}
