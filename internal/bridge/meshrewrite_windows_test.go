//go:build windows

package bridge

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// The adapters, prefixes and addresses of TestMeshSourceRewrite_RealWintun.
// The mesh adapter carries the bridge's mesh address, the provider's adapter
// the address of its pool, and the tunnel's adapter none, as plexd up leaves
// it on Windows. No other test that touches the host uses 10.255.240.0/24,
// 10.255.241.0/24 or 10.255.242.0/24, so its addresses and routes cannot
// collide. Its NetNat objects can: WinNAT keys them by name, and their names
// are the ones a bridge on the host and the real NAT tests of internal/policy
// use too, so the test refuses to start beside an object of those names.
const (
	msrMeshName     = "plexd-rwm"
	msrProviderName = "wg-ua-0000c1c1"
	msrTunnelName   = "wg-s2s-0000c1c1"

	msrMeshCIDR     = "10.255.241.1/24"
	msrProviderCIDR = "10.255.242.1/24"
	msrSiteSubnet   = "10.255.240.0/24"

	// msrChain is the WFP chain the policy checks apply on the mesh adapter.
	msrChain = "plexd-meshrewrite"

	// msrMeshPortFirst and msrMeshPortLast bound the mesh ports and mesh ids
	// the rewriter gives a translated flow.
	msrMeshPortFirst = 32768
	msrMeshPortLast  = 49151

	// msrAnswerWait bounds the wait for a packet a check expects, and
	// msrSilenceWait is how long a check watches for a packet that must not
	// come. msrHandshakeWait bounds a far end's first handshake, which
	// wireguard-go repeats every 5 s when one is lost.
	msrAnswerWait    = 5 * time.Second
	msrSilenceWait   = 2 * time.Second
	msrHandshakeWait = 30 * time.Second

	// msrKeepalive is the production keepalive. A far end turns it on once
	// it knows the bridge's device, which sends a keepalive at once and so
	// opens the handshake.
	msrKeepalive = 25

	// msrNetNatName and msrNetNatExemptPrefix are the names internal/policy
	// gives the bridge NAT's NetNat object and a tunnel's exemption objects.
	msrNetNatName         = "plexd"
	msrNetNatExemptPrefix = "plexd-exempt-"

	// msrListNetNat prints each NetNat object of the host as its name and the
	// prefix it translates, as the real NAT tests of internal/policy list
	// them.
	msrListNetNat = "Get-NetNat | ForEach-Object { $_.Name + '|' + $_.InternalIPInterfaceAddressPrefix }"
)

var (
	msrMeshAddr     = netip.MustParseAddr("10.255.241.1") // the bridge's mesh address
	msrNodeN        = netip.MustParseAddr("10.255.241.2") // mesh node N
	msrProviderAddr = netip.MustParseAddr("10.255.242.1") // the provider's address
	msrDeviceD      = netip.MustParseAddr("10.255.242.2") // device D behind the provider
	msrSiteS        = netip.MustParseAddr("10.255.240.2") // site host S behind the tunnel

	// msrLinkLocal is the range an exemption's /30 comes from.
	msrLinkLocal = netip.MustParsePrefix("169.254.0.0/16")
)

// TestMeshSourceRewrite_RealWintun proves the in-process mesh source rewrite
// and a tunnel's exemption from the bridge NAT on Windows, with WireGuard
// traffic. The bridge side is real and comes from the production
// constructors: one wireguard.MeshRewriter that the devices of three
// WindowsControllers share, the mesh adapter, a user access provider's adapter
// through WGAccessController, a site-to-site tunnel's adapter through
// WGVPNController, a WindowsRouteController for the forwarding flags, the
// route to the site and the bridge NAT, and a WFPController for the policy
// chain, the NetNat objects and the exemption. No manager runs: the test adds
// the rewrites itself.
//
// The far ends are plain wireguard-go devices on channel tuns in this process,
// which reach the bridge's devices over UDP on 127.0.0.1: mesh node N, device
// D behind the provider and site host S behind the tunnel. N's peer entry for
// the bridge allows the mesh address and the site's subnet alone, so
// wireguard-go at N drops a packet that kept D's address, as a mesh node does.
// What D and S open toward N is translated inside the process and never
// reaches Windows. What N opens toward S crosses Windows forwarding, the WFP
// forward layer and WinNAT, and so does S's answer.
//
// It creates adapters, alters the routing table and the forwarding flags, and
// programs the filter engine and WinNAT, so it runs only when
// PLEXD_TEST_REAL_WINTUN, PLEXD_TEST_REAL_ROUTES and PLEXD_TEST_REAL_WFP are
// all set, elevated. CI runs it in a step of its own with the Windows
// Firewall's profiles off, because the echo socket on the provider's address
// takes unsolicited inbound UDP. Every WireGuard port is one the kernel
// picked: the runner holds persistent port reservations that refuse a fixed
// bind with WSAEACCES.
func TestMeshSourceRewrite_RealWintun(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_WINTUN") != "1" || os.Getenv("PLEXD_TEST_REAL_ROUTES") != "1" || os.Getenv("PLEXD_TEST_REAL_WFP") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WINTUN=1, PLEXD_TEST_REAL_ROUTES=1 and PLEXD_TEST_REAL_WFP=1 to create real Wintun adapters, route between them and program the filter engine and WinNAT")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating Wintun adapters, altering routes and programming the filter engine and WinNAT need Administrator")
	}

	// AddNATMasquerade takes over the object named plexd and rebuilds it
	// when it translates another prefix, and the cleanup removes it and
	// every plexd-exempt-* object by name. So the test must not find one it
	// did not make: a bridge on the host owns such an object, or a real NAT
	// test of internal/policy runs beside this one, which CI rules out by
	// running the two packages in steps of their own. Nor may an object
	// already cover the mesh prefix: it would translate the test's flows,
	// and New-NetNat refuses an overlapping prefix. The reset matches names
	// with PowerShell's -like, which ignores case, so the check does too.
	before := msrHostNetNats(t)
	t.Logf("NetNat objects before the test: %q", before)
	meshPrefix := netip.MustParsePrefix(msrMeshCIDR).Masked()
	for _, obj := range before {
		name, prefix, _ := strings.Cut(obj, "|")
		if name = strings.ToLower(name); name == msrNetNatName || strings.HasPrefix(name, msrNetNatExemptPrefix) {
			t.Fatalf("the host already holds the NetNat object %q, which the test would rebuild or remove", obj)
		}
		if p, err := netip.ParsePrefix(prefix); err == nil && p.Overlaps(meshPrefix) {
			t.Fatalf("the host already holds the NetNat object %q, which covers the test's mesh prefix %s", obj, meshPrefix)
		}
	}

	// Registered first, so it runs last and the log holds the cleanup too.
	logs := &integLogBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", logs)
		}
	})
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The bridge side as plexd up builds it on a Windows bridge: the mesh,
	// the access and the tunnel adapters live in three controllers, whose
	// devices one rewriter knows. The route controller's NAT backend is the
	// WFP controller, as newRouteController makes it.
	rewriter := wireguard.NewMeshRewriter(logger)
	var rewrite MeshSourceRewriter = rewriter
	newController := func() *wireguard.WindowsController {
		c := wireguard.NewWindowsController(logger)
		c.SetMeshRewriter(rewriter)
		return c
	}
	meshCtrl := newController()
	access := NewWGAccessController(newController(), logger)
	vpn := NewWGVPNController(newController(), "", logger)
	wfp := policy.NewWFPController(logger, msrMeshName)
	var exempter NATExempter = wfp
	routes := NewWindowsRouteController(logger, wfp)

	meshKey, providerKey, tunnelKey := integKey(t), integKey(t), integKey(t)

	if err := meshCtrl.CreateInterface(msrMeshName, meshKey[:], 0); err != nil {
		t.Fatalf("create the mesh adapter %s: %v", msrMeshName, err)
	}
	t.Cleanup(func() {
		if err := meshCtrl.DeleteInterface(msrMeshName); err != nil {
			t.Errorf("cleanup: delete %s: %v", msrMeshName, err)
		}
	})
	if err := meshCtrl.ConfigureAddress(msrMeshName, msrMeshCIDR); err != nil {
		t.Fatalf("assign %s to %s: %v", msrMeshCIDR, msrMeshName, err)
	}
	if err := meshCtrl.SetInterfaceUp(msrMeshName); err != nil {
		t.Fatalf("bring %s up: %v", msrMeshName, err)
	}

	if err := access.CreateInterface(msrProviderName, providerKey[:], 0, msrProviderCIDR); err != nil {
		t.Fatalf("create the provider's adapter %s: %v", msrProviderName, err)
	}
	t.Cleanup(func() {
		if err := access.RemoveInterface(msrProviderName); err != nil {
			t.Errorf("cleanup: remove %s: %v", msrProviderName, err)
		}
	})

	if err := vpn.CreateTunnelInterface(msrTunnelName, tunnelKey[:], 0); err != nil {
		t.Fatalf("create the tunnel's adapter %s: %v", msrTunnelName, err)
	}
	t.Cleanup(func() {
		if err := vpn.RemoveTunnelInterface(msrTunnelName); err != nil {
			t.Errorf("cleanup: remove %s: %v", msrTunnelName, err)
		}
	})

	meshPort := uapiListenPort(t, uapiDump(t, uapiPipePrefix+msrMeshName))
	providerPort := uapiListenPort(t, uapiDump(t, uapiPipePrefix+msrProviderName))
	tunnelPort := uapiListenPort(t, uapiDump(t, uapiPipePrefix+msrTunnelName))

	nodeN := msrStartFarEnd(t, logs, "N", msrNodeN)
	devD := msrStartFarEnd(t, logs, "D", msrDeviceD)
	siteS := msrStartFarEnd(t, logs, "S", msrSiteS)

	// The bridge's devices learn the far ends first, so the handshake each
	// far end opens below finds its peer.
	nPub := nodeN.key.PublicKey()
	if err := meshCtrl.AddPeer(msrMeshName, wireguard.PeerConfig{
		PublicKey:  nPub[:],
		Endpoint:   nodeN.endpoint(t),
		AllowedIPs: []string{"10.255.241.2/32"},
	}); err != nil {
		t.Fatalf("add N to %s: %v", msrMeshName, err)
	}
	// A provider's peer has no endpoint: D opens the handshake.
	if err := access.ConfigurePeer(msrProviderName, devD.key.PublicKey().String(), []string{"10.255.242.2/32"}, ""); err != nil {
		t.Fatalf("add D to %s: %v", msrProviderName, err)
	}
	if err := vpn.ConfigureTunnelPeer(msrTunnelName, siteS.key.PublicKey().String(), []string{msrSiteSubnet}, siteS.endpoint(t), ""); err != nil {
		t.Fatalf("add S to %s: %v", msrTunnelName, err)
	}
	nodeN.connect(t, meshKey.PublicKey(), meshPort, "10.255.241.1/32", msrSiteSubnet)
	devD.connect(t, providerKey.PublicKey(), providerPort, "10.255.241.0/24", "10.255.242.1/32")
	siteS.connect(t, tunnelKey.PublicKey(), tunnelPort, "10.255.241.0/24")

	for _, from := range []string{msrProviderName, msrTunnelName} {
		if err := routes.EnableForwarding(msrMeshName, from); err != nil {
			t.Fatalf("EnableForwarding(%q, %q): %v", msrMeshName, from, err)
		}
		t.Cleanup(func() {
			if err := routes.DisableForwarding(msrMeshName, from); err != nil {
				t.Errorf("cleanup: DisableForwarding(%q, %q): %v", msrMeshName, from, err)
			}
		})
	}

	// The rewriter reads the adapters' prefixes as the host lists them and
	// takes the mesh adapter's first IPv4 address as the mesh address.
	if got := msrHostPrefixes(t, msrMeshName); len(got) == 0 || got[0] != netip.MustParsePrefix(msrMeshCIDR) {
		t.Fatalf("the host lists the IPv4 prefixes %v for %s, want %s first: the rewriter takes the first as the mesh address", got, msrMeshName, msrMeshCIDR)
	}
	if got := msrHostPrefixes(t, msrProviderName); !slices.Contains(got, netip.MustParsePrefix(msrProviderCIDR)) {
		t.Fatalf("the host lists the IPv4 prefixes %v for %s, want %s among them", got, msrProviderName, msrProviderCIDR)
	}
	for _, from := range []string{msrProviderName, msrTunnelName} {
		if err := rewrite.AddMeshSourceRewrite(from, msrMeshName); err != nil {
			t.Fatalf("AddMeshSourceRewrite(%q, %q): %v", from, msrMeshName, err)
		}
	}

	if err := routes.AddRoute(msrSiteSubnet, msrTunnelName); err != nil {
		t.Fatalf("AddRoute(%q, %q): %v", msrSiteSubnet, msrTunnelName, err)
	}
	t.Cleanup(func() {
		if err := routes.RemoveRoute(msrSiteSubnet, msrTunnelName); err != nil {
			t.Errorf("cleanup: RemoveRoute(%q, %q): %v", msrSiteSubnet, msrTunnelName, err)
		}
	})

	msrEchoUDP(t, netip.AddrPortFrom(msrProviderAddr, 7002))

	for _, end := range []*msrFarEnd{nodeN, devD, siteS} {
		end.waitHandshake(t)
	}

	t.Run("udp from D to N and back", func(t *testing.T) {
		msrRewriteRoundTrip(t, devD, nodeN, 5001, "udp from D")
	})

	t.Run("tcp and icmp echo from D to N and back", func(t *testing.T) {
		msrSYNRoundTrip(t, devD, nodeN, 5002)
		msrEchoRoundTrip(t, devD, nodeN, 0x0214)
	})

	t.Run("udp from D to the provider's address and back", func(t *testing.T) {
		const payload = "plexd#214 udp from D to the echo socket"
		devD.send(t, msrUDP(msrDeviceD, msrProviderAddr, 5003, 7002, []byte(payload)))
		echo, ok := devD.expect(t, "the echo of the socket on 10.255.242.1:7002", msrUDPTo(msrDeviceD, 5003, payload))
		if ok && (echo.src != msrProviderAddr || echo.sport != 7002) {
			t.Errorf("D read the echo as %v, want it from %s:7002", echo, msrProviderAddr)
		}
	})

	t.Run("no rewrite from D after RemoveMeshSourceRewrite", func(t *testing.T) {
		if err := rewrite.RemoveMeshSourceRewrite(msrProviderName, msrMeshName); err != nil {
			t.Fatalf("RemoveMeshSourceRewrite(%q, %q): %v", msrProviderName, msrMeshName, err)
		}
		// Without the rewrite the datagram keeps D's address, which N's
		// device drops, whether or not Windows forwards it.
		const payload = "plexd#214 udp from D without the rewrite"
		devD.send(t, msrUDP(msrDeviceD, msrNodeN, 5004, 7001, []byte(payload)))
		nodeN.expectNone(t, "D's datagram of a new flow to N:7001", msrUDPTo(msrNodeN, 7001, payload))
	})

	t.Run("udp from S to N and back", func(t *testing.T) {
		msrRewriteRoundTrip(t, siteS, nodeN, 6001, "udp from S")
	})

	t.Run("udp from N to S and back", func(t *testing.T) {
		msrForwardRoundTrip(t, nodeN, siteS, 50001, "udp from N")
	})

	denyOnly := []policy.FirewallRule{{Interface: msrMeshName, Action: "deny"}}
	allowSite := []policy.FirewallRule{
		{Interface: msrMeshName, SrcIP: "10.255.241.2/32", DstIP: msrSiteSubnet, Action: "allow"},
		denyOnly[0],
	}
	t.Cleanup(func() {
		if err := wfp.DeleteChain(msrChain); err != nil {
			t.Errorf("cleanup: DeleteChain(%q): %v", msrChain, err)
		}
	})

	t.Run("the default deny drops what N opens toward S", func(t *testing.T) {
		if err := wfp.ApplyRules(msrChain, denyOnly); err != nil {
			t.Fatalf("ApplyRules with the default deny alone: %v", err)
		}
		msrForwardDropped(t, nodeN, siteS, 50002, "udp from N under the default deny")
		msrRewriteRoundTrip(t, siteS, nodeN, 6002, "udp from S under the default deny")
	})

	t.Run("an allow rule above the deny admits what N opens toward S", func(t *testing.T) {
		if err := wfp.ApplyRules(msrChain, allowSite); err != nil {
			t.Fatalf("ApplyRules with the allow rule above the default deny: %v", err)
		}
		msrForwardRoundTrip(t, nodeN, siteS, 50003, "udp from N under the allow rule")
	})

	// Registered before the NetNat objects exist, so they go even when a
	// call fails halfway. Both scripts take an absent object for a success,
	// so after the last check the cleanup has nothing left to remove. No
	// object of their names was there when the test began, so what they
	// remove is the test's own.
	t.Cleanup(func() {
		if err := routes.RemoveNATMasquerade(msrMeshName); err != nil {
			t.Errorf("cleanup: RemoveNATMasquerade(%q): %v", msrMeshName, err)
		}
		if err := exempter.ResetNATExemptions(); err != nil {
			t.Errorf("cleanup: ResetNATExemptions: %v", err)
		}
	})

	t.Run("the exempted tunnel keeps the addresses beside the bridge NAT", func(t *testing.T) {
		// AddNATMasquerade and ExemptFromNAT take the mesh prefix from the
		// mesh adapter's first IPv4 address in this table.
		t.Logf("%s carries %v", msrMeshName, msrAdapterAddresses(t, msrMeshName))
		if err := routes.AddNATMasquerade(msrMeshName); err != nil {
			t.Fatalf("AddNATMasquerade(%q): %v", msrMeshName, err)
		}

		// A fresh adapter may carry no address yet, and WinNAT has nothing
		// to translate to on a link without one (measured on windows-latest,
		// 2026-11-23), so a send before ExemptFromNAT shows nothing. The
		// control that shows the exemption at work is in the last check,
		// where the adapter carries its /30.
		t.Logf("%s carries %v before ExemptFromNAT", msrTunnelName, msrAdapterAddresses(t, msrTunnelName))

		if err := exempter.ExemptFromNAT(msrTunnelName); err != nil {
			t.Fatalf("ExemptFromNAT(%q): %v", msrTunnelName, err)
		}
		addrs := msrAdapterAddresses(t, msrTunnelName)
		t.Logf("%s carries %v after ExemptFromNAT", msrTunnelName, addrs)
		var exempt []netip.Prefix
		for _, a := range addrs {
			if a.Bits() == 30 && msrLinkLocal.Contains(a.Addr()) {
				exempt = append(exempt, a)
			}
		}
		if len(exempt) != 1 {
			t.Errorf("%s carries %v after ExemptFromNAT, want one address of %s with prefix length 30", msrTunnelName, addrs, msrLinkLocal)
		}
		msrForwardRoundTrip(t, nodeN, siteS, 50005, "udp from N beside the bridge NAT")
	})

	t.Run("the default deny applies to the exempted tunnel", func(t *testing.T) {
		if err := wfp.ApplyRules(msrChain, denyOnly); err != nil {
			t.Fatalf("ApplyRules with the default deny alone: %v", err)
		}
		msrForwardDropped(t, nodeN, siteS, 50006, "udp from N under the default deny beside the bridge NAT")
		msrRewriteRoundTrip(t, siteS, nodeN, 6003, "udp from S under the default deny beside the bridge NAT")
	})

	t.Run("the exemption and the bridge NAT go", func(t *testing.T) {
		// The control: UnexemptFromNAT removes the exemption's object, and
		// the adapter keeps its /30, which goes with the adapter. Beside
		// the bridge NAT's object alone, WinNAT then translates what N opens
		// toward S to that address on its way out of the adapter, and S's
		// device drops a source outside 10.255.241.0/24. Once the bridge
		// NAT's object goes too, the same kind of flow reaches S from N's
		// own address. The allow rule holds for both sends, so the NAT
		// objects are the only thing that changes between them, and the
		// pair shows that the exemption is what kept N's source in the
		// exemption's check above.
		if err := wfp.ApplyRules(msrChain, allowSite); err != nil {
			t.Fatalf("ApplyRules with the allow rule above the default deny: %v", err)
		}
		if err := exempter.UnexemptFromNAT(msrTunnelName); err != nil {
			t.Errorf("UnexemptFromNAT(%q) = %v, want nil", msrTunnelName, err)
		}
		t.Logf("%s carries %v after UnexemptFromNAT", msrTunnelName, msrAdapterAddresses(t, msrTunnelName))
		msrForwardDropped(t, nodeN, siteS, 50007, "udp from N beside the bridge NAT after UnexemptFromNAT")
		if err := routes.RemoveNATMasquerade(msrMeshName); err != nil {
			t.Errorf("RemoveNATMasquerade(%q) = %v, want nil", msrMeshName, err)
		}
		msrForwardRoundTrip(t, nodeN, siteS, 50008, "udp from N after RemoveNATMasquerade")
		// A start's reset runs on a controller of its own.
		var next NATExempter = policy.NewWFPController(logger, msrMeshName)
		if err := next.ResetNATExemptions(); err != nil {
			t.Errorf("ResetNATExemptions on a second WFPController = %v, want nil", err)
		}
	})
}

// msrRewriteRoundTrip sends a datagram of a new flow from the far end from,
// from port sport, to N:7001, and N's answer back. It checks that N reads the
// datagram from the mesh address and a mesh port, translated in the process,
// and that from reads the answer from N:7001 at its own address and port,
// both with valid checksums. what tells the payloads of the checks apart.
func msrRewriteRoundTrip(t *testing.T, from, nodeN *msrFarEnd, sport uint16, what string) {
	t.Helper()

	query := "plexd#214 " + what
	from.send(t, msrUDP(from.ip, msrNodeN, sport, 7001, []byte(query)))
	atN, ok := nodeN.expect(t, from.name+"'s datagram to N:7001", msrUDPTo(msrNodeN, 7001, query))
	if !ok {
		return
	}
	if atN.src != msrMeshAddr || !msrMeshPort(atN.sport) || !atN.sumsOK {
		t.Errorf("N read %s's datagram as %v, checksums valid %t, want it from %s and a port from %d to %d with valid checksums",
			from.name, atN, atN.sumsOK, msrMeshAddr, msrMeshPortFirst, msrMeshPortLast)
		return
	}

	answer := query + ", answered"
	nodeN.send(t, msrUDP(msrNodeN, msrMeshAddr, 7001, atN.sport, []byte(answer)))
	back, ok := from.expect(t, "N's answer", msrUDPTo(from.ip, sport, answer))
	if ok && (back.src != msrNodeN || back.sport != 7001 || !back.sumsOK) {
		t.Errorf("%s read N's answer as %v, checksums valid %t, want it from %s:7001 with valid checksums", from.name, back, back.sumsOK, msrNodeN)
	}
}

// msrSYNRoundTrip sends a TCP SYN of a new flow from D, from port sport, to
// N:7001, and N's SYN-ACK back, and checks them as msrRewriteRoundTrip checks
// a datagram.
func msrSYNRoundTrip(t *testing.T, devD, nodeN *msrFarEnd, sport uint16) {
	t.Helper()

	const seq = 0x214
	devD.send(t, msrTCP(msrDeviceD, msrNodeN, sport, 7001, msrTCPSYN, seq, 0))
	atN, ok := nodeN.expect(t, "D's SYN to N:7001", msrTCPTo(msrNodeN, 7001, msrTCPSYN))
	if !ok {
		return
	}
	if atN.src != msrMeshAddr || !msrMeshPort(atN.sport) || !atN.sumsOK {
		t.Errorf("N read D's SYN as %v, checksums valid %t, want it from %s and a port from %d to %d with valid checksums",
			atN, atN.sumsOK, msrMeshAddr, msrMeshPortFirst, msrMeshPortLast)
		return
	}

	nodeN.send(t, msrTCP(msrNodeN, msrMeshAddr, 7001, atN.sport, msrTCPSYN|msrTCPACK, 0x7001, seq+1))
	back, ok := devD.expect(t, "N's SYN-ACK", msrTCPTo(msrDeviceD, sport, msrTCPSYN|msrTCPACK))
	if ok && (back.src != msrNodeN || back.sport != 7001 || !back.sumsOK) {
		t.Errorf("D read N's SYN-ACK as %v, checksums valid %t, want it from %s:7001 with valid checksums", back, back.sumsOK, msrNodeN)
	}
}

// msrEchoRoundTrip sends an ICMP echo request with id from D to N, and N's
// reply back. It checks that N reads the request from the mesh address with a
// mesh id, and that D reads the reply from N with its own id, both with valid
// checksums.
func msrEchoRoundTrip(t *testing.T, devD, nodeN *msrFarEnd, id uint16) {
	t.Helper()

	const data = "plexd#214 icmp echo from D"
	devD.send(t, msrEcho(msrDeviceD, msrNodeN, msrEchoRequest, id, 1, []byte(data)))
	atN, ok := nodeN.expect(t, "D's echo request to N", msrEchoTo(msrNodeN, msrEchoRequest, data))
	if !ok {
		return
	}
	if atN.src != msrMeshAddr || !msrMeshPort(atN.echoID) || !atN.sumsOK {
		t.Errorf("N read D's echo request as %v, checksums valid %t, want it from %s with an id from %d to %d and valid checksums",
			atN, atN.sumsOK, msrMeshAddr, msrMeshPortFirst, msrMeshPortLast)
		return
	}

	// An echo reply carries the request's data back.
	nodeN.send(t, msrEcho(msrNodeN, msrMeshAddr, msrEchoReply, atN.echoID, 1, []byte(data)))
	back, ok := devD.expect(t, "N's echo reply", msrEchoTo(msrDeviceD, msrEchoReply, data))
	if ok && (back.src != msrNodeN || back.echoID != id || !back.sumsOK) {
		t.Errorf("D read N's echo reply as %v, checksums valid %t, want it from %s with D's id %d and valid checksums", back, back.sumsOK, msrNodeN, id)
	}
}

// msrForwardRoundTrip sends a datagram of a new flow from N, from port sport,
// to S:7002, and S's answer back. Both cross Windows forwarding, the WFP
// forward layer and WinNAT. It checks that each end reads the other's own
// address and port. S's device drops a datagram whose source left
// 10.255.241.0/24, as a translation by WinNAT would leave it, so such a
// datagram reads as none.
func msrForwardRoundTrip(t *testing.T, nodeN, siteS *msrFarEnd, sport uint16, what string) {
	t.Helper()

	query := "plexd#214 " + what
	nodeN.send(t, msrUDP(msrNodeN, msrSiteS, sport, 7002, []byte(query)))
	atS, ok := siteS.expect(t, "N's datagram to S:7002", msrUDPTo(msrSiteS, 7002, query))
	if !ok {
		return
	}
	if atS.src != msrNodeN || atS.sport != sport {
		t.Errorf("S read N's datagram as %v, want it from %s:%d", atS, msrNodeN, sport)
		return
	}

	answer := query + ", answered"
	siteS.send(t, msrUDP(msrSiteS, msrNodeN, 7002, sport, []byte(answer)))
	back, ok := nodeN.expect(t, "S's answer", msrUDPTo(msrNodeN, sport, answer))
	if ok && (back.src != msrSiteS || back.sport != 7002) {
		t.Errorf("N read S's answer as %v, want it from %s:7002", back, msrSiteS)
	}
}

// msrForwardDropped sends a datagram of a new flow from N, from port sport, to
// S:7002 and checks that S reads nothing of it for msrSilenceWait.
func msrForwardDropped(t *testing.T, nodeN, siteS *msrFarEnd, sport uint16, what string) {
	t.Helper()

	query := "plexd#214 " + what
	nodeN.send(t, msrUDP(msrNodeN, msrSiteS, sport, 7002, []byte(query)))
	siteS.expectNone(t, "N's datagram of a new flow to S:7002", msrUDPTo(msrSiteS, 7002, query))
}

// msrFarEnd is a far end of TestMeshSourceRewrite_RealWintun: a plain
// wireguard-go device on a channel tun with the drain of integNode, its key,
// and the name the checks call it by.
type msrFarEnd struct {
	*integNode
	name string
	key  wgtypes.Key
}

// msrStartFarEnd brings up a device for name with address ip on a port the
// kernel picks and no peer yet. Its log lines go to logs. It is closed on
// cleanup.
func msrStartFarEnd(t *testing.T, logs *integLogBuffer, name string, ip netip.Addr) *msrFarEnd {
	t.Helper()

	logf := func(format string, args ...any) {
		fmt.Fprintf(logs, "device %s: %s\n", name, fmt.Sprintf(format, args...))
	}
	n := &integNode{
		ip:       ip,
		tun:      tuntest.NewChannelTUN(),
		received: make(chan []byte, 64),
		stop:     make(chan struct{}),
		drained:  make(chan struct{}),
	}
	n.dev = device.NewDevice(n.tun.TUN(), conn.NewDefaultBind(), &device.Logger{Verbosef: logf, Errorf: logf})
	go n.drain()
	t.Cleanup(n.close)

	e := &msrFarEnd{integNode: n, name: name, key: integKey(t)}
	if err := n.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n", hex.EncodeToString(e.key[:]))); err != nil {
		t.Fatalf("configure %s: %v", name, err)
	}
	if err := n.dev.Up(); err != nil {
		t.Fatalf("bring up %s: %v", name, err)
	}
	return e
}

// uapi returns the far end's UAPI dump.
func (e *msrFarEnd) uapi(t *testing.T) string {
	t.Helper()

	dump, err := e.dev.IpcGet()
	if err != nil {
		t.Fatalf("read %s's device: %v", e.name, err)
	}
	return dump
}

// endpoint returns 127.0.0.1 and the port the far end's device listens on.
func (e *msrFarEnd) endpoint(t *testing.T) string {
	t.Helper()
	return netip.AddrPortFrom(natLoopback, uint16(uapiListenPort(t, e.uapi(t)))).String()
}

// connect gives the far end the bridge's device with the public key bridge,
// listening on 127.0.0.1:port, as its only peer, with allowed as its allowed
// IPs and the production keepalive. Turning the keepalive on sends one at
// once, which opens the handshake.
func (e *msrFarEnd) connect(t *testing.T, bridge wgtypes.Key, port int, allowed ...string) {
	t.Helper()

	var cfg strings.Builder
	fmt.Fprintf(&cfg, "public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\n",
		hex.EncodeToString(bridge[:]), netip.AddrPortFrom(natLoopback, uint16(port)))
	for _, prefix := range allowed {
		fmt.Fprintf(&cfg, "allowed_ip=%s\n", prefix)
	}
	fmt.Fprintf(&cfg, "persistent_keepalive_interval=%d\n", msrKeepalive)
	if err := e.dev.IpcSet(cfg.String()); err != nil {
		t.Fatalf("give %s the bridge's device as its peer: %v", e.name, err)
	}
}

// waitHandshake waits up to msrHandshakeWait until the far end has completed
// a handshake with the bridge's device, so no check depends on a packet
// wireguard-go holds back for a handshake.
func (e *msrFarEnd) waitHandshake(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(msrHandshakeWait)
	for {
		for line := range strings.SplitSeq(e.uapi(t), "\n") {
			if sec, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && sec != "0" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s completed no handshake with the bridge's device within %s", e.name, msrHandshakeWait)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// send hands pkt to the far end's device, which sends it to the bridge.
func (e *msrFarEnd) send(t *testing.T, pkt []byte) {
	t.Helper()

	select {
	case e.tun.Outbound <- pkt:
	case <-time.After(msrAnswerWait):
		t.Fatalf("%s's device took no packet to send within %s", e.name, msrAnswerWait)
	}
}

// next waits up to wait for a packet the far end's device delivers that match
// accepts. It logs and skips every other one.
func (e *msrFarEnd) next(t *testing.T, wait time.Duration, match func(msrPacket) bool) (msrPacket, bool) {
	t.Helper()

	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	for {
		select {
		case raw := <-e.received:
			p, ok := msrParse(raw)
			switch {
			case ok && match(p):
				return p, true
			case ok:
				t.Logf("%s read a packet no check waits for: %v", e.name, p)
			default:
				t.Logf("%s read %d bytes that are no IPv4 packet a check reads", e.name, len(raw))
			}
		case <-timeout.C:
			return msrPacket{}, false
		}
	}
}

// expect fails the test unless the far end reads a packet that match accepts
// within msrAnswerWait, and returns it.
func (e *msrFarEnd) expect(t *testing.T, what string, match func(msrPacket) bool) (msrPacket, bool) {
	t.Helper()

	p, ok := e.next(t, msrAnswerWait, match)
	if !ok {
		t.Errorf("%s read no %s within %s", e.name, what, msrAnswerWait)
	}
	return p, ok
}

// expectNone fails the test if the far end reads a packet that match accepts
// within msrSilenceWait.
func (e *msrFarEnd) expectNone(t *testing.T, what string, match func(msrPacket) bool) {
	t.Helper()

	if p, ok := e.next(t, msrSilenceWait, match); ok {
		t.Errorf("%s read %s as %v, want none within %s", e.name, what, p, msrSilenceWait)
	}
}

// msrEchoUDP binds a UDP socket on addr and sends every datagram it receives
// back to its sender until the test ends. It waits up to 10 s for the bind,
// since a host may hold a fresh address back for a moment after it is
// assigned.
func msrEchoUDP(t *testing.T, addr netip.AddrPort) {
	t.Helper()

	var sock *net.UDPConn
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		if sock, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no socket could bind %s within 10 s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, from, err := sock.ReadFromUDPAddrPort(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// Windows reports an ICMP port unreachable for an earlier
				// send as WSAECONNRESET on the next read; the socket still
				// works.
				continue
			}
			_, _ = sock.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	t.Cleanup(func() {
		_ = sock.Close()
		<-done
	})
}

// msrHostPrefixes returns the IPv4 prefixes the host lists for the adapter
// name, in the host's order, read as the rewriter reads them: through
// net.InterfaceByName and its Addrs.
func msrHostPrefixes(t *testing.T, name string) []netip.Prefix {
	t.Helper()

	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		t.Fatalf("read the addresses of %s: %v", name, err)
	}
	var prefixes []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() == nil {
			continue
		}
		ones, bits := ipn.Mask.Size()
		if bits == 8*net.IPv6len {
			ones -= 8 * (net.IPv6len - net.IPv4len)
		}
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte(ipn.IP.To4())), ones))
	}
	return prefixes
}

// msrAdapterAddresses returns the IPv4 addresses of the adapter name, each
// with its on-link prefix length, read through the IP Helper API.
func msrAdapterAddresses(t *testing.T, name string) []netip.Prefix {
	t.Helper()

	luid, err := winipcfgRouter{}.LookupLUID(name)
	if err != nil {
		t.Fatalf("resolve the LUID of %s: %v", name, err)
	}
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		t.Fatalf("read the host's IPv4 addresses: %v", err)
	}
	var addrs []netip.Prefix
	for i := range rows {
		if uint64(rows[i].InterfaceLUID) == luid {
			addrs = append(addrs, netip.PrefixFrom(rows[i].Address.Addr(), int(rows[i].OnLinkPrefixLength)))
		}
	}
	return addrs
}

// msrHostNetNats returns the host's NetNat objects, each as its name and the
// prefix it translates, joined by "|". It runs the Windows PowerShell of the
// system directory, as internal/policy does, and gives it 30 s, since
// PowerShell takes seconds to start on a cold host.
func msrHostNetNats(t *testing.T) []string {
	t.Helper()

	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("locate the system directory: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	out, err := NewStdCommandExecutor().Run(ctx, filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-Command", msrListNetNat)
	if err != nil {
		t.Fatalf("%s: %v\n%s", msrListNetNat, err, out)
	}
	var objects []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			objects = append(objects, line)
		}
	}
	return objects
}

// msrMeshPort reports whether port lies in the range the rewriter gives a
// translated flow's mesh port or mesh id from.
func msrMeshPort(port uint16) bool {
	return port >= msrMeshPortFirst && port <= msrMeshPortLast
}

// The protocols, ICMP types and TCP flags the checks build and read.
const (
	msrProtoICMP = 1
	msrProtoTCP  = 6
	msrProtoUDP  = 17

	msrEchoReply   = 0
	msrEchoRequest = 8

	msrTCPSYN = 0x02
	msrTCPACK = 0x10
)

// msrPacket is what a check reads of an IPv4 packet a far end's device
// delivered. sumsOK reports whether the header checksum and the transport
// checksum are valid.
type msrPacket struct {
	src, dst     netip.Addr
	proto        uint8
	sport, dport uint16 // TCP and UDP
	tcpFlags     uint8
	icmpType     uint8
	echoID       uint16
	payload      []byte
	sumsOK       bool
}

func (p msrPacket) String() string {
	switch p.proto {
	case msrProtoUDP:
		return fmt.Sprintf("udp %s:%d > %s:%d", p.src, p.sport, p.dst, p.dport)
	case msrProtoTCP:
		return fmt.Sprintf("tcp %s:%d > %s:%d flags %#02x", p.src, p.sport, p.dst, p.dport, p.tcpFlags)
	case msrProtoICMP:
		return fmt.Sprintf("icmp %s > %s type %d id %d", p.src, p.dst, p.icmpType, p.echoID)
	}
	return fmt.Sprintf("protocol %d %s > %s", p.proto, p.src, p.dst)
}

// msrUDPTo matches a UDP datagram to dst:dport that carries payload.
func msrUDPTo(dst netip.Addr, dport uint16, payload string) func(msrPacket) bool {
	return func(p msrPacket) bool {
		return p.proto == msrProtoUDP && p.dst == dst && p.dport == dport && string(p.payload) == payload
	}
}

// msrTCPTo matches a TCP segment to dst:dport whose flags are flags.
func msrTCPTo(dst netip.Addr, dport uint16, flags uint8) func(msrPacket) bool {
	return func(p msrPacket) bool {
		return p.proto == msrProtoTCP && p.dst == dst && p.dport == dport && p.tcpFlags == flags
	}
}

// msrEchoTo matches an ICMP echo message of type typ to dst that carries
// data.
func msrEchoTo(dst netip.Addr, typ uint8, data string) func(msrPacket) bool {
	return func(p msrPacket) bool {
		return p.proto == msrProtoICMP && p.dst == dst && p.icmpType == typ && string(p.payload) == data
	}
}

// msrParse reads an IPv4 packet. It reports false for anything else, for a
// fragment, which no check sends, and for a transport header that does not
// fit the packet.
func msrParse(b []byte) (msrPacket, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return msrPacket{}, false
	}
	hl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if hl < 20 || total < hl || total > len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return msrPacket{}, false
	}
	b = b[:total]
	p := msrPacket{
		proto: b[9],
		src:   netip.AddrFrom4([4]byte(b[12:16])),
		dst:   netip.AddrFrom4([4]byte(b[16:20])),
	}
	headerOK := msrFold(msrSum(0, b[:hl])) == 0xffff
	l4 := b[hl:]
	pseudo := msrPseudoSum(p.src, p.dst, p.proto, len(l4))

	transportOK := true
	switch p.proto {
	case msrProtoUDP:
		if len(l4) < 8 {
			return msrPacket{}, false
		}
		p.sport, p.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
		p.payload = l4[8:]
		// A UDP checksum of 0 is none.
		transportOK = binary.BigEndian.Uint16(l4[6:8]) == 0 || msrFold(msrSum(pseudo, l4)) == 0xffff
	case msrProtoTCP:
		if len(l4) < 20 {
			return msrPacket{}, false
		}
		off := int(l4[12]>>4) * 4
		if off < 20 || off > len(l4) {
			return msrPacket{}, false
		}
		p.sport, p.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
		p.tcpFlags = l4[13]
		p.payload = l4[off:]
		transportOK = msrFold(msrSum(pseudo, l4)) == 0xffff
	case msrProtoICMP:
		if len(l4) < 8 {
			return msrPacket{}, false
		}
		p.icmpType = l4[0]
		p.echoID = binary.BigEndian.Uint16(l4[4:6])
		p.payload = l4[8:]
		transportOK = msrFold(msrSum(0, l4)) == 0xffff
	}
	p.sumsOK = headerOK && transportOK
	return p, true
}

// msrUDP builds a UDP datagram with a valid checksum.
func msrUDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	copy(l4[8:], payload)
	sum := ^msrFold(msrSum(msrPseudoSum(src, dst, msrProtoUDP, len(l4)), l4))
	if sum == 0 {
		// 0 means no checksum, so a computed 0 goes out as its complement.
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(l4[6:8], sum)
	return msrIPv4(src, dst, msrProtoUDP, l4)
}

// msrTCP builds a TCP segment without options or data, with a valid
// checksum.
func msrTCP(src, dst netip.Addr, sport, dport uint16, flags uint8, seq, ack uint32) []byte {
	l4 := make([]byte, 20)
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	binary.BigEndian.PutUint32(l4[4:8], seq)
	binary.BigEndian.PutUint32(l4[8:12], ack)
	l4[12] = 5 << 4
	l4[13] = flags
	binary.BigEndian.PutUint16(l4[14:16], 65535)
	binary.BigEndian.PutUint16(l4[16:18], ^msrFold(msrSum(msrPseudoSum(src, dst, msrProtoTCP, len(l4)), l4)))
	return msrIPv4(src, dst, msrProtoTCP, l4)
}

// msrEcho builds an ICMP echo request or reply with a valid checksum.
func msrEcho(src, dst netip.Addr, typ uint8, id, seq uint16, data []byte) []byte {
	l4 := make([]byte, 8+len(data))
	l4[0] = typ
	binary.BigEndian.PutUint16(l4[4:6], id)
	binary.BigEndian.PutUint16(l4[6:8], seq)
	copy(l4[8:], data)
	binary.BigEndian.PutUint16(l4[2:4], ^msrFold(msrSum(0, l4)))
	return msrIPv4(src, dst, msrProtoICMP, l4)
}

// msrIPID numbers the packets msrIPv4 builds.
var msrIPID atomic.Uint32

// msrIPv4 puts an IPv4 header without options in front of l4: TTL 64, no
// fragmentation flag, and a valid header checksum.
func msrIPv4(src, dst netip.Addr, proto uint8, l4 []byte) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(msrIPID.Add(1)))
	pkt[8] = 64
	pkt[9] = proto
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], ^msrFold(msrSum(0, pkt[:20])))
	copy(pkt[20:], l4)
	return pkt
}

// msrPseudoSum is the sum of the pseudo header a TCP or UDP checksum covers.
func msrPseudoSum(src, dst netip.Addr, proto uint8, length int) uint32 {
	s, d := src.As4(), dst.As4()
	return msrSum(msrSum(uint32(proto)+uint32(length), s[:]), d[:])
}

// msrSum adds b to sum as 16-bit words in network byte order, an odd last
// byte padded with zero.
func msrSum(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// msrFold folds sum into 16 bits, the ones' complement sum. A checksum is
// valid when the folded sum over the bytes it covers, itself included, is
// 0xffff.
func msrFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}
