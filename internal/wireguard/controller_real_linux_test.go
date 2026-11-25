//go:build linux

package wireguard

import (
	"net"
	"os"
	"slices"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/plexsphere/plexd/internal/nettest"
)

// linkIPv4 reads, inside the namespace, the IPv4 addresses of the named link
// and the routes of the main table through it.
func linkIPv4(t *testing.T, ns *nettest.Netns, name string) ([]string, []netlink.Route) {
	t.Helper()
	var (
		addrs  []string
		routes []netlink.Route
	)
	if err := ns.Do(func() error {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		list, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		for _, a := range list {
			addrs = append(addrs, a.IPNet.String())
		}
		routes, err = netlink.RouteList(link, netlink.FAMILY_V4)
		return err
	}); err != nil {
		t.Fatalf("namespace %s: read %s: %v", ns.Name, name, err)
	}
	return addrs, routes
}

// TestNetlinkController_RealReplaceAddress proves on a real kernel that
// ReplaceAddress swaps the address of a live WireGuard link in an order that
// keeps the routes through it. The link holds 10.98.0.1/24 and a route
// 172.16.5.0/24 with no source, as a peer's routed subnet has, before the
// call. Deleting the only address of a link would remove that route, and so
// would adding 10.98.0.9/24 before deleting the old address, because the new
// one would be a secondary of the old. A second link proves the two calls of
// a pair of /32 addresses.
//
// Every call is repeated with the same arguments, which meets an old address
// that is gone and a new one that is there, as the repeat of a call that
// failed halfway does.
//
// The links live in a network namespace of their own. The gate is a variable
// besides the effective uid, as for TestRTTProbe_RealAnswersOnlyTheMeshInterface,
// and CI runs it in the step "Run privileged Linux tests".
func TestNetlinkController_RealReplaceAddress(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to create real WireGuard links in a test network namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a network namespace and links")
	}

	const (
		meshLink = "wg-readdress"
		hostLink = "wg-readdress32"
	)

	ns := nettest.NewNetns(t, "readdress")
	c := NewNetlinkController(discardLogger())

	// Do runs its function on another goroutine, so the steps return their
	// error and the test fails here.
	in := func(what string, fn func() error) {
		t.Helper()
		if err := ns.Do(fn); err != nil {
			t.Fatalf("namespace %s: %s: %v", ns.Name, what, err)
		}
	}
	setUp := func(name, cidr string) {
		t.Helper()
		key := mustKey(t)
		in("set up "+name, func() error {
			if err := c.CreateInterface(name, key[:], 0); err != nil {
				return err
			}
			if err := c.ConfigureAddress(name, cidr); err != nil {
				return err
			}
			return c.SetInterfaceUp(name)
		})
	}

	setUp(meshLink, "10.98.0.1/24")
	in("route 172.16.5.0/24 through "+meshLink, func() error {
		link, err := netlink.LinkByName(meshLink)
		if err != nil {
			return err
		}
		_, dst, _ := net.ParseCIDR("172.16.5.0/24")
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Scope:     netlink.SCOPE_LINK,
			Protocol:  syscall.RTPROT_STATIC,
		})
	})

	checkMesh := func(when string) {
		t.Helper()
		addrs, routes := linkIPv4(t, ns, meshLink)
		if !slices.Equal(addrs, []string{"10.98.0.9/24"}) {
			t.Errorf("%s: %s holds %q, want 10.98.0.9/24 alone", when, meshLink, addrs)
		}
		var kept, connected bool
		for _, r := range routes {
			if r.Dst == nil {
				continue
			}
			switch r.Dst.String() {
			case "172.16.5.0/24":
				kept = true
			case "10.98.0.0/24":
				connected = true
				if !r.Src.Equal(net.IPv4(10, 98, 0, 9)) {
					t.Errorf("%s: the connected route 10.98.0.0/24 names source %v, want 10.98.0.9", when, r.Src)
				}
			}
		}
		if !kept {
			t.Errorf("%s: the route 172.16.5.0/24 through %s is gone, routes: %v", when, meshLink, routes)
		}
		if !connected {
			t.Errorf("%s: no connected route 10.98.0.0/24 through %s, routes: %v", when, meshLink, routes)
		}
	}

	in("replace 10.98.0.1/24", func() error { return c.ReplaceAddress(meshLink, "10.98.0.1/24", "10.98.0.9/24") })
	checkMesh("after the call")
	in("repeat the replace of 10.98.0.1/24", func() error { return c.ReplaceAddress(meshLink, "10.98.0.1/24", "10.98.0.9/24") })
	checkMesh("after the repeated call")

	checkHost := func(when string) {
		t.Helper()
		if addrs, _ := linkIPv4(t, ns, hostLink); !slices.Equal(addrs, []string{"10.98.1.9/32"}) {
			t.Errorf("%s: %s holds %q, want 10.98.1.9/32 alone", when, hostLink, addrs)
		}
	}

	setUp(hostLink, "10.98.1.1/32")
	in("replace 10.98.1.1/32", func() error { return c.ReplaceAddress(hostLink, "10.98.1.1/32", "10.98.1.9/32") })
	checkHost("after the call")
	in("repeat the replace of 10.98.1.1/32", func() error { return c.ReplaceAddress(hostLink, "10.98.1.1/32", "10.98.1.9/32") })
	checkHost("after the repeated call")
}
