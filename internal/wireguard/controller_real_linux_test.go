//go:build linux

package wireguard

import (
	"maps"
	"net"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

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
// An observer subscribes to the namespace's address events before the first
// link exists and keeps each link's addresses by address alone, without the
// prefix length, as systemd-resolved does. After the replace of
// 10.98.0.1/24 and after its repeat, the last event of the link must be the
// add of 10.98.0.9/24 and the observer must hold 10.98.0.9 alone. The calls
// before the announcement end with the delete of 10.98.0.9/32, which such an
// observer takes as the removal of 10.98.0.9. The /32 pair must leave it
// holding 10.98.1.9 alone. The observer reads the events one call caused up
// to a marker address it adds to lo afterwards: the kernel queues a call's
// events before the call returns.
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

	// The socket is opened inside Do, so it belongs to the namespace.
	updates := make(chan netlink.AddrUpdate, 64)
	done := make(chan struct{})
	in("subscribe to address events", func() error { return netlink.AddrSubscribe(updates, done) })
	t.Cleanup(func() { close(done) })

	// addrEvents returns the IPv4 address events of the named link since the
	// last call, up to the new-address event of a marker on lo.
	marker := &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(192, 0, 2, 1).To4(), Mask: net.CIDRMask(32, 32)}}
	addrEvents := func(name string) []netlink.AddrUpdate {
		t.Helper()
		var index int
		in("add the marker "+marker.IPNet.String()+" to lo", func() error {
			link, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			index = link.Attrs().Index
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return err
			}
			return netlink.AddrAdd(lo, marker)
		})
		var events []netlink.AddrUpdate
		timeout := time.After(5 * time.Second)
		for {
			select {
			case u, ok := <-updates:
				if !ok {
					t.Fatalf("namespace %s: the address events ended before the marker %s arrived", ns.Name, marker.IPNet)
				}
				if u.NewAddr && u.LinkAddress.String() == marker.IPNet.String() {
					in("delete the marker "+marker.IPNet.String()+" from lo", func() error {
						lo, err := netlink.LinkByName("lo")
						if err != nil {
							return err
						}
						return netlink.AddrDel(lo, marker)
					})
					return events
				}
				if u.LinkIndex == index && u.LinkAddress.IP.To4() != nil {
					events = append(events, u)
				}
			case <-timeout:
				t.Fatalf("namespace %s: the marker %s did not arrive within 5s", ns.Name, marker.IPNet)
			}
		}
	}

	// held keeps, per link, the addresses an observer holds that keys them by
	// address alone. observe folds the link's new events into it and returns
	// them as "new <cidr>" or "del <cidr>".
	held := map[string]map[string]bool{meshLink: {}, hostLink: {}}
	observe := func(name, when string) []string {
		t.Helper()
		var seq []string
		for _, u := range addrEvents(name) {
			if u.NewAddr {
				held[name][u.LinkAddress.IP.String()] = true
				seq = append(seq, "new "+u.LinkAddress.String())
			} else {
				delete(held[name], u.LinkAddress.IP.String())
				seq = append(seq, "del "+u.LinkAddress.String())
			}
		}
		t.Logf("%s: %s sent the address events %q, and an observer keyed by address holds %q", when, name, seq, slices.Sorted(maps.Keys(held[name])))
		return seq
	}
	checkHeld := func(name, when, want string) {
		t.Helper()
		if got := slices.Sorted(maps.Keys(held[name])); !slices.Equal(got, []string{want}) {
			t.Errorf("%s: an observer that keeps the addresses of %s without their prefix length holds %q, want %s alone", when, name, got, want)
		}
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
	observe(meshLink, "after the set-up")

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
		if seq := observe(meshLink, when); len(seq) == 0 || seq[len(seq)-1] != "new 10.98.0.9/24" {
			t.Errorf("%s: the last address event of %s is not new 10.98.0.9/24, events: %q", when, meshLink, seq)
		}
		checkHeld(meshLink, when, "10.98.0.9")
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
		observe(hostLink, when)
		checkHeld(hostLink, when, "10.98.1.9")
	}

	setUp(hostLink, "10.98.1.1/32")
	observe(hostLink, "after the set-up")
	in("replace 10.98.1.1/32", func() error { return c.ReplaceAddress(hostLink, "10.98.1.1/32", "10.98.1.9/32") })
	checkHost("after the call")
	in("repeat the replace of 10.98.1.1/32", func() error { return c.ReplaceAddress(hostLink, "10.98.1.1/32", "10.98.1.9/32") })
	checkHost("after the repeated call")
}
