//go:build linux

package bridge

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/vishvananda/netlink"
)

func discardLoggerRoute() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Compile-time check that NetlinkRouteController implements RouteController.
var _ RouteController = (*NetlinkRouteController)(nil)

func TestNewNetlinkRouteController(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())
	if ctrl == nil {
		t.Fatal("NewNetlinkRouteController returned nil")
	}
	if ctrl.logger == nil {
		t.Fatal("logger field is nil")
	}
}

func TestAddRouteInvalidCIDR(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.AddRoute("not-a-cidr", "lo")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}

	expected := "bridge: add route: parse CIDR"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveRouteInvalidCIDR(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.RemoveRoute("not-a-cidr", "lo")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}

	expected := "bridge: remove route: parse CIDR"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestAddRouteNonExistentInterface(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.AddRoute("10.99.0.0/24", "plexd-nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "bridge: add route: lookup interface"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveRouteNonExistentInterface(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.RemoveRoute("10.99.0.0/24", "plexd-nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "bridge: remove route: lookup interface"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestEnableForwardingRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.EnableForwarding("lo", "lo")
	if err == nil {
		// Succeeded — running as root. Restore.
		_ = ctrl.DisableForwarding("lo", "lo")
		return
	}

	expected := "bridge: enable forwarding:"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestDisableForwardingRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.DisableForwarding("lo", "lo")
	if err == nil {
		return
	}

	expected := "bridge: disable forwarding:"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestAddNATMasqueradeRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.AddNATMasquerade("lo")
	if err == nil {
		// Succeeded — running as root. Clean up.
		_ = ctrl.RemoveNATMasquerade("lo")
		return
	}

	expected := "bridge: add NAT masquerade"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveNATMasqueradeRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.RemoveNATMasquerade("lo")
	if err == nil {
		return
	}

	expected := "bridge: remove NAT masquerade"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestIfaceNameBytes(t *testing.T) {
	tests := []struct {
		name string
		want int // expected length including null terminator
	}{
		{"lo", 3},
		{"eth0", 5},
		{"plexd0", 7},
	}

	for _, tt := range tests {
		got := ifaceNameBytes(tt.name)
		if len(got) != tt.want {
			t.Errorf("ifaceNameBytes(%q) length = %d, want %d", tt.name, len(got), tt.want)
		}
		// Verify null terminator.
		if got[len(got)-1] != 0 {
			t.Errorf("ifaceNameBytes(%q) missing null terminator", tt.name)
		}
		// Verify the name content matches.
		if string(got[:len(got)-1]) != tt.name {
			t.Errorf("ifaceNameBytes(%q) content = %q, want %q", tt.name, got[:len(got)-1], tt.name)
		}
	}
}

func TestValidateIfaceName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"wg0", false},
		{"eth0", false},
		{"plexd-mesh", false},
		{"../etc/passwd", true},
		{"/dev/null", true},
		{"wg0\x00", true},
		{"", true},
		{"lo", false},
	}

	for _, tt := range tests {
		err := validateIfaceName(tt.name)
		if tt.wantErr && err == nil {
			t.Errorf("validateIfaceName(%q) expected error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("validateIfaceName(%q) unexpected error: %v", tt.name, err)
		}
	}
}


func TestAddRouteRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	// Adding a route via the loopback — requires CAP_NET_ADMIN.
	err := ctrl.AddRoute("10.99.0.0/24", "lo")
	if err == nil {
		// Succeeded — running as root. Clean up.
		_ = ctrl.RemoveRoute("10.99.0.0/24", "lo")
		return
	}

	expected := "bridge: add route"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveRouteNonExistentRouteIdempotent(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	// Removing a non-existent route via loopback.
	err := ctrl.RemoveRoute("10.99.99.0/24", "lo")
	if err == nil {
		// Idempotent success on root.
		return
	}

	// On non-root, we may get permission errors for the interface lookup
	// or ESRCH for the route — both are acceptable.
	expected := "bridge: remove route"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestAddAndRemoveRouteRoundTrip(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	subnet := "10.88.0.0/24"

	if err := ctrl.AddRoute(subnet, "lo"); err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}

	// Adding again should be idempotent.
	if err := ctrl.AddRoute(subnet, "lo"); err != nil {
		t.Fatalf("second AddRoute failed: %v", err)
	}

	if err := ctrl.RemoveRoute(subnet, "lo"); err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	// Removing again should be idempotent.
	if err := ctrl.RemoveRoute(subnet, "lo"); err != nil {
		t.Fatalf("second RemoveRoute failed: %v", err)
	}
}

func TestAddAndRemoveNATMasqueradeRoundTrip(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	if err := ctrl.AddNATMasquerade("lo"); err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}

	// Adding again should be idempotent (table/chain/rules are re-applied).
	if err := ctrl.AddNATMasquerade("lo"); err != nil {
		t.Fatalf("second AddNATMasquerade failed: %v", err)
	}

	if err := ctrl.RemoveNATMasquerade("lo"); err != nil {
		t.Fatalf("RemoveNATMasquerade failed: %v", err)
	}

	// Removing again should be idempotent.
	if err := ctrl.RemoveNATMasquerade("lo"); err != nil {
		t.Fatalf("second RemoveNATMasquerade failed: %v", err)
	}
}

// formatExprs renders expressions with their types and field values, so a
// mismatch shows what differs rather than two addresses.
func formatExprs(exprs []expr.Any) string {
	var b strings.Builder
	for i, e := range exprs {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%T%+v", e, reflect.Indirect(reflect.ValueOf(e)).Interface())
	}
	return "[" + b.String() + "]"
}

func assertExprs(t *testing.T, got, want []expr.Any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expressions differ\n got: %s\nwant: %s", formatExprs(got), formatExprs(want))
	}
}

// TestMeshSourceRewriteExprs pins the rule that rewrites the source of a
// packet from a user access interface into the mesh: the incoming interface
// name, then the outgoing one, each compared with its terminating NUL, a
// counter, and masquerade at the end.
func TestMeshSourceRewriteExprs(t *testing.T) {
	want := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("wg-ua-a0a0a0e1\x00")},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("plexd0\x00")},
		&expr.Counter{},
		&expr.Masq{},
	}
	assertExprs(t, meshSourceRewriteExprs("wg-ua-a0a0a0e1", "plexd0"), want)
}

// TestMeshSourceRewriteTag pins the tag as the comment TLV libnftnl writes
// (type 0, the length, the name and its NUL), which nft list ruleset shows as
// the rule's comment.
func TestMeshSourceRewriteTag(t *testing.T) {
	got := meshSourceRewriteTag("wg-ua-a0a0a0e1")

	want := append([]byte{byte(userdata.TypeComment), 15}, "wg-ua-a0a0a0e1\x00"...)
	if !bytes.Equal(got, want) {
		t.Errorf("meshSourceRewriteTag = %v, want %v", got, want)
	}
	if comment, ok := userdata.GetString(got, userdata.TypeComment); !ok || comment != "wg-ua-a0a0a0e1" {
		t.Errorf("comment = %q, %v; want %q, true", comment, ok, "wg-ua-a0a0a0e1")
	}
}

func TestFindMeshSourceRewrite(t *testing.T) {
	untagged := &nftables.Rule{Handle: 1}
	prefix := &nftables.Rule{Handle: 2, UserData: meshSourceRewriteTag("wg-ua-a0a0a0e")}
	provider := &nftables.Rule{Handle: 3, UserData: meshSourceRewriteTag("wg-ua-a0a0a0e1")}
	vendor := &nftables.Rule{Handle: 4, UserData: meshSourceRewriteTag("tailscale0")}
	rules := []*nftables.Rule{untagged, prefix, provider, vendor}

	tests := []struct {
		name      string
		rules     []*nftables.Rule
		fromIface string
		want      *nftables.Rule
	}{
		{"provider interface", rules, "wg-ua-a0a0a0e1", provider},
		{"vendor interface", rules, "tailscale0", vendor},
		{"tag is a prefix of another", rules, "wg-ua-a0a0a0e", prefix},
		{"no rule carries the tag", rules, "wt0", nil},
		{"no rules", nil, "wg-ua-a0a0a0e1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findMeshSourceRewrite(tt.rules, tt.fromIface); got != tt.want {
				t.Errorf("findMeshSourceRewrite(%q) = %+v, want %+v", tt.fromIface, got, tt.want)
			}
		})
	}
}

// TestAddMeshSourceRewriteRefusesInvalidInterfaceName covers the names
// ifaceNameBytes cannot encode. They are refused before any nftables call.
func TestAddMeshSourceRewriteRefusesInvalidInterfaceName(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	tests := []struct {
		name      string
		fromIface string
		meshIface string
	}{
		{"empty incoming", "", "plexd0"},
		{"empty outgoing", "wg-ua-a0a0a0e1", ""},
		{"incoming beyond IFNAMSIZ", "wg-ua-0123456789", "plexd0"},
		{"outgoing beyond IFNAMSIZ", "wg-ua-a0a0a0e1", "plexd0123456789a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ctrl.AddMeshSourceRewrite(tt.fromIface, tt.meshIface)
			if err == nil {
				t.Fatal("expected error for invalid interface name")
			}
			expected := "bridge: add mesh source rewrite: invalid interface name"
			if !strings.HasPrefix(err.Error(), expected) {
				t.Errorf("expected error prefix %q, got %q", expected, err.Error())
			}
		})
	}
}

// TestNetlinkRouteController_RealRoutes adds a route through a dummy link in
// a network namespace of its own and wants RemoveRoute to delete it from the
// kernel, not only to return nil. AddRoute installs the route with link
// scope, and the kernel deletes an IPv4 route only when the request names its
// scope or none, so a delete with the universe scope found nothing, answered
// ESRCH, and RemoveRoute took that for a route that was already gone. A
// peer's routed subnet is routed through the mesh interface, which outlives
// the route, so the route stayed after the pull that dropped the subnet.
//
// It also wants RemoveRoute to keep a route plexd did not add: the kernel's
// route to the link's own network, which AddRoute meets as EEXIST and takes
// for its own. A delete that matched it would cut the host off that network,
// an access LAN a bridge serves as one of its access_subnets, when the bridge
// stops.
//
// It shares the gate of TestNetlinkVPNController_RealLinks, which CI runs in
// the step "Run privileged Linux tests".
func TestNetlinkRouteController_RealRoutes(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to add real routes in a test network namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating a network namespace and routes needs root; run with sudo")
	}

	const (
		iface     = "plexd-rt0"
		subnet    = "10.40.0.0/16"
		connected = "10.41.0.0/16"
	)
	inOwnNetns(t, func() {
		la := netlink.NewLinkAttrs()
		la.Name = iface
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la}); err != nil {
			t.Fatalf("add dummy link %s: %v", iface, err)
		}
		link := mustLink(t, iface)
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatalf("set %s up: %v", iface, err)
		}
		addr, err := netlink.ParseAddr("10.41.0.1/16")
		if err != nil {
			t.Fatalf("ParseAddr: %v", err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatalf("address %s: %v", iface, err)
		}
		routes := func(cidr string) []netlink.Route {
			t.Helper()
			_, dst, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", cidr, err)
			}
			got, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
				&netlink.Route{Dst: dst, LinkIndex: link.Attrs().Index},
				netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
			if err != nil {
				t.Fatalf("list the routes to %s: %v", cidr, err)
			}
			return got
		}
		if got := routes(connected); len(got) != 1 {
			t.Fatalf("the kernel holds %d routes to %s, the network of %s, want its own one: %+v", len(got), connected, iface, got)
		}

		c := NewNetlinkRouteController(discardLoggerRoute())
		for range 2 {
			if err := c.AddRoute(subnet, iface); err != nil {
				t.Fatalf("AddRoute(%q, %q): %v", subnet, iface, err)
			}
		}
		if got := routes(subnet); len(got) != 1 {
			t.Fatalf("after AddRoute twice, the kernel holds %d routes to %s through %s, want 1: %+v", len(got), subnet, iface, got)
		}

		for range 2 {
			if err := c.RemoveRoute(subnet, iface); err != nil {
				t.Fatalf("RemoveRoute(%q, %q): %v", subnet, iface, err)
			}
		}
		if got := routes(subnet); len(got) != 0 {
			t.Fatalf("after RemoveRoute, the kernel still holds the route to %s through %s: %+v", subnet, iface, got)
		}

		// The kernel's route to the link's network: AddRoute meets it as
		// EEXIST, and RemoveRoute must leave it.
		if err := c.AddRoute(connected, iface); err != nil {
			t.Fatalf("AddRoute(%q, %q) over the kernel's route: %v", connected, iface, err)
		}
		if err := c.RemoveRoute(connected, iface); err != nil {
			t.Fatalf("RemoveRoute(%q, %q): %v", connected, iface, err)
		}
		if got := routes(connected); len(got) != 1 {
			t.Fatalf("after RemoveRoute, the kernel holds %d routes to %s, the network of %s, want its own one kept: %+v", len(got), connected, iface, got)
		}
	})
}
