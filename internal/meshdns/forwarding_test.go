package meshdns

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// testSelf is the listen address the forwarding tests give BuildForwarding,
// a mesh IP of the contract's example Domain that no host of exampleBlock
// holds.
var testSelf = netip.MustParseAddr("10.42.0.1")

// fwdZone is a forward zone of the forwarding member with resolvers.
func fwdZone(zone string, resolvers ...string) api.NodeStateDNSForwardZone {
	return api.NodeStateDNSForwardZone{Zone: zone, Resolvers: resolvers}
}

// mustForward builds setting against records with testSelf and fails the
// test when any entry was skipped.
func mustForward(t *testing.T, setting api.NodeStateDNSForwarding, records *Records) *Forwarding {
	t.Helper()
	f, skipped := BuildForwarding(setting, records, testSelf)
	if len(skipped) != 0 {
		t.Fatalf("BuildForwarding skipped %d entries, want none: %q", len(skipped), skipped)
	}
	return f
}

// addrs parses each of ss.
func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// routeCase is one name and where Route must send it: the resolvers and the
// zone, or nowhere when ok is false.
type routeCase struct {
	name      string
	resolvers []netip.Addr
	zone      string
	ok        bool
}

// to is a routeCase that Route sends to zone's resolvers.
func to(name, zone string, resolvers ...string) routeCase {
	return routeCase{name: name, resolvers: addrs(resolvers...), zone: zone, ok: true}
}

// nowhere is a routeCase that Route does not send anywhere.
func nowhere(name string) routeCase {
	return routeCase{name: name}
}

func runRoutes(t *testing.T, f *Forwarding, cases []routeCase) {
	t.Helper()
	for _, tc := range cases {
		resolvers, zone, ok := f.Route(tc.name)
		if !slices.Equal(resolvers, tc.resolvers) || zone != tc.zone || ok != tc.ok {
			t.Errorf("Route(%q) = %v, %q, %v, want %v, %q, %v", tc.name, resolvers, zone, ok, tc.resolvers, tc.zone, tc.ok)
		}
	}
}

func TestBuildForwarding_Accepts(t *testing.T) {
	records := mustBuild(t, exampleBlock())
	f := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{
			fwdZone("corp.example.com", "192.0.2.1"),
			// An Active Directory zone under local.
			fwdZone("corp.local", "192.0.2.2"),
			fwdZone("2.0.192.in-addr.arpa", "192.0.2.3"),
			fwdZone("corp", "192.0.2.4"),
			// Under another forward zone, with _ in a label.
			fwdZone("_msdcs.corp.example.com", "192.0.2.5"),
			// Above the mesh zones edge.example.com and lab.internal.
			fwdZone("example.com", "192.0.2.6"),
			fwdZone("internal", "2001:db8::53", "192.0.2.7"),
		},
		CatchAll: []string{"198.51.100.1", "2001:db8::1"},
	}, records)

	if got := f.ZoneCount(); got != 7 {
		t.Errorf("ZoneCount() = %d, want 7", got)
	}
	if got := f.CatchAllCount(); got != 2 {
		t.Errorf("CatchAllCount() = %d, want 2", got)
	}
	want := []string{"2.0.192.in-addr.arpa", "_msdcs.corp.example.com", "corp", "corp.example.com", "corp.local", "example.com", "internal"}
	if !slices.Equal(f.zones, want) {
		t.Errorf("zones = %q, want %q ascending", f.zones, want)
	}
	runRoutes(t, f, []routeCase{
		to("host.corp.example.com", "corp.example.com", "192.0.2.1"),
		to("dc.corp.local", "corp.local", "192.0.2.2"),
		to("7.2.0.192.in-addr.arpa", "2.0.192.in-addr.arpa", "192.0.2.3"),
		to("files.corp", "corp", "192.0.2.4"),
		to("_ldap._tcp._msdcs.corp.example.com", "_msdcs.corp.example.com", "192.0.2.5"),
		to("www.example.com", "example.com", "192.0.2.6"),
		to("ci.internal", "internal", "2001:db8::53", "192.0.2.7"),
		to("example.org", ".", "198.51.100.1", "2001:db8::1"),
	})
}

func TestBuildForwarding_SkipsForwardZones(t *testing.T) {
	records := mustBuild(t, exampleBlock())
	setting := api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{
			fwdZone("corp.example.com", "192.0.2.1"),
			// The name.
			fwdZone("", "192.0.2.1"),
			fwdZone("bad..zone", "192.0.2.1"),
			fwdZone("corp.example.org.", "192.0.2.1"),
			fwdZone("sp ace.example", "192.0.2.1"),
			// The reserved names themselves, folded.
			fwdZone("local", "192.0.2.1"),
			fwdZone("LocalHost", "192.0.2.1"),
			fwdZone("arpa", "192.0.2.1"),
			fwdZone("in-addr.arpa", "192.0.2.1"),
			fwdZone("ip6.arpa", "192.0.2.1"),
			// Under a reserved name.
			fwdZone("printer.localhost", "192.0.2.1"),
			fwdZone("1.e164.arpa", "192.0.2.1"),
			// Shadowed by a mesh zone or a reverse zone, the longest named.
			fwdZone("lab.internal", "192.0.2.1"),
			fwdZone("db.openstack.lab.internal", "192.0.2.1"),
			fwdZone("0.42.10.in-addr.arpa", "192.0.2.1"),
			// A repeat, folded.
			fwdZone("Corp.Example.Com", "192.0.2.9"),
			// No resolver.
			fwdZone("nil.example.com"),
			fwdZone("empty.example.com", []string{}...),
			// Two failed checks: the first one is reported.
			fwdZone("-bad.localhost", "192.0.2.1"),
			fwdZone("LAB.internal"),
			fwdZone("corp.example.com"),
		},
		CatchAll: []string{},
	}

	f, skipped := BuildForwarding(setting, records, testSelf)

	wantSkipped(t, skipped, []string{
		`forward zone "" is not a valid name because it is empty`,
		`forward zone "bad..zone" is not a valid name because it has an empty label`,
		`forward zone "corp.example.org." is not a valid name because it ends in a dot`,
		`forward zone "sp ace.example" is not a valid name because it has a character outside a-z, 0-9, - and _`,
		`forward zone "local" is local itself, which the contract rules out`,
		`forward zone "LocalHost" is localhost itself, which the contract rules out`,
		`forward zone "arpa" is arpa itself, which the contract rules out`,
		`forward zone "in-addr.arpa" is in-addr.arpa itself, which the contract rules out`,
		`forward zone "ip6.arpa" is ip6.arpa itself, which the contract rules out`,
		`forward zone "printer.localhost" is under localhost, which the contract rules out`,
		`forward zone "1.e164.arpa" is under arpa, which the contract rules out`,
		`forward zone "lab.internal" is shadowed by the mesh zone "lab.internal", which answers its names`,
		`forward zone "db.openstack.lab.internal" is shadowed by the mesh zone "openstack.lab.internal", which answers its names`,
		`forward zone "0.42.10.in-addr.arpa" is shadowed by the mesh zone "42.10.in-addr.arpa", which answers its names`,
		`forward zone "Corp.Example.Com" repeats an earlier forward zone`,
		`forward zone "nil.example.com" has no usable resolver`,
		`forward zone "empty.example.com" has no usable resolver`,
		`forward zone "-bad.localhost" is not a valid name because it has a label that starts or ends with -`,
		`forward zone "LAB.internal" is shadowed by the mesh zone "lab.internal", which answers its names`,
		`forward zone "corp.example.com" repeats an earlier forward zone`,
	})
	if want := []string{"corp.example.com"}; !slices.Equal(f.zones, want) {
		t.Errorf("zones = %q, want %q", f.zones, want)
	}
	// The repeat did not replace the first entry's resolvers.
	runRoutes(t, f, []routeCase{
		to("host.corp.example.com", "corp.example.com", "192.0.2.1"),
		nowhere("db.lab.internal"),
		nowhere("printer.localhost"),
		nowhere("host.empty.example.com"),
	})
}

// resolverValues holds one value for each row of the resolver checks, two
// that pass among them, and the sentences each owner gets for them, in
// order.
var resolverValues = []string{
	"192.0.2.1",
	// Not an IP address.
	"not-an-ip", "", "192.0.2.01", "192.0.2.0/24",
	// Not an address plexd forwards to.
	"fe80::1%eth0", "::ffff:192.0.2.9", "0.0.0.0", "::", "127.0.0.53", "::1",
	"224.0.0.251", "ff02::fb", "169.254.1.1", "fe80::1", "255.255.255.255",
	// The listen address.
	"10.42.0.1",
	// A repeat of a resolver accepted earlier.
	"192.0.2.1",
	"2001:db8::53",
	"2001:DB8::53",
}

func resolverSentences(owner string) []string {
	var out []string
	for _, v := range []string{"not-an-ip", "", "192.0.2.01", "192.0.2.0/24"} {
		out = append(out, fmt.Sprintf("resolver %q of %s is not an IP address", v, owner))
	}
	for _, v := range []string{"fe80::1%eth0", "::ffff:192.0.2.9", "0.0.0.0", "::", "127.0.0.53", "::1",
		"224.0.0.251", "ff02::fb", "169.254.1.1", "fe80::1", "255.255.255.255"} {
		out = append(out, fmt.Sprintf("resolver %q of %s is not an address plexd forwards to", v, owner))
	}
	out = append(out,
		fmt.Sprintf(`resolver "10.42.0.1" of %s is the resolver's own listen address`, owner),
		fmt.Sprintf(`resolver "192.0.2.1" of %s repeats an earlier resolver`, owner),
		fmt.Sprintf(`resolver "2001:DB8::53" of %s repeats an earlier resolver`, owner),
	)
	return out
}

func TestBuildForwarding_SkipsResolvers(t *testing.T) {
	f, skipped := BuildForwarding(api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{
			fwdZone("corp.example.com", resolverValues...),
			// Every resolver is skipped, so the zone is too, after them.
			fwdZone("dead.example.com", "127.0.0.1", "nope"),
			fwdZone("ops.example.com", "192.0.2.3"),
		},
		CatchAll: resolverValues,
	}, mustBuild(t, exampleBlock()), testSelf)

	var want []string
	want = append(want, resolverSentences(`forward zone "corp.example.com"`)...)
	want = append(want,
		`resolver "127.0.0.1" of forward zone "dead.example.com" is not an address plexd forwards to`,
		`resolver "nope" of forward zone "dead.example.com" is not an IP address`,
		`forward zone "dead.example.com" has no usable resolver`,
	)
	want = append(want, resolverSentences("the catch-all")...)
	wantSkipped(t, skipped, want)

	// The skipped resolvers cost only themselves: the others stay, in their
	// order.
	runRoutes(t, f, []routeCase{
		to("host.corp.example.com", "corp.example.com", "192.0.2.1", "2001:db8::53"),
		to("host.ops.example.com", "ops.example.com", "192.0.2.3"),
		to("host.dead.example.com", ".", "192.0.2.1", "2001:db8::53"),
	})
}

// The listen address is compared as the address it listens on, so an
// IPv4-mapped one refuses the IPv4 resolver it carries.
func TestBuildForwarding_MappedSelf(t *testing.T) {
	_, skipped := BuildForwarding(api.NodeStateDNSForwarding{
		CatchAll: []string{"10.42.0.1"},
	}, nil, netip.MustParseAddr("::ffff:10.42.0.1"))
	wantSkipped(t, skipped, []string{`resolver "10.42.0.1" of the catch-all is the resolver's own listen address`})
}

func TestBuildForwarding_Empty(t *testing.T) {
	tests := []struct {
		name    string
		setting api.NodeStateDNSForwarding
		records *Records
	}{
		{"two empty lists", api.NodeStateDNSForwarding{ForwardZones: []api.NodeStateDNSForwardZone{}, CatchAll: []string{}}, mustBuild(t, exampleBlock())},
		{"two nil lists", api.NodeStateDNSForwarding{}, mustBuild(t, exampleBlock())},
		{"nil records", api.NodeStateDNSForwarding{}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, skipped := BuildForwarding(tc.setting, tc.records, testSelf)
			if f == nil {
				t.Fatal("BuildForwarding() = nil, want an empty table")
			}
			wantSkipped(t, skipped, nil)
			if f.ZoneCount() != 0 || f.CatchAllCount() != 0 {
				t.Errorf("ZoneCount(), CatchAllCount() = %d, %d, want 0, 0", f.ZoneCount(), f.CatchAllCount())
			}
			if !f.Equal(nil) {
				t.Errorf("Equal(nil) = false, want true for a table that forwards nothing")
			}
			runRoutes(t, f, []routeCase{nowhere("host.corp.example.com"), nowhere("example.org"), nowhere(".")})
		})
	}

	// Without records nothing is shadowed: every zone is a forward zone.
	f := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{fwdZone("lab.internal", "192.0.2.1")},
	}, nil)
	runRoutes(t, f, []routeCase{to("db.lab.internal", "lab.internal", "192.0.2.1")})

	_, skipped := BuildForwarding(api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{{Zone: "corp.example.com", Resolvers: []string{}}},
		CatchAll:     []string{},
	}, nil, testSelf)
	wantSkipped(t, skipped, []string{`forward zone "corp.example.com" has no usable resolver`})
}

func TestForwarding_Route(t *testing.T) {
	zones := []api.NodeStateDNSForwardZone{
		fwdZone("corp.example.com", "192.0.2.1", "192.0.2.2"),
		fwdZone("DC1.Corp.Example.Com", "192.0.2.3"),
	}
	without := mustForward(t, api.NodeStateDNSForwarding{ForwardZones: zones, CatchAll: []string{}}, nil)
	with := mustForward(t, api.NodeStateDNSForwarding{ForwardZones: zones, CatchAll: []string{"198.51.100.1"}}, nil)

	inZones := []routeCase{
		// The longest of two nested zones.
		to("host.dc1.corp.example.com", "dc1.corp.example.com", "192.0.2.3"),
		to("dc1.corp.example.com", "dc1.corp.example.com", "192.0.2.3"),
		to("host.corp.example.com", "corp.example.com", "192.0.2.1", "192.0.2.2"),
		to("corp.example.com", "corp.example.com", "192.0.2.1", "192.0.2.2"),
		// Case and one trailing dot do not matter.
		to("HOST.Dc1.CORP.example.COM.", "dc1.corp.example.com", "192.0.2.3"),
		to("host.corp.example.com.", "corp.example.com", "192.0.2.1", "192.0.2.2"),
	}
	// Names under no forward zone: label-wise, xcorp.example.com is not
	// under corp.example.com, and only one trailing dot is dropped.
	outside := []string{"xcorp.example.com", "example.com", "host.corp.example.com..", "example.org.", "."}

	t.Run("without a catch-all", func(t *testing.T) {
		cases := slices.Clone(inZones)
		for _, name := range outside {
			cases = append(cases, nowhere(name))
		}
		runRoutes(t, without, cases)
	})
	t.Run("with a catch-all", func(t *testing.T) {
		cases := slices.Clone(inZones)
		for _, name := range outside {
			cases = append(cases, to(name, ".", "198.51.100.1"))
		}
		runRoutes(t, with, cases)
	})
	t.Run("nil table", func(t *testing.T) {
		runRoutes(t, nil, []routeCase{nowhere("host.corp.example.com"), nowhere("example.org")})
	})
}

func TestForwarding_Equal(t *testing.T) {
	setting := func(f func(*api.NodeStateDNSForwarding)) *Forwarding {
		s := api.NodeStateDNSForwarding{
			ForwardZones: []api.NodeStateDNSForwardZone{
				fwdZone("corp.example.com", "192.0.2.1", "192.0.2.2"),
				fwdZone("ops.example.com", "192.0.2.3"),
			},
			CatchAll: []string{"198.51.100.1", "198.51.100.2"},
		}
		if f != nil {
			f(&s)
		}
		return mustForward(t, s, nil)
	}
	base := setting(nil)
	empty := mustForward(t, api.NodeStateDNSForwarding{ForwardZones: []api.NodeStateDNSForwardZone{}, CatchAll: []string{}}, nil)

	tests := []struct {
		name  string
		other *Forwarding
		want  bool
	}{
		{"same setting", setting(nil), true},
		{"zone order and case", setting(func(s *api.NodeStateDNSForwarding) {
			s.ForwardZones = []api.NodeStateDNSForwardZone{
				fwdZone("Ops.Example.Com", "192.0.2.3"),
				fwdZone("corp.example.com", "192.0.2.1", "192.0.2.2"),
			}
		}), true},
		{"one resolver", setting(func(s *api.NodeStateDNSForwarding) { s.ForwardZones[1].Resolvers = []string{"192.0.2.4"} }), false},
		{"resolver order", setting(func(s *api.NodeStateDNSForwarding) { slices.Reverse(s.ForwardZones[0].Resolvers) }), false},
		{"zone added", setting(func(s *api.NodeStateDNSForwarding) {
			s.ForwardZones = append(s.ForwardZones, fwdZone("dev.example.com", "192.0.2.3"))
		}), false},
		{"zone renamed", setting(func(s *api.NodeStateDNSForwarding) { s.ForwardZones[1].Zone = "dev.example.com" }), false},
		{"catch-all order", setting(func(s *api.NodeStateDNSForwarding) { slices.Reverse(s.CatchAll) }), false},
		{"catch-all removed", setting(func(s *api.NodeStateDNSForwarding) { s.CatchAll = nil }), false},
		{"empty", empty, false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := base.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
			if got := tc.other.Equal(base); got != tc.want {
				t.Errorf("Equal() reversed = %v, want %v", got, tc.want)
			}
		})
	}

	var none *Forwarding
	if !none.Equal(nil) || !none.Equal(empty) || !empty.Equal(none) {
		t.Errorf("nil and empty tables compare unequal, want equal: a node that never forwards logs no change")
	}
	catchAllOnly := mustForward(t, api.NodeStateDNSForwarding{CatchAll: []string{"198.51.100.1"}}, nil)
	if none.Equal(catchAllOnly) || catchAllOnly.Equal(none) {
		t.Errorf("nil table equals one with a catch-all, want unequal")
	}
}

func TestForwarding_CountsOnNil(t *testing.T) {
	var f *Forwarding
	if f.ZoneCount() != 0 || f.CatchAllCount() != 0 {
		t.Errorf("ZoneCount(), CatchAllCount() on nil = %d, %d, want 0, 0", f.ZoneCount(), f.CatchAllCount())
	}
}
