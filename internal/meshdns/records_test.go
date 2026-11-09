package meshdns

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/plexsphere/plexd/internal/api"
)

// exampleBlock returns the dns block of the "Mesh DNS names" section of
// plexsphere's agent contract: the Domain lab with the mesh CIDR
// 10.42.0.0/16, its default domain lab.internal, the Project openstack with
// the zone openstack.lab.internal, and the Project edge with the zone
// override edge.example.com, as pulled by a node in openstack.
func exampleBlock() api.NodeStateDNS {
	return api.NodeStateDNS{
		SearchDomain: "openstack.lab.internal",
		Zones:        []string{"edge.example.com", "lab.internal", "openstack.lab.internal"},
		Hosts: []api.NodeStateDNSHost{
			{NodeID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d2", FQDN: "db-1.openstack.lab.internal", MeshIP: "10.42.0.3"},
			{NodeID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d3", FQDN: "gw.edge.example.com", MeshIP: "10.42.0.9"},
			{NodeID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", FQDN: "web.openstack.lab.internal", MeshIP: "10.42.0.2"},
		},
		ReverseZones: []string{"42.10.in-addr.arpa"},
	}
}

// mustBuild builds block and fails the test when any entry was skipped.
func mustBuild(t *testing.T, block api.NodeStateDNS) *Records {
	t.Helper()
	r, skipped := BuildRecords(block)
	if len(skipped) != 0 {
		t.Fatalf("BuildRecords skipped %d entries, want none: %q", len(skipped), skipped)
	}
	return r
}

// lookupCase is one query against a set of records and the answer it must
// get, compared as a whole.
type lookupCase struct {
	name  string
	qtype dnsmessage.Type
	want  Answer
}

func runLookups(t *testing.T, r *Records, cases []lookupCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s %v", tc.name, tc.qtype), func(t *testing.T) {
			if got := r.Lookup(tc.name, tc.qtype); got != tc.want {
				t.Errorf("Lookup(%q, %v) = %+v, want %+v", tc.name, tc.qtype, got, tc.want)
			}
		})
	}
}

func found(zone, addr string) Answer {
	return Answer{Result: ResultFound, Zone: zone, Addr: netip.MustParseAddr(addr)}
}

func foundPTR(zone, target string) Answer {
	return Answer{Result: ResultFound, Zone: zone, Target: target}
}

func noData(zone string) Answer   { return Answer{Result: ResultNoData, Zone: zone} }
func nxDomain(zone string) Answer { return Answer{Result: ResultNXDomain, Zone: zone} }

var refused = Answer{Result: ResultRefused}

func TestBuildRecords_ContractExample(t *testing.T) {
	r := mustBuild(t, exampleBlock())

	runLookups(t, r, []lookupCase{
		{"db-1.openstack.lab.internal", dnsmessage.TypeA, found("openstack.lab.internal", "10.42.0.3")},
		{"3.0.42.10.in-addr.arpa", dnsmessage.TypePTR, foundPTR("42.10.in-addr.arpa", "db-1.openstack.lab.internal")},
		{"DB-1.OpenStack.Lab.Internal", dnsmessage.TypeA, found("openstack.lab.internal", "10.42.0.3")},
		{"db-1.openstack.lab.internal.", dnsmessage.TypeA, found("openstack.lab.internal", "10.42.0.3")},
		{"web.openstack.lab.internal", dnsmessage.TypeA, found("openstack.lab.internal", "10.42.0.2")},
		{"gw.edge.example.com", dnsmessage.TypeA, found("edge.example.com", "10.42.0.9")},
		{"2.0.42.10.in-addr.arpa.", dnsmessage.TypePTR, foundPTR("42.10.in-addr.arpa", "web.openstack.lab.internal")},
		{"9.0.42.10.IN-ADDR.ARPA", dnsmessage.TypePTR, foundPTR("42.10.in-addr.arpa", "gw.edge.example.com")},
	})

	if got := r.SearchDomain(); got != "openstack.lab.internal" {
		t.Errorf("SearchDomain() = %q, want %q", got, "openstack.lab.internal")
	}
	if got := r.HostCount(); got != 3 {
		t.Errorf("HostCount() = %d, want 3", got)
	}
	if got := r.ZoneCount(); got != 3 {
		t.Errorf("ZoneCount() = %d, want 3", got)
	}
	if got := r.ReverseZoneCount(); got != 1 {
		t.Errorf("ReverseZoneCount() = %d, want 1", got)
	}
}

func TestRecords_LookupNegative(t *testing.T) {
	r := mustBuild(t, exampleBlock())

	runLookups(t, r, []lookupCase{
		// A host asked for a type it has no record of.
		{"db-1.openstack.lab.internal", dnsmessage.TypeAAAA, noData("openstack.lab.internal")},
		{"db-1.openstack.lab.internal", dnsmessage.TypeTXT, noData("openstack.lab.internal")},
		{"db-1.openstack.lab.internal", dnsmessage.TypeMX, noData("openstack.lab.internal")},
		{"db-1.openstack.lab.internal", dnsmessage.TypePTR, noData("openstack.lab.internal")},
		{"db-1.openstack.lab.internal", dnsmessage.TypeSOA, noData("openstack.lab.internal")},
		{"3.0.42.10.in-addr.arpa", dnsmessage.TypeA, noData("42.10.in-addr.arpa")},
		// A zone or reverse zone itself answers SOA and nothing else.
		{"lab.internal", dnsmessage.TypeA, noData("lab.internal")},
		{"openstack.lab.internal", dnsmessage.TypeAAAA, noData("openstack.lab.internal")},
		{"edge.example.com", dnsmessage.TypeMX, noData("edge.example.com")},
		{"42.10.in-addr.arpa", dnsmessage.TypePTR, noData("42.10.in-addr.arpa")},
		{"lab.internal", dnsmessage.TypeSOA, Answer{Result: ResultFound, Zone: "lab.internal"}},
		{"OpenStack.Lab.Internal.", dnsmessage.TypeSOA, Answer{Result: ResultFound, Zone: "openstack.lab.internal"}},
		{"42.10.in-addr.arpa", dnsmessage.TypeSOA, Answer{Result: ResultFound, Zone: "42.10.in-addr.arpa"}},
		// An empty non-terminal: a reverse name lies below it.
		{"0.42.10.in-addr.arpa", dnsmessage.TypePTR, noData("42.10.in-addr.arpa")},
		// A name nothing holds, under the longest matching zone.
		{"nope.openstack.lab.internal", dnsmessage.TypeA, nxDomain("openstack.lab.internal")},
		{"nope.lab.internal", dnsmessage.TypeA, nxDomain("lab.internal")},
		{"x.db-1.openstack.lab.internal", dnsmessage.TypeA, nxDomain("openstack.lab.internal")},
		{"9.9.42.10.in-addr.arpa", dnsmessage.TypePTR, nxDomain("42.10.in-addr.arpa")},
		{"4.0.42.10.in-addr.arpa", dnsmessage.TypePTR, nxDomain("42.10.in-addr.arpa")},
		// Outside every zone and reverse zone.
		{"example.com", dnsmessage.TypeA, refused},
		{"1.0.43.10.in-addr.arpa", dnsmessage.TypePTR, refused},
		{"xlab.internal", dnsmessage.TypeA, refused},
		{"internal", dnsmessage.TypeA, refused},
		{"10.in-addr.arpa", dnsmessage.TypeSOA, refused},
		{"", dnsmessage.TypeA, refused},
		{".", dnsmessage.TypeSOA, refused},
		{"lab.internal..", dnsmessage.TypeSOA, refused},
	})
}

func TestRecords_LookupNestedZone(t *testing.T) {
	r := mustBuild(t, api.NodeStateDNS{
		Zones: []string{"lab.internal", "a.b.lab.internal"},
		Hosts: []api.NodeStateDNSHost{
			{NodeID: "n1", FQDN: "h.a.b.lab.internal", MeshIP: "10.42.1.1"},
		},
		ReverseZones: []string{},
	})

	runLookups(t, r, []lookupCase{
		// b.lab.internal holds nothing, but the zone a.b.lab.internal lies
		// below it, so it exists.
		{"b.lab.internal", dnsmessage.TypeA, noData("lab.internal")},
		{"b.lab.internal", dnsmessage.TypeSOA, noData("lab.internal")},
		{"c.b.lab.internal", dnsmessage.TypeA, nxDomain("lab.internal")},
		{"a.b.lab.internal", dnsmessage.TypeSOA, Answer{Result: ResultFound, Zone: "a.b.lab.internal"}},
		{"h.a.b.lab.internal", dnsmessage.TypeA, found("a.b.lab.internal", "10.42.1.1")},
		{"x.a.b.lab.internal", dnsmessage.TypeA, nxDomain("a.b.lab.internal")},
	})
}

// fd00::/48 is the contract's example of an IPv6 mesh CIDR, and
// 0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa its reverse zone.
func TestRecords_IPv6(t *testing.T) {
	r := mustBuild(t, api.NodeStateDNS{
		SearchDomain: "lab.internal",
		Zones:        []string{"lab.internal"},
		Hosts: []api.NodeStateDNSHost{
			{NodeID: "n1", FQDN: "v6.lab.internal", MeshIP: "fd00::2"},
			{NodeID: "n2", FQDN: "v6-upper.lab.internal", MeshIP: "FD00::1:ABCD"},
		},
		ReverseZones: []string{"0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"},
	})

	const zone = "0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"
	v6PTR := "2.0." + strings.Repeat("0.", 28) + "d.f.ip6.arpa"
	upperPTR := "d.c.b.a.1.0.0.0." + strings.Repeat("0.", 22) + "d.f.ip6.arpa"
	outsidePTR := "2.0." + strings.Repeat("0.", 26) + "1.0.d.f.ip6.arpa"

	runLookups(t, r, []lookupCase{
		{"v6.lab.internal", dnsmessage.TypeAAAA, found("lab.internal", "fd00::2")},
		{"v6.lab.internal", dnsmessage.TypeA, noData("lab.internal")},
		{"v6-upper.lab.internal", dnsmessage.TypeAAAA, found("lab.internal", "fd00::1:abcd")},
		{v6PTR, dnsmessage.TypePTR, foundPTR(zone, "v6.lab.internal")},
		{strings.ToUpper(v6PTR) + ".", dnsmessage.TypePTR, foundPTR(zone, "v6.lab.internal")},
		{upperPTR, dnsmessage.TypePTR, foundPTR(zone, "v6-upper.lab.internal")},
		{v6PTR, dnsmessage.TypeAAAA, noData(zone)},
		{"3.0." + strings.Repeat("0.", 28) + "d.f.ip6.arpa", dnsmessage.TypePTR, nxDomain(zone)},
		{zone, dnsmessage.TypeSOA, Answer{Result: ResultFound, Zone: zone}},
		{outsidePTR, dnsmessage.TypePTR, refused},
	})
}

func TestBuildRecords_UnmapsIPv4MappedMeshIP(t *testing.T) {
	r := mustBuild(t, api.NodeStateDNS{
		Zones: []string{"lab.internal"},
		Hosts: []api.NodeStateDNSHost{
			{NodeID: "n1", FQDN: "mapped.lab.internal", MeshIP: "::ffff:10.42.0.7"},
		},
		ReverseZones: []string{"42.10.in-addr.arpa"},
	})

	runLookups(t, r, []lookupCase{
		{"mapped.lab.internal", dnsmessage.TypeA, found("lab.internal", "10.42.0.7")},
		{"mapped.lab.internal", dnsmessage.TypeAAAA, noData("lab.internal")},
		{"7.0.42.10.in-addr.arpa", dnsmessage.TypePTR, foundPTR("42.10.in-addr.arpa", "mapped.lab.internal")},
	})
}

// Two hosts may share an address only through a control plane bug. Both keep
// their name, and the reverse name answers the first, so a later entry cannot
// take an address over. A host whose address lies outside every accepted
// reverse zone has no PTR.
func TestBuildRecords_ReverseNames(t *testing.T) {
	r := mustBuild(t, api.NodeStateDNS{
		Zones: []string{"lab.internal"},
		Hosts: []api.NodeStateDNSHost{
			{NodeID: "n1", FQDN: "a.lab.internal", MeshIP: "10.42.0.5"},
			{NodeID: "n2", FQDN: "b.lab.internal", MeshIP: "10.42.0.5"},
			{NodeID: "n3", FQDN: "c.lab.internal", MeshIP: "10.43.0.1"},
		},
		ReverseZones: []string{"42.10.in-addr.arpa"},
	})

	runLookups(t, r, []lookupCase{
		{"a.lab.internal", dnsmessage.TypeA, found("lab.internal", "10.42.0.5")},
		{"b.lab.internal", dnsmessage.TypeA, found("lab.internal", "10.42.0.5")},
		{"5.0.42.10.in-addr.arpa", dnsmessage.TypePTR, foundPTR("42.10.in-addr.arpa", "a.lab.internal")},
		{"c.lab.internal", dnsmessage.TypeA, found("lab.internal", "10.43.0.1")},
		{"1.0.43.10.in-addr.arpa", dnsmessage.TypePTR, refused},
	})
}

// 10.64.0.0/20 is the contract's example of a mesh CIDR that takes 16 reverse
// zones. None of them may be merged into 64.10.in-addr.arpa, which would deny
// the addresses outside the mesh.
func TestRecords_SixteenReverseZones(t *testing.T) {
	var reverse []string
	for i := range 16 {
		reverse = append(reverse, fmt.Sprintf("%d.64.10.in-addr.arpa", i))
	}
	r := mustBuild(t, api.NodeStateDNS{
		SearchDomain: "lab.internal",
		Zones:        []string{"lab.internal"},
		Hosts: []api.NodeStateDNSHost{
			{NodeID: "n1", FQDN: "first.lab.internal", MeshIP: "10.64.0.1"},
			{NodeID: "n2", FQDN: "last.lab.internal", MeshIP: "10.64.15.254"},
			{NodeID: "n3", FQDN: "outside.lab.internal", MeshIP: "10.64.16.1"},
		},
		ReverseZones: reverse,
	})

	if got := r.ReverseZoneCount(); got != 16 {
		t.Errorf("ReverseZoneCount() = %d, want 16", got)
	}
	runLookups(t, r, []lookupCase{
		{"1.0.64.10.in-addr.arpa", dnsmessage.TypePTR, foundPTR("0.64.10.in-addr.arpa", "first.lab.internal")},
		{"254.15.64.10.in-addr.arpa", dnsmessage.TypePTR, foundPTR("15.64.10.in-addr.arpa", "last.lab.internal")},
		{"1.7.64.10.in-addr.arpa", dnsmessage.TypePTR, nxDomain("7.64.10.in-addr.arpa")},
		{"1.16.64.10.in-addr.arpa", dnsmessage.TypePTR, refused},
		{"64.10.in-addr.arpa", dnsmessage.TypeSOA, refused},
	})

	reg := r.Registration("plexd0", netip.MustParseAddrPort("10.64.0.1:5354"))
	want := slices.Sorted(slices.Values(reverse))
	if !slices.Equal(reg.RoutingDomains, want) {
		t.Errorf("RoutingDomains = %q, want %q", reg.RoutingDomains, want)
	}
	if reg.SearchDomain != "lab.internal" {
		t.Errorf("SearchDomain = %q, want %q", reg.SearchDomain, "lab.internal")
	}
}

// A block with four empty lists is a Domain without names: the node answers
// nothing and registers nothing.
func TestBuildRecords_EmptyBlock(t *testing.T) {
	r, skipped := BuildRecords(api.NodeStateDNS{
		SearchDomain: "",
		Zones:        []string{},
		Hosts:        []api.NodeStateDNSHost{},
		ReverseZones: []string{},
	})
	if r == nil {
		t.Fatal("BuildRecords returned nil records, want an empty set")
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %q, want none", skipped)
	}
	assertAnswersNothing(t, r)

	reg := r.Registration("plexd0", netip.MustParseAddrPort("10.42.0.3:5354"))
	if !reg.Empty() {
		t.Errorf("Registration() = %+v, want an empty registration", reg)
	}
	if reg.Interface != "plexd0" || reg.Server != netip.MustParseAddrPort("10.42.0.3:5354") {
		t.Errorf("Registration() = %+v, want Interface plexd0 and Server 10.42.0.3:5354", reg)
	}
	if r.HostCount() != 0 || r.ZoneCount() != 0 || r.ReverseZoneCount() != 0 || r.SearchDomain() != "" {
		t.Errorf("counts = %d hosts, %d zones, %d reverse zones, search domain %q, want all empty",
			r.HostCount(), r.ZoneCount(), r.ReverseZoneCount(), r.SearchDomain())
	}
}

// The server holds nil before the first block, so a nil *Records must answer
// like an empty one.
func TestRecords_NilAnswersRefused(t *testing.T) {
	var r *Records
	assertAnswersNothing(t, r)

	reg := r.Registration("plexd0", netip.MustParseAddrPort("10.42.0.3:5354"))
	if !reg.Empty() {
		t.Errorf("Registration() = %+v, want an empty registration", reg)
	}
	if r.HostCount() != 0 || r.ZoneCount() != 0 || r.ReverseZoneCount() != 0 || r.SearchDomain() != "" {
		t.Errorf("counts = %d hosts, %d zones, %d reverse zones, search domain %q, want all empty",
			r.HostCount(), r.ZoneCount(), r.ReverseZoneCount(), r.SearchDomain())
	}
}

func assertAnswersNothing(t *testing.T, r *Records) {
	t.Helper()
	names := []string{
		"", ".", "lab.internal", "db-1.openstack.lab.internal", "example.com.",
		"3.0.42.10.in-addr.arpa", "in-addr.arpa", "arpa", "localhost",
	}
	types := []dnsmessage.Type{
		dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypePTR,
		dnsmessage.TypeSOA, dnsmessage.TypeTXT, dnsmessage.TypeALL,
	}
	for _, name := range names {
		for _, qtype := range types {
			if got := r.Lookup(name, qtype); got != refused {
				t.Errorf("Lookup(%q, %v) = %+v, want %+v", name, qtype, got, refused)
			}
		}
	}
}

func TestBuildRecords_SkipsInvalidEntries(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)
	if len(long) != 254 {
		t.Fatalf("long name has %d characters, want 254", len(long))
	}

	block := exampleBlock()
	block.Zones = append(block.Zones,
		"", "local", "printer.local", "localhost", "arpa", "10.in-addr.arpa", "bad..zone", long,
		// Duplicates are kept once, without a sentence.
		"lab.internal", "Lab.Internal",
	)
	block.ReverseZones = append(block.ReverseZones,
		"lab.internal", "", "in-addr.arpa",
		"42.10.in-addr.arpa",
	)
	block.Hosts = append(block.Hosts,
		api.NodeStateDNSHost{NodeID: "n-zone", FQDN: "lab.internal", MeshIP: "10.42.0.20"},
		api.NodeStateDNSHost{NodeID: "n-outside", FQDN: "db-2.example.org", MeshIP: "10.42.0.21"},
		api.NodeStateDNSHost{NodeID: "n-bad-ip", FQDN: "bad-ip.lab.internal", MeshIP: "not-an-ip"},
		api.NodeStateDNSHost{NodeID: "n-no-ip", FQDN: "no-ip.lab.internal", MeshIP: ""},
		api.NodeStateDNSHost{NodeID: "n-dup", FQDN: "db-1.openstack.lab.internal", MeshIP: "10.42.0.22"},
		api.NodeStateDNSHost{NodeID: "n-invalid", FQDN: "under_score.lab.internal", MeshIP: "10.42.0.23"},
		api.NodeStateDNSHost{NodeID: "n-local", FQDN: "laser.printer.local", MeshIP: "10.42.0.24"},
	)

	r, skipped := BuildRecords(block)

	want := []string{
		`zone "" is not a valid name because it is empty`,
		`zone "local" is local itself, which the contract rules out`,
		`zone "printer.local" is under local, which the contract rules out`,
		`zone "localhost" is localhost itself, which the contract rules out`,
		`zone "arpa" is arpa itself, which the contract rules out`,
		`zone "10.in-addr.arpa" is under arpa, which the contract rules out`,
		`zone "bad..zone" is not a valid name because it has an empty label`,
		fmt.Sprintf(`zone %q is not a valid name because it has more than 253 characters`, long),
		`reverse zone "lab.internal" does not end in .in-addr.arpa or .ip6.arpa`,
		`reverse zone "" is not a valid name because it is empty`,
		`reverse zone "in-addr.arpa" does not end in .in-addr.arpa or .ip6.arpa`,
		`host "lab.internal" of node "n-zone" is the zone itself, and a host must lie at least one label below its zone`,
		`host "db-2.example.org" of node "n-outside" lies under no accepted zone`,
		`host "bad-ip.lab.internal" of node "n-bad-ip" has mesh_ip "not-an-ip", which is not an IP address`,
		`host "no-ip.lab.internal" of node "n-no-ip" has mesh_ip "", which is not an IP address`,
		`host "db-1.openstack.lab.internal" of node "n-dup" repeats the fqdn of node "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d2"`,
		`host "under_score.lab.internal" of node "n-invalid" is not a valid name because it has a character outside a-z, 0-9 and -`,
		`host "laser.printer.local" of node "n-local" lies under no accepted zone`,
	}
	if !slices.Equal(skipped, want) {
		t.Errorf("skipped has %d sentences, want %d", len(skipped), len(want))
		for i := range max(len(skipped), len(want)) {
			var got, exp string
			if i < len(skipped) {
				got = skipped[i]
			}
			if i < len(want) {
				exp = want[i]
			}
			if got != exp {
				t.Errorf("skipped[%d] = %q, want %q", i, got, exp)
			}
		}
	}

	if got := r.ZoneCount(); got != 3 {
		t.Errorf("ZoneCount() = %d, want 3", got)
	}
	if got := r.ReverseZoneCount(); got != 1 {
		t.Errorf("ReverseZoneCount() = %d, want 1", got)
	}
	if got := r.HostCount(); got != 3 {
		t.Errorf("HostCount() = %d, want 3", got)
	}
	runLookups(t, r, []lookupCase{
		// The valid entries still answer.
		{"db-1.openstack.lab.internal", dnsmessage.TypeA, found("openstack.lab.internal", "10.42.0.3")},
		{"web.openstack.lab.internal", dnsmessage.TypeA, found("openstack.lab.internal", "10.42.0.2")},
		{"gw.edge.example.com", dnsmessage.TypeA, found("edge.example.com", "10.42.0.9")},
		{"3.0.42.10.in-addr.arpa", dnsmessage.TypePTR, foundPTR("42.10.in-addr.arpa", "db-1.openstack.lab.internal")},
		// The skipped ones do not.
		{"lab.internal", dnsmessage.TypeA, noData("lab.internal")},
		{"bad-ip.lab.internal", dnsmessage.TypeA, nxDomain("lab.internal")},
		{"no-ip.lab.internal", dnsmessage.TypeA, nxDomain("lab.internal")},
		{"22.0.42.10.in-addr.arpa", dnsmessage.TypePTR, nxDomain("42.10.in-addr.arpa")},
		{"printer.local", dnsmessage.TypeSOA, refused},
		{"laser.printer.local", dnsmessage.TypeA, refused},
		{"localhost", dnsmessage.TypeA, refused},
		{"1.0.0.10.in-addr.arpa", dnsmessage.TypePTR, refused},
		{"foo.lab.internal.in-addr.arpa", dnsmessage.TypePTR, refused},
	})
}

func TestInvalidName(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("d", 61)
	tests := []struct {
		name string
		want string
	}{
		{"lab.internal", ""},
		{"db-1.openstack.lab.internal", ""},
		{"0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", ""},
		{"x", ""},
		{label63 + ".internal", ""},
		{name253, ""},
		{"", "is empty"},
		{name253 + "d", "has more than 253 characters"},
		{"lab.internal.", "ends in a dot"},
		{".lab.internal", "has an empty label"},
		{"bad..zone", "has an empty label"},
		{label63 + "a.internal", "has a label of more than 63 characters"},
		{"-lab.internal", "has a label that starts or ends with -"},
		{"lab-.internal", "has a label that starts or ends with -"},
		{"under_score.internal", "has a character outside a-z, 0-9 and -"},
		{"Lab.internal", "has a character outside a-z, 0-9 and -"},
		{"lab internal", "has a character outside a-z, 0-9 and -"},
		{"läb.internal", "has a character outside a-z, 0-9 and -"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := invalidName(tt.name); got != tt.want {
				t.Errorf("invalidName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// DNS folds ASCII letters only. The Kelvin sign folds to k under Unicode
// rules, so strings.ToLower would let "K" name the same zone as "k".
func TestFoldName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"lab.internal", "lab.internal"},
		{"DB-1.OpenStack.Lab.Internal", "db-1.openstack.lab.internal"},
		{"K.lab.internal", "K.lab.internal"},
		{"\xff.LAB", "\xff.lab"},
	}
	for _, tt := range tests {
		if got := foldName(tt.in); got != tt.want {
			t.Errorf("foldName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReverseName(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"10.42.0.3", "3.0.42.10.in-addr.arpa"},
		{"192.0.2.255", "255.2.0.192.in-addr.arpa"},
		// The example of RFC 3596, section 2.5.
		{"4321:0:1:2:3:4:567:89ab", "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa"},
	}
	for _, tt := range tests {
		if got := reverseName(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("reverseName(%s) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestRecords_SearchDomain(t *testing.T) {
	tests := []struct {
		name         string
		searchDomain string
		want         string
		wantSkipped  []string
		wantRouting  []string
	}{
		{
			name:         "accepted zone",
			searchDomain: "openstack.lab.internal",
			want:         "openstack.lab.internal",
			wantRouting:  []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
		},
		{
			name:         "folded to an accepted zone",
			searchDomain: "OpenStack.Lab.Internal",
			want:         "openstack.lab.internal",
			wantRouting:  []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
		},
		{
			name:         "no accepted zone",
			searchDomain: "corp.example.org",
			want:         "",
			wantSkipped:  []string{`search_domain "corp.example.org" is no accepted zone, so the node has no search domain`},
			wantRouting:  []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
		},
		{
			name:         "a host name, not a zone",
			searchDomain: "db-1.openstack.lab.internal",
			want:         "",
			wantSkipped:  []string{`search_domain "db-1.openstack.lab.internal" is no accepted zone, so the node has no search domain`},
			wantRouting:  []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
		},
		{
			name:         "empty",
			searchDomain: "",
			want:         "",
			wantRouting:  []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
		},
		{
			// A search domain that is a top-level zone routes that zone, so
			// it is not listed again.
			name:         "top-level zone",
			searchDomain: "lab.internal",
			want:         "lab.internal",
			wantRouting:  []string{"edge.example.com", "42.10.in-addr.arpa"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := exampleBlock()
			block.SearchDomain = tt.searchDomain
			r, skipped := BuildRecords(block)
			if !slices.Equal(skipped, tt.wantSkipped) {
				t.Errorf("skipped = %q, want %q", skipped, tt.wantSkipped)
			}
			if got := r.SearchDomain(); got != tt.want {
				t.Errorf("SearchDomain() = %q, want %q", got, tt.want)
			}
			reg := r.Registration("plexd0", netip.MustParseAddrPort("10.42.0.3:5354"))
			if reg.SearchDomain != tt.want {
				t.Errorf("Registration().SearchDomain = %q, want %q", reg.SearchDomain, tt.want)
			}
			if !slices.Equal(reg.RoutingDomains, tt.wantRouting) {
				t.Errorf("Registration().RoutingDomains = %q, want %q", reg.RoutingDomains, tt.wantRouting)
			}
		})
	}
}

func TestRecords_Registration(t *testing.T) {
	server := netip.MustParseAddrPort("10.42.0.3:5354")
	tests := []struct {
		name  string
		block api.NodeStateDNS
		want  Registration
	}{
		{
			name:  "contract example",
			block: exampleBlock(),
			want: Registration{
				Interface:      "plexd0",
				Server:         server,
				SearchDomain:   "openstack.lab.internal",
				RoutingDomains: []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
			},
		},
		{
			// Every Project zone under the default domain: routing the
			// default domain routes them all.
			name: "per-project zones",
			block: api.NodeStateDNS{
				SearchDomain: "b.lab.internal",
				Zones:        []string{"lab.internal", "c.lab.internal", "b.lab.internal", "a.lab.internal"},
				Hosts:        []api.NodeStateDNSHost{},
				ReverseZones: []string{"42.10.in-addr.arpa"},
			},
			want: Registration{
				Interface:      "plexd0",
				Server:         server,
				SearchDomain:   "b.lab.internal",
				RoutingDomains: []string{"lab.internal", "42.10.in-addr.arpa"},
			},
		},
		{
			// The input order does not matter: each group is ascending.
			name: "unsorted input",
			block: api.NodeStateDNS{
				Zones:        []string{"zeta.example", "alpha.example", "mid.alpha.example"},
				Hosts:        []api.NodeStateDNSHost{},
				ReverseZones: []string{"43.10.in-addr.arpa", "42.10.in-addr.arpa"},
			},
			want: Registration{
				Interface:      "plexd0",
				Server:         server,
				RoutingDomains: []string{"alpha.example", "zeta.example", "42.10.in-addr.arpa", "43.10.in-addr.arpa"},
			},
		},
		{
			// A reverse zone under another one stays: reverse zones are
			// never merged.
			name: "nested reverse zones",
			block: api.NodeStateDNS{
				Zones:        []string{"lab.internal"},
				Hosts:        []api.NodeStateDNSHost{},
				ReverseZones: []string{"42.10.in-addr.arpa", "0.42.10.in-addr.arpa"},
			},
			want: Registration{
				Interface:      "plexd0",
				Server:         server,
				RoutingDomains: []string{"lab.internal", "0.42.10.in-addr.arpa", "42.10.in-addr.arpa"},
			},
		},
		{
			// A single-label zone is a valid name, and routing it routes
			// every zone under it.
			name: "single-label zone",
			block: api.NodeStateDNS{
				Zones:        []string{"lab.internal", "internal"},
				Hosts:        []api.NodeStateDNSHost{},
				ReverseZones: []string{},
			},
			want: Registration{
				Interface:      "plexd0",
				Server:         server,
				RoutingDomains: []string{"internal"},
			},
		},
		{
			name: "reverse zones only",
			block: api.NodeStateDNS{
				Zones:        []string{},
				Hosts:        []api.NodeStateDNSHost{},
				ReverseZones: []string{"0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"},
			},
			want: Registration{
				Interface:      "plexd0",
				Server:         server,
				RoutingDomains: []string{"0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustBuild(t, tt.block)
			got := r.Registration("plexd0", server)
			if got.Interface != tt.want.Interface {
				t.Errorf("Interface = %q, want %q", got.Interface, tt.want.Interface)
			}
			if got.Server != tt.want.Server {
				t.Errorf("Server = %s, want %s", got.Server, tt.want.Server)
			}
			if got.SearchDomain != tt.want.SearchDomain {
				t.Errorf("SearchDomain = %q, want %q", got.SearchDomain, tt.want.SearchDomain)
			}
			if !slices.Equal(got.RoutingDomains, tt.want.RoutingDomains) {
				t.Errorf("RoutingDomains = %q, want %q", got.RoutingDomains, tt.want.RoutingDomains)
			}
			if got.Empty() {
				t.Errorf("Empty() = true, want false for %+v", got)
			}
		})
	}
}

func TestRegistration_Empty(t *testing.T) {
	server := netip.MustParseAddrPort("10.42.0.3:5354")
	tests := []struct {
		name string
		reg  Registration
		want bool
	}{
		{"zero", Registration{}, true},
		{"interface and server only", Registration{Interface: "plexd0", Server: server}, true},
		{"empty routing slice", Registration{Interface: "plexd0", Server: server, RoutingDomains: []string{}}, true},
		{"search domain only", Registration{SearchDomain: "lab.internal"}, false},
		{"routing domain only", Registration{RoutingDomains: []string{"42.10.in-addr.arpa"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.reg.Empty(); got != tt.want {
				t.Errorf("Empty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegistration_Equal(t *testing.T) {
	base := Registration{
		Interface:      "plexd0",
		Server:         netip.MustParseAddrPort("10.42.0.3:5354"),
		SearchDomain:   "openstack.lab.internal",
		RoutingDomains: []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
	}
	with := func(f func(*Registration)) Registration {
		r := base
		r.RoutingDomains = slices.Clone(base.RoutingDomains)
		f(&r)
		return r
	}
	tests := []struct {
		name  string
		other Registration
		want  bool
	}{
		{"identical copy", with(func(*Registration) {}), true},
		{"interface", with(func(r *Registration) { r.Interface = "plexd1" }), false},
		{"server address", with(func(r *Registration) { r.Server = netip.MustParseAddrPort("10.42.0.4:5354") }), false},
		{"server port", with(func(r *Registration) { r.Server = netip.MustParseAddrPort("10.42.0.3:5355") }), false},
		{"search domain", with(func(r *Registration) { r.SearchDomain = "" }), false},
		{"routing domain added", with(func(r *Registration) { r.RoutingDomains = append(r.RoutingDomains, "43.10.in-addr.arpa") }), false},
		{"routing domain order", with(func(r *Registration) { slices.Reverse(r.RoutingDomains) }), false},
		{"routing domains nil", with(func(r *Registration) { r.RoutingDomains = nil }), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base.Equal(tt.other); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
			if got := tt.other.Equal(base); got != tt.want {
				t.Errorf("Equal() reversed = %v, want %v", got, tt.want)
			}
		})
	}

	empty := Registration{Interface: "plexd0"}
	if !empty.Equal(Registration{Interface: "plexd0", RoutingDomains: []string{}}) {
		t.Error("Equal() = false for nil and empty RoutingDomains, want true")
	}
}

func TestRecords_Equal(t *testing.T) {
	base := mustBuild(t, exampleBlock())
	modified := func(f func(*api.NodeStateDNS)) *Records {
		block := exampleBlock()
		f(&block)
		return mustBuild(t, block)
	}
	empty := mustBuild(t, api.NodeStateDNS{Zones: []string{}, Hosts: []api.NodeStateDNSHost{}, ReverseZones: []string{}})

	tests := []struct {
		name  string
		other *Records
		want  bool
	}{
		{"same block", mustBuild(t, exampleBlock()), true},
		{"node id only", modified(func(b *api.NodeStateDNS) { b.Hosts[0].NodeID = "other" }), true},
		{"host order", modified(func(b *api.NodeStateDNS) { slices.Reverse(b.Hosts) }), true},
		{"zone order and case", modified(func(b *api.NodeStateDNS) {
			b.Zones = []string{"Lab.Internal", "openstack.lab.internal", "edge.example.com"}
		}), true},
		{"renamed host", modified(func(b *api.NodeStateDNS) { b.Hosts[0].FQDN = "db-2.openstack.lab.internal" }), false},
		{"moved host", modified(func(b *api.NodeStateDNS) { b.Hosts[0].MeshIP = "10.42.0.4" }), false},
		{"search domain", modified(func(b *api.NodeStateDNS) { b.SearchDomain = "lab.internal" }), false},
		{"zone added", modified(func(b *api.NodeStateDNS) { b.Zones = append(b.Zones, "ops.example.com") }), false},
		{"reverse zone added", modified(func(b *api.NodeStateDNS) { b.ReverseZones = append(b.ReverseZones, "43.10.in-addr.arpa") }), false},
		{"reverse zone removed", modified(func(b *api.NodeStateDNS) { b.ReverseZones = []string{} }), false},
		{"empty", empty, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base.Equal(tt.other); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
			if got := tt.other.Equal(base); got != tt.want {
				t.Errorf("Equal() reversed = %v, want %v", got, tt.want)
			}
		})
	}

	var none *Records
	if !none.Equal(nil) {
		t.Error("nil.Equal(nil) = false, want true")
	}
	if none.Equal(empty) {
		t.Error("nil.Equal(empty) = true, want false: the first block is a change even when it is empty")
	}
}

func TestResult_String(t *testing.T) {
	tests := []struct {
		r    Result
		want string
	}{
		{ResultRefused, "refused"},
		{ResultNXDomain, "nxdomain"},
		{ResultNoData, "nodata"},
		{ResultFound, "found"},
		{Result(9), "Result(9)"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("Result(%d).String() = %q, want %q", int(tt.r), got, tt.want)
		}
	}
}
