package nat

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// upFlags are the flags of an ordinary, eligible Ethernet interface.
const upFlags = net.FlagUp | net.FlagBroadcast | net.FlagMulticast

// ens3 is the eligible interface most cases build on.
func ens3(prefixes ...string) Interface {
	return iface("ens3", 2, upFlags, prefixes...)
}

func iface(name string, index int, flags net.Flags, prefixes ...string) Interface {
	out := Interface{Name: name, Index: index, Flags: flags}
	for _, p := range prefixes {
		out.Prefixes = append(out.Prefixes, netip.MustParsePrefix(p))
	}
	return out
}

func TestSelectCandidates_NothingEligibleReturnsEmptyNonNil(t *testing.T) {
	tests := []struct {
		name   string
		ifaces []Interface
	}{
		{name: "nil input", ifaces: nil},
		{name: "interfaces without prefixes", ifaces: []Interface{ens3(), iface("eth1", 3, upFlags)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated := SelectCandidates(tt.ifaces, 51820, CandidateFilter{})
			if got == nil {
				t.Fatal("SelectCandidates returned nil, want an empty non-nil slice")
			}
			if len(got) != 0 {
				t.Errorf("SelectCandidates = %v, want empty", got)
			}
			if truncated != 0 {
				t.Errorf("truncated = %d, want 0", truncated)
			}
		})
	}
}

func TestSelectCandidates_DualStackInterface(t *testing.T) {
	got, truncated := SelectCandidates([]Interface{ens3("10.0.0.5/24", "fd00:10::5/64")}, 51820, CandidateFilter{})
	want := []string{"10.0.0.5:51820", "[fd00:10::5]:51820"}
	if !slices.Equal(got, want) {
		t.Errorf("SelectCandidates = %v, want %v", got, want)
	}
	if truncated != 0 {
		t.Errorf("truncated = %d, want 0", truncated)
	}
}

// TestSelectCandidates_Skips adds one ineligible interface or address beside
// an eligible ens3 in each case, so a case passes only when the rule drops
// exactly the item it names.
func TestSelectCandidates_Skips(t *testing.T) {
	tests := []struct {
		name   string
		extra  Interface
		filter CandidateFilter
	}{
		{name: "interface without FlagUp", extra: iface("eth1", 3, net.FlagBroadcast|net.FlagMulticast, "192.168.1.5/24")},
		{name: "interface with FlagLoopback", extra: iface("lo", 1, net.FlagUp|net.FlagLoopback, "192.168.1.5/24")},
		{name: "interface with FlagPointToPoint", extra: iface("wg0", 3, net.FlagUp|net.FlagPointToPoint, "192.168.1.5/24")},
		{name: "interface in ExcludeInterfaces", extra: iface("plexd0", 3, upFlags, "192.168.1.5/24"), filter: CandidateFilter{ExcludeInterfaces: []string{"plexd0"}}},
		{name: "docker0", extra: iface("docker0", 3, upFlags, "172.17.0.1/16")},
		{name: "br-1a2b3c4d5e6f", extra: iface("br-1a2b3c4d5e6f", 3, upFlags, "172.18.0.1/16")},
		{name: "veth12ab", extra: iface("veth12ab", 3, upFlags, "172.19.0.1/16")},
		{name: "cni0", extra: iface("cni0", 3, upFlags, "10.244.0.1/24")},
		{name: "flannel.1", extra: iface("flannel.1", 3, upFlags, "10.244.0.0/32")},
		{name: "address 0.0.0.0", extra: iface("eth1", 3, upFlags, "0.0.0.0/8")},
		{name: "address 127.0.0.1", extra: iface("eth1", 3, upFlags, "127.0.0.1/8")},
		{name: "address 169.254.1.1", extra: iface("eth1", 3, upFlags, "169.254.1.1/16")},
		{name: "address fe80::1", extra: iface("eth1", 3, upFlags, "fe80::1/64")},
		{name: "address ff02::1", extra: iface("eth1", 3, upFlags, "ff02::1/128")},
		{name: "address 224.0.0.1", extra: iface("eth1", 3, upFlags, "224.0.0.1/32")},
		{name: "10.99.0.7 inside ExcludePrefix 10.99.0.0/24", extra: iface("eth1", 3, upFlags, "10.99.0.7/24"), filter: CandidateFilter{ExcludePrefix: netip.MustParsePrefix("10.99.0.0/24")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifaces := []Interface{ens3("10.0.0.5/24"), tt.extra}
			got, _ := SelectCandidates(ifaces, 51820, tt.filter)
			want := []string{"10.0.0.5:51820"}
			if !slices.Equal(got, want) {
				t.Errorf("SelectCandidates = %v, want %v", got, want)
			}
			prefixes := EligiblePrefixes(ifaces, tt.filter)
			wantPrefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")}
			if !slices.Equal(prefixes, wantPrefixes) {
				t.Errorf("EligiblePrefixes = %v, want %v", prefixes, wantPrefixes)
			}
		})
	}
}

func TestSelectCandidates_AllowlistBypassesVirtualPrefixes(t *testing.T) {
	ifaces := []Interface{ens3("10.0.0.5/24"), iface("docker0", 3, upFlags, "172.17.0.1/16")}
	got, _ := SelectCandidates(ifaces, 51820, CandidateFilter{Interfaces: []string{"docker0"}})
	want := []string{"172.17.0.1:51820"}
	if !slices.Equal(got, want) {
		t.Errorf("SelectCandidates = %v, want %v", got, want)
	}
}

func TestSelectCandidates_UnmapsIPv4MappedPrefix(t *testing.T) {
	ifaces := []Interface{ens3("::ffff:10.0.0.5/120")}
	got, _ := SelectCandidates(ifaces, 51820, CandidateFilter{})
	want := []string{"10.0.0.5:51820"}
	if !slices.Equal(got, want) {
		t.Errorf("SelectCandidates = %v, want %v", got, want)
	}

	// The manager tests on-link candidates against these prefixes, so the
	// mapped /120 must come back as the IPv4 /24 it describes.
	prefixes := EligiblePrefixes(ifaces, CandidateFilter{})
	wantPrefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")}
	if !slices.Equal(prefixes, wantPrefixes) {
		t.Fatalf("EligiblePrefixes = %v, want %v", prefixes, wantPrefixes)
	}
	if !prefixes[0].IsValid() || !prefixes[0].Contains(netip.MustParseAddr("10.0.0.9")) {
		t.Errorf("EligiblePrefixes[0] = %v, want a valid prefix containing 10.0.0.9", prefixes[0])
	}
}

func TestSelectCandidates_Order(t *testing.T) {
	// Listed out of order: eth1 (index 3) before ens3 (index 2), and each
	// interface's addresses unsorted.
	ifaces := []Interface{
		iface("eth1", 3, upFlags, "fd00::3/64", "10.0.0.9/24"),
		ens3("fd00::2/64", "192.168.1.5/24", "10.0.0.7/24"),
	}
	got, _ := SelectCandidates(ifaces, 51820, CandidateFilter{})
	// IPv4 first; within a family the lower index wins over the lower
	// address (192.168.1.5 on index 2 precedes 10.0.0.9 on index 3); within
	// an interface the lower address comes first.
	want := []string{
		"10.0.0.7:51820",
		"192.168.1.5:51820",
		"10.0.0.9:51820",
		"[fd00::2]:51820",
		"[fd00::3]:51820",
	}
	if !slices.Equal(got, want) {
		t.Errorf("SelectCandidates = %v, want %v", got, want)
	}
}

func TestSelectCandidates_AddressOnTwoInterfacesPublishedOnce(t *testing.T) {
	ifaces := []Interface{
		iface("eth1", 3, upFlags, "10.0.0.1/24", "10.0.0.5/24"),
		ens3("10.0.0.5/24"),
	}
	got, truncated := SelectCandidates(ifaces, 51820, CandidateFilter{})
	// 10.0.0.5 keeps its position on ens3 (index 2), ahead of eth1's
	// 10.0.0.1, rather than the later one on eth1.
	want := []string{"10.0.0.5:51820", "10.0.0.1:51820"}
	if !slices.Equal(got, want) {
		t.Errorf("SelectCandidates = %v, want %v", got, want)
	}
	if truncated != 0 {
		t.Errorf("truncated = %d, want 0 (a duplicate is not a truncated candidate)", truncated)
	}
}

func TestSelectCandidates_TruncatesPastMax(t *testing.T) {
	var prefixes []string
	for i := 10; i >= 1; i-- {
		prefixes = append(prefixes, fmt.Sprintf("10.0.0.%d/24", i))
	}
	ifaces := []Interface{ens3(prefixes...)}

	got, truncated := SelectCandidates(ifaces, 51820, CandidateFilter{})
	var want []string
	for i := 1; i <= api.MaxEndpointCandidates; i++ {
		want = append(want, fmt.Sprintf("10.0.0.%d:51820", i))
	}
	if !slices.Equal(got, want) {
		t.Errorf("SelectCandidates = %v, want %v", got, want)
	}
	if truncated != 2 {
		t.Errorf("truncated = %d, want 2", truncated)
	}

	// The on-link prefixes are not capped: every eligible address counts.
	if n := len(EligiblePrefixes(ifaces, CandidateFilter{})); n != 10 {
		t.Errorf("len(EligiblePrefixes) = %d, want 10", n)
	}
}

func TestPrefixFromIPNet(t *testing.T) {
	tests := []struct {
		name   string
		ipnet  *net.IPNet
		want   netip.Prefix
		wantOK bool
	}{
		{
			// The form net.Interface.Addrs returns for IPv4 on Linux.
			name:   "16-byte IPv4 with a 4-byte mask",
			ipnet:  &net.IPNet{IP: net.IPv4(10, 0, 0, 5), Mask: net.CIDRMask(24, 32)},
			want:   netip.MustParsePrefix("10.0.0.5/24"),
			wantOK: true,
		},
		{
			name:   "4-byte IPv4",
			ipnet:  &net.IPNet{IP: net.IPv4(10, 0, 0, 5).To4(), Mask: net.CIDRMask(24, 32)},
			want:   netip.MustParsePrefix("10.0.0.5/24"),
			wantOK: true,
		},
		{
			name:   "IPv4-mapped IPv6 with a 128-bit mask",
			ipnet:  &net.IPNet{IP: net.ParseIP("::ffff:10.0.0.5"), Mask: net.CIDRMask(120, 128)},
			want:   netip.MustParsePrefix("10.0.0.5/24"),
			wantOK: true,
		},
		{
			name:   "IPv4-mapped IPv6 shorter than the mapping prefix",
			ipnet:  &net.IPNet{IP: net.ParseIP("::ffff:10.0.0.5"), Mask: net.CIDRMask(64, 128)},
			want:   netip.MustParsePrefix("10.0.0.5/32"),
			wantOK: true,
		},
		{
			name:   "IPv6",
			ipnet:  &net.IPNet{IP: net.ParseIP("fd00:10::5"), Mask: net.CIDRMask(64, 128)},
			want:   netip.MustParsePrefix("fd00:10::5/64"),
			wantOK: true,
		},
		{
			name:  "non-canonical mask",
			ipnet: &net.IPNet{IP: net.IPv4(10, 0, 0, 5), Mask: net.IPv4Mask(255, 0, 255, 0)},
		},
		{
			name:  "unreadable address",
			ipnet: &net.IPNet{IP: net.IP{10, 0, 5}, Mask: net.CIDRMask(24, 32)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := prefixFromIPNet(tt.ipnet)
			if ok != tt.wantOK {
				t.Fatalf("prefixFromIPNet ok = %v, want %v (prefix %v)", ok, tt.wantOK, got)
			}
			if ok && got != tt.want {
				t.Errorf("prefixFromIPNet = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSystemInterfaces_Host(t *testing.T) {
	ifaces, err := SystemInterfaces()
	if err != nil {
		t.Fatalf("SystemInterfaces() error = %v", err)
	}

	var loopback []netip.Prefix
	found := false
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			found = true
			loopback = append(loopback, ifc.Prefixes...)
		}
	}
	if !found {
		t.Fatalf("SystemInterfaces() = %+v, want an interface carrying FlagLoopback", ifaces)
	}

	for _, p := range EligiblePrefixes(ifaces, CandidateFilter{}) {
		if !p.IsValid() {
			t.Errorf("EligiblePrefixes holds invalid prefix %v", p)
		}
		if p.Addr().IsLoopback() || slices.Contains(loopback, p) {
			t.Errorf("EligiblePrefixes holds loopback prefix %v", p)
		}
	}
}

func TestGatherCandidates_Host(t *testing.T) {
	got, _, err := GatherCandidates(51820, CandidateFilter{})
	if err != nil {
		t.Fatalf("GatherCandidates() error = %v", err)
	}
	if got == nil {
		t.Fatal("GatherCandidates returned nil candidates, want a non-nil slice")
	}
	if len(got) > api.MaxEndpointCandidates {
		t.Errorf("GatherCandidates = %d candidates, want at most %d", len(got), api.MaxEndpointCandidates)
	}
	for _, c := range got {
		ap, err := netip.ParseAddrPort(c)
		if err != nil {
			t.Errorf("candidate %q does not parse: %v", c, err)
			continue
		}
		if ap.Port() != 51820 || ap.Addr().IsLoopback() || ap.Addr().Zone() != "" || !strings.HasSuffix(c, ":51820") {
			t.Errorf("candidate %q, want a non-loopback, zoneless host on port 51820", c)
		}
	}
}
