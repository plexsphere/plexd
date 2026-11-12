//go:build linux

package policy

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func discardLoggerNft() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Compile-time check that NftablesController implements FirewallController.
var _ FirewallController = (*NftablesController)(nil)

func TestNewNftablesController(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())
	if ctrl == nil {
		t.Fatal("NewNftablesController returned nil")
	}
	if ctrl.logger == nil {
		t.Fatal("logger field is nil")
	}
}

func TestDeleteChainNonExistent(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	// Deleting a non-existent chain should be idempotent and return nil.
	// This requires CAP_NET_ADMIN; skip if we get a permission error.
	err := ctrl.DeleteChain("plexd-test-nonexistent")
	if err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
}

func TestEnsureChainRequiresPrivileges(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	err := ctrl.EnsureChain("plexd-test-ensure")
	if err == nil {
		// Succeeded — running as root. Clean up.
		_ = ctrl.FlushChain("plexd-test-ensure")
		_ = ctrl.DeleteChain("plexd-test-ensure")
		return
	}

	// Without CAP_NET_ADMIN the listing of IPv4 tables, which looks for the
	// table an earlier plexd left behind, is the first call to fail.
	expected := "policy: nftables: ensure chain: list tables:"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestFlushChainRequiresPrivileges(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	err := ctrl.FlushChain("plexd-test-flush")
	if err == nil {
		return
	}

	expected := "policy: nftables: flush chain"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestApplyRulesRequiresPrivileges(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	rules := []FirewallRule{
		{
			SrcIP:    "10.0.0.1",
			DstIP:    "10.0.0.2",
			Port:     443,
			Protocol: "tcp",
			Action:   "allow",
		},
		{
			SrcIP:  "0.0.0.0/0",
			DstIP:  "0.0.0.0/0",
			Action: "deny",
		},
	}

	err := ctrl.ApplyRules("plexd-test-apply", rules)
	if err == nil {
		// Succeeded — running as root. Clean up.
		_ = ctrl.FlushChain("plexd-test-apply")
		_ = ctrl.DeleteChain("plexd-test-apply")
		return
	}

	expected := "policy: nftables: apply rules"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestNftablesController_DedicatedTable(t *testing.T) {
	// Verify the controller uses the dedicated "plexd" table name.
	if tableName != "plexd" {
		t.Errorf("tableName = %q, want %q", tableName, "plexd")
	}
}

func TestNftablesController_ApplyRulesWithInterface(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	chain := "plexd-test-iface"
	if err := ctrl.EnsureChain(chain); err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
	defer func() {
		_ = ctrl.FlushChain(chain)
		_ = ctrl.DeleteChain(chain)
	}()

	rules := []FirewallRule{
		{
			Interface: "wg0",
			SrcIP:     "10.0.0.1",
			DstIP:     "10.0.0.2",
			Port:      443,
			Protocol:  "tcp",
			Action:    "allow",
		},
		{
			Interface: "wg0",
			Action:    "deny",
		},
	}

	if err := ctrl.ApplyRules(chain, rules); err != nil {
		t.Fatalf("ApplyRules with interface failed: %v", err)
	}
}

func TestBuildRuleExprsAllow(t *testing.T) {
	rule := FirewallRule{
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		Port:     80,
		Protocol: "tcp",
		Action:   "allow",
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("buildRuleExprs returned empty expressions")
	}
}

func TestBuildRuleExprsDeny(t *testing.T) {
	rule := FirewallRule{
		SrcIP:  "0.0.0.0/0",
		DstIP:  "0.0.0.0/0",
		Action: "deny",
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("buildRuleExprs returned empty expressions")
	}
}

func TestBuildRuleExprsInvalidAction(t *testing.T) {
	rule := FirewallRule{Action: "reject"}
	_, err := buildRuleExprs(rule)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestBuildRuleExprsInvalidProtocol(t *testing.T) {
	rule := FirewallRule{Protocol: "sctp", Action: "allow"}
	_, err := buildRuleExprs(rule)
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestBuildRuleExprsICMP(t *testing.T) {
	rule := FirewallRule{DstIP: "10.0.0.1", Protocol: "icmp", Action: "allow"}
	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error for icmp: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("buildRuleExprs returned empty expressions for icmp")
	}
}

func TestBuildRuleExprsPortRange(t *testing.T) {
	rule := FirewallRule{
		DstIP:    "10.0.0.1",
		Port:     1000,
		PortTo:   2000,
		Protocol: "tcp",
		Action:   "allow",
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}

	// A range emits exactly one Gte and one Lte comparison on the dport payload.
	var gte, lte *expr.Cmp
	for _, e := range exprs {
		cmp, ok := e.(*expr.Cmp)
		if !ok {
			continue
		}
		switch cmp.Op {
		case expr.CmpOpGte:
			gte = cmp
		case expr.CmpOpLte:
			lte = cmp
		}
	}
	if gte == nil || lte == nil {
		t.Fatalf("expected both CmpOpGte and CmpOpLte for a port range, got gte=%v lte=%v", gte, lte)
	}
	wantLo := portBytes(1000)
	if len(gte.Data) != 2 || gte.Data[0] != wantLo[0] || gte.Data[1] != wantLo[1] {
		t.Errorf("Gte data = %v, want %v (port 1000)", gte.Data, wantLo)
	}
	wantHi := portBytes(2000)
	if len(lte.Data) != 2 || lte.Data[0] != wantHi[0] || lte.Data[1] != wantHi[1] {
		t.Errorf("Lte data = %v, want %v (port 2000)", lte.Data, wantHi)
	}
}

func TestBuildRuleExprsSinglePortUsesEq(t *testing.T) {
	rule := FirewallRule{DstIP: "10.0.0.1", Port: 443, Protocol: "tcp", Action: "allow"}
	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}
	// A single port must not emit range comparisons.
	for _, e := range exprs {
		if cmp, ok := e.(*expr.Cmp); ok {
			if cmp.Op == expr.CmpOpGte || cmp.Op == expr.CmpOpLte {
				t.Errorf("single-port rule emitted a range comparison Op=%v", cmp.Op)
			}
		}
	}
}

func TestBuildRuleExprsCIDRSubnet(t *testing.T) {
	rule := FirewallRule{
		SrcIP:  "10.0.0.0/8",
		DstIP:  "192.168.1.0/24",
		Action: "allow",
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("buildRuleExprs returned empty expressions")
	}
}

func TestBuildRuleExprsWildcardSkipped(t *testing.T) {
	// Wildcard "0.0.0.0/0" should not generate match expressions.
	rule := FirewallRule{
		SrcIP:  "0.0.0.0/0",
		DstIP:  "0.0.0.0/0",
		Action: "deny",
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}

	// The family match stays, since 0.0.0.0/0 is every IPv4 address and no
	// IPv6 one; the address match goes.
	assertExprs(t, exprs, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	})
}

func TestBuildRuleExprsUDP(t *testing.T) {
	rule := FirewallRule{
		DstIP:    "10.0.0.1",
		Port:     53,
		Protocol: "udp",
		Action:   "allow",
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("buildRuleExprs returned empty expressions")
	}
}

func TestBuildRuleExprsWithInterface(t *testing.T) {
	rule := FirewallRule{
		Interface: "wg0",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		Port:      443,
		Protocol:  "tcp",
		Action:    "allow",
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}

	// First two expressions must be Meta(IIFNAME) + Cmp for the interface match.
	if len(exprs) < 2 {
		t.Fatalf("expected at least 2 expressions, got %d", len(exprs))
	}

	meta, ok := exprs[0].(*expr.Meta)
	if !ok {
		t.Fatalf("exprs[0] is %T, want *expr.Meta", exprs[0])
	}
	if meta.Key != expr.MetaKeyIIFNAME {
		t.Errorf("Meta key = %v, want MetaKeyIIFNAME", meta.Key)
	}

	cmp, ok := exprs[1].(*expr.Cmp)
	if !ok {
		t.Fatalf("exprs[1] is %T, want *expr.Cmp", exprs[1])
	}
	// Interface name should be null-terminated: "wg0\x00"
	want := []byte{'w', 'g', '0', 0}
	if len(cmp.Data) != len(want) {
		t.Errorf("Cmp data length = %d, want %d", len(cmp.Data), len(want))
	}
	for i := range want {
		if i < len(cmp.Data) && cmp.Data[i] != want[i] {
			t.Errorf("Cmp data[%d] = %d, want %d", i, cmp.Data[i], want[i])
		}
	}
}

func TestBuildRuleExprsInvalidIP(t *testing.T) {
	rule := FirewallRule{
		SrcIP:  "not-an-ip",
		Action: "allow",
	}

	_, err := buildRuleExprs(rule)
	if err == nil {
		t.Fatal("expected error for invalid IP address")
	}
}

func TestBuildIPMatchExprsExactIP(t *testing.T) {
	// A bare address is read as its host prefix.
	prefix, ok, err := parseRuleAddr("10.0.0.1")
	if err != nil || !ok {
		t.Fatalf("parseRuleAddr returned %v, %v, %v", prefix, ok, err)
	}
	exprs := buildIPMatchExprs(prefix, true)
	// Exact IP match: payload + cmp = 2 expressions.
	if len(exprs) != 2 {
		t.Errorf("expected 2 expressions for exact IP, got %d", len(exprs))
	}
}

func TestBuildIPMatchExprsCIDR32(t *testing.T) {
	exprs := buildIPMatchExprs(netip.MustParsePrefix("10.0.0.1/32"), false)
	// /32 is an exact match: payload + cmp = 2 expressions.
	if len(exprs) != 2 {
		t.Errorf("expected 2 expressions for /32 CIDR, got %d", len(exprs))
	}
}

func TestBuildIPMatchExprsSubnet(t *testing.T) {
	exprs := buildIPMatchExprs(netip.MustParsePrefix("192.168.0.0/16"), true)
	// Subnet match: payload + bitwise + cmp = 3 expressions.
	if len(exprs) != 3 {
		t.Errorf("expected 3 expressions for subnet CIDR, got %d", len(exprs))
	}
}

func TestBuildIPMatchExprsZeroLength(t *testing.T) {
	for _, p := range []string{"0.0.0.0/0", "::/0"} {
		if exprs := buildIPMatchExprs(netip.MustParsePrefix(p), true); len(exprs) != 0 {
			t.Errorf("buildIPMatchExprs(%s) = %s, want no expressions", p, formatExprs(exprs))
		}
	}
}

func TestProtocolNumber(t *testing.T) {
	tests := []struct {
		proto string
		fam   addrFamily
		want  byte
		err   bool
	}{
		{"tcp", familyAny, 6, false},
		{"udp", familyAny, 17, false},
		{"tcp", familyIPv6, 6, false},
		{"icmp", familyIPv4, 1, false},
		{"icmp", familyIPv6, 58, false},
		{"icmp", familyAny, 0, true},
		{"sctp", familyIPv4, 0, true},
		{"", familyIPv4, 0, true},
	}

	for _, tt := range tests {
		got, err := protocolNumber(tt.proto, tt.fam)
		if tt.err {
			if err == nil {
				t.Errorf("protocolNumber(%q, %d) expected error", tt.proto, tt.fam)
			}
			continue
		}
		if err != nil {
			t.Errorf("protocolNumber(%q, %d) returned error: %v", tt.proto, tt.fam, err)
			continue
		}
		if got != tt.want {
			t.Errorf("protocolNumber(%q, %d) = %d, want %d", tt.proto, tt.fam, got, tt.want)
		}
	}
}

func TestPortBytes(t *testing.T) {
	tests := []struct {
		port uint16
		want []byte
	}{
		{80, []byte{0x00, 0x50}},
		{443, []byte{0x01, 0xBB}},
		{22, []byte{0x00, 0x16}},
		{8080, []byte{0x1F, 0x90}},
	}

	for _, tt := range tests {
		got := portBytes(tt.port)
		if len(got) != 2 || got[0] != tt.want[0] || got[1] != tt.want[1] {
			t.Errorf("portBytes(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestEnsureChainAndDeleteRoundTrip(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	// Ensure chain — requires privileges.
	if err := ctrl.EnsureChain("plexd-test-roundtrip"); err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}

	// Delete the chain we just created.
	if err := ctrl.DeleteChain("plexd-test-roundtrip"); err != nil {
		t.Fatalf("DeleteChain failed: %v", err)
	}

	// Deleting again should be idempotent.
	if err := ctrl.DeleteChain("plexd-test-roundtrip"); err != nil {
		t.Fatalf("second DeleteChain failed: %v", err)
	}
}

func TestApplyAndFlushRoundTrip(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	chain := "plexd-test-applyflush"
	if err := ctrl.EnsureChain(chain); err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
	defer func() {
		_ = ctrl.FlushChain(chain)
		_ = ctrl.DeleteChain(chain)
	}()

	rules := []FirewallRule{
		{
			SrcIP:    "10.0.0.1",
			DstIP:    "10.0.0.2",
			Port:     443,
			Protocol: "tcp",
			Action:   "allow",
		},
		{
			SrcIP:  "0.0.0.0/0",
			DstIP:  "0.0.0.0/0",
			Action: "deny",
		},
	}

	if err := ctrl.ApplyRules(chain, rules); err != nil {
		t.Fatalf("ApplyRules failed: %v", err)
	}

	if err := ctrl.FlushChain(chain); err != nil {
		t.Fatalf("FlushChain failed: %v", err)
	}
}

func TestProbeErrorPrefix(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())

	err := ctrl.Probe()
	if err == nil {
		// Backend usable — running with CAP_NET_ADMIN on a kernel offering
		// nf_tables. Nothing to clean up: the probe only reads.
		return
	}

	expected := "policy: nftables: probe"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

// The pre-flight check is only worth running if its verdict matches the one the
// baseline install would reach, so assert the two agree on whatever host this
// runs on — privileged or not.
func TestProbeAgreesWithEnsureChain(t *testing.T) {
	ctrl := NewNftablesController(discardLoggerNft())
	chain := "plexd-test-probe-agree"

	probeErr := ctrl.Probe()
	ensureErr := ctrl.EnsureChain(chain)
	if ensureErr == nil {
		_ = ctrl.FlushChain(chain)
		_ = ctrl.DeleteChain(chain)
	}

	if (probeErr == nil) != (ensureErr == nil) {
		t.Errorf("Probe and EnsureChain disagree: probe = %v, EnsureChain = %v", probeErr, ensureErr)
	}
}

// formatExprs renders an expression list with the values behind its pointers,
// so a mismatch shows what differs rather than two addresses.
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

func TestBuildRuleExprsAddressFamilies(t *testing.T) {
	nfproto := func(family byte) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		}
	}
	network := func(offset, length uint32) *expr.Payload {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}
	}
	eq := func(data []byte) *expr.Cmp {
		return &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}
	}
	mask := func(m []byte) *expr.Bitwise {
		return &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(m)), Mask: m, Xor: make([]byte, len(m))}
	}
	addr := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	join := func(parts ...[]expr.Any) []expr.Any {
		var out []expr.Any
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	accept := []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}}
	drop := []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}

	tests := []struct {
		name string
		rule FirewallRule
		want []expr.Any
	}{
		{
			name: "IPv4 host source",
			rule: FirewallRule{SrcIP: "10.0.0.1/32", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV4), []expr.Any{network(12, 4), eq(addr("10.0.0.1"))}, accept),
		},
		{
			name: "IPv4 subnet destination",
			rule: FirewallRule{DstIP: "192.168.1.0/24", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV4),
				[]expr.Any{network(16, 4), mask([]byte{255, 255, 255, 0}), eq(addr("192.168.1.0"))}, accept),
		},
		{
			name: "IPv6 host source",
			rule: FirewallRule{SrcIP: "fd00::1/128", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV6), []expr.Any{network(8, 16), eq(addr("fd00::1"))}, accept),
		},
		{
			name: "IPv6 bare destination",
			rule: FirewallRule{DstIP: "fd00::2", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV6), []expr.Any{network(24, 16), eq(addr("fd00::2"))}, accept),
		},
		{
			name: "IPv6 /64 source",
			rule: FirewallRule{SrcIP: "fd00::/64", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV6), []expr.Any{
				network(8, 16),
				mask([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}),
				eq(addr("fd00::")),
			}, accept),
		},
		{
			name: "IPv6 any address",
			rule: FirewallRule{SrcIP: "::/0", DstIP: "::/0", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV6), accept),
		},
		{
			name: "address-less default deny",
			rule: FirewallRule{Interface: "plexd0", Action: "deny"},
			want: join([]expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				eq([]byte("plexd0\x00")),
			}, drop),
		},
		{
			name: "icmp under IPv4",
			rule: FirewallRule{DstIP: "10.0.0.1", Protocol: "icmp", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV4), []expr.Any{
				network(16, 4), eq(addr("10.0.0.1")),
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, eq([]byte{1}),
			}, accept),
		},
		{
			name: "icmp under IPv6",
			rule: FirewallRule{DstIP: "fd00::1", Protocol: "icmp", Action: "allow"},
			want: join(nfproto(unix.NFPROTO_IPV6), []expr.Any{
				network(24, 16), eq(addr("fd00::1")),
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, eq([]byte{58}),
			}, accept),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRuleExprs(tt.rule)
			if err != nil {
				t.Fatalf("buildRuleExprs returned error: %v", err)
			}
			assertExprs(t, got, tt.want)
		})
	}
}

func TestBuildRuleExprsRejectsAddresses(t *testing.T) {
	tests := []struct {
		name string
		rule FirewallRule
		want string
	}{
		{
			name: "mixed families",
			rule: FirewallRule{SrcIP: "10.0.0.1/32", DstIP: "fd00::1/128", Action: "allow"},
			want: "differ in address family",
		},
		{
			name: "IPv4-mapped",
			rule: FirewallRule{DstIP: "::ffff:10.0.0.1/128", Action: "allow"},
			want: "IPv4-mapped IPv6 address",
		},
		{
			name: "icmp without an address",
			rule: FirewallRule{Protocol: "icmp", Action: "allow"},
			want: "protocol icmp needs an address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildRuleExprs(tt.rule)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("buildRuleExprs error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestConnTrackExprs(t *testing.T) {
	iface := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("plexd0\x00")},
	}
	state := func(bit uint32) []expr.Any {
		return []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(bit),
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		}
	}

	var established []expr.Any
	established = append(established, iface...)
	established = append(established, state(expr.CtStateBitESTABLISHED)...)
	established = append(established,
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		// IP_CT_DIR_REPLY, one byte.
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	var related []expr.Any
	related = append(related, iface...)
	related = append(related, state(expr.CtStateBitRELATED)...)
	related = append(related,
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	got := connTrackExprs("plexd0")
	if len(got) != 2 {
		t.Fatalf("connTrackExprs returned %d rules, want 2", len(got))
	}
	assertExprs(t, got[0], established)
	assertExprs(t, got[1], related)
}

// A rule without an interface matches every interface, and so do the
// connection tracking rules that open its chain.
func TestConnTrackExprsWithoutInterface(t *testing.T) {
	for i, rule := range connTrackExprs("") {
		if ct, ok := rule[0].(*expr.Ct); !ok || ct.Key != expr.CtKeySTATE {
			t.Errorf("rule %d starts with %s, want the ct state load", i, formatExprs(rule[:1]))
		}
	}
}

func TestChainRuleExprs(t *testing.T) {
	rules := []FirewallRule{
		{Interface: "wg0", DstIP: "10.0.0.1/32", Protocol: "tcp", Port: 22, Action: "allow"},
		{Interface: "wg1", DstIP: "fd00::1/128", Action: "allow"},
		{Interface: "wg0", Action: "deny"},
	}

	got, err := chainRuleExprs(rules)
	if err != nil {
		t.Fatalf("chainRuleExprs returned error: %v", err)
	}

	// One connection tracking pair per interface, in order of first
	// appearance, then the rules in the order given.
	var want [][]expr.Any
	want = append(want, connTrackExprs("wg0")...)
	want = append(want, connTrackExprs("wg1")...)
	for _, rule := range rules {
		exprs, err := buildRuleExprs(rule)
		if err != nil {
			t.Fatalf("buildRuleExprs returned error: %v", err)
		}
		want = append(want, exprs)
	}
	if len(got) != len(want) {
		t.Fatalf("chainRuleExprs returned %d rules, want %d", len(got), len(want))
	}
	for i := range want {
		assertExprs(t, got[i], want[i])
	}
}

func TestChainRuleExprsEmpty(t *testing.T) {
	got, err := chainRuleExprs(nil)
	if err != nil {
		t.Fatalf("chainRuleExprs returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("chainRuleExprs(nil) returned %d rules, want none", len(got))
	}
}

func TestChainRuleExprsRejectsInvalidRule(t *testing.T) {
	_, err := chainRuleExprs([]FirewallRule{
		{Interface: "wg0", Action: "allow"},
		{Interface: "wg0", SrcIP: "not-an-ip", Action: "allow"},
	})
	want := "policy: nftables: apply rules: policy: firewall rule:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("chainRuleExprs error = %v, want one starting %q", err, want)
	}
}

func TestChainNames(t *testing.T) {
	input, forward := chainNames("plexd-mesh")
	if input != "plexd-mesh-input" || forward != "plexd-mesh-forward" {
		t.Errorf("chainNames(plexd-mesh) = %q, %q, want plexd-mesh-input, plexd-mesh-forward", input, forward)
	}
}
