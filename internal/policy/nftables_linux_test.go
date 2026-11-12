//go:build linux

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
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

// The tests below that call the controller run inside inTestNetns: as root
// they work in a network namespace of their own and leave the host's ruleset
// alone, and unprivileged they run in place and see the permission errors.

func TestDeleteChainNonExistent(t *testing.T) {
	inTestNetns(t, func() {
		ctrl := NewNftablesController(discardLoggerNft())

		// Deleting a non-existent chain should be idempotent and return nil.
		// This requires CAP_NET_ADMIN; skip if we get a permission error.
		err := ctrl.DeleteChain("plexd-test-nonexistent")
		if err != nil {
			t.Skipf("skipping: requires elevated privileges: %v", err)
		}
	})
}

func TestEnsureChainRequiresPrivileges(t *testing.T) {
	inTestNetns(t, func() {
		ctrl := NewNftablesController(discardLoggerNft())

		err := ctrl.EnsureChain("plexd-test-ensure")
		if err == nil {
			// Succeeded — running as root. Clean up.
			_ = ctrl.FlushChain("plexd-test-ensure")
			_ = ctrl.DeleteChain("plexd-test-ensure")
			return
		}

		// Without CAP_NET_ADMIN the listing of IPv4 tables, which looks for
		// the table an earlier plexd left behind, is the first call to fail.
		expected := "policy: nftables: ensure chain: list tables:"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("expected error prefix %q, got %q", expected, err.Error())
		}
	})
}

func TestFlushChainRequiresPrivileges(t *testing.T) {
	inTestNetns(t, func() {
		ctrl := NewNftablesController(discardLoggerNft())

		err := ctrl.FlushChain("plexd-test-flush")
		if err == nil {
			return
		}

		expected := "policy: nftables: flush chain"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("expected error prefix %q, got %q", expected, err.Error())
		}
	})
}

func TestApplyRulesRequiresPrivileges(t *testing.T) {
	inTestNetns(t, func() {
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
	})
}

func TestNftablesController_DedicatedTable(t *testing.T) {
	// Verify the controller uses the dedicated "plexd" table name.
	if tableName != "plexd" {
		t.Errorf("tableName = %q, want %q", tableName, "plexd")
	}
}

func TestNftablesController_ApplyRulesWithInterface(t *testing.T) {
	inTestNetns(t, func() {
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
	})
}

func TestBuildRuleExprsAllow(t *testing.T) {
	rule := FirewallRule{
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		Port:     80,
		Protocol: "tcp",
		Action:   "allow",
	}

	exprs, err := buildRuleExprs(rule, dirIn)
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

	exprs, err := buildRuleExprs(rule, dirIn)
	if err != nil {
		t.Fatalf("buildRuleExprs returned error: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("buildRuleExprs returned empty expressions")
	}
}

func TestBuildRuleExprsInvalidAction(t *testing.T) {
	rule := FirewallRule{Action: "reject"}
	_, err := buildRuleExprs(rule, dirIn)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestBuildRuleExprsInvalidProtocol(t *testing.T) {
	rule := FirewallRule{Protocol: "sctp", Action: "allow"}
	_, err := buildRuleExprs(rule, dirIn)
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestBuildRuleExprsICMP(t *testing.T) {
	rule := FirewallRule{DstIP: "10.0.0.1", Protocol: "icmp", Action: "allow"}
	exprs, err := buildRuleExprs(rule, dirIn)
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

	exprs, err := buildRuleExprs(rule, dirIn)
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
	exprs, err := buildRuleExprs(rule, dirIn)
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

	exprs, err := buildRuleExprs(rule, dirIn)
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

	exprs, err := buildRuleExprs(rule, dirIn)
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

	exprs, err := buildRuleExprs(rule, dirIn)
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

	exprs, err := buildRuleExprs(rule, dirIn)
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

	_, err := buildRuleExprs(rule, dirIn)
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
	inTestNetns(t, func() {
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
	})
}

func TestApplyAndFlushRoundTrip(t *testing.T) {
	inTestNetns(t, func() {
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
	})
}

func TestProbeErrorPrefix(t *testing.T) {
	inTestNetns(t, func() {
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
	})
}

// The pre-flight check is only worth running if its verdict matches the one the
// baseline install would reach, so assert the two agree on whatever host this
// runs on — privileged or not.
func TestProbeAgreesWithEnsureChain(t *testing.T) {
	inTestNetns(t, func() {
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
	})
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
			got, err := buildRuleExprs(tt.rule, dirIn)
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
			_, err := buildRuleExprs(tt.rule, dirIn)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("buildRuleExprs error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// pinnedConnTrackExprs writes out the two connection tracking rules for iface
// by hand, with key as the interface match: MetaKeyIIFNAME for the input and
// forward chains, MetaKeyOIFNAME for the output chain.
func pinnedConnTrackExprs(iface string, key expr.MetaKey) [][]expr.Any {
	ifaceMatch := []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(iface + "\x00")},
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
	established = append(established, ifaceMatch...)
	established = append(established, state(expr.CtStateBitESTABLISHED)...)
	established = append(established,
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		// IP_CT_DIR_REPLY, one byte.
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	var related []expr.Any
	related = append(related, ifaceMatch...)
	related = append(related, state(expr.CtStateBitRELATED)...)
	related = append(related,
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	return [][]expr.Any{established, related}
}

func TestConnTrackExprs(t *testing.T) {
	want := pinnedConnTrackExprs("plexd0", expr.MetaKeyIIFNAME)
	got := connTrackExprs("plexd0", dirIn)
	if len(got) != 2 {
		t.Fatalf("connTrackExprs returned %d rules, want 2", len(got))
	}
	assertExprs(t, got[0], want[0])
	assertExprs(t, got[1], want[1])
}

// The output chain opens with the same two rules, matched against the
// interface a packet leaves through.
func TestConnTrackExprsOut(t *testing.T) {
	want := pinnedConnTrackExprs("plexd0", expr.MetaKeyOIFNAME)
	got := connTrackExprs("plexd0", dirOut)
	if len(got) != 2 {
		t.Fatalf("connTrackExprs returned %d rules, want 2", len(got))
	}
	assertExprs(t, got[0], want[0])
	assertExprs(t, got[1], want[1])
}

// A rule without an interface matches every interface, and so do the
// connection tracking rules that open its chain.
func TestConnTrackExprsWithoutInterface(t *testing.T) {
	for _, dir := range []ifaceDir{dirIn, dirOut} {
		for i, rule := range connTrackExprs("", dir) {
			if ct, ok := rule[0].(*expr.Ct); !ok || ct.Key != expr.CtKeySTATE {
				t.Errorf("direction %d: rule %d starts with %s, want the ct state load", dir, i, formatExprs(rule[:1]))
			}
		}
	}
}

func TestChainRuleExprs(t *testing.T) {
	rules := []FirewallRule{
		{Interface: "wg0", DstIP: "10.0.0.1/32", Protocol: "tcp", Port: 22, Action: "allow"},
		{Interface: "wg1", DstIP: "fd00::1/128", Action: "allow"},
		{Interface: "wg0", Action: "deny"},
	}

	got, err := chainRuleExprs(rules, dirIn)
	if err != nil {
		t.Fatalf("chainRuleExprs returned error: %v", err)
	}

	// One connection tracking pair per interface, in order of first
	// appearance, then the rules in the order given.
	var want [][]expr.Any
	want = append(want, connTrackExprs("wg0", dirIn)...)
	want = append(want, connTrackExprs("wg1", dirIn)...)
	for _, rule := range rules {
		exprs, err := buildRuleExprs(rule, dirIn)
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
	got, err := chainRuleExprs(nil, dirIn)
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
	}, dirIn)
	want := "policy: nftables: apply rules: policy: firewall rule:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("chainRuleExprs error = %v, want one starting %q", err, want)
	}
}

// pinnedForeignSourceExprs is the rule that lets a packet leave iface
// unfiltered when its source is not an address of iface: oifname "<iface>"
// fib saddr . oif type != local counter accept. RTN_LOCAL is 2, loaded in
// host byte order.
func pinnedForeignSourceExprs(iface string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(iface + "\x00")},
		&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagSADDR: true, FlagOIF: true},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(2)},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func TestForeignSourceExprs(t *testing.T) {
	assertExprs(t, foreignSourceExprs("plexd0"), pinnedForeignSourceExprs("plexd0"))
}

func TestChainRuleExprsOut(t *testing.T) {
	rules := []FirewallRule{
		{Interface: "wg0", DstIP: "10.0.0.1/32", Protocol: "tcp", Port: 22, Action: "allow"},
		{Interface: "wg1", DstIP: "fd00::1/128", Action: "allow"},
		{Interface: "wg0", Action: "deny"},
	}

	got, err := chainRuleExprs(rules, dirOut)
	if err != nil {
		t.Fatalf("chainRuleExprs returned error: %v", err)
	}

	oifname := func(iface string) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(iface + "\x00")},
		}
	}
	// The relay probe rule: UDP to port 9 leaving through iface, from and to
	// any address of either family.
	probe := func(iface string) []expr.Any {
		return append(oifname(iface),
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x09}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		)
	}

	// Per interface, in order of first appearance, the connection tracking
	// pair, the foreign-source rule and the relay probe rule, then the rules
	// in the order given.
	var want [][]expr.Any
	for _, iface := range []string{"wg0", "wg1"} {
		want = append(want, pinnedConnTrackExprs(iface, expr.MetaKeyOIFNAME)...)
		want = append(want, pinnedForeignSourceExprs(iface))
		want = append(want, probe(iface))
	}
	for _, rule := range rules {
		exprs, err := buildRuleExprs(rule, dirOut)
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

	// Every rule of the policy matches the interface it leaves through.
	for i, rule := range rules {
		exprs := got[len(got)-len(rules)+i]
		if len(exprs) < 2 {
			t.Fatalf("rule %d has %d expressions, want an interface match first", i, len(exprs))
		}
		assertExprs(t, exprs[:2], oifname(rule.Interface))
	}
}

func TestChainRuleExprsOutEmpty(t *testing.T) {
	for _, rules := range [][]FirewallRule{nil, {}} {
		got, err := chainRuleExprs(rules, dirOut)
		if err != nil {
			t.Fatalf("chainRuleExprs(%#v, dirOut) returned error: %v", rules, err)
		}
		if len(got) != 0 {
			t.Errorf("chainRuleExprs(%#v, dirOut) returned %d rules, want none", rules, len(got))
		}
	}
}

func TestChainRuleExprsOutRejectsInvalidRule(t *testing.T) {
	rules := []FirewallRule{
		{Interface: "wg0", Action: "allow"},
		{Interface: "wg0", SrcIP: "not-an-ip", Action: "allow"},
	}
	_, err := chainRuleExprs(rules, dirOut)
	want := "policy: nftables: apply rules: policy: firewall rule:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("chainRuleExprs error = %v, want one starting %q", err, want)
	}
	if _, errIn := chainRuleExprs(rules, dirIn); errIn == nil || errIn.Error() != err.Error() {
		t.Errorf("chainRuleExprs errors differ by direction: dirIn %v, dirOut %v", errIn, err)
	}
}

// The output chain matches a rule exactly as the input chain does, except
// that the interface match reads the interface a packet leaves through.
func TestBuildRuleExprsOutInterface(t *testing.T) {
	rule := FirewallRule{
		Interface: "wg0",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		Port:      443,
		Protocol:  "tcp",
		Action:    "allow",
	}

	in, err := buildRuleExprs(rule, dirIn)
	if err != nil {
		t.Fatalf("buildRuleExprs(dirIn) returned error: %v", err)
	}
	out, err := buildRuleExprs(rule, dirOut)
	if err != nil {
		t.Fatalf("buildRuleExprs(dirOut) returned error: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("buildRuleExprs(dirOut) returned %d expressions, want an interface match first", len(out))
	}
	assertExprs(t, out[:2], []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("wg0\x00")},
	})
	assertExprs(t, out[2:], in[2:])
}

// A rule without an interface gets no interface match in either direction.
func TestBuildRuleExprsOutWithoutInterface(t *testing.T) {
	for _, rule := range []FirewallRule{
		{DstIP: "10.0.0.1/32", Port: 22, Protocol: "tcp", Action: "allow"},
		{Action: "deny"},
	} {
		in, err := buildRuleExprs(rule, dirIn)
		if err != nil {
			t.Fatalf("buildRuleExprs(%+v, dirIn) returned error: %v", rule, err)
		}
		out, err := buildRuleExprs(rule, dirOut)
		if err != nil {
			t.Fatalf("buildRuleExprs(%+v, dirOut) returned error: %v", rule, err)
		}
		for _, e := range out {
			if meta, ok := e.(*expr.Meta); ok && (meta.Key == expr.MetaKeyOIFNAME || meta.Key == expr.MetaKeyIIFNAME) {
				t.Errorf("buildRuleExprs(%+v, dirOut) = %s, want no interface match", rule, formatExprs(out))
			}
		}
		assertExprs(t, out, in)
	}
}

func TestRelayProbeRule(t *testing.T) {
	got := relayProbeRule("plexd0")
	want := FirewallRule{Interface: "plexd0", Protocol: "udp", Port: 9, Action: "allow"}
	if got != want {
		t.Errorf("relayProbeRule(plexd0) = %+v, want %+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("relayProbeRule(plexd0).Validate() = %v, want nil", err)
	}
}

// An ApplyRules batch writes the input list into two chains and the output
// list into one, and every rule it adds gets the per-rule allowance on top of
// the base.
func TestApplyBufferBytes(t *testing.T) {
	for _, tc := range []struct {
		in, out, want int
	}{
		{0, 0, netlinkBufferBase},
		{3, 4, netlinkBufferBase + 10*netlinkBufferPerRule},
		{1003, 1004, netlinkBufferBase + 3010*netlinkBufferPerRule},
	} {
		if got := applyBufferBytes(tc.in, tc.out); got != tc.want {
			t.Errorf("applyBufferBytes(%d, %d) = %d, want %d", tc.in, tc.out, got, tc.want)
		}
	}
}

func TestChainNames(t *testing.T) {
	input, forward, output := chainNames("plexd-mesh")
	if input != "plexd-mesh-input" || forward != "plexd-mesh-forward" || output != "plexd-mesh-output" {
		t.Errorf("chainNames(plexd-mesh) = %q, %q, %q, want plexd-mesh-input, plexd-mesh-forward, plexd-mesh-output", input, forward, output)
	}
}

// nftLoggedRules is a logged allow of TCP to port 7001 on plexd0 with tag
// "1/0", then the default deny.
func nftLoggedRules() []FirewallRule {
	return []FirewallRule{
		{Interface: "plexd0", Protocol: "tcp", Port: 7001, Action: "allow", LogTag: "1/0"},
		{Interface: "plexd0", Action: "deny"},
	}
}

// pinnedLoggedRules writes out by hand the rules nftLoggedRules become behind a
// chain's opening rules, with key as the interface match: the log rule, the
// accept rule and the deny.
func pinnedLoggedRules(key expr.MetaKey) [][]expr.Any {
	iface := func() []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: key, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("plexd0\x00")},
		}
	}
	match := func() []expr.Any {
		return append(iface(),
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			// 7001 in network byte order.
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x1b, 0x59}},
		)
	}
	logRule := append(match(),
		// ct state new, loaded in host byte order.
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		// log group 28772 prefix "1/0", and no verdict.
		&expr.Log{Key: 1<<unix.NFTA_LOG_GROUP | 1<<unix.NFTA_LOG_PREFIX, Group: 28772, Data: []byte("1/0")},
	)
	accept := append(match(), &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept})
	deny := append(iface(), &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
	return [][]expr.Any{logRule, accept, deny}
}

// pinnedRelayProbeExprs is the relay probe rule of the output chain: UDP to
// port 9 leaving through iface, from and to any address of either family.
func pinnedRelayProbeExprs(iface string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(iface + "\x00")},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x09}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// pinnedChainOpening is what opens a chain for plexd0 in direction dir: the
// connection tracking pair and, for dirOut, the foreign-source rule and the
// relay probe rule.
func pinnedChainOpening(dir ifaceDir) [][]expr.Any {
	if dir == dirOut {
		opening := pinnedConnTrackExprs("plexd0", expr.MetaKeyOIFNAME)
		return append(opening, pinnedForeignSourceExprs("plexd0"), pinnedRelayProbeExprs("plexd0"))
	}
	return pinnedConnTrackExprs("plexd0", expr.MetaKeyIIFNAME)
}

// nftLogRuleCount counts the rules of list that hold a log expression.
func nftLogRuleCount(list [][]expr.Any) int {
	n := 0
	for _, rule := range list {
		for _, e := range rule {
			if _, ok := e.(*expr.Log); ok {
				n++
				break
			}
		}
	}
	return n
}

func assertNftRuleLists(t *testing.T, got, want [][]expr.Any) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d", len(got), len(want))
	}
	for i := range want {
		assertExprs(t, got[i], want[i])
	}
}

// A logged rule gets its log rule directly in front of it, in the input and
// forward list behind the connection tracking pair, and in the output list
// behind the foreign-source and relay probe rules too.
func TestChainRuleExprsLogged(t *testing.T) {
	for _, tc := range []struct {
		dir ifaceDir
		key expr.MetaKey
	}{
		{dirIn, expr.MetaKeyIIFNAME},
		{dirOut, expr.MetaKeyOIFNAME},
	} {
		got, err := chainRuleExprs(nftLoggedRules(), tc.dir)
		if err != nil {
			t.Fatalf("chainRuleExprs(dir %d) returned error: %v", tc.dir, err)
		}
		assertNftRuleLists(t, got, append(pinnedChainOpening(tc.dir), pinnedLoggedRules(tc.key)...))
	}
}

// Without a log tag the lists are the ones plexd wrote before connection
// logging: no log rule in either direction.
func TestChainRuleExprsUntaggedUnchanged(t *testing.T) {
	for _, tc := range []struct {
		dir ifaceDir
		key expr.MetaKey
	}{
		{dirIn, expr.MetaKeyIIFNAME},
		{dirOut, expr.MetaKeyOIFNAME},
	} {
		got, err := chainRuleExprs(withoutLogTags(nftLoggedRules()), tc.dir)
		if err != nil {
			t.Fatalf("chainRuleExprs(dir %d) returned error: %v", tc.dir, err)
		}
		assertNftRuleLists(t, got, append(pinnedChainOpening(tc.dir), pinnedLoggedRules(tc.key)[1:]...))
		if n := nftLogRuleCount(got); n != 0 {
			t.Errorf("dir %d: %d log rules, want none", tc.dir, n)
		}
	}
}

func TestLogRuleExprsRejectsInvalidRule(t *testing.T) {
	if _, err := logRuleExprs(FirewallRule{SrcIP: "not-an-ip", Action: "allow", LogTag: "1/0"}, dirIn); err == nil {
		t.Error("logRuleExprs accepted a rule with an invalid source address")
	}
}

// assertNoNftLogRules checks that rules, written into either list, carry no
// log rule and match the lists of nftLoggedRules without tags.
func assertNoNftLogRules(t *testing.T, rules []FirewallRule) {
	t.Helper()
	for _, dir := range []ifaceDir{dirIn, dirOut} {
		got, err := chainRuleExprs(rules, dir)
		if err != nil {
			t.Fatalf("chainRuleExprs(dir %d) returned error: %v", dir, err)
		}
		if n := nftLogRuleCount(got); n != 0 {
			t.Errorf("dir %d: %d log rules, want none", dir, n)
		}
		want, err := chainRuleExprs(withoutLogTags(nftLoggedRules()), dir)
		if err != nil {
			t.Fatalf("chainRuleExprs(dir %d) returned error: %v", dir, err)
		}
		assertNftRuleLists(t, got, want)
	}
}

// When the reader cannot bind the NFLOG group, ApplyRules installs the rules
// without their log tags and says so once, with the bind error.
func TestNftablesController_LoggingUnavailable(t *testing.T) {
	var buf bytes.Buffer
	ctrl := NewNftablesController(captureLogger(&buf))
	var groups []uint16
	ctrl.openLog = func(group uint16, _ ConnSink, _ *slog.Logger) (*nflogReader, error) {
		groups = append(groups, group)
		// The kernel refuses the bind.
		conn := nltest.Dial(func(reqs []netlink.Message) ([]netlink.Message, error) {
			return nltest.Error(int(unix.EBUSY), reqs)
		})
		defer func() { _ = conn.Close() }()
		return nil, bindNflog(conn, group)
	}
	ctrl.SetConnSink(&nflogSink{})

	got := ctrl.prepareLogging(nftLoggedRules())
	if want := withoutLogTags(nftLoggedRules()); !reflect.DeepEqual(got, want) {
		t.Errorf("prepareLogging() = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(groups, []uint16{28772}) {
		t.Errorf("openLog was called for groups %v, want [28772]", groups)
	}
	assertNoNftLogRules(t, got)
	out := buf.String()
	for _, want := range []string{
		"level=WARN",
		`msg="policy connection logging unavailable, logged rules are enforced without it"`,
		"component=policy",
		`error="policy: nftables: nflog: bind group 28772: `,
		"device or resource busy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q lacks %q", out, want)
		}
	}
	if heldNflogReader(ctrl) != nil {
		t.Error("the controller kept a reader after the open failed")
	}

	// ApplyRules takes the same path and logs the Warn once per apply. Its
	// batch fails without CAP_NET_ADMIN.
	buf.Reset()
	inTestNetns(t, func() {
		const chain = "plexd-test-nflog"
		err := ctrl.ApplyRules(chain, nftLoggedRules())
		if err == nil {
			_ = ctrl.FlushChain(chain)
			_ = ctrl.DeleteChain(chain)
		} else if want := "policy: nftables: apply rules"; !strings.HasPrefix(err.Error(), want) {
			t.Errorf("ApplyRules() error = %q, want one starting %q", err, want)
		}
	})
	if n := strings.Count(buf.String(), connLogUnavailable); n != 1 {
		t.Errorf("ApplyRules logged %q %d times, want once:\n%s", connLogUnavailable, n, buf.String())
	}
}

// Without a sink nothing reads the group, so ApplyRules installs the rules
// without their log tags, opens no reader and logs no Warn.
func TestNftablesController_LoggingWithoutSink(t *testing.T) {
	var buf bytes.Buffer
	ctrl := NewNftablesController(captureLogger(&buf))
	ctrl.openLog = func(uint16, ConnSink, *slog.Logger) (*nflogReader, error) {
		t.Error("openLog was called without a sink")
		return nil, errors.New("no sink")
	}

	got := ctrl.prepareLogging(nftLoggedRules())
	if want := withoutLogTags(nftLoggedRules()); !reflect.DeepEqual(got, want) {
		t.Errorf("prepareLogging() = %+v, want %+v", got, want)
	}
	assertNoNftLogRules(t, got)

	inTestNetns(t, func() {
		const chain = "plexd-test-nflog"
		if err := ctrl.ApplyRules(chain, nftLoggedRules()); err == nil {
			_ = ctrl.FlushChain(chain)
			_ = ctrl.DeleteChain(chain)
		}
	})
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("logged %q, want no Warn line", buf.String())
	}
}

// heldNflogReader returns the reader the controller holds.
func heldNflogReader(c *NftablesController) *nflogReader {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reader
}

// The controller opens one reader for logged rules and keeps it, replaces one
// whose loop ended, and closes it in DeleteChain and when the sink changes.
func TestNftablesController_LogReaderLifecycle(t *testing.T) {
	f := &fakeNflog{}
	ctrl := NewNftablesController(discardLoggerNft())
	ctrl.openLog = f.open
	sink := &nflogSink{}
	ctrl.SetConnSink(sink)

	rules := nftLoggedRules()
	if got := ctrl.prepareLogging(rules); !reflect.DeepEqual(got, rules) {
		t.Errorf("prepareLogging() = %+v, want the rules with their tags %+v", got, rules)
	}
	if f.opened() != 1 || f.groups[0] != nflogGroup || f.sinks[0] != ConnSink(sink) {
		t.Fatalf("openLog calls: groups %v, sinks %v; want one for group %d and the sink", f.groups, f.sinks, nflogGroup)
	}
	if heldNflogReader(ctrl) != f.readers[0] {
		t.Error("the controller does not hold the reader it opened")
	}

	t.Log("a running reader serves the next apply, with or without a logged rule")
	ctrl.prepareLogging(rules)
	if got := ctrl.prepareLogging(withoutLogTags(rules)); !reflect.DeepEqual(got, withoutLogTags(rules)) {
		t.Errorf("prepareLogging() of untagged rules = %+v, want them unchanged", got)
	}
	if f.opened() != 1 || !f.readers[0].running() {
		t.Errorf("openLog called %d times, reader running %v; want once and running", f.opened(), f.readers[0].running())
	}

	t.Log("a reader whose loop ended is closed and replaced at the next apply with a logged rule")
	close(f.fails[0])
	<-f.readers[0].done
	ctrl.prepareLogging(rules)
	if f.opened() != 2 {
		t.Fatalf("openLog called %d times, want twice", f.opened())
	}
	if !f.readers[0].closed.Load() {
		t.Error("the reader whose loop ended was not closed")
	}

	t.Log("DeleteChain closes the reader, also when no chain exists")
	inTestNetns(t, func() {
		_ = ctrl.DeleteChain("plexd-test-nflog-none")
	})
	if f.readers[1].running() || heldNflogReader(ctrl) != nil {
		t.Errorf("after DeleteChain: reader running %v, held %v; want it closed and dropped", f.readers[1].running(), heldNflogReader(ctrl) != nil)
	}

	t.Log("a new sink closes the reader opened for the old one")
	ctrl.prepareLogging(rules)
	other := &nflogSink{}
	ctrl.SetConnSink(other)
	if f.readers[2].running() || heldNflogReader(ctrl) != nil {
		t.Errorf("after SetConnSink: reader running %v, held %v; want it closed and dropped", f.readers[2].running(), heldNflogReader(ctrl) != nil)
	}
	ctrl.prepareLogging(rules)
	if f.opened() != 4 || f.sinks[3] != ConnSink(other) {
		t.Fatalf("openLog called %d times; want 4, the last with the new sink", f.opened())
	}
	ctrl.closeLog()
	if f.readers[3].running() {
		t.Error("closeLog left the reader running")
	}
}
