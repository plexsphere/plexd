//go:build linux

package policy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables"
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

// pinnedIfaceMatch is the interface match of a rule on iface, with key
// MetaKeyIIFNAME or MetaKeyOIFNAME, written out by hand. An empty iface
// stands for a rule without a match of its own: one behind the guard of a
// single interface, or one whose Interface is empty.
func pinnedIfaceMatch(iface string, key expr.MetaKey) []expr.Any {
	if iface == "" {
		return nil
	}
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(iface + "\x00")},
	}
}

// pinnedGuard is the guard that opens a list for ifaces, with key as the
// interface it reads: the name loaded once, one != per interface, then
// accept, and no counter.
func pinnedGuard(key expr.MetaKey, ifaces ...string) []expr.Any {
	guard := []expr.Any{&expr.Meta{Key: key, Register: 1}}
	for _, iface := range ifaces {
		guard = append(guard, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte(iface + "\x00")})
	}
	return append(guard, &expr.Verdict{Kind: expr.VerdictAccept})
}

// pinnedConnTrackExprs writes out the two connection tracking rules for iface
// by hand, with key as the interface match: MetaKeyIIFNAME for the input and
// forward chains, MetaKeyOIFNAME for the output chain. An empty iface leaves
// the match out.
func pinnedConnTrackExprs(iface string, key expr.MetaKey) [][]expr.Any {
	ifaceMatch := pinnedIfaceMatch(iface, key)
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

// oneIfaceRules is a ruleset on one interface, wg0: an IPv4 allow with a
// port, an IPv6 allow and the default deny.
func oneIfaceRules() []FirewallRule {
	return []FirewallRule{
		{Interface: "wg0", DstIP: "10.0.0.1/32", Protocol: "tcp", Port: 22, Action: "allow"},
		{Interface: "wg0", DstIP: "fd00::1/128", Action: "allow"},
		{Interface: "wg0", Action: "deny"},
	}
}

// ruleEntries returns the list chainRuleExprs builds for hook from the
// segments segmentRules cuts from rules, with or without sets.
func ruleEntries(t *testing.T, rules []FirewallRule, sets bool, hook chainHook) []chainEntry {
	t.Helper()
	segments, err := segmentRules(rules, sets)
	if err != nil {
		t.Fatalf("segmentRules(sets %v) returned error: %v", sets, err)
	}
	got, err := chainRuleExprs(segments, hook)
	if err != nil {
		t.Fatalf("chainRuleExprs(hook %d) returned error: %v", hook, err)
	}
	return got
}

// entryExprs returns the expressions of each entry.
func entryExprs(entries []chainEntry) [][]expr.Any {
	out := make([][]expr.Any, len(entries))
	for i, entry := range entries {
		out[i] = entry.exprs
	}
	return out
}

// ruleLists returns the list chainRuleExprs builds for hook from rules cut
// into segments without sets, and fails on an entry that holds a set.
func ruleLists(t *testing.T, rules []FirewallRule, hook chainHook) [][]expr.Any {
	t.Helper()
	entries := ruleEntries(t, rules, false, hook)
	for i, entry := range entries {
		if entry.set != nil {
			t.Fatalf("hook %d: entry %d holds a set, want none without sets", hook, i)
		}
	}
	return entryExprs(entries)
}

// builtRules returns buildRuleExprs of each rule with dir, in order.
func builtRules(t *testing.T, rules []FirewallRule, dir ifaceDir) [][]expr.Any {
	t.Helper()
	var out [][]expr.Any
	for _, rule := range rules {
		exprs, err := buildRuleExprs(rule, dir)
		if err != nil {
			t.Fatalf("buildRuleExprs(%+v) returned error: %v", rule, err)
		}
		out = append(out, exprs)
	}
	return out
}

// assertNoIfaceMatch checks that no rule of list loads an interface name.
func assertNoIfaceMatch(t *testing.T, list [][]expr.Any) {
	t.Helper()
	for i, rule := range list {
		for _, e := range rule {
			if meta, ok := e.(*expr.Meta); ok && (meta.Key == expr.MetaKeyIIFNAME || meta.Key == expr.MetaKeyOIFNAME) {
				t.Errorf("rule %d = %s, want no interface match", i, formatExprs(rule))
			}
		}
	}
}

func TestGuardExprs(t *testing.T) {
	assertExprs(t, guardExprs([]string{"plexd0"}, dirIn), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("plexd0\x00")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	})
	assertExprs(t, guardExprs([]string{"plexd0"}, dirOut), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("plexd0\x00")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	})
	// Two interfaces: one load, then one != per interface in the order given.
	assertExprs(t, guardExprs([]string{"wg1", "wg0"}, dirIn), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("wg1\x00")},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("wg0\x00")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	})
}

// Behind the guard the input list opens with the connection tracking pair
// and the round-trip probe rule, without their iifname matches, and holds
// the rules without theirs.
func TestChainRuleExprs(t *testing.T) {
	rules := oneIfaceRules()
	got := ruleLists(t, rules, hookInput)

	want := [][]expr.Any{pinnedGuard(expr.MetaKeyIIFNAME, "wg0")}
	want = append(want, pinnedChainOpening(hookInput, "")...)
	want = append(want, builtRules(t, rules, dirNone)...)
	assertNftRuleLists(t, got, want)
	assertNoIfaceMatch(t, got[1:])
}

// The forward list opens with the guard and the connection tracking pair
// alone: nothing the node forwards passes the round-trip probe exemption.
func TestChainRuleExprsForward(t *testing.T) {
	rules := oneIfaceRules()
	got := ruleLists(t, rules, hookForward)

	want := [][]expr.Any{pinnedGuard(expr.MetaKeyIIFNAME, "wg0")}
	want = append(want, pinnedChainOpening(hookForward, "")...)
	want = append(want, builtRules(t, rules, dirNone)...)
	assertNftRuleLists(t, got, want)
	assertNoIfaceMatch(t, got[1:])
}

// With two interfaces the guard names both, in order of first appearance,
// and every other rule keeps its interface match: the opening per interface
// as plexd wrote it before the guard, then the rules.
func TestChainRuleExprsTwoInterfaces(t *testing.T) {
	rules := []FirewallRule{
		{Interface: "wg0", DstIP: "10.0.0.1/32", Protocol: "tcp", Port: 22, Action: "allow"},
		{Interface: "wg1", DstIP: "fd00::1/128", Action: "allow"},
		{Interface: "wg0", Action: "deny"},
	}
	for _, tc := range []struct {
		hook chainHook
		key  expr.MetaKey
		dir  ifaceDir
	}{
		{hookInput, expr.MetaKeyIIFNAME, dirIn},
		{hookForward, expr.MetaKeyIIFNAME, dirIn},
		{hookOutput, expr.MetaKeyOIFNAME, dirOut},
	} {
		got := ruleLists(t, rules, tc.hook)
		want := [][]expr.Any{pinnedGuard(tc.key, "wg0", "wg1")}
		want = append(want, pinnedChainOpening(tc.hook, "wg0")...)
		want = append(want, pinnedChainOpening(tc.hook, "wg1")...)
		want = append(want, builtRules(t, rules, tc.dir)...)
		assertNftRuleLists(t, got, want)
	}
}

// A rule without an interface matches every interface, so no guard can
// stand in front of the list: it is the list plexd wrote before the guard,
// each opening and rule with the interface match of its rule, none for the
// empty one.
func TestChainRuleExprsWithoutInterface(t *testing.T) {
	rules := []FirewallRule{
		{Interface: "plexd0", DstIP: "10.0.0.1/32", Protocol: "tcp", Port: 22, Action: "allow"},
		{Action: "deny"},
	}
	for _, tc := range []struct {
		hook chainHook
		key  expr.MetaKey
		dir  ifaceDir
	}{
		{hookInput, expr.MetaKeyIIFNAME, dirIn},
		{hookForward, expr.MetaKeyIIFNAME, dirIn},
		{hookOutput, expr.MetaKeyOIFNAME, dirOut},
	} {
		got := ruleLists(t, rules, tc.hook)
		want := pinnedChainOpening(tc.hook, "plexd0")
		want = append(want, pinnedChainOpening(tc.hook, "")...)
		want = append(want, builtRules(t, rules, tc.dir)...)
		assertNftRuleLists(t, got, want)
	}
}

// pinnedSetLookup writes out by hand the set rule of family and shape behind
// the guard of a single interface: the family match, the fields of the key
// into the 4-byte registers from 8 on, the lookup from register 8, a counter
// and accept.
func pinnedSetLookup(family addrFamily, shape setShape) []expr.Any {
	network := func(reg, offset, length uint32) *expr.Payload {
		return &expr.Payload{DestRegister: reg, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}
	}
	var exprs []expr.Any
	var protoReg uint32
	if family == familyIPv4 {
		exprs = []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			network(8, 12, 4), // ip saddr
			network(9, 16, 4), // ip daddr
		}
		protoReg = 10
	} else {
		exprs = []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			network(8, 8, 16),   // ip6 saddr, registers 8 to 11
			network(12, 24, 16), // ip6 daddr, registers 12 to 15
		}
		protoReg = 16
	}
	if shape != shapeAddrs {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: protoReg})
	}
	if shape == shapePort {
		exprs = append(exprs, &expr.Payload{DestRegister: protoReg + 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
	}
	return append(exprs,
		&expr.Lookup{SourceRegister: 8},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// setElem returns the set element of a rule's box.
func setElem(t *testing.T, rule FirewallRule) nftables.SetElement {
	t.Helper()
	box, _, shape, err := boxOf(rule)
	if err != nil {
		t.Fatalf("boxOf(%+v) returned error: %v", rule, err)
	}
	return box.element(shape)
}

func TestSegmentRules(t *testing.T) {
	allowA := FirewallRule{Interface: "plexd0", SrcIP: "10.0.0.1/32", DstIP: "10.0.0.9/32", Port: 22, Protocol: "tcp", Action: "allow"}
	allowB := FirewallRule{Interface: "plexd0", SrcIP: "10.0.0.2/32", DstIP: "10.0.0.9/32", Port: 22, Protocol: "tcp", Action: "allow"}
	logged := FirewallRule{Interface: "plexd0", SrcIP: "10.0.0.3/32", DstIP: "10.0.0.9/32", Port: 80, Protocol: "tcp", Action: "allow", LogTag: "1/2"}
	allowC := FirewallRule{Interface: "plexd0", DstIP: "fd00::9/128", Action: "allow"}
	deny := FirewallRule{Interface: "plexd0", Action: "deny"}
	noAddr := FirewallRule{Interface: "plexd0", Port: 53, Protocol: "udp", Action: "allow"}
	rules := []FirewallRule{allowA, allowB, logged, allowC, deny, noAddr}

	t.Log("allow, allow, logged allow, allow, deny, allow without an address: a run of two, a rule, a run of one, two rules")
	got, err := segmentRules(rules, true)
	if err != nil {
		t.Fatalf("segmentRules() returned error: %v", err)
	}
	want := []segment{
		{iface: "plexd0", sets: []ruleSet{{family: familyIPv4, shape: shapePort, elems: []nftables.SetElement{setElem(t, allowA), setElem(t, allowB)}}}},
		{rule: logged, iface: "plexd0"},
		{iface: "plexd0", sets: []ruleSet{{family: familyIPv6, shape: shapeAddrs, elems: []nftables.SetElement{setElem(t, allowC)}}}},
		{rule: deny, iface: "plexd0"},
		{rule: noAddr, iface: "plexd0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("segmentRules() =\n%+v\nwant\n%+v", got, want)
	}

	t.Log("without sets every rule is a segment of its own")
	got, err = segmentRules(rules, false)
	if err != nil {
		t.Fatalf("segmentRules(sets false) returned error: %v", err)
	}
	want = nil
	for _, rule := range rules {
		want = append(want, segment{rule: rule, iface: "plexd0"})
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("segmentRules(sets false) =\n%+v\nwant\n%+v", got, want)
	}

	t.Log("two consecutive allows on different interfaces are two runs")
	onWG0, onWG1 := allowA, allowB
	onWG0.Interface, onWG1.Interface = "wg0", "wg1"
	got, err = segmentRules([]FirewallRule{onWG0, onWG1}, true)
	if err != nil {
		t.Fatalf("segmentRules(wg0, wg1) returned error: %v", err)
	}
	want = []segment{
		{iface: "wg0", sets: []ruleSet{{family: familyIPv4, shape: shapePort, elems: []nftables.SetElement{setElem(t, onWG0)}}}},
		{iface: "wg1", sets: []ruleSet{{family: familyIPv4, shape: shapePort, elems: []nftables.SetElement{setElem(t, onWG1)}}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("segmentRules(wg0, wg1) =\n%+v\nwant\n%+v", got, want)
	}

	t.Log("a nil and an empty ruleset give no segment")
	for _, rules := range [][]FirewallRule{nil, {}} {
		if got, err := segmentRules(rules, true); err != nil || len(got) != 0 {
			t.Errorf("segmentRules(%#v) = %+v, %v; want no segment and no error", rules, got, err)
		}
	}
}

func TestBoxOf(t *testing.T) {
	prefix := netip.MustParsePrefix
	for _, tc := range []struct {
		name  string
		rule  FirewallRule
		fam   addrFamily
		shape setShape
		box   ruleBox
	}{
		{
			name:  "tcp with a port",
			rule:  FirewallRule{SrcIP: "10.99.0.0/24", DstIP: "10.99.0.1", Port: 5201, Protocol: "tcp", Action: "allow"},
			fam:   familyIPv4,
			shape: shapePort,
			box:   ruleBox{src: prefix("10.99.0.0/24"), dst: prefix("10.99.0.1/32"), proto: 6, port: 5201, last: 5201},
		},
		{
			name:  "tcp with a port range",
			rule:  FirewallRule{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Port: 1000, PortTo: 2000, Protocol: "tcp", Action: "allow"},
			fam:   familyIPv4,
			shape: shapePort,
			box:   ruleBox{src: prefix("10.0.0.1/32"), dst: prefix("10.0.0.2/32"), proto: 6, port: 1000, last: 2000},
		},
		{
			name:  "a port range ending at its start",
			rule:  FirewallRule{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Port: 1000, PortTo: 1000, Protocol: "tcp", Action: "allow"},
			fam:   familyIPv4,
			shape: shapePort,
			box:   ruleBox{src: prefix("10.0.0.1/32"), dst: prefix("10.0.0.2/32"), proto: 6, port: 1000, last: 1000},
		},
		{
			name:  "udp without a port",
			rule:  FirewallRule{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "udp", Action: "allow"},
			fam:   familyIPv4,
			shape: shapeProto,
			box:   ruleBox{src: prefix("10.0.0.1/32"), dst: prefix("10.0.0.2/32"), proto: 17},
		},
		{
			name:  "icmp in IPv4",
			rule:  FirewallRule{DstIP: "10.0.0.1", Protocol: "icmp", Action: "allow"},
			fam:   familyIPv4,
			shape: shapeProto,
			box:   ruleBox{src: prefix("0.0.0.0/0"), dst: prefix("10.0.0.1/32"), proto: 1},
		},
		{
			name:  "icmp in IPv6",
			rule:  FirewallRule{DstIP: "fd00::1", Protocol: "icmp", Action: "allow"},
			fam:   familyIPv6,
			shape: shapeProto,
			box:   ruleBox{src: prefix("::/0"), dst: prefix("fd00::1/128"), proto: 58},
		},
		{
			name:  "any protocol",
			rule:  FirewallRule{SrcIP: "fd00:99::/64", DstIP: "fd00:99::1/128", Action: "allow"},
			fam:   familyIPv6,
			shape: shapeAddrs,
			box:   ruleBox{src: prefix("fd00:99::/64"), dst: prefix("fd00:99::1/128")},
		},
		{
			name:  "only a source in IPv4",
			rule:  FirewallRule{SrcIP: "10.0.0.1/32", Action: "allow"},
			fam:   familyIPv4,
			shape: shapeAddrs,
			box:   ruleBox{src: prefix("10.0.0.1/32"), dst: prefix("0.0.0.0/0")},
		},
		{
			name:  "only a source in IPv6",
			rule:  FirewallRule{SrcIP: "fd00::/64", Action: "allow"},
			fam:   familyIPv6,
			shape: shapeAddrs,
			box:   ruleBox{src: prefix("fd00::/64"), dst: prefix("::/0")},
		},
		{
			name:  "a zero-length prefix",
			rule:  FirewallRule{SrcIP: "0.0.0.0/0", DstIP: "10.0.0.1/32", Port: 22, Protocol: "tcp", Action: "allow"},
			fam:   familyIPv4,
			shape: shapePort,
			box:   ruleBox{src: prefix("0.0.0.0/0"), dst: prefix("10.0.0.1/32"), proto: 6, port: 22, last: 22},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			box, fam, shape, err := boxOf(tc.rule)
			if err != nil {
				t.Fatalf("boxOf() returned error: %v", err)
			}
			if box != tc.box || fam != tc.fam || shape != tc.shape {
				t.Errorf("boxOf() = %+v, family %d, shape %d; want %+v, family %d, shape %d", box, fam, shape, tc.box, tc.fam, tc.shape)
			}
		})
	}

	if _, _, _, err := boxOf(FirewallRule{Port: 22, Protocol: "tcp", Action: "allow"}); err == nil {
		t.Error("boxOf() of a rule without an address returned no error")
	}
}

func TestLayerBoxes(t *testing.T) {
	box := func(src, dst string, proto byte, port, last uint16) ruleBox {
		return ruleBox{src: netip.MustParsePrefix(src), dst: netip.MustParsePrefix(dst), proto: proto, port: port, last: last}
	}
	tcp80 := box("10.0.0.0/24", "10.0.1.1/32", 6, 80, 90)
	tcp85 := box("10.0.0.0/24", "10.0.1.1/32", 6, 85, 95)
	tcp100 := box("10.0.0.0/24", "10.0.1.1/32", 6, 100, 100)
	udp80 := box("10.0.0.0/24", "10.0.1.1/32", 17, 80, 90)
	other := box("10.0.2.0/24", "10.0.1.1/32", 6, 80, 90)
	big := box("10.0.0.0/8", "10.0.1.0/24", 6, 80, 90)
	small := box("10.0.5.0/24", "10.0.1.1/32", 6, 85, 85)

	for _, tc := range []struct {
		name  string
		boxes []ruleBox
		want  [][]ruleBox
	}{
		{"disjoint boxes share a layer", []ruleBox{tcp80, udp80, other, tcp100}, [][]ruleBox{{tcp80, udp80, other, tcp100}}},
		{"a contained box after its container is dropped", []ruleBox{big, small}, [][]ruleBox{{big}}},
		{"a contained box before its container is dropped", []ruleBox{small, big}, [][]ruleBox{{big}}},
		{"identical boxes are kept once", []ruleBox{tcp80, tcp80}, [][]ruleBox{{tcp80}}},
		{"crossing port ranges on equal addresses take two layers", []ruleBox{tcp80, tcp85}, [][]ruleBox{{tcp80}, {tcp85}}},
		{"a box takes the first layer it fits", []ruleBox{tcp80, tcp85, tcp100}, [][]ruleBox{{tcp80, tcp100}, {tcp85}}},
		{"no boxes", []ruleBox{}, nil},
		{"nil", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := layerBoxes(tc.boxes); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("layerBoxes() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRuleBoxElement(t *testing.T) {
	hexBytes := func(s string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	box := func(src, dst string, proto byte, port, last uint16) ruleBox {
		return ruleBox{src: netip.MustParsePrefix(src), dst: netip.MustParsePrefix(dst), proto: proto, port: port, last: last}
	}
	for _, tc := range []struct {
		name     string
		box      ruleBox
		shape    setShape
		key, end string
	}{
		{
			name:  "IPv4 port: 10.99.0.0/24 to 10.99.0.1/32, tcp 5201",
			box:   box("10.99.0.0/24", "10.99.0.1/32", 6, 5201, 5201),
			shape: shapePort,
			key:   "0a630000 0a630001 06000000 14510000",
			end:   "0a6300ff 0a630001 06000000 14510000",
		},
		{
			name:  "IPv6 port: fd00:99::/64 to fd00:99::1/128, tcp 7001-7003",
			box:   box("fd00:99::/64", "fd00:99::1/128", 6, 7001, 7003),
			shape: shapePort,
			key:   "fd000099000000000000000000000000 fd000099000000000000000000000001 06000000 1b590000",
			end:   "fd00009900000000ffffffffffffffff fd000099000000000000000000000001 06000000 1b5b0000",
		},
		{
			name:  "proto: 10.0.0.1/32 to 10.0.0.0/30, udp",
			box:   box("10.0.0.1/32", "10.0.0.0/30", 17, 0, 0),
			shape: shapeProto,
			key:   "0a000001 0a000000 11000000",
			end:   "0a000001 0a000003 11000000",
		},
		{
			name:  "addresses: 0.0.0.0/0 to 10.0.0.0/20",
			box:   box("0.0.0.0/0", "10.0.0.0/20", 0, 0, 0),
			shape: shapeAddrs,
			key:   "00000000 0a000000",
			end:   "ffffffff 0a000fff",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.box.element(tc.shape)
			want := nftables.SetElement{Key: hexBytes(tc.key), KeyEnd: hexBytes(tc.end)}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("element() = key %x end %x, want key %x end %x", got.Key, got.KeyEnd, want.Key, want.KeyEnd)
			}
			if n := setKeyType(familyOf(tc.box.src), tc.shape).Bytes; int(n) != len(got.Key) {
				t.Errorf("setKeyType() is %d bytes long, the key %d", n, len(got.Key))
			}
		})
	}
}

// The lookup of each shape in both families loads the fields of its key into
// the registers from 8 on, without an interface match behind a guard
// (dirNone) or for an empty interface, and with one otherwise.
func TestSetLookupExprs(t *testing.T) {
	for _, fam := range []addrFamily{familyIPv4, familyIPv6} {
		for _, shape := range []setShape{shapeAddrs, shapeProto, shapePort} {
			want := pinnedSetLookup(fam, shape)
			assertExprs(t, setLookupExprs("plexd0", dirNone, fam, shape), want)
			assertExprs(t, setLookupExprs("", dirIn, fam, shape), want)
			assertExprs(t, setLookupExprs("plexd0", dirIn, fam, shape), append(pinnedIfaceMatch("plexd0", expr.MetaKeyIIFNAME), want...))
			assertExprs(t, setLookupExprs("plexd0", dirOut, fam, shape), append(pinnedIfaceMatch("plexd0", expr.MetaKeyOIFNAME), want...))
		}
	}
}

func TestElementChunks(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want []int
	}{
		{0, nil},
		{256, []int{256}},
		{257, []int{256, 1}},
		{1000, []int{256, 256, 256, 232}},
	} {
		elems := make([]nftables.SetElement, tc.n)
		for i := range elems {
			elems[i].Key = []byte{byte(i >> 8), byte(i)}
		}
		var sizes []int
		var joined []nftables.SetElement
		for _, chunk := range elementChunks(elems) {
			sizes = append(sizes, len(chunk))
			joined = append(joined, chunk...)
		}
		if !reflect.DeepEqual(sizes, tc.want) {
			t.Errorf("elementChunks(%d elements) gave chunks of %v, want %v", tc.n, sizes, tc.want)
		}
		if len(joined) != len(elems) || (len(elems) > 0 && !reflect.DeepEqual(joined, elems)) {
			t.Errorf("elementChunks(%d elements) lost or reordered elements", tc.n)
		}
	}
}

// Behind the guard and the opening, a logged rule stays a rule behind its
// log rule, the two IPv4 tcp allows become one set rule of the port shape
// with two elements, the IPv6 any-protocol allow one set rule of the address
// shape with one element, and the deny stays a rule.
func TestChainRuleExprsSets(t *testing.T) {
	logged := FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.2/32", DstIP: "10.99.0.1/32", Port: 7001, Protocol: "tcp", Action: "allow", LogTag: "1/0"}
	ssh := FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.0/24", DstIP: "10.99.0.1/32", Port: 22, Protocol: "tcp", Action: "allow"}
	https := FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.0/24", DstIP: "10.99.0.1/32", Port: 443, Protocol: "tcp", Action: "allow"}
	v6 := FirewallRule{Interface: "plexd0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::1/128", Action: "allow"}
	deny := FirewallRule{Interface: "plexd0", Action: "deny"}
	rules := []FirewallRule{logged, ssh, https, v6, deny}

	logExprs, err := logRuleExprs(logged, dirNone)
	if err != nil {
		t.Fatal(err)
	}
	rest := builtRules(t, []FirewallRule{logged, deny}, dirNone)
	for _, hook := range []chainHook{hookInput, hookForward, hookOutput} {
		got := ruleEntries(t, rules, true, hook)
		want := [][]expr.Any{pinnedGuard(guardKey(hook), "plexd0")}
		want = append(want, pinnedChainOpening(hook, "")...)
		want = append(want, logExprs, rest[0], pinnedSetLookup(familyIPv4, shapePort), pinnedSetLookup(familyIPv6, shapeAddrs), rest[1])
		assertNftRuleLists(t, entryExprs(got), want)

		n := len(got)
		wantSets := map[int]ruleSet{
			n - 3: {family: familyIPv4, shape: shapePort, elems: []nftables.SetElement{setElem(t, ssh), setElem(t, https)}},
			n - 2: {family: familyIPv6, shape: shapeAddrs, elems: []nftables.SetElement{setElem(t, v6)}},
		}
		for i, entry := range got {
			wantSet, isSet := wantSets[i]
			switch {
			case !isSet && entry.set != nil:
				t.Errorf("hook %d: entry %d holds a set, want none", hook, i)
			case isSet && (entry.set == nil || !reflect.DeepEqual(*entry.set, wantSet)):
				t.Errorf("hook %d: entry %d holds set %+v, want %+v", hook, i, entry.set, wantSet)
			}
		}
	}
}

// A nil and an empty ruleset give an empty list for all three hooks: no
// guard, no opening and no set.
func TestChainRuleExprsEmpty(t *testing.T) {
	for _, rules := range [][]FirewallRule{nil, {}} {
		for _, hook := range []chainHook{hookInput, hookForward, hookOutput} {
			if got := ruleEntries(t, rules, true, hook); len(got) != 0 {
				t.Errorf("rules %#v, hook %d: %d entries, want none", rules, hook, len(got))
			}
		}
	}
}

// segmentRules validates every rule before it cuts the list, with or without
// sets, and a logged rule as well: the error names the rule, behind the
// prefix of ApplyRules.
func TestSegmentRulesRejectsInvalidRule(t *testing.T) {
	want := "policy: nftables: apply rules: policy: firewall rule:"
	for _, tc := range []struct {
		name  string
		rules []FirewallRule
	}{
		{"unlogged", []FirewallRule{
			{Interface: "wg0", Action: "allow"},
			{Interface: "wg0", SrcIP: "not-an-ip", Action: "allow"},
		}},
		{"logged", []FirewallRule{
			{Interface: "wg0", SrcIP: "not-an-ip", Action: "allow", LogTag: "1/0"},
		}},
	} {
		for _, sets := range []bool{true, false} {
			if _, err := segmentRules(tc.rules, sets); err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Errorf("%s, sets %v: segmentRules error = %v, want one starting %q", tc.name, sets, err, want)
			}
		}
	}
}

// pinnedForeignSourceExprs is the rule that lets a packet leave iface
// unfiltered when its source is not an address of iface: oifname "<iface>"
// fib saddr . oif type != local counter accept. RTN_LOCAL is 2, loaded in
// host byte order. An empty iface leaves the oifname match out.
func pinnedForeignSourceExprs(iface string) []expr.Any {
	return append(pinnedIfaceMatch(iface, expr.MetaKeyOIFNAME),
		&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagSADDR: true, FlagOIF: true},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(2)},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// Behind the guard of a single interface the foreign-source rule carries no
// oifname match: the fib lookup still reads the output interface.
func TestForeignSourceExprs(t *testing.T) {
	assertExprs(t, foreignSourceExprs("plexd0", dirOut), pinnedForeignSourceExprs("plexd0"))
	assertExprs(t, foreignSourceExprs("plexd0", dirNone), pinnedForeignSourceExprs(""))
}

// Behind the guard the output list opens with the connection tracking pair,
// the foreign-source rule, the relay probe rule and the round-trip probe
// rule, without their oifname matches, and holds the rules without theirs.
func TestChainRuleExprsOut(t *testing.T) {
	rules := oneIfaceRules()
	got := ruleLists(t, rules, hookOutput)

	want := [][]expr.Any{pinnedGuard(expr.MetaKeyOIFNAME, "wg0")}
	want = append(want, pinnedChainOpening(hookOutput, "")...)
	want = append(want, builtRules(t, rules, dirNone)...)
	assertNftRuleLists(t, got, want)
	assertNoIfaceMatch(t, got[1:])
}

func TestChainRuleExprsOutEmpty(t *testing.T) {
	for _, rules := range [][]FirewallRule{nil, {}} {
		if got := ruleEntries(t, rules, true, hookOutput); len(got) != 0 {
			t.Errorf("rules %#v, hookOutput: %d entries, want none", rules, len(got))
		}
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

func TestRTTProbeRule(t *testing.T) {
	got := rttProbeRule("plexd0")
	want := FirewallRule{Interface: "plexd0", Protocol: "udp", Port: 7911, Action: "allow"}
	if got != want {
		t.Errorf("rttProbeRule(plexd0) = %+v, want %+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("rttProbeRule(plexd0).Validate() = %v, want nil", err)
	}
}

// Every rule an ApplyRules batch adds gets the per-rule allowance on top of
// the base, and every set element the per-element one.
func TestApplyBufferBytes(t *testing.T) {
	for _, tc := range []struct {
		rules, elements, want int
	}{
		{0, 0, netlinkBufferBase},
		{9, 0, netlinkBufferBase + 9*netlinkBufferPerRule},
		{0, 1000, netlinkBufferBase + 1000*netlinkBufferPerElement},
		{39, 9006, netlinkBufferBase + 39*netlinkBufferPerRule + 9006*netlinkBufferPerElement},
	} {
		if got := applyBufferBytes(tc.rules, tc.elements); got != tc.want {
			t.Errorf("applyBufferBytes(%d, %d) = %d, want %d", tc.rules, tc.elements, got, tc.want)
		}
	}
}

func TestChainNames(t *testing.T) {
	input, forward, output := chainNames("plexd-mesh")
	if input != "plexd-mesh-input" || forward != "plexd-mesh-forward" || output != "plexd-mesh-output" {
		t.Errorf("chainNames(plexd-mesh) = %q, %q, %q, want plexd-mesh-input, plexd-mesh-forward, plexd-mesh-output", input, forward, output)
	}
}

// sumDropCounters adds up the counters of the rules whose last expression is
// a drop verdict. It skips the rules that accept, the log rules, which end in
// their log expression, and a rule without expressions, and it returns 0, 0
// for no rules at all.
func TestSumDropCounters(t *testing.T) {
	counted := func(packets, octets uint64, verdict expr.VerdictKind) *nftables.Rule {
		return &nftables.Rule{Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceNameBytes("plexd0")},
			&expr.Counter{Packets: packets, Bytes: octets},
			&expr.Verdict{Kind: verdict},
		}}
	}

	// The default deny as buildRuleExprs builds it, with its counter set as a
	// dump would return it.
	defaultDeny, err := buildRuleExprs(FirewallRule{Interface: "plexd0", Action: "deny"}, dirIn)
	if err != nil {
		t.Fatalf("buildRuleExprs(default deny) error = %v", err)
	}
	for _, e := range defaultDeny {
		if c, ok := e.(*expr.Counter); ok {
			c.Packets, c.Bytes = 4, 160
		}
	}

	logRule := &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceNameBytes("plexd0")},
		&expr.Log{Key: 1 << unix.NFTA_LOG_GROUP, Group: nflogGroup},
	}}

	tests := []struct {
		name        string
		rules       []*nftables.Rule
		wantPackets uint64
		wantBytes   uint64
	}{
		{name: "nil list"},
		{name: "empty list", rules: []*nftables.Rule{}},
		{
			name:  "accept rules ignored",
			rules: []*nftables.Rule{counted(7, 700, expr.VerdictAccept), counted(9, 900, expr.VerdictAccept)},
		},
		{
			name: "drop rules summed",
			rules: []*nftables.Rule{
				counted(100, 9000, expr.VerdictAccept),
				counted(3, 120, expr.VerdictDrop),
				logRule,
				{},
				{Exprs: defaultDeny},
				counted(2, 80, expr.VerdictDrop),
			},
			wantPackets: 9,
			wantBytes:   360,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPackets, gotBytes := sumDropCounters(tt.rules)
			if gotPackets != tt.wantPackets || gotBytes != tt.wantBytes {
				t.Errorf("sumDropCounters() = %d, %d, want %d, %d", gotPackets, gotBytes, tt.wantPackets, tt.wantBytes)
			}
		})
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
// chain's guard and opening rules: the log rule, the accept rule and the
// deny, without interface matches, which the guard of plexd0 makes
// redundant.
func pinnedLoggedRules() [][]expr.Any {
	match := func() []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			// 7001 in network byte order.
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x1b, 0x59}},
		}
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
	deny := []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}
	return [][]expr.Any{logRule, accept, deny}
}

// pinnedRelayProbeExprs is the relay probe rule of the output chain: UDP to
// port 9 leaving through iface, from and to any address of either family. An
// empty iface leaves the oifname match out.
func pinnedRelayProbeExprs(iface string) []expr.Any {
	return append(pinnedIfaceMatch(iface, expr.MetaKeyOIFNAME),
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x09}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// pinnedRTTProbeExprs is the round-trip probe rule of the input and output
// chains: UDP to port 7911 on iface, from and to any address of either
// family, with key as the interface match: MetaKeyIIFNAME for the input
// chain, MetaKeyOIFNAME for the output chain. An empty iface leaves the
// match out.
func pinnedRTTProbeExprs(iface string, key expr.MetaKey) []expr.Any {
	return append(pinnedIfaceMatch(iface, key),
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		// 7911 in network byte order.
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x1e, 0xe7}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// pinnedChainOpening is what opens the chain hook selects for iface: the
// connection tracking pair, then the round-trip probe rule in the input
// chain, and the foreign-source rule, the relay probe rule and the round-trip
// probe rule in the output chain. The forward chain opens with the pair
// alone. An empty iface gives the opening without interface matches, as it
// stands behind the guard of a single interface.
func pinnedChainOpening(hook chainHook, iface string) [][]expr.Any {
	switch hook {
	case hookInput:
		opening := pinnedConnTrackExprs(iface, expr.MetaKeyIIFNAME)
		return append(opening, pinnedRTTProbeExprs(iface, expr.MetaKeyIIFNAME))
	case hookOutput:
		opening := pinnedConnTrackExprs(iface, expr.MetaKeyOIFNAME)
		return append(opening, pinnedForeignSourceExprs(iface), pinnedRelayProbeExprs(iface), pinnedRTTProbeExprs(iface, expr.MetaKeyOIFNAME))
	}
	return pinnedConnTrackExprs(iface, expr.MetaKeyIIFNAME)
}

// guardKey is the interface key the guard of the chain hook selects reads.
func guardKey(hook chainHook) expr.MetaKey {
	if hook == hookOutput {
		return expr.MetaKeyOIFNAME
	}
	return expr.MetaKeyIIFNAME
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

// A logged rule gets its log rule directly in front of it, in every list
// behind the guard and the chain's opening rules: the connection tracking
// pair, then the round-trip probe rule in the input list, and the
// foreign-source, relay probe and round-trip probe rules in the output list.
// It stays a rule of its own, ahead of the set rule of the unlogged run that
// follows it.
func TestChainRuleExprsLogged(t *testing.T) {
	allow443 := FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.0/24", DstIP: "10.99.0.1/32", Port: 443, Protocol: "tcp", Action: "allow"}
	logged := nftLoggedRules()
	rules := []FirewallRule{logged[0], allow443, logged[1]}
	for _, hook := range []chainHook{hookInput, hookForward, hookOutput} {
		got := ruleEntries(t, rules, true, hook)
		want := [][]expr.Any{pinnedGuard(guardKey(hook), "plexd0")}
		want = append(want, pinnedChainOpening(hook, "")...)
		pinned := pinnedLoggedRules()
		want = append(want, pinned[0], pinned[1], pinnedSetLookup(familyIPv4, shapePort), pinned[2])
		assertNftRuleLists(t, entryExprs(got), want)

		set := got[len(got)-2].set
		if set == nil {
			t.Fatalf("hook %d: the entry behind the logged rule holds no set", hook)
		}
		box, _, _, err := boxOf(allow443)
		if err != nil {
			t.Fatal(err)
		}
		if want := (ruleSet{family: familyIPv4, shape: shapePort, elems: []nftables.SetElement{box.element(shapePort)}}); !reflect.DeepEqual(*set, want) {
			t.Errorf("hook %d: set = %+v, want %+v", hook, *set, want)
		}
		for i, entry := range got {
			if entry.set != nil && i != len(got)-2 {
				t.Errorf("hook %d: entry %d holds a set, want only the one behind the logged rule", hook, i)
			}
		}
	}
}

// Without a log tag the lists hold no log rule in any chain, and the rules
// as they are without connection logging.
func TestChainRuleExprsUntaggedUnchanged(t *testing.T) {
	for _, hook := range []chainHook{hookInput, hookForward, hookOutput} {
		got := entryExprs(ruleEntries(t, withoutLogTags(nftLoggedRules()), true, hook))
		want := [][]expr.Any{pinnedGuard(guardKey(hook), "plexd0")}
		want = append(want, pinnedChainOpening(hook, "")...)
		assertNftRuleLists(t, got, append(want, pinnedLoggedRules()[1:]...))
		if n := nftLogRuleCount(got); n != 0 {
			t.Errorf("hook %d: %d log rules, want none", hook, n)
		}
	}
}

func TestLogRuleExprsRejectsInvalidRule(t *testing.T) {
	if _, err := logRuleExprs(FirewallRule{SrcIP: "not-an-ip", Action: "allow", LogTag: "1/0"}, dirIn); err == nil {
		t.Error("logRuleExprs accepted a rule with an invalid source address")
	}
}

// assertNoNftLogRules checks that rules, written into any of the three lists,
// carry no log rule and match the lists of nftLoggedRules without tags.
func assertNoNftLogRules(t *testing.T, rules []FirewallRule) {
	t.Helper()
	for _, hook := range []chainHook{hookInput, hookForward, hookOutput} {
		got := entryExprs(ruleEntries(t, rules, true, hook))
		if n := nftLogRuleCount(got); n != 0 {
			t.Errorf("hook %d: %d log rules, want none", hook, n)
		}
		want := entryExprs(ruleEntries(t, withoutLogTags(nftLoggedRules()), true, hook))
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
