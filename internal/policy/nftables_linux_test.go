//go:build linux

package policy

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
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

	// Verify error wrapping format.
	expected := "policy: nftables: ensure chain"
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
	rule := FirewallRule{Protocol: "icmp", Action: "allow"}
	_, err := buildRuleExprs(rule)
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
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

	// Should only have counter + verdict (no IP match expressions).
	if len(exprs) != 2 {
		t.Errorf("expected 2 expressions (counter+verdict) for wildcard rule, got %d", len(exprs))
	}
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
	exprs, err := buildIPMatchExprs("10.0.0.1", 12)
	if err != nil {
		t.Fatalf("buildIPMatchExprs returned error: %v", err)
	}
	// Exact IP match: payload + cmp = 2 expressions.
	if len(exprs) != 2 {
		t.Errorf("expected 2 expressions for exact IP, got %d", len(exprs))
	}
}

func TestBuildIPMatchExprsCIDR32(t *testing.T) {
	exprs, err := buildIPMatchExprs("10.0.0.1/32", 16)
	if err != nil {
		t.Fatalf("buildIPMatchExprs returned error: %v", err)
	}
	// /32 is an exact match: payload + cmp = 2 expressions.
	if len(exprs) != 2 {
		t.Errorf("expected 2 expressions for /32 CIDR, got %d", len(exprs))
	}
}

func TestBuildIPMatchExprsSubnet(t *testing.T) {
	exprs, err := buildIPMatchExprs("192.168.0.0/16", 12)
	if err != nil {
		t.Fatalf("buildIPMatchExprs returned error: %v", err)
	}
	// Subnet match: payload + bitwise + cmp = 3 expressions.
	if len(exprs) != 3 {
		t.Errorf("expected 3 expressions for subnet CIDR, got %d", len(exprs))
	}
}

func TestProtocolNumber(t *testing.T) {
	tests := []struct {
		proto string
		want  byte
		err   bool
	}{
		{"tcp", 6, false},
		{"udp", 17, false},
		{"icmp", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		got, err := protocolNumber(tt.proto)
		if tt.err {
			if err == nil {
				t.Errorf("protocolNumber(%q) expected error", tt.proto)
			}
			continue
		}
		if err != nil {
			t.Errorf("protocolNumber(%q) returned error: %v", tt.proto, err)
			continue
		}
		if got != tt.want {
			t.Errorf("protocolNumber(%q) = %d, want %d", tt.proto, got, tt.want)
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
