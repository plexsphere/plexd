//go:build linux

package wireguard

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TestClampMSSExprs checks the twelve expressions of each clamp rule against
// the list nft --debug=netlink prints for the rule the issue measured, for
// plexd0 at 1332 (0x0534): the interface comparison takes the name padded
// with zeros to 16 bytes, and only the first expression tells the two
// directions apart.
func TestClampMSSExprs(t *testing.T) {
	want := func(key expr.MetaKey) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: key, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("plexd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x06}},
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x06}, Xor: []byte{0x00}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
			&expr.Exthdr{Op: expr.ExthdrOpTcpopt, Type: 2, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: []byte{0x05, 0x34}},
			&expr.Counter{},
			&expr.Immediate{Register: 1, Data: []byte{0x05, 0x34}},
			&expr.Exthdr{Op: expr.ExthdrOpTcpopt, Type: 2, Offset: 2, Len: 2, SourceRegister: 1},
		}
	}

	tests := []struct {
		name string
		in   bool
		want []expr.Any
	}{
		{name: "iifname", in: true, want: want(expr.MetaKeyIIFNAME)},
		{name: "oifname", in: false, want: want(expr.MetaKeyOIFNAME)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampMSSExprs("plexd0", tt.in, 1332)
			if len(got) != len(tt.want) {
				t.Fatalf("clampMSSExprs(%q, %v, 1332) returned %d expressions, want %d", "plexd0", tt.in, len(got), len(tt.want))
			}
			for i := range got {
				if !reflect.DeepEqual(got[i], tt.want[i]) {
					t.Errorf("expression %d = %#v, want %#v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestNetlinkController_ClampMSSInvalid checks that ClampMSS refuses an MSS
// outside 1 to 65535 before it opens a netlink socket: the error wraps no
// cause, which a refused or failed netlink call would add, so the test holds
// for an unprivileged user and for root alike.
func TestNetlinkController_ClampMSSInvalid(t *testing.T) {
	c := NewNetlinkController(discardLogger())
	for _, tt := range []struct {
		mss  int
		want string
	}{
		{mss: 0, want: "wireguard: clamp mss: invalid mss 0"},
		{mss: -1, want: "wireguard: clamp mss: invalid mss -1"},
		{mss: 65536, want: "wireguard: clamp mss: invalid mss 65536"},
	} {
		err := c.ClampMSS("plexd0", tt.mss)
		if err == nil || err.Error() != tt.want {
			t.Errorf("ClampMSS(%q, %d) = %v, want %s", "plexd0", tt.mss, err, tt.want)
			continue
		}
		if cause := errors.Unwrap(err); cause != nil {
			t.Errorf("ClampMSS(%q, %d) wraps %v, want no cause: the range check comes before any netlink call", "plexd0", tt.mss, cause)
		}
	}
}

// TestNetlinkController_ClampMSSUnprivileged runs ClampMSS and UnclampMSS
// without root and checks where each fails: the kernel refuses the nftables
// batch of ClampMSS and the table dump of UnclampMSS with EPERM, and the
// errors name the step. Root would change the host's ruleset, so the test
// skips at effective uid 0.
func TestNetlinkController_ClampMSSUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs only without root: as root ClampMSS would write the host's ruleset")
	}
	c := NewNetlinkController(discardLogger())

	err := c.ClampMSS("plexd0", 1332)
	if err == nil || !strings.HasPrefix(err.Error(), `wireguard: clamp mss on "plexd0": `) {
		t.Errorf(`ClampMSS("plexd0", 1332) = %v, want an error that starts with "wireguard: clamp mss on \"plexd0\": "`, err)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Errorf(`ClampMSS("plexd0", 1332) = %v, want an error that wraps EPERM`, err)
	}

	err = c.UnclampMSS("plexd0")
	if err == nil || !strings.HasPrefix(err.Error(), "wireguard: unclamp mss: list tables: ") {
		t.Errorf(`UnclampMSS("plexd0") = %v, want an error that starts with "wireguard: unclamp mss: list tables: "`, err)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Errorf(`UnclampMSS("plexd0") = %v, want an error that wraps EPERM`, err)
	}
}
