//go:build linux

package wireguard

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

type nopWriterLinux struct{}

func (nopWriterLinux) Write(p []byte) (int, error) { return len(p), nil }

func discardLoggerLinux() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriterLinux{}, nil))
}

// Compile-time checks that NetlinkController implements WGController, that
// the handshake report and tunnel metrics can read peer state from it, and
// that the manager can swap the mesh address through it.
var (
	_ WGController    = (*NetlinkController)(nil)
	_ PeerStatsReader = (*NetlinkController)(nil)
	_ AddressReplacer = (*NetlinkController)(nil)
)

func TestNewNetlinkController(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())
	if ctrl == nil {
		t.Fatal("NewNetlinkController returned nil")
	}
	if ctrl.logger == nil {
		t.Fatal("logger field is nil")
	}
}

func TestDeleteInterfaceNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	// Deleting a non-existent interface should be idempotent and return nil.
	// This may require root/CAP_NET_ADMIN; skip if we get a permission error.
	err := ctrl.DeleteInterface("wg-nonexistent-test")
	if err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
}

func TestPeerStatsNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	// Reading a device needs CAP_NET_ADMIN once the kernel's WireGuard family
	// is registered: unprivileged, netlink answers EPERM, which says nothing
	// about this method. A privileged read validates the name first and
	// refuses one longer than IFNAMSIZ-1 (15 bytes) with EINVAL before any
	// lookup, so this name proves only the error prefix. Without the family
	// wgctrl falls back to its userspace lookup, which finds no socket and
	// reports ErrNotExist.
	_, err := ctrl.PeerStats("wg-nonexistent-test")
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: peer stats:"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}

	// The missing-device mapping is checked on a name the kernel accepts.
	_, err = ctrl.PeerStats("wg-nonexist0")
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want it to wrap os.ErrNotExist", err)
	}
}

func TestAllowedIPPrefixes(t *testing.T) {
	nets := []net.IPNet{
		// wgctrl's shape for an IPv4 and an IPv6 entry.
		{IP: net.IP{10, 99, 0, 2}, Mask: net.CIDRMask(32, 32)},
		{IP: net.IP{10, 20, 0, 0}, Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(64, 128)},
		// A 16-byte IPv4 address with a 32-bit mask is unmapped.
		{IP: net.ParseIP("10.30.0.0"), Mask: net.CIDRMask(16, 32)},
		// A mask that is not canonical, and one that does not fit its
		// address, are left out.
		{IP: net.IP{10, 40, 0, 0}, Mask: net.IPMask{255, 0, 255, 0}},
		{IP: net.IP{10, 50, 0, 0}, Mask: net.CIDRMask(64, 128)},
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.99.0.2/32"),
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("fd00::/64"),
		netip.MustParsePrefix("10.30.0.0/16"),
	}
	if got := allowedIPPrefixes(nets); !slices.Equal(got, want) {
		t.Errorf("allowedIPPrefixes() = %v, want %v", got, want)
	}
	if got := allowedIPPrefixes(nil); got != nil {
		t.Errorf("allowedIPPrefixes(nil) = %#v, want nil", got)
	}
}

func TestCreateInterfaceRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	// Creating an interface without root should fail; verify the error is wrapped.
	err := ctrl.CreateInterface("wg-test-priv", make([]byte, 32), 51820)
	if err == nil {
		// Cleanup if we somehow succeeded (running as root in CI).
		_ = ctrl.DeleteInterface("wg-test-priv")
		return
	}

	// Verify error wrapping format.
	expected := "wireguard: create interface:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

// fakeLinkOps records what addLink asks of netlink. adds holds the errors
// the successive adds return; existing is the link the name lookup finds.
type fakeLinkOps struct {
	adds     []error
	existing netlink.Link
	delErr   error
	added    int
	looked   int
	deleted  []string
}

func (f *fakeLinkOps) ops() linkOps {
	return linkOps{
		add: func(netlink.Link) error {
			f.added++
			if f.added > len(f.adds) {
				return nil
			}
			return f.adds[f.added-1]
		},
		byName: func(name string) (netlink.Link, error) {
			f.looked++
			if f.existing == nil {
				return nil, netlink.LinkNotFoundError{}
			}
			return f.existing, nil
		},
		del: func(l netlink.Link) error {
			f.deleted = append(f.deleted, l.Attrs().Name)
			return f.delErr
		},
	}
}

func wireGuardLink(name string) *netlink.GenericLink {
	la := netlink.NewLinkAttrs()
	la.Name = name
	return &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}
}

// A link left behind by a killed process keeps plexd0 in the kernel, and the
// add answers EEXIST, wrapped the way netlink annotates an errno.
func TestAddLink(t *testing.T) {
	exists := fmt.Errorf("%w: link already exists", syscall.EEXIST)
	leftover := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "plexd0"}}
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "plexd0"}}

	tests := []struct {
		name         string
		fake         fakeLinkOps
		wantReplaced bool
		wantErr      error
		wantText     string
		wantAdds     int
		wantDeleted  []string
	}{
		{name: "fresh name", wantAdds: 1},
		{
			name:         "leftover wireguard link replaced",
			fake:         fakeLinkOps{adds: []error{exists}, existing: leftover},
			wantReplaced: true, wantAdds: 2, wantDeleted: []string{"plexd0"},
		},
		{
			name:     "link of another type keeps the name",
			fake:     fakeLinkOps{adds: []error{exists}, existing: dummy},
			wantErr:  syscall.EEXIST,
			wantText: "a dummy link holds the name plexd0",
			wantAdds: 1,
		},
		{
			name:     "other add error is not a leftover",
			fake:     fakeLinkOps{adds: []error{syscall.EPERM}, existing: leftover},
			wantErr:  syscall.EPERM,
			wantAdds: 1,
		},
		{
			name:     "link gone before the lookup",
			fake:     fakeLinkOps{adds: []error{exists}},
			wantErr:  syscall.EEXIST,
			wantAdds: 1,
		},
		{
			name:        "delete fails",
			fake:        fakeLinkOps{adds: []error{exists}, existing: leftover, delErr: syscall.EBUSY},
			wantErr:     syscall.EBUSY,
			wantText:    "delete the plexd0 link an earlier process left behind",
			wantAdds:    1,
			wantDeleted: []string{"plexd0"},
		},
		{
			name:        "second add fails",
			fake:        fakeLinkOps{adds: []error{exists, syscall.ENOBUFS}, existing: leftover},
			wantErr:     syscall.ENOBUFS,
			wantAdds:    2,
			wantDeleted: []string{"plexd0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := tt.fake
			replaced, err := addLink(fake.ops(), wireGuardLink("plexd0"))
			if replaced != tt.wantReplaced {
				t.Errorf("replaced = %v, want %v", replaced, tt.wantReplaced)
			}
			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatalf("err = %v, want nil", err)
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Fatalf("err = %v, want it to wrap %v", err, tt.wantErr)
			}
			if tt.wantText != "" && !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("err = %q, want it to contain %q", err, tt.wantText)
			}
			if fake.added != tt.wantAdds {
				t.Errorf("adds = %d, want %d", fake.added, tt.wantAdds)
			}
			if fmt.Sprint(fake.deleted) != fmt.Sprint(tt.wantDeleted) {
				t.Errorf("deleted = %v, want %v", fake.deleted, tt.wantDeleted)
			}
			if tt.fake.adds == nil && fake.looked != 0 {
				t.Errorf("looked the name up %d times after a successful add, want 0", fake.looked)
			}
		})
	}
}

func TestSetInterfaceUpNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	err := ctrl.SetInterfaceUp("wg-nonexistent-test")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: set interface up:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestConfigureAddressNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	err := ctrl.ConfigureAddress("wg-nonexistent-test", "10.0.0.1/32")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: configure address:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

// The arguments are checked before netlink is asked anything, so a name no
// link holds still gets the argument's error.
func TestReplaceAddress_InvalidArguments(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	tests := []struct {
		name             string
		oldCIDR, newCIDR string
		want             string
	}{
		{"old not a CIDR", "not-a-cidr", "10.0.0.9/24", `wireguard: replace address: parse "not-a-cidr":`},
		{"new without a length", "10.0.0.1/24", "10.0.0.9", `wireguard: replace address: parse "10.0.0.9":`},
		{"lengths differ", "10.0.0.1/24", "10.0.0.9/16", "wireguard: replace address: 10.0.0.1/24 and 10.0.0.9/16 are not of one length"},
		{"IPv6 pair", "fd00::1/64", "fd00::9/64", "wireguard: replace address: fd00::1/64 is not an IPv4 CIDR"},
		{"IPv6 new", "10.0.0.1/24", "fd00::9/24", "wireguard: replace address: fd00::9/24 is not an IPv4 CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ctrl.ReplaceAddress("wg-nonexistent-test", tt.oldCIDR, tt.newCIDR)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("ReplaceAddress(%q, %q) error = %v, want prefix %q", tt.oldCIDR, tt.newCIDR, err, tt.want)
			}
		})
	}
}

func TestReplaceAddressNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	err := ctrl.ReplaceAddress("wg-nonexistent-test", "10.0.0.1/24", "10.0.0.9/24")
	assertPrefix(t, err, "wireguard: replace address:")
}

// fakeAddrOps records what replaceAddress asks of netlink, each call as
// "add <cidr>", "del <cidr>" or "replace <cidr>". errs holds the error the
// call at that index returns.
type fakeAddrOps struct {
	errs   map[int]error
	looked []string
	calls  []string
}

func (f *fakeAddrOps) ops() addrOps {
	record := func(verb string, addr *netlink.Addr) error {
		f.calls = append(f.calls, verb+" "+addr.IPNet.String())
		return f.errs[len(f.calls)-1]
	}
	return addrOps{
		byName: func(name string) (netlink.Link, error) {
			f.looked = append(f.looked, name)
			return wireGuardLink(name), nil
		},
		add:     func(_ netlink.Link, addr *netlink.Addr) error { return record("add", addr) },
		del:     func(_ netlink.Link, addr *netlink.Addr) error { return record("del", addr) },
		replace: func(_ netlink.Link, addr *netlink.Addr) error { return record("replace", addr) },
	}
}

func TestReplaceAddress_Order(t *testing.T) {
	tests := []struct {
		name             string
		oldCIDR, newCIDR string
		want             []string
	}{
		{
			// The /32 keeps the link addressed while the old address goes,
			// and the new address brings the connected route back. The
			// replace announces the new address after the delete of the /32,
			// which a listener that keeps addresses without their prefix
			// length takes as the removal of the new address.
			name:    "prefix shorter than /32",
			oldCIDR: "10.0.0.1/24", newCIDR: "10.0.0.9/24",
			want: []string{"add 10.0.0.9/32", "del 10.0.0.1/24", "add 10.0.0.9/24", "del 10.0.0.9/32", "replace 10.0.0.9/24"},
		},
		{
			name:    "pair of /32 addresses",
			oldCIDR: "10.0.0.1/32", newCIDR: "10.0.0.9/32",
			want: []string{"add 10.0.0.9/32", "del 10.0.0.1/32"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeAddrOps{}
			err := replaceAddress(f.ops(), "plexd0", netip.MustParsePrefix(tt.oldCIDR), netip.MustParsePrefix(tt.newCIDR))
			if err != nil {
				t.Fatalf("replaceAddress: %v", err)
			}
			if !slices.Equal(f.calls, tt.want) {
				t.Errorf("calls = %q, want %q", f.calls, tt.want)
			}
			if !slices.Equal(f.looked, []string{"plexd0"}) {
				t.Errorf("looked up %q, want the link plexd0 once", f.looked)
			}
		})
	}
}

// A repeat of a call that failed halfway finds the new addresses there and
// the old one gone, and netlink answers that the way it annotates an errno.
func TestReplaceAddress_ToleratesARepeat(t *testing.T) {
	exists := fmt.Errorf("%w: address already exists", syscall.EEXIST)
	gone := fmt.Errorf("%w: cannot assign requested address", syscall.EADDRNOTAVAIL)
	f := &fakeAddrOps{errs: map[int]error{0: exists, 1: gone, 2: exists, 3: gone}}

	err := replaceAddress(f.ops(), "plexd0", netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("10.0.0.9/24"))
	if err != nil {
		t.Fatalf("replaceAddress = %v, want nil when every step is already done", err)
	}
	if len(f.calls) != 5 {
		t.Errorf("calls = %q, want all five", f.calls)
	}
}

func TestReplaceAddress_StepFails(t *testing.T) {
	tests := []struct {
		name      string
		errs      map[int]error
		wantErr   error
		wantText  string
		wantCalls int
	}{
		{
			name:      "first add",
			errs:      map[int]error{0: syscall.EPERM},
			wantErr:   syscall.EPERM,
			wantText:  "wireguard: replace address: add 10.0.0.9/32: operation not permitted",
			wantCalls: 1,
		},
		{
			// EEXIST is no answer a delete tolerates.
			name:      "delete of the old address",
			errs:      map[int]error{1: syscall.EEXIST},
			wantErr:   syscall.EEXIST,
			wantText:  "wireguard: replace address: delete 10.0.0.1/24: file exists",
			wantCalls: 2,
		},
		{
			// EADDRNOTAVAIL is no answer an add tolerates.
			name:      "add with the prefix length",
			errs:      map[int]error{2: syscall.EADDRNOTAVAIL},
			wantErr:   syscall.EADDRNOTAVAIL,
			wantText:  "wireguard: replace address: add 10.0.0.9/24: cannot assign requested address",
			wantCalls: 3,
		},
		{
			name:      "delete of the /32",
			errs:      map[int]error{3: syscall.EBUSY},
			wantErr:   syscall.EBUSY,
			wantText:  "wireguard: replace address: delete 10.0.0.9/32: device or resource busy",
			wantCalls: 4,
		},
		{
			// The announcement tolerates no errno: a link that holds the
			// address answers a replace with success.
			name:      "announcement of the address",
			errs:      map[int]error{4: syscall.ENODEV},
			wantErr:   syscall.ENODEV,
			wantText:  "wireguard: replace address: announce 10.0.0.9/24: no such device",
			wantCalls: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeAddrOps{errs: tt.errs}
			err := replaceAddress(f.ops(), "plexd0", netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("10.0.0.9/24"))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want it to wrap %v", err, tt.wantErr)
			}
			if err.Error() != tt.wantText {
				t.Errorf("err = %q, want %q", err, tt.wantText)
			}
			if len(f.calls) != tt.wantCalls {
				t.Errorf("calls = %q, want the first %d", f.calls, tt.wantCalls)
			}
		})
	}
}

// Deleting the old address of a pair that names one address would delete the
// new one, so nothing is asked of netlink beyond the lookup.
func TestReplaceAddress_SameAddress(t *testing.T) {
	for _, cidr := range []string{"10.0.0.1/24", "10.0.0.1/32"} {
		f := &fakeAddrOps{}
		p := netip.MustParsePrefix(cidr)
		if err := replaceAddress(f.ops(), "plexd0", p, p); err != nil {
			t.Errorf("replaceAddress(%s, %s) = %v, want nil", p, p, err)
		}
		if len(f.calls) != 0 {
			t.Errorf("calls for %s = %q, want none", p, f.calls)
		}
	}
}

func TestReplaceAddress_LookupFails(t *testing.T) {
	f := &fakeAddrOps{}
	ops := f.ops()
	ops.byName = func(string) (netlink.Link, error) { return nil, netlink.LinkNotFoundError{} }

	err := replaceAddress(ops, "plexd0", netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("10.0.0.9/24"))
	assertPrefix(t, err, "wireguard: replace address:")
	if len(f.calls) != 0 {
		t.Errorf("calls = %q, want none without a link", f.calls)
	}
}

func TestSetMTUNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	err := ctrl.SetMTU("wg-nonexistent-test", 1420)
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: set mtu:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestNetlinkPeerConfig_Keepalive(t *testing.T) {
	key := make([]byte, 32)
	for _, tt := range []struct {
		keepalive int
		want      time.Duration
	}{
		{0, 0},
		{25, 25 * time.Second},
	} {
		cfg, err := netlinkPeerConfig(PeerConfig{PublicKey: key, PersistentKeepalive: tt.keepalive})
		if err != nil {
			t.Fatalf("netlinkPeerConfig(%d): %v", tt.keepalive, err)
		}
		// A nil interval would leave the device's keepalive as it is, so a 0 must
		// arrive as a pointer to clear one an earlier run programmed.
		if cfg.PersistentKeepaliveInterval == nil {
			t.Fatalf("PersistentKeepaliveInterval = nil for %d, want a pointer to %v", tt.keepalive, tt.want)
		}
		if got := *cfg.PersistentKeepaliveInterval; got != tt.want {
			t.Errorf("PersistentKeepaliveInterval = %v for %d, want %v", got, tt.keepalive, tt.want)
		}
	}
}

func TestNetlinkPeerConfig_ParseErrors(t *testing.T) {
	key := make([]byte, 32)
	tests := []struct {
		name string
		cfg  PeerConfig
		want string
	}{
		{"bad public key", PeerConfig{PublicKey: []byte{1, 2, 3}}, "wireguard: add peer: parse public key:"},
		{"bad endpoint", PeerConfig{PublicKey: key, Endpoint: "not-an-endpoint"}, "wireguard: add peer: resolve endpoint:"},
		{"bad allowed IP", PeerConfig{PublicKey: key, AllowedIPs: []string{"10.0.0.2"}}, `wireguard: add peer: parse allowed IP "10.0.0.2":`},
		{"bad psk", PeerConfig{PublicKey: key, PSK: []byte{1, 2, 3}}, "wireguard: add peer: parse psk:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := netlinkPeerConfig(tt.cfg)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("netlinkPeerConfig() error = %v, want prefix %q", err, tt.want)
			}
		})
	}
}
