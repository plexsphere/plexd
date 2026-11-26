//go:build linux

package relaybpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestObject_MatchesTheLoader checks, without privileges, that the committed
// object declares what the loader and the session encoding assume.
func TestObject_MatchesTheLoader(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatalf("parse the embedded object: %v", err)
	}

	prog := spec.Programs["relay_forward"]
	if prog == nil {
		t.Fatal("the object holds no program relay_forward")
	}
	if prog.Type != ebpf.SchedCLS {
		t.Errorf("relay_forward has type %v, want %v", prog.Type, ebpf.SchedCLS)
	}
	if prog.License != "Dual BSD/GPL" {
		t.Errorf("relay_forward has licence %q, want %q", prog.License, "Dual BSD/GPL")
	}

	sessions := spec.Maps["relay_sessions"]
	if sessions == nil {
		t.Fatal("the object holds no map relay_sessions")
	}
	if sessions.Type != ebpf.Hash {
		t.Errorf("relay_sessions has type %v, want %v", sessions.Type, ebpf.Hash)
	}
	if sessions.KeySize != 4 {
		t.Errorf("relay_sessions has key size %d, want 4", sessions.KeySize)
	}
	if sessions.ValueSize != sessionSize {
		t.Errorf("relay_sessions has value size %d, want %d", sessions.ValueSize, sessionSize)
	}
	if sessions.MaxEntries != 65536 {
		t.Errorf("relay_sessions has %d entries, want 65536", sessions.MaxEntries)
	}

	counters := spec.Maps["relay_counters"]
	if counters == nil {
		t.Fatal("the object holds no map relay_counters")
	}
	if counters.Type != ebpf.PerCPUArray {
		t.Errorf("relay_counters has type %v, want %v", counters.Type, ebpf.PerCPUArray)
	}
	if counters.MaxEntries != 9 || int(counters.MaxEntries) != len(CounterNames) {
		t.Errorf("relay_counters has %d entries, want 9, one per name in CounterNames (%d)",
			counters.MaxEntries, len(CounterNames))
	}
	if counters.ValueSize != 8 {
		t.Errorf("relay_counters has value size %d, want 8", counters.ValueSize)
	}

	for name, size := range map[string]uint32{"relay_port": 2, "lookup_ifindex": 4} {
		v := spec.Variables[name]
		if v == nil {
			t.Errorf("the object holds no variable %s", name)
			continue
		}
		if v.Size() != size {
			t.Errorf("variable %s has %d bytes, want %d", name, v.Size(), size)
		}
		if !v.Constant() {
			t.Errorf("variable %s is not constant, so the verifier would not see the value Load sets", name)
		}
	}
}

// TestSession_Encoding checks, without privileges, that a Session encodes to
// the bytes of struct relay_session and that one mixing address families is
// refused.
func TestSession_Encoding(t *testing.T) {
	const usedNS = 0x1122334455667788

	t.Run("IPv4", func(t *testing.T) {
		s := Session{
			Partner:    netip.MustParseAddrPort("192.0.2.1:51820"),
			PartnerDst: netip.MustParseAddr("198.51.100.1"),
			Owner:      netip.MustParseAddrPort("203.0.113.7:41000"),
			OwnerSrc:   netip.MustParseAddr("198.51.100.2"),
			OwnerIf:    7,
		}
		got, err := s.encode(usedNS)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		checkField(t, got, "psrc", 0, 16, []byte{192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		checkField(t, got, "pdst", 16, 16, []byte{198, 51, 100, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		checkField(t, got, "dst", 32, 16, []byte{203, 0, 113, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		checkField(t, got, "local", 48, 16, []byte{198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		checkField(t, got, "psport", 64, 2, []byte{0xca, 0x6c}) // 51820
		checkField(t, got, "dport", 66, 2, []byte{0xa0, 0x28})  // 41000
		checkField(t, got, "oif", 68, 4, binary.NativeEndian.AppendUint32(nil, 7))
		checkField(t, got, "used_ns", 72, 8, binary.NativeEndian.AppendUint64(nil, usedNS))
		checkField(t, got, "family", 80, 1, []byte{2})
		checkField(t, got, "pad", 81, 7, make([]byte, 7))
	})

	t.Run("IPv6", func(t *testing.T) {
		s := Session{
			Partner:    netip.MustParseAddrPort("[2001:db8::1]:51820"),
			PartnerDst: netip.MustParseAddr("2001:db8:1::1"),
			Owner:      netip.MustParseAddrPort("[2001:db8:2::7]:41000"),
			OwnerSrc:   netip.MustParseAddr("2001:db8:1::2"),
			OwnerIf:    12,
		}
		got, err := s.encode(usedNS)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		checkField(t, got, "psrc", 0, 16, addr16("2001:db8::1"))
		checkField(t, got, "pdst", 16, 16, addr16("2001:db8:1::1"))
		checkField(t, got, "dst", 32, 16, addr16("2001:db8:2::7"))
		checkField(t, got, "local", 48, 16, addr16("2001:db8:1::2"))
		checkField(t, got, "psport", 64, 2, []byte{0xca, 0x6c})
		checkField(t, got, "dport", 66, 2, []byte{0xa0, 0x28})
		checkField(t, got, "oif", 68, 4, binary.NativeEndian.AppendUint32(nil, 12))
		checkField(t, got, "used_ns", 72, 8, binary.NativeEndian.AppendUint64(nil, usedNS))
		checkField(t, got, "family", 80, 1, []byte{10})
		checkField(t, got, "pad", 81, 7, make([]byte, 7))
	})

	t.Run("IPv4-mapped addresses count as IPv4", func(t *testing.T) {
		s := Session{
			Partner:    netip.MustParseAddrPort("[::ffff:192.0.2.1]:51820"),
			PartnerDst: netip.MustParseAddr("198.51.100.1"),
			Owner:      netip.MustParseAddrPort("203.0.113.7:41000"),
			OwnerSrc:   netip.MustParseAddr("::ffff:198.51.100.2"),
		}
		got, err := s.encode(usedNS)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		checkField(t, got, "psrc", 0, 16, []byte{192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		checkField(t, got, "local", 48, 16, []byte{198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		checkField(t, got, "family", 80, 1, []byte{2})
	})

	v4 := Session{
		Partner:    netip.MustParseAddrPort("192.0.2.1:51820"),
		PartnerDst: netip.MustParseAddr("198.51.100.1"),
		Owner:      netip.MustParseAddrPort("203.0.113.7:41000"),
		OwnerSrc:   netip.MustParseAddr("198.51.100.2"),
	}
	v6port := netip.MustParseAddrPort("[2001:db8::1]:51820")
	v6 := netip.MustParseAddr("2001:db8::2")
	mixed := map[string]Session{
		"IPv6 partner":     {Partner: v6port, PartnerDst: v4.PartnerDst, Owner: v4.Owner, OwnerSrc: v4.OwnerSrc},
		"IPv6 partner dst": {Partner: v4.Partner, PartnerDst: v6, Owner: v4.Owner, OwnerSrc: v4.OwnerSrc},
		"IPv6 owner":       {Partner: v4.Partner, PartnerDst: v4.PartnerDst, Owner: v6port, OwnerSrc: v4.OwnerSrc},
		"IPv6 owner src":   {Partner: v4.Partner, PartnerDst: v4.PartnerDst, Owner: v4.Owner, OwnerSrc: v6},
		"no owner src":     {Partner: v4.Partner, PartnerDst: v4.PartnerDst, Owner: v4.Owner},
	}
	for name, s := range mixed {
		t.Run("refuses "+name, func(t *testing.T) {
			if _, err := s.encode(usedNS); err == nil || err.Error() != "relaybpf: session mixes address families" {
				t.Errorf("encode returned %v, want relaybpf: session mixes address families", err)
			}
			// Put refuses the session before it touches the table, so a
			// Forwarder without a loaded table answers the same.
			if err := (&Forwarder{}).Put(1, s); err == nil || err.Error() != "relaybpf: session mixes address families" {
				t.Errorf("Put returned %v, want relaybpf: session mixes address families", err)
			}
		})
	}

	t.Run("the key is the index as the datagram carries it", func(t *testing.T) {
		// WireGuard writes the receiver index little-endian, so index
		// 0x04030201 stands in the datagram as the bytes 1, 2, 3, 4.
		if got, want := sessionKey(0x04030201), [4]byte{1, 2, 3, 4}; got != want {
			t.Errorf("sessionKey(0x04030201) = %v, want %v", got, want)
		}
	})
}

// checkField fails t when the size bytes at offset of value differ from want.
func checkField(t *testing.T, value [sessionSize]byte, name string, offset, size int, want []byte) {
	t.Helper()
	if got := value[offset : offset+size]; !bytes.Equal(got, want) {
		t.Errorf("%s at offset %d = % x, want % x", name, offset, got, want)
	}
}

// addr16 returns the 16 bytes of an IPv6 address.
func addr16(s string) []byte {
	b := netip.MustParseAddr(s).As16()
	return b[:]
}

// TestLoad_Unprivileged checks that Load fails at loading, with the
// permission error intact, when the process may not create BPF objects.
func TestLoad_Unprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs only without privileges: root may load the program")
	}
	f, err := Load(51820, 1)
	if err == nil {
		_ = f.Close()
		t.Fatal("Load succeeded without privileges")
	}
	if !strings.HasPrefix(err.Error(), "relaybpf: load:") {
		t.Errorf("Load returned %q, want the prefix relaybpf: load:", err)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Errorf("Load returned %q, which is not unix.EPERM", err)
	}
}
