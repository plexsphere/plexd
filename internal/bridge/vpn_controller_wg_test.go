package bridge

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/wireguard"
)

const (
	testVPNIface   = "wg-s2s-0"
	testVPNPort    = 51823
	testVPNAddress = "10.0.0.5/32"
)

func TestWGVPNController_CreateTunnelInterface(t *testing.T) {
	fake := &fakeWGController{}
	logger, buf := debugLogger()
	c := NewWGVPNController(fake, "", logger)

	if err := c.CreateTunnelInterface(testVPNIface, testVPNPort); err != nil {
		t.Fatalf("CreateTunnelInterface() error = %v", err)
	}

	created := fake.wgCallsFor("CreateInterface")
	if len(created) != 1 {
		t.Fatalf("CreateInterface calls = %d, want 1", len(created))
	}
	if got := created[0].Args[0]; got != testVPNIface {
		t.Errorf("interface = %v, want %q", got, testVPNIface)
	}
	key, ok := created[0].Args[1].([]byte)
	if !ok || len(key) != 32 {
		t.Errorf("private key = %v, want 32 bytes", created[0].Args[1])
	}
	if got := created[0].Args[2]; got != testVPNPort {
		t.Errorf("listen port = %v, want %d", got, testVPNPort)
	}

	if calls := fake.wgCallsFor("ConfigureAddress"); len(calls) != 0 {
		t.Errorf("ConfigureAddress calls = %d, want 0 for an unnumbered interface", len(calls))
	}

	logged := buf.String()
	for _, want := range []string{
		"level=INFO",
		`msg="tunnel interface created"`,
		"component=bridge",
		"interface=wg-s2s-0",
		"listen_port=51823",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
	if strings.Contains(logged, "interface addressed") {
		t.Errorf("log = %q, want no address line for an unnumbered interface", logged)
	}
}

// TestWGVPNController_CreateTunnelInterfaceAddressed covers the macOS case:
// the tunnel utun carries the node's mesh IP as a /32 so route(8) accepts a
// route over it.
func TestWGVPNController_CreateTunnelInterfaceAddressed(t *testing.T) {
	fake := &fakeWGController{}
	logger, buf := debugLogger()
	c := NewWGVPNController(fake, testVPNAddress, logger)

	if err := c.CreateTunnelInterface(testVPNIface, testVPNPort); err != nil {
		t.Fatalf("CreateTunnelInterface() error = %v", err)
	}

	wantOrder := []string{"CreateInterface", "ConfigureAddress", "SetInterfaceUp"}
	if got := fake.wgMethods(); !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("calls = %v, want %v", got, wantOrder)
	}

	addressed := fake.wgCallsFor("ConfigureAddress")
	if len(addressed) != 1 {
		t.Fatalf("ConfigureAddress calls = %d, want 1", len(addressed))
	}
	if got := addressed[0].Args[0]; got != testVPNIface {
		t.Errorf("ConfigureAddress interface = %v, want %q", got, testVPNIface)
	}
	if got := addressed[0].Args[1]; got != testVPNAddress {
		t.Errorf("ConfigureAddress address = %v, want %q", got, testVPNAddress)
	}

	logged := buf.String()
	for _, want := range []string{
		`level=INFO msg="tunnel interface created"`,
		`level=DEBUG msg="tunnel interface addressed"`,
		"interface=wg-s2s-0",
		"address=10.0.0.5/32",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
}

func TestWGVPNController_CreateTunnelInterfaceFreshKeys(t *testing.T) {
	fake := &fakeWGController{}
	c := NewWGVPNController(fake, "", discardLogger())

	for i := range 2 {
		if err := c.CreateTunnelInterface(testVPNIface, testVPNPort); err != nil {
			t.Fatalf("CreateTunnelInterface() #%d error = %v", i, err)
		}
	}

	created := fake.wgCallsFor("CreateInterface")
	if len(created) != 2 {
		t.Fatalf("CreateInterface calls = %d, want 2", len(created))
	}
	first := created[0].Args[1].([]byte)
	second := created[1].Args[1].([]byte)
	if bytes.Equal(first, second) {
		t.Error("both tunnels got the same private key, want a fresh key per interface")
	}
}

func TestWGVPNController_CreateTunnelInterfaceErrors(t *testing.T) {
	fakeErr := errors.New("wg failed")

	t.Run("create fails", func(t *testing.T) {
		fake := &fakeWGController{createInterfaceErr: fakeErr}
		c := NewWGVPNController(fake, testVPNAddress, discardLogger())

		err := c.CreateTunnelInterface(testVPNIface, testVPNPort)
		wantWGErrPrefix(t, err, "bridge: vpn: create interface wg-s2s-0:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		for _, method := range []string{"ConfigureAddress", "SetInterfaceUp", "DeleteInterface"} {
			if calls := fake.wgCallsFor(method); len(calls) != 0 {
				t.Errorf("%s calls = %d, want 0", method, len(calls))
			}
		}
	})

	t.Run("configure address fails", func(t *testing.T) {
		fake := &fakeWGController{configureAddressErr: fakeErr}
		c := NewWGVPNController(fake, testVPNAddress, discardLogger())

		err := c.CreateTunnelInterface(testVPNIface, testVPNPort)
		wantWGErrPrefix(t, err, "bridge: vpn: configure address 10.0.0.5/32:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		deleted := fake.wgCallsFor("DeleteInterface")
		if len(deleted) != 1 {
			t.Fatalf("DeleteInterface calls = %d, want 1", len(deleted))
		}
		if got := deleted[0].Args[0]; got != testVPNIface {
			t.Errorf("DeleteInterface interface = %v, want %q", got, testVPNIface)
		}
		if calls := fake.wgCallsFor("SetInterfaceUp"); len(calls) != 0 {
			t.Errorf("SetInterfaceUp calls = %d, want 0 after a failed address", len(calls))
		}
	})

	t.Run("set up fails", func(t *testing.T) {
		fake := &fakeWGController{setInterfaceUpErr: fakeErr}
		c := NewWGVPNController(fake, "", discardLogger())

		err := c.CreateTunnelInterface(testVPNIface, testVPNPort)
		wantWGErrPrefix(t, err, "bridge: vpn: set interface up:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		deleted := fake.wgCallsFor("DeleteInterface")
		if len(deleted) != 1 {
			t.Fatalf("DeleteInterface calls = %d, want 1", len(deleted))
		}
		if got := deleted[0].Args[0]; got != testVPNIface {
			t.Errorf("DeleteInterface interface = %v, want %q", got, testVPNIface)
		}
	})
}

func TestWGVPNController_RemoveTunnelInterface(t *testing.T) {
	t.Run("removes", func(t *testing.T) {
		fake := &fakeWGController{}
		logger, buf := debugLogger()
		c := NewWGVPNController(fake, "", logger)

		if err := c.RemoveTunnelInterface(testVPNIface); err != nil {
			t.Fatalf("RemoveTunnelInterface() error = %v", err)
		}

		deleted := fake.wgCallsFor("DeleteInterface")
		if len(deleted) != 1 {
			t.Fatalf("DeleteInterface calls = %d, want 1", len(deleted))
		}
		if got := deleted[0].Args[0]; got != testVPNIface {
			t.Errorf("DeleteInterface interface = %v, want %q", got, testVPNIface)
		}

		logged := buf.String()
		for _, want := range []string{"level=INFO", `msg="tunnel interface removed"`, "interface=wg-s2s-0"} {
			if !strings.Contains(logged, want) {
				t.Errorf("log = %q, want it to contain %q", logged, want)
			}
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		fakeErr := errors.New("wg failed")
		fake := &fakeWGController{deleteInterfaceErr: fakeErr}
		c := NewWGVPNController(fake, "", discardLogger())

		err := c.RemoveTunnelInterface(testVPNIface)
		wantWGErrPrefix(t, err, "bridge: vpn: remove interface:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
	})
}

func TestWGVPNController_ConfigureTunnelPeer(t *testing.T) {
	pubB64, pubRaw := testPeerKey(t)
	pskB64, pskRaw := testPeerKey(t)

	fake := &fakeWGController{}
	logger, buf := debugLogger()
	c := NewWGVPNController(fake, testVPNAddress, logger)

	err := c.ConfigureTunnelPeer(testVPNIface, pubB64, []string{"10.1.0.0/24"}, "203.0.113.7:51820", pskB64)
	if err != nil {
		t.Fatalf("ConfigureTunnelPeer() error = %v", err)
	}

	added := fake.wgCallsFor("AddPeer")
	if len(added) != 1 {
		t.Fatalf("AddPeer calls = %d, want 1", len(added))
	}
	if got := added[0].Args[0]; got != testVPNIface {
		t.Errorf("AddPeer interface = %v, want %q", got, testVPNIface)
	}
	want := wireguard.PeerConfig{
		PublicKey:  pubRaw,
		Endpoint:   "203.0.113.7:51820",
		AllowedIPs: []string{"10.1.0.0/24"},
		PSK:        pskRaw,
	}
	if got := added[0].Args[1]; !reflect.DeepEqual(got, want) {
		t.Errorf("PeerConfig = %+v, want %+v", got, want)
	}

	logged := buf.String()
	for _, want := range []string{"level=DEBUG", `msg="tunnel peer configured"`, "component=bridge", "interface=wg-s2s-0"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
	if strings.Contains(logged, pubB64) || strings.Contains(logged, pskB64) {
		t.Errorf("log = %q, want no key material in it", logged)
	}
}

func TestWGVPNController_ConfigureTunnelPeerEndpoints(t *testing.T) {
	pubB64, pubRaw := testPeerKey(t)

	t.Run("empty endpoint", func(t *testing.T) {
		fake := &fakeWGController{}
		c := NewWGVPNController(fake, "", discardLogger())

		if err := c.ConfigureTunnelPeer(testVPNIface, pubB64, nil, "", ""); err != nil {
			t.Fatalf("ConfigureTunnelPeer() error = %v", err)
		}

		added := fake.wgCallsFor("AddPeer")
		if len(added) != 1 {
			t.Fatalf("AddPeer calls = %d, want 1", len(added))
		}
		want := wireguard.PeerConfig{PublicKey: pubRaw}
		if got := added[0].Args[1]; !reflect.DeepEqual(got, want) {
			t.Errorf("PeerConfig = %+v, want %+v", got, want)
		}
	})

	// The address that reaches the device is the one that was resolved, not
	// the string the control plane sent: a second lookup could answer
	// differently, so what was checked would not be what was programmed. The
	// literal is upper case and unbracketed by netip, so the two differ
	// without a name server being asked anything.
	t.Run("resolved endpoint reaches the device", func(t *testing.T) {
		fake := &fakeWGController{}
		c := NewWGVPNController(fake, "", discardLogger())

		if err := c.ConfigureTunnelPeer(testVPNIface, pubB64, nil, "[2001:DB8::1]:51820", ""); err != nil {
			t.Fatalf("ConfigureTunnelPeer() error = %v", err)
		}

		added := fake.wgCallsFor("AddPeer")
		if len(added) != 1 {
			t.Fatalf("AddPeer calls = %d, want 1", len(added))
		}
		want := wireguard.PeerConfig{PublicKey: pubRaw, Endpoint: "[2001:db8::1]:51820"}
		if got := added[0].Args[1]; !reflect.DeepEqual(got, want) {
			t.Errorf("PeerConfig = %+v, want %+v", got, want)
		}
	})

	// The port is out of range, which the port lookup rejects before the host
	// is looked up, so the case needs no name server.
	t.Run("port out of range", func(t *testing.T) {
		fake := &fakeWGController{}
		c := NewWGVPNController(fake, "", discardLogger())

		err := c.ConfigureTunnelPeer(testVPNIface, pubB64, nil, "host:99999", "")
		wantWGErrPrefix(t, err, "bridge: vpn: resolve endpoint:")
		if calls := fake.wgCallsFor("AddPeer"); len(calls) != 0 {
			t.Errorf("AddPeer calls = %d, want 0 for an unresolvable endpoint", len(calls))
		}
	})
}

// A dual-stack name must be programmed with its A record, the family
// net.ResolveUDPAddr picks for network "udp" and therefore the family
// NetlinkVPNController programs on Linux. Pinning the AAAA record instead
// would leave a gateway with no IPv6 egress reporting an active tunnel whose
// handshake never completes.
func TestPreferIPv4(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  string
	}{
		{name: "AAAA first", addrs: []string{"2001:db8::10", "203.0.113.10"}, want: "203.0.113.10"},
		{name: "A first", addrs: []string{"203.0.113.10", "2001:db8::10"}, want: "203.0.113.10"},
		{name: "IPv6 only", addrs: []string{"2001:db8::10", "2001:db8::11"}, want: "2001:db8::10"},
		{name: "IPv4-mapped", addrs: []string{"2001:db8::10", "::ffff:203.0.113.10"}, want: "203.0.113.10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs := make([]netip.Addr, 0, len(tt.addrs))
			for _, s := range tt.addrs {
				addrs = append(addrs, netip.MustParseAddr(s))
			}
			if got := preferIPv4(addrs); got.String() != tt.want {
				t.Errorf("preferIPv4(%v) = %q, want %q", tt.addrs, got, tt.want)
			}
		})
	}
}

func TestWGVPNController_ConfigureTunnelPeerInvalidInput(t *testing.T) {
	pubB64, _ := testPeerKey(t)
	shortB64 := base64.StdEncoding.EncodeToString(make([]byte, 5))

	tests := []struct {
		name        string
		publicKey   string
		allowedIPs  []string
		psk         string
		wantPrefix  string
		wantCorrupt bool
	}{
		{
			name:        "public key not base64",
			publicKey:   "!!!",
			wantPrefix:  "bridge: vpn: decode public key:",
			wantCorrupt: true,
		},
		{
			name:       "public key empty",
			publicKey:  "",
			wantPrefix: "bridge: vpn: parse public key:",
		},
		{
			name:       "public key too short",
			publicKey:  shortB64,
			wantPrefix: "bridge: vpn: parse public key:",
		},
		{
			name:       "allowed IP malformed",
			publicKey:  pubB64,
			allowedIPs: []string{"10.0.0/33"},
			wantPrefix: `bridge: vpn: parse allowed IP "10.0.0/33":`,
		},
		{
			name:       "psk not base64",
			publicKey:  pubB64,
			psk:        "!!!",
			wantPrefix: "bridge: vpn: decode psk:",
		},
		{
			name:       "psk too short",
			publicKey:  pubB64,
			psk:        shortB64,
			wantPrefix: "bridge: vpn: parse psk:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeWGController{}
			c := NewWGVPNController(fake, "", discardLogger())

			err := c.ConfigureTunnelPeer(testVPNIface, tt.publicKey, tt.allowedIPs, "", tt.psk)
			wantWGErrPrefix(t, err, tt.wantPrefix)
			if tt.wantCorrupt && !errors.As(err, new(base64.CorruptInputError)) {
				t.Errorf("errors.As(err, *base64.CorruptInputError) = false, want true")
			}
			if calls := fake.wgCallsFor("AddPeer"); len(calls) != 0 {
				t.Errorf("AddPeer calls = %d, want 0 for invalid input", len(calls))
			}
		})
	}
}

func TestWGVPNController_ConfigureTunnelPeerAddPeerError(t *testing.T) {
	pubB64, _ := testPeerKey(t)
	fakeErr := errors.New("wg failed")

	fake := &fakeWGController{addPeerErr: fakeErr}
	c := NewWGVPNController(fake, "", discardLogger())

	err := c.ConfigureTunnelPeer(testVPNIface, pubB64, []string{"10.1.0.0/24"}, "203.0.113.7:51820", "")
	wantWGErrPrefix(t, err, "bridge: vpn: configure peer:")
	if !errors.Is(err, fakeErr) {
		t.Errorf("errors.Is(err, fakeErr) = false, want true")
	}
}

func TestWGVPNController_RemoveTunnelPeer(t *testing.T) {
	pubB64, pubRaw := testPeerKey(t)

	t.Run("removes", func(t *testing.T) {
		fake := &fakeWGController{}
		logger, buf := debugLogger()
		c := NewWGVPNController(fake, "", logger)

		if err := c.RemoveTunnelPeer(testVPNIface, pubB64); err != nil {
			t.Fatalf("RemoveTunnelPeer() error = %v", err)
		}

		removed := fake.wgCallsFor("RemovePeer")
		if len(removed) != 1 {
			t.Fatalf("RemovePeer calls = %d, want 1", len(removed))
		}
		if got := removed[0].Args[0]; got != testVPNIface {
			t.Errorf("RemovePeer interface = %v, want %q", got, testVPNIface)
		}
		if got := removed[0].Args[1]; !reflect.DeepEqual(got, pubRaw) {
			t.Errorf("RemovePeer public key = %v, want %v", got, pubRaw)
		}

		logged := buf.String()
		for _, want := range []string{"level=DEBUG", `msg="tunnel peer removed"`, "interface=wg-s2s-0"} {
			if !strings.Contains(logged, want) {
				t.Errorf("log = %q, want it to contain %q", logged, want)
			}
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		tests := []struct {
			name       string
			publicKey  string
			wantPrefix string
		}{
			{name: "not base64", publicKey: "!!!", wantPrefix: "bridge: vpn: decode public key:"},
			{name: "empty", publicKey: "", wantPrefix: "bridge: vpn: parse public key:"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeWGController{}
				c := NewWGVPNController(fake, "", discardLogger())

				wantWGErrPrefix(t, c.RemoveTunnelPeer(testVPNIface, tt.publicKey), tt.wantPrefix)
				if calls := fake.wgCallsFor("RemovePeer"); len(calls) != 0 {
					t.Errorf("RemovePeer calls = %d, want 0 for invalid input", len(calls))
				}
			})
		}
	})

	t.Run("remove fails", func(t *testing.T) {
		fakeErr := errors.New("wg failed")
		fake := &fakeWGController{removePeerErr: fakeErr}
		c := NewWGVPNController(fake, "", discardLogger())

		err := c.RemoveTunnelPeer(testVPNIface, pubB64)
		wantWGErrPrefix(t, err, "bridge: vpn: remove peer:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
	})
}

func TestWGVPNController_OSInterfaceName(t *testing.T) {
	t.Run("controller names devices", func(t *testing.T) {
		namer := &namerWGController{
			fakeWGController: &fakeWGController{},
			names:            map[string]string{testVPNIface: "utun9"},
		}
		c := NewWGVPNController(namer, testVPNAddress, discardLogger())

		if got, ok := c.OSInterfaceName(testVPNIface); got != "utun9" || !ok {
			t.Errorf("OSInterfaceName(%q) = (%q, %v), want (\"utun9\", true)", testVPNIface, got, ok)
		}
		if got, ok := c.OSInterfaceName("other"); got != "" || ok {
			t.Errorf("OSInterfaceName(\"other\") = (%q, %v), want (\"\", false)", got, ok)
		}
	})

	// Windows keeps the configured name, so that name is what the operating
	// system knows the adapter by. Reporting no mapping there would tell a
	// caller reading the wireguard.OSInterfaceNamer contract that a live
	// adapter does not exist.
	t.Run("controller keeps the configured name", func(t *testing.T) {
		c := NewWGVPNController(&fakeWGController{}, "", discardLogger())

		if got, ok := c.OSInterfaceName(testVPNIface); got != testVPNIface || !ok {
			t.Errorf("OSInterfaceName(%q) = (%q, %v), want (%q, true)", testVPNIface, got, ok, testVPNIface)
		}
	})
}
