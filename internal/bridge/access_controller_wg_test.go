package bridge

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/wireguard"
)

const (
	testAccessIface   = "wg-access"
	testAccessPort    = 51822
	testAccessAddress = "10.98.0.1/24"
)

func TestWGAccessController_CreateInterface(t *testing.T) {
	key := testPrivateKey(t)
	fake := &fakeWGController{}
	logger, buf := debugLogger()
	c := NewWGAccessController(fake, logger)

	if err := c.CreateInterface(testAccessIface, key, testAccessPort, testAccessAddress); err != nil {
		t.Fatalf("CreateInterface() error = %v", err)
	}

	wantOrder := []string{"CreateInterface", "ConfigureAddress", "SetInterfaceUp"}
	if got := fake.wgMethods(); !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("calls = %v, want %v", got, wantOrder)
	}

	created := fake.wgCallsFor("CreateInterface")
	if len(created) != 1 {
		t.Fatalf("CreateInterface calls = %d, want 1", len(created))
	}
	if got := created[0].Args[0]; got != testAccessIface {
		t.Errorf("interface = %v, want %q", got, testAccessIface)
	}
	if got, ok := created[0].Args[1].([]byte); !ok || !bytes.Equal(got, key) {
		t.Error("private key differs from the key passed to CreateInterface")
	}
	if got := created[0].Args[2]; got != testAccessPort {
		t.Errorf("listen port = %v, want %d", got, testAccessPort)
	}

	addressed := fake.wgCallsFor("ConfigureAddress")
	if len(addressed) != 1 {
		t.Fatalf("ConfigureAddress calls = %d, want 1", len(addressed))
	}
	if got := addressed[0].Args[0]; got != testAccessIface {
		t.Errorf("ConfigureAddress interface = %v, want %q", got, testAccessIface)
	}
	if got := addressed[0].Args[1]; got != testAccessAddress {
		t.Errorf("ConfigureAddress address = %v, want %q", got, testAccessAddress)
	}

	up := fake.wgCallsFor("SetInterfaceUp")
	if len(up) != 1 {
		t.Fatalf("SetInterfaceUp calls = %d, want 1", len(up))
	}
	if got := up[0].Args[0]; got != testAccessIface {
		t.Errorf("SetInterfaceUp interface = %v, want %q", got, testAccessIface)
	}

	logged := buf.String()
	for _, want := range []string{
		`level=INFO msg="access interface created"`,
		`level=DEBUG msg="access interface addressed"`,
		"component=bridge",
		"interface=wg-access",
		"listen_port=51822",
		"address=10.98.0.1/24",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
	if strings.Contains(logged, base64.StdEncoding.EncodeToString(key)) {
		t.Errorf("log = %q, want no key material in it", logged)
	}
}

func TestWGAccessController_CreateInterfaceUnnumbered(t *testing.T) {
	fake := &fakeWGController{}
	logger, buf := debugLogger()
	c := NewWGAccessController(fake, logger)

	if err := c.CreateInterface(testAccessIface, testPrivateKey(t), testAccessPort, ""); err != nil {
		t.Fatalf("CreateInterface() error = %v", err)
	}

	wantOrder := []string{"CreateInterface", "SetInterfaceUp"}
	if got := fake.wgMethods(); !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("calls = %v, want %v for an unnumbered interface", got, wantOrder)
	}
	if logged := buf.String(); strings.Contains(logged, "interface addressed") {
		t.Errorf("log = %q, want no address line for an unnumbered interface", logged)
	}
}

// The caller owns the key, so an interface created again under the same key
// keeps its public key, and every device configured against it keeps working.
func TestWGAccessController_CreateInterfaceKeptKey(t *testing.T) {
	key := testPrivateKey(t)
	fake := &fakeWGController{}
	c := NewWGAccessController(fake, discardLogger())

	for i := range 2 {
		if err := c.CreateInterface(testAccessIface, key, testAccessPort, testAccessAddress); err != nil {
			t.Fatalf("CreateInterface() #%d error = %v", i, err)
		}
	}

	created := fake.wgCallsFor("CreateInterface")
	if len(created) != 2 {
		t.Fatalf("CreateInterface calls = %d, want 2", len(created))
	}
	for i, call := range created {
		if got, ok := call.Args[1].([]byte); !ok || !bytes.Equal(got, key) {
			t.Errorf("create #%d: private key differs from the key passed in, want the same key on every create", i)
		}
	}
}

func TestWGAccessController_CreateInterfaceErrors(t *testing.T) {
	fakeErr := errors.New("wg failed")

	t.Run("private key malformed", func(t *testing.T) {
		for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
			fake := &fakeWGController{}
			c := NewWGAccessController(fake, discardLogger())

			err := c.CreateInterface(testAccessIface, key, testAccessPort, testAccessAddress)
			wantWGErrPrefix(t, err, "bridge: access: parse private key:")
			if got := fake.wgMethods(); len(got) != 0 {
				t.Errorf("%d-byte key: calls = %v, want none", len(key), got)
			}
		}
	})

	t.Run("create fails", func(t *testing.T) {
		fake := &fakeWGController{createInterfaceErr: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		err := c.CreateInterface(testAccessIface, testPrivateKey(t), testAccessPort, testAccessAddress)
		wantWGErrPrefix(t, err, "bridge: access: create interface wg-access:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		if errors.Is(err, ErrListenPortInUse) {
			t.Errorf("errors.Is(err, ErrListenPortInUse) = true for %v, want false", err)
		}
		for _, method := range []string{"ConfigureAddress", "SetInterfaceUp", "DeleteInterface"} {
			if calls := fake.wgCallsFor(method); len(calls) != 0 {
				t.Errorf("%s calls = %d, want 0", method, len(calls))
			}
		}
	})

	// wireguard-go binds the listen port when the wrapped controller brings
	// the device up, and a port another socket holds surfaces as the bind's
	// EADDRINUSE, wrapped.
	t.Run("create fails on a taken port", func(t *testing.T) {
		fake := &fakeWGController{createInterfaceErr: takenPortErr()}
		c := NewWGAccessController(fake, discardLogger())

		err := c.CreateInterface(testAccessIface, testPrivateKey(t), testAccessPort, testAccessAddress)
		wantWGErrPrefix(t, err, "bridge: access: create interface wg-access: listen port in use:")
		if !errors.Is(err, ErrListenPortInUse) {
			t.Errorf("errors.Is(err, ErrListenPortInUse) = false for %v, want true", err)
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Errorf("errors.Is(err, syscall.EADDRINUSE) = false for %v, want true", err)
		}
	})

	t.Run("configure address fails", func(t *testing.T) {
		fake := &fakeWGController{configureAddressErr: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		err := c.CreateInterface(testAccessIface, testPrivateKey(t), testAccessPort, testAccessAddress)
		wantWGErrPrefix(t, err, "bridge: access: configure address 10.98.0.1/24:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		deleted := fake.wgCallsFor("DeleteInterface")
		if len(deleted) != 1 {
			t.Fatalf("DeleteInterface calls = %d, want 1", len(deleted))
		}
		if got := deleted[0].Args[0]; got != testAccessIface {
			t.Errorf("DeleteInterface interface = %v, want %q", got, testAccessIface)
		}
		if calls := fake.wgCallsFor("SetInterfaceUp"); len(calls) != 0 {
			t.Errorf("SetInterfaceUp calls = %d, want 0 after a failed address", len(calls))
		}
	})

	t.Run("set up fails", func(t *testing.T) {
		fake := &fakeWGController{setInterfaceUpErr: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		err := c.CreateInterface(testAccessIface, testPrivateKey(t), testAccessPort, testAccessAddress)
		wantWGErrPrefix(t, err, "bridge: access: set interface up:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		deleted := fake.wgCallsFor("DeleteInterface")
		if len(deleted) != 1 {
			t.Fatalf("DeleteInterface calls = %d, want 1", len(deleted))
		}
		if got := deleted[0].Args[0]; got != testAccessIface {
			t.Errorf("DeleteInterface interface = %v, want %q", got, testAccessIface)
		}
	})
}

// takenPortErr is what UserspaceBackend returns when wireguard-go cannot bind
// a port another socket holds: its prefix around the bind's net.OpError.
func takenPortErr() error {
	bind := &net.OpError{Op: "listen", Net: "udp4", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	return fmt.Errorf("wireguard: create interface: up: %w", bind)
}

func TestWGAccessController_OSInterfaceName(t *testing.T) {
	t.Run("controller names devices", func(t *testing.T) {
		namer := &namerWGController{
			fakeWGController: &fakeWGController{},
			names:            map[string]string{testAccessIface: "utun7"},
		}
		c := NewWGAccessController(namer, discardLogger())

		if got, ok := c.OSInterfaceName(testAccessIface); got != "utun7" || !ok {
			t.Errorf("OSInterfaceName(%q) = (%q, %v), want (\"utun7\", true)", testAccessIface, got, ok)
		}
		if got, ok := c.OSInterfaceName("other"); got != "" || ok {
			t.Errorf("OSInterfaceName(\"other\") = (%q, %v), want (\"\", false)", got, ok)
		}
	})

	t.Run("controller keeps the configured name", func(t *testing.T) {
		c := NewWGAccessController(&fakeWGController{}, discardLogger())

		if got, ok := c.OSInterfaceName(testAccessIface); got != testAccessIface || !ok {
			t.Errorf("OSInterfaceName(%q) = (%q, %v), want (%q, true)", testAccessIface, got, ok, testAccessIface)
		}
	})
}

// osInterfaceName falls back to the configured name whenever no namer finds
// the interface, so a manager always has a name to hand to the host.
func TestOSInterfaceName(t *testing.T) {
	namer := &namerWGController{
		fakeWGController: &fakeWGController{},
		names:            map[string]string{testAccessIface: "utun7"},
	}

	tests := []struct {
		name string
		ctrl any
		want string
	}{
		{name: "a namer that finds the interface", ctrl: namer, want: "utun7"},
		{name: "a nil controller", ctrl: nil, want: testAccessIface},
		{name: "a controller without a namer", ctrl: &mockAccessController{}, want: testAccessIface},
		{name: "a namer that reports false", ctrl: &namerWGController{fakeWGController: &fakeWGController{}}, want: testAccessIface},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := osInterfaceName(tt.ctrl, testAccessIface); got != tt.want {
				t.Errorf("osInterfaceName(%T, %q) = %q, want %q", tt.ctrl, testAccessIface, got, tt.want)
			}
		})
	}
}

func TestWGAccessController_RemoveInterface(t *testing.T) {
	t.Run("removes", func(t *testing.T) {
		fake := &fakeWGController{}
		logger, buf := debugLogger()
		c := NewWGAccessController(fake, logger)

		if err := c.RemoveInterface(testAccessIface); err != nil {
			t.Fatalf("RemoveInterface() error = %v", err)
		}

		deleted := fake.wgCallsFor("DeleteInterface")
		if len(deleted) != 1 {
			t.Fatalf("DeleteInterface calls = %d, want 1", len(deleted))
		}
		if got := deleted[0].Args[0]; got != testAccessIface {
			t.Errorf("DeleteInterface interface = %v, want %q", got, testAccessIface)
		}

		logged := buf.String()
		for _, want := range []string{"level=INFO", `msg="access interface removed"`, "interface=wg-access"} {
			if !strings.Contains(logged, want) {
				t.Errorf("log = %q, want it to contain %q", logged, want)
			}
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		fakeErr := errors.New("wg failed")
		fake := &fakeWGController{deleteInterfaceErr: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		err := c.RemoveInterface(testAccessIface)
		wantWGErrPrefix(t, err, "bridge: access: remove interface:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
	})
}

// A userspace device ends with the process that created it, so there is
// nothing a start would have to clear: RemoveInterfaces succeeds without
// asking the controller anything.
func TestWGAccessController_RemoveInterfaces(t *testing.T) {
	fake := &fakeWGController{}
	c := NewWGAccessController(fake, discardLogger())

	if err := c.RemoveInterfaces("wg-ua-"); err != nil {
		t.Fatalf("RemoveInterfaces() error = %v", err)
	}
	if got := fake.wgMethods(); len(got) != 0 {
		t.Errorf("calls = %v, want none", got)
	}
}

func TestWGAccessController_PeerHandshakes(t *testing.T) {
	t.Run("reads the peer stats", func(t *testing.T) {
		b64A, rawA := testPeerKey(t)
		b64B, rawB := testPeerKey(t)
		handshake := time.Unix(1700000000, 0)

		fake := &statsWGController{
			fakeWGController: &fakeWGController{},
			stats: []wireguard.PeerStat{
				{PublicKey: [32]byte(rawA), LastHandshake: handshake, RxBytes: 10},
				{PublicKey: [32]byte(rawB)},
			},
		}
		c := NewWGAccessController(fake, discardLogger())

		got, err := c.PeerHandshakes(testAccessIface)
		if err != nil {
			t.Fatalf("PeerHandshakes() error = %v", err)
		}

		// The peer that never completed a handshake is kept, with the zero time.
		want := map[string]time.Time{b64A: handshake, b64B: {}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("PeerHandshakes() = %v, want %v", got, want)
		}

		read := fake.wgCallsFor("PeerStats")
		if len(read) != 1 || read[0].Args[0] != testAccessIface {
			t.Errorf("PeerStats calls = %v, want one for %q", read, testAccessIface)
		}
	})

	t.Run("no peers", func(t *testing.T) {
		fake := &statsWGController{fakeWGController: &fakeWGController{}}
		c := NewWGAccessController(fake, discardLogger())

		got, err := c.PeerHandshakes(testAccessIface)
		if err != nil {
			t.Fatalf("PeerHandshakes() error = %v", err)
		}
		if got == nil || len(got) != 0 {
			t.Errorf("PeerHandshakes() = %v, want an empty map", got)
		}
	})

	t.Run("read fails", func(t *testing.T) {
		fakeErr := errors.New("wg failed")
		fake := &statsWGController{fakeWGController: &fakeWGController{}, err: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		got, err := c.PeerHandshakes(testAccessIface)
		wantWGErrPrefix(t, err, "bridge: access: peer handshakes:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		if got != nil {
			t.Errorf("PeerHandshakes() = %v, want nil on error", got)
		}
	})

	t.Run("controller reads no stats", func(t *testing.T) {
		fake := &fakeWGController{}
		c := NewWGAccessController(fake, discardLogger())

		got, err := c.PeerHandshakes(testAccessIface)
		wantWGErrPrefix(t, err, "bridge: access: peer handshakes:")
		if !errors.Is(err, wireguard.ErrPeerStatsUnsupported) {
			t.Errorf("errors.Is(err, wireguard.ErrPeerStatsUnsupported) = false, want true")
		}
		if got != nil {
			t.Errorf("PeerHandshakes() = %v, want nil on error", got)
		}
		if calls := fake.wgMethods(); len(calls) != 0 {
			t.Errorf("calls = %v, want none", calls)
		}
	})
}

func TestWGAccessController_ConfigurePeer(t *testing.T) {
	pubB64, pubRaw := testPeerKey(t)

	fake := &fakeWGController{}
	logger, buf := debugLogger()
	c := NewWGAccessController(fake, logger)

	if err := c.ConfigurePeer(testAccessIface, pubB64, []string{"10.7.0.2/32"}, ""); err != nil {
		t.Fatalf("ConfigurePeer() error = %v", err)
	}

	added := fake.wgCallsFor("AddPeer")
	if len(added) != 1 {
		t.Fatalf("AddPeer calls = %d, want 1", len(added))
	}
	if got := added[0].Args[0]; got != testAccessIface {
		t.Errorf("AddPeer interface = %v, want %q", got, testAccessIface)
	}
	want := wireguard.PeerConfig{
		PublicKey:  pubRaw,
		AllowedIPs: []string{"10.7.0.2/32"},
	}
	if got := added[0].Args[1]; !reflect.DeepEqual(got, want) {
		t.Errorf("PeerConfig = %+v, want %+v", got, want)
	}

	logged := buf.String()
	for _, want := range []string{"level=DEBUG", `msg="access peer configured"`, "component=bridge", "interface=wg-access"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
	if strings.Contains(logged, pubB64) {
		t.Errorf("log = %q, want no key material in it", logged)
	}
}

func TestWGAccessController_ConfigurePeerAllowedIPs(t *testing.T) {
	pubB64, pubRaw := testPeerKey(t)

	tests := []struct {
		name       string
		allowedIPs []string
	}{
		{name: "empty slice", allowedIPs: []string{}},
		{name: "nil slice", allowedIPs: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeWGController{}
			c := NewWGAccessController(fake, discardLogger())

			if err := c.ConfigurePeer(testAccessIface, pubB64, tt.allowedIPs, ""); err != nil {
				t.Fatalf("ConfigurePeer() error = %v", err)
			}

			added := fake.wgCallsFor("AddPeer")
			if len(added) != 1 {
				t.Fatalf("AddPeer calls = %d, want 1", len(added))
			}
			want := wireguard.PeerConfig{PublicKey: pubRaw, AllowedIPs: tt.allowedIPs}
			if got := added[0].Args[1]; !reflect.DeepEqual(got, want) {
				t.Errorf("PeerConfig = %+v, want %+v", got, want)
			}
		})
	}
}

func TestWGAccessController_ConfigurePeerInvalidInput(t *testing.T) {
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
			wantPrefix:  "bridge: access: decode public key:",
			wantCorrupt: true,
		},
		{
			name:       "public key empty",
			publicKey:  "",
			wantPrefix: "bridge: access: parse public key:",
		},
		{
			name:       "public key too short",
			publicKey:  shortB64,
			wantPrefix: "bridge: access: parse public key:",
		},
		{
			name:       "allowed IP malformed",
			publicKey:  pubB64,
			allowedIPs: []string{"10.0.0/33"},
			wantPrefix: `bridge: access: parse allowed IP "10.0.0/33":`,
		},
		{
			name:       "psk not base64",
			publicKey:  pubB64,
			psk:        "!!!",
			wantPrefix: "bridge: access: decode psk:",
		},
		{
			name:       "psk too short",
			publicKey:  pubB64,
			psk:        shortB64,
			wantPrefix: "bridge: access: parse psk:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeWGController{}
			c := NewWGAccessController(fake, discardLogger())

			err := c.ConfigurePeer(testAccessIface, tt.publicKey, tt.allowedIPs, tt.psk)
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

func TestWGAccessController_ConfigurePeerPSK(t *testing.T) {
	pubB64, pubRaw := testPeerKey(t)
	pskB64, pskRaw := testPeerKey(t)

	fake := &fakeWGController{}
	c := NewWGAccessController(fake, discardLogger())

	if err := c.ConfigurePeer(testAccessIface, pubB64, []string{"10.7.0.2/32"}, pskB64); err != nil {
		t.Fatalf("ConfigurePeer() error = %v", err)
	}

	added := fake.wgCallsFor("AddPeer")
	if len(added) != 1 {
		t.Fatalf("AddPeer calls = %d, want 1", len(added))
	}
	want := wireguard.PeerConfig{
		PublicKey:  pubRaw,
		AllowedIPs: []string{"10.7.0.2/32"},
		PSK:        pskRaw,
	}
	if got := added[0].Args[1]; !reflect.DeepEqual(got, want) {
		t.Errorf("PeerConfig = %+v, want %+v", got, want)
	}
}

func TestWGAccessController_ConfigurePeerAddPeerError(t *testing.T) {
	pubB64, _ := testPeerKey(t)
	fakeErr := errors.New("wg failed")

	fake := &fakeWGController{addPeerErr: fakeErr}
	c := NewWGAccessController(fake, discardLogger())

	err := c.ConfigurePeer(testAccessIface, pubB64, []string{"10.7.0.2/32"}, "")
	wantWGErrPrefix(t, err, "bridge: access: configure peer:")
	if !errors.Is(err, fakeErr) {
		t.Errorf("errors.Is(err, fakeErr) = false, want true")
	}
}

func TestWGAccessController_RemovePeer(t *testing.T) {
	pubB64, pubRaw := testPeerKey(t)

	t.Run("removes", func(t *testing.T) {
		fake := &fakeWGController{}
		logger, buf := debugLogger()
		c := NewWGAccessController(fake, logger)

		if err := c.RemovePeer(testAccessIface, pubB64); err != nil {
			t.Fatalf("RemovePeer() error = %v", err)
		}

		removed := fake.wgCallsFor("RemovePeer")
		if len(removed) != 1 {
			t.Fatalf("RemovePeer calls = %d, want 1", len(removed))
		}
		if got := removed[0].Args[0]; got != testAccessIface {
			t.Errorf("RemovePeer interface = %v, want %q", got, testAccessIface)
		}
		if got := removed[0].Args[1]; !reflect.DeepEqual(got, pubRaw) {
			t.Errorf("RemovePeer public key = %v, want %v", got, pubRaw)
		}

		logged := buf.String()
		for _, want := range []string{"level=DEBUG", `msg="access peer removed"`, "interface=wg-access"} {
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
			{name: "not base64", publicKey: "!!!", wantPrefix: "bridge: access: decode public key:"},
			{name: "empty", publicKey: "", wantPrefix: "bridge: access: parse public key:"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakeWGController{}
				c := NewWGAccessController(fake, discardLogger())

				wantWGErrPrefix(t, c.RemovePeer(testAccessIface, tt.publicKey), tt.wantPrefix)
				if calls := fake.wgCallsFor("RemovePeer"); len(calls) != 0 {
					t.Errorf("RemovePeer calls = %d, want 0 for invalid input", len(calls))
				}
			})
		}
	})

	t.Run("remove fails", func(t *testing.T) {
		fakeErr := errors.New("wg failed")
		fake := &fakeWGController{removePeerErr: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		err := c.RemovePeer(testAccessIface, pubB64)
		wantWGErrPrefix(t, err, "bridge: access: remove peer:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
	})
}
