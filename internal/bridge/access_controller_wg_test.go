package bridge

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/wireguard"
)

const (
	testAccessIface = "wg-access"
	testAccessPort  = 51822
)

func TestWGAccessController_CreateInterface(t *testing.T) {
	fake := &fakeWGController{}
	logger, buf := debugLogger()
	c := NewWGAccessController(fake, logger)

	if err := c.CreateInterface(testAccessIface, testAccessPort); err != nil {
		t.Fatalf("CreateInterface() error = %v", err)
	}

	created := fake.wgCallsFor("CreateInterface")
	if len(created) != 1 {
		t.Fatalf("CreateInterface calls = %d, want 1", len(created))
	}
	if got := created[0].Args[0]; got != testAccessIface {
		t.Errorf("interface = %v, want %q", got, testAccessIface)
	}
	key, ok := created[0].Args[1].([]byte)
	if !ok || len(key) != 32 {
		t.Errorf("private key = %v, want 32 bytes", created[0].Args[1])
	}
	if got := created[0].Args[2]; got != testAccessPort {
		t.Errorf("listen port = %v, want %d", got, testAccessPort)
	}

	if calls := fake.wgCallsFor("ConfigureAddress"); len(calls) != 0 {
		t.Errorf("ConfigureAddress calls = %d, want 0 for an unnumbered interface", len(calls))
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
		"level=INFO",
		`msg="access interface created"`,
		"component=bridge",
		"interface=wg-access",
		"listen_port=51822",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
	if strings.Contains(logged, "interface addressed") {
		t.Errorf("log = %q, want no address line for an unnumbered interface", logged)
	}
}

func TestWGAccessController_CreateInterfaceFreshKeys(t *testing.T) {
	fake := &fakeWGController{}
	c := NewWGAccessController(fake, discardLogger())

	for i := range 2 {
		if err := c.CreateInterface(testAccessIface, testAccessPort); err != nil {
			t.Fatalf("CreateInterface() #%d error = %v", i, err)
		}
	}

	created := fake.wgCallsFor("CreateInterface")
	if len(created) != 2 {
		t.Fatalf("CreateInterface calls = %d, want 2", len(created))
	}
	first := created[0].Args[1].([]byte)
	second := created[1].Args[1].([]byte)
	if bytes.Equal(first, second) {
		t.Error("both interfaces got the same private key, want a fresh key per interface")
	}
}

func TestWGAccessController_CreateInterfaceErrors(t *testing.T) {
	fakeErr := errors.New("wg failed")

	t.Run("create fails", func(t *testing.T) {
		fake := &fakeWGController{createInterfaceErr: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		err := c.CreateInterface(testAccessIface, testAccessPort)
		wantWGErrPrefix(t, err, "bridge: access: create interface wg-access:")
		if !errors.Is(err, fakeErr) {
			t.Errorf("errors.Is(err, fakeErr) = false, want true")
		}
		for _, method := range []string{"ConfigureAddress", "SetInterfaceUp", "DeleteInterface"} {
			if calls := fake.wgCallsFor(method); len(calls) != 0 {
				t.Errorf("%s calls = %d, want 0", method, len(calls))
			}
		}
	})

	t.Run("set up fails", func(t *testing.T) {
		fake := &fakeWGController{setInterfaceUpErr: fakeErr}
		c := NewWGAccessController(fake, discardLogger())

		err := c.CreateInterface(testAccessIface, testAccessPort)
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
