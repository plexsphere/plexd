//go:build linux

package bridge

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

// The kernel reports a listen port another socket holds as EADDRINUSE: bare
// from netlink.LinkSetUp, wrapped in an operation error from wgctrl's
// ConfigureDevice. Either form has to read as ErrListenPortInUse while still
// wrapping what the kernel said; any other errno must not.
func TestListenPortErr(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantInUse bool
	}{
		{name: "bare EADDRINUSE", err: syscall.EADDRINUSE, wantInUse: true},
		{name: "wrapped EADDRINUSE", err: fmt.Errorf("receive: %w", syscall.EADDRINUSE), wantInUse: true},
		{name: "syscall error EADDRINUSE", err: os.NewSyscallError("bind", syscall.EADDRINUSE), wantInUse: true},
		{name: "other errno", err: fmt.Errorf("receive: %w", syscall.EPERM)},
		{name: "plain error", err: errors.New("boom")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := listenPortErr("access", "set interface up", tt.err)

			wantWGErrPrefix(t, err, "bridge: access: set interface up:")
			if got := errors.Is(err, ErrListenPortInUse); got != tt.wantInUse {
				t.Errorf("errors.Is(err, ErrListenPortInUse) = %v, want %v (err = %q)", got, tt.wantInUse, err)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("errors.Is(err, cause) = false, want the cause wrapped (err = %q)", err)
			}
		})
	}

	// Each controller passes its own prefix, so the access and the
	// site-to-site interface read apart in the log.
	for _, tt := range []struct {
		prefix, want string
	}{
		{prefix: "access", want: "bridge: access: configure device: listen port in use: address already in use"},
		{prefix: "vpn", want: "bridge: vpn: configure device: listen port in use: address already in use"},
	} {
		if got := listenPortErr(tt.prefix, "configure device", syscall.EADDRINUSE).Error(); got != tt.want {
			t.Errorf("error = %q, want %q", got, tt.want)
		}
	}
}

// Malformed input is refused before the link is added, so these cases need no
// privileges and leave no kernel state behind.
func TestNetlinkAccessController_CreateInterfaceInvalidInput(t *testing.T) {
	key := testPrivateKey(t)

	tests := []struct {
		name       string
		key        []byte
		address    string
		wantPrefix string
	}{
		{name: "nil key", key: nil, address: testAccessAddress, wantPrefix: "bridge: access: parse private key:"},
		{name: "short key", key: make([]byte, 31), address: testAccessAddress, wantPrefix: "bridge: access: parse private key:"},
		{name: "address without prefix length", key: key, address: "10.98.0.1", wantPrefix: `bridge: access: parse address "10.98.0.1":`},
		{name: "address malformed", key: key, address: "not-an-address", wantPrefix: `bridge: access: parse address "not-an-address":`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewNetlinkAccessController(discardLogger())

			wantWGErrPrefix(t, c.CreateInterface("plexd-uatest", tt.key, testAccessPort, tt.address), tt.wantPrefix)
		})
	}
}

// An empty prefix would match the mesh interface and every tunnel, so it is
// refused before any link is listed.
func TestNetlinkAccessController_RemoveInterfacesEmptyPrefix(t *testing.T) {
	c := NewNetlinkAccessController(discardLogger())

	wantWGErrPrefix(t, c.RemoveInterfaces(""), "bridge: access: remove interfaces: empty prefix")
}

// Listing links needs no privileges. A prefix no link carries deletes nothing
// and succeeds, which is what a start finds after a clean shutdown.
func TestNetlinkAccessController_RemoveInterfacesNoMatch(t *testing.T) {
	c := NewNetlinkAccessController(discardLogger())

	if err := c.RemoveInterfaces("plexd-nolink-"); err != nil {
		t.Fatalf("RemoveInterfaces() error = %v, want nil", err)
	}
}
