//go:build windows

package nodeapi

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// currentPeerIsPrivileged reports what the secrets policy says about this test
// process when it connects to itself.
func currentPeerIsPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func TestGetPeerCredentials_Self(t *testing.T) {
	path := shortSocketPath(t)

	ln, err := ListenLocal(path, discardLogger())
	if err != nil {
		t.Fatalf("ListenLocal: %v", err)
	}
	defer ln.Close()

	accepts := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepts)
			return
		}
		accepts <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := DialLocal(ctx, path)
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	defer client.Close()

	select {
	case conn, ok := <-accepts:
		if !ok {
			t.Fatal("Accept failed")
		}
		defer conn.Close()

		cred, err := GetPeerCredentials(conn)
		if err != nil {
			t.Fatalf("GetPeerCredentials: %v", err)
		}
		if cred.PID != uint32(os.Getpid()) {
			t.Errorf("PID = %d, want %d", cred.PID, os.Getpid())
		}
		if want := windows.GetCurrentProcessToken().IsElevated(); cred.Elevated != want {
			t.Errorf("Elevated = %v, want %v", cred.Elevated, want)
		}
		if cred.LocalSystem {
			t.Error("LocalSystem = true, want false for the test process")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not see the dialed connection")
	}
}

func TestWindowsSecretPolicy(t *testing.T) {
	tests := []struct {
		name string
		cred PeerCredentials
		want bool
	}{
		{name: "elevated administrator", cred: PeerCredentials{Elevated: true}, want: true},
		{name: "local system", cred: PeerCredentials{LocalSystem: true}, want: true},
		{name: "filtered token", cred: PeerCredentials{}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (windowsSecretPolicy{}).AllowSecrets(&tt.cred); got != tt.want {
				t.Errorf("AllowSecrets(%+v) = %v, want %v", tt.cred, got, tt.want)
			}
		})
	}
}
