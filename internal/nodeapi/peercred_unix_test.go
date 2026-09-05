//go:build linux || darwin

// peercred_other.go has no real implementation to exercise, so the credential
// tests are limited to the two platforms that read peer credentials.

package nodeapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

type mockGroupChecker struct {
	groups map[string]bool // "uid:groupName" -> bool
}

func (m *mockGroupChecker) IsInGroup(uid, _ uint32, groupName string) bool {
	key := fmt.Sprintf("%d:%s", uid, groupName)
	return m.groups[key]
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
		if cred.UID != uint32(os.Getuid()) {
			t.Errorf("UID = %d, want %d", cred.UID, os.Getuid())
		}
		if cred.GID != uint32(os.Getgid()) {
			t.Errorf("GID = %d, want %d", cred.GID, os.Getgid())
		}
		if cred.PID != uint32(os.Getpid()) {
			t.Errorf("PID = %d, want %d", cred.PID, os.Getpid())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not see the dialed connection")
	}
}

func TestConnContextWithPeerCred(t *testing.T) {
	fn := connContextWithPeerCred(discardLogger())
	if fn == nil {
		t.Fatal("connContextWithPeerCred() = nil, want a ConnContext function")
	}

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

		connCtx := fn(context.Background(), conn)
		cred, ok := connCtx.Value(peerCredKey{}).(*PeerCredentials)
		if !ok || cred == nil {
			t.Fatal("peer credentials should be in context")
		}
		if cred.UID != uint32(os.Getuid()) {
			t.Errorf("UID = %d, want %d", cred.UID, os.Getuid())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not see the dialed connection")
	}
}

func TestUnixSecretPolicy(t *testing.T) {
	tests := []struct {
		name   string
		groups map[string]bool
		cred   PeerCredentials
		want   bool
	}{
		{
			name:   "root without any group",
			groups: map[string]bool{},
			cred:   PeerCredentials{UID: 0},
			want:   true,
		},
		{
			name:   "plexd-secrets member",
			groups: map[string]bool{"1000:plexd-secrets": true},
			cred:   PeerCredentials{UID: 1000, GID: 1000},
			want:   true,
		},
		{
			name:   "ordinary user",
			groups: map[string]bool{},
			cred:   PeerCredentials{UID: 1000, GID: 1000},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := unixSecretPolicy{groups: &mockGroupChecker{groups: tt.groups}}
			if got := policy.AllowSecrets(&tt.cred); got != tt.want {
				t.Errorf("AllowSecrets(%+v) = %v, want %v", tt.cred, got, tt.want)
			}
		})
	}
}
