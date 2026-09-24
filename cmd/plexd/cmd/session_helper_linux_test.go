//go:build linux

package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/registration"
)

func newHelperTestKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, base64.StdEncoding.EncodeToString(pub)
}

// saveHelperTestIdentity registers a node in dataDir whose signing key is key.
func saveHelperTestIdentity(t *testing.T, dataDir, key string) {
	t.Helper()
	nsk := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := registration.SaveIdentity(dataDir, &registration.NodeIdentity{
		NodeID:           "0e9f8a36-7c43-4d0a-9f5e-1b2c3d4e5f60",
		MeshIP:           "10.99.0.1",
		SigningPublicKey: key,
		SigningKeyID:     "kid-1",
		PrivateKey:       make([]byte, 32),
		NodeSecretKey:    nsk,
	}); err != nil {
		t.Fatalf("SaveIdentity() error: %v", err)
	}
}

func TestResolveHelperSigningKey(t *testing.T) {
	configured, configuredB64 := newHelperTestKey(t)
	pinned, pinnedB64 := newHelperTestKey(t)
	identity, identityB64 := newHelperTestKey(t)

	t.Run("configured key wins and leaves the pin absent", func(t *testing.T) {
		dir := t.TempDir()
		pin := filepath.Join(dir, "session-signing-key")
		saveHelperTestIdentity(t, dir, identityB64)
		cfg := &agent.AgentConfig{DataDir: dir}
		cfg.Tunnel.SessionSigningPublicKey = configuredB64

		key, err := resolveHelperSigningKey(cfg, pin, discardLogger())
		if err != nil {
			t.Fatalf("resolveHelperSigningKey() error: %v", err)
		}
		if !key.Equal(configured) {
			t.Error("the configured key was not used")
		}
		if _, err := os.Stat(pin); !os.IsNotExist(err) {
			t.Errorf("the pin was written although a key is configured (stat error %v)", err)
		}
	})

	t.Run("configured key wins over an existing pin", func(t *testing.T) {
		dir := t.TempDir()
		pin := filepath.Join(dir, "session-signing-key")
		if err := os.WriteFile(pin, []byte(pinnedB64+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := &agent.AgentConfig{DataDir: dir}
		cfg.Tunnel.SessionSigningPublicKey = configuredB64

		key, err := resolveHelperSigningKey(cfg, pin, discardLogger())
		if err != nil {
			t.Fatalf("resolveHelperSigningKey() error: %v", err)
		}
		if !key.Equal(configured) {
			t.Error("the configured key was not used")
		}
		if data, _ := os.ReadFile(pin); string(data) != pinnedB64+"\n" {
			t.Errorf("pin = %q, want it untouched", data)
		}
	})

	t.Run("existing pin is used without identity.json", func(t *testing.T) {
		dir := t.TempDir()
		pin := filepath.Join(dir, "session-signing-key")
		if err := os.WriteFile(pin, []byte(pinnedB64+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		key, err := resolveHelperSigningKey(&agent.AgentConfig{DataDir: filepath.Join(dir, "no-data")}, pin, discardLogger())
		if err != nil {
			t.Fatalf("resolveHelperSigningKey() error: %v", err)
		}
		if !key.Equal(pinned) {
			t.Error("the pinned key was not used")
		}
	})

	// plexd can write identity.json, so a pin, once taken, must win over it.
	t.Run("existing pin wins over identity.json", func(t *testing.T) {
		dir := t.TempDir()
		pin := filepath.Join(dir, "session-signing-key")
		if err := os.WriteFile(pin, []byte(pinnedB64+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		saveHelperTestIdentity(t, dir, identityB64)

		key, err := resolveHelperSigningKey(&agent.AgentConfig{DataDir: dir}, pin, discardLogger())
		if err != nil {
			t.Fatalf("resolveHelperSigningKey() error: %v", err)
		}
		if !key.Equal(pinned) {
			t.Error("the pinned key was not used")
		}
		if data, _ := os.ReadFile(pin); string(data) != pinnedB64+"\n" {
			t.Errorf("pin = %q, want it untouched", data)
		}
	})

	t.Run("absent pin is written from the identity", func(t *testing.T) {
		dir := t.TempDir()
		pin := filepath.Join(dir, "session-signing-key")
		saveHelperTestIdentity(t, dir, identityB64)

		key, err := resolveHelperSigningKey(&agent.AgentConfig{DataDir: dir}, pin, discardLogger())
		if err != nil {
			t.Fatalf("resolveHelperSigningKey() error: %v", err)
		}
		if !key.Equal(identity) {
			t.Error("the identity's key was not used")
		}
		info, err := os.Stat(pin)
		if err != nil {
			t.Fatalf("the pin was not written: %v", err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Errorf("pin mode = %o, want 644", info.Mode().Perm())
		}
		data, _ := os.ReadFile(pin)
		if string(data) != identityB64+"\n" {
			t.Errorf("pin = %q, want the identity's key", data)
		}
	})

	for _, tc := range []struct {
		name       string
		configured string
		setup      func(t *testing.T, dir, pin string)
		wantPrefix string
	}{
		{
			name: "malformed pin",
			setup: func(t *testing.T, dir, pin string) {
				saveHelperTestIdentity(t, dir, identityB64)
				if err := os.WriteFile(pin, []byte("garbage"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantPrefix: "session helper: pinned key " + "%PIN%" + " is malformed: ",
		},
		{
			name:       "not registered",
			setup:      func(*testing.T, string, string) {},
			wantPrefix: "session helper: node is not registered; no signing key to pin",
		},
		{
			name: "pin path is a directory",
			setup: func(t *testing.T, _, pin string) {
				if err := os.Mkdir(pin, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantPrefix: "session helper: read pinned key ",
		},
		{
			name:       "malformed configured key",
			configured: "not base64!",
			setup:      func(*testing.T, string, string) {},
			wantPrefix: "session helper: tunnel.session_signing_public_key: ",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pin := filepath.Join(dir, "session-signing-key")
			tc.setup(t, dir, pin)
			cfg := &agent.AgentConfig{DataDir: dir}
			cfg.Tunnel.SessionSigningPublicKey = tc.configured
			_, err := resolveHelperSigningKey(cfg, pin, discardLogger())
			want := strings.ReplaceAll(tc.wantPrefix, "%PIN%", pin)
			if err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("error = %v, want prefix %q", err, want)
			}
		})
	}
}

func TestSelectHelperMode(t *testing.T) {
	pid := os.Getpid()
	own := strconv.Itoa(pid)
	const neither = "plexd session-helper: start it through plexd-session-helper.socket or let plexd start it (--child)"

	for _, tc := range []struct {
		name           string
		listenPID, fds string
		child          bool
		keys           []string
		wantSocket     bool
		wantErr        string
	}{
		{name: "socket-activated", listenPID: own, fds: "1", wantSocket: true},
		{name: "child with a key", child: true, keys: []string{"k"}},
		{name: "trusted key in socket mode", listenPID: own, fds: "1", keys: []string{"k"}, wantErr: "--trusted-key is only valid with --child"},
		{name: "child without a key", child: true, wantErr: "--child needs at least one --trusted-key"},
		{name: "neither", wantErr: neither},
		{name: "both", listenPID: own, fds: "1", child: true, keys: []string{"k"}, wantErr: neither},
		{name: "another process's activation", listenPID: strconv.Itoa(pid + 1), fds: "1", wantErr: neither},
		{name: "two activated descriptors", listenPID: own, fds: "2", wantErr: neither},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket, err := selectHelperMode(tc.listenPID, tc.fds, pid, tc.child, tc.keys)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if socket != tc.wantSocket {
				t.Errorf("socket = %v, want %v", socket, tc.wantSocket)
			}
		})
	}
}
