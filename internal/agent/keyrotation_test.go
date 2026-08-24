package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/registration"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeRotateClient records the submitted requests and returns a configurable
// response/error. When gate is non-nil it blocks inside the call until gate is
// released, signalling entry on entered — this drives the single-flight test.
type fakeRotateClient struct {
	mu       sync.Mutex
	calls    int
	requests []api.KeyRotateRequest
	resp     *api.KeyRotateResponse
	err      error

	gate    chan struct{}
	entered chan struct{}
}

func (c *fakeRotateClient) RotateKeys(_ context.Context, req api.KeyRotateRequest) (*api.KeyRotateResponse, error) {
	c.mu.Lock()
	c.calls++
	c.requests = append(c.requests, req)
	entered, gate := c.entered, c.gate
	resp, err := c.resp, c.err
	c.mu.Unlock()

	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	return resp, err
}

func (c *fakeRotateClient) getCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *fakeRotateClient) getRequests() []api.KeyRotateRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]api.KeyRotateRequest, len(c.requests))
	copy(out, c.requests)
	return out
}

// fakeDeviceUpdater records the private keys handed to the WireGuard device and
// returns a configurable error. failFor limits err to that many leading calls,
// modelling a transient device failure; 0 makes every call return err.
type fakeDeviceUpdater struct {
	mu      sync.Mutex
	keys    [][]byte
	err     error
	failFor int
}

func (d *fakeDeviceUpdater) UpdatePrivateKey(privateKey []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := append([]byte(nil), privateKey...)
	d.keys = append(d.keys, k)
	if d.failFor > 0 && len(d.keys) > d.failFor {
		return nil
	}
	return d.err
}

func (d *fakeDeviceUpdater) getKeys() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.keys))
	copy(out, d.keys)
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestRotator wires a KeyRotator against a temp data dir holding a persisted
// identity whose private key is a fixed, distinguishable sentinel.
func newTestRotator(t *testing.T, client RotateClient, device DeviceKeyUpdater) (*KeyRotator, string, *registration.NodeIdentity, *mockReconcileTrigger) {
	t.Helper()
	dir := t.TempDir()

	id := &registration.NodeIdentity{
		NodeID:           "node-rotate",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "spk",
		// nsk must be std-base64 of 32 bytes so LoadIdentity accepts it.
		NodeSecretKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 32)),
	}
	id.PrivateKey = bytes.Repeat([]byte{0x11}, 32)
	if err := registration.SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	rt := &mockReconcileTrigger{}
	r := NewKeyRotator(client, id, dir, device, rt, testLogger())
	return r, dir, id, rt
}

func pendingExists(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, "rotation_pending_key"))
	switch {
	case err == nil:
		return true
	case os.IsNotExist(err):
		return false
	default:
		t.Fatalf("stat rotation_pending_key: %v", err)
		return false
	}
}

func readPrivateKeyFile(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "private_key"))
	if err != nil {
		t.Fatalf("read private_key: %v", err)
	}
	return string(data)
}

// waitFor polls cond until it holds or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

// ---------------------------------------------------------------------------
// Rotate tests
// ---------------------------------------------------------------------------

func TestKeyRotator_Rotate_HappyPath(t *testing.T) {
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1", WrapKeyVersion: 3}}
	device := &fakeDeviceUpdater{}
	r, dir, id, rt := newTestRotator(t, client, device)

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Exactly one HTTP call carrying a valid 44-char base64 public key.
	if got := client.getCalls(); got != 1 {
		t.Fatalf("HTTP calls = %d, want 1", got)
	}
	reqs := client.getRequests()
	if n := len(reqs[0].NewPublicKey); n != 44 {
		t.Errorf("NewPublicKey length = %d, want 44", n)
	}
	pub, err := base64.StdEncoding.DecodeString(reqs[0].NewPublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey is not base64: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("decoded public key = %d bytes, want 32", len(pub))
	}

	// The committed private key is the freshly staged one, and its public half
	// matches the key that was submitted.
	if bytes.Equal(id.PrivateKey, bytes.Repeat([]byte{0x11}, 32)) {
		t.Error("in-memory PrivateKey was not swapped")
	}
	derived, err := curve25519.X25519(id.PrivateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if base64.StdEncoding.EncodeToString(derived) != reqs[0].NewPublicKey {
		t.Error("committed private key does not match the submitted public key")
	}

	// The receipt is recorded in memory and on disk.
	want := registration.RotationReceipt{RotationID: "rot-1", KID: "kid-1", WrapKeyVersion: 3}
	if id.LastRotation == nil || *id.LastRotation != want {
		t.Errorf("LastRotation = %+v, want %+v", id.LastRotation, want)
	}
	loaded, err := registration.LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if !bytes.Equal(loaded.PrivateKey, id.PrivateKey) {
		t.Error("private_key file does not hold the new key")
	}
	if loaded.LastRotation == nil || *loaded.LastRotation != want {
		t.Errorf("reloaded LastRotation = %+v, want %+v", loaded.LastRotation, want)
	}

	// The device received the same private key and a reconcile fired once.
	keys := device.getKeys()
	if len(keys) != 1 || !bytes.Equal(keys[0], id.PrivateKey) {
		t.Errorf("device keys = %v, want the committed private key once", keys)
	}
	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}

	// The staging file is gone.
	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present after commit")
	}
}

func TestKeyRotator_Rotate_ReusesStagedKey(t *testing.T) {
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	r, dir, _, _ := newTestRotator(t, client, &fakeDeviceUpdater{})

	kp, err := registration.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := registration.SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	reqs := client.getRequests()
	if len(reqs) != 1 {
		t.Fatalf("HTTP calls = %d, want 1", len(reqs))
	}
	if reqs[0].NewPublicKey != kp.EncodePublicKey() {
		t.Errorf("submitted NewPublicKey = %q, want the staged key %q", reqs[0].NewPublicKey, kp.EncodePublicKey())
	}
}

func TestKeyRotator_Rotate_UnreadableStagingFileSelfHeals(t *testing.T) {
	// A corrupt staging file must not wedge rotation: without the self-heal
	// every Rotate returns the decode error before touching the network and the
	// node never rotates again.
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	r, dir, id, _ := newTestRotator(t, client, &fakeDeviceUpdater{})

	if err := os.WriteFile(filepath.Join(dir, "rotation_pending_key"), []byte("not base64!!"), 0600); err != nil {
		t.Fatalf("write corrupt staging file: %v", err)
	}

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if got := client.getCalls(); got != 1 {
		t.Fatalf("HTTP calls = %d, want 1 (a fresh key must be staged and submitted)", got)
	}
	if bytes.Equal(id.PrivateKey, bytes.Repeat([]byte{0x11}, 32)) {
		t.Error("in-memory PrivateKey was not swapped")
	}
	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present after commit")
	}
}

func TestKeyRotator_Rotate_CooldownSkipsRepeatSignals(t *testing.T) {
	// The control plane repeats rotate_keys until it observes the new key, so a
	// lagging observation must not rekey the device on every heartbeat.
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	device := &fakeDeviceUpdater{}
	r, _, _, rt := newTestRotator(t, client, device)

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("second Rotate: %v", err)
	}

	if got := client.getCalls(); got != 1 {
		t.Errorf("HTTP calls = %d, want 1 (the repeat signal is within the cooldown)", got)
	}
	if got := len(device.getKeys()); got != 1 {
		t.Errorf("device installs = %d, want 1", got)
	}
	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}

	// Once the cooldown has elapsed, a signal rotates again.
	r.minInterval = 0
	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("third Rotate: %v", err)
	}
	if got := client.getCalls(); got != 2 {
		t.Errorf("HTTP calls = %d, want 2 after the cooldown elapsed", got)
	}
}

func TestKeyRotator_RotateNow_BypassesCooldown(t *testing.T) {
	// The SSE rotate_keys event arrives once per rotation decision and is
	// never repeated, so unlike the heartbeat flag it must start a fresh
	// rotation even within the cooldown window.
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	device := &fakeDeviceUpdater{}
	r, dir, _, rt := newTestRotator(t, client, device)
	r.lastCommit = time.Now()

	if err := r.RotateNow(context.Background()); err != nil {
		t.Fatalf("RotateNow: %v", err)
	}

	if got := client.getCalls(); got != 1 {
		t.Errorf("HTTP calls = %d, want 1 (RotateNow must bypass the cooldown)", got)
	}
	if got := len(device.getKeys()); got != 1 {
		t.Errorf("device installs = %d, want 1", got)
	}
	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}
	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present after commit")
	}
}

func TestKeyRotator_Rotate_CooldownStillResubmitsStagedKey(t *testing.T) {
	// The cooldown gates starting a new rotation, never the resubmit of a key
	// the control plane may already have accepted.
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	r, dir, _, _ := newTestRotator(t, client, &fakeDeviceUpdater{})
	r.lastCommit = time.Now()

	kp, err := registration.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := registration.SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	reqs := client.getRequests()
	if len(reqs) != 1 || reqs[0].NewPublicKey != kp.EncodePublicKey() {
		t.Fatalf("submitted requests = %+v, want the staged key %q resubmitted", reqs, kp.EncodePublicKey())
	}
}

func TestKeyRotator_Rotate_StageWriteError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on windows")
	}
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{}}
	r, dir, _, rt := newTestRotator(t, client, &fakeDeviceUpdater{})

	// Make the data dir unwritable so SavePendingKey fails before any HTTP call.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	if err := r.Rotate(context.Background()); err == nil {
		t.Fatal("Rotate on unwritable dir: expected error, got nil")
	}

	if got := client.getCalls(); got != 0 {
		t.Errorf("HTTP calls = %d, want 0 (must not submit after a stage failure)", got)
	}
	if got := rt.getCalls(); got != 0 {
		t.Errorf("TriggerReconcile calls = %d, want 0", got)
	}
}

func TestKeyRotator_Rotate_UnchangedCommitsWithoutReceipt(t *testing.T) {
	client := &fakeRotateClient{err: &api.APIError{StatusCode: 422, Code: "keys_rotate_public_key_unchanged"}}
	device := &fakeDeviceUpdater{}
	r, dir, id, rt := newTestRotator(t, client, device)

	// Seed and persist a prior receipt that the nil-receipt commit must preserve.
	prior := &registration.RotationReceipt{RotationID: "rot-prior", KID: "kid-prior", WrapKeyVersion: 1}
	id.LastRotation = prior
	if err := registration.SaveIdentity(dir, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	kp, err := registration.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := registration.SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The staged key was committed even though the server reported it unchanged.
	if !bytes.Equal(id.PrivateKey, kp.PrivateKey) {
		t.Error("PrivateKey was not swapped to the staged key")
	}
	// The prior receipt survives in memory and on disk.
	if id.LastRotation == nil || *id.LastRotation != *prior {
		t.Errorf("in-memory LastRotation = %+v, want prior %+v", id.LastRotation, prior)
	}
	loaded, err := registration.LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.LastRotation == nil || *loaded.LastRotation != *prior {
		t.Errorf("reloaded LastRotation = %+v, want prior %+v", loaded.LastRotation, prior)
	}
	if !bytes.Equal(loaded.PrivateKey, kp.PrivateKey) {
		t.Error("private_key file does not hold the staged key")
	}

	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}
	if keys := device.getKeys(); len(keys) != 1 || !bytes.Equal(keys[0], kp.PrivateKey) {
		t.Errorf("device keys = %v, want the staged key once", keys)
	}
	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present after commit")
	}
}

func TestKeyRotator_Rotate_NoPendingRotationDiscards(t *testing.T) {
	client := &fakeRotateClient{err: &api.APIError{StatusCode: 409, Code: "keys_rotate_no_pending_rotation"}}
	device := &fakeDeviceUpdater{}
	r, dir, id, rt := newTestRotator(t, client, device)

	origPriv := append([]byte(nil), id.PrivateKey...)
	origFile := readPrivateKeyFile(t, dir)

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present, want discarded")
	}
	if got := readPrivateKeyFile(t, dir); got != origFile {
		t.Error("private_key file changed, want unchanged")
	}
	if !bytes.Equal(id.PrivateKey, origPriv) {
		t.Error("in-memory PrivateKey changed, want unchanged")
	}
	if len(device.getKeys()) != 0 {
		t.Error("device was updated, want no call")
	}
	if got := rt.getCalls(); got != 0 {
		t.Errorf("TriggerReconcile calls = %d, want 0", got)
	}
}

func TestKeyRotator_Rotate_TerminalRejectionDiscardsAndErrors(t *testing.T) {
	// Every documented permanent rejection must drop the staged key, so neither
	// RecoverPending nor a later signal replays a key the server keeps refusing.
	cases := []struct {
		name string
		err  *api.APIError
	}{
		{"invalid public key", &api.APIError{StatusCode: 422, Code: "keys_rotate_public_key_invalid"}},
		{"peer not found", &api.APIError{StatusCode: 404, Code: "keys_rotate_peer_not_found"}},
		{"malformed request", &api.APIError{StatusCode: 400, Code: "malformed_keys_rotate_request"}},
		{"rebac denial", &api.APIError{StatusCode: 403}},
		{"body too large", &api.APIError{StatusCode: 413, Code: "keys_rotate_body_too_large"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeRotateClient{err: tc.err}
			device := &fakeDeviceUpdater{}
			r, dir, id, rt := newTestRotator(t, client, device)

			origPriv := append([]byte(nil), id.PrivateKey...)

			err := r.Rotate(context.Background())
			if err == nil {
				t.Fatal("Rotate: expected error, got nil")
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("Rotate error = %v, want %v", err, tc.err)
			}
			if pendingExists(t, dir) {
				t.Error("rotation_pending_key still present, want discarded")
			}
			if !bytes.Equal(id.PrivateKey, origPriv) {
				t.Error("in-memory PrivateKey changed, want unchanged")
			}
			if len(device.getKeys()) != 0 {
				t.Error("device was updated, want no call")
			}
			if got := rt.getCalls(); got != 0 {
				t.Errorf("TriggerReconcile calls = %d, want 0", got)
			}
		})
	}
}

func TestKeyRotator_Rotate_IncompleteReceiptKeepsStaging(t *testing.T) {
	// A control plane on the pre-v1 contract answers 200 with a body that
	// decodes into a zero receipt.
	cases := []struct {
		name string
		resp *api.KeyRotateResponse
	}{
		{"empty receipt", &api.KeyRotateResponse{}},
		{"missing kid", &api.KeyRotateResponse{RotationID: "rot-1"}},
		{"missing rotation id", &api.KeyRotateResponse{KID: "kid-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeRotateClient{resp: tc.resp}
			device := &fakeDeviceUpdater{}
			r, dir, id, rt := newTestRotator(t, client, device)

			origPriv := append([]byte(nil), id.PrivateKey...)
			origFile := readPrivateKeyFile(t, dir)

			if err := r.Rotate(context.Background()); err == nil {
				t.Fatal("Rotate: expected an error for an incomplete receipt, got nil")
			}

			// Nothing was committed and the staged key survives for a resubmit.
			if !pendingExists(t, dir) {
				t.Error("rotation_pending_key gone, want the staged key to survive")
			}
			if got := readPrivateKeyFile(t, dir); got != origFile {
				t.Error("private_key file changed, want unchanged")
			}
			if !bytes.Equal(id.PrivateKey, origPriv) {
				t.Error("in-memory PrivateKey changed, want unchanged")
			}
			if id.LastRotation != nil {
				t.Errorf("LastRotation = %+v, want no receipt persisted", id.LastRotation)
			}
			if len(device.getKeys()) != 0 {
				t.Error("device was updated, want no call")
			}
			if got := rt.getCalls(); got != 0 {
				t.Errorf("TriggerReconcile calls = %d, want 0", got)
			}
		})
	}
}

func TestKeyRotator_Rotate_ServerErrorKeepsStaging(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"api 5xx", &api.APIError{StatusCode: 500, Code: "internal"}},
		{"transport", &url.Error{Op: "Post", URL: "https://cp.example/v1/keys/rotate", Err: errors.New("connection refused")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeRotateClient{err: tc.err}
			device := &fakeDeviceUpdater{}
			r, dir, id, rt := newTestRotator(t, client, device)

			kp, err := registration.GenerateKeypair()
			if err != nil {
				t.Fatalf("GenerateKeypair: %v", err)
			}
			if err := registration.SavePendingKey(dir, kp); err != nil {
				t.Fatalf("SavePendingKey: %v", err)
			}
			origPriv := append([]byte(nil), id.PrivateKey...)

			err = r.Rotate(context.Background())
			if err == nil {
				t.Fatal("Rotate: expected error, got nil")
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("Rotate error = %v, want %v", err, tc.err)
			}

			// The staged key survives so a resubmit can recover.
			if !pendingExists(t, dir) {
				t.Fatal("rotation_pending_key gone, want the staged key to survive")
			}
			staged, err := registration.LoadPendingKey(dir)
			if err != nil {
				t.Fatalf("LoadPendingKey: %v", err)
			}
			if staged == nil || !bytes.Equal(staged.PrivateKey, kp.PrivateKey) {
				t.Error("staged key changed, want the same key")
			}
			if !bytes.Equal(id.PrivateKey, origPriv) {
				t.Error("in-memory PrivateKey changed, want unchanged")
			}
			if len(device.getKeys()) != 0 {
				t.Error("device was updated, want no call")
			}
			if got := rt.getCalls(); got != 0 {
				t.Errorf("TriggerReconcile calls = %d, want 0", got)
			}
		})
	}
}

func TestKeyRotator_Rotate_SingleFlight(t *testing.T) {
	client := &fakeRotateClient{
		resp:    &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"},
		gate:    make(chan struct{}),
		entered: make(chan struct{}),
	}
	r, _, _, _ := newTestRotator(t, client, &fakeDeviceUpdater{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- r.Rotate(context.Background())
	}()

	// Block until the first Rotate is inside the client call (holding the lock).
	<-client.entered

	// A concurrent Rotate must bail out immediately without a second HTTP call.
	if err := r.Rotate(context.Background()); err != nil {
		t.Errorf("concurrent Rotate = %v, want nil", err)
	}

	close(client.gate) // release the in-flight call
	if err := <-errCh; err != nil {
		t.Errorf("first Rotate = %v, want nil", err)
	}

	if got := client.getCalls(); got != 1 {
		t.Errorf("HTTP calls = %d, want exactly 1", got)
	}
}

func TestKeyRotator_Rotate_NilDevice(t *testing.T) {
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	// Pass a genuinely nil DeviceKeyUpdater (not a typed nil).
	r, dir, id, rt := newTestRotator(t, client, nil)

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if id.LastRotation == nil || id.LastRotation.RotationID != "rot-1" {
		t.Errorf("LastRotation = %+v, want rot-1 committed", id.LastRotation)
	}
	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}
	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present after commit")
	}
}

func TestKeyRotator_Rotate_DeviceErrorStillCommits(t *testing.T) {
	devErr := errors.New("device down")
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	device := &fakeDeviceUpdater{err: devErr}
	r, dir, id, rt := newTestRotator(t, client, device)
	r.deviceDelay = time.Millisecond

	err := r.Rotate(context.Background())
	if !errors.Is(err, devErr) {
		t.Fatalf("Rotate = %v, want the device error %v", err, devErr)
	}

	// A permanent device failure is retried a bounded number of times.
	if got := len(device.getKeys()); got != deviceInstallAttempts {
		t.Errorf("device install attempts = %d, want %d", got, deviceInstallAttempts)
	}

	// The durable identity committed regardless of the device failure.
	if id.LastRotation == nil || id.LastRotation.RotationID != "rot-1" {
		t.Errorf("LastRotation = %+v, want rot-1 committed", id.LastRotation)
	}
	loaded, err := registration.LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if !bytes.Equal(loaded.PrivateKey, id.PrivateKey) {
		t.Error("private_key file was not committed")
	}
	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}
	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present after commit")
	}
}

func TestKeyRotator_Rotate_DeviceErrorRetriesUntilInstalled(t *testing.T) {
	// A transient device failure must not strand the node: the durable key is
	// already swapped and the control plane has published its public half, so
	// the install has to keep trying within the same rotation.
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	device := &fakeDeviceUpdater{err: errors.New("device busy"), failFor: deviceInstallAttempts - 1}
	r, dir, id, rt := newTestRotator(t, client, device)
	r.deviceDelay = time.Millisecond

	if err := r.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate = %v, want nil once the device accepts the key", err)
	}

	keys := device.getKeys()
	if len(keys) != deviceInstallAttempts {
		t.Fatalf("device install attempts = %d, want %d", len(keys), deviceInstallAttempts)
	}
	if !bytes.Equal(keys[len(keys)-1], id.PrivateKey) {
		t.Error("the installed key is not the committed private key")
	}
	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}
	if pendingExists(t, dir) {
		t.Error("rotation_pending_key still present after commit")
	}
}

// ---------------------------------------------------------------------------
// RecoverPending tests
// ---------------------------------------------------------------------------

// startRecovery runs RecoverPending in the background and returns a stop
// function that cancels it and waits for the goroutine to finish.
func startRecovery(t *testing.T, r *KeyRotator) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RecoverPending(ctx)
	}()
	return func() {
		t.Helper()
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("RecoverPending did not return after context cancellation")
		}
	}
}

func TestKeyRotator_RecoverPending_NoStagedFile(t *testing.T) {
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{}}
	r, _, _, _ := newTestRotator(t, client, &fakeDeviceUpdater{})
	r.recoverInitial = time.Millisecond
	r.recoverMax = time.Millisecond

	stop := startRecovery(t, r)
	// Let the sweep run many times over at its (millisecond) idle cadence.
	time.Sleep(50 * time.Millisecond)
	stop()

	if got := client.getCalls(); got != 0 {
		t.Errorf("HTTP calls = %d, want 0 when nothing is staged", got)
	}
}

func TestKeyRotator_RecoverPending_ResubmitsStagedKey(t *testing.T) {
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	r, dir, id, _ := newTestRotator(t, client, &fakeDeviceUpdater{})
	r.recoverInitial = time.Millisecond
	r.recoverMax = time.Millisecond

	kp, err := registration.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := registration.SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	stop := startRecovery(t, r)
	waitFor(t, 2*time.Second, func() bool { return !pendingExists(t, dir) })
	// A committed rotation stages nothing new, so the sweep stays quiet.
	time.Sleep(20 * time.Millisecond)
	stop()

	if got := client.getCalls(); got != 1 {
		t.Errorf("HTTP calls = %d, want 1", got)
	}
	if !bytes.Equal(id.PrivateKey, kp.PrivateKey) {
		t.Error("commit did not happen during recovery")
	}
}

func TestKeyRotator_RecoverPending_ResubmitsAKeyStagedAfterStart(t *testing.T) {
	// A submit whose response is lost leaves a staged key behind while the
	// control plane has already rotated and therefore never signals again. The
	// sweep is the only driver left, so it must pick up a key staged long after
	// startup instead of having returned when the data dir was clean.
	client := &fakeRotateClient{resp: &api.KeyRotateResponse{RotationID: "rot-1", KID: "kid-1"}}
	r, dir, id, _ := newTestRotator(t, client, &fakeDeviceUpdater{})
	r.recoverInitial = time.Millisecond
	r.recoverMax = time.Millisecond

	stop := startRecovery(t, r)

	// Nothing is staged yet: the sweep must still be running when one appears.
	time.Sleep(20 * time.Millisecond)
	kp, err := registration.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := registration.SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	waitFor(t, 2*time.Second, func() bool { return !pendingExists(t, dir) })
	stop()

	reqs := client.getRequests()
	if len(reqs) != 1 || reqs[0].NewPublicKey != kp.EncodePublicKey() {
		t.Fatalf("submitted requests = %+v, want the staged key %q resubmitted once", reqs, kp.EncodePublicKey())
	}
	if !bytes.Equal(id.PrivateKey, kp.PrivateKey) {
		t.Error("the late-staged rotation was not committed")
	}
}

func TestKeyRotator_RecoverPending_BackoffAndCancel(t *testing.T) {
	client := &fakeRotateClient{err: &api.APIError{StatusCode: 503, Code: "unavailable"}}
	r, dir, _, _ := newTestRotator(t, client, &fakeDeviceUpdater{})
	r.recoverInitial = 10 * time.Millisecond
	r.recoverMax = 40 * time.Millisecond

	kp, err := registration.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := registration.SavePendingKey(dir, kp); err != nil {
		t.Fatalf("SavePendingKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RecoverPending(ctx)
	}()

	// A persistent 5xx keeps the rotation pending, so the resubmit retries.
	waitFor(t, 2*time.Second, func() bool { return client.getCalls() >= 3 })
	before := client.getCalls()
	// Retries keep coming (spaced by the backoff), so the count grows.
	waitFor(t, 2*time.Second, func() bool { return client.getCalls() > before })

	cancel()
	select {
	case <-done:
		// RecoverPending returned on cancellation.
	case <-time.After(2 * time.Second):
		t.Fatal("RecoverPending did not return after context cancellation")
	}

	// The staged key is untouched — every retry kept it for a later attempt.
	if !pendingExists(t, dir) {
		t.Error("rotation_pending_key gone, want it to survive a persistent 5xx")
	}
}
