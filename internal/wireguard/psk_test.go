package wireguard

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

const (
	testPSKSelf  = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"
	testPSKPeerA = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1"
	testPSKPeerB = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2"

	// Epochs in the contract's fixed-width form, oldest first.
	testEpochOld  = "2025-12-01T00:00:00.000000000Z|2025-12-01T00:00:01.000000000Z"
	testEpoch     = "2026-01-01T00:00:00.000000000Z|2026-01-01T00:00:01.000000000Z"
	testEpochNext = "2026-02-01T00:00:00.000000000Z|2026-01-01T00:00:01.000000000Z"
)

var testPSKNSK = bytes.Repeat([]byte{0x11}, 32)

// testPSKKey returns a distinct 32-byte edge PSK for b.
func testPSKKey(b byte) []byte { return bytes.Repeat([]byte{b}, edgePSKSize) }

// sealTestPSK seals plaintext under nsk with aad the way the control plane
// seals an edge-PSK envelope: a random 12-byte nonce, then the GCM output.
func sealTestPSK(t *testing.T, nsk, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(nsk)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad)
}

// testEnvelope returns the envelope the control plane serves testPSKSelf for
// its edge to peer: key sealed under testPSKNSK for epoch.
func testEnvelope(t *testing.T, key []byte, peer, epoch string) *api.EdgePSKEnvelope {
	t.Helper()
	return &api.EdgePSKEnvelope{
		Data:  sealTestPSK(t, testPSKNSK, key, edgePSKAAD(testPSKSelf, peer, epoch)),
		KID:   "nsk-kid-1",
		Epoch: epoch,
	}
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

func TestEdgePSKAAD(t *testing.T) {
	got := string(edgePSKAAD(" 0190A8B8-A0C0-7A0A-8A0A-A0A0A0A0A0A3 ", "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1", "e|f"))
	const want = "plexsphere/mesh/edge-psk/v1|0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3|0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1|e|f"
	if got != want {
		t.Errorf("edgePSKAAD = %q, want %q", got, want)
	}
}

func TestOpenEdgePSK_Recovers(t *testing.T) {
	key := testPSKKey(0x42)
	got, err := openEdgePSK(testPSKNSK, testEnvelope(t, key, testPSKPeerA, testEpoch), testPSKSelf, testPSKPeerA)
	if err != nil {
		t.Fatalf("openEdgePSK: %v", err)
	}
	if !bytes.Equal(got[:], key) {
		t.Error("openEdgePSK did not recover the sealed key")
	}
}

func TestOpenEdgePSK_AuthenticationFailed(t *testing.T) {
	key := testPSKKey(0x42)
	flipped := testEnvelope(t, key, testPSKPeerA, testEpoch)
	flipped.Data[20] ^= 0x01

	tests := []struct {
		name       string
		nsk        []byte
		env        *api.EdgePSKEnvelope
		self, peer string
	}{
		{"wrong nsk", bytes.Repeat([]byte{0x12}, 32), testEnvelope(t, key, testPSKPeerA, testEpoch), testPSKSelf, testPSKPeerA},
		{"swapped self and peer", testPSKNSK, testEnvelope(t, key, testPSKPeerA, testEpoch), testPSKPeerA, testPSKSelf},
		{"another epoch", testPSKNSK, &api.EdgePSKEnvelope{
			Data:  testEnvelope(t, key, testPSKPeerA, testEpoch).Data,
			KID:   "nsk-kid-1",
			Epoch: testEpochNext,
		}, testPSKSelf, testPSKPeerA},
		{"flipped ciphertext byte", testPSKNSK, flipped, testPSKSelf, testPSKPeerA},
		{"secret body sealed with no aad", testPSKNSK, &api.EdgePSKEnvelope{
			Data:  sealTestPSK(t, testPSKNSK, key, nil),
			KID:   "nsk-kid-1",
			Epoch: testEpoch,
		}, testPSKSelf, testPSKPeerA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := openEdgePSK(tt.nsk, tt.env, tt.self, tt.peer)
			if err == nil || err.Error() != "wireguard: open edge psk: authentication failed" {
				t.Errorf("err = %v, want authentication failed", err)
			}
		})
	}
}

func TestOpenEdgePSK_Lengths(t *testing.T) {
	env := testEnvelope(t, testPSKKey(0x42), testPSKPeerA, testEpoch)
	_, err := openEdgePSK(testPSKNSK[:31], env, testPSKSelf, testPSKPeerA)
	if err == nil || err.Error() != "wireguard: open edge psk: nsk must be 32 bytes" {
		t.Errorf("31-byte nsk: err = %v, want nsk must be 32 bytes", err)
	}

	short := &api.EdgePSKEnvelope{
		Data:  sealTestPSK(t, testPSKNSK, testPSKKey(0x42)[:31], edgePSKAAD(testPSKSelf, testPSKPeerA, testEpoch)),
		KID:   "nsk-kid-1",
		Epoch: testEpoch,
	}
	_, err = openEdgePSK(testPSKNSK, short, testPSKSelf, testPSKPeerA)
	if err == nil || err.Error() != "wireguard: open edge psk: plaintext is 31 bytes, want 32" {
		t.Errorf("31-byte plaintext: err = %v, want plaintext is 31 bytes, want 32", err)
	}
	assertNoKeyMaterial(t, err.Error(), testPSKNSK, testPSKKey(0x42), env.Data, short.Data)
}

// ---------------------------------------------------------------------------
// Edge PSK store
// ---------------------------------------------------------------------------

// fakeEdgePSKFetcher answers each fetch through respond and records the peer
// it was asked for. during, when set, runs while a fetch is in flight.
type fakeEdgePSKFetcher struct {
	mu      sync.Mutex
	calls   []string
	served  [][]byte // every envelope body respond returned
	respond func(peerNodeID string) (*api.EdgePSKEnvelope, error)
	during  func(peerNodeID string)
}

func (f *fakeEdgePSKFetcher) FetchEdgePSK(_ context.Context, nodeID, peerNodeID string) (*api.EdgePSKEnvelope, error) {
	f.mu.Lock()
	f.calls = append(f.calls, peerNodeID)
	respond, during := f.respond, f.during
	f.mu.Unlock()
	if nodeID != testPSKSelf {
		return nil, fmt.Errorf("fetch for node %q, want %q", nodeID, testPSKSelf)
	}
	if during != nil {
		during(peerNodeID)
	}
	env, err := respond(peerNodeID)
	if env != nil {
		f.mu.Lock()
		f.served = append(f.served, bytes.Clone(env.Data))
		f.mu.Unlock()
	}
	return env, err
}

func (f *fakeEdgePSKFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeEdgePSKFetcher) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type installCall struct {
	nodeID, publicKey string
	psk               []byte
}

// fakeEdgePSKInstaller records every SetPeerPSK call and fails it with err.
type fakeEdgePSKInstaller struct {
	mu    sync.Mutex
	calls []installCall
	err   error
}

func (f *fakeEdgePSKInstaller) SetPeerPSK(peerNodeID, publicKey string, psk []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, installCall{nodeID: peerNodeID, publicKey: publicKey, psk: bytes.Clone(psk)})
	return f.err
}

func (f *fakeEdgePSKInstaller) callList() []installCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]installCall(nil), f.calls...)
}

// pskStoreFixture is an EdgePSKs over fakes, with a clock the test moves and a
// log it reads.
type pskStoreFixture struct {
	store     *EdgePSKs
	fetcher   *fakeEdgePSKFetcher
	installer *fakeEdgePSKInstaller
	logs      *bytes.Buffer
	clock     time.Time
}

func newPSKStoreFixture(t *testing.T) *pskStoreFixture {
	t.Helper()
	f := &pskStoreFixture{
		fetcher:   &fakeEdgePSKFetcher{},
		installer: &fakeEdgePSKInstaller{},
		logs:      &bytes.Buffer{},
		clock:     time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
	}
	f.store = NewEdgePSKs(f.fetcher, testPSKSelf, testPSKNSK, f.installer, slogTextLogger(f.logs))
	f.store.now = func() time.Time { return f.clock }
	// Whatever the test did, its log must not carry the NSK, a served
	// envelope, or a key the store opened: every opened key reaches the
	// installer, and every envelope passes through the fetcher.
	t.Cleanup(func() {
		secrets := [][]byte{testPSKNSK}
		for _, call := range f.installer.callList() {
			secrets = append(secrets, call.psk)
		}
		f.fetcher.mu.Lock()
		secrets = append(secrets, f.fetcher.served...)
		f.fetcher.mu.Unlock()
		assertNoKeyMaterial(t, f.logs.String(), secrets...)
	})
	return f
}

// serve makes every fetch answer key sealed for epoch.
func (f *pskStoreFixture) serve(t *testing.T, keys map[string][]byte, epoch string) {
	t.Helper()
	f.fetcher.mu.Lock()
	defer f.fetcher.mu.Unlock()
	f.fetcher.respond = func(peer string) (*api.EdgePSKEnvelope, error) {
		key, ok := keys[peer]
		if !ok {
			return nil, &api.APIError{StatusCode: 404, Code: "peer_not_found"}
		}
		return testEnvelope(t, key, peer, epoch), nil
	}
}

// fail makes every fetch answer err.
func (f *pskStoreFixture) fail(err error) {
	f.fetcher.mu.Lock()
	defer f.fetcher.mu.Unlock()
	f.fetcher.respond = func(string) (*api.EdgePSKEnvelope, error) { return nil, err }
}

func pskPeer(nodeID, publicKey string) api.SnapshotPeer {
	return api.SnapshotPeer{NodeID: nodeID, MeshIP: "10.99.0.2", PublicKey: publicKey}
}

// assertNoKeyMaterial fails when out holds any of secrets raw, quoted the way
// slog's text handler writes a []byte or a non-UTF-8 string, in hex, in base64
// or in Go's %v and %x forms.
func assertNoKeyMaterial(t *testing.T, out string, secrets ...[]byte) {
	t.Helper()
	for _, secret := range secrets {
		quoted := strconv.Quote(string(secret))
		for _, form := range []string{
			string(secret),
			quoted[1 : len(quoted)-1],
			hex.EncodeToString(secret),
			base64.StdEncoding.EncodeToString(secret),
			fmt.Sprintf("%v", secret),
			fmt.Sprintf("%x", secret),
		} {
			if strings.Contains(out, form) {
				t.Errorf("output contains key material (%d bytes):\n%s", len(secret), out)
				return
			}
		}
	}
}

func TestEdgePSKs_SyncFetchesAndInstalls(t *testing.T) {
	f := newPSKStoreFixture(t)
	keys := map[string][]byte{testPSKPeerA: testPSKKey(0xa1), testPSKPeerB: testPSKKey(0xb2)}
	f.serve(t, keys, testEpoch)

	// Out of order on purpose: fetches go in node-ID order.
	f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerB, "pk-b"), pskPeer(testPSKPeerA, "pk-a")})

	if got := f.fetcher.callList(); len(got) != 2 || got[0] != testPSKPeerA || got[1] != testPSKPeerB {
		t.Fatalf("fetches = %v, want [%s %s]", got, testPSKPeerA, testPSKPeerB)
	}
	installs := f.installer.callList()
	if len(installs) != 2 {
		t.Fatalf("installs = %d, want 2", len(installs))
	}
	for i, want := range []installCall{
		{nodeID: testPSKPeerA, publicKey: "pk-a", psk: keys[testPSKPeerA]},
		{nodeID: testPSKPeerB, publicKey: "pk-b", psk: keys[testPSKPeerB]},
	} {
		got := installs[i]
		if got.nodeID != want.nodeID || got.publicKey != want.publicKey || !bytes.Equal(got.psk, want.psk) {
			t.Errorf("install %d = {%s %s}, want {%s %s} with the peer's key", i, got.nodeID, got.publicKey, want.nodeID, want.publicKey)
		}
	}

	key, ok := f.store.Lookup(testPSKPeerA, "pk-a")
	if !ok || !bytes.Equal(key, keys[testPSKPeerA]) {
		t.Errorf("Lookup(peer a, pk-a) = (%v, %v), want the key", key != nil, ok)
	}
	if _, ok := f.store.Lookup(testPSKPeerA, "pk-other"); ok {
		t.Error("Lookup returned a key for another public key")
	}
	key[0] ^= 0xff
	if again, _ := f.store.Lookup(testPSKPeerA, "pk-a"); !bytes.Equal(again, keys[testPSKPeerA]) {
		t.Error("Lookup returned the stored key itself, not a copy")
	}
}

func TestEdgePSKs_RefetchRule(t *testing.T) {
	f := newPSKStoreFixture(t)
	oldKey := testPSKKey(0xa1)
	f.serve(t, map[string][]byte{testPSKPeerA: oldKey, testPSKPeerB: testPSKKey(0xb2)}, testEpoch)
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")}
	f.store.Sync(context.Background(), peers)

	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 2 {
		t.Fatalf("fetches after an unchanged Sync = %d, want 2", n)
	}

	rotated := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a2"), pskPeer(testPSKPeerB, "pk-b")}
	f.store.Sync(context.Background(), rotated)
	if got := f.fetcher.callList(); len(got) != 3 || got[2] != testPSKPeerA {
		t.Fatalf("fetches after peer a's key change = %v, want a third fetch for peer a", got)
	}
	installs := f.installer.callList()
	if last := installs[len(installs)-1]; len(installs) != 3 || last.nodeID != testPSKPeerA || last.publicKey != "pk-a2" {
		t.Fatalf("installs after peer a's key change = %d (last %s/%s), want a third one for peer a's new key", len(installs), last.nodeID, last.publicKey)
	}

	// This node rotated: every PSK goes stale, and the old key stays in use
	// until its replacement arrives.
	f.store.InvalidateAll()
	if key, ok := f.store.Lookup(testPSKPeerA, "pk-a2"); !ok || !bytes.Equal(key, oldKey) {
		t.Error("Lookup after InvalidateAll did not return the stale key")
	}
	newKey := testPSKKey(0xa3)
	f.serve(t, map[string][]byte{testPSKPeerA: newKey, testPSKPeerB: testPSKKey(0xb4)}, testEpochNext)
	f.store.Sync(context.Background(), rotated)
	if got := f.fetcher.callList(); len(got) != 5 {
		t.Fatalf("fetches after InvalidateAll = %v, want both peers again", got)
	}
	if key, _ := f.store.Lookup(testPSKPeerA, "pk-a2"); !bytes.Equal(key, newKey) {
		t.Error("Lookup after the re-fetch did not return the new key")
	}
	// The peer set did not change, so the reconcile handler does not run: the
	// re-fetched PSKs reach the device only through the installer.
	installs = f.installer.callList()
	if len(installs) != 5 {
		t.Fatalf("installs after InvalidateAll = %d, want both re-fetched PSKs installed", len(installs))
	}
	for i, want := range []installCall{
		{nodeID: testPSKPeerA, publicKey: "pk-a2", psk: newKey},
		{nodeID: testPSKPeerB, publicKey: "pk-b", psk: testPSKKey(0xb4)},
	} {
		got := installs[3+i]
		if got.nodeID != want.nodeID || got.publicKey != want.publicKey || !bytes.Equal(got.psk, want.psk) {
			t.Errorf("install after InvalidateAll %d = %s/%s, want %s/%s with the re-fetched key", i, got.nodeID, got.publicKey, want.nodeID, want.publicKey)
		}
	}
}

func TestEdgePSKs_InvalidateDuringFetch(t *testing.T) {
	f := newPSKStoreFixture(t)
	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1)}, testEpoch)
	var once sync.Once
	f.fetcher.during = func(string) { once.Do(f.store.InvalidateAll) }
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")}

	f.store.Sync(context.Background(), peers)
	f.store.Sync(context.Background(), peers)

	if n := f.fetcher.callCount(); n != 2 {
		t.Errorf("fetches = %d, want 2: a PSK fetched while this node rotated must be fetched again", n)
	}
}

func TestEdgePSKs_PrunesPeers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		peers []api.SnapshotPeer
	}{
		{"nil peers", nil},
		{"empty peers", []api.SnapshotPeer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPSKStoreFixture(t)
			f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1), testPSKPeerB: testPSKKey(0xb2)}, testEpoch)
			f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")})

			f.store.Sync(context.Background(), tc.peers)

			if n := f.fetcher.callCount(); n != 2 {
				t.Errorf("fetches = %d, want 2 (none for %s)", n, tc.name)
			}
			for _, id := range []string{testPSKPeerA, testPSKPeerB} {
				if _, ok := f.store.Lookup(id, map[string]string{testPSKPeerA: "pk-a", testPSKPeerB: "pk-b"}[id]); ok {
					t.Errorf("Lookup(%s) still holds a key after the peer left", id)
				}
			}
		})
	}

	t.Run("one peer leaves while another stays", func(t *testing.T) {
		f := newPSKStoreFixture(t)
		f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1), testPSKPeerB: testPSKKey(0xb2)}, testEpoch)
		f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")})

		f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerB, "pk-b")})
		if n := f.fetcher.callCount(); n != 2 {
			t.Errorf("fetches = %d, want none for the peer that stayed", n-2)
		}
		if _, ok := f.store.Lookup(testPSKPeerA, "pk-a"); ok {
			t.Error("the peer that left still holds a key")
		}
		if _, ok := f.store.Lookup(testPSKPeerB, "pk-b"); !ok {
			t.Error("the peer that stayed lost its key")
		}

		// Its floor went with it: when it rejoins, an older epoch is accepted.
		older := testPSKKey(0xa0)
		f.serve(t, map[string][]byte{testPSKPeerA: older, testPSKPeerB: testPSKKey(0xb2)}, testEpochOld)
		f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")})
		if key, ok := f.store.Lookup(testPSKPeerA, "pk-a"); !ok || !bytes.Equal(key, older) {
			t.Error("an older epoch was refused for a rejoining peer whose floor should have been forgotten")
		}
	})

	t.Run("a peer that left loses its floor", func(t *testing.T) {
		f := newPSKStoreFixture(t)
		f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1)}, testEpoch)
		f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")})
		f.store.Sync(context.Background(), []api.SnapshotPeer{})

		older := testPSKKey(0xa0)
		f.serve(t, map[string][]byte{testPSKPeerA: older}, testEpochOld)
		f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")})
		if key, ok := f.store.Lookup(testPSKPeerA, "pk-a"); !ok || !bytes.Equal(key, older) {
			t.Error("an older epoch was refused for a peer whose floor should have been forgotten")
		}
	})
}

func TestEdgePSKs_NotReadyContinues(t *testing.T) {
	for _, notReady := range []*api.APIError{
		{StatusCode: 404, Code: "peer_not_found"},
		{StatusCode: 409, Code: "psk_not_ready"},
	} {
		t.Run(notReady.Code, func(t *testing.T) {
			f := newPSKStoreFixture(t)
			f.fetcher.respond = func(peer string) (*api.EdgePSKEnvelope, error) {
				if peer == testPSKPeerA {
					return nil, notReady
				}
				return testEnvelope(t, testPSKKey(0xb2), peer, testEpoch), nil
			}
			peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")}

			f.store.Sync(context.Background(), peers)
			if got := f.fetcher.callList(); len(got) != 2 {
				t.Fatalf("fetches = %v, want both peers", got)
			}
			if _, ok := f.store.Lookup(testPSKPeerB, "pk-b"); !ok {
				t.Error("peer b's PSK is missing after peer a was not ready")
			}

			f.store.Sync(context.Background(), peers)
			if got := f.fetcher.callList(); len(got) != 3 || got[2] != testPSKPeerA {
				t.Errorf("fetches after the second Sync = %v, want a retry of peer a only", got)
			}
		})
	}
}

func TestEdgePSKs_NotServed(t *testing.T) {
	f := newPSKStoreFixture(t)
	f.fail(&api.APIError{StatusCode: 501, Code: "psk_delivery_not_provisioned"})
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")}

	for i := 1; i <= 3; i++ {
		f.store.Sync(context.Background(), peers)
		if n := f.fetcher.callCount(); n != i {
			t.Fatalf("fetches after %d Syncs = %d, want one request per pass", i, n)
		}
	}
	if n := strings.Count(f.logs.String(), "control plane does not serve edge psks"); n != 1 {
		t.Errorf("not-served line logged %d times, want once:\n%s", n, f.logs.String())
	}

	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1), testPSKPeerB: testPSKKey(0xb2)}, testEpoch)
	f.store.Sync(context.Background(), peers)
	f.store.Sync(context.Background(), peers)
	if n := strings.Count(f.logs.String(), "control plane serves edge psks"); n != 1 {
		t.Errorf("recovery line logged %d times, want once:\n%s", n, f.logs.String())
	}
}

func TestEdgePSKs_RateLimited(t *testing.T) {
	f := newPSKStoreFixture(t)
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")}
	f.fail(&api.APIError{StatusCode: 429, Code: "per_node_rate_limited", RetryAfter: 30 * time.Second})

	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 1 {
		t.Fatalf("fetches = %d, want the pass to stop after the 429", n)
	}
	start := f.clock
	f.clock = start.Add(29 * time.Second)
	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 1 {
		t.Fatalf("fetches 29s into a 30s pause = %d, want none", n-1)
	}
	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1), testPSKPeerB: testPSKKey(0xb2)}, testEpoch)
	f.clock = start.Add(30 * time.Second)
	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 3 {
		t.Fatalf("fetches once the 30s pause ended = %d, want both peers", n-1)
	}
}

func TestEdgePSKs_RateLimitedWithoutRetryAfter(t *testing.T) {
	f := newPSKStoreFixture(t)
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")}
	f.fail(&api.APIError{StatusCode: 429, Code: "per_node_rate_limited"})

	f.store.Sync(context.Background(), peers)
	start := f.clock
	f.clock = start.Add(500 * time.Millisecond)
	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 1 {
		t.Fatalf("fetches half a second after a 429 without Retry-After = %d, want none", n-1)
	}
	f.clock = start.Add(time.Second)
	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 2 {
		t.Fatalf("fetches a second after a 429 without Retry-After = %d, want one", n-1)
	}
}

func TestEdgePSKs_ContextCancelled(t *testing.T) {
	f := newPSKStoreFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.fetcher.respond = func(string) (*api.EdgePSKEnvelope, error) {
		cancel()
		return nil, ctx.Err()
	}

	f.store.Sync(ctx, []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")})

	if n := f.fetcher.callCount(); n != 1 {
		t.Errorf("fetches = %d, want 1: a cancelled pass sends no second request", n)
	}
	if _, ok := f.store.Lookup(testPSKPeerA, "pk-a"); ok {
		t.Error("a PSK was stored by a cancelled pass")
	}
	if n := len(f.installer.callList()); n != 0 {
		t.Errorf("installs = %d, want 0", n)
	}
}

func TestEdgePSKs_TransportErrorEndsPass(t *testing.T) {
	f := newPSKStoreFixture(t)
	f.fail(&url.Error{Op: "Get", URL: "https://cp.example/v1/nodes/n/peers/p/psk", Err: errors.New("i/o timeout")})
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")}

	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 1 {
		t.Fatalf("fetches = %d, want the pass to end after the transport error", n)
	}
	if !strings.Contains(f.logs.String(), "wireguard: edge psk: control plane unreachable, retrying on the next pull") {
		t.Errorf("log does not carry the unreachable line:\n%s", f.logs.String())
	}

	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1), testPSKPeerB: testPSKKey(0xb2)}, testEpoch)
	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 3 {
		t.Errorf("fetches after the next pull = %d, want both peers fetched", n-1)
	}
}

func TestEdgePSKs_Forbidden(t *testing.T) {
	f := newPSKStoreFixture(t)
	f.fail(&api.APIError{StatusCode: 403, Code: "node_deregistered"})
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a"), pskPeer(testPSKPeerB, "pk-b")}

	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 1 {
		t.Fatalf("fetches = %d, want the pass to stop after the 403", n)
	}
	out := f.logs.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "control plane refused this node, stopping edge psk fetches") {
		t.Errorf("log does not carry the 403 Error line:\n%s", out)
	}

	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1)}, testEpoch)
	f.clock = f.clock.Add(time.Hour)
	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 1 {
		t.Errorf("fetches after a 403 = %d, want no further request", n-1)
	}
}

func TestEdgePSKs_EpochFloor(t *testing.T) {
	f := newPSKStoreFixture(t)
	current := testPSKKey(0xa1)
	f.serve(t, map[string][]byte{testPSKPeerA: current}, testEpoch)
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")}
	f.store.Sync(context.Background(), peers)

	// An older envelope is refused and installs nothing.
	f.store.InvalidateAll()
	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa0)}, testEpochOld)
	installs := len(f.installer.callList())
	f.store.Sync(context.Background(), peers)
	if !strings.Contains(f.logs.String(), "refusing an envelope older than the epoch in force") {
		t.Errorf("log does not carry the refusal:\n%s", f.logs.String())
	}
	if n := len(f.installer.callList()); n != installs {
		t.Errorf("installs after an older envelope = %d, want none", n-installs)
	}
	if key, _ := f.store.Lookup(testPSKPeerA, "pk-a"); !bytes.Equal(key, current) {
		t.Error("an older envelope replaced the key in force")
	}

	// An envelope at the same epoch is accepted and installed.
	same := testPSKKey(0xa2)
	f.serve(t, map[string][]byte{testPSKPeerA: same}, testEpoch)
	f.store.Sync(context.Background(), peers)
	if key, _ := f.store.Lookup(testPSKPeerA, "pk-a"); !bytes.Equal(key, same) {
		t.Error("an envelope at the epoch in force was refused")
	}
	if got := f.installer.callList(); len(got) != installs+1 || !bytes.Equal(got[len(got)-1].psk, same) {
		t.Errorf("installs after an envelope at the epoch in force = %d, want the new key installed once", len(got)-installs)
	}

	// The floor survives the peer's key change.
	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa0)}, testEpochOld)
	f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a2")})
	if _, ok := f.store.Lookup(testPSKPeerA, "pk-a2"); ok {
		t.Error("an older envelope was accepted after the peer's key changed")
	}
}

func TestEdgePSKs_OpenFailed(t *testing.T) {
	f := newPSKStoreFixture(t)
	f.fetcher.respond = func(peer string) (*api.EdgePSKEnvelope, error) {
		return &api.EdgePSKEnvelope{
			Data:  sealTestPSK(t, bytes.Repeat([]byte{0x12}, 32), testPSKKey(0xa1), edgePSKAAD(testPSKSelf, peer, testEpoch)),
			KID:   "nsk-kid-1",
			Epoch: testEpoch,
		}, nil
	}

	f.store.Sync(context.Background(), []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")})

	if !strings.Contains(f.logs.String(), "wireguard: edge psk: open failed") {
		t.Errorf("log does not carry the open failure:\n%s", f.logs.String())
	}
	if n := len(f.installer.callList()); n != 0 {
		t.Errorf("installs = %d, want 0", n)
	}
	assertNoKeyMaterial(t, f.logs.String(), testPSKNSK, bytes.Repeat([]byte{0x12}, 32), testPSKKey(0xa1))
}

func TestEdgePSKs_InstallRetry(t *testing.T) {
	f := newPSKStoreFixture(t)
	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1)}, testEpoch)
	f.installer.err = errors.New("device busy")
	peers := []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")}

	f.store.Sync(context.Background(), peers)
	if !strings.Contains(f.logs.String(), "wireguard: edge psk: install failed") {
		t.Errorf("log does not carry the install failure:\n%s", f.logs.String())
	}

	f.installer.mu.Lock()
	f.installer.err = nil
	f.installer.mu.Unlock()
	f.store.Sync(context.Background(), peers)
	if n := f.fetcher.callCount(); n != 1 {
		t.Errorf("fetches = %d, want the retry to install without a fetch", n)
	}
	if n := len(f.installer.callList()); n != 2 {
		t.Fatalf("installs = %d, want a retry", n)
	}

	f.store.Sync(context.Background(), peers)
	if n := len(f.installer.callList()); n != 2 {
		t.Errorf("installs after an accepted install = %d, want no further one", n)
	}
}

func TestEdgePSKDispatchHandler(t *testing.T) {
	f := newPSKStoreFixture(t)
	f.serve(t, map[string][]byte{testPSKPeerA: testPSKKey(0xa1)}, testEpoch)
	handler := EdgePSKDispatchHandler(f.store)

	handler(context.Background(), nil)
	if n := f.fetcher.callCount(); n != 0 {
		t.Fatalf("fetches for a nil snapshot = %d, want 0", n)
	}

	handler(context.Background(), &api.NodeStateSnapshot{Peers: []api.SnapshotPeer{pskPeer(testPSKPeerA, "pk-a")}})
	if n := f.fetcher.callCount(); n != 1 {
		t.Errorf("fetches = %d, want 1", n)
	}
}
