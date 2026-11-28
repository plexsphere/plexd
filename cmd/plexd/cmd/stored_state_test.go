package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/statestore"
	"github.com/plexsphere/plexd/internal/wireguard"
)

const (
	storedRestoredMsg = "stored state restored"
	storedPolicyPort  = 2222
)

// storedPeer is the peer newPSKControlPlane serves.
func storedPeer() api.SnapshotPeer {
	return api.SnapshotPeer{
		NodeID:           upPSKPeerID,
		MeshIP:           "100.64.0.2",
		PublicKey:        upPSKPeerKey,
		Endpoint:         upPSKPeerDirect,
		FallbackEndpoint: "203.0.113.1:51820",
	}
}

// storedPolicy is a one-rule policy whose port no default ruleset carries.
func storedPolicy() *api.PolicySnapshot {
	return &api.PolicySnapshot{
		RevisionID:  "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f1",
		Fingerprint: "c3RvcmVkLXN0YXRlLXBvbGljeS1maW5nZXJwcmludA==",
		Rules: []api.PolicyRule{{
			Protocol:        "tcp",
			SourceCIDR:      "100.64.0.0/10",
			DestinationCIDR: "100.64.0.0/10",
			Ports:           &api.PortRange{From: storedPolicyPort, To: storedPolicyPort},
		}},
	}
}

// storedFile is the file the state store writes for upTestNodeID after a pull
// of storedPeer and storedPolicy, with the peer's edge PSK sealed as the PSK
// control plane serves it.
func storedFile(t *testing.T, savedAt time.Time, maxAgeSeconds int64) statestore.File {
	t.Helper()
	return statestore.File{
		Version:       statestore.Version,
		NodeID:        upTestNodeID,
		SavedAt:       savedAt.UTC(),
		MaxAgeSeconds: maxAgeSeconds,
		Peers:         []api.SnapshotPeer{storedPeer()},
		Policy:        storedPolicy(),
		EdgePSKs: []wireguard.SealedEdgePSK{{
			PeerNodeID: upPSKPeerID,
			PublicKey:  upPSKPeerKey,
			Epoch:      upPSKEpoch,
			Envelope:   sealUpEdgePSK(t, upTestNSKBytes, upPSKKey, upTestNodeID, upPSKPeerID, upPSKEpoch),
		}},
	}
}

// seedStoredState writes f where the state store keeps it.
func seedStoredState(t *testing.T, dataDir string, f statestore.File) {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	seedStoredStateRaw(t, dataDir, data)
}

func seedStoredStateRaw(t *testing.T, dataDir string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dataDir, statestore.FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// storedStateYAML is upDaemonYAML with policy enforcement on, so a firewall
// double sees the rulesets, and a 1s reconcile interval.
func storedStateYAML(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`policy:
  enabled: true
tunnel:
  enabled: false
node_api:
  socket_path: %s
reconcile:
  interval: 1s
`, shortSocketPath(t))
}

// unavailableControlPlane answers every state pull with 503 and every other
// request with an empty JSON object, and counts the state pulls.
func unavailableControlPlane(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	pulls := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/state") {
			pulls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"unavailable"}`))
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, pulls
}

// recordingFirewallController clears every check and records each ruleset
// it is handed.
type recordingFirewallController struct {
	mu      sync.Mutex
	applied [][]policy.FirewallRule
}

func (*recordingFirewallController) Probe() error             { return nil }
func (*recordingFirewallController) EnsureChain(string) error { return nil }
func (*recordingFirewallController) FlushChain(string) error  { return nil }
func (*recordingFirewallController) DeleteChain(string) error { return nil }

func (f *recordingFirewallController) ApplyRules(_ string, rules []policy.FirewallRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, slices.Clone(rules))
	return nil
}

func (f *recordingFirewallController) rulesets() [][]policy.FirewallRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.applied)
}

// carriesStoredPolicy reports whether a ruleset allows the stored policy's
// port.
func carriesStoredPolicy(rules []policy.FirewallRule) bool {
	return slices.ContainsFunc(rules, func(r policy.FirewallRule) bool {
		return r.Action == "allow" && r.Port == storedPolicyPort
	})
}

// isDefaultDenyOnly reports whether a ruleset is the default deny alone.
func isDefaultDenyOnly(rules []policy.FirewallRule) bool {
	return len(rules) == 1 && rules[0].Action == "deny"
}

// writesFor returns the device writes for the peer with publicKey.
func writesFor(ctrl *recordingWGController, publicKey string) []wireguard.PeerConfig {
	var out []wireguard.PeerConfig
	for _, cfg := range ctrl.writes() {
		if base64.StdEncoding.EncodeToString(cfg.PublicKey) == publicKey {
			out = append(out, cfg)
		}
	}
	return out
}

// waitUntil polls cond every 10ms until it holds or 30s passed.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after 30s waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// storedStateRig is a daemon over a recording WireGuard controller, a
// recording firewall and a recording log, with an identity seeded in its
// data dir.
type storedStateRig struct {
	dataDir string
	ctrl    *recordingWGController
	fw      *recordingFirewallController
	logs    *recordingHandler
}

func newStoredStateRig(t *testing.T, apiBase, yaml string) *storedStateRig {
	t.Helper()
	// Outside a cluster no PlexdHook list runs; an ambient
	// KUBERNETES_SERVICE_HOST must not turn this into a cluster test.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	rig := &storedStateRig{
		ctrl: &recordingWGController{},
		fw:   &recordingFirewallController{},
		logs: useRecordingDaemonLog(t),
	}
	useWGController(t, rig.ctrl)
	useFirewallController(t, rig.fw)
	rig.dataDir = writeUpConfig(t, apiBase, yaml)
	seedIdentity(t, rig.dataDir, upTestNodeID, upTestNSK)
	return rig
}

// After one pull, the stored state holds the pulled peer, the policy and the
// peer's edge PSK, still sealed.
func TestRunUp_WritesTheStoredStateAfterAPull(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	cp, apiBase := newPSKControlPlane(t)
	cp.servePolicy(storedPolicy())
	useWGController(t, &recordingWGController{})
	dataDir := writeUpConfig(t, apiBase, upDaemonYAML(t))
	shutdown := startRunUp(t)
	defer shutdown()

	path := filepath.Join(dataDir, statestore.FileName)
	var raw []byte
	var f statestore.File
	waitUntil(t, "a stored state with the peer, the policy and one sealed PSK", func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		f = statestore.File{}
		if json.Unmarshal(data, &f) != nil {
			return false
		}
		raw = data
		return len(f.Peers) == 1 && f.Policy != nil && len(f.EdgePSKs) == 1
	})

	if f.NodeID != upTestNodeID || f.Version != statestore.Version {
		t.Errorf("node_id = %q, version = %d, want %q and %d", f.NodeID, f.Version, upTestNodeID, statestore.Version)
	}
	if f.Peers[0].NodeID != upPSKPeerID || f.Peers[0].PublicKey != upPSKPeerKey {
		t.Errorf("stored peer = %+v, want %s with its public key", f.Peers[0], upPSKPeerID)
	}
	if f.Policy.Fingerprint != storedPolicy().Fingerprint {
		t.Errorf("stored policy fingerprint = %q, want %q", f.Policy.Fingerprint, storedPolicy().Fingerprint)
	}
	psk := f.EdgePSKs[0]
	if psk.PeerNodeID != upPSKPeerID || psk.PublicKey != upPSKPeerKey || psk.Epoch != upPSKEpoch || len(psk.Envelope) != api.EdgePSKEnvelopeSize {
		t.Errorf("stored PSK = {%s %s %s, %d bytes}, want the envelope served for %s", psk.PeerNodeID, psk.PublicKey, psk.Epoch, len(psk.Envelope), upPSKPeerID)
	}
	for _, form := range [][]byte{upPSKKey, []byte(base64.StdEncoding.EncodeToString(upPSKKey))} {
		if bytes.Contains(raw, form) {
			t.Error("the stored state carries the edge PSK in the clear")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("stored state mode = %o, want 600", mode)
	}
}

// With a stored state and a control plane that answers every state pull with
// 503, the stored peer is programmed with its PSK, the firewall gets the
// stored policy's rules, and the restore is logged.
func TestRunUp_RestoresTheStoredStateWithoutAControlPlane(t *testing.T) {
	apiBase, pulls := unavailableControlPlane(t)
	rig := newStoredStateRig(t, apiBase, storedStateYAML(t))
	seedStoredState(t, rig.dataDir, storedFile(t, time.Now().Add(-time.Hour), 0))
	shutdown := startRunUpDaemon(t)
	defer shutdown()

	waitUntil(t, "the restore and a refused pull", func() bool {
		return rig.logs.count(slog.LevelInfo, storedRestoredMsg) == 1 && pulls.Load() > 0
	})

	writes := writesFor(rig.ctrl, upPSKPeerKey)
	if len(writes) == 0 {
		t.Fatal("the stored peer was never written to the device")
	}
	if !bytes.Equal(writes[0].PSK, upPSKKey) {
		t.Error("the stored peer was written without its stored edge PSK")
	}
	if !slices.ContainsFunc(rig.fw.rulesets(), carriesStoredPolicy) {
		t.Errorf("no ruleset carries the stored policy's rule; rulesets: %+v", rig.fw.rulesets())
	}
	attrs := rig.logs.attrsOf(slog.LevelInfo, storedRestoredMsg)
	for key, want := range map[string]string{"peers": "1", "edge_psks": "1", "policy_fingerprint": storedPolicy().Fingerprint, "handler_failed": "false"} {
		if attrs[key] != want {
			t.Errorf("%s %s = %q, want %q", storedRestoredMsg, key, attrs[key], want)
		}
	}
	if _, err := os.Stat(filepath.Join(rig.dataDir, statestore.MarkerName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("restore marker after the restore: %v, want it removed", err)
	}
}

// With a stored state equal to what the control plane serves, the first pull
// finds no peer to change: the peer is written once, by the restore, and its
// edge PSK is not fetched again.
func TestRunUp_AppliesOnlyTheDifferenceAfterARestore(t *testing.T) {
	cp, apiBase := newPSKControlPlane(t)
	rig := newStoredStateRig(t, apiBase, upDaemonYAML(t)+"reconcile:\n  interval: 1s\n")
	f := storedFile(t, time.Now().Add(-time.Minute), 0)
	f.Policy = nil
	seedStoredState(t, rig.dataDir, f)
	shutdown := startRunUpDaemon(t)
	defer shutdown()

	waitUntil(t, "three state pulls after the restore", func() bool {
		pulls, _ := cp.counts()
		return rig.logs.count(slog.LevelInfo, storedRestoredMsg) == 1 && pulls >= 3
	})

	if n := len(writesFor(rig.ctrl, upPSKPeerKey)); n != 1 {
		t.Errorf("the peer was written %d times, want once: the restore, and no add by a pull equal to it", n)
	}
	if _, requests := cp.counts(); requests != 0 {
		t.Errorf("PSK requests = %d, want 0: the restored PSK serves the peer", requests)
	}
}

// checkStoredStateSkipped seeds a stored state with seed, starts the daemon
// against a control plane that refuses every pull, and checks that the
// restore logged warn and restored nothing: no write for the stored peer and
// only the default-deny ruleset.
func checkStoredStateSkipped(t *testing.T, seed func(t *testing.T, dataDir string), warn string) *storedStateRig {
	t.Helper()
	apiBase, pulls := unavailableControlPlane(t)
	rig := newStoredStateRig(t, apiBase, storedStateYAML(t))
	seed(t, rig.dataDir)
	shutdown := startRunUpDaemon(t)
	defer shutdown()

	// The reconciler starts after the restore, so a pull it tried shows the
	// restore is over.
	waitUntil(t, fmt.Sprintf("%q and a refused pull", warn), func() bool {
		return rig.logs.count(slog.LevelWarn, warn) == 1 && pulls.Load() > 0
	})

	if n := len(writesFor(rig.ctrl, upPSKPeerKey)); n != 0 {
		t.Errorf("the stored peer was written %d times, want never", n)
	}
	rulesets := rig.fw.rulesets()
	if len(rulesets) == 0 {
		t.Error("no ruleset was installed, want the default-deny baseline")
	}
	for i, rules := range rulesets {
		if !isDefaultDenyOnly(rules) {
			t.Errorf("ruleset %d = %+v, want the default deny alone", i, rules)
		}
	}
	if n := rig.logs.count(slog.LevelInfo, storedRestoredMsg); n != 0 {
		t.Errorf("%q logged %d times, want never", storedRestoredMsg, n)
	}
	return rig
}

// A stored state older than the limit stored with it is not restored.
func TestRunUp_SkipsStoredStateOlderThanTheLimit(t *testing.T) {
	checkStoredStateSkipped(t, func(t *testing.T, dataDir string) {
		seedStoredState(t, dataDir, storedFile(t, time.Now().Add(-2*time.Hour), 60))
	}, "stored state older than the limit, not restored")
}

// Without a limit the age is not checked: a stored state saved in 2001 is
// restored.
func TestRunUp_RestoresAnOldStoredStateWithoutALimit(t *testing.T) {
	apiBase, _ := unavailableControlPlane(t)
	rig := newStoredStateRig(t, apiBase, storedStateYAML(t))
	seedStoredState(t, rig.dataDir, storedFile(t, time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), 0))
	shutdown := startRunUpDaemon(t)
	defer shutdown()

	waitUntil(t, "the restore", func() bool { return rig.logs.count(slog.LevelInfo, storedRestoredMsg) == 1 })
	if n := len(writesFor(rig.ctrl, upPSKPeerKey)); n == 0 {
		t.Error("the stored peer was never written to the device")
	}
}

// A stored state written for another node is not restored.
func TestRunUp_SkipsStoredStateOfAnotherNode(t *testing.T) {
	checkStoredStateSkipped(t, func(t *testing.T, dataDir string) {
		f := storedFile(t, time.Now().Add(-time.Minute), 0)
		f.NodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0ff"
		seedStoredState(t, dataDir, f)
	}, "stored state belongs to another node, not restored")
}

// Under a limit, a stored state saved more than a minute ahead of the clock
// is not restored: the clock cannot measure its age.
func TestRunUp_SkipsStoredStateNewerThanTheClock(t *testing.T) {
	checkStoredStateSkipped(t, func(t *testing.T, dataDir string) {
		seedStoredState(t, dataDir, storedFile(t, time.Now().Add(time.Hour), 3600))
	}, "stored state is newer than the clock, not restored")
}

// A stored state that does not decode is not restored, and stays for the
// next successful pull to overwrite.
func TestRunUp_SkipsAnUnreadableStoredState(t *testing.T) {
	rig := checkStoredStateSkipped(t, func(t *testing.T, dataDir string) {
		seedStoredStateRaw(t, dataDir, []byte(`{"version":1,"node_id":"`+upTestNodeID+`","peers":[`))
	}, "stored state unusable, not restored")
	if _, err := os.Stat(filepath.Join(rig.dataDir, statestore.FileName)); err != nil {
		t.Errorf("the unreadable stored state is gone: %v, want it kept", err)
	}
}

// A restore marker left by a start that died while it restored discards the
// stored state: nothing is restored and both files are gone.
func TestRunUp_DiscardsTheStoredStateAfterAnInterruptedRestore(t *testing.T) {
	rig := checkStoredStateSkipped(t, func(t *testing.T, dataDir string) {
		seedStoredState(t, dataDir, storedFile(t, time.Now().Add(-time.Minute), 0))
		if err := os.WriteFile(filepath.Join(dataDir, statestore.MarkerName), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}, "stored state discarded, the previous restore did not complete")
	for _, name := range []string{statestore.FileName, statestore.MarkerName} {
		if _, err := os.Stat(filepath.Join(rig.dataDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after the start: %v, want it removed", name, err)
		}
	}
}

// Without a stored state the daemon starts as it did before the store: it
// logs no Warn about stored state and installs the default-deny baseline.
func TestRunUp_StartsWithoutStoredState(t *testing.T) {
	apiBase, pulls := unavailableControlPlane(t)
	rig := newStoredStateRig(t, apiBase, storedStateYAML(t))
	shutdown := startRunUpDaemon(t)
	defer shutdown()

	waitUntil(t, "a refused pull", func() bool { return pulls.Load() > 0 })

	if n := rig.logs.count(slog.LevelDebug, "no stored state"); n != 1 {
		t.Errorf("%q logged %d times at Debug, want once", "no stored state", n)
	}
	rig.logs.mu.Lock()
	for _, rec := range rig.logs.records {
		if rec.level >= slog.LevelWarn && strings.Contains(rec.msg, "stored state") {
			t.Errorf("logged %q at %v, want no Warn about stored state", rec.msg, rec.level)
		}
	}
	rig.logs.mu.Unlock()
	rulesets := rig.fw.rulesets()
	if len(rulesets) == 0 || !isDefaultDenyOnly(rulesets[0]) {
		t.Errorf("rulesets = %+v, want the default-deny baseline first", rulesets)
	}
}

// The restore hands the stored secret inventory to the bridge's inventory
// handlers after the policy and before the reconcile handlers get the stored
// bridge block, as a pull does, so a part whose Secret the control plane
// serves comes up at the restore instead of going down until a later pull.
func TestRestoreStoredState_HandsTheSecretInventoryOverFirst(t *testing.T) {
	dataDir := t.TempDir()
	f := storedFile(t, time.Now().Add(-time.Minute), 0)
	f.Bridge = &api.BridgeSnapshot{SiteToSite: &api.SiteToSiteConfig{Enabled: true, Tunnels: []api.SiteToSiteTunnel{{ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1e1"}}}}
	inventory := []api.NodeStateSecret{{Name: "s2s-psk", Version: 2}}
	f.Secrets = &inventory
	seedStoredState(t, dataDir, f)

	logger := slog.New(slog.DiscardHandler)
	var order []string
	r := reconcile.NewReconciler(nil, reconcile.Config{}, logger)
	r.RegisterHandler(func(_ context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		order = append(order, "reconcile")
		if !diff.BridgeChanged || desired.Bridge == nil || desired.Bridge.SiteToSite == nil {
			t.Errorf("the reconcile handler got bridge %+v (changed %v), want the stored site-to-site block", desired.Bridge, diff.BridgeChanged)
		}
		return nil
	})
	takeInventory := func(name string) reconcile.DispatchHandler {
		return func(_ context.Context, desired *api.NodeStateSnapshot) {
			order = append(order, name)
			if desired.Secrets == nil || !slices.Equal(*desired.Secrets, inventory) {
				t.Errorf("%s got the inventory %v, want the stored %v", name, desired.Secrets, inventory)
			}
		}
	}
	restoreStoredState(context.Background(), storedStateDeps{
		store:           statestore.New(dataDir, upTestNodeID, logger),
		reconciler:      r,
		policy:          func(context.Context, *api.NodeStateSnapshot) { order = append(order, "policy") },
		secretInventory: []reconcile.DispatchHandler{takeInventory("ingress"), takeInventory("site-to-site")},
		logger:          logger,
	})

	if want := []string{"policy", "ingress", "site-to-site", "reconcile"}; !slices.Equal(order, want) {
		t.Errorf("restore order = %v, want %v", order, want)
	}
}
