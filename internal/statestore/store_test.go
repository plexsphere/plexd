package statestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/wireguard"
)

const testNodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"

// syncBuffer is a log sink safe for the test to read.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newTestStore returns a Store for testNodeID under dir with a clock the test
// moves and a log it reads.
func newTestStore(dir string) (*Store, *syncBuffer, *time.Time) {
	logs := &syncBuffer{}
	s := New(dir, testNodeID, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	clock := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	return s, logs, &clock
}

// fullPull returns a pull with every block the store keeps.
func fullPull() *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{NodeID: "peer-a", MeshIP: "10.99.0.2", PublicKey: "pk-a", Endpoint: "198.51.100.7:51820", RoutedSubnets: []string{"10.50.0.0/16"}},
			{NodeID: "peer-b", MeshIP: "10.99.0.3", PublicKey: "pk-b"},
		},
		Policy: &api.PolicySnapshot{
			RevisionID:  "rev-1",
			Fingerprint: "fp-1",
			Rules:       []api.PolicyRule{{Protocol: "tcp", SourceCIDR: "10.99.0.0/24", DestinationCIDR: "10.99.0.0/24", Ports: &api.PortRange{From: 22, To: 22}}},
		},
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{Enabled: true, Providers: []api.UserAccessProvider{{ID: "ua-1"}}},
		},
		Secrets:          &[]api.NodeStateSecret{{Name: "s2s-psk", Version: 3}},
		SharedSubnets:    []api.NodeStateSharedSubnet{{Subnet: "10.20.0.0/16", Bridges: []string{"peer-a", "peer-b"}}},
		FailureDetection: json.RawMessage(`{"detect_after_seconds":20}`),
		DNS:              &api.NodeStateDNS{SearchDomain: "app.internal"},
		Executions:       []api.NodeStateExecution{{ExecutionID: "exec-1"}},
	}
}

// twoSealed returns two sealed PSKs.
func twoSealed() []wireguard.SealedEdgePSK {
	return []wireguard.SealedEdgePSK{
		{PeerNodeID: "peer-a", PublicKey: "pk-a", Epoch: "e1", Envelope: bytes.Repeat([]byte{0xa1}, api.EdgePSKEnvelopeSize)},
		{PeerNodeID: "peer-b", PublicKey: "pk-b", Epoch: "e2", Envelope: bytes.Repeat([]byte{0xb2}, api.EdgePSKEnvelopeSize)},
	}
}

func readFile(t *testing.T, dir string) File {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("read the stored state: %v", err)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("decode the stored state: %v", err)
	}
	return f
}

func writeRaw(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A pull with every stored block and two sealed PSKs goes through the
// observer and comes back from Load, in a file of mode 0600.
func TestStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, _, clock := newTestStore(dir)
	pull := fullPull()

	s.Observer(twoSealed, func() int64 { return 3600 })(context.Background(), pull)

	got, err := New(dir, testNodeID, slog.New(slog.DiscardHandler)).Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := &File{
		Version:          Version,
		NodeID:           testNodeID,
		SavedAt:          *clock,
		MaxAgeSeconds:    3600,
		Peers:            pull.Peers,
		Policy:           pull.Policy,
		Bridge:           pull.Bridge,
		Secrets:          pull.Secrets,
		SharedSubnets:    pull.SharedSubnets,
		FailureDetection: pull.FailureDetection,
		EdgePSKs:         twoSealed(),
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Errorf("Load() =\n%s\nwant\n%s", gotJSON, wantJSON)
	}
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range []string{`"dns"`, `"executions"`, `"sessions"`, `"state"`, `"reports"`} {
		if bytes.Contains(raw, []byte(block)) {
			t.Errorf("the stored state carries %s, a block the store does not keep", block)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o, want 600", mode)
	}
}

// Load names a missing file, another node's file, and a file it cannot read,
// and removes none of them.
func TestStore_LoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		content *string
		want    error
		wrapped bool
	}{
		{name: "missing", want: ErrNoState},
		{name: "another node", content: new(`{"version":1,"node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0ff","saved_at":"2026-11-28T12:00:00Z","peers":[],"policy":null,"bridge":null,"shared_subnets":null}`), want: ErrForeign},
		{name: "truncated", content: new(`{"version":1,"node_id":"` + testNodeID + `","peers":[`), wrapped: true},
		{name: "empty", content: new(""), wrapped: true},
		{name: "version 2", content: new(`{"version":2,"node_id":"` + testNodeID + `","peers":[]}`), wrapped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.content != nil {
				writeRaw(t, dir, *tt.content)
			}
			s, _, _ := newTestStore(dir)

			f, err := s.Load()
			if f != nil {
				t.Errorf("Load() file = %+v, want nil", f)
			}
			switch {
			case tt.wrapped:
				if err == nil || !strings.HasPrefix(err.Error(), "statestore: load: ") {
					t.Errorf("Load() error = %v, want one wrapped as statestore: load: ...", err)
				}
				for _, sentinel := range []error{ErrNoState, ErrForeign, ErrInterrupted} {
					if errors.Is(err, sentinel) {
						t.Errorf("Load() error = %v, want none of the sentinels", err)
					}
				}
			case !errors.Is(err, tt.want):
				t.Errorf("Load() error = %v, want %v", err, tt.want)
			}
			if tt.content != nil {
				if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
					t.Errorf("the stored state is gone after Load: %v", err)
				}
			}
		})
	}
}

// The restore marker makes Load return ErrInterrupted and remove both files.
func TestStore_LoadAfterAnInterruptedRestore(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newTestStore(dir)
	s.Observer(nil, nil)(context.Background(), fullPull())
	if err := s.BeginRestore(); err != nil {
		t.Fatalf("BeginRestore() error = %v", err)
	}

	_, err := New(dir, testNodeID, slog.New(slog.DiscardHandler)).Load()
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("Load() error = %v, want ErrInterrupted", err)
	}
	for _, name := range []string{FileName, MarkerName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after Load: %v, want it removed", name, err)
		}
	}
}

// EndRestore removes the marker, so the next Load reads the file again.
func TestStore_EndRestore(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newTestStore(dir)
	s.Observer(nil, nil)(context.Background(), fullPull())
	if err := s.BeginRestore(); err != nil {
		t.Fatal(err)
	}
	if err := s.EndRestore(); err != nil {
		t.Fatalf("EndRestore() error = %v", err)
	}
	if err := s.EndRestore(); err != nil {
		t.Errorf("EndRestore() without a marker = %v, want nil", err)
	}
	if _, err := New(dir, testNodeID, slog.New(slog.DiscardHandler)).Load(); err != nil {
		t.Errorf("Load() after EndRestore = %v, want the file", err)
	}
}

// Without a limit two equal pulls write once; under a limit each pull
// rewrites the file with a later saved_at; and a pull with no peers and a
// null policy is stored as such.
func TestStore_WritesOnChangeOrUnderALimit(t *testing.T) {
	dir := t.TempDir()
	s, _, clock := newTestStore(dir)
	limit := int64(0)
	observe := s.Observer(nil, func() int64 { return limit })
	path := filepath.Join(dir, FileName)

	observe(context.Background(), fullPull())
	first := readFile(t, dir)
	*clock = clock.Add(time.Minute)
	if err := os.Chtimes(path, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	observe(context.Background(), fullPull())
	if got := readFile(t, dir); !got.SavedAt.Equal(first.SavedAt) {
		t.Errorf("saved_at after an equal pull without a limit = %v, want the first write's %v", got.SavedAt, first.SavedAt)
	}
	if info, err := os.Stat(path); err != nil || !info.ModTime().Equal(time.Unix(1, 0)) {
		t.Errorf("an equal pull without a limit rewrote the file (%v, %v)", info.ModTime(), err)
	}

	limit = 180
	for i := range 2 {
		*clock = clock.Add(time.Minute)
		observe(context.Background(), fullPull())
		got := readFile(t, dir)
		if !got.SavedAt.Equal(*clock) {
			t.Errorf("pull %d under a limit: saved_at = %v, want %v", i, got.SavedAt, *clock)
		}
		if got.MaxAgeSeconds != 180 {
			t.Errorf("pull %d under a limit: max_age_seconds = %d, want 180", i, got.MaxAgeSeconds)
		}
	}

	limit = 0
	observe(context.Background(), &api.NodeStateSnapshot{})
	got := readFile(t, dir)
	if len(got.Peers) != 0 || got.Policy != nil || got.Bridge != nil {
		t.Errorf("stored state after an empty pull = %+v, want no peers, no policy and no bridge", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"policy":null`)) || !bytes.Contains(raw, []byte(`"peers":null`)) {
		t.Errorf("stored state after an empty pull = %s, want peers and policy null", raw)
	}
}

// A pull without failure_detection keeps the stored block, also one Load
// read, and so does a pull with a null secrets block; a nil sealed callback
// stores no edge_psks.
func TestStore_CarriesFailureDetectionOver(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newTestStore(dir)
	s.Observer(nil, nil)(context.Background(), fullPull())

	restarted, _, _ := newTestStore(dir)
	if _, err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	observe := restarted.Observer(nil, nil)
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null")} {
		pull := fullPull()
		pull.Peers = pull.Peers[:1]
		pull.FailureDetection = raw
		pull.Secrets = nil
		observe(context.Background(), pull)
		got := readFile(t, dir)
		if len(got.Peers) != 1 {
			t.Fatalf("failure_detection %q: the pull was not written (%d peers)", raw, len(got.Peers))
		}
		if string(got.FailureDetection) != `{"detect_after_seconds":20}` {
			t.Errorf("failure_detection %q: stored block = %s, want the earlier {\"detect_after_seconds\":20}", raw, got.FailureDetection)
		}
		if got.Secrets == nil || len(*got.Secrets) != 1 || (*got.Secrets)[0] != (api.NodeStateSecret{Name: "s2s-psk", Version: 3}) {
			t.Errorf("secrets after a pull with a null block = %v, want the earlier inventory [s2s-psk 3]", got.Secrets)
		}
		pull.Peers = nil
		observe(context.Background(), pull)
	}

	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"edge_psks"`)) {
		t.Errorf("a nil sealed callback stored edge_psks: %s", data)
	}
}

// A data dir that is a regular file fails every write: the Warn is logged
// once across three pulls, and a later write that succeeds says so.
func TestStore_FailedWriteLogsOnce(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "data")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, logs, _ := newTestStore(notADir)
	observe := s.Observer(twoSealed, nil)

	for range 3 {
		observe(context.Background(), fullPull())
	}
	if n := strings.Count(logs.String(), `msg="stored state not written"`); n != 1 {
		t.Errorf("'stored state not written' logged %d times over three pulls, want once:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "component=statestore") {
		t.Errorf("the failure is not a Warn of component=statestore:\n%s", logs.String())
	}

	s.dataDir = dir
	observe(context.Background(), fullPull())
	if n := strings.Count(logs.String(), `msg="stored state written again"`); n != 1 {
		t.Errorf("'stored state written again' logged %d times, want once:\n%s", n, logs.String())
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Errorf("no stored state after the write that succeeded: %v", err)
	}
}

// A pull with an empty secret inventory stores it as such: [] says the node
// may read nothing, which is not the null that keeps the stored inventory.
func TestStore_StoresAnEmptyInventory(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newTestStore(dir)
	observe := s.Observer(nil, nil)
	observe(context.Background(), fullPull())

	pull := fullPull()
	pull.Secrets = &[]api.NodeStateSecret{}
	observe(context.Background(), pull)

	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"secrets":[]`)) {
		t.Errorf("stored state after a pull with an empty inventory = %s, want \"secrets\":[]", raw)
	}
}
