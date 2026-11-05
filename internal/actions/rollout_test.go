package actions

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// The production types the installer is wired to satisfy its interfaces, and
// Handle is a dispatch handler the reconciler can register.
var (
	_ HookVersionFetcher        = (*api.ControlPlane)(nil)
	_ HookSignatureVerifier     = (*api.Ed25519Verifier)(nil)
	_ reconcile.DispatchHandler = (*RolloutInstaller)(nil).Handle
)

const (
	rolloutTestKeyID   = "signing-domain-test-1"
	rolloutTestScope   = "domain:0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1"
	rolloutTestProject = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1"
	rolloutTestNodeID  = "node-1"
)

// scriptHex is the lowercase hex SHA-256 of script, the form of the record
// and the executor's pins.
func scriptHex(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
}

// scriptWire is the SHA-256 of script in the wire form, standard base64 of
// the 32 raw bytes, the form of a pull entry's and a payload's checksum.
func scriptWire(script string) string {
	sum := sha256.Sum256([]byte(script))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// versionScript is the script of version of the hook name, distinct per pair
// so a test can tell which bytes landed.
func versionScript(name string, version int) string {
	return fmt.Sprintf("#!/bin/sh\necho %s v%d\n", name, version)
}

// hookFetchCall is one request the fake control plane answered.
type hookFetchCall struct {
	name    string
	version int
}

// fakeHookFetcher is the control plane's hook version fetch. It serves the
// versions a test published, answers 404 hook_not_assigned for any other
// pair, and records every request.
type fakeHookFetcher struct {
	mu       sync.Mutex
	versions map[hookFetchCall]*api.NodeHookVersion
	errs     map[hookFetchCall]error
	calls    []hookFetchCall
	nodeIDs  []string
	// hold, when set, runs before the answer, outside mu, and its error
	// becomes the answer. A test blocks a fetch in it.
	hold func(ctx context.Context, call hookFetchCall) error
}

func newFakeHookFetcher() *fakeHookFetcher {
	return &fakeHookFetcher{
		versions: make(map[hookFetchCall]*api.NodeHookVersion),
		errs:     make(map[hookFetchCall]error),
	}
}

func (f *fakeHookFetcher) FetchHookVersion(ctx context.Context, nodeID, name string, version int) (*api.NodeHookVersion, error) {
	call := hookFetchCall{name: name, version: version}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.nodeIDs = append(f.nodeIDs, nodeID)
	hv, err, hold := f.versions[call], f.errs[call], f.hold
	f.mu.Unlock()

	if hold != nil {
		if err := hold(ctx, call); err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	if hv == nil {
		return nil, &api.APIError{StatusCode: http.StatusNotFound, Code: "hook_not_assigned", Message: "hook version not assigned to node"}
	}
	served := *hv
	return &served, nil
}

func (f *fakeHookFetcher) serve(name string, version int, hv *api.NodeHookVersion) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions[hookFetchCall{name: name, version: version}] = hv
}

func (f *fakeHookFetcher) fail(name string, version int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[hookFetchCall{name: name, version: version}] = err
}

func (f *fakeHookFetcher) setHold(hold func(ctx context.Context, call hookFetchCall) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hold = hold
}

func (f *fakeHookFetcher) getCalls() []hookFetchCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// rolloutLogs captures the installer's JSON log lines.
type rolloutLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *rolloutLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// records returns every record logged with msg, decoded.
func (l *rolloutLogs) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	l.mu.Lock()
	data := l.buf.String()
	l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// wantLogged fails the test unless msg was logged exactly n times, each at
// level.
func (l *rolloutLogs) wantLogged(t *testing.T, msg, level string, n int) []map[string]any {
	t.Helper()
	recs := l.records(t, msg)
	if len(recs) != n {
		t.Errorf("%q logged %d times, want %d", msg, len(recs), n)
	}
	for _, rec := range recs {
		if rec["level"] != level {
			t.Errorf("%q logged at %v, want %s", msg, rec["level"], level)
		}
	}
	return recs
}

// rolloutHarness is a RolloutInstaller over temporary directories, fed by a
// fake control plane whose versions are signed with a real Domain key and
// checked by a real api.Ed25519Verifier.
type rolloutHarness struct {
	t *testing.T

	hooksDir, dataDir, rolloutDir string

	priv     ed25519.PrivateKey
	verifier *api.Ed25519Verifier
	fetcher  *fakeHookFetcher
	logs     *rolloutLogs
	changes  atomic.Int32

	// newExec builds the executor open hands the installer. The default
	// verifies every hook, so the tests here are about the installer alone.
	newExec func(cfg Config) *Executor

	exec *Executor
	inst *RolloutInstaller
}

// newRolloutHarness returns a harness whose installer models a Linux node,
// with the rollout directory at <data dir>/hooks as plexd derives it. edit,
// when set, changes the actions config.
func newRolloutHarness(t *testing.T, edit func(*Config)) *rolloutHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dataDir := t.TempDir()
	h := &rolloutHarness{
		t:          t,
		hooksDir:   t.TempDir(),
		dataDir:    dataDir,
		rolloutDir: filepath.Join(dataDir, "hooks"),
		priv:       priv,
		verifier:   api.NewEd25519Verifier(rolloutTestKeyID, pub),
		fetcher:    newFakeHookFetcher(),
		logs:       &rolloutLogs{},
		newExec: func(cfg Config) *Executor {
			return newTestExecutor(cfg, &mockReporter{}, &mockVerifier{ok: true})
		},
	}
	h.open(edit)
	return h
}

// open builds a fresh executor and installer over the harness's directories,
// as a restart of plexd would. The caller runs Load.
func (h *rolloutHarness) open(edit func(*Config)) {
	h.t.Helper()
	cfg := Config{HooksDir: h.hooksDir, RolloutHooksDir: h.rolloutDir}
	if edit != nil {
		edit(&cfg)
	}
	h.exec = h.newExec(cfg)
	logger := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	inst, err := NewRolloutInstaller(cfg, h.dataDir, rolloutTestNodeID, h.fetcher, h.verifier, h.exec, logger)
	if err != nil {
		h.t.Fatalf("NewRolloutInstaller: %v", err)
	}
	// Every platform runs the installer's logic here; the Windows refusal
	// has a test of its own.
	inst.goos = "linux"
	inst.SetOnChange(func() { h.changes.Add(1) })
	h.inst = inst
}

func (h *rolloutHarness) load() {
	h.t.Helper()
	if err := h.inst.Load(); err != nil {
		h.t.Fatalf("Load: %v", err)
	}
}

// pass runs one pass of the installer on block.
func (h *rolloutHarness) pass(block ...api.NodeStateHook) {
	h.t.Helper()
	if block == nil {
		block = []api.NodeStateHook{}
	}
	h.inst.pass(context.Background(), block)
}

// sign returns an envelope of type typ carrying payload, signed the way the
// control plane signs a hook version. issued_at is 30 days back, as for a
// version published long before the fetch.
func (h *rolloutHarness) sign(typ string, payload json.RawMessage) api.Envelope {
	h.t.Helper()
	env := api.Envelope{
		ID:       "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f1",
		Type:     typ,
		Scope:    rolloutTestScope,
		KeyID:    rolloutTestKeyID,
		IssuedAt: time.Now().Add(-30 * 24 * time.Hour).UTC(),
		Payload:  payload,
	}
	msg, err := api.SignedMessage(env)
	if err != nil {
		h.t.Fatalf("signed message: %v", err)
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(h.priv, msg))
	return env
}

// version returns version of the hook name with script as the control plane
// serves it, after edit changed the payload, and the pull entry that lists it.
func (h *rolloutHarness) version(name string, version int, script string, edit func(*api.HookVersionPayload)) (*api.NodeHookVersion, api.NodeStateHook) {
	h.t.Helper()
	payload := api.HookVersionPayload{
		ProjectID:    rolloutTestProject,
		Name:         name,
		Version:      version,
		Checksum:     scriptWire(script),
		SandboxLevel: "none",
	}
	if edit != nil {
		edit(&payload)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		h.t.Fatalf("encode payload: %v", err)
	}
	hv := &api.NodeHookVersion{
		Envelope:     h.sign(api.HookVersionEnvelopeType, raw),
		ScriptBase64: base64.StdEncoding.EncodeToString([]byte(script)),
	}
	return hv, api.NodeStateHook{Name: name, Version: version, Checksum: scriptWire(script)}
}

// publish serves version of the hook name with versionScript's script and
// returns its pull entry.
func (h *rolloutHarness) publish(name string, version int, edit func(*api.HookVersionPayload)) api.NodeStateHook {
	h.t.Helper()
	hv, entry := h.version(name, version, versionScript(name, version), edit)
	h.fetcher.serve(name, version, hv)
	return entry
}

// install publishes and installs version of the hook name, failing the test
// unless the pass leaves it installed.
func (h *rolloutHarness) install(name string, version int, block ...api.NodeStateHook) api.NodeStateHook {
	h.t.Helper()
	entry := h.publish(name, version, nil)
	h.pass(append(block, entry)...)
	h.wantInstalled(name, version)
	return entry
}

// pin returns the executor's rollout pin of name.
func (h *rolloutHarness) pin(name string) (rolloutPin, bool) {
	h.exec.mu.Lock()
	defer h.exec.mu.Unlock()
	pin, ok := h.exec.rolloutPins[name]
	return pin, ok
}

// pins returns the names the executor holds a rollout pin for.
func (h *rolloutHarness) pins() []string {
	h.exec.mu.Lock()
	defer h.exec.mu.Unlock()
	names := make([]string, 0, len(h.exec.rolloutPins))
	for name := range h.exec.rolloutPins {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// savedRecord returns the record on disk, decoded.
func (h *rolloutHarness) savedRecord() rolloutRecord {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dataDir, rolloutRecordFile))
	if err != nil {
		h.t.Fatalf("read record: %v", err)
	}
	var rec rolloutRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		h.t.Fatalf("decode record %s: %v", data, err)
	}
	return rec
}

// wantSavedRecord fails the test unless the record on disk lists exactly the
// installed versions of want, by name.
func (h *rolloutHarness) wantSavedRecord(want ...rolloutRecordEntry) {
	h.t.Helper()
	if want == nil {
		want = []rolloutRecordEntry{}
	}
	if got := h.savedRecord().Hooks; !reflect.DeepEqual(got, want) {
		h.t.Errorf("saved record = %+v, want %+v", got, want)
	}
}

// recorded is the record entry of version of the hook name with
// versionScript's script.
func recorded(name string, version int) rolloutRecordEntry {
	return rolloutRecordEntry{Name: name, Version: version, Checksum: scriptHex(versionScript(name, version))}
}

// wantInstalled fails the test unless version of the hook name is on disk,
// in the record and pinned.
func (h *rolloutHarness) wantInstalled(name string, version int) {
	h.t.Helper()
	script := versionScript(name, version)
	if got := readRolloutFile(h.t, filepath.Join(h.rolloutDir, name)); got != script {
		h.t.Errorf("%s script = %q, want %q", name, got, script)
	}
	if rec, ok := h.inst.record[name]; !ok || rec != recorded(name, version) {
		h.t.Errorf("record entry of %s = %+v (present %v), want %+v", name, rec, ok, recorded(name, version))
	}
	want := rolloutPin{version: version, checksum: scriptHex(script)}
	if pin, ok := h.pin(name); !ok || pin != want {
		h.t.Errorf("pin of %s = %+v (present %v), want %+v", name, pin, ok, want)
	}
}

// wantNotInstalled fails the test unless the hook name has no file in the
// rollout directory, no record entry and no pin.
func (h *rolloutHarness) wantNotInstalled(name string) {
	h.t.Helper()
	for _, file := range []string{name, name + ".json"} {
		if _, err := os.Lstat(filepath.Join(h.rolloutDir, file)); !errors.Is(err, os.ErrNotExist) {
			h.t.Errorf("%s in the rollout directory: Lstat error %v, want it gone", file, err)
		}
	}
	if rec, ok := h.inst.record[name]; ok {
		h.t.Errorf("record entry of %s = %+v, want none", name, rec)
	}
	if pin, ok := h.pin(name); ok {
		h.t.Errorf("pin of %s = %+v, want none", name, pin)
	}
}

// rolloutFiles returns the names in the rollout directory.
func (h *rolloutHarness) rolloutFiles() []string {
	h.t.Helper()
	entries, err := os.ReadDir(h.rolloutDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		h.t.Fatalf("read rollout directory: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// wantFetches fails the test unless the control plane answered exactly want,
// in order, since the harness was built.
func (h *rolloutHarness) wantFetches(want ...hookFetchCall) {
	h.t.Helper()
	if want == nil {
		want = []hookFetchCall{}
	}
	got := h.fetcher.getCalls()
	if got == nil {
		got = []hookFetchCall{}
	}
	if !reflect.DeepEqual(got, want) {
		h.t.Errorf("fetches = %+v, want %+v", got, want)
	}
}

// wantErrors fails the test unless Errors returns exactly want.
func (h *rolloutHarness) wantErrors(want ...api.HookRolloutError) {
	h.t.Helper()
	if got := h.inst.Errors(); !reflect.DeepEqual(got, want) {
		h.t.Errorf("Errors() = %+v, want %+v", got, want)
	}
}

// wantChanges fails the test unless onChange was called n times.
func (h *rolloutHarness) wantChanges(n int) {
	h.t.Helper()
	if got := h.changes.Load(); int(got) != n {
		h.t.Errorf("onChange calls = %d, want %d", got, n)
	}
}

// runInstaller starts Run and returns a stop that ends it and waits for it to
// return. The test's cleanup calls stop too, so goleak finds no Run left.
func runInstaller(t *testing.T, inst *RolloutInstaller) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- inst.Run(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run = %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("Run did not return after its context ended")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func readRolloutFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// writeHandPlaced writes a file into hooks_dir as an operator would and
// returns its bytes.
func writeHandPlaced(t *testing.T, dir, name, content string) []byte {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return []byte(content)
}

// TestNewRolloutInstaller_RefusesSharedDirectory checks that the installer
// will not own hooks_dir: it removes every file it did not write from its
// directory, which there would be the operator's hooks.
func TestNewRolloutInstaller_RefusesSharedDirectory(t *testing.T) {
	base := t.TempDir()
	exec := newTestExecutor(Config{}, &mockReporter{}, &mockVerifier{ok: true})
	tests := []struct {
		name               string
		hooksDir, rollouts string
	}{
		{"same path", filepath.Join(base, "hooks"), filepath.Join(base, "hooks")},
		{"trailing separator", filepath.Join(base, "hooks") + string(filepath.Separator), filepath.Join(base, "hooks")},
		{"dot segment", filepath.Join(base, "hooks"), base + string(filepath.Separator) + "." + string(filepath.Separator) + "hooks"},
		{"parent segment", filepath.Join(base, "hooks"), filepath.Join(base, "x") + string(filepath.Separator) + ".." + string(filepath.Separator) + "hooks"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{HooksDir: tt.hooksDir, RolloutHooksDir: tt.rollouts}
			inst, err := NewRolloutInstaller(cfg, base, rolloutTestNodeID, newFakeHookFetcher(), &api.Ed25519Verifier{}, exec, testLogger())
			if err == nil {
				t.Fatalf("NewRolloutInstaller(%q, %q) = %v, want an error", tt.hooksDir, tt.rollouts, inst)
			}
			if inst != nil {
				t.Errorf("installer = %v, want nil with the error", inst)
			}
		})
	}

	t.Run("distinct directories", func(t *testing.T) {
		cfg := Config{HooksDir: filepath.Join(base, "etc-hooks"), RolloutHooksDir: filepath.Join(base, "hooks")}
		if _, err := NewRolloutInstaller(cfg, base, rolloutTestNodeID, newFakeHookFetcher(), &api.Ed25519Verifier{}, exec, testLogger()); err != nil {
			t.Fatalf("NewRolloutInstaller: %v", err)
		}
	})
}

// TestRolloutInstaller_InstallsListedVersion checks the install of a listed
// version: one fetch, verified under the real Domain key although it was
// signed 30 days ago, the script and a sidecar in plexd's format, the record,
// the pin, no errors and one onChange call. rollout_unix_test.go checks the
// file modes.
func TestRolloutInstaller_InstallsListedVersion(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	entry := h.publish("backup-db", 2, func(p *api.HookVersionPayload) {
		p.Description = "Dump the application database to /var/backups."
		p.Parameters = []api.ActionParam{{Name: "database", Type: "string", Description: "Database to dump."}}
		p.TimeoutSeconds = 600
	})

	h.pass(entry)

	h.wantFetches(hookFetchCall{"backup-db", 2})
	h.fetcher.mu.Lock()
	nodeIDs := slices.Clone(h.fetcher.nodeIDs)
	h.fetcher.mu.Unlock()
	if got := nodeIDs; !reflect.DeepEqual(got, []string{rolloutTestNodeID}) {
		t.Errorf("fetched for nodes %v, want [%s]", got, rolloutTestNodeID)
	}
	h.wantInstalled("backup-db", 2)

	var sidecar map[string]any
	if err := json.Unmarshal([]byte(readRolloutFile(t, filepath.Join(h.rolloutDir, "backup-db.json"))), &sidecar); err != nil {
		t.Fatalf("decode sidecar: %v", err)
	}
	wantSidecar := map[string]any{
		"description": "Dump the application database to /var/backups.",
		"parameters": []any{map[string]any{
			"name": "database", "type": "string", "required": false, "description": "Database to dump.",
		}},
		"timeout": "600s",
		"sandbox": "none",
	}
	if !reflect.DeepEqual(sidecar, wantSidecar) {
		t.Errorf("sidecar = %v, want %v", sidecar, wantSidecar)
	}

	wantRecord := `{"hooks":[{"name":"backup-db","version":2,"checksum":"` + scriptHex(versionScript("backup-db", 2)) + `"}]}`
	if got := readRolloutFile(t, filepath.Join(h.dataDir, rolloutRecordFile)); got != wantRecord {
		t.Errorf("record = %s, want %s", got, wantRecord)
	}

	if got := h.inst.Errors(); got != nil {
		t.Errorf("Errors() = %+v, want nil", got)
	}
	h.wantChanges(1)
	h.logs.wantLogged(t, "actions: rollout: hook installed", "INFO", 1)
	if got := h.rolloutFiles(); !reflect.DeepEqual(got, []string{"backup-db", "backup-db.json"}) {
		t.Errorf("rollout directory = %v, want the script and its sidecar alone", got)
	}
}

// TestRolloutInstaller_SidecarOmitsEmptyFields checks that a version which
// declares no metadata gets a sidecar of the sandbox level alone.
func TestRolloutInstaller_SidecarOmitsEmptyFields(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 1)
	if got, want := readRolloutFile(t, filepath.Join(h.rolloutDir, "backup-db.json")), `{"sandbox":"none"}`; got != want {
		t.Errorf("sidecar = %s, want %s", got, want)
	}
}

// TestRolloutInstaller_SecondPassSameBlockIsANoOp checks that a pass on the
// block that is already installed fetches nothing and reports no change.
func TestRolloutInstaller_SecondPassSameBlockIsANoOp(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	entry := h.install("backup-db", 1)
	h.wantChanges(1)

	h.pass(entry)

	h.wantFetches(hookFetchCall{"backup-db", 1})
	h.wantChanges(1)
	h.wantInstalled("backup-db", 1)
}

// TestRolloutInstaller_MissingScriptIsFetchedAgain checks that a recorded
// hook whose script is gone counts as not installed, so the next pass fetches
// and installs it again.
func TestRolloutInstaller_MissingScriptIsFetchedAgain(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	entry := h.install("backup-db", 1)
	if err := os.Remove(filepath.Join(h.rolloutDir, "backup-db")); err != nil {
		t.Fatal(err)
	}

	h.pass(entry)

	h.wantFetches(hookFetchCall{"backup-db", 1}, hookFetchCall{"backup-db", 1})
	h.wantInstalled("backup-db", 1)
	h.wantErrors()
}

// TestRolloutInstaller_UpgradesToListedVersion checks that a block listing a
// new version replaces the installed one with one fetch.
func TestRolloutInstaller_UpgradesToListedVersion(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 1)

	h.pass(h.publish("backup-db", 2, nil))

	h.wantFetches(hookFetchCall{"backup-db", 1}, hookFetchCall{"backup-db", 2})
	h.wantInstalled("backup-db", 2)
	h.wantSavedRecord(recorded("backup-db", 2))
	h.wantChanges(2)
	h.wantErrors()
}

// TestRolloutInstaller_NilHooksBlockRunsNoPass checks that a pull whose hooks
// block is null, a control plane that could not compute the set, changes
// nothing: Handle hands nothing to Run, so nothing is fetched or removed, and
// the errors stay those of the last pass.
func TestRolloutInstaller_NilHooksBlockRunsNoPass(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	installed := h.install("backup-db", 1)
	failing := api.NodeStateHook{Name: "rotate-logs", Version: 1, Checksum: scriptWire("unpublished")}
	h.pass(installed, failing)
	before := h.inst.Errors()
	if len(before) != 1 || before[0].Code != api.HookRolloutCodeFetchFailed {
		t.Fatalf("Errors() = %+v, want one fetch_failed", before)
	}
	fetches := h.fetcher.getCalls()

	h.inst.Handle(context.Background(), &api.NodeStateSnapshot{Hooks: nil})

	if len(h.inst.signal) != 0 {
		t.Error("Handle signalled Run for a nil hooks block")
	}
	h.inst.mu.Lock()
	hasPending := h.inst.hasPending
	h.inst.mu.Unlock()
	if hasPending {
		t.Error("Handle left a pending block for a nil hooks block")
	}
	h.wantFetches(fetches...)
	h.wantInstalled("backup-db", 1)
	h.wantErrors(before...)
	h.logs.wantLogged(t, "actions: rollout: pull carried no hooks block; keeping rolled-out hooks", "DEBUG", 1)
}

// TestRolloutInstaller_EmptyBlockRemovesEverything checks that "hooks":[]
// removes every rolled-out script, sidecar, record entry and pin, and leaves
// hooks_dir alone.
func TestRolloutInstaller_EmptyBlockRemovesEverything(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	local := writeHandPlaced(t, h.hooksDir, "local-hook", "#!/bin/sh\necho local\n")
	localSidecar := []byte(`{"description":"hand-placed"}`)
	if err := os.WriteFile(filepath.Join(h.hooksDir, "local-hook.json"), localSidecar, 0o644); err != nil {
		t.Fatal(err)
	}
	backup := h.install("backup-db", 1)
	h.install("rotate-logs", 3, backup)
	changes := h.changes.Load()

	h.inst.Handle(context.Background(), &api.NodeStateSnapshot{Hooks: &[]api.NodeStateHook{}})
	h.inst.mu.Lock()
	block, ok := h.inst.pending, h.inst.hasPending
	h.inst.mu.Unlock()
	if !ok || block == nil || len(block) != 0 {
		t.Fatalf("pending block = %v (present %v), want an empty block", block, ok)
	}
	h.pass(block...)

	h.wantNotInstalled("backup-db")
	h.wantNotInstalled("rotate-logs")
	if got := h.rolloutFiles(); len(got) != 0 {
		t.Errorf("rollout directory = %v, want empty", got)
	}
	if got := h.pins(); len(got) != 0 {
		t.Errorf("pins = %v, want none", got)
	}
	h.wantSavedRecord()
	h.logs.wantLogged(t, "actions: rollout: hook removed", "INFO", 2)
	if got := h.changes.Load(); got != changes+1 {
		t.Errorf("onChange calls = %d, want %d", got, changes+1)
	}

	if got := readRolloutFile(t, filepath.Join(h.hooksDir, "local-hook")); got != string(local) {
		t.Errorf("hand-placed hook = %q, want it unchanged %q", got, local)
	}
	if got := readRolloutFile(t, filepath.Join(h.hooksDir, "local-hook.json")); got != string(localSidecar) {
		t.Errorf("hand-placed sidecar = %q, want it unchanged %q", got, localSidecar)
	}
}

// TestRolloutInstaller_DropsInvalidEntriesOnce checks that an entry with a
// name off the grammar, a version below 1, or a repeated name is dropped
// with one WARN, not again on the next pass with the same block, and with no
// rollout error, while the valid entries of the block install.
func TestRolloutInstaller_DropsInvalidEntriesOnce(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	valid := h.publish("rotate-logs", 1, nil)
	other := h.publish("zz-report", 1, nil)
	block := []api.NodeStateHook{
		{Name: "Backup", Version: 1, Checksum: scriptWire("x")},
		{Name: "backup-db", Version: 0, Checksum: scriptWire("x")},
		valid,
		{Name: "rotate-logs", Version: 2, Checksum: scriptWire("x")},
		other,
	}

	h.pass(block...)

	recs := h.logs.wantLogged(t, "actions: rollout: entry dropped", "WARN", 3)
	var got []string
	for _, rec := range recs {
		got = append(got, fmt.Sprintf("%v/%v/%v", rec["name"], rec["version"], rec["reason"]))
	}
	want := []string{"Backup/1/invalid name", "backup-db/0/invalid version", "rotate-logs/2/duplicate name"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dropped = %v, want %v", got, want)
	}
	h.wantErrors()
	h.wantInstalled("rotate-logs", 1)
	h.wantInstalled("zz-report", 1)
	h.wantFetches(hookFetchCall{"rotate-logs", 1}, hookFetchCall{"zz-report", 1})

	h.pass(block...)
	h.logs.wantLogged(t, "actions: rollout: entry dropped", "WARN", 3)
	h.wantErrors()

	// A changed set of dropped entries is logged again.
	h.pass(block[1:]...)
	h.logs.wantLogged(t, "actions: rollout: entry dropped", "WARN", 5)
}

// TestRolloutInstaller_DroppedEntryKeepsInstalledHook checks that an entry
// dropped for its version still lists its name, so the installed hook of that
// name stays and nothing is removed.
func TestRolloutInstaller_DroppedEntryKeepsInstalledHook(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 1)
	changes := h.changes.Load()

	h.pass(api.NodeStateHook{Name: "backup-db", Version: 0, Checksum: scriptWire(versionScript("backup-db", 1))})

	h.wantInstalled("backup-db", 1)
	h.wantSavedRecord(recorded("backup-db", 1))
	h.logs.wantLogged(t, "actions: rollout: hook removed", "INFO", 0)
	h.wantFetches(hookFetchCall{"backup-db", 1})
	h.wantErrors()
	if got := h.changes.Load(); got != changes {
		t.Errorf("onChange calls = %d, want %d", got, changes)
	}
}

// TestRolloutInstaller_BadPullChecksum checks that a pull entry whose
// checksum is not a SHA-256 digest gets verification_failed without a fetch,
// and keeps the version of that name that is installed.
func TestRolloutInstaller_BadPullChecksum(t *testing.T) {
	checksums := map[string]string{
		"not base64":    "not base64!",
		"31 bytes":      base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"hex digest":    scriptHex("x"),
		"empty":         "",
		"unpadded":      strings.TrimRight(scriptWire("x"), "="),
		"url alphabet":  base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)),
		"trailing data": scriptWire("x") + "AA==",
	}
	for name, checksum := range checksums {
		t.Run(name, func(t *testing.T) {
			h := newRolloutHarness(t, nil)
			h.load()
			h.install("backup-db", 1)
			h.publish("backup-db", 2, nil)

			h.pass(api.NodeStateHook{Name: "backup-db", Version: 2, Checksum: checksum})

			h.wantErrors(api.HookRolloutError{
				Name: "backup-db", Version: 2, Code: api.HookRolloutCodeVerificationFailed,
				Detail: "pull entry checksum is not 32 bytes of standard base64",
			})
			h.wantFetches(hookFetchCall{"backup-db", 1})
			h.wantInstalled("backup-db", 1)
		})
	}
}

// TestRolloutInstaller_FetchFailedKeepsInstalledVersion checks that a fetch
// the control plane refuses gets fetch_failed with its error, keeps the
// installed version, and is tried again on the next pass.
func TestRolloutInstaller_FetchFailedKeepsInstalledVersion(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 1)
	// Version 2 is listed but not served, so the fake answers 404
	// hook_not_assigned.
	entry := api.NodeStateHook{Name: "backup-db", Version: 2, Checksum: scriptWire(versionScript("backup-db", 2))}

	h.pass(entry)

	errs := h.inst.Errors()
	if len(errs) != 1 || errs[0].Name != "backup-db" || errs[0].Version != 2 || errs[0].Code != api.HookRolloutCodeFetchFailed {
		t.Fatalf("Errors() = %+v, want one fetch_failed for backup-db version 2", errs)
	}
	if !strings.Contains(errs[0].Detail, "hook_not_assigned") {
		t.Errorf("detail = %q, want it to contain hook_not_assigned", errs[0].Detail)
	}
	h.wantInstalled("backup-db", 1)
	h.logs.wantLogged(t, "actions: rollout: fetch failed", "WARN", 1)

	h.pass(entry)
	h.wantFetches(hookFetchCall{"backup-db", 1}, hookFetchCall{"backup-db", 2}, hookFetchCall{"backup-db", 2})
	h.wantInstalled("backup-db", 1)

	// Once the control plane serves it, the next pass installs it and the
	// error clears.
	h.pass(h.publish("backup-db", 2, nil))
	h.wantInstalled("backup-db", 2)
	h.wantErrors()
}

// TestRolloutInstaller_FetchFailedDetailIsStable checks that the detail of a
// fetch_failed error leaves out the correlation_id the control plane gives
// every request, bare or wrapped. A fetch that keeps failing the same way then
// changes no error and calls onChange once, so it sends no new manifest on
// every pass. The WARN keeps the id for the operator.
func TestRolloutInstaller_FetchFailedDetailIsStable(t *testing.T) {
	wrappings := map[string]func(error) error{
		"bare":    func(err error) error { return err },
		"wrapped": func(err error) error { return fmt.Errorf("api: request: %w", err) },
	}
	for name, wrap := range wrappings {
		t.Run(name, func(t *testing.T) {
			h := newRolloutHarness(t, nil)
			h.load()
			entry := api.NodeStateHook{Name: "backup-db", Version: 1, Checksum: scriptWire(versionScript("backup-db", 1))}
			refusal := func(correlationID string) error {
				return wrap(&api.APIError{
					StatusCode: http.StatusNotFound, Code: "hook_not_assigned",
					Message: "hook version not assigned to node", CorrelationID: correlationID,
				})
			}
			want := api.HookRolloutError{
				Name: "backup-db", Version: 1, Code: api.HookRolloutCodeFetchFailed,
				Detail: wrap(errors.New("api: HTTP 404 (hook_not_assigned): hook version not assigned to node")).Error(),
			}
			ids := []string{"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d2"}

			for _, id := range ids {
				h.fetcher.fail("backup-db", 1, refusal(id))
				h.pass(entry)
				h.wantErrors(want)
			}

			h.wantChanges(1)
			recs := h.logs.wantLogged(t, "actions: rollout: fetch failed", "WARN", len(ids))
			for i, rec := range recs {
				if got := fmt.Sprint(rec["error"]); !strings.Contains(got, "(correlation_id="+ids[i]+")") {
					t.Errorf("WARN %d error = %q, want the correlation_id %s", i, got, ids[i])
				}
			}
		})
	}
}

// TestRolloutInstaller_InstalledVersionUnderOtherChecksum checks that the
// installed rule compares the checksum as well as the version: a pull that
// lists the installed version with another checksum fetches that version
// again, and a version that does not match the pull keeps the installed one.
func TestRolloutInstaller_InstalledVersionUnderOtherChecksum(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	h.install("backup-db", 2)

	h.pass(api.NodeStateHook{Name: "backup-db", Version: 2, Checksum: scriptWire("#!/bin/sh\necho other\n")})

	h.wantFetches(hookFetchCall{"backup-db", 2}, hookFetchCall{"backup-db", 2})
	h.wantErrors(api.HookRolloutError{
		Name: "backup-db", Version: 2, Code: api.HookRolloutCodeVerificationFailed,
		Detail: "payload checksum does not match the pull checksum",
	})
	h.wantInstalled("backup-db", 2)
	h.wantSavedRecord(recorded("backup-db", 2))
}

// TestRolloutInstaller_EditedScriptIsNotRepaired checks that a pass compares
// the pull with the record, never with the bytes on disk: an installed script
// edited in place is not fetched again or rewritten. It stays pinned to the
// delivered checksum, which refuses it at dispatch, until a new version or a
// withdrawal replaces it.
func TestRolloutInstaller_EditedScriptIsNotRepaired(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	entry := h.install("backup-db", 1)
	changes := h.changes.Load()
	path := filepath.Join(h.rolloutDir, "backup-db")
	edited := versionScript("backup-db", 1) + "echo tampered\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("echo tampered\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	h.pass(entry)

	h.wantFetches(hookFetchCall{"backup-db", 1})
	h.wantErrors()
	if got := readRolloutFile(t, path); got != edited {
		t.Errorf("script = %q, want the edited bytes %q left alone", got, edited)
	}
	want := rolloutPin{version: 1, checksum: scriptHex(versionScript("backup-db", 1))}
	if pin, ok := h.pin("backup-db"); !ok || pin != want {
		t.Errorf("pin = %+v (present %v), want the delivered %+v", pin, ok, want)
	}
	h.wantSavedRecord(recorded("backup-db", 1))
	if got := h.changes.Load(); got != changes {
		t.Errorf("onChange calls = %d, want %d", got, changes)
	}
}

// TestRolloutInstaller_FetchDeadline checks that a fetch that runs out of
// time gets fetch_failed, both when the fetcher reports the deadline and
// when the installer's own fetch timeout ends the request.
func TestRolloutInstaller_FetchDeadline(t *testing.T) {
	entry := api.NodeStateHook{Name: "backup-db", Version: 1, Checksum: scriptWire(versionScript("backup-db", 1))}

	t.Run("fetcher returns the deadline", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		h.fetcher.fail("backup-db", 1, context.DeadlineExceeded)

		h.pass(entry)

		h.wantErrors(api.HookRolloutError{
			Name: "backup-db", Version: 1, Code: api.HookRolloutCodeFetchFailed, Detail: context.DeadlineExceeded.Error(),
		})
		h.wantNotInstalled("backup-db")
	})

	t.Run("fetch timeout ends the request", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		h.inst.fetchTimeout = 50 * time.Millisecond
		h.fetcher.setHold(func(ctx context.Context, _ hookFetchCall) error {
			<-ctx.Done()
			return ctx.Err()
		})

		h.pass(entry)

		h.wantErrors(api.HookRolloutError{
			Name: "backup-db", Version: 1, Code: api.HookRolloutCodeFetchFailed, Detail: context.DeadlineExceeded.Error(),
		})
		h.wantNotInstalled("backup-db")
	})
}

// TestRolloutInstaller_VerificationFailures checks each check a fetched
// version has to pass: a failure gets verification_failed naming the check,
// writes nothing, and logs at ERROR.
func TestRolloutInstaller_VerificationFailures(t *testing.T) {
	const name = "backup-db"
	script := versionScript(name, 2)
	other := "#!/bin/sh\necho other\n"

	tests := []struct {
		name string
		// serve returns the version the control plane serves for the pull
		// entry of script.
		serve      func(h *rolloutHarness) *api.NodeHookVersion
		wantDetail string
	}{
		{
			name: "type other than hook_version",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				hv, _ := h.version(name, 2, script, nil)
				hv.Envelope = h.sign("hook_published", hv.Envelope.Payload)
				return hv
			},
			wantDetail: `envelope type "hook_published" is not hook_version`,
		},
		{
			name: "payload that is not a JSON object",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				hv, _ := h.version(name, 2, script, nil)
				hv.Envelope = h.sign(api.HookVersionEnvelopeType, json.RawMessage(`["backup-db",2]`))
				return hv
			},
			wantDetail: "payload does not decode",
		},
		{
			name: "payload name other than the fetched one",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				hv, _ := h.version(name, 2, script, func(p *api.HookVersionPayload) { p.Name = "rotate-logs" })
				return hv
			},
			wantDetail: `payload names "rotate-logs" version 2, not the fetched "backup-db" version 2`,
		},
		{
			name: "payload version other than the fetched one",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				hv, _ := h.version(name, 2, script, func(p *api.HookVersionPayload) { p.Version = 1 })
				return hv
			},
			wantDetail: `payload names "backup-db" version 1, not the fetched "backup-db" version 2`,
		},
		{
			name: "VerifySignature error",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				hv, _ := h.version(name, 2, script, nil)
				sig, err := base64.StdEncoding.DecodeString(hv.Envelope.Signature)
				if err != nil {
					h.t.Fatal(err)
				}
				sig[0] ^= 0x01
				hv.Envelope.Signature = base64.StdEncoding.EncodeToString(sig)
				return hv
			},
			wantDetail: "signature: api: verifier: signature verification failed",
		},
		{
			name: "script_base64 that is not base64",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				hv, _ := h.version(name, 2, script, nil)
				hv.ScriptBase64 = "#!/bin/sh"
				return hv
			},
			wantDetail: "script_base64 does not decode",
		},
		{
			name: "script SHA-256 other than the payload checksum",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				hv, _ := h.version(name, 2, script, nil)
				hv.ScriptBase64 = base64.StdEncoding.EncodeToString([]byte(script + "echo tampered\n"))
				return hv
			},
			wantDetail: "script SHA-256 does not match the payload checksum",
		},
		{
			name: "payload checksum other than the pull checksum",
			serve: func(h *rolloutHarness) *api.NodeHookVersion {
				// A consistent version of other bytes: the script matches its
				// payload, and neither matches what the pull listed.
				hv, _ := h.version(name, 2, other, nil)
				return hv
			},
			wantDetail: "payload checksum does not match the pull checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRolloutHarness(t, nil)
			h.load()
			h.fetcher.serve(name, 2, tt.serve(h))

			h.pass(api.NodeStateHook{Name: name, Version: 2, Checksum: scriptWire(script)})

			errs := h.inst.Errors()
			if len(errs) != 1 || errs[0].Name != name || errs[0].Version != 2 || errs[0].Code != api.HookRolloutCodeVerificationFailed {
				t.Fatalf("Errors() = %+v, want one verification_failed for %s version 2", errs, name)
			}
			if !strings.HasPrefix(errs[0].Detail, tt.wantDetail) {
				t.Errorf("detail = %q, want it to start with %q", errs[0].Detail, tt.wantDetail)
			}
			if got := h.rolloutFiles(); len(got) != 0 {
				t.Errorf("rollout directory = %v, want nothing written", got)
			}
			h.wantNotInstalled(name)
			h.wantSavedRecordAbsentOrEmpty()
			h.logs.wantLogged(t, "actions: rollout: verification failed", "ERROR", 1)
			h.wantChanges(1)
		})
	}
}

// wantSavedRecordAbsentOrEmpty fails the test unless the record on disk lists
// no hook, if there is one.
func (h *rolloutHarness) wantSavedRecordAbsentOrEmpty() {
	h.t.Helper()
	if _, err := os.Stat(filepath.Join(h.dataDir, rolloutRecordFile)); errors.Is(err, os.ErrNotExist) {
		return
	}
	h.wantSavedRecord()
}

// TestRolloutInstaller_UnsupportedPayload checks that a verified version
// plexd cannot honour gets install_failed and writes nothing.
func TestRolloutInstaller_UnsupportedPayload(t *testing.T) {
	tests := []struct {
		name       string
		edit       func(*api.HookVersionPayload)
		wantDetail string
	}{
		{
			name:       "sandbox level container",
			edit:       func(p *api.HookVersionPayload) { p.SandboxLevel = "container" },
			wantDetail: `sandbox level "container" is not implemented`,
		},
		{
			name:       "timeout_seconds 86401",
			edit:       func(p *api.HookVersionPayload) { p.TimeoutSeconds = 86401 },
			wantDetail: "timeout_seconds 86401 is outside the range 0 to 86400",
		},
		{
			name:       "negative timeout_seconds",
			edit:       func(p *api.HookVersionPayload) { p.TimeoutSeconds = -1 },
			wantDetail: "timeout_seconds -1 is outside the range 0 to 86400",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRolloutHarness(t, nil)
			h.load()

			h.pass(h.publish("backup-db", 1, tt.edit))

			h.wantErrors(api.HookRolloutError{
				Name: "backup-db", Version: 1, Code: api.HookRolloutCodeInstallFailed, Detail: tt.wantDetail,
			})
			if got := h.rolloutFiles(); len(got) != 0 {
				t.Errorf("rollout directory = %v, want nothing written", got)
			}
			h.wantNotInstalled("backup-db")
		})
	}

	t.Run("the largest timeout and an empty sandbox level install", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		h.pass(
			h.publish("backup-db", 1, func(p *api.HookVersionPayload) { p.TimeoutSeconds = 86400 }),
			h.publish("rotate-logs", 1, func(p *api.HookVersionPayload) { p.SandboxLevel = "" }),
		)
		h.wantErrors()
		h.wantInstalled("backup-db", 1)
		h.wantInstalled("rotate-logs", 1)
		sidecars := map[string]string{
			"backup-db.json":   `{"timeout":"86400s","sandbox":"none"}`,
			"rotate-logs.json": `{"sandbox":"none"}`,
		}
		for file, want := range sidecars {
			if got := readRolloutFile(t, filepath.Join(h.rolloutDir, file)); got != want {
				t.Errorf("%s = %s, want %s", file, got, want)
			}
		}
	})
}

// TestRolloutInstaller_CollisionWithHooksDir checks that a name hooks_dir
// holds blocks its rollout: collision without a fetch, plexd's own copy of
// the name removed, and the hand-placed file untouched.
func TestRolloutInstaller_CollisionWithHooksDir(t *testing.T) {
	t.Run("before any install", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		local := writeHandPlaced(t, h.hooksDir, "backup-db", "#!/bin/sh\necho hand-placed\n")

		h.pass(h.publish("backup-db", 1, nil))

		h.wantErrors(api.HookRolloutError{
			Name: "backup-db", Version: 1, Code: api.HookRolloutCodeCollision, Detail: "hooks_dir holds a hook of this name",
		})
		h.wantFetches()
		h.wantNotInstalled("backup-db")
		h.logs.wantLogged(t, "actions: rollout: name collision with hooks_dir", "WARN", 1)
		if got := readRolloutFile(t, filepath.Join(h.hooksDir, "backup-db")); got != string(local) {
			t.Errorf("hand-placed hook = %q, want it unchanged %q", got, local)
		}
	})

	t.Run("over an installed copy", func(t *testing.T) {
		h := newRolloutHarness(t, nil)
		h.load()
		entry := h.install("backup-db", 1)
		local := writeHandPlaced(t, h.hooksDir, "backup-db", "#!/bin/sh\necho hand-placed\n")

		h.pass(entry)

		h.wantErrors(api.HookRolloutError{
			Name: "backup-db", Version: 1, Code: api.HookRolloutCodeCollision, Detail: "hooks_dir holds a hook of this name",
		})
		h.wantFetches(hookFetchCall{"backup-db", 1})
		h.wantNotInstalled("backup-db")
		h.wantSavedRecord()
		h.logs.wantLogged(t, "actions: rollout: hook removed", "INFO", 1)
		if got := readRolloutFile(t, filepath.Join(h.hooksDir, "backup-db")); got != string(local) {
			t.Errorf("hand-placed hook = %q, want it unchanged %q", got, local)
		}

		// Once the operator removes the hand-placed hook, the next pass
		// installs the rollout.
		if err := os.Remove(filepath.Join(h.hooksDir, "backup-db")); err != nil {
			t.Fatal(err)
		}
		h.pass(entry)
		h.wantInstalled("backup-db", 1)
		h.wantErrors()
	})
}

// TestRolloutInstaller_ActionsDisabled checks a node whose actions are
// disabled: a listed version not installed gets install_failed with no
// fetch, an installed version the block still lists stays, and a withdrawn
// one is removed.
func TestRolloutInstaller_ActionsDisabled(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	alpha := h.install("alpha", 1)
	beta := h.install("beta", 1, alpha)
	h.install("gamma", 1, alpha, beta)
	fetches := h.fetcher.getCalls()

	h.open(func(cfg *Config) { cfg.Enabled = boolPtr(false) })
	h.load()
	h.pass(
		alpha,
		api.NodeStateHook{Name: "beta", Version: 2, Checksum: scriptWire(versionScript("beta", 2))},
		api.NodeStateHook{Name: "delta", Version: 1, Checksum: scriptWire(versionScript("delta", 1))},
	)

	h.wantErrors(
		api.HookRolloutError{Name: "beta", Version: 2, Code: api.HookRolloutCodeInstallFailed, Detail: "actions are disabled on this node"},
		api.HookRolloutError{Name: "delta", Version: 1, Code: api.HookRolloutCodeInstallFailed, Detail: "actions are disabled on this node"},
	)
	h.wantFetches(fetches...)
	h.wantInstalled("alpha", 1)
	h.wantInstalled("beta", 1)
	h.wantNotInstalled("gamma")
	h.wantNotInstalled("delta")
	h.wantSavedRecord(recorded("alpha", 1), recorded("beta", 1))
}

// TestRolloutInstaller_RolloutsDisabled checks the node owner's veto: Load
// removes every rolled-out hook and stray and saves an empty record, and a
// pass reports each listed version as install_failed with no fetch.
func TestRolloutInstaller_RolloutsDisabled(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	alpha := h.install("alpha", 1)
	h.install("beta", 2, alpha)
	stray := filepath.Join(h.rolloutDir, ".tmp-alpha-123")
	if err := os.WriteFile(stray, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	fetches := h.fetcher.getCalls()

	h.open(func(cfg *Config) { cfg.RolloutsEnabled = boolPtr(false) })
	h.load()

	if got := h.rolloutFiles(); len(got) != 0 {
		t.Errorf("rollout directory after Load = %v, want empty", got)
	}
	if got := h.pins(); len(got) != 0 {
		t.Errorf("pins after Load = %v, want none", got)
	}
	h.wantSavedRecord()
	h.logs.wantLogged(t, "actions: rollout: hook removed", "INFO", 2)
	h.logs.wantLogged(t, "actions: rollout: stray file removed", "INFO", 1)

	h.pass(alpha, api.NodeStateHook{Name: "beta", Version: 2, Checksum: scriptWire(versionScript("beta", 2))})

	h.wantErrors(
		api.HookRolloutError{Name: "alpha", Version: 1, Code: api.HookRolloutCodeInstallFailed, Detail: "rolled-out hooks are disabled on this node"},
		api.HookRolloutError{Name: "beta", Version: 2, Code: api.HookRolloutCodeInstallFailed, Detail: "rolled-out hooks are disabled on this node"},
	)
	h.wantFetches(fetches...)
	if got := h.rolloutFiles(); len(got) != 0 {
		t.Errorf("rollout directory after the pass = %v, want empty", got)
	}
}

// TestRolloutInstaller_RolloutsVetoComesBeforeCollision checks the rule
// order: with rolled-out hooks disabled, a listed name that hooks_dir also
// holds reports the veto, not a collision, and logs no collision WARN.
func TestRolloutInstaller_RolloutsVetoComesBeforeCollision(t *testing.T) {
	h := newRolloutHarness(t, func(cfg *Config) { cfg.RolloutsEnabled = boolPtr(false) })
	h.load()
	writeHandPlaced(t, h.hooksDir, "backup-db", "#!/bin/sh\necho hand-placed\n")

	h.pass(h.publish("backup-db", 1, nil))

	h.wantErrors(api.HookRolloutError{
		Name: "backup-db", Version: 1, Code: api.HookRolloutCodeInstallFailed, Detail: "rolled-out hooks are disabled on this node",
	})
	h.wantFetches()
	h.logs.wantLogged(t, "actions: rollout: name collision with hooks_dir", "WARN", 0)
}

// TestRolloutInstaller_WindowsReportsInstallFailed checks that a Windows
// node, which runs no script hooks, reports every listed version as
// install_failed and fetches and writes nothing. The platform is the first
// rule, so the switches do not change the detail.
func TestRolloutInstaller_WindowsReportsInstallFailed(t *testing.T) {
	configs := map[string]func(*Config){
		"default":           nil,
		"rollouts disabled": func(cfg *Config) { cfg.RolloutsEnabled = boolPtr(false) },
		"actions disabled":  func(cfg *Config) { cfg.Enabled = boolPtr(false) },
	}
	for name, edit := range configs {
		t.Run(name, func(t *testing.T) {
			h := newRolloutHarness(t, edit)
			h.inst.goos = "windows"
			h.load()
			if _, err := os.Stat(h.rolloutDir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("rollout directory after Load: Stat error %v, want it never created", err)
			}

			h.pass(h.publish("backup-db", 1, nil), h.publish("rotate-logs", 2, nil))

			h.wantErrors(
				api.HookRolloutError{Name: "backup-db", Version: 1, Code: api.HookRolloutCodeInstallFailed, Detail: "script hooks are not supported on Windows"},
				api.HookRolloutError{Name: "rotate-logs", Version: 2, Code: api.HookRolloutCodeInstallFailed, Detail: "script hooks are not supported on Windows"},
			)
			h.wantFetches()
			if got := h.rolloutFiles(); len(got) != 0 {
				t.Errorf("rollout directory = %v, want nothing written", got)
			}
			if _, err := os.Stat(filepath.Join(h.dataDir, rolloutRecordFile)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("record: Stat error %v, want none written", err)
			}
			h.wantChanges(1)
		})
	}
}

// TestRolloutInstaller_ErrorsCappedAt64 checks that the errors of 65 failing
// entries are cut to the 64 first by name, with one WARN, so the manifest
// stays inside the control plane's limit.
func TestRolloutInstaller_ErrorsCappedAt64(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	var block []api.NodeStateHook
	for i := 64; i >= 0; i-- {
		name := fmt.Sprintf("hook-%03d", i)
		block = append(block, api.NodeStateHook{Name: name, Version: 1, Checksum: scriptWire(name)})
	}

	h.pass(block...)

	errs := h.inst.Errors()
	if len(errs) != api.MaxHookRolloutErrors {
		t.Fatalf("Errors() has %d entries, want %d", len(errs), api.MaxHookRolloutErrors)
	}
	for i, e := range errs {
		if want := fmt.Sprintf("hook-%03d", i); e.Name != want || e.Code != api.HookRolloutCodeFetchFailed {
			t.Errorf("Errors()[%d] = %s %s, want %s fetch_failed", i, e.Name, e.Code, want)
		}
	}
	h.logs.wantLogged(t, "actions: rollout: too many rollout errors; reporting the first by name", "WARN", 1)

	// Errors hands out a copy.
	errs[0].Name = "changed"
	if got := h.inst.Errors()[0].Name; got != "hook-000" {
		t.Errorf("Errors()[0].Name after editing a returned copy = %q, want hook-000", got)
	}
}

// TestRolloutInstaller_ErrorDetailSanitized checks that a detail reaches the
// manifest with each NUL replaced by U+FFFD and cut to 1024 code points, the
// control plane's limits.
func TestRolloutInstaller_ErrorDetailSanitized(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	h.fetcher.fail("backup-db", 1, errors.New("refused\x00"+strings.Repeat("é", 2000)))

	h.pass(api.NodeStateHook{Name: "backup-db", Version: 1, Checksum: scriptWire("x")})

	errs := h.inst.Errors()
	if len(errs) != 1 {
		t.Fatalf("Errors() = %+v, want one entry", errs)
	}
	detail := errs[0].Detail
	if strings.ContainsRune(detail, 0) {
		t.Error("detail holds a NUL")
	}
	if !strings.HasPrefix(detail, "refused�é") {
		t.Errorf("detail starts %q, want the NUL replaced by U+FFFD", detail[:min(len(detail), 16)])
	}
	if n := utf8.RuneCountInString(detail); n != api.MaxHookRolloutDetailChars {
		t.Errorf("detail has %d code points, want %d", n, api.MaxHookRolloutDetailChars)
	}

	for _, short := range []string{"", "fetch failed", strings.Repeat("é", api.MaxHookRolloutDetailChars)} {
		if got := sanitizeRolloutDetail(short); got != short {
			t.Errorf("sanitizeRolloutDetail(%d code points) changed a detail inside the limits", utf8.RuneCountInString(short))
		}
	}
}

// TestRolloutInstaller_HandleCoalescesBlocks checks that Handle never waits
// for a pass, and that Run takes the newest block handed over while a pass
// ran, skipping the older ones.
func TestRolloutInstaller_HandleCoalescesBlocks(t *testing.T) {
	h := newRolloutHarness(t, nil)
	h.load()
	blocks := make(map[string]api.NodeStateHook)
	for _, name := range []string{"hook-a", "hook-b", "hook-c", "hook-d", "hook-e"} {
		blocks[name] = h.publish(name, 1, nil)
	}

	fetching := make(chan hookFetchCall, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	h.fetcher.setHold(func(ctx context.Context, call hookFetchCall) error {
		fetching <- call
		if call.name == "hook-a" {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	stop := runInstaller(t, h.inst)

	handle := func(names ...string) {
		block := make([]api.NodeStateHook, 0, len(names))
		for _, name := range names {
			block = append(block, blocks[name])
		}
		h.inst.Handle(context.Background(), &api.NodeStateSnapshot{Hooks: &block})
	}
	nextFetch := func() hookFetchCall {
		t.Helper()
		select {
		case call := <-fetching:
			return call
		case <-time.After(5 * time.Second):
			t.Fatal("no fetch")
			return hookFetchCall{}
		}
	}

	handle("hook-a")
	if call := nextFetch(); call.name != "hook-a" {
		t.Fatalf("first fetch = %+v, want hook-a", call)
	}

	// The pass is held in the fetch of hook-a. Three more blocks arrive.
	handled := make(chan struct{})
	go func() {
		handle("hook-b")
		handle("hook-c")
		handle("hook-d")
		close(handled)
	}()
	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle blocked while a pass ran")
	}

	releaseOnce.Do(func() { close(release) })
	if call := nextFetch(); call.name != "hook-d" {
		t.Fatalf("fetch after the held pass = %+v, want hook-d from the newest block", call)
	}

	// A later block runs in a pass of its own, so no pass for hook-b or
	// hook-c ran in between.
	handle("hook-e")
	if call := nextFetch(); call.name != "hook-e" {
		t.Fatalf("fetch after hook-d = %+v, want hook-e", call)
	}
	waitFor(t, 5*time.Second, func() bool { return h.changes.Load() == 3 })
	h.wantFetches(hookFetchCall{"hook-a", 1}, hookFetchCall{"hook-d", 1}, hookFetchCall{"hook-e", 1})

	stop()
}
