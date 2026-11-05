package actions

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
	"github.com/plexsphere/plexd/internal/integrity"
)

// rolloutFetchTimeout bounds one hook version fetch. A pass fetches one
// version at a time, so the bound is what one unresponsive control plane call
// costs every entry queued behind it.
const rolloutFetchTimeout = 30 * time.Second

// rolloutRecordFile is the name, in the data dir, of the record of the hooks
// the installer put into the rollout directory.
const rolloutRecordFile = "hook_rollouts.json"

// maxRolloutTimeoutSeconds is the largest timeout_seconds a published version
// can declare, the contract's 86400 seconds, which is MaxHookTimeout.
const maxRolloutTimeoutSeconds = int64(MaxHookTimeout / time.Second)

// HookVersionFetcher fetches one published hook version. *api.ControlPlane
// satisfies it.
type HookVersionFetcher interface {
	FetchHookVersion(ctx context.Context, nodeID, name string, version int) (*api.NodeHookVersion, error)
}

// HookSignatureVerifier checks the Domain signature of an envelope without a
// freshness window, because a hook_version envelope carries the instant the
// version was signed, often days before the fetch. *api.Ed25519Verifier
// satisfies it.
type HookSignatureVerifier interface {
	VerifySignature(env api.Envelope) error
}

// rolloutRecordEntry is one hook the installer put into the rollout
// directory: the version it installed and the digest that version was
// delivered with, as lowercase hex.
type rolloutRecordEntry struct {
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Checksum string `json:"checksum"`
}

// rolloutRecord is the on-disk form of the record.
type rolloutRecord struct {
	Hooks []rolloutRecordEntry `json:"hooks"`
}

// rolloutSidecar is the sidecar the installer writes beside a rolled-out
// script. It is plexd's own sidecar format, hookMetadata, with empty fields
// left out, so the rollout watcher and the executor read it like the sidecar
// of a hand-placed hook.
type rolloutSidecar struct {
	Description string            `json:"description,omitempty"`
	Parameters  []api.ActionParam `json:"parameters,omitempty"`
	Timeout     string            `json:"timeout,omitempty"`
	Sandbox     string            `json:"sandbox,omitempty"`
}

// droppedHook is a hooks block entry a pass leaves out, with the reason it was
// refused.
type droppedHook struct {
	entry  api.NodeStateHook
	reason string
}

// listedHook is a hooks block entry a pass decides on, with the pull checksum
// decoded to the hex form the record and the executor's pins use.
type listedHook struct {
	api.NodeStateHook
	hex string
}

// RolloutInstaller converges the rollout directory on the hooks block of the
// state pull. For each listed version it fetches the signed version, verifies
// it against the Domain key and the checksum the pull delivered, and installs
// it atomically, pinned to that checksum. It removes the rolled-out hooks the
// block no longer lists, and reports what it could not install as
// hook_rollout_errors for the capability manifest.
//
// It owns the rollout directory and everything in it: Load removes files it
// did not write. It compares the pull with its own record of what it
// installed, never with the bytes on disk, so a rolled-out file edited after
// install stays refused at dispatch until a new version or a withdrawal
// replaces it, or until the edited file is deleted: a recorded hook whose
// script is gone counts as not installed, and the next pass fetches it again.
//
// Handle runs on the reconcile goroutine and only hands the block over. Run
// does the work on its own goroutine, so a slow fetch never holds back the
// rest of the reconcile cycle.
type RolloutInstaller struct {
	cfg      Config
	dataDir  string
	nodeID   string
	fetcher  HookVersionFetcher
	verifier HookSignatureVerifier
	executor *Executor
	logger   *slog.Logger

	// goos, fetchTimeout and writeFile are seams for tests: runtime.GOOS,
	// rolloutFetchTimeout and fsutil.WriteFileAtomic in production.
	goos         string
	fetchTimeout time.Duration
	writeFile    func(dir, name string, data []byte, perm os.FileMode) error

	// signal wakes Run. It holds one token, so Handle never blocks and any
	// number of blocks handed over during a pass wake Run once.
	signal chan struct{}

	// passMu serializes Load and the passes, which share the record and the
	// fields below it.
	passMu sync.Mutex
	// record is what the installer put into the rollout directory, by name.
	record map[string]rolloutRecordEntry
	// unsaved is set while the record on disk lags the one in memory, so the
	// end of every pass retries the save until it lands.
	unsaved bool
	// saveTried is set once the current pass attempted a save, so a pass
	// whose own save failed does not retry it at its end.
	saveTried bool
	// lastDropped is the set of entries the last pass dropped, so a dropped
	// entry is logged once until that set changes rather than every pass.
	lastDropped []droppedHook

	// mu guards the fields below, which Handle, Errors and SetOnChange reach
	// from other goroutines.
	mu sync.Mutex
	// pending is the newest block Handle handed over that no pass has taken.
	pending    []api.NodeStateHook
	hasPending bool
	errors     []api.HookRolloutError
	onChange   func()
}

// NewRolloutInstaller returns an installer for cfg.RolloutHooksDir that keeps
// its record in dataDir, fetches versions for nodeID with fetcher, checks
// their signatures with verifier, and pins what it installs in executor.
//
// It refuses a rollout directory that is hooks_dir under any spelling, a
// relative path or a symlink included, because the installer removes every
// file it did not write from its directory, which there would be the
// operator's hand-placed hooks.
func NewRolloutInstaller(cfg Config, dataDir, nodeID string, fetcher HookVersionFetcher, verifier HookSignatureVerifier, executor *Executor, logger *slog.Logger) (*RolloutInstaller, error) {
	switch {
	case cfg.RolloutHooksDir == "":
		return nil, errors.New("actions: rollout: no rollout directory configured")
	case dataDir == "":
		return nil, errors.New("actions: rollout: no data dir configured")
	case fetcher == nil || verifier == nil || executor == nil:
		return nil, errors.New("actions: rollout: fetcher, verifier and executor are required")
	case sameDirectory(cfg.HooksDir, cfg.RolloutHooksDir):
		return nil, fmt.Errorf("actions: rollout: the rollout directory %s is hooks_dir; plexd would remove hand-placed hooks as strays", cfg.RolloutHooksDir)
	}
	return &RolloutInstaller{
		cfg:          cfg,
		dataDir:      dataDir,
		nodeID:       nodeID,
		fetcher:      fetcher,
		verifier:     verifier,
		executor:     executor,
		logger:       logger.With("component", "actions"),
		goos:         runtime.GOOS,
		fetchTimeout: rolloutFetchTimeout,
		writeFile:    fsutil.WriteFileAtomic,
		signal:       make(chan struct{}, 1),
		record:       make(map[string]rolloutRecordEntry),
	}, nil
}

// sameDirectory reports whether the paths a and b name one directory: equal
// once made absolute and cleaned, or, when both exist, the same file by
// os.SameFile on what os.Stat returns, which follows symlinks. hooks_dir may
// be relative to the working directory, and either directory may be reached
// through a symlink, so comparing the cleaned strings alone misses both.
func sameDirectory(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil && absA == absB {
		return true
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

// SetOnChange registers fn, called after every pass that changed the set of
// installed hooks or the rollout errors, so the caller can rescan the rollout
// directory and report the manifest again. fn runs on Run's goroutine.
func (r *RolloutInstaller) SetOnChange(fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onChange = fn
}

// Errors returns the rollout errors of the last pass, sorted by name and at
// most api.MaxHookRolloutErrors, or nil when there are none. The slice is a
// copy.
func (r *RolloutInstaller) Errors() []api.HookRolloutError {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.errors) == 0 {
		return nil
	}
	return slices.Clone(r.errors)
}

// Load restores what the installer put into the rollout directory before this
// process started. It runs once, before the first scan of the rollout
// directory, so the scan finds only files the record vouches for, each
// already pinned.
//
// A missing record is an empty one, and so is a corrupt one, which is logged.
// An entry whose script is gone is dropped. Every surviving entry is pinned to
// its recorded checksum, and every other file in the directory is removed,
// which covers the temporary files of a write a crash interrupted. With
// rollouts disabled it removes every file in the directory and saves an empty
// record instead. On Windows, where script hooks do not run, it does nothing.
//
// It returns an error when the rollout directory cannot be created or read.
// Every later pass tries again.
func (r *RolloutInstaller) Load() error {
	if r.goos == "windows" {
		return nil
	}
	r.passMu.Lock()
	defer r.passMu.Unlock()

	r.record = r.readRecord()

	if !r.cfg.IsRolloutsEnabled() {
		// The node owner refused delivered scripts, so nothing in the
		// directory is vouched for. Nothing is pinned before Load, so a file
		// whose removal fails cannot run; removeStrays tries it once more, and
		// so does every later start.
		for _, name := range slices.Sorted(maps.Keys(r.record)) {
			if err := r.executor.RemoveRolloutHook(name, r.removeFiles(name)); err != nil {
				r.logger.Warn("actions: rollout: hook not removed", "name", name, "version", r.record[name].Version, "error", err)
				continue
			}
			r.logger.Info("actions: rollout: hook removed", "name", name, "version", r.record[name].Version)
		}
		r.record = make(map[string]rolloutRecordEntry)
		err := r.removeStrays()
		r.saveRecord()
		return err
	}

	dropped := false
	for name := range r.record {
		if !r.scriptExists(name) {
			delete(r.record, name)
			dropped = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(r.record)) {
		entry := r.record[name]
		// A nil swap pins without touching the file, so it cannot fail.
		_ = r.executor.SwapRolloutHook(name, entry.Version, entry.Checksum, nil)
	}
	if dropped {
		r.saveRecord()
	}

	if err := os.MkdirAll(r.cfg.RolloutHooksDir, 0o755); err != nil {
		return fmt.Errorf("actions: rollout: create %s: %w", r.cfg.RolloutHooksDir, err)
	}
	return r.removeStrays()
}

// Handle is a reconcile.DispatchHandler. It hands the hooks block of a
// successful pull to Run and returns at once, because the dispatch handlers
// run one after another inside the reconcile cycle and a fetch here would
// hold back the executions block. A nil block, from a control plane that
// could not compute the set this time, changes nothing: no pass runs and the
// rollout errors stay as they were.
func (r *RolloutInstaller) Handle(_ context.Context, desired *api.NodeStateSnapshot) {
	if desired == nil || desired.Hooks == nil {
		r.logger.Debug("actions: rollout: pull carried no hooks block; keeping rolled-out hooks")
		return
	}
	block := slices.Clone(*desired.Hooks)

	r.mu.Lock()
	r.pending = block
	r.hasPending = true
	r.mu.Unlock()

	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// Run runs one pass per signal from Handle, always on the newest block handed
// over, so blocks that arrive while a pass runs collapse into the next one. It
// returns nil when ctx ends.
func (r *RolloutInstaller) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.signal:
		}

		r.mu.Lock()
		block, ok := r.pending, r.hasPending
		r.pending, r.hasPending = nil, false
		r.mu.Unlock()
		if ok {
			r.pass(ctx, block)
		}
	}
}

// pass converges the rollout directory on block, the pull's full desired set,
// and then replaces the rollout errors. A pass abandoned because ctx ended
// leaves the errors as they were.
func (r *RolloutInstaller) pass(ctx context.Context, block []api.NodeStateHook) {
	r.passMu.Lock()
	defer r.passMu.Unlock()
	r.saveTried = false

	var errs []api.HookRolloutError
	fail := func(h api.NodeStateHook, code, detail string) {
		errs = append(errs, api.HookRolloutError{Name: h.Name, Version: h.Version, Code: code, Detail: detail})
	}

	valid, listed := r.validate(block, fail)

	// Removals come first, so a withdrawn hook stops running even when the
	// fetches below take the rest of the pass.
	changed := false
	for _, name := range slices.Sorted(maps.Keys(r.record)) {
		if _, ok := listed[name]; !ok && r.removeHook(name) {
			changed = true
		}
	}

	for _, h := range valid {
		if ctx.Err() != nil {
			return
		}
		entryChanged, code, detail := r.decide(ctx, h)
		if entryChanged {
			changed = true
		}
		if code != "" {
			fail(h.NodeStateHook, code, detail)
		}
	}
	if ctx.Err() != nil {
		return
	}

	if r.unsaved && !r.saveTried {
		r.saveRecord()
	}

	errs = r.finishErrors(errs)

	r.mu.Lock()
	if !slices.Equal(errs, r.errors) {
		changed = true
	}
	r.errors = errs
	onChange := r.onChange
	r.mu.Unlock()

	if changed && onChange != nil {
		onChange()
	}
}

// validate is step one of a pass. It drops an entry with a name outside the
// grammar, a version below 1, or a name an earlier entry already used, and
// logs the dropped set once until it changes. A dropped entry gets no rollout
// error, because the control plane refuses such an error and the whole
// manifest with it. It reports verification_failed for an entry whose checksum
// is not a SHA-256 digest, which therefore fetches nothing.
//
// listed holds every name on the grammar the block carries, the dropped and
// the failed entries among them, so neither costs the name its installed
// hook: the control plane still lists it.
func (r *RolloutInstaller) validate(block []api.NodeStateHook, fail func(api.NodeStateHook, string, string)) (valid []listedHook, listed map[string]struct{}) {
	listed = make(map[string]struct{}, len(block))
	seen := make(map[string]struct{}, len(block))
	var dropped []droppedHook
	for _, entry := range block {
		_, dup := seen[entry.Name]
		var reason string
		switch {
		case !api.ValidHookName(entry.Name):
			reason = "invalid name"
		case entry.Version < 1:
			reason = "invalid version"
		case dup:
			reason = "duplicate name"
		}
		if api.ValidHookName(entry.Name) {
			listed[entry.Name] = struct{}{}
			seen[entry.Name] = struct{}{}
		}
		if reason != "" {
			dropped = append(dropped, droppedHook{entry: entry, reason: reason})
			continue
		}

		hexSum, err := integrity.HexChecksum(entry.Checksum)
		if err != nil {
			fail(entry, api.HookRolloutCodeVerificationFailed, "pull entry checksum is not 32 bytes of standard base64")
			continue
		}
		valid = append(valid, listedHook{NodeStateHook: entry, hex: hexSum})
	}

	if !slices.Equal(dropped, r.lastDropped) {
		for _, d := range dropped {
			r.logger.Warn("actions: rollout: entry dropped",
				"name", d.entry.Name, "version", d.entry.Version, "reason", d.reason)
		}
		r.lastDropped = dropped
	}
	return valid, listed
}

// decide is step three of a pass for one valid entry: the first rule that
// matches wins. It reports whether it changed the installed set, by an install
// or by removing a rolled-out copy a collision blocks, and the rollout error
// code and detail, or an empty code when the entry is installed.
func (r *RolloutInstaller) decide(ctx context.Context, h listedHook) (changed bool, code, detail string) {
	switch {
	case r.goos == "windows":
		return false, api.HookRolloutCodeInstallFailed, "script hooks are not supported on Windows"
	case !r.cfg.IsRolloutsEnabled():
		return false, api.HookRolloutCodeInstallFailed, "rolled-out hooks are disabled on this node"
	}

	// Any directory entry of the name blocks the rollout, a dangling link or a
	// directory included: the executor and the manifest prefer hooks_dir, so a
	// rolled-out copy would never run, and removing the operator's entry is
	// not plexd's call.
	if r.cfg.HooksDir != "" {
		_, err := os.Lstat(filepath.Join(r.cfg.HooksDir, h.Name))
		switch {
		case err == nil:
			if _, recorded := r.record[h.Name]; recorded {
				changed = r.removeHook(h.Name)
			}
			r.logger.Warn("actions: rollout: name collision with hooks_dir", "name", h.Name, "version", h.Version)
			return changed, api.HookRolloutCodeCollision, "hooks_dir holds a hook of this name"
		case !errors.Is(err, fs.ErrNotExist):
			return false, api.HookRolloutCodeInstallFailed, fmt.Sprintf("check hooks_dir: %v", err)
		}
	}

	if rec, ok := r.record[h.Name]; ok && rec.Version == h.Version && rec.Checksum == h.hex && r.scriptExists(h.Name) {
		return false, "", ""
	}

	if !r.cfg.IsEnabled() {
		return false, api.HookRolloutCodeInstallFailed, "actions are disabled on this node"
	}

	fetchCtx, cancel := context.WithTimeout(ctx, r.fetchTimeout)
	hv, err := r.fetcher.FetchHookVersion(fetchCtx, r.nodeID, h.Name, h.Version)
	cancel()
	if err == nil && hv == nil {
		err = errors.New("fetch returned no hook version")
	}
	if err != nil {
		r.logger.Warn("actions: rollout: fetch failed", "name", h.Name, "version", h.Version, "error", err)
		return false, api.HookRolloutCodeFetchFailed, fetchFailedDetail(err)
	}

	payload, script, err := r.verify(h, hv)
	if err != nil {
		r.logger.Error("actions: rollout: verification failed", "name", h.Name, "version", h.Version, "error", err)
		return false, api.HookRolloutCodeVerificationFailed, err.Error()
	}

	if payload.SandboxLevel != "" && payload.SandboxLevel != "none" {
		return false, api.HookRolloutCodeInstallFailed, fmt.Sprintf("sandbox level %q is not implemented", payload.SandboxLevel)
	}
	if payload.TimeoutSeconds < 0 || payload.TimeoutSeconds > maxRolloutTimeoutSeconds {
		return false, api.HookRolloutCodeInstallFailed,
			fmt.Sprintf("timeout_seconds %d is outside the range 0 to %d", payload.TimeoutSeconds, maxRolloutTimeoutSeconds)
	}

	if err := r.install(h, payload, script); err != nil {
		r.logger.Warn("actions: rollout: install failed", "name", h.Name, "version", h.Version, "error", err)
		return false, api.HookRolloutCodeInstallFailed, err.Error()
	}
	return true, "", ""
}

// fetchFailedDetail returns the detail of a fetch_failed error: the error
// text without the correlation_id an *api.APIError appends. The control plane
// gives every request a new correlation_id, so with it a fetch that keeps
// failing the same way would change the errors on every pass and send the
// manifest again each time. The WARN that reports the failure keeps the id.
func fetchFailedDetail(err error) string {
	detail := err.Error()
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.CorrelationID != "" {
		stable := *apiErr
		stable.CorrelationID = ""
		detail = strings.Replace(detail, apiErr.Error(), stable.Error(), 1)
	}
	return detail
}

// verify checks a fetched version in the contract's order and returns its
// payload and its script. The error names the check that failed.
func (r *RolloutInstaller) verify(h listedHook, hv *api.NodeHookVersion) (api.HookVersionPayload, []byte, error) {
	var payload api.HookVersionPayload
	env := hv.Envelope
	if env.Type != api.HookVersionEnvelopeType {
		return payload, nil, fmt.Errorf("envelope type %q is not %s", env.Type, api.HookVersionEnvelopeType)
	}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return payload, nil, fmt.Errorf("payload does not decode: %w", err)
	}
	if payload.Name != h.Name || payload.Version != h.Version {
		return payload, nil, fmt.Errorf("payload names %q version %d, not the fetched %q version %d",
			payload.Name, payload.Version, h.Name, h.Version)
	}
	if err := r.verifier.VerifySignature(env); err != nil {
		return payload, nil, fmt.Errorf("signature: %w", err)
	}
	script, err := base64.StdEncoding.DecodeString(hv.ScriptBase64)
	if err != nil {
		return payload, nil, fmt.Errorf("script_base64 does not decode: %w", err)
	}
	payloadHex, err := integrity.HexChecksum(payload.Checksum)
	if err != nil {
		return payload, nil, fmt.Errorf("payload checksum: %w", err)
	}
	sum := sha256.Sum256(script)
	if hex.EncodeToString(sum[:]) != payloadHex {
		return payload, nil, errors.New("script SHA-256 does not match the payload checksum")
	}
	if payloadHex != h.hex {
		return payload, nil, errors.New("payload checksum does not match the pull checksum")
	}
	return payload, script, nil
}

// install writes a verified version and pins it. The sidecar goes first and
// the script last, both inside SwapRolloutHook, so no dispatch verifies the
// new script against the old pin. A failure leaves the previous version
// pinned: a write that failed after the sidecar landed leaves the new sidecar
// beside the old script until the next pass repeats the install.
//
// The atomic write renames the script into place before it syncs the
// directory, so it can fail after the new bytes landed. A failed script write
// therefore hashes the file: when it holds the delivered checksum, the
// failure is logged and the install goes on, so the pin moves with the bytes
// instead of refusing them at every dispatch as tampered.
func (r *RolloutInstaller) install(h listedHook, payload api.HookVersionPayload, script []byte) error {
	sidecar := rolloutSidecar{
		Description: payload.Description,
		Parameters:  payload.Parameters,
		Sandbox:     "none",
	}
	if payload.TimeoutSeconds > 0 {
		sidecar.Timeout = fmt.Sprintf("%ds", payload.TimeoutSeconds)
	}
	sidecarData, err := json.Marshal(sidecar)
	if err != nil {
		return fmt.Errorf("encode sidecar: %w", err)
	}

	dir := r.cfg.RolloutHooksDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	err = r.executor.SwapRolloutHook(h.Name, h.Version, h.hex, func() error {
		if err := r.writeFile(dir, h.Name+".json", sidecarData, 0o644); err != nil {
			return err
		}
		writeErr := r.writeFile(dir, h.Name, script, 0o755)
		if writeErr == nil {
			return nil
		}
		if sum, err := integrity.HashFile(filepath.Join(dir, h.Name)); err == nil && sum == h.hex {
			r.logger.Warn("actions: rollout: script written but not synced", "name", h.Name, "version", h.Version, "error", writeErr)
			return nil
		}
		return writeErr
	})
	if err != nil {
		return err
	}

	r.record[h.Name] = rolloutRecordEntry{Name: h.Name, Version: h.Version, Checksum: h.hex}
	r.saveRecord()
	r.logger.Info("actions: rollout: hook installed", "name", h.Name, "version", h.Version)
	return nil
}

// removeHook removes the rolled-out hook name: its script, then its sidecar,
// then its pin, then its record entry. It reports whether it removed the hook.
// A failed unlink keeps the pin and the entry, so the next pass tries again.
func (r *RolloutInstaller) removeHook(name string) bool {
	version := r.record[name].Version
	if err := r.executor.RemoveRolloutHook(name, r.removeFiles(name)); err != nil {
		r.logger.Warn("actions: rollout: hook not removed", "name", name, "version", version, "error", err)
		return false
	}
	delete(r.record, name)
	r.saveRecord()
	r.logger.Info("actions: rollout: hook removed", "name", name, "version", version)
	return true
}

// removeFiles returns the removal RemoveRolloutHook runs for name: the script,
// then the sidecar. A file already gone is not a failure.
func (r *RolloutInstaller) removeFiles(name string) func() error {
	return func() error {
		for _, file := range []string{name, name + ".json"} {
			if err := os.Remove(filepath.Join(r.cfg.RolloutHooksDir, file)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	}
}

// removeStrays removes every file of the rollout directory that is neither a
// recorded script nor its sidecar. Only the installer writes there, so such a
// file is a leftover of an interrupted write, of a hook the record lost, or
// of an account other than plexd. Directories are left alone. A missing
// rollout directory has no strays.
func (r *RolloutInstaller) removeStrays() error {
	entries, err := os.ReadDir(r.cfg.RolloutHooksDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("actions: rollout: read %s: %w", r.cfg.RolloutHooksDir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		if _, ok := r.record[name]; ok {
			continue
		}
		if script, ok := strings.CutSuffix(name, ".json"); ok {
			if _, recorded := r.record[script]; recorded {
				continue
			}
		}
		if err := os.Remove(filepath.Join(r.cfg.RolloutHooksDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			r.logger.Warn("actions: rollout: stray file not removed", "file", name, "error", err)
			continue
		}
		r.logger.Info("actions: rollout: stray file removed", "file", name)
	}
	return nil
}

// scriptExists reports whether the rollout directory holds an entry for the
// script of name. A recorded hook whose script is gone counts as not
// installed, so the next pass fetches it again.
func (r *RolloutInstaller) scriptExists(name string) bool {
	_, err := os.Lstat(filepath.Join(r.cfg.RolloutHooksDir, name))
	return err == nil
}

// readRecord reads the record from the data dir. A missing record is empty.
// One that cannot be read or decoded, or that holds an entry no pass could
// have written, is logged and treated as empty: Load then removes the files it
// no longer vouches for, and the next pass fetches the listed versions again.
// The names are checked because Load and the passes join them to a path.
func (r *RolloutInstaller) readRecord() map[string]rolloutRecordEntry {
	record := make(map[string]rolloutRecordEntry)
	data, err := os.ReadFile(filepath.Join(r.dataDir, rolloutRecordFile))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.logger.Warn("actions: rollout: record unreadable; starting empty", "error", err)
		}
		return record
	}
	var file rolloutRecord
	if err := json.Unmarshal(data, &file); err != nil {
		r.logger.Warn("actions: rollout: record unreadable; starting empty", "error", err)
		return record
	}
	for _, entry := range file.Hooks {
		if err := validRecordEntry(entry); err != nil {
			r.logger.Warn("actions: rollout: record unreadable; starting empty", "error", err)
			return make(map[string]rolloutRecordEntry)
		}
		if _, dup := record[entry.Name]; dup {
			r.logger.Warn("actions: rollout: record unreadable; starting empty",
				"error", fmt.Errorf("hook %q is recorded twice", entry.Name))
			return make(map[string]rolloutRecordEntry)
		}
		record[entry.Name] = entry
	}
	return record
}

// validRecordEntry checks an entry read from the record the way a pass checks
// one before it writes it: a name on the grammar, a version of at least 1, and
// a lowercase hex SHA-256 digest.
func validRecordEntry(entry rolloutRecordEntry) error {
	if !api.ValidHookName(entry.Name) {
		return fmt.Errorf("recorded hook name %q is outside the grammar", entry.Name)
	}
	if entry.Version < 1 {
		return fmt.Errorf("hook %q is recorded at version %d", entry.Name, entry.Version)
	}
	raw, err := hex.DecodeString(entry.Checksum)
	if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != entry.Checksum {
		return fmt.Errorf("hook %q is recorded with checksum %q, not a lowercase hex SHA-256 digest", entry.Name, entry.Checksum)
	}
	return nil
}

// saveRecord writes the record to the data dir. A failure is logged and
// leaves the record in memory, and with it every pin, as it is: the hooks run,
// and the end of every pass tries the save again until it lands.
func (r *RolloutInstaller) saveRecord() {
	r.saveTried = true
	file := rolloutRecord{Hooks: make([]rolloutRecordEntry, 0, len(r.record))}
	for _, name := range slices.Sorted(maps.Keys(r.record)) {
		file.Hooks = append(file.Hooks, r.record[name])
	}
	data, err := json.Marshal(file)
	if err == nil {
		err = r.writeFile(r.dataDir, rolloutRecordFile, data, 0o600)
	}
	if err != nil {
		r.logger.Error("actions: rollout: record not saved", "error", err)
		r.unsaved = true
		return
	}
	r.unsaved = false
}

// finishErrors is step four of a pass: it sorts the errors by name, keeps the
// first api.MaxHookRolloutErrors, and makes every detail one the control plane
// accepts, with no NUL and at most api.MaxHookRolloutDetailChars code points.
// An error it cannot carry would refuse the whole manifest.
func (r *RolloutInstaller) finishErrors(errs []api.HookRolloutError) []api.HookRolloutError {
	slices.SortStableFunc(errs, func(a, b api.HookRolloutError) int {
		return strings.Compare(a.Name, b.Name)
	})
	if len(errs) > api.MaxHookRolloutErrors {
		r.logger.Warn("actions: rollout: too many rollout errors; reporting the first by name",
			"errors", len(errs), "reported", api.MaxHookRolloutErrors)
		errs = errs[:api.MaxHookRolloutErrors]
	}
	for i := range errs {
		errs[i].Detail = sanitizeRolloutDetail(errs[i].Detail)
	}
	return errs
}

// sanitizeRolloutDetail replaces each NUL with U+FFFD and cuts detail to
// api.MaxHookRolloutDetailChars code points. A detail often carries an error
// text from the network or the file system, which nothing else bounds.
func sanitizeRolloutDetail(detail string) string {
	detail = strings.ReplaceAll(detail, "\x00", "�")
	if utf8.RuneCountInString(detail) <= api.MaxHookRolloutDetailChars {
		return detail
	}
	runes := []rune(detail)
	return string(runes[:api.MaxHookRolloutDetailChars])
}
