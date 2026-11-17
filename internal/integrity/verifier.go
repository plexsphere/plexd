package integrity

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
)

// ViolationReporter abstracts control plane violation reporting for testability.
//
// The contract's ingest endpoint takes a batch, so the interface does too: a
// directory sweep that finds three tampered hooks delivers them as one request
// rather than three.
type ViolationReporter interface {
	ReportViolations(ctx context.Context, nodeID string, reports []api.IntegrityViolationReport) error
}

// Verifier orchestrates integrity verification for the plexd binary, the hook
// scripts, and the SSH host key.
type Verifier struct {
	cfg      Config
	store    *Store
	reporter ViolationReporter
	logger   *slog.Logger

	mu             sync.Mutex
	binaryChecksum string

	// checkMu serialises the baseline checks (VerifyBinary, verifyHooksDir,
	// VerifyHostKey) for their whole body, report included. Without it the
	// watcher's debounced sweep and a tick could both read the old baseline
	// and report one change twice. It is separate from mu so BinaryChecksum
	// never waits on a network call.
	checkMu sync.Mutex

	// watchDir is a seam over fsutil.WatchDir, replaced in tests.
	watchDir func(ctx context.Context, dir string, onRetry func(error)) (*fsnotify.Watcher, error)
}

// NewVerifier creates a Verifier with the given configuration, store, reporter, and logger.
func NewVerifier(cfg Config, store *Store, reporter ViolationReporter, logger *slog.Logger) *Verifier {
	return &Verifier{
		cfg:      cfg,
		store:    store,
		reporter: reporter,
		logger:   logger.With("component", "integrity"),
		watchDir: fsutil.WatchDir,
	}
}

// BinaryChecksum returns the last computed binary checksum (thread-safe).
// Returns an empty string before any verification has run.
func (v *Verifier) BinaryChecksum() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.binaryChecksum
}

// checksumViolation builds a contract entry for one of the two checksum kinds,
// re-encoding both digests from the hex this package works in into the base64
// the wire carries. It reports false when either digest will not convert.
//
// Dropping the entry rather than the batch is the rule declaredHooks already
// uses for the capability manifest: the control plane validates every entry and
// refuses the whole request on any bad one, so a single unconvertible digest
// would cost every other violation travelling with it.
func (v *Verifier) checksumViolation(kind api.IntegrityViolationKind, detector api.IntegrityDetector, artifactID, expected, observed string) (api.IntegrityViolationReport, bool) {
	wireExpected, err := WireChecksum(expected)
	if err != nil {
		v.logger.Warn("violation omitted: expected checksum is not a SHA-256 digest",
			"path", artifactID, "error", err)
		return api.IntegrityViolationReport{}, false
	}
	wireObserved, err := WireChecksum(observed)
	if err != nil {
		v.logger.Warn("violation omitted: observed checksum is not a SHA-256 digest",
			"path", artifactID, "error", err)
		return api.IntegrityViolationReport{}, false
	}
	return api.IntegrityViolationReport{
		Kind:             kind,
		DetectedBy:       detector,
		ArtifactID:       artifactID,
		ObservedChecksum: wireObserved,
		ExpectedChecksum: wireExpected,
	}, true
}

// report posts violations to the control plane in batches the contract accepts,
// splitting anything over its ceiling and sending nothing at all for an empty
// slice. A failed delivery is logged rather than returned: the caller's job is
// to detect tampering, and it has already logged the violation locally at Error.
// Only VerifyHook uses it, because its expected value is the executor's pin
// rather than a stored baseline; the baseline checks use reportAndAdopt.
func (v *Verifier) report(ctx context.Context, nodeID string, reports []api.IntegrityViolationReport) {
	for len(reports) > 0 {
		n := min(len(reports), api.MaxIntegrityViolationsPerBatch)
		if err := v.reporter.ReportViolations(ctx, nodeID, reports[:n]); err != nil {
			v.logger.Warn("failed to report integrity violations", "count", n, "error", err)
		}
		reports = reports[n:]
	}
}

// divergence is one mismatch against a stored baseline.
type divergence struct {
	report   api.IntegrityViolationReport
	key      string // store key: the artifact's path
	observed string // value to adopt: hex digest, or SHA256:<base64> fingerprint
}

// reportAndAdopt reports divergences to the control plane in batches the
// contract accepts, sending nothing for an empty slice, and adopts the observed
// value of every entry in a batch the control plane accepted as its new
// baseline. A divergence is therefore reported once: the next pass compares
// against what was reported. A batch that failed keeps its old baselines, so
// the next pass reports those entries again.
func (v *Verifier) reportAndAdopt(ctx context.Context, nodeID string, found []divergence) {
	for len(found) > 0 {
		n := min(len(found), api.MaxIntegrityViolationsPerBatch)
		chunk := found[:n]
		found = found[n:]

		reports := make([]api.IntegrityViolationReport, len(chunk))
		for i, d := range chunk {
			reports[i] = d.report
		}
		if err := v.reporter.ReportViolations(ctx, nodeID, reports); err != nil {
			v.logger.Warn("failed to report integrity violations", "count", n, "error", err)
			continue
		}
		for _, d := range chunk {
			v.adopt(d.key, d.observed)
		}
	}
}

// adopt makes observed the stored baseline for key. A failed write is logged:
// Store.Set has already updated its map, so this process compares against the
// new value, and only the next start, reading the old file, reports the
// divergence once more.
func (v *Verifier) adopt(key, observed string) {
	if err := v.store.Set(key, observed); err != nil {
		v.logger.Warn("failed to store integrity baseline", "path", key, "error", err)
		return
	}
	v.logger.Info("integrity baseline updated", "path", key)
}

// VerifyBinary computes the binary checksum, compares against the stored baseline,
// and reports a violation on mismatch. On first run (no baseline), the checksum is
// stored as the new baseline. Once the control plane has accepted a report, the
// observed checksum becomes the baseline, so one change is reported once; a
// mismatch whose digests cannot be put on the wire is adopted without a report.
func (v *Verifier) VerifyBinary(ctx context.Context, nodeID string) error {
	v.checkMu.Lock()
	defer v.checkMu.Unlock()

	actual, err := HashFile(v.cfg.BinaryPath)
	if err != nil {
		v.logger.Error("binary hash failed", "path", v.cfg.BinaryPath, "error", err)
		return err
	}

	v.mu.Lock()
	v.binaryChecksum = actual
	v.mu.Unlock()

	expected := v.store.Get(v.cfg.BinaryPath)

	if expected == "" {
		// First run: store baseline.
		v.logger.Info("binary baseline established", "path", v.cfg.BinaryPath, "checksum", actual)
		return v.store.Set(v.cfg.BinaryPath, actual)
	}

	if actual == expected {
		v.logger.Info("binary verified", "path", v.cfg.BinaryPath, "checksum", actual)
		return nil
	}

	// Mismatch: report violation.
	v.logger.Error("binary integrity violation",
		"path", v.cfg.BinaryPath,
		"expected_checksum", expected,
		"actual_checksum", actual,
	)

	report, ok := v.checksumViolation(
		api.IntegrityKindBinaryChecksum, api.IntegrityDetectorStartupScan,
		v.cfg.BinaryPath, expected, actual,
	)
	if !ok {
		// No later pass could report it either.
		v.adopt(v.cfg.BinaryPath, actual)
		return nil
	}
	v.reportAndAdopt(ctx, nodeID, []divergence{{report: report, key: v.cfg.BinaryPath, observed: actual}})
	return nil
}

// VerifyHook verifies a hook script against the expected checksum from the control plane.
// Returns true if the hook is safe to execute, false if there is a mismatch.
// An error is returned if the expected checksum is empty (hooks require a checksum).
func (v *Verifier) VerifyHook(ctx context.Context, nodeID, hookPath, expectedChecksum string) (bool, error) {
	result, err := VerifyFile(hookPath, expectedChecksum, true)
	if err != nil {
		return false, err
	}

	if result.OK {
		v.logger.Info("hook verified", "path", hookPath, "checksum", result.Actual)
		return true, nil
	}

	// Mismatch: report violation.
	v.logger.Error("hook integrity violation",
		"path", hookPath,
		"expected_checksum", result.Expected,
		"actual_checksum", result.Actual,
	)

	if report, ok := v.checksumViolation(
		api.IntegrityKindHookChecksum, api.IntegrityDetectorPreDispatch,
		hookPath, result.Expected, result.Actual,
	); ok {
		v.report(ctx, nodeID, []api.IntegrityViolationReport{report})
	}
	return false, nil
}

// VerifyHooksDir computes checksums for all files in the hooks directory,
// compares against stored baselines, and reports violations on mismatch.
// Violations are attributed to the scanning detector; the fsnotify watcher
// enters the same sweep through verifyHooksDir with the inotify detector.
// An empty HooksDir, or one that does not exist, is a no-op.
func (v *Verifier) VerifyHooksDir(ctx context.Context, nodeID string) {
	v.verifyHooksDir(ctx, nodeID, api.IntegrityDetectorStartupScan)
}

// verifyHooksDir is VerifyHooksDir with the detector the caller represents.
// Every violation the sweep finds travels in one batch: the control plane
// records them in a single transaction, so an operator sees one alert for one
// tampering event rather than one per file. The observed checksums of a batch
// the control plane accepted become the hooks' baselines.
func (v *Verifier) verifyHooksDir(ctx context.Context, nodeID string, detector api.IntegrityDetector) {
	v.checkMu.Lock()
	defer v.checkMu.Unlock()

	if v.cfg.HooksDir == "" {
		return
	}

	entries, err := os.ReadDir(v.cfg.HooksDir)
	if err != nil {
		if !os.IsNotExist(err) {
			v.logger.Warn("hooks dir read failed", "path", v.cfg.HooksDir, "error", err)
		}
		return
	}

	var found []divergence

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		hookPath := filepath.Join(v.cfg.HooksDir, entry.Name())
		actual, err := HashFile(hookPath)
		if err != nil {
			v.logger.Warn("hook hash failed", "path", hookPath, "error", err)
			continue
		}

		expected := v.store.Get(hookPath)
		if expected == "" {
			v.logger.Info("hook baseline established", "path", hookPath, "checksum", actual)
			if err := v.store.Set(hookPath, actual); err != nil {
				v.logger.Warn("failed to store hook baseline", "path", hookPath, "error", err)
			}
			continue
		}

		if actual == expected {
			continue
		}

		v.logger.Error("hook integrity violation",
			"path", hookPath,
			"expected_checksum", expected,
			"actual_checksum", actual,
		)

		report, ok := v.checksumViolation(
			api.IntegrityKindHookChecksum, detector, hookPath, expected, actual,
		)
		if !ok {
			// No later pass could report it either.
			v.adopt(hookPath, actual)
			continue
		}
		found = append(found, divergence{report: report, key: hookPath, observed: actual})
	}

	v.reportAndAdopt(ctx, nodeID, found)
}

// VerifyHostKey computes the SSH host key's fingerprint, compares it against
// the stored baseline, and reports a violation on mismatch. On first run the
// fingerprint becomes the baseline, as for the binary.
//
// A key that changes under a running agent is the tamper signal: the SSH server
// keeps serving the key it loaded at startup, so a divergence on disk means
// something replaced it. The fingerprint identifies the key, not the file — the
// same key re-serialised keeps its fingerprint, which is why this is not a
// checksum comparison. An unset HostKeyPath or an absent file is a no-op: a node
// that never started the tunnel has no key to watch. Once the control plane has
// accepted a report, the observed fingerprint becomes the baseline.
func (v *Verifier) VerifyHostKey(ctx context.Context, nodeID string) error {
	v.checkMu.Lock()
	defer v.checkMu.Unlock()

	if v.cfg.HostKeyPath == "" {
		return nil
	}

	actual, err := HostKeyFingerprint(v.cfg.HostKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		v.logger.Error("host key fingerprint failed", "path", v.cfg.HostKeyPath, "error", err)
		return err
	}

	expected := v.store.Get(v.cfg.HostKeyPath)

	if expected == "" {
		v.logger.Info("host key baseline established", "path", v.cfg.HostKeyPath, "fingerprint", actual)
		return v.store.Set(v.cfg.HostKeyPath, actual)
	}

	if actual == expected {
		v.logger.Info("host key verified", "path", v.cfg.HostKeyPath, "fingerprint", actual)
		return nil
	}

	v.logger.Error("host key integrity violation",
		"path", v.cfg.HostKeyPath,
		"expected_fingerprint", expected,
		"observed_fingerprint", actual,
	)

	v.reportAndAdopt(ctx, nodeID, []divergence{{
		report: api.IntegrityViolationReport{
			Kind:                api.IntegrityKindSSHHostKey,
			DetectedBy:          api.IntegrityDetectorStartupScan,
			ArtifactID:          v.cfg.HostKeyPath,
			ObservedFingerprint: actual,
			ExpectedFingerprint: expected,
		},
		key:      v.cfg.HostKeyPath,
		observed: actual,
	}})
	return nil
}

// verifyAll runs one pass of the baseline checks: the binary, the hooks
// directory, and the SSH host key, in that order. A check that fails is logged
// and does not stop the pass, so an unreadable binary still leaves the host key
// checked.
func (v *Verifier) verifyAll(ctx context.Context, nodeID string) {
	if err := v.VerifyBinary(ctx, nodeID); err != nil {
		v.logger.Error("binary verification failed", "error", err)
	}
	v.VerifyHooksDir(ctx, nodeID)
	if err := v.VerifyHostKey(ctx, nodeID); err != nil {
		v.logger.Error("host key verification failed", "error", err)
	}
}

// Run verifies the binary, the hooks directory, and the SSH host key once at
// start and then on every tick of VerifyInterval. When the watch is enabled and
// HooksDir is set, it also monitors the hooks directory via inotify for
// real-time change detection. Run returns at once when verification is
// disabled, and otherwise blocks until the context is cancelled and the
// watcher has stopped, so a caller that waits for Run waits for the watcher
// too.
func (v *Verifier) Run(ctx context.Context, nodeID string) error {
	if !v.cfg.IsEnabled() {
		v.logger.Info("integrity verification disabled")
		return nil
	}

	var watcher sync.WaitGroup
	defer watcher.Wait()

	// Start fsnotify watcher if enabled and hooks dir is configured.
	if v.cfg.IsWatchEnabled() && v.cfg.HooksDir != "" {
		watcher.Add(1)
		go func() {
			defer watcher.Done()
			v.watchHooksDir(ctx, nodeID)
		}()
	}

	v.verifyAll(ctx, nodeID)

	ticker := time.NewTicker(v.cfg.VerifyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			v.verifyAll(ctx, nodeID)
		}
	}
}

// watchHooksDir monitors the hooks directory for file changes using fsnotify.
// On any file modification, checksums are recomputed after a short debounce.
// It returns only after a debounced sweep that has already started is done,
// so nothing it started outlives it.
func (v *Verifier) watchHooksDir(ctx context.Context, nodeID string) {
	if err := os.MkdirAll(v.cfg.HooksDir, 0o755); err != nil {
		v.logger.Warn("integrity: failed to create hooks dir for watching", "path", v.cfg.HooksDir, "error", err)
		return
	}

	watcher, err := v.watchDir(ctx, v.cfg.HooksDir, func(err error) {
		v.logger.Warn("integrity: a hook vanished while the watch was set up; retrying", "path", v.cfg.HooksDir, "error", err)
	})
	if err != nil {
		if ctx.Err() == nil {
			v.logger.Warn("integrity: failed to watch hooks dir", "path", v.cfg.HooksDir, "error", err)
		}
		return
	}
	defer watcher.Close()

	v.logger.Info("integrity: watching hooks dir for changes", "path", v.cfg.HooksDir)

	// Debounce timer to coalesce rapid changes. sweeps counts each armed
	// timer until its sweep has run or Stop has cancelled it.
	var debounceTimer *time.Timer
	var sweeps sync.WaitGroup
	const debouncePeriod = 200 * time.Millisecond
	defer func() {
		if debounceTimer != nil && debounceTimer.Stop() {
			sweeps.Done()
		}
		sweeps.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			isRelevant := event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) != 0
			if !isRelevant {
				continue
			}

			v.logger.Debug("integrity: hook file change detected",
				"path", event.Name,
				"op", event.Op.String(),
			)

			// Debounce: reset timer on each event. A Stop that returns
			// false means the sweep has started and releases sweeps itself.
			if debounceTimer != nil && debounceTimer.Stop() {
				sweeps.Done()
			}
			sweeps.Add(1)
			debounceTimer = time.AfterFunc(debouncePeriod, func() {
				defer sweeps.Done()
				v.logger.Info("integrity: recomputing hook checksums after file change")
				v.verifyHooksDir(ctx, nodeID, api.IntegrityDetectorInotify)
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			v.logger.Warn("integrity: fsnotify error", "error", err)
		}
	}
}
