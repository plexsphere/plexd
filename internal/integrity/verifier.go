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
}

// NewVerifier creates a Verifier with the given configuration, store, reporter, and logger.
func NewVerifier(cfg Config, store *Store, reporter ViolationReporter, logger *slog.Logger) *Verifier {
	return &Verifier{
		cfg:      cfg,
		store:    store,
		reporter: reporter,
		logger:   logger.With("component", "integrity"),
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
func (v *Verifier) report(ctx context.Context, nodeID string, reports []api.IntegrityViolationReport) {
	for len(reports) > 0 {
		n := min(len(reports), api.MaxIntegrityViolationsPerBatch)
		if err := v.reporter.ReportViolations(ctx, nodeID, reports[:n]); err != nil {
			v.logger.Warn("failed to report integrity violations", "count", n, "error", err)
		}
		reports = reports[n:]
	}
}

// VerifyBinary computes the binary checksum, compares against the stored baseline,
// and reports a violation on mismatch. On first run (no baseline), the checksum is
// stored as the new baseline.
func (v *Verifier) VerifyBinary(ctx context.Context, nodeID string) error {
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

	if report, ok := v.checksumViolation(
		api.IntegrityKindBinaryChecksum, api.IntegrityDetectorStartupScan,
		v.cfg.BinaryPath, expected, actual,
	); ok {
		v.report(ctx, nodeID, []api.IntegrityViolationReport{report})
	}
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
func (v *Verifier) VerifyHooksDir(ctx context.Context, nodeID string) {
	v.verifyHooksDir(ctx, nodeID, api.IntegrityDetectorStartupScan)
}

// verifyHooksDir is VerifyHooksDir with the detector the caller represents.
// Every violation the sweep finds travels in one batch: the control plane
// records them in a single transaction, so an operator sees one alert for one
// tampering event rather than one per file.
func (v *Verifier) verifyHooksDir(ctx context.Context, nodeID string, detector api.IntegrityDetector) {
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

	var reports []api.IntegrityViolationReport

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

		if report, ok := v.checksumViolation(
			api.IntegrityKindHookChecksum, detector, hookPath, expected, actual,
		); ok {
			reports = append(reports, report)
		}
	}

	v.report(ctx, nodeID, reports)
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
// that never started the tunnel has no key to watch.
func (v *Verifier) VerifyHostKey(ctx context.Context, nodeID string) error {
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

	v.report(ctx, nodeID, []api.IntegrityViolationReport{{
		Kind:                api.IntegrityKindSSHHostKey,
		DetectedBy:          api.IntegrityDetectorStartupScan,
		ArtifactID:          v.cfg.HostKeyPath,
		ObservedFingerprint: actual,
		ExpectedFingerprint: expected,
	}})
	return nil
}

// Run performs periodic integrity verification for the binary, the hooks
// directory, and the SSH host key. When WatchEnabled is true, it also monitors
// the hooks directory via inotify for real-time change detection. Run blocks
// until the context is cancelled.
func (v *Verifier) Run(ctx context.Context, nodeID string) error {
	if !v.cfg.Enabled {
		v.logger.Info("integrity verification disabled")
		return nil
	}

	// Start fsnotify watcher if enabled and hooks dir is configured.
	if v.cfg.WatchEnabled && v.cfg.HooksDir != "" {
		go v.watchHooksDir(ctx, nodeID)
	}

	ticker := time.NewTicker(v.cfg.VerifyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := v.VerifyBinary(ctx, nodeID); err != nil {
				v.logger.Error("periodic binary verification failed", "error", err)
			}
			v.VerifyHooksDir(ctx, nodeID)
			if err := v.VerifyHostKey(ctx, nodeID); err != nil {
				v.logger.Error("periodic host key verification failed", "error", err)
			}
		}
	}
}

// watchHooksDir monitors the hooks directory for file changes using fsnotify.
// On any file modification, checksums are recomputed immediately.
func (v *Verifier) watchHooksDir(ctx context.Context, nodeID string) {
	if err := os.MkdirAll(v.cfg.HooksDir, 0o755); err != nil {
		v.logger.Warn("integrity: failed to create hooks dir for watching", "path", v.cfg.HooksDir, "error", err)
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		v.logger.Warn("integrity: failed to create fsnotify watcher", "error", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(v.cfg.HooksDir); err != nil {
		v.logger.Warn("integrity: failed to watch hooks dir", "path", v.cfg.HooksDir, "error", err)
		return
	}

	v.logger.Info("integrity: watching hooks dir for changes", "path", v.cfg.HooksDir)

	// Debounce timer to coalesce rapid changes.
	var debounceTimer *time.Timer
	const debouncePeriod = 200 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
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

			// Debounce: reset timer on each event.
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(debouncePeriod, func() {
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
