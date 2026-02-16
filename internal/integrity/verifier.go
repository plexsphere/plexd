package integrity

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/plexsphere/plexd/internal/api"
)

// Violation type constants used in integrity violation reports.
const (
	ViolationTypeBinary = "binary"
	ViolationTypeHook   = "hook"
)

// ViolationReporter abstracts control plane violation reporting for testability.
type ViolationReporter interface {
	ReportViolation(ctx context.Context, nodeID string, report api.IntegrityViolationReport) error
}

// Verifier orchestrates integrity verification for the plexd binary and hook scripts.
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

	report := api.IntegrityViolationReport{
		Type:             ViolationTypeBinary,
		Path:             v.cfg.BinaryPath,
		ExpectedChecksum: expected,
		ActualChecksum:   actual,
		Detail:           "binary checksum mismatch",
		Timestamp:        time.Now().UTC(),
	}
	if err := v.reporter.ReportViolation(ctx, nodeID, report); err != nil {
		v.logger.Warn("failed to report binary violation", "error", err)
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

	report := api.IntegrityViolationReport{
		Type:             ViolationTypeHook,
		Path:             hookPath,
		ExpectedChecksum: result.Expected,
		ActualChecksum:   result.Actual,
		Detail:           "hook checksum mismatch",
		Timestamp:        time.Now().UTC(),
	}
	if err := v.reporter.ReportViolation(ctx, nodeID, report); err != nil {
		v.logger.Warn("failed to report hook violation", "error", err)
	}
	return false, nil
}

// VerifyHooksDir computes checksums for all files in the hooks directory,
// compares against stored baselines, and reports violations on mismatch.
func (v *Verifier) VerifyHooksDir(ctx context.Context, nodeID string) {
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

		report := api.IntegrityViolationReport{
			Type:             ViolationTypeHook,
			Path:             hookPath,
			ExpectedChecksum: expected,
			ActualChecksum:   actual,
			Detail:           "hook file checksum changed",
			Timestamp:        time.Now().UTC(),
		}
		if err := v.reporter.ReportViolation(ctx, nodeID, report); err != nil {
			v.logger.Warn("failed to report hook violation", "error", err)
		}
	}
}

// Run performs periodic integrity verification for the binary and hooks directory.
// When WatchEnabled is true, it also monitors the hooks directory via inotify
// for real-time change detection. Run blocks until the context is cancelled.
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
				v.VerifyHooksDir(ctx, nodeID)
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			v.logger.Warn("integrity: fsnotify error", "error", err)
		}
	}
}
