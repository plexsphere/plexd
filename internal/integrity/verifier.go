package integrity

import (
	"context"
	"log/slog"
	"sync"
	"time"

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

// Run performs startup binary verification and then periodically re-verifies
// at the configured interval. When the config is disabled, Run returns immediately.
// Run blocks until the context is cancelled.
func (v *Verifier) Run(ctx context.Context, nodeID string) error {
	if !v.cfg.Enabled {
		v.logger.Info("integrity verification disabled")
		return nil
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
		}
	}
}
