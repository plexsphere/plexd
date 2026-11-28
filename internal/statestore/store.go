// Package statestore keeps the desired state of plexd's last successful state
// pull in the data directory, so that a node restarting while the control
// plane is unreachable can apply it before its first pull.
//
// The stored set is what a running node holds for its tunnels and firewall:
// the peers, the edge-PSK envelopes as the control plane served them (sealed
// under the node secret key), the compiled policy, the bridge block with the
// secret inventory its parts take their Secrets' versions from (names and
// versions, never a value), and the shared_subnets and failure_detection
// blocks peers are programmed from. The dns block, the delivery queues
// (executions, sessions, hooks) and the state and reports blocks, which the
// node API cache persists on its own, are not stored.
package statestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/wireguard"
)

const (
	// FileName is the stored state's file in the data directory.
	FileName = "desired-state.json"
	// MarkerName is the file that marks a restore in progress.
	MarkerName = "desired-state.restoring"
	// Version is the version of File this binary writes and restores.
	Version = 1
	// filePerm is the mode of both files: the stored state sits beside the
	// node's private key and node secret key.
	filePerm = 0o600
)

var (
	// ErrNoState is returned by Load when no state is stored.
	ErrNoState = errors.New("statestore: no stored state")
	// ErrInterrupted is returned by Load when the previous restore did not
	// complete: the process died while it applied the stored state, which
	// may well be the cause, so Load removes the file and the marker.
	ErrInterrupted = errors.New("statestore: the previous restore did not complete")
	// ErrForeign is returned by Load when the stored state names another
	// node: it was written under an identity the node no longer holds.
	ErrForeign = errors.New("statestore: stored state belongs to another node")
)

// File is the stored state, the JSON document in FileName.
type File struct {
	// Version is Version. A file of another version is not restored, and the
	// next successful pull overwrites it.
	Version int `json:"version"`
	// NodeID is the node the state was pulled for.
	NodeID string `json:"node_id"`
	// SavedAt is when the file was written, in UTC. Under a maximum age the
	// file is written on every successful pull, so it is the time of the
	// last one.
	SavedAt time.Time `json:"saved_at"`
	// MaxAgeSeconds is the maximum age the control plane set, as
	// reconcile.Reconciler.MaxAgeSeconds returns it; 0 for none.
	MaxAgeSeconds int64               `json:"max_age_seconds,omitempty"`
	Peers         []api.SnapshotPeer  `json:"peers"`
	Policy        *api.PolicySnapshot `json:"policy"`
	Bridge        *api.BridgeSnapshot `json:"bridge"`
	// Secrets is the pull's secret inventory, names and versions only, which
	// the bridge's ingress, user access and site-to-site managers take before
	// a restore applies the bridge block, so a part whose Secret the control
	// plane can serve comes up at once. Left out while no pull carried one.
	Secrets          *[]api.NodeStateSecret      `json:"secrets,omitempty"`
	SharedSubnets    []api.NodeStateSharedSubnet `json:"shared_subnets"`
	FailureDetection json.RawMessage             `json:"failure_detection,omitempty"`
	EdgePSKs         []wireguard.SealedEdgePSK   `json:"edge_psks,omitempty"`
}

// Store reads and writes the stored state of one node. Load, BeginRestore and
// EndRestore run before the reconciler does, on the goroutine that then runs
// it, and the observer runs on the reconcile goroutine, so a Store needs no
// lock.
type Store struct {
	dataDir string
	nodeID  string
	logger  *slog.Logger
	now     func() time.Time

	// record is what the file on disk holds, marshalled without saved_at;
	// nil before a load or a write succeeded.
	record []byte
	// failureDetection and secrets are the failure_detection and secrets
	// blocks of the file on disk, carried over by a pull without them.
	failureDetection json.RawMessage
	secrets          *[]api.NodeStateSecret
	// failing tells whether the last write failed, so a run of failures
	// logs once.
	failing bool
}

// New returns the Store of the node nodeID under dataDir.
func New(dataDir, nodeID string, logger *slog.Logger) *Store {
	return &Store{
		dataDir: dataDir,
		nodeID:  nodeID,
		logger:  logger.With("component", "statestore"),
		now:     time.Now,
	}
}

// Load reads the stored state. It returns ErrNoState when there is none,
// ErrInterrupted when the restore marker exists, after removing the file and
// the marker, and ErrForeign when the file names another node. Any read,
// decode or version error is returned wrapped as "statestore: load: ...".
// Only ErrInterrupted removes anything. A loaded file becomes the Store's
// record of what is on disk.
func (s *Store) Load() (*File, error) {
	marker := filepath.Join(s.dataDir, MarkerName)
	switch _, err := os.Lstat(marker); {
	case err == nil:
		var errs []error
		for _, path := range []string{filepath.Join(s.dataDir, FileName), marker} {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		return nil, errors.Join(append([]error{ErrInterrupted}, errs...)...)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("statestore: load: %w", err)
	}

	data, err := os.ReadFile(filepath.Join(s.dataDir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoState
	}
	if err != nil {
		return nil, fmt.Errorf("statestore: load: %w", err)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("statestore: load: %w", err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("statestore: load: %w", fmt.Errorf("version %d, this plexd restores version %d", f.Version, Version))
	}
	if f.NodeID != s.nodeID {
		return nil, ErrForeign
	}
	key, err := contentKey(&f)
	if err != nil {
		return nil, fmt.Errorf("statestore: load: %w", err)
	}
	s.record, s.failureDetection, s.secrets = key, f.FailureDetection, f.Secrets
	return &f, nil
}

// BeginRestore writes the restore marker, an empty file, before the stored
// state is applied. A start that finds it knows the previous restore did not
// complete (see Load).
func (s *Store) BeginRestore() error {
	if err := fsutil.WriteFileAtomic(s.dataDir, MarkerName, nil, filePerm); err != nil {
		return fmt.Errorf("statestore: begin restore: %w", err)
	}
	return nil
}

// EndRestore removes the restore marker once the stored state is applied.
func (s *Store) EndRestore() error {
	if err := os.Remove(filepath.Join(s.dataDir, MarkerName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("statestore: end restore: %w", err)
	}
	return nil
}

// Observer returns the reconciler's cycle observer (see
// reconcile.Reconciler.SetCycleObserver), which stores each successful pull.
// It builds a File from the pull, the edge-PSK envelopes sealed returns (a
// nil sealed stores none) and the maximum age maxAgeSeconds returns. A pull
// whose failure_detection is absent or null carries the stored block over,
// as the WireGuard manager keeps the value it holds, and so does a pull whose
// secrets block is null, as the bridge managers keep the inventory they hold.
//
// It writes the file, mode 0600, when the content, compared without
// saved_at, differs from what is on disk, and on every pull while
// maxAgeSeconds is above 0, so that under a limit saved_at is the time of the
// last successful pull. A failed write logs stored state not written at Warn
// once per run of failures and stored state written again at Info when one
// succeeds; it never fails the cycle, and the next pull tries again.
func (s *Store) Observer(sealed func() []wireguard.SealedEdgePSK, maxAgeSeconds func() int64) reconcile.DispatchHandler {
	return func(_ context.Context, desired *api.NodeStateSnapshot) {
		if desired == nil {
			return
		}
		f := &File{
			Version:          Version,
			NodeID:           s.nodeID,
			Peers:            desired.Peers,
			Policy:           desired.Policy,
			Bridge:           desired.Bridge,
			Secrets:          desired.Secrets,
			SharedSubnets:    desired.SharedSubnets,
			FailureDetection: desired.FailureDetection,
		}
		if isNull(f.FailureDetection) {
			f.FailureDetection = s.failureDetection
		}
		if f.Secrets == nil {
			f.Secrets = s.secrets
		}
		if sealed != nil {
			f.EdgePSKs = sealed()
		}
		if maxAgeSeconds != nil {
			f.MaxAgeSeconds = max(maxAgeSeconds(), 0)
		}
		s.write(f)
	}
}

// write stores f when its content differs from the record or a maximum age
// applies.
func (s *Store) write(f *File) {
	key, err := contentKey(f)
	if err == nil && f.MaxAgeSeconds == 0 && s.record != nil && bytes.Equal(key, s.record) {
		return
	}
	var data []byte
	if err == nil {
		f.SavedAt = s.now().UTC()
		data, err = json.Marshal(f)
	}
	if err == nil {
		err = fsutil.WriteFileAtomic(s.dataDir, FileName, data, filePerm)
	}
	if err != nil {
		if !s.failing {
			s.logger.Warn("stored state not written", "error", err)
			s.failing = true
		}
		return
	}
	if s.failing {
		s.logger.Info("stored state written again")
		s.failing = false
	}
	s.record, s.failureDetection, s.secrets = key, f.FailureDetection, f.Secrets
}

// contentKey marshals f without its saved_at, the form two writes compare in.
func contentKey(f *File) ([]byte, error) {
	cp := *f
	cp.SavedAt = time.Time{}
	return json.Marshal(&cp)
}

// isNull reports whether raw is absent or the JSON null.
func isNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}
