package nodeapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
)

var (
	// ErrVersionConflict is returned when an optimistic locking check fails.
	ErrVersionConflict = errors.New("nodeapi: version conflict")
	// ErrNotFound is returned when the requested entry does not exist.
	ErrNotFound = errors.New("nodeapi: not found")
)

// ReportEntry represents a locally-managed report entry.
type ReportEntry struct {
	Key         string          `json:"key"`
	ContentType string          `json:"content_type"`
	Payload     json.RawMessage `json:"payload"`
	Version     int             `json:"version"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// StateCache holds node state in memory with file persistence.
type StateCache struct {
	mu          sync.RWMutex
	dataDir     string // base dir; state lives under dataDir/state/
	logger      *slog.Logger
	metadata    map[string]string
	data        map[string]api.DataEntry
	secretIndex []api.SecretRef
	reports     map[string]ReportEntry
}

// NewStateCache creates a new StateCache with empty maps. dataDir is the base
// path; the state subdirectory tree will be created under dataDir/state/.
func NewStateCache(dataDir string, logger *slog.Logger) *StateCache {
	return &StateCache{
		dataDir:     dataDir,
		logger:      logger,
		metadata:    make(map[string]string),
		data:        make(map[string]api.DataEntry),
		secretIndex: nil,
		reports:     make(map[string]ReportEntry),
	}
}

// stateDir returns the path to the state subdirectory.
func (sc *StateCache) stateDir() string {
	return filepath.Join(sc.dataDir, "state")
}

// Load reads persisted state from disk. Missing files or directories are
// treated as fresh (empty) state. The directory tree is created if absent.
func (sc *StateCache) Load() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sd := sc.stateDir()

	// Ensure directory tree exists.
	for _, sub := range []string{filepath.Join(sd, "data"), filepath.Join(sd, "report")} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			return err
		}
	}

	// Load metadata.json.
	if data, err := os.ReadFile(filepath.Join(sd, "metadata.json")); err == nil {
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return err
		}
		sc.metadata = m
	} else if !os.IsNotExist(err) {
		return err
	}

	// Load secrets.json.
	if data, err := os.ReadFile(filepath.Join(sd, "secrets.json")); err == nil {
		var refs []api.SecretRef
		if err := json.Unmarshal(data, &refs); err != nil {
			return err
		}
		sc.secretIndex = refs
	} else if !os.IsNotExist(err) {
		return err
	}

	// Load data/*.json.
	sc.data = make(map[string]api.DataEntry)
	dataDir := filepath.Join(sd, "data")
	dataEntries, err := os.ReadDir(dataDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, de := range dataEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dataDir, de.Name()))
		if err != nil {
			return err
		}
		var entry api.DataEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		sc.data[entry.Key] = entry
	}

	// Load report/*.json.
	sc.reports = make(map[string]ReportEntry)
	reportDir := filepath.Join(sd, "report")
	reportEntries, err := os.ReadDir(reportDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, re := range reportEntries {
		if re.IsDir() || !strings.HasSuffix(re.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(reportDir, re.Name()))
		if err != nil {
			return err
		}
		var entry ReportEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		sc.reports[entry.Key] = entry
	}

	return nil
}

// UpdateMetadata replaces the metadata in memory and persists to metadata.json.
func (sc *StateCache) UpdateMetadata(m map[string]string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.metadata = maps.Clone(m)
	sc.persistJSON(filepath.Join(sc.stateDir(), "metadata.json"), sc.metadata)
}

// UpdateData replaces data entries in memory and persists each to
// data/{key}.json. Files for entries no longer present are removed.
func (sc *StateCache) UpdateData(entries []api.DataEntry) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Track old keys for cleanup.
	oldKeys := make(map[string]struct{}, len(sc.data))
	for k := range sc.data {
		oldKeys[k] = struct{}{}
	}

	newData := make(map[string]api.DataEntry, len(entries))
	dataDir := filepath.Join(sc.stateDir(), "data")
	for _, e := range entries {
		newData[e.Key] = e
		delete(oldKeys, e.Key)
		sc.persistJSON(filepath.Join(dataDir, e.Key+".json"), e)
	}

	// Remove files for entries no longer present.
	for k := range oldKeys {
		os.Remove(filepath.Join(dataDir, k+".json"))
	}

	sc.data = newData
}

// UpdateSecretIndex replaces the secret index in memory and persists to
// secrets.json.
func (sc *StateCache) UpdateSecretIndex(refs []api.SecretRef) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	cp := make([]api.SecretRef, len(refs))
	copy(cp, refs)
	sc.secretIndex = cp
	sc.persistJSON(filepath.Join(sc.stateDir(), "secrets.json"), sc.secretIndex)
}

// GetMetadata returns a copy of the metadata map.
func (sc *StateCache) GetMetadata() map[string]string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return maps.Clone(sc.metadata)
}

// GetMetadataKey returns the value for a metadata key and whether it exists.
func (sc *StateCache) GetMetadataKey(key string) (string, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	v, ok := sc.metadata[key]
	return v, ok
}

// GetData returns a copy of the data map.
func (sc *StateCache) GetData() map[string]api.DataEntry {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return maps.Clone(sc.data)
}

// GetDataEntry returns a data entry by key and whether it exists.
func (sc *StateCache) GetDataEntry(key string) (api.DataEntry, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	e, ok := sc.data[key]
	return e, ok
}

// GetSecretIndex returns a copy of the secret index.
func (sc *StateCache) GetSecretIndex() []api.SecretRef {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.secretIndex == nil {
		return nil
	}
	cp := make([]api.SecretRef, len(sc.secretIndex))
	copy(cp, sc.secretIndex)
	return cp
}

// GetReports returns a copy of the reports map.
func (sc *StateCache) GetReports() map[string]ReportEntry {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return maps.Clone(sc.reports)
}

// GetReport returns a report entry by key and whether it exists.
func (sc *StateCache) GetReport(key string) (ReportEntry, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	r, ok := sc.reports[key]
	return r, ok
}

// PutReport creates or updates a report entry. If the entry exists and ifMatch
// is non-nil, it must equal the current version or ErrVersionConflict is
// returned. Version starts at 1 for new entries and increments on update.
func (sc *StateCache) PutReport(key, contentType string, payload json.RawMessage, ifMatch *int) (ReportEntry, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	existing, exists := sc.reports[key]

	version := 1
	if exists {
		if ifMatch != nil && *ifMatch != existing.Version {
			return ReportEntry{}, ErrVersionConflict
		}
		version = existing.Version + 1
	} else if ifMatch != nil && *ifMatch != 0 {
		return ReportEntry{}, ErrVersionConflict
	}

	entry := ReportEntry{
		Key:         key,
		ContentType: contentType,
		Payload:     payload,
		Version:     version,
		UpdatedAt:   time.Now(),
	}
	sc.reports[key] = entry
	sc.persistJSON(filepath.Join(sc.stateDir(), "report", key+".json"), entry)

	return entry, nil
}

// DeleteReport removes a report entry and its file. Returns ErrNotFound if the
// key does not exist.
func (sc *StateCache) DeleteReport(key string) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, ok := sc.reports[key]; !ok {
		return ErrNotFound
	}
	delete(sc.reports, key)
	os.Remove(filepath.Join(sc.stateDir(), "report", key+".json"))
	return nil
}

// persistJSON marshals v to JSON and writes it atomically to path.
func (sc *StateCache) persistJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		sc.logger.Error("persist marshal failed", "path", path, "error", err)
		return
	}
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	if err := fsutil.WriteFileAtomic(dir, name, data, 0600); err != nil {
		sc.logger.Error("persist write failed", "path", path, "error", err)
	}
}
