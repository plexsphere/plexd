package integrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/plexsphere/plexd/internal/fsutil"
)

const checksumFileName = "checksums.json"

// Store persists known-good checksums as a JSON file in the agent's data directory.
type Store struct {
	mu        sync.RWMutex
	dataDir   string
	checksums map[string]string
}

// NewStore creates a Store backed by dataDir/checksums.json.
// If the file does not exist, an empty store is created.
func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		dataDir:   dataDir,
		checksums: make(map[string]string),
	}

	data, err := os.ReadFile(filepath.Join(dataDir, checksumFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("integrity: read store: %w", err)
	}

	if err := json.Unmarshal(data, &s.checksums); err != nil {
		return nil, fmt.Errorf("integrity: parse store: %w", err)
	}
	return s, nil
}

// Get returns the stored checksum for path, or empty string if not found.
func (s *Store) Get(path string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.checksums[path]
}

// Set updates the checksum for path and persists to disk atomically.
func (s *Store) Set(path, checksum string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checksums[path] = checksum
	return s.persist()
}

// Remove deletes the checksum for path and persists to disk.
func (s *Store) Remove(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.checksums, path)
	return s.persist()
}

func (s *Store) persist() error {
	data, err := json.Marshal(s.checksums)
	if err != nil {
		return fmt.Errorf("integrity: marshal store: %w", err)
	}
	return fsutil.WriteFileAtomic(s.dataDir, checksumFileName, data, 0o600)
}
