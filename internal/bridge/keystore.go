package bridge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/plexsphere/plexd/internal/fsutil"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// keyFileSuffix ends the name of every key file: <id>.key.
const keyFileSuffix = ".key"

// InterfaceKeyStore keeps the private keys of WireGuard interfaces in one
// directory, one file per id, so an interface built again for the same id
// carries the key it had before. A key is the standard base64 encoding of
// its 32 bytes, the form the node's own private_key is stored in.
//
// The store is safe for concurrent use. Two stores over the same directory
// do not coordinate their writes.
type InterfaceKeyStore struct {
	dir string
	mu  sync.Mutex
}

// NewInterfaceKeyStore returns a store over dir. Nothing is created on disk
// until LoadOrCreate needs it.
func NewInterfaceKeyStore(dir string) *InterfaceKeyStore {
	return &InterfaceKeyStore{dir: dir}
}

// validKeyID reports whether id can name a key file: it is not empty, holds
// no path separator, and does not start with ".", which keeps it out of the
// names of hidden files and of the temp files fsutil.WriteFileAtomic uses.
// Callers validate ids before; this only keeps a bad one from becoming a
// path.
func validKeyID(id string) bool {
	return id != "" && !strings.ContainsAny(id, `/\`) && !strings.HasPrefix(id, ".")
}

// LoadOrCreate returns the key stored for id. When the store has none, it
// generates one, writes it and returns it.
//
// The directory is created with mode 0700 when it does not exist; one that
// exists keeps its mode. A key file is written with mode 0600. A file that
// does not hold the base64 encoding of 32 bytes is an error and is never
// replaced: a fresh key would invalidate every peer that knows the old one.
func (s *InterfaceKeyStore) LoadOrCreate(id string) (wgtypes.Key, error) {
	if !validKeyID(id) {
		return wgtypes.Key{}, fmt.Errorf("bridge: key store: invalid id %q", id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureDir(); err != nil {
		return wgtypes.Key{}, fmt.Errorf("bridge: key store: create directory: %w", err)
	}

	name := id + keyFileSuffix
	path := filepath.Join(s.dir, name)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		// The file content is never part of the error: it is key material.
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("bridge: key store: %s: not base64: %w", path, err)
		}
		key, err := wgtypes.NewKey(raw)
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("bridge: key store: %s: %w", path, err)
		}
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return wgtypes.Key{}, fmt.Errorf("bridge: key store: read %s: %w", path, err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("bridge: key store: generate key: %w", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(key[:]))
	if err := fsutil.WriteFileAtomic(s.dir, name, encoded, 0600); err != nil {
		return wgtypes.Key{}, fmt.Errorf("bridge: key store: write %s: %w", path, err)
	}
	return key, nil
}

// ensureDir creates the store's directory, and its parents, when it does not
// exist. Mkdir applies the umask, so a directory created here is set to 0700
// afterwards; a directory that already exists is left as it is.
func (s *InterfaceKeyStore) ensureDir() error {
	if err := os.MkdirAll(filepath.Dir(s.dir), 0700); err != nil {
		return err
	}
	err := os.Mkdir(s.dir, 0700)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.Chmod(s.dir, 0700)
}

// Prune deletes the key file of every id not in keep. It considers only
// regular files named <id>.key with an id LoadOrCreate accepts, and leaves
// every other entry of the directory alone, among them the temp files of an
// interrupted write. A directory that does not exist holds no key and is no
// error. A failed deletion does not stop the others; the errors are joined.
func (s *InterfaceKeyStore) Prune(keep map[string]struct{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bridge: key store: prune: %w", err)
	}

	var errs []error
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		id, ok := strings.CutSuffix(entry.Name(), keyFileSuffix)
		if !ok || !validKeyID(id) {
			continue
		}
		if _, kept := keep[id]; kept {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("bridge: key store: prune: %w", err))
		}
	}
	return errors.Join(errs...)
}
