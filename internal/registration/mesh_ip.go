package registration

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/plexsphere/plexd/internal/fsutil"
)

// CommitMeshIP persists a mesh address learned after registration, the one a
// state pull carried, into identity.json's mesh_ip. A restart then brings the
// mesh interface up with it rather than with the address registration handed
// out.
//
// It re-reads the group under identityMu and changes only mesh_ip, so every
// other field, last_rotation included, is written back as it was loaded, and
// the three key files are not written at all.
//
// An empty meshIP returns an error and writes nothing: LoadIdentity refuses an
// identity without one. An empty data dir returns an error wrapping
// ErrNotRegistered and writes nothing.
func CommitMeshIP(dataDir, meshIP string) error {
	if meshIP == "" {
		return errors.New("registration: commit mesh ip: mesh_ip is empty")
	}

	// identityMu makes the read-modify-write below atomic against SaveIdentity
	// and CommitRotatedKey; see its declaration.
	identityMu.Lock()
	defer identityMu.Unlock()

	current, err := LoadIdentity(dataDir)
	if err != nil {
		return fmt.Errorf("registration: commit mesh ip: %w", err)
	}

	// Rewrite identity.json without SaveIdentity's remove-first step, for the
	// reason CommitRotatedKey gives: an identity-less window would force an
	// impossible re-registration on a crash.
	current.MeshIP = meshIP
	jsonData, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("registration: commit mesh ip: %w", err)
	}
	if err := fsutil.WriteFileAtomic(dataDir, "identity.json", jsonData, 0600); err != nil {
		return fmt.Errorf("registration: commit mesh ip: %w", err)
	}
	return nil
}
