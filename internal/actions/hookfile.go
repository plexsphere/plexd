package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// errHookRefused marks a hook plexd will not run. The message after it is the
// terminal callback's error.
var errHookRefused = errors.New("hook refused")

// hookDeclaration is what a hook's sidecar says about how it runs.
type hookDeclaration struct {
	timeout time.Duration // 0 means none declared
}

// loadHookDeclaration reads the sidecar of the hook name from disk and refuses
// one plexd cannot honour. It reads the disk rather than the hooks snapshot,
// which cannot tell a missing sidecar from a malformed one, and only the
// missing one lets the hook run.
//
// A sidecar value has no length limit here, so the refusals quote at most 64
// characters of it: the control plane answers 400 to an error over 4096
// characters, which would strand the execution at started. The quoting also
// escapes a NUL, which a JSON string can carry.
func loadHookDeclaration(hooksDir, name string, ownerUID uint32) (hookDeclaration, error) {
	if err := validateHookName(name); err != nil {
		return hookDeclaration{}, err
	}

	// The sidecar gates the run and sits outside the digest, so it gets the same
	// checks as its hook. Otherwise an account that can write it could lift a
	// refusal.
	sidecar := name + ".json"
	if err := checkHookFile(hooksDir, sidecar, ownerUID); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return hookDeclaration{}, nil
		}
		return hookDeclaration{}, err
	}

	data, err := readSidecar(filepath.Join(hooksDir, sidecar))
	if err != nil {
		return hookDeclaration{}, fmt.Errorf("%w: sidecar %s: %w", errHookRefused, sidecar, err)
	}
	var meta hookMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return hookDeclaration{}, fmt.Errorf("%w: sidecar %s: %w", errHookRefused, sidecar, err)
	}

	if meta.Sandbox != "" && meta.Sandbox != "none" {
		return hookDeclaration{}, fmt.Errorf("%w: sandbox level %.64q is not implemented; plexd runs hooks at level none only", errHookRefused, meta.Sandbox)
	}
	timeout, err := ParseHookTimeout(meta.Timeout)
	if err != nil {
		return hookDeclaration{}, fmt.Errorf("%w: sidecar %s declares an unusable timeout %.64q: want a duration from 0 to 24h", errHookRefused, sidecar, meta.Timeout)
	}
	return hookDeclaration{timeout: timeout}, nil
}

// MaxHookTimeout is the largest timeout a sidecar can declare, the contract's
// 86400 seconds as a duration.
const MaxHookTimeout = 24 * time.Hour

// ParseHookTimeout parses a sidecar's timeout. The empty string means none
// declared and is checked first, because time.ParseDuration refuses it. The
// manifest and the run both call this, so they agree on what a usable timeout
// is.
func ParseHookTimeout(timeout string) (time.Duration, error) {
	if timeout == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(timeout)
	if err != nil {
		return 0, err
	}
	if d < 0 || d > MaxHookTimeout {
		return 0, fmt.Errorf("timeout %s is outside the range 0 to %s", d, MaxHookTimeout)
	}
	return d, nil
}

// checkHookFile decides whether plexd trusts the file name in hooksDir. With
// links followed, the file must stay inside the directory, be a regular file, be
// owned by ownerUID, and not be group- or other-writable. It reads the disk on
// every call, so a chown or chmod takes effect on the next dispatch.
//
// A missing file returns an error matching fs.ErrNotExist, and the caller decides
// what that means. Every other failure wraps errHookRefused.
func checkHookFile(hooksDir, name string, ownerUID uint32) error {
	// EvalSymlinks keeps a relative path relative, while a link with an
	// absolute target resolves to an absolute path, and Rel cannot compare the
	// two. hooks_dir may be relative to plexd's working directory.
	absDir, err := filepath.Abs(hooksDir)
	if err != nil {
		return hookFileError(name, err)
	}
	resolvedDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return hookFileError(name, err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(resolvedDir, name))
	if err != nil {
		return hookFileError(name, err)
	}
	rel, err := filepath.Rel(resolvedDir, resolved)
	if err != nil {
		return hookFileError(name, err)
	}
	if !filepath.IsLocal(rel) {
		return fmt.Errorf("%w: %s resolves outside the hooks directory", errHookRefused, name)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return hookFileError(name, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", errHookRefused, name)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("%w: %s: owner unavailable", errHookRefused, name)
	}
	if uid != ownerUID {
		return fmt.Errorf("%w: %s is owned by uid %d, not root", errHookRefused, name, uid)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s is group- or other-writable (mode %04o)", errHookRefused, name, perm)
	}
	return nil
}

// hookFileError refuses a file on a resolve or stat failure, except a missing
// file, which stays recognisable as that.
func hookFileError(name string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fmt.Errorf("%w: %s: %w", errHookRefused, name, err)
}
