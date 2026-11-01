package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/integrity"
)

// hookMetadata represents the optional sidecar JSON file for a hook script.
type hookMetadata struct {
	Description string            `json:"description"`
	Parameters  []api.ActionParam `json:"parameters"`
	Timeout     string            `json:"timeout"`
	Sandbox     string            `json:"sandbox"`
}

// DiscoverHooks scans hooksDir for executable files and returns their metadata.
// Returns an empty slice (not nil) and no error if the directory does not exist.
// Individual file errors (hash failures, unreadable sidecars) are logged at warn
// level but do not prevent discovery of other hooks.
func DiscoverHooks(hooksDir string, logger *slog.Logger) ([]api.HookInfo, error) {
	hooks, _, err := scanHooks(hooksDir, logger, integrity.HashFile)
	return hooks, err
}

// scanHooks is DiscoverHooks with the hash as a parameter. It also returns the
// names of the executable files it could not read, so a caller that already
// lists one of them can keep its entry: a transient read error says nothing
// about whether the hook is still there. A file that is gone is not a failure.
func scanHooks(hooksDir string, logger *slog.Logger, hash func(string) (string, error)) (hooks []api.HookInfo, failed []string, err error) {
	if hooksDir == "" {
		return []api.HookInfo{}, nil, nil
	}

	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []api.HookInfo{}, nil, nil
		}
		return nil, nil, err
	}

	unreadable := func(name, msg string, err error) {
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		logger.Warn(msg, "file", name, "error", err)
		failed = append(failed, name)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()

		// Skip .json sidecar files.
		if strings.HasSuffix(name, ".json") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			unreadable(name, "actions: discovery: stat failed", err)
			continue
		}

		// Skip non-executable files.
		if info.Mode().Perm()&0o111 == 0 {
			continue
		}

		fullPath := filepath.Join(hooksDir, name)

		// Stat follows a symlink, so a link to an executable regular file stays
		// a hook. Anything else stops here because opening a FIFO to hash it
		// blocks until a writer appears, and the scan would block with it.
		target, err := os.Stat(fullPath)
		if err != nil {
			unreadable(name, "actions: discovery: stat failed", err)
			continue
		}
		if !target.Mode().IsRegular() {
			logger.Warn("actions: discovery: not a regular file", "file", name, "mode", target.Mode().String())
			continue
		}

		// The mode checked above is a symlink's own, which always has the
		// executable bits. The target's decides, as it does in processFile.
		if target.Mode().Perm()&0o111 == 0 {
			continue
		}

		checksum, err := hash(fullPath)
		if err != nil {
			unreadable(name, "actions: discovery: hash failed", err)
			continue
		}

		h := api.HookInfo{
			Name:     name,
			Source:   "local",
			Checksum: checksum,
		}

		// Try to load sidecar metadata.
		sidecarPath := fullPath + ".json"
		if data, err := readSidecar(sidecarPath); err == nil {
			var meta hookMetadata
			if err := json.Unmarshal(data, &meta); err != nil {
				logger.Warn("actions: discovery: sidecar parse failed", "file", sidecarPath, "error", err)
			} else {
				h.Description = meta.Description
				h.Parameters = meta.Parameters
				h.Timeout = meta.Timeout
				h.Sandbox = meta.Sandbox
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("actions: discovery: sidecar read failed", "file", sidecarPath, "error", err)
		}

		hooks = append(hooks, h)
	}

	if hooks == nil {
		hooks = []api.HookInfo{}
	}

	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Name < hooks[j].Name
	})

	return hooks, failed, nil
}

// readSidecar reads the sidecar file at path. Anything but a regular file is an
// error, because reading a FIFO blocks the way hashing one does.
func readSidecar(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("actions: sidecar %s is not a regular file", path)
	}
	return os.ReadFile(path)
}
