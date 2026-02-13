package actions

import (
	"encoding/json"
	"errors"
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
	if hooksDir == "" {
		return []api.HookInfo{}, nil
	}

	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []api.HookInfo{}, nil
		}
		return nil, err
	}

	var hooks []api.HookInfo

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
			logger.Warn("actions: discovery: stat failed", "file", name, "error", err)
			continue
		}

		// Skip non-executable files.
		if info.Mode().Perm()&0o111 == 0 {
			continue
		}

		fullPath := filepath.Join(hooksDir, name)

		checksum, err := integrity.HashFile(fullPath)
		if err != nil {
			logger.Warn("actions: discovery: hash failed", "file", name, "error", err)
			continue
		}

		h := api.HookInfo{
			Name:     name,
			Source:   "local",
			Checksum: checksum,
		}

		// Try to load sidecar metadata.
		sidecarPath := fullPath + ".json"
		if data, err := os.ReadFile(sidecarPath); err == nil {
			var meta hookMetadata
			if err := json.Unmarshal(data, &meta); err != nil {
				logger.Warn("actions: discovery: sidecar parse failed", "file", sidecarPath, "error", err)
			} else {
				h.Description = meta.Description
				h.Parameters = meta.Parameters
				h.Timeout = meta.Timeout
				h.Sandbox = meta.Sandbox
			}
		}

		hooks = append(hooks, h)
	}

	if hooks == nil {
		hooks = []api.HookInfo{}
	}

	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Name < hooks[j].Name
	})

	return hooks, nil
}
