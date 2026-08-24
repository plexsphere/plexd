// Package paths resolves the directories plexd uses by default on the host it
// runs on: the configuration directory, the data directory and the runtime
// directory, plus the files the rest of the agent derives from them.
//
// Every value is a default. --config, PLEXD_CONFIG, the YAML keys and the
// PLEXD_* environment overrides replace it, and they take precedence on every
// platform. The per-platform values are listed in
// docs/reference/core/configuration.md under "Platform defaults".
package paths

import "path/filepath"

// ConfigDir returns the default configuration directory.
func ConfigDir() string { return configDir() }

// DataDir returns the default data directory. It is never the same directory
// as ConfigDir: plexd deregister --purge removes the data directory whole, so
// an equal pair would take config.yaml down with the identity.
func DataDir() string { return dataDir() }

// RunDir returns the default runtime directory.
func RunDir() string { return runDir() }

// ConfigFile returns the default path of config.yaml.
func ConfigFile() string { return filepath.Join(ConfigDir(), "config.yaml") }

// HooksDir returns the default hook script directory.
func HooksDir() string { return filepath.Join(ConfigDir(), "hooks") }

// TokenFile returns the default bootstrap token file.
func TokenFile() string { return filepath.Join(ConfigDir(), "bootstrap-token") }

// SocketPath returns the default Unix socket of the local node API.
func SocketPath() string { return filepath.Join(RunDir(), "api.sock") }
