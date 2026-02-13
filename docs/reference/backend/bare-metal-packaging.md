---
title: Bare-Metal Packaging Reference
quadrant: backend
---

# Bare-Metal Packaging Reference

Reference documentation for the `internal/packaging` module, which handles installing and managing plexd as a systemd service on bare-metal Linux servers.

## InstallConfig

Configuration struct for packaging and installing plexd.

| Field          | Type   | Default                                  | Description                                  |
|----------------|--------|------------------------------------------|----------------------------------------------|
| `BinaryPath`   | string | `/usr/local/bin/plexd`                   | Path to install the plexd binary             |
| `ConfigDir`    | string | `/etc/plexd`                             | Configuration directory                      |
| `DataDir`      | string | `/var/lib/plexd`                         | Data directory                               |
| `RunDir`       | string | `/var/run/plexd`                         | Runtime directory                            |
| `UnitFilePath` | string | `/etc/systemd/system/plexd.service`      | Path for the systemd unit file               |
| `ServiceName`  | string | `plexd`                                  | Systemd service name                         |
| `APIBaseURL`   | string | *(empty)*                                | Control plane API URL (optional)             |
| `TokenValue`   | string | *(empty)*                                | Bootstrap token value (optional)             |
| `TokenFile`    | string | *(empty)*                                | Path to token file to copy from (optional)   |

### Methods

- **`ApplyDefaults()`** — Sets default values for zero-valued fields.
- **`Validate() error`** — Returns an error if any required field (`BinaryPath`, `ConfigDir`, `DataDir`, `RunDir`, `ServiceName`) is empty.

## GenerateUnitFile

```go
func GenerateUnitFile(cfg InstallConfig) string
```

Produces a complete systemd unit file. Calls `cfg.ApplyDefaults()` before generating output.

### Unit file directives

| Section     | Directive                | Value                                    | Purpose                                      |
|-------------|--------------------------|------------------------------------------|----------------------------------------------|
| `[Unit]`    | `Description`            | `plexd node agent`                       | Service description                          |
|             | `After`                  | `network-online.target`                  | Start after network is available             |
|             | `Wants`                  | `network-online.target`                  | Declare network dependency                   |
|             | `StartLimitBurst`        | `5`                                      | Max restart attempts in interval             |
|             | `StartLimitIntervalSec`  | `60`                                     | Crash loop protection window (seconds)       |
| `[Service]` | `Type`                   | `simple`                                 | Process type                                 |
|             | `ExecStart`              | `{BinaryPath} up --config {ConfigDir}/config.yaml` | Start command                   |
|             | `Restart`                | `on-failure`                             | Restart on non-zero exit                     |
|             | `RestartSec`             | `5s`                                     | Delay between restarts                       |
|             | `LimitNOFILE`            | `65536`                                  | File descriptor limit for WireGuard tunnels  |
|             | `EnvironmentFile`        | `-{ConfigDir}/environment`               | Optional environment file (dash = optional)  |
|             | `AmbientCapabilities`    | `CAP_NET_ADMIN CAP_NET_RAW`              | Network capabilities for WireGuard and ICMP  |
|             | `CapabilityBoundingSet`  | `CAP_NET_ADMIN CAP_NET_RAW`              | Limit capabilities to required set           |
|             | `ProtectSystem`          | `full`                                   | Make /usr, /boot, /efi read-only             |
|             | `ProtectHome`            | `true`                                   | Make /home, /root, /run/user inaccessible    |
|             | `ReadWritePaths`         | `{DataDir} {RunDir}`                     | Allow writes to data and runtime dirs        |
| `[Install]` | `WantedBy`               | `multi-user.target`                      | Enable at boot in multi-user mode            |

## GenerateDefaultConfig

```go
func GenerateDefaultConfig(apiBaseURL string) string
```

Produces a minimal default `config.yaml`. When `apiBaseURL` is empty, writes a commented-out placeholder.

### Output fields

| Field        | Value                           | Description               |
|--------------|---------------------------------|---------------------------|
| `api_url`    | Provided URL or `# api_url: …` | Control plane API URL     |
| `data_dir`   | `/var/lib/plexd`                | Data directory            |
| `log_level`  | `info`                          | Log verbosity             |
| `token_file` | `/etc/plexd/bootstrap-token`    | Bootstrap token file path |

## Installer

```go
func NewInstaller(cfg InstallConfig, systemd SystemdController, root RootChecker, logger *slog.Logger) *Installer
```

### Install() error

Installs plexd as a systemd service. Steps:

1. Verify root privileges (`RootChecker.IsRoot()`)
2. Verify systemd is available (`SystemdController.IsAvailable()`)
3. Create directories: `ConfigDir` (0755), `DataDir` (0700), `RunDir` (0755)
4. Copy the running binary to `BinaryPath` (0755)
5. Write default `config.yaml` if absent (preserves existing)
6. Write bootstrap token if `TokenValue` or `TokenFile` is set (0600)
7. Write systemd unit file to `UnitFilePath` (0644)
8. Execute `systemctl daemon-reload`

### Uninstall(purge bool) error

Removes the plexd systemd service. Steps:

1. Verify root privileges
2. If unit file does not exist, return nil (idempotent)
3. Stop service (errors tolerated — service may not be running)
4. Disable service
5. Remove unit file
6. Execute `systemctl daemon-reload`
7. Remove binary
8. If `purge` is true, remove `DataDir` and `ConfigDir` recursively

## Interfaces

### SystemdController

```go
type SystemdController interface {
    IsAvailable() bool
    DaemonReload() error
    Enable(service string) error
    Disable(service string) error
    Stop(service string) error
    IsActive(service string) bool
}
```

Production implementation (`NewSystemdController()`) uses `os/exec` to call `systemctl`.

### RootChecker

```go
type RootChecker interface {
    IsRoot() bool
}
```

Production implementation (`NewRootChecker()`) uses `os.Getuid() == 0`.

## File paths and permissions

| Path                                      | Permission | Created by | Description              |
|-------------------------------------------|------------|------------|--------------------------|
| `/usr/local/bin/plexd`                    | 0755       | Install    | plexd binary             |
| `/etc/plexd/`                             | 0755       | Install    | Configuration directory  |
| `/etc/plexd/config.yaml`                  | 0644       | Install    | Service configuration    |
| `/etc/plexd/bootstrap-token`              | 0600       | Install    | Bootstrap token          |
| `/etc/plexd/environment`                  | *(user)*   | Operator   | Optional env vars        |
| `/var/lib/plexd/`                         | 0700       | Install    | Data directory           |
| `/var/run/plexd/`                         | 0755       | Install    | Runtime directory        |
| `/etc/systemd/system/plexd.service`       | 0644       | Install    | Systemd unit file        |

## Token validation

Bootstrap tokens are validated with the same rules as `internal/registration/token.go`:

- Maximum length: 512 bytes
- Characters: printable ASCII only (0x20–0x7E)
- Token priority: `TokenValue` > `TokenFile`
- Written to `{ConfigDir}/bootstrap-token` with 0600 permissions

## Install script

The install script (`deploy/install.sh`) is a POSIX-compatible shell script.

### Usage

```sh
curl -fsSL https://get.plexsphere.io/install.sh | sh -s -- [OPTIONS]
```

### Flags

| Flag              | Description                                | Default    |
|-------------------|--------------------------------------------|------------|
| `--token VALUE`   | Bootstrap token for enrollment             | *(none)*   |
| `--api-url URL`   | Control plane API URL                      | *(none)*   |
| `--version VERSION` | Version to install                       | `latest`   |
| `--no-start`      | Don't start the service after install      | *(start)*  |

### Behavior

1. Detects OS (Linux required)
2. Detects architecture (`x86_64` → `amd64`, `aarch64` → `arm64`)
3. Downloads binary from artifact URL
4. Downloads and verifies SHA-256 checksum
5. Runs `plexd install` with passthrough flags
6. Enables and starts the service (unless `--no-start`)
7. Cleans up temporary files on exit

### Environment variables

| Variable              | Description                       | Default                                      |
|-----------------------|-----------------------------------|----------------------------------------------|
| `PLEXD_ARTIFACT_URL`  | Base URL for binary artifacts     | `https://artifacts.plexsphere.io/plexd`      |
