---
title: Bare-Metal Packaging Reference
---

# Bare-Metal Packaging Reference

Reference documentation for the `internal/packaging` module, which installs plexd as a host service and manages it afterwards: a systemd unit on Linux and other Unix, a launchd daemon on macOS, a Windows service under the Service Control Manager (SCM).

## InstallConfig

Configuration struct for packaging and installing plexd.

| Field          | Type   | Default                                  | Description                                  |
|----------------|--------|------------------------------------------|----------------------------------------------|
| `BinaryPath`   | string | `/usr/local/bin/plexd` (Linux)           | Path to install the plexd binary (per platform, below) |
| `ConfigDir`    | string | `/etc/plexd` (Linux)                     | Configuration directory ([per platform](../core/configuration.md#platform-defaults)) |
| `DataDir`      | string | `/var/lib/plexd` (Linux)                 | Data directory ([per platform](../core/configuration.md#platform-defaults)) |
| `RunDir`       | string | `/var/run/plexd` (Linux)                 | Runtime directory ([per platform](../core/configuration.md#platform-defaults)) |
| `LogDir`       | string | *(empty on Linux)*                       | Directory the service manager writes plexd's output to (per platform, below) |
| `UnitFilePath` | string | `/etc/systemd/system/plexd.service` (Linux) | Path of the service definition file (per platform, below) |
| `ServiceName`  | string | `plexd`                                  | Name the host's service manager knows plexd by |
| `APIBaseURL`   | string | *(empty)*                                | Control plane API URL (optional)             |
| `TokenValue`   | string | *(empty)*                                | Bootstrap token value (optional)             |
| `TokenFile`    | string | *(empty)*                                | Path to token file to copy from (optional)   |

Three of those defaults are resolved per platform:

| Field          | Linux                               | macOS                                                  | Windows                        |
|----------------|-------------------------------------|--------------------------------------------------------|--------------------------------|
| `BinaryPath`   | `/usr/local/bin/plexd`              | `/usr/local/bin/plexd`                                  | `%ProgramFiles%\plexd\plexd.exe` |
| `UnitFilePath` | `/etc/systemd/system/plexd.service` | `/Library/LaunchDaemons/com.plexsphere.plexd.plist`     | *(empty)*                      |
| `LogDir`       | *(empty)*                           | `/Library/Logs/plexd`                                   | *(empty)*                      |

`UnitFilePath` is empty on Windows because the SCM keeps its service definition in its own database rather than in a file. `LogDir` is empty wherever the manager keeps the logs itself: journald on Linux, the Application Event Log on Windows. `%ProgramFiles%` is the `ProgramFiles` environment variable, with `C:\Program Files` as the fallback when it is unset or empty.

### Methods

- **`ApplyDefaults()`** — Sets default values for zero-valued fields.
- **`Validate() error`** — Returns an error if any required field (`BinaryPath`, `ConfigDir`, `DataDir`, `RunDir`, `ServiceName`) is empty. `UnitFilePath` and `LogDir` are not required, because they are legitimately empty on some platforms; the managers that need one check it themselves.

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
|             | `Restart`                | `always`                                 | Restart unconditionally                      |
|             | `RestartSec`             | `5s`                                     | Delay between restarts                       |
|             | `LimitNOFILE`            | `65536`                                  | File descriptor limit for WireGuard tunnels  |
|             | `EnvironmentFile`        | `-{ConfigDir}/environment`               | Optional environment file (dash = optional)  |
|             | `AmbientCapabilities`    | `CAP_NET_ADMIN CAP_NET_RAW`              | Network capabilities for WireGuard and ICMP  |
|             | `CapabilityBoundingSet`  | `CAP_NET_ADMIN CAP_NET_RAW`              | Limit capabilities to required set           |
|             | `ProtectSystem`          | `full`                                   | Make /usr, /boot, /efi read-only             |
|             | `ProtectHome`            | `true`                                   | Make /home, /root, /run/user inaccessible    |
|             | `ReadWritePaths`         | `{DataDir} {RunDir}`                     | Allow writes to data and runtime dirs        |
| `[Install]` | `WantedBy`               | `multi-user.target`                      | Enable at boot in multi-user mode            |

## GenerateLaunchdPlist

```go
func GenerateLaunchdPlist(cfg InstallConfig) string
```

Produces the LaunchDaemon property list macOS loads from `/Library/LaunchDaemons`. Calls `cfg.ApplyDefaults()` before generating output, and escapes every interpolated string as XML character data.

### Plist keys

| Key                                | Value                                    | Purpose                                      |
|------------------------------------|------------------------------------------|----------------------------------------------|
| `Label`                            | `com.plexsphere.plexd`                   | The reverse-DNS label launchd keys the daemon by |
| `ProgramArguments`                 | `{BinaryPath}`, `up`, `--config`, `{ConfigDir}/config.yaml` | Start command, one array entry per argument |
| `RunAtLoad`                        | `true`                                   | Start when launchd loads the daemon          |
| `KeepAlive`                        | `true`                                   | Restart unconditionally (the unit file's `Restart=always`) |
| `ThrottleInterval`                 | `5`                                      | Seconds between restarts (`RestartSec=5s`)   |
| `StandardOutPath`                  | `{LogDir}/plexd.log`                     | Where the daemon's stdout goes               |
| `StandardErrorPath`                | `{LogDir}/plexd.log`                     | Where the daemon's stderr goes               |
| `SoftResourceLimits.NumberOfFiles` | `65536`                                  | File descriptor limit (`LimitNOFILE`)        |
| `HardResourceLimits.NumberOfFiles` | `65536`                                  | File descriptor limit (`LimitNOFILE`)        |

launchd has no `StartLimitBurst` counterpart, so a daemon that exits on a configuration error restarts every five seconds until an operator boots it out. It has no `EnvironmentFile` counterpart either: `PLEXD_*` overrides on macOS go into `config.yaml`, or into an `EnvironmentVariables` dict an operator adds by hand.

## GenerateNewsyslogConf

```go
func GenerateNewsyslogConf(cfg InstallConfig) string
```

Produces the rotation rule `plexd install` writes to `/etc/newsyslog.d/com.plexsphere.plexd.conf`. launchd appends to `StandardOutPath` forever, so without it the log grows without bound.

```
# plexd log rotation, written by plexd install
/Library/Logs/plexd/plexd.log	644	5	10240	*	J
```

The fields are mode `644`, five rotated generations kept, rotation at 10240 KiB (10 MiB), no time restriction, and `J` for bzip2 compression.

## Windows service configuration

The SCM has no definition file. `Register` creates the service with this configuration, or refreshes an existing one through `UpdateConfig`:

| Setting            | Value                                                        |
|--------------------|--------------------------------------------------------------|
| Service name       | `plexd`                                                       |
| `DisplayName`      | `plexd node agent`                                            |
| `Description`      | `Plexsphere node agent. Registers the node, builds WireGuard mesh tunnels and enforces network policy.` |
| `StartType`        | `mgr.StartAutomatic` — starts at boot                         |
| `ErrorControl`     | `mgr.ErrorNormal`                                             |
| `BinaryPathName`   | `"{BinaryPath}" up --config {ConfigDir}\config.yaml`, each argument quoted where it needs it |
| `ServiceStartName` | *(empty)* — the service runs as LocalSystem                   |

Recovery actions are the SCM's counterpart to `Restart=always` and `RestartSec=5s`: three `ServiceRestart` actions five seconds apart, a 60-second reset period, and `SetRecoveryActionsOnNonCrashFailures(true)`. The SCM applies the last action to every later failure, so the service restarts indefinitely.

`Register` also installs the Application Event Log source `plexd`, pointed at `%SystemRoot%\System32\EventCreate.exe`, whose message table renders event ids 1 to 1000 as the message text. plexd ships no message DLL of its own.

## GenerateDefaultConfig

```go
func GenerateDefaultConfig(apiBaseURL string) string
```

Produces a minimal default `config.yaml`. When `apiBaseURL` is empty, writes a commented-out placeholder. The two paths it writes are the platform defaults ([per platform](../core/configuration.md#platform-defaults)); the values below are the Linux ones.

### Output fields

| Field                      | Value                                  | Description               |
|----------------------------|----------------------------------------|---------------------------|
| `api.base_url`             | Provided URL or `# api: base_url: …`  | Control plane API URL     |
| `data_dir`                 | `/var/lib/plexd` (Linux)               | Data directory            |
| `log_level`                | `info`                                 | Log verbosity             |
| `registration.token_file`  | `/etc/plexd/bootstrap-token` (Linux)   | Bootstrap token file path |

## Installer

```go
func NewInstaller(cfg InstallConfig, mgr ServiceManager, root RootChecker, logger *slog.Logger) *Installer
```

The Installer owns the files that are the same on every platform — the binary, the config, the token — and leaves the service definition to the `ServiceManager`.

### Install() error

Installs plexd as a host service. Steps:

1. Verify privileges (`RootChecker.IsRoot()`): root on Unix, an elevated token on Windows
2. Verify the host's service manager is available (`ServiceManager.Available()`)
3. Create directories: `ConfigDir` (0755), `DataDir` (0700), `RunDir` (0755), and `LogDir` (0755) where it is set
4. Copy the running binary to `BinaryPath` (0755)
5. Write default `config.yaml` if absent (preserves existing)
6. Write bootstrap token if `TokenValue` or `TokenFile` is set (0600)
7. Register the service (`ServiceManager.Register()`)

The service is registered, never started. `--api-url` is optional, so an install can legitimately precede a usable configuration; the start command per platform is in the [CLI reference](../core/cli.md#plexd-install).

### Uninstall(purge bool) error

Removes the plexd host service. Steps:

1. Verify privileges
2. If the service is not registered (`ServiceManager.Registered()`), return nil (idempotent)
3. Stop the service and remove its definition (`ServiceManager.Unregister()`)
4. Remove binary
5. If `purge` is true, remove `DataDir` and `ConfigDir` recursively

On Windows the binary is a running image whenever `plexd uninstall` runs from the installed path, and Windows refuses to delete one. The file is renamed to `plexd.exe.old` and handed to the boot-time delete queue instead, so it disappears at the next reboot.

## Interfaces

### ServiceManager

```go
type ServiceManager interface {
    Name() string
    Available() bool
    Registered(cfg InstallConfig) (bool, error)
    Register(cfg InstallConfig) error
    Unregister(cfg InstallConfig) error
    Start(cfg InstallConfig) error
    Stop(cfg InstallConfig) error
    Restart(ctx context.Context, cfg InstallConfig) error
    Status(cfg InstallConfig) (ServiceStatus, error)
}
```

`NewServiceManager(logger)` returns the host's own. What each method does per manager:

| Method       | systemd                                     | launchd                                                  | Service Control Manager                              |
|--------------|---------------------------------------------|----------------------------------------------------------|------------------------------------------------------|
| `Name`       | `systemd`                                   | `launchd`                                                 | `service control manager`                            |
| `Available`  | `systemctl` on `PATH`                       | `launchctl` on `PATH`                                     | the SCM accepts a connection                         |
| `Registered` | the unit file exists                        | the plist exists                                          | `OpenService` finds the service                      |
| `Register`   | write the unit file, `systemctl daemon-reload` | write the plist and the newsyslog rule                 | `CreateService` or `UpdateConfig`, recovery actions, Event Log source |
| `Unregister` | `systemctl stop`, `disable`, remove the unit file, `daemon-reload` | `launchctl bootout`, remove the plist and the newsyslog rule | stop, `Delete`, remove the Event Log source |
| `Start`      | `systemctl start`                           | `launchctl bootstrap system <plist>`                      | `Service.Start`                                      |
| `Stop`       | `systemctl stop`                            | `launchctl bootout` when loaded                           | `Service.Control(svc.Stop)`, then poll for `Stopped` |
| `Restart`    | `systemctl restart`                         | `launchctl kickstart -k`                                  | a detached `Restart-Service`                         |
| `Status`     | `systemctl is-active`                       | `launchctl print` reports `state = running`               | `Service.Query` reports `Running`                    |

`Status` returns `ErrNotRegistered` when the service definition is missing, and otherwise `StatusRunning` or `StatusStopped`.

`Register` never starts the service, on any platform. What "registered" means differs: a systemd unit is written but not enabled; a launchd plist in `/Library/LaunchDaemons` is loaded at the next boot; a Windows service with automatic start starts at the next boot.

`Stop` on launchd boots the daemon out rather than calling `launchctl stop`, because `KeepAlive` would restart a stopped daemon immediately. `Restart` on Windows goes through a detached PowerShell process: the SCM has no restart control, and the caller is usually the service being restarted, so stopping it from inside would kill whatever was meant to start it again.

### SystemdController

```go
type SystemdController interface {
    IsAvailable() bool
    DaemonReload() error
    Enable(service string) error
    Disable(service string) error
    Start(service string) error
    Stop(service string) error
    Restart(ctx context.Context, service string) error
    IsActive(service string) bool
}
```

Production implementation (`NewSystemdController()`) uses `os/exec` to call `systemctl`. The systemd `ServiceManager` drives `systemctl` only through this interface, so its unit-file flow is testable without systemd.

### RootChecker

```go
type RootChecker interface {
    IsRoot() bool
}
```

Production implementation (`NewRootChecker()`) uses `os.Getuid() == 0` on Unix and the process token's elevation state on Windows, where `os.Getuid` returns -1 and would refuse an Administrator along with everybody else.

## File paths and permissions

Linux:

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

The daemon's own output goes to journald.

macOS:

| Path                                                | Permission | Created by | Description                    |
|-----------------------------------------------------|------------|------------|--------------------------------|
| `/usr/local/bin/plexd`                              | 0755       | Install    | plexd binary                   |
| `/Library/Application Support/plexd/`               | 0755       | Install    | Configuration directory        |
| `/Library/Application Support/plexd/data/`          | 0700       | Install    | Data directory                 |
| `/var/run/plexd/`                                   | 0755       | Install    | Runtime directory              |
| `/Library/LaunchDaemons/com.plexsphere.plexd.plist` | 0644       | Install    | LaunchDaemon definition, `root:wheel` |
| `/Library/Logs/plexd/`                              | 0755       | Install    | Log directory                  |
| `/Library/Logs/plexd/plexd.log`                     | *(launchd)*| launchd    | Daemon stdout and stderr       |
| `/etc/newsyslog.d/com.plexsphere.plexd.conf`        | 0644       | Install    | Log rotation rule              |

launchd refuses to load a daemon whose plist is not owned by `root:wheel` and writable only by its owner, which is what the installer's own privileges produce.

Windows:

| Path                                    | Created by | Description                                        |
|-----------------------------------------|------------|----------------------------------------------------|
| `%ProgramFiles%\plexd\plexd.exe`         | Install    | plexd binary                                       |
| `%ProgramFiles%\plexd\plexd.exe.old`     | Upgrade    | The previous binary, removed by the next upgrade or at the next reboot after `plexd uninstall` |
| `%ProgramData%\plexd\`                   | Install    | Configuration directory                            |
| `%ProgramData%\plexd\data\`              | Install    | Data directory                                     |
| `%ProgramData%\plexd\run\`               | Install    | Runtime directory                                  |
| SCM service `plexd`                     | Install    | Service definition, in the SCM's own database      |
| Event Log source `plexd`                | Install    | The Application log the daemon writes to           |

Windows has no POSIX permission bits; access is governed by the ACLs those directories inherit.

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
curl -fsSL https://get.plexsphere.com/install.sh | sh -s -- [OPTIONS]
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
| `PLEXD_ARTIFACT_URL`  | Base URL for binary artifacts     | `https://artifacts.plexsphere.com/plexd`      |
