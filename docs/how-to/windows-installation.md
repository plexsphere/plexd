---
title: Windows Installation Guide
---

# Windows Installation Guide

Step-by-step guide for installing plexd on Windows, where it runs as a service under the Service Control Manager.

There is no install script for Windows: `deploy/install.sh` is a POSIX shell script and cannot serve it. Every step below is run by hand from an elevated PowerShell.

## Prerequisites

- **Windows on x64 or ARM64.** CI runs the test suite on Windows Server 2025 x64; the ARM64 binary is cross-compiled and not exercised there.
- **An elevated PowerShell.** Start it with "Run as administrator". Creating a Wintun adapter, programming routes and installing filters all need Administrator; the installed service runs as LocalSystem, which satisfies the same requirement.
- **Network connectivity** to the control plane API.
- **A bootstrap token** from the control plane.

No driver download is needed. plexd carries the signed `wintun.dll` inside the binary, one architecture per build, and writes it next to `plexd.exe` before it creates the first adapter.

## Installation

### 1. Download and verify the binary

```powershell
Invoke-WebRequest -Uri https://artifacts.plexsphere.com/plexd/latest/plexd-windows-amd64.exe -OutFile plexd.exe
Invoke-WebRequest -Uri https://artifacts.plexsphere.com/plexd/latest/checksums.sha256 -OutFile checksums.sha256
```

On ARM64, fetch `plexd-windows-arm64.exe` instead.

```powershell
$expected = (Select-String -Path checksums.sha256 -Pattern 'plexd-windows-amd64\.exe$').Line.Split()[0]
$actual   = (Get-FileHash .\plexd.exe -Algorithm SHA256).Hash
if ($actual -ieq $expected) { "checksum ok" } else { "CHECKSUM MISMATCH" }
```

The comparison is case-insensitive because `Get-FileHash` prints uppercase hex and the checksum file holds lowercase.

Every release binary also carries a Sigstore bundle. Verifying it needs `cosign` and proves the binary came out of this repository's release workflow:

```powershell
Invoke-WebRequest -Uri https://artifacts.plexsphere.com/plexd/latest/plexd-windows-amd64.exe.sigstore.json -OutFile plexd.exe.sigstore.json

cosign verify-blob --bundle plexd.exe.sigstore.json `
  --certificate-identity-regexp '^https://github\.com/plexsphere/plexd/\.github/workflows/release\.yml@refs/tags/v.+$' `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  .\plexd.exe
```

Those two values are the defaults `upgrade.signing_identity_regexp` and `upgrade.signing_issuer` carry, which is what plexd itself checks before an in-place upgrade.

### 2. Install the service

```powershell
.\plexd.exe install --token <YOUR_BOOTSTRAP_TOKEN> --api-url https://api.plexsphere.com
```

This creates:

| Path or object                     | Description                                        |
|------------------------------------|----------------------------------------------------|
| `%ProgramFiles%\plexd\plexd.exe`    | plexd binary                                       |
| `%ProgramData%\plexd\`              | Configuration directory                            |
| `%ProgramData%\plexd\config.yaml`   | Service configuration                              |
| `%ProgramData%\plexd\bootstrap-token` | Bootstrap token                                  |
| `%ProgramData%\plexd\data\`         | Data directory                                     |
| `%ProgramData%\plexd\run\`          | Runtime directory                                  |
| SCM service `plexd`                | Service definition, automatic start, LocalSystem   |
| Event Log source `plexd`           | The Application log the daemon writes to           |

The binary is copied to `%ProgramFiles%\plexd\plexd.exe`, so the download can be deleted afterwards. The service is registered with automatic start but is not started by the install.

### 3. Start the service

```powershell
sc.exe start plexd
```

`Start-Service plexd` does the same thing.

### 4. Allow inbound WireGuard traffic

```powershell
New-NetFirewallRule -DisplayName 'plexd WireGuard' -Direction Inbound `
  -Protocol UDP -LocalPort 51820 -Action Allow
```

51820 is the `wireguard.listen_port` default; use the port your configuration sets. plexd's own WFP permits are soft, which means they cannot open a port Windows Defender Firewall closes, so this rule has to be added separately.

A node behind NAT that only ever initiates handshakes reaches its peers without the rule. A node other peers must reach directly needs it.

## Automated installation

Pre-provision the token before installing, then leave `--token` off:

```powershell
New-Item -ItemType Directory -Force -Path "$env:ProgramData\plexd" | Out-Null
Set-Content -Path "$env:ProgramData\plexd\bootstrap-token" -Value '<TOKEN>' -NoNewline
```

The service runs as LocalSystem and does not read an interactive user's environment, so `PLEXD_*` overrides set in a shell do not reach it. Put those settings in `config.yaml`.

## Verification

### Check the service

```powershell
Get-Service plexd
```

Expect `Status` to read `Running`. `sc.exe query plexd` reports the same thing.

### Check plexd

```powershell
plexd status
```

Run it from the elevated shell. The node API is a named pipe whose security descriptor admits LocalSystem and Administrators only, so a non-elevated shell is refused: an unelevated token carries the Administrators SID as deny-only.

### View logs

```powershell
plexd logs
```

That renders the 100 most recent Application-log records written under provider `plexd`, oldest first. The same query by hand:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='plexd'} -MaxEvents 50
```

Event Viewer shows them under Windows Logs, Application, source `plexd`. `plexd logs --follow` is refused on Windows: the Event Log's live feed is a subscription with no command-line form.

A `plexd up` started by hand in a console logs to stderr rather than to the Event Log, so only what the service wrote appears there.

## Uninstall

```powershell
plexd uninstall
```

This stops the service, deletes it from the SCM, removes the Event Log source, and keeps `%ProgramData%\plexd\`.

```powershell
plexd uninstall --purge
```

This removes the configuration and data directories as well.

Windows refuses to delete a running image, and `plexd uninstall` usually runs from the installed path. The binary is renamed to `plexd.exe.old` and handed to the boot-time delete queue, so it disappears at the next reboot.

## Troubleshooting

### `wireguard setup failed, continuing without WireGuard`

The log carries `Access is denied. (creating a Wintun adapter requires Administrator)`. plexd was started from a shell that is not elevated, so no adapter was created and the agent is running without a mesh. The service runs as LocalSystem and is unaffected.

### `wintun.dll is missing beside plexd.exe`

plexd writes the embedded driver next to its own binary before creating the first adapter. This means the file was removed afterwards, or the directory is not writable by the account the service runs under. Reinstalling puts it back.

### plexd exits before it registers, naming Administrator

```
policy enforcement needs Administrator
```

plexd checks that it can enforce policy *before* it spends its one-shot bootstrap token. Run it elevated or as the LocalSystem service. To run the node without enforcement instead, set `policy.enabled: false` in `config.yaml`.

### The service restarts every five seconds

The SCM's recovery actions retry three times five seconds apart and then apply the last action to every later failure, so a service that exits on a configuration error restarts indefinitely. Inspect the actions with `sc.exe qfailure plexd`, and read the Event Log for the reason.

### `service.reload_config` fails

Windows has no signal that maps to a configuration reload, so the action returns `reload signal not supported on windows; restart the service instead`. Restart it:

```powershell
Restart-Service plexd
```

### `wg show` reports no device

`wgctrl` and `wg.exe` reach a WireGuard device only through a LocalSystem-owned UAPI pipe. A plexd started from a console owns its own pipe, so those tools find nothing; against the service, which is how plexd normally runs, `wg show plexd0` works.

## See also

- [Platform Support](../guide/platform-support.md) — what Windows supports, feature by feature
- [Bare-Metal Packaging Reference](../reference/deployment/bare-metal-packaging.md) — the SCM configuration, recovery actions and the full path table
- [CLI Reference](../reference/core/cli.md) — every command and its flags
- [Using the Local Node API](./local-node-api.md) — reaching the named pipe from a client
