---
title: macOS Installation Guide
---

# macOS Installation Guide

Step-by-step guide for installing plexd on a Mac, where it runs as a launchd daemon.

## Prerequisites

- **A Mac** on Apple silicon or Intel. CI runs the test suite on macOS 26 arm64; the `amd64` binary is cross-compiled and not exercised there.
- **An administrator account.** plexd runs as root: creating a utun device, programming routes and loading a pf anchor are all privileged.
- **Network connectivity** to the control plane API.
- **A bootstrap token** from the control plane.
- **An untouched `/etc/pf.conf`**, if policy enforcement stays on. plexd loads its rules into the anchor `com.apple/plexd`, which only works while the main ruleset still references `anchor "com.apple/*"` and `nat-anchor "com.apple/*"`. Apple's default file does.

## Quick start

```sh
curl -fsSL https://get.plexsphere.com/install.sh | sudo sh -s -- \
  --token <YOUR_BOOTSTRAP_TOKEN> \
  --api-url https://api.plexsphere.com
```

This downloads `plexd-darwin-<arch>`, verifies its checksum, runs `plexd install`, and bootstraps the daemon into launchd.

### Install script flags

| Flag              | Description                                |
|-------------------|--------------------------------------------|
| `--token VALUE`   | Bootstrap token for enrollment             |
| `--api-url URL`   | Control plane API URL                      |
| `--version VERSION` | Version to install (default: `latest`)   |
| `--no-start`      | Don't start the daemon after install       |

The script does not create the `plexd` and `plexd-secrets` groups on macOS, which has no `groupadd`. It warns and carries on; see [Verification](#verification).

## Manual installation

### 1. Download and verify the binary

```sh
# Apple silicon
curl -fsSL -o /tmp/plexd https://artifacts.plexsphere.com/plexd/latest/plexd-darwin-arm64

# Intel
curl -fsSL -o /tmp/plexd https://artifacts.plexsphere.com/plexd/latest/plexd-darwin-amd64

chmod +x /tmp/plexd
```

Verify the checksum:

```sh
curl -fsSL -o /tmp/checksums.sha256 https://artifacts.plexsphere.com/plexd/latest/checksums.sha256

EXPECTED=$(grep ' plexd-darwin-arm64$' /tmp/checksums.sha256 | awk '{print $1}')
ACTUAL=$(shasum -a 256 /tmp/plexd | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] && echo "checksum ok" || echo "CHECKSUM MISMATCH"
```

Every release binary also carries a Sigstore bundle. Verifying it needs `cosign` and proves the binary came out of this repository's release workflow:

```sh
curl -fsSL -O https://artifacts.plexsphere.com/plexd/latest/plexd-darwin-arm64.sigstore.json

cosign verify-blob --bundle plexd-darwin-arm64.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/plexsphere/plexd/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  /tmp/plexd
```

Those two values are the defaults `upgrade.signing_identity_regexp` and `upgrade.signing_issuer` carry, which is what plexd itself checks before an in-place upgrade.

::: tip Gatekeeper
A binary fetched with `curl` carries no `com.apple.quarantine` attribute and runs as it is. One saved by a browser does; clear it with `xattr -d com.apple.quarantine /tmp/plexd`.
:::

### 2. Install as a launchd daemon

```sh
sudo /tmp/plexd install --token <YOUR_BOOTSTRAP_TOKEN> --api-url https://api.plexsphere.com
```

This creates:

| Path                                                | Description                           |
|-----------------------------------------------------|---------------------------------------|
| `/usr/local/bin/plexd`                              | plexd binary                          |
| `/Library/Application Support/plexd/`               | Configuration directory               |
| `/Library/Application Support/plexd/config.yaml`    | Service configuration                 |
| `/Library/Application Support/plexd/bootstrap-token`| Bootstrap token (0600)                |
| `/Library/Application Support/plexd/data/`          | Data directory (0700)                 |
| `/var/run/plexd/`                                   | Runtime directory                     |
| `/Library/LaunchDaemons/com.plexsphere.plexd.plist` | LaunchDaemon definition, `root:wheel` |
| `/Library/Logs/plexd/plexd.log`                     | Daemon stdout and stderr              |
| `/etc/newsyslog.d/com.plexsphere.plexd.conf`        | Log rotation rule                     |

The install registers the daemon; it does not start it.

### 3. Start the daemon

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.plexsphere.plexd.plist
```

## Automated installation

Pre-provision the token before running the installer, then leave `--token` off:

```sh
sudo mkdir -p "/Library/Application Support/plexd"
printf '%s' "<TOKEN>" | sudo tee "/Library/Application Support/plexd/bootstrap-token" >/dev/null
sudo chmod 600 "/Library/Application Support/plexd/bootstrap-token"
```

launchd has no `EnvironmentFile`, so `PLEXD_*` overrides do not work the way they do under systemd. Put the settings in `config.yaml`, or add an `EnvironmentVariables` dict to the plist by hand.

## Verification

### Check the daemon

```sh
sudo launchctl print system/com.plexsphere.plexd
```

Expect a line reading `state = running`.

### Check plexd

```sh
sudo plexd status
```

`sudo` is needed because the node API socket is owner-only until the `plexd` group exists. macOS keeps groups in Open Directory and nothing creates them for you; the [local node API guide](./local-node-api.md#prerequisites) has the `dscl` and `dseditgroup` commands, and the daemon must be restarted afterwards for the new mode to apply.

### View logs

```sh
plexd logs -f
```

That tails `/Library/Logs/plexd/plexd.log`, which is where launchd sends the daemon's output. Reading the file directly works too:

```sh
tail -f /Library/Logs/plexd/plexd.log
```

A `plexd up` started by hand in a terminal writes to that terminal instead, so the file stays empty on a host where the daemon was never installed.

## Uninstall

```sh
sudo plexd uninstall
```

This boots the daemon out, removes the plist, the newsyslog rule and the binary, and keeps `/Library/Application Support/plexd/`.

```sh
sudo plexd uninstall --purge
```

This removes the configuration and data directories as well.

## Troubleshooting

### The daemon restarts every five seconds

launchd has no counterpart to systemd's `StartLimitBurst`, so a daemon that exits on a configuration error is restarted forever. Read `/Library/Logs/plexd/plexd.log` for the reason, fix the configuration, then:

```sh
sudo launchctl kickstart -k system/com.plexsphere.plexd
```

To stop it entirely while you work:

```sh
sudo launchctl bootout system/com.plexsphere.plexd
```

### `wireguard setup failed, continuing without WireGuard`

The log carries `creating a utun device requires root`. plexd was started without root, so no tunnel was built and the agent is running without a mesh. The launchd daemon runs as root; a hand-started `plexd up` needs `sudo`.

### plexd exits before it registers, naming pf

```
policy enforcement needs root and a pf main ruleset that references anchor "com.apple/*"
```

plexd checks that it can enforce policy *before* it spends its one-shot bootstrap token. Either the process is not root, or `/etc/pf.conf` no longer references the wildcard anchors. Restore the file and reload it:

```sh
sudo pfctl -f /etc/pf.conf
```

To run the node without enforcement instead, set `policy.enabled: false` in `config.yaml`.

### `launchctl bootstrap` refuses the plist

launchd loads a daemon only when its plist is owned by `root:wheel` and writable by nobody else. That is what `sudo plexd install` produces; a plist copied into place by hand may not be.

```sh
sudo chown root:wheel /Library/LaunchDaemons/com.plexsphere.plexd.plist
sudo chmod 644 /Library/LaunchDaemons/com.plexsphere.plexd.plist
```

## See also

- [Platform Support](../guide/platform-support.md) — what macOS supports, feature by feature
- [Bare-Metal Packaging Reference](../reference/deployment/bare-metal-packaging.md) — the plist keys, the newsyslog rule and the full path table
- [CLI Reference](../reference/core/cli.md) — every command and its flags
- [Configuration Reference](../reference/core/configuration.md#platform-defaults) — the per-platform path defaults
