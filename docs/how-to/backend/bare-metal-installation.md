---
title: Bare-Metal Installation Guide
quadrant: backend
---

# Bare-Metal Installation Guide

Step-by-step guide for installing plexd on a bare-metal Linux server.

## Prerequisites

- **Linux** server (amd64 or arm64)
- **Root access** (sudo or root user)
- **Network connectivity** to the control plane API
- **Bootstrap token** from the control plane (for enrollment)

## Quick start

Install plexd with a single command:

```sh
curl -fsSL https://get.plexsphere.io/install.sh | sh -s -- \
  --token <YOUR_BOOTSTRAP_TOKEN> \
  --api-url https://api.your-plexsphere.io
```

This downloads the binary, verifies its checksum, installs plexd as a systemd service, and starts it.

### Install script flags

| Flag              | Description                                |
|-------------------|--------------------------------------------|
| `--token VALUE`   | Bootstrap token for enrollment             |
| `--api-url URL`   | Control plane API URL                      |
| `--version VERSION` | Version to install (default: `latest`)  |
| `--no-start`      | Don't start the service after install      |

## Manual installation

### 1. Download the binary

```sh
# For amd64
curl -fsSL -o /tmp/plexd https://artifacts.plexsphere.io/plexd/latest/plexd-linux-amd64

# For arm64
curl -fsSL -o /tmp/plexd https://artifacts.plexsphere.io/plexd/latest/plexd-linux-arm64

chmod +x /tmp/plexd
```

### 2. Install as a systemd service

```sh
sudo /tmp/plexd install --token <YOUR_BOOTSTRAP_TOKEN>
```

This creates:

| Path                                 | Description              |
|--------------------------------------|--------------------------|
| `/usr/local/bin/plexd`               | plexd binary             |
| `/etc/plexd/config.yaml`            | Service configuration    |
| `/etc/plexd/bootstrap-token`        | Bootstrap token (0600)   |
| `/var/lib/plexd/`                    | Data directory           |
| `/var/run/plexd/`                    | Runtime directory        |
| `/etc/systemd/system/plexd.service` | Systemd unit file        |

### 3. Enable and start the service

```sh
sudo systemctl enable --now plexd
```

## Automated installation

For automated provisioning with configuration management tools (Ansible, Puppet) or PXE boot:

### 1. Pre-provision the token file

Write the bootstrap token to `/etc/plexd/bootstrap-token` before running the installer:

```sh
mkdir -p /etc/plexd
echo -n "<TOKEN>" > /etc/plexd/bootstrap-token
chmod 600 /etc/plexd/bootstrap-token
```

### 2. Run the install script without --token

```sh
curl -fsSL https://get.plexsphere.io/install.sh | sh -s -- \
  --api-url https://api.your-plexsphere.io
```

plexd reads the pre-provisioned token file on startup and registers automatically.

### 3. Environment-based token

Alternatively, set the token via the systemd environment file:

```sh
mkdir -p /etc/plexd
echo "PLEXD_BOOTSTRAP_TOKEN=<TOKEN>" > /etc/plexd/environment
```

Token resolution order: direct value > file > environment variable > metadata service.

## Verification

### Check service status

```sh
sudo systemctl status plexd
```

Expected output:

```
● plexd.service - plexd node agent
     Loaded: loaded (/etc/systemd/system/plexd.service; enabled; preset: enabled)
     Active: active (running) since ...
```

### Check plexd status

```sh
plexd status
```

### View logs

```sh
# Follow logs in real-time
journalctl -u plexd -f

# View recent logs
journalctl -u plexd --since "5 minutes ago"
```

## Uninstall

### Preserve configuration and data

```sh
sudo plexd uninstall
```

This stops and disables the service, removes the binary and unit file, but keeps `/etc/plexd/` and `/var/lib/plexd/`.

### Purge everything

```sh
sudo plexd uninstall --purge
```

This removes all files including configuration and data directories.

## Troubleshooting

### Service fails to start

Check the journal for errors:

```sh
journalctl -u plexd -n 50 --no-pager
```

Common issues:

- **Missing token**: Provide a bootstrap token via `plexd join` or the `--token` flag.
- **Network unreachable**: Verify connectivity to the control plane API URL.
- **Permission denied**: Ensure plexd was installed as root.

### Verify the unit file

```sh
systemctl cat plexd
```

### Restart the service

```sh
sudo systemctl restart plexd
```

## See also

- [Bare-Metal Packaging Reference](../../reference/backend/bare-metal-packaging.md) — Full reference for InstallConfig, unit file directives, and install script flags.
