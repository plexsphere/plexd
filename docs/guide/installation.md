---
title: Installation & Quick Start
---

# Installation & Quick Start

## Installation

### Binary

```bash
# Linux
curl -fsSL https://get.plexsphere.com/plexd | sh

# macOS — plexd runs as root, so the installer needs it too
curl -fsSL https://get.plexsphere.com/plexd | sudo sh
```

Windows has no install script: a POSIX shell script cannot serve it. Follow the [Windows Installation Guide](../how-to/windows-installation.md), which downloads the binary and registers the service by hand from an elevated PowerShell.

### Container

```bash
docker pull ghcr.io/plexsphere/plexd:latest
```

Every release publishes the same multi-arch image under several tags, so you can pin at whatever
granularity you want:

| Tag              | Example  | Moves                                          |
|------------------|----------|------------------------------------------------|
| `v<version>`     | `v0.2.0` | Never — the release version, spelled as the git tag and the GitHub release name |
| `<version>`      | `0.2.0`  | Never — the same image, without the `v` prefix |
| `<major>.<minor>`| `0.2`    | With each patch release in that minor series   |
| `<major>`        | `0`      | With each release in that major series         |
| `latest`         |          | With each release                              |
| `dev`            |          | With each push to `main` — unreleased, not for production |

`v<version>` and `<version>` point at the same manifest digest; pick the spelling that matches how
you record versions elsewhere.

### OpenWRT

No opkg package yet - download the release binary for your package
architecture (e.g. `plexd-linux-mipsle` for `mipsel_24kc` devices) and manage
it with the procd init script from `deploy/openwrt/` in the repository. See
the README there for requirements and step-by-step instructions.

### From Source

Requires Go 1.26+. Building needs nothing else. Running the Linux data plane additionally needs WireGuard tools and nftables on the host; macOS and Windows need nothing beyond the binary, because both carry their own userspace WireGuard.

```bash
git clone https://github.com/plexsphere/plexd.git
cd plexd
make build
```

## Quick Start

### Platform-Provisioned Node (Token via Cloud-Init)

No manual steps required - plexd reads the bootstrap token automatically:

```bash
plexd up
```

### Manual Enrollment

Generate a token in the Plexsphere UI or CLI, then:

```bash
# Interactive prompt (recommended - token never visible in shell history or process list)
plexd join

# From file
plexd join --token-file /etc/plexd/bootstrap-token

# From environment variable
PLEXD_BOOTSTRAP_TOKEN=plx_enroll_a8f3c7... plexd join
```

### Running as a Service

`plexd install` registers plexd with whatever service manager the host has, and never starts it. Start it with the matching command:

```bash
# Linux — systemd
sudo plexd install
sudo systemctl enable --now plexd
```

```bash
# macOS — launchd
sudo plexd install
sudo launchctl bootstrap system /Library/LaunchDaemons/com.plexsphere.plexd.plist
```

```powershell
# Windows — Service Control Manager, from an elevated PowerShell
.\plexd.exe install
sc.exe start plexd
```

The [macOS](../how-to/macos-installation.md) and [Windows](../how-to/windows-installation.md) guides carry the full walkthrough, including verification and uninstall.

### Kubernetes (DaemonSet)

> **Production:** Use [External Secrets Operator (ESO)](https://external-secrets.io) to provision the bootstrap token from your secrets manager (e.g. Vault, AWS Secrets Manager) instead of storing it as a plain Secret.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: plexd-bootstrap
  namespace: plexd-system
type: Opaque
stringData:
  token: "plx_enroll_a8f3c7..."
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: plexd
  namespace: plexd-system
spec:
  selector:
    matchLabels:
      app: plexd
  template:
    metadata:
      labels:
        app: plexd
    spec:
      hostNetwork: true
      serviceAccountName: plexd
      containers:
        - name: plexd
          image: ghcr.io/plexsphere/plexd:latest
          securityContext:
            capabilities:
              add:
                - NET_ADMIN
                - NET_RAW
          env:
            - name: PLEXD_API
              value: "https://api.plexsphere.com"
            - name: PLEXD_BOOTSTRAP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: plexd-bootstrap
                  key: token
          volumeMounts:
            - name: plexd-data
              mountPath: /var/lib/plexd
      volumes:
        - name: plexd-data
          hostPath:
            path: /var/lib/plexd
            type: DirectoryOrCreate
```

### Docker (Bridge Mode)

```yaml
services:
  plexd:
    image: ghcr.io/plexsphere/plexd:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - plexd-data:/var/lib/plexd
    environment:
      PLEXD_API: "https://api.plexsphere.com"
      PLEXD_BOOTSTRAP_TOKEN_FILE: /run/secrets/bootstrap-token
      PLEXD_MODE: bridge
    secrets:
      - bootstrap-token
    restart: unless-stopped

volumes:
  plexd-data:

secrets:
  bootstrap-token:
    file: ./bootstrap-token
```

## See Also

- [Platform Support](platform-support.md) — what Linux, macOS and Windows each support
- [macOS Installation Guide](../how-to/macos-installation.md)
- [Windows Installation Guide](../how-to/windows-installation.md)
- [Configuration Reference](../reference/core/configuration.md)
- [Environment Variables](../reference/core/environment-variables.md)
- [CLI Reference](../reference/core/cli.md)
