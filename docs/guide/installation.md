---
title: Installation & Quick Start
---

# Installation & Quick Start

## Installation

### Binary

```bash
curl -fsSL https://get.plexsphere.com/plexd | sh
```

### Container

```bash
docker pull ghcr.io/plexsphere/plexd:latest
```

### From Source

Requires Go 1.26+, WireGuard tools, and nftables.

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

```bash
sudo plexd install   # Creates systemd unit
sudo systemctl enable --now plexd
```

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

- [Configuration Reference](../reference/core/configuration.md)
- [Environment Variables](../reference/core/environment-variables.md)
- [CLI Reference](../reference/core/cli.md)
