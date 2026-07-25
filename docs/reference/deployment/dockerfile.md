---
title: Container Image (Dockerfile) Reference
feature: PXD-0032
---

# Container Image (Dockerfile) Reference

Reference documentation for the multi-stage Dockerfile at `deploy/docker/Dockerfile`, which builds the plexd container image.

## Base Images

| Stage | Image | Purpose |
|-------|-------|---------|
| Builder | `golang:1.26-alpine` | Go toolchain for compiling plexd (matches `go.mod` Go version) |
| Runtime | `gcr.io/distroless/static-debian12` | Minimal runtime with no shell, no package manager, includes CA certificates |

## Build Command

From the repository root:

```bash
docker build -f deploy/docker/Dockerfile .
```

Or using the Makefile target (injects version metadata from git):

```bash
make docker-build
```

The Makefile target produces the image tagged as `ghcr.io/plexsphere/plexd:dev`.

## Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `VERSION` | `dev` | Version string injected via `-X main.version` ldflags |
| `COMMIT` | `none` | Git commit hash injected via `-X main.commit` ldflags |
| `DATE` | `unknown` | Build date injected via `-X main.date` ldflags |
| `TARGETOS` | `linux` | Target operating system for cross-compilation (`GOOS`) |
| `TARGETARCH` | `amd64` | Target architecture for cross-compilation (`GOARCH`) |

Example with explicit version metadata:

```bash
docker build -f deploy/docker/Dockerfile \
    --build-arg VERSION=1.0.0 \
    --build-arg COMMIT=$(git rev-parse --short HEAD) \
    --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    -t ghcr.io/plexsphere/plexd:1.0.0 .
```

The `VERSION`, `COMMIT`, and `DATE` values are passed to `go build -ldflags` targeting the variables in `cmd/plexd/main.go`:

```go
var (
    version = "dev"
    commit  = "none"
    date    = "unknown"
)
```

## Multi-Platform Builds

The Dockerfile supports building for `linux/amd64` and `linux/arm64` using Docker BuildKit's automatic `TARGETOS` and `TARGETARCH` arguments.

Build for a single platform:

```bash
docker buildx build -f deploy/docker/Dockerfile --platform linux/arm64 -t ghcr.io/plexsphere/plexd:dev .
```

Build and push a multi-arch manifest:

```bash
docker buildx build -f deploy/docker/Dockerfile \
    --platform linux/amd64,linux/arm64 \
    -t ghcr.io/plexsphere/plexd:latest \
    --push .
```

## Exposed Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9100 | TCP | Local node API (optional, token-gated, disabled by default) |
| 9101 | TCP | Health endpoints (`/healthz`, `/readyz`) |
| 51820 | UDP | WireGuard mesh traffic |

The liveness and readiness probes in `deploy/kubernetes/daemonset.yaml` target 9101, and 51820 is the default `wireguard.listen_port` in the configuration.

## Runtime User

The container runs as non-root user `65534:65534` (nobody). This can be overridden at runtime for privileged deployments that require `NET_ADMIN` capability (e.g., Kubernetes DaemonSet with `securityContext`).

## Directory Layout

| Directory | Purpose |
|-----------|---------|
| `/usr/local/bin/plexd` | Statically compiled plexd binary |
| `/var/lib/plexd` | Persistent data (state cache, node state) |
| `/var/run/plexd` | Runtime files (Unix socket, PID) |
| `/var/log/plexd` | Log files (startup log) |
| `/etc/plexd` | Configuration files |

All directories are created during the build with ownership set to `65534:65534`. In Kubernetes, these paths are typically backed by volume mounts (see `deploy/kubernetes/daemonset.yaml`).

## Entrypoint

The entrypoint is set to the binary in exec form:

```dockerfile
ENTRYPOINT ["/usr/local/bin/plexd"]
```

Pass any subcommand as arguments: `up`, `join`, `status`, etc. Use `--version` flag to display version information.

## Build Optimizations

- **Module cache layer**: `go.mod` and `go.sum` are copied and modules downloaded before the full source tree is copied. Source-only changes reuse the cached module layer.
- **Static binary**: Built with `CGO_ENABLED=0` and ldflags `-s -w` (stripped debug info and DWARF tables) for minimal binary size.
- **Distroless base**: The runtime image contains no shell, package manager, or unnecessary utilities — only the binary and CA certificates.

## .dockerignore

The `.dockerignore` file at the repository root excludes non-essential files from the Docker build context:

| Pattern | Reason |
|---------|--------|
| `.git/` | Git history not needed for build |
| `.github/` | CI workflows not needed for build |
| `.planwerk/`, `.claude/`, `.serena/` | Tooling directories |
| `docs/` | Documentation not needed for build |
| `deploy/systemd/`, `deploy/kubernetes/`, `deploy/cloud-init/` | Deploy manifests not needed for build |
| `deploy/install.sh`, `deploy/install_test.sh` | Install scripts not needed for build |
| `*_test.go`, `*_test.sh` | Test files not needed for build |
| `*.md` | Markdown files not needed for build |
| `LICENSE` | License file not needed for build |

The build context includes: `go.mod`, `go.sum`, `cmd/`, `internal/`, `Makefile`, and `deploy/docker/Dockerfile`.

## Testing

Run the Dockerfile validation tests (requires Docker):

```bash
sh deploy/docker/test_dockerfile.sh
```

The test script validates: hadolint compliance, successful build, version argument injection, non-root user, static binary, exposed ports, entrypoint, image size (< 30 MB), directory existence, and `.dockerignore` exclusions.
