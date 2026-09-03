---
title: Getting Started with Development
package: cmd/plexd
feature: PXD-0026
---

# Getting Started with Development

## Prerequisites

- Go 1.26+
- WireGuard tools (`wg`, `wg-quick`)
- nftables
- Docker (for integration tests)

## Make Targets

```bash
make build        # Build binary
make test         # Run unit tests
make test-e2e     # Run integration tests (requires Docker)
make lint         # Run linter
```

## Project Structure

```
plexd/
├── cmd/                    # CLI entrypoints
│   └── plexd/
├── internal/
│   ├── actions/            # Remote actions, hook execution, file watcher
│   ├── agent/              # Core agent lifecycle and heartbeat
│   ├── api/                # Control plane API client, SSE, event verification
│   ├── auditfwd/           # Audit log collection and forwarding (auditd, K8s)
│   ├── bridge/             # Bridge mode: user access, public ingress, site-to-site, relay
│   ├── fsutil/             # Atomic file operations
│   ├── integrity/          # Binary and file integrity verification
│   ├── kubernetes/         # K8s detection, CRD controller, PlexdHook types
│   ├── logfwd/             # Log collection and forwarding (journald, file sources)
│   ├── metrics/            # Metrics collection, system stats, tunnel stats
│   ├── nat/                # STUN-based NAT traversal and endpoint discovery
│   ├── nodeapi/            # Local Node API server, state cache, report sync
│   ├── packaging/          # Host service installer: systemd unit, launchd plist, Windows service
│   ├── paths/              # Per-platform default config, data and runtime dirs
│   ├── peerexchange/       # Peer endpoint exchange protocol
│   ├── policy/             # Network policy evaluation, nftables firewall rules
│   ├── reconcile/          # Configuration reconciliation loop
│   ├── registration/       # Token handling, enrollment, Ed25519 key management
│   ├── tunnel/             # SSH server, secure access tunneling, K8s API proxy
│   └── wireguard/          # WireGuard interface management via netlink
├── deploy/
│   ├── cloud-init/         # Cloud-init templates and Terraform examples
│   ├── install.sh          # Bare-metal installer script
│   ├── kubernetes/         # DaemonSet manifests, RBAC
│   │   └── crds/           # Custom Resource Definitions (PlexdHook, PlexdNodeState)
│   └── systemd/            # Unit files
├── docs/
│   ├── how-to/             # Task-oriented guides
│   └── reference/          # API and configuration reference
├── Makefile
└── README.md
```

## Platform-specific files

Code that only builds on some operating systems lives in its own file, tagged by the platform it serves. Two conventions are in use:

| Tag | File suffix | Used for | Examples |
|---|---|---|---|
| `//go:build linux` / `//go:build darwin` / `//go:build windows` / `//go:build !linux && !darwin && !windows` | `_linux.go` / `_darwin.go` / `_windows.go` / `_other.go` | Controllers with a per-OS implementation, paired with a stub on the platforms that have none yet | `cmd/plexd/cmd/up_linux.go`, `cmd/plexd/cmd/up_darwin.go`, `cmd/plexd/cmd/up_windows.go`, `cmd/plexd/cmd/up_other.go`, `internal/wireguard/controller_linux.go`, `internal/wireguard/controller_darwin.go`, `internal/wireguard/controller_windows.go`, `internal/bridge/route_linux.go`, `internal/bridge/route_darwin.go`, `internal/bridge/route_windows.go`, `internal/policy/nftables_linux.go`, `internal/policy/pf_darwin.go`, `internal/policy/wfp_windows.go`, `internal/nodeapi/socket_perms_other.go` |
| `//go:build unix` / `//go:build windows` | `_unix.go` / `_windows.go` | Syscall helpers that Linux and macOS share | `internal/actions/builtins_unix.go`, `internal/actions/builtins_windows.go`, `internal/packaging/root_unix.go`, `internal/packaging/root_windows.go`, `cmd/plexd/cmd/service_unix.go`, `cmd/plexd/cmd/service_windows.go`, `internal/wireguard/uapi_unix.go`, `internal/wireguard/uapi_windows.go` |
| `//go:build unix && !darwin` / `//go:build darwin` / `//go:build windows` | `_unix.go` / `_darwin.go` / `_windows.go` | Values every Unix but macOS shares, with macOS and Windows each answering for itself | `internal/paths/paths_unix.go`, `internal/paths/paths_darwin.go`, `internal/paths/paths_windows.go`, `internal/packaging/defaults_unix.go`, `internal/packaging/defaults_darwin.go`, `internal/packaging/defaults_windows.go` |

Pick `unix` / `windows` when Linux and macOS want the same implementation; `!linux` would wrongly catch Windows. When macOS needs its own answer, narrow the Unix file to `unix && !darwin` and put a `_darwin.go` beside it rather than renaming it to `_linux.go`: that name carries an implicit `linux` constraint and would leave every other Unix, freebsd included, with no definition at all. Every such file carries an explicit `//go:build` line, even when its name already implies the constraint: only `_windows.go`, `_linux.go` and `_darwin.go` are implicit to the Go tool, and `_unix.go` and `_other.go` are not.

Before pushing, check that the tree still builds for every supported target:

```bash
for t in linux/amd64 linux/arm64 linux/mipsle darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build ./... || exit 1
done

for t in linux/amd64 linux/arm64 linux/mipsle darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go vet ./... || exit 1
done
```

`go vet` compiles the test files too, so it catches a platform-tagged test that no longer builds.

CI covers the same ground: the [Build workflow](./release-workflow.md) compiles all seven targets on every pull request, and the [CI workflow](./ci-workflow.md) runs `go test -race ./...` on Linux, Windows and macOS. The loop above is a faster local check, not the only one.

## Tests that cannot run everywhere

Most tests run on all three platforms. A test that cannot is constrained, never deleted or excluded from `./...`, and the constraint says what the platform lacks:

| Situation | What to write |
|---|---|
| Every test in the file needs hook scripts | Tag the file `//go:build unix` and name it `_unix_test.go` (`internal/actions/watcher_unix_test.go`) |
| One test needs a hook script | `requireHookScripts(t)`, which skips on Windows |
| One test asserts POSIX permission bits, or forces a failure with `os.Chmod` | Skip on `runtime.GOOS == "windows"` |
| A test checks a mode alongside other things | Wrap only the mode assertion in `if runtime.GOOS != "windows"`, so the rest still runs |
| A test binds a Unix socket | Use the package's `shortSocketPath(t)` helper |
| The test would install or register a real service on a privileged runner | Skip when `packaging.NewRootChecker().IsRoot()` is true (`cmd/plexd/cmd/install_test.go`) |
| The test creates a real utun, which needs root | Skip unless `os.Geteuid() == 0` (`internal/wireguard/controller_darwin_test.go`, `TestDarwinController_RealUTUN`). CI runs it in its own privileged step on the macOS runner; locally, `sudo go test -run TestDarwinController_RealUTUN ./internal/wireguard/` |
| The test creates a real Wintun adapter, which needs the driver and Administrator | Skip unless `PLEXD_TEST_REAL_WINTUN=1` and the process token is elevated (`internal/wireguard/controller_windows_test.go`, `TestWindowsController_RealWintun`). The variable is the gate because the Windows runner is already elevated; CI runs it in its own step there, and locally it is `$env:PLEXD_TEST_REAL_WINTUN='1'; go test -run TestWindowsController_RealWintun ./internal/wireguard/` from an elevated shell |
| The test alters the routing table and the forwarding sysctl, which needs root | Skip unless `os.Geteuid() == 0` (`internal/bridge/route_darwin_test.go`, `TestDarwinRouteController_Real`). CI runs it in the privileged macOS step; locally, `sudo go test -run TestDarwinRouteController_Real ./internal/bridge/` |
| The test alters the routing table and an adapter's forwarding flag, which needs Administrator | Skip unless `PLEXD_TEST_REAL_ROUTES=1` and the process token is elevated (`internal/bridge/route_windows_test.go`, `TestWindowsRouteController_Real`). CI runs it in its own step; locally it is `$env:PLEXD_TEST_REAL_ROUTES='1'; go test -run TestWindowsRouteController_Real ./internal/bridge/` from an elevated shell |
| The test loads a pf anchor and takes a pf enable reference, which needs root | Skip unless `os.Geteuid() == 0` (`internal/policy/pf_darwin_test.go`, `TestPFController_Real`); CI runs it in the privileged macOS step; locally `sudo go test -run TestPFController_Real ./internal/policy/` |
| The test programs the filter engine and creates a NetNat object, which needs Administrator | Skip unless `PLEXD_TEST_REAL_WFP=1` and the token is elevated (`internal/policy/wfp_windows_test.go`, `TestWFPController_Real`; `netnat_windows_test.go`, `TestWFPController_RealNAT`); CI runs them in their own step; locally `$env:PLEXD_TEST_REAL_WFP='1'; go test -run 'TestWFPController_Real' ./internal/policy/` from an elevated shell |

Hooks are discovered by their executable bit and executed directly, so they are `#!/bin/sh` scripts; Windows has neither the mode bit nor the interpreter. Windows reports `0666` or `0777` from `Mode().Perm()`, `os.Chmod` there only toggles the read-only attribute, and a read-only directory still accepts writes, so a test that injects a failure that way cannot work.

`shortSocketPath` exists because `t.TempDir()` embeds the test's own name in the path, which overruns the 104-byte `sun_path` limit on macOS for a long-named test.

A shared helper that untagged tests call must itself live in an untagged file, or the package stops compiling on Windows. `internal/actions/helpers_test.go` holds those for that package, `TestMain` among them, so goroutine-leak checking still runs where the tagged files do not build.

The repository's `.gitattributes` sets `* -text`, which stops git from rewriting line endings on a Windows checkout. Without it, `internal/upgrade/testdata/fixture.bin` would be converted to CRLF and no longer match the digest its checked-in Sigstore bundle pins.

## Client-Side Implementation

| Module | Responsibility |
|---|---|
| `internal/registration/` | Generate key pair, exchange bootstrap token for node identity |
| `internal/api/` | SSE stream, receive peer updates with public keys and PSKs, Ed25519 event signature verification |
| `internal/wireguard/` | WireGuard interface management via netlink, apply key and peer configuration |
| `internal/nat/` | STUN discovery, report and receive endpoint updates |
| `internal/peerexchange/` | Peer endpoint exchange protocol |
| `internal/reconcile/` | Periodic full-state comparison: local WireGuard config vs. control plane |
| `internal/actions/` | Remote actions, hook execution engine, checksum verification, file watcher |
| `internal/tunnel/` | SSH server, secure access tunneling, K8s API proxy |
| `internal/nodeapi/` | Local Node API server (Unix socket + optional TCP), auth, state cache, report sync |
| `internal/kubernetes/` | K8s detection, CRD controller, PlexdHook types |
