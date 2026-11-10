---
title: Systemd E2E Test
package: test/e2e/systemd
feature: PXD-0040
---

# Systemd E2E Test

Validates that plexd runs correctly as a systemd service by deploying it inside a privileged Ubuntu container with systemd as PID 1. The test installs the plexd binary and the production `plexd.service` unit file, starts the service via `systemctl`, polls the mock-api assertion endpoint to verify registration, heartbeat, state retrieval, capabilities reporting, state convergence, and observability forwarding (metrics, logs, audit), checks that the mesh DNS resolver registers with the container's systemd-resolved and answers through it, then verifies clean shutdown.

## Container Topology

```
┌──────────────┐       ┌─────────────────────────┐
│   mock-api   │◄──────│   systemd container     │
│  :8080 (HTTP)│       │  (Ubuntu 24.04)         │
│  :8443 (TLS) │       │  systemd PID 1          │
│  /v1/health  │       │  plexd.service managed   │
└──────────────┘       └─────────────────────────┘
        │                          │
        └──── plexd-systemd-e2e ───┘
              (Docker network)
```

| Container | Image | Source | Purpose |
|-----------|-------|--------|---------|
| `plexd-e2e-mockapi` | `mockapi:e2e-systemd` | `test/e2e/mockapi/Dockerfile` | Fixture-based mock Central API, tracks call counters |
| `plexd-e2e-systemd` | `plexd-systemd:e2e` | `test/e2e/systemd/Dockerfile` | Ubuntu 24.04 with systemd as PID 1, runs plexd as a real service |

The systemd image installs `dbus` and `systemd-resolved` next to `systemd`, `systemd-sysv`, `curl`, `ca-certificates`, `jq`, `openssh-client`, and `sshpass`. Both install enabled, so the container boots with a system bus and its own systemd-resolved, which plexd registers its mesh DNS resolver with. Docker mounts its own `/etc/resolv.conf` (`nameserver 127.0.0.11`) over the one the package would link, so systemd-resolved runs in foreign mode with Docker's DNS as its global server, `nsswitch.conf` keeps `hosts: files dns`, and the mesh DNS phases ask systemd-resolved directly with `resolvectl`. Every `resolvectl` call runs inside the container through `docker exec` and reaches the container's systemd-resolved, never the host's.

## Test Phases

### 1. Pre-flight checks

Verifies that `docker`, `curl`, and `jq` are available on `$PATH`. Exits immediately if any tool is missing.

### 2. Pre-cleanup

Removes any leftover containers and network from a previous run (handles the case where a prior run was killed with SIGKILL and the trap did not fire).

### 3. Image build

Builds the mock-api image, the systemd container image, and cross-compiles the plexd binary using a Go Alpine container. The Go version is extracted from `go.mod`.

### 4. Network and container startup

Creates a Docker bridge network and starts both containers on it. The systemd container runs with `--privileged`, `--cgroupns=host`, and cgroup volume mounts for full systemd functionality.

### 5. Service installation

Copies the plexd binary, the production `deploy/systemd/plexd.service` unit file and the two session helper units (`plexd-session-helper.socket`, `plexd-session-helper@.service`) into the systemd container. Writes `config.yaml` pointing at the mock-api container and the bootstrap token to `/etc/plexd/bootstrap-token` (mode 0600), before the service starts so the unit can grant write access to it, and creates `/etc/plexd/hooks` as `plexd install` would. Runs `systemctl daemon-reload` and `systemctl enable --now plexd`, then checks that `systemctl is-active plexd-session-helper.socket` prints `active`: `plexd.service` wants the socket and names it in `Also=`.

### 6. Assertion polling

Polls `GET http://localhost:18080/test/assertions` every 3 seconds for up to 60 seconds (configurable via `TIMEOUT`).

### 7. Request body validation

Uses `GET /test/last-request/{endpoint}` to verify the content of request payloads:

| Endpoint | Validated Fields |
|----------|-----------------|
| `register` | `token` (non-empty), `hostname` (non-empty) |
| `heartbeat` | Valid JSON with `timestamp` field |
| `capabilities` | `binary_version` (non-empty), `binary_checksum` (32-byte base64 digest), eleven `builtin_actions`; `binary` and `plexd_hooks` absent |

### 8. Spent token cleanup

The unit keeps `/etc` read-only and grants write access to `/etc/plexd/bootstrap-token` alone, so plexd cannot unlink the token it spent and empties the file instead. The phase fails unless `stat -c %s /etc/plexd/bootstrap-token` prints `0`, `journalctl -u plexd` contains `token file emptied, it could not be removed`, and the journal contains neither `failed to delete token file` nor `hook watcher stopped`.

### 9. Periodic loop verification

Waits up to 60 seconds for `heartbeat_count`, `metrics_count`, and `logs_count` to reach >= 2, proving that periodic loops run continuously. Logs work via journald in the systemd container. Audit is tested separately via restart.

### 10. Audit forwarding via service restart

The `ProcessSource` uses `sync.Once` to emit a single `process_start` audit entry per process lifetime. The test restarts the plexd service via `systemctl restart plexd`, creating a new process with a fresh `ProcessSource`, and verifies `audit_count` increases.

### 11. Local endpoint delivery

Polls `GET /test/assertions` until `local_metrics_count`, `local_logs_count`, and `local_audit_count` are all >= 1 (timeout: 60s). Validates that the local endpoint credential chain works with systemd: NSK from registration → secret fetch → AES-256-GCM decryption → Bearer token → HTTPS POST to `plexd-e2e-mockapi:8443`.

### 12. Mediated ssh session

Drives a mediated ssh session through the sessions block, the socket-activated session helper and a real OpenSSH client, over connections plexd opens to the mock. An ssh session binds no listener, so every login goes through the mock's relay: the helper `session_connect <session_id>` posts to `POST /test/session-connect` and prints the relay port, and `ssh_in_node` takes a session id, opens a connection with that helper, and runs `sshpass -e ssh … -p <port> <user>@plexd-e2e-mockapi <command>` inside the container (`docker exec`). Once the client connects, the mock broadcasts a signed `session_connect` event, plexd opens the WebSocket, and the mock splices the client onto it, so every login runs over a connection plexd opened. The image carries `openssh-client`, `sshpass` and an unprivileged user `e2e`. Each login uses `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1`; the last option makes a refused token end ssh with `255` instead of sshpass giving up on a second prompt. Tokens come from `POST /test/session-token`.

1. Configures an `ssh` entry for `root` and waits up to 60 s for its `session_started` row; without one it prints `journalctl -u plexd` and fails. It also fails when the row carries `listener_endpoint`.
2. Runs `id -un` as `root` and expects `root`, then a last session activity body with `ssh.command == "id -un"` and `ssh.exit_code == 0`.
3. Checks that `/etc/plexd/session-signing-key` has mode `644` and holds `signing_public_key` from `identity.json`, the key the helper pinned on its first run.
4. Records `session_activity_count`, adds an entry for `e2e`, waits for the counter to rise, and checks that the last body is an ssh `session_started` row, because started rows no longer differ by endpoint. It then expects `id -un` to print `e2e`, which proves the helper switched uid.
5. Expects `exit 3` to exit `3`, and a token minted for another session id to end with `255` and `Permission denied`.
6. Drains the block, waits up to 60 s for `session_activity_count` to rise by 2, and requires `session_activity_rejected_count` unchanged: both `session_ended` rows post for sessions the mock already holds as revoked, and the mock, like the control plane, records the ending row of such a session once, so both are accepted, as the tcp drain is in the docker suite. The last body is an ssh `session_ended` row with `terminated_by` `plexd_close`.
7. Opens a connection for the drained `sess-e2e-ssh-root`. plexd finds no live session and opens nothing, so the `ssh` attempt exits `255`, `session_connection_timeout_count` rises by 1, `session_connection_count` does not move, and `journalctl -u plexd` contains `session_connect names no live ssh session; not connecting`.

### 13. Mesh DNS through systemd-resolved

plexd answers the `dns` block of its state pull on its own mesh IP, `10.99.0.1:5354`, and registers that server with the container's systemd-resolved for the mesh zones on `plexd0` (see [Mesh DNS](../networking/mesh-dns.md)). The mock's fixture block has the search domain `app.e2e.internal`, the zones `app.e2e.internal` and `e2e.internal`, the reverse zone `0.99.10.in-addr.arpa`, the hosts `node-1`, `peer-1` and `peer-2` under `app.e2e.internal` at `10.99.0.1` to `10.99.0.3`, and eight records (see [the mock's fixture](mock-api-server.md)): the `A` records `192.0.2.10` and `192.0.2.11` and the `AAAA` record `2001:db8::10` at `db.e2e.internal`, the `SRV` record `0 5 5432 db.e2e.internal` at `_db._tcp.app.e2e.internal`, the `MX` record `10 mail.example.com` and the `TXT` record `"v=e2e" "owner=plexd"` at `e2e.internal`, and the CNAMEs `alias.app.e2e.internal` to `peer-2.app.e2e.internal` and `ext.e2e.internal` to `ext.example.com`. Every query runs `resolvectl query <name>` inside the container. An answer counts only when its line reads `<name>: <value>` and ends in `-- link: plexd0`. `resolvectl` prints every further address of a name on an indented line of its own, which must end in `-- link: plexd0` too. A query for one record type adds `--type=<type>`, and its answer counts only when a line starts with `<name> IN <type> <data>` and ends in `-- link: plexd0`. A failure counts as an NXDOMAIN only when it reads `'<name>' not found`, and as a NODATA only when it reads `'<name>' does not have any RR of the requested type`. `resolvectl` wraps a long domain list onto the next line, so the phase compares domain lists word by word. Every check fails the suite.

1. **Interface.** `/sys/class/net/plexd0` must exist. No earlier phase depends on the WireGuard interface, and the resolver listens on its mesh IP.
2. **Registration.** It polls `resolvectl status plexd0` every 2 seconds for up to 30 seconds until its `DNS Servers:` line is exactly `10.99.0.1:5354`. plexd registers on the first pull after a start, and the last start was the audit phase's restart, so the registration is normally in place already. The output must then hold the words `app.e2e.internal`, `~e2e.internal`, `~0.99.10.in-addr.arpa` and `-DefaultRoute`, and `resolvectl domain plexd0` must list exactly `app.e2e.internal`, `~0.99.10.in-addr.arpa` and `~e2e.internal`: the search domain once, and no routing domain for `app.e2e.internal`, which `~e2e.internal` covers. The journal must hold a `mesh dns registered with systemd-resolved` line of the running process (`plexd[<MainPID>]:`) with `interface=plexd0` and `server=10.99.0.1:5354`.
3. **Names.** `peer-1.app.e2e.internal` must answer `10.99.0.2` on `plexd0`. The bare `peer-1` must answer `10.99.0.2` on `plexd0` as `(peer-1.app.e2e.internal)`, through the search domain. `10.99.0.3` must answer `peer-2.app.e2e.internal` on `plexd0`, through the reverse zone. `nope.app.e2e.internal` must fail with `not found`.

   3b. **Records.** `db.e2e.internal` must answer `192.0.2.10`, `192.0.2.11` and `2001:db8::10`, each on `plexd0`. `alias.app.e2e.internal` must answer `10.99.0.3` on `plexd0` as `(peer-2.app.e2e.internal)`: plexd follows the CNAME inside its zones and answers it together with the address of `peer-2`. `--type=SRV _db._tcp.app.e2e.internal` must print `_db._tcp.app.e2e.internal IN SRV 0 5 5432 db.e2e.internal`, `--type=MX e2e.internal` must print `e2e.internal IN MX 10 mail.example.com`, and `--type=TXT e2e.internal` must print `e2e.internal IN TXT "v=e2e" "owner=plexd"`, each on `plexd0`. `--type=MX db.e2e.internal` must fail with `does not have any RR of the requested type`. `ext.e2e.internal` is not asked for here: its target lies outside the mesh zones, and systemd-resolved would follow it through Docker's DNS.
4. **Other names.** The mock API's container name, qualified with the network's name, `plexd-e2e-mockapi.plexd-systemd-e2e`, must answer the address `docker inspect` gives for the container on `plexd-systemd-e2e`, and the output must not name `plexd0`: Docker's DNS answers it as systemd-resolved's global server. The bare container name cannot be used, because systemd-resolved sends no single-label name to a DNS server.
5. **A changed block.** It reads the live snapshot, requires its `dns.hosts` to carry `peer-1.app.e2e.internal` at `10.99.0.2` once, renames that host to `db-1.app.e2e.internal`, and adds the zone `ops.e2e.test` and the host `gw.ops.e2e.test` at `10.99.0.4`. In `dns.records` it sets the `A` record `192.0.2.10` of `db.e2e.internal` to `192.0.2.20`, removes `ext.e2e.internal`, adds the CNAME `mock.e2e.internal` to `plexd-e2e-mockapi.plexd-systemd-e2e`, the name step 4 resolves, and adds eight `TXT` records at `big.e2e.internal`, each with one string: a digit from `0` to `7`, `-` and 200 times `x`. It sorts the records by `fqdn`, then `type`, as the control plane serves them, and posts the result to `POST /test/configure-state`, so every other block travels back verbatim. No event nudges plexd: the heartbeat answers `reconcile: true`, so a pull comes about every 30 seconds. The phase polls every 3 seconds for up to 90 seconds until `resolvectl domain plexd0` lists `~ops.e2e.test`, `db-1.app.e2e.internal` answers `10.99.0.2` on `plexd0`, `gw.ops.e2e.test` answers `10.99.0.4` on `plexd0`, `peer-1.app.e2e.internal` fails with `not found`, `db.e2e.internal` answers `192.0.2.20` and `192.0.2.11` on `plexd0` and no longer `192.0.2.10`, and `ext.e2e.internal` fails with `not found`. `gw.ops.e2e.test` is asked for only once `plexd0` routes its zone, so no query for it leaves through the global server. `ext.e2e.internal` is asked for only once `db.e2e.internal` answers the changed records: before that pull plexd still answers the CNAME to `ext.example.com`, and systemd-resolved would follow it through Docker's DNS, which on an offline runner can stall each pass. The domain list must then be exactly `app.e2e.internal`, `~0.99.10.in-addr.arpa`, `~e2e.internal` and `~ops.e2e.test`, and `systemctl show -p MainPID --value plexd` must print the PID it printed before the post. The query for `mock.e2e.internal` must then exit 0 with the line `mock.e2e.internal: <address>`, the address step 4 checks, and with `(plexd-e2e-mockapi.plexd-systemd-e2e)`, and that line must not end in `-- link: plexd0`: plexd answers the CNAME alone, and systemd-resolved follows it through Docker's DNS. `--type=TXT big.e2e.internal` must print exactly eight lines that start with `big.e2e.internal IN TXT "` and end in `-- link: plexd0`. The eight records take more than 1232 bytes, the most plexd sends over UDP, so plexd sends the UDP answer with TC set and systemd-resolved asks again over TCP. The eight lines alone do not prove that repeat, because systemd-resolved 255 also accepts an untruncated UDP reply larger than the 1472 bytes it offers. The query therefore runs with the container's systemd-resolved at log level debug, set with `resolvectl log-level debug` and put back afterwards, and with its cache flushed, and `journalctl -u systemd-resolved` since the query must hold `Reply truncated, retrying via TCP.`
6. **A paused control plane.** It runs `docker pause plexd-e2e-mockapi` for 20 seconds. After 10 seconds it runs `resolvectl flush-caches` in the container. `db-1.app.e2e.internal` must then answer `10.99.0.2` and `db.e2e.internal` must answer `192.0.2.20`, each on `plexd0` with the line `-- Data from: network`, so the answers came from plexd and not from systemd-resolved's cache. After `docker unpause` it waits 2 seconds, so a request plexd sent into the paused mock and that completes once it runs again is not counted, reads `heartbeat_count` and `state_count`, and polls for up to 60 seconds until both have grown: plexd sent a heartbeat and the pull its `reconcile: true` answer asks for. While the mock is paused, `MOCK_PAUSED` is set, and `fail` and the `EXIT` trap both run `docker unpause` first.

### 14. Start after a reboot

A reboot empties `/run`, which takes `/run/plexd` with it. The phase stops plexd, removes `/run/plexd` and starts plexd again, then waits up to 30 s for `/var/run/plexd/api.sock` and expects `systemctl is-active plexd` to print `active`. Every `ReadWritePaths` entry of the unit is optional, so systemd skips the missing directory instead of failing with `226/NAMESPACE`, and plexd recreates it for the node API socket.

The stop also takes the mesh DNS registration with it. Right after `systemctl stop plexd`, `resolvectl query db-1.app.e2e.internal` must fail without naming `10.99.0.2` or `plexd0`, `resolvectl domain` must list no domain that contains `e2e.internal`, and the journal of the stopped process must hold `mesh dns registration reverted` with `interface=plexd0`. These checks sit here and not in the shutdown phase because the opt-out phase leaves nothing registered for the final stop to remove. After the start, the phase polls `db-1.app.e2e.internal` every second until it answers `10.99.0.2` on `plexd0` again, and fails if that takes more than 30 seconds from the phase's start, the stop included. The first pull of the new process serves the block step 5 of the mesh DNS phase configured.

### 15. Mesh DNS opt-out

The phase reads `/etc/plexd/config.yaml`, fails if a line already starts with `dns:`, appends `dns: {enabled: false}` as a block, and runs `systemctl restart plexd`. The journal of the new process must hold `mesh dns disabled by dns.enabled` within 30 seconds, and must not hold `mesh dns listening`. The phase then waits for `state_count` to grow past its value after the restart, for up to 60 seconds from the restart, so a pull carrying the `dns` block reached the new process. `resolvectl status plexd0` must then exit 0 and show no DNS server, and `resolvectl domain plexd0` must list no domain. The restart's stop reverted the registration of the run before, and a disabled resolver registers nothing.

### 16. Shutdown verification

Stops the service with `systemctl stop plexd`, verifies `inactive` state and exit code 0, checks `journalctl -u plexd` for absence of crash indicators (`core dumped`, `segfault`, `SIGABRT`, `SIGKILL`), and verifies the shutdown message was logged. It runs with the opt-out of phase 15 in place.

### 17. Cleanup

The `cleanup` function runs on `EXIT` trap (both success and failure). It unpauses the mock API if the mesh DNS phase left it paused, prints diagnostics on failure, then removes both containers and the Docker network.

## Assertion Logic

The test polls `GET http://localhost:18080/test/assertions` which returns JSON counters:

```json
{
  "registration_count": 1,
  "heartbeat_count": 1,
  "state_count": 1,
  "capabilities_count": 1,
  "metrics_count": 1,
  "logs_count": 1,
  "audit_count": 1,
  "local_metrics_count": 1,
  "local_logs_count": 1,
  "local_audit_count": 1
}
```

The test passes when all seven platform counters are >= 1 (initial assertions), and separately verifies that all three local endpoint counters are >= 1 (Phase 11):

| Counter | Meaning |
|---------|---------|
| `registration_count` | plexd called `POST /v1/register` |
| `heartbeat_count` | plexd called `POST /v1/nodes/{id}/heartbeat` |
| `state_count` | plexd called `GET /v1/nodes/{id}/state` |
| `capabilities_count` | plexd called `PUT /v1/nodes/{id}/capabilities` |
| `metrics_count` | plexd called `POST /v1/nodes/{id}/metrics` |
| `logs_count` | plexd called `POST /v1/nodes/{id}/logs` |
| `audit_count` | plexd called `POST /v1/nodes/{id}/audit` |
| `local_metrics_count` | plexd sent metrics to `POST /local/metrics` (TLS) |
| `local_logs_count` | plexd sent logs to `POST /local/logs` (TLS) |
| `local_audit_count` | plexd sent audit to `POST /local/audit` (TLS) |

## plexd Configuration

The config is written directly into the container (not via the installer script):

```yaml
api:
  base_url: http://plexd-e2e-mockapi:8080
registration:
  data_dir: /var/lib/plexd
node_api:
  data_dir: /var/lib/plexd
heartbeat:
  node_id: e2e-systemd-node
metrics:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  local_endpoint:
    url: https://plexd-e2e-mockapi:8443/local/metrics
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
log_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  file_patterns:
    - "/var/log/plexd/*.log"
  local_endpoint:
    url: https://plexd-e2e-mockapi:8443/local/logs
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  local_endpoint:
    url: https://plexd-e2e-mockapi:8443/local/audit
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
```

The bootstrap token is written to `/etc/plexd/bootstrap-token` (mode 0600) before the service starts; no environment file is written.

The config sets no `dns` key, so the mesh DNS resolver runs with its defaults, enabled on port 5354, until phase 15 appends:

```yaml
dns:
  enabled: false
```

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TIMEOUT` | `60` | Assertion polling timeout in seconds |

## Usage

```bash
make test-e2e-systemd
```

Or directly:

```bash
bash test/e2e/systemd/test.sh
```

Override configuration:

```bash
TIMEOUT=120 make test-e2e-systemd
```

### Prerequisites

- Docker
- `curl` and `jq` on the host
- Kernel WireGuard on the host: the mesh DNS phase needs `plexd0`, which plexd creates in the container's network namespace

## Debugging Failures

**systemd does not boot inside the container:**

The container requires `--privileged`, `--cgroupns=host`, and cgroup volume mounts. Verify the host supports cgroup v2:

```bash
mount | grep cgroup2
```

**plexd service fails to start:**

```bash
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager
docker exec plexd-e2e-systemd systemctl status plexd
```

Common causes:
- Binary not executable — check that `chmod +x` was applied to `/usr/local/bin/plexd`.
- Config YAML parse error — field names must use snake_case YAML tags (e.g. `base_url`, not `baseurl`).
- Missing bootstrap token — `/etc/plexd/bootstrap-token` must hold the token before the service starts.

**Assertions not met (counters stay at 0):**

```bash
docker logs plexd-e2e-mockapi
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager -n 100
```

Common causes:
- Network connectivity — both containers must be on the `plexd-systemd-e2e` bridge network.
- mock-api not ready — the script polls `/v1/health` for readiness but the health timeout may be too short.

**A mesh name does not resolve:**

```bash
docker exec plexd-e2e-systemd resolvectl status plexd0
docker exec plexd-e2e-systemd resolvectl query peer-1.app.e2e.internal
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager | grep -E 'mesh dns|component=meshdns|dns block|PLEXD_DNS_ENABLED'
```

Run these in the container only. On a host that is itself a Node, `resolvectl` without `docker exec` talks to the host's systemd-resolved.

Common causes:
- No `plexd0`: WireGuard did not come up, and plexd logs `wireguard unavailable, mesh dns not started`.
- No `DNS Servers:` line on `plexd0`: look for `mesh dns not registered, systemd-resolved is not usable` or `mesh dns registration failed` in the journal; `systemctl status systemd-resolved dbus` shows whether both run.

**Leftover containers from previous run:**

The script performs pre-cleanup, but if issues persist:

```bash
docker rm -f plexd-e2e-mockapi plexd-e2e-systemd
docker network rm plexd-systemd-e2e
```

## Diagnostics Output

On any failure, the `print_diagnostics` function outputs:

| Command | Purpose |
|---------|---------|
| `docker network inspect plexd-systemd-e2e` | Network state and connected containers |
| `docker logs plexd-e2e-mockapi` | Mock API server logs |
| `systemctl status plexd` | Service state and recent log lines |
| `journalctl -u plexd -n 100` | Recent plexd service logs |
| `journalctl -u 'plexd-session-helper@*' -n 100` | Recent session helper logs |
| `journalctl -n 50` | Recent system-wide journal entries |
| `ps aux` | Process list inside systemd container |
| `ls -la /etc/plexd/` | Configuration files |
| `ls -la /usr/local/bin/plexd` | Binary presence and permissions |
| `resolvectl status --no-pager` | The container's systemd-resolved: global and per-link DNS servers and domains |

## Key Files

| File | Purpose |
|------|---------|
| `test/e2e/systemd/Dockerfile` | Ubuntu 24.04 systemd container image, with `dbus` and `systemd-resolved` |
| `test/e2e/systemd/test.sh` | Orchestration script (build, install, assert, shutdown, cleanup) |
| `test/e2e/systemd/.dockerignore` | Prevents unnecessary files in Docker context |
| `test/e2e/mockapi/Dockerfile` | Mock API image |
| `test/e2e/mockapi/mockapi.go` | Mock API server with `/test/assertions` endpoint |
| `deploy/systemd/plexd.service` | Production unit file (copied verbatim into container) |
| `deploy/systemd/plexd-session-helper.socket`, `deploy/systemd/plexd-session-helper@.service` | Session helper units (copied verbatim into container) |
| `Makefile` | `test-e2e-systemd` target |

## See also

- [Docker E2E Test](docker-e2e-test.md) — Docker Compose-based E2E test
- [Kubernetes E2E Test](kubernetes-e2e-test.md) — kind-based Kubernetes E2E test
