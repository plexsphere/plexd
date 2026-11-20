---
title: Systemd E2E Test
package: test/e2e/systemd
feature: PXD-0040
---

# Systemd E2E Test

Validates that plexd runs correctly as a systemd service by deploying it inside a privileged Ubuntu container with systemd as PID 1. The test installs the plexd binary and the production `plexd.service` unit file, starts the service via `systemctl`, polls the mock-api assertion endpoint to verify registration, heartbeat, state retrieval, capabilities reporting, state convergence, and observability forwarding (metrics, logs, audit), checks that the mesh DNS resolver registers with the container's systemd-resolved, answers through it and forwards to the mock's DNS stub, turns the node into a bridge that serves public ingress rules under the unit's `CAP_NET_BIND_SERVICE`, ends TLS at the bridge with the certificate of a Secret and with one it obtains from Pebble, Let's Encrypt's test CA, routes the requests of `terminate` rules with request conditions that share a host by path prefix and header, spreads the connections and requests of a rule over its targets and moves a connection off a target that refuses it, checks the bridge's ingress status report, closes every public listener for a block that does not enable ingress and on a bridge that opts out with `bridge.ingress_enabled: false`, serves a `wireguard` user access provider through which a device reaches a mesh node with the bridge's mesh address, reports each provider's state, keeps the provider's key across a restart and a killed process, and opts out with `bridge.user_access_enabled: false`, serves a `wireguard` site-to-site tunnel through which a host of a remote site reaches a mesh node with the bridge's mesh address and a mesh node reaches the site under the bridge's policy, reports each tunnel's state, keeps the tunnel's key across a restart and a killed process, and opts out with `bridge.site_to_site_enabled: false`, registers with `plexd join` through `api.tls_ca_file` against the mock's TLS listener for the control plane, then verifies clean shutdown.

## Container Topology

![Seven containers share the Docker network plexd-systemd-e2e. In the systemd container, Ubuntu 24.04 with systemd as PID 1, systemd manages plexd.service. plexd calls mock-api, which listens on port 8080 for HTTP and on port 8443 for TLS and serves /v1/health. plexd connects to the rule targets on the ingress target, which serves TLS on ports 9441 to 9443 and a banner on port 9022 and carries openssl and nc, and the ingress target probes plexd. plexd talks ACME to pebble, Let's Encrypt's test CA, on port 14000 over HTTPS, and pebble validates plexd with TLS-ALPN-01 on port 443. The device, with wg0 at 10.77.0.2 and an nc probe, reaches plexd over WireGuard on port 51900, a wg-ua- interface of the bridge. The mesh node, with wg0 at 10.99.0.3 and nc listening on port 7101, peers with plexd over WireGuard on plexd0 port 51820. The site, with wg0 at 10.40.0.1/16 and nc listening on port 7201, is the remote end of a site-to-site tunnel of the bridge, a wg-s2s- interface on port 51930.](../../diagrams/development-systemd-topology.svg)

| Container | Image | Source | Purpose |
|-----------|-------|--------|---------|
| `plexd-e2e-mockapi` | `mockapi:e2e-systemd` | `test/e2e/mockapi/Dockerfile` | Fixture-based mock Central API, tracks call counters, answers DNS on port 53 |
| `plexd-e2e-systemd` | `plexd-systemd:e2e` | `test/e2e/systemd/Dockerfile` | Ubuntu 24.04 with systemd as PID 1, runs plexd as a real service |
| `plexd-e2e-ingress-target` | `plexd-ingress-target:e2e` | `test/e2e/meshpeer/Dockerfile` | Alpine with `openssl`, `netcat-openbsd`, `socat`, `curl` and `http-target.sh`; started by phase 16, serves the ingress rules' targets, a UDP echo server and two HTTP servers that write back the request head they read among them, and runs the probes |
| `plexd-e2e-pebble` | `ghcr.io/letsencrypt/pebble:2.10.3`, pinned by digest | Pebble's release image, with `test/e2e/systemd/pebble-config.json` mounted | Pebble, Let's Encrypt's test CA; started by phase 16 with the network alias `pebble`, issues the certificate of the `acme` rule after it validated the bridge over TLS-ALPN-01 on port 443 |
| `plexd-e2e-meshnode` | `plexd-ingress-target:e2e` | `test/e2e/meshpeer/Dockerfile` | Alpine with `wireguard-tools`, `iproute2` and `netcat-openbsd`; started by phase 17 with `NET_ADMIN`, the fixture's mesh peer `...a0b2` on a `wg0` of its own at `10.99.0.3`, and listens on port 7101 |
| `plexd-e2e-device` | `plexd-ingress-target:e2e` | `test/e2e/meshpeer/Dockerfile` | The same image; started by phase 17 with `NET_ADMIN`, a device of a `wireguard` user access provider on a `wg0` of its own at `10.77.0.2`, and runs the probe to the mesh node |
| `plexd-e2e-site` | `plexd-ingress-target:e2e` | `test/e2e/meshpeer/Dockerfile` | The same image; started by phase 18 with `NET_ADMIN`, the remote site of a `wireguard` site-to-site tunnel on a `wg0` of its own at `10.40.0.1/16`, listens on UDP 51940 and on TCP 7201, and runs the probe to the mesh node |

Phases 17 and 18 also run short-lived containers of the same image with `--network container:plexd-e2e-systemd` and `NET_ADMIN`, which share the systemd container's network namespace: the systemd image carries neither `ip` nor `wg`, so they read the kernel state of `plexd0`, of the provider's interface and of the tunnel's interface and its route. They are removed as they exit.

The systemd image installs `dbus` and `systemd-resolved` next to `systemd`, `systemd-sysv`, `curl`, `ca-certificates`, `jq`, `openssh-client`, and `sshpass`. Both install enabled, so the container boots with a system bus and its own systemd-resolved, which plexd registers its mesh DNS resolver with. Docker mounts its own `/etc/resolv.conf` (`nameserver 127.0.0.11`) over the one the package would link, so systemd-resolved runs in foreign mode with Docker's DNS as its global server, `nsswitch.conf` keeps `hosts: files dns`, and the mesh DNS phases ask systemd-resolved directly with `resolvectl`. Every `resolvectl` call runs inside the container through `docker exec` and reaches the container's systemd-resolved, never the host's.

## Test Phases

### 1. Pre-flight checks

Verifies that `docker`, `curl`, and `jq` are available on `$PATH`. Exits immediately if any tool is missing.

### 2. Pre-cleanup

Removes any leftover containers and network from a previous run (handles the case where a prior run was killed with SIGKILL and the trap did not fire).

### 3. Image build

Builds the mock-api image, the systemd container image, and cross-compiles the plexd binary using a Go Alpine container. The Go version is extracted from `go.mod`.

### 4. Network and container startup

Creates a Docker bridge network and starts the mock API and the systemd container on it; phase 16 starts the ingress target and Pebble on the same network, phase 17 the mesh node and the device, and phase 18 the site. The mock API runs with `-addr :8080 -dns-addr :53 -api-tls-addr :8444`, so it also serves its DNS stub (see [the mock API server](mock-api-server.md)) on UDP and TCP port 53, which step 5b of the mesh DNS phase forwards to, and the control plane API over TLS on port 8444, which only phase 19 joins through. The image runs as uid 65534, and Docker sets `net.ipv4.ip_unprivileged_port_start` to `0` in the container, so the port binds. The systemd container runs with `--privileged`, `--cgroupns=host`, and cgroup volume mounts for full systemd functionality.

### 5. Service installation

Copies the plexd binary, the production `deploy/systemd/plexd.service` unit file and the two session helper units (`plexd-session-helper.socket`, `plexd-session-helper@.service`) into the systemd container. Fetches the mock's CA from `GET http://localhost:18080/test/tls-ca` on the host, fails when the fetch fails or the body is empty, and writes it to `/etc/plexd/mock-ca.pem` (mode 0644) in the container, which the three local endpoints of `config.yaml` name in `tls_ca_file`. Writes `config.yaml` pointing at the mock-api container and the bootstrap token to `/etc/plexd/bootstrap-token` (mode 0600), before the service starts so the unit can grant write access to it, and creates `/etc/plexd/hooks` as `plexd install` would. Runs `systemctl daemon-reload` and `systemctl enable --now plexd`, then checks that `systemctl is-active plexd-session-helper.socket` prints `active`: `plexd.service` wants the socket and names it in `Also=`.

### 6. Assertion polling

Polls `GET http://localhost:18080/test/assertions` every 3 seconds for up to 60 seconds (configurable via `TIMEOUT`).

### 7. Request body validation

Uses `GET /test/last-request/{endpoint}` to verify the content of request payloads:

| Endpoint | Validated Fields |
|----------|-----------------|
| `register` | `bootstrap_token`, `project_id`, `resource_handle`, `nonce` (each non-empty) |
| `heartbeat` | Valid JSON with `client_now` (RFC 3339), `binary_checksum` (32-byte base64 digest), `binary_version` (non-empty) and `nat_summary` (a JSON object) |
| `capabilities` | `binary_version` (non-empty), `binary_checksum` (32-byte base64 digest), eleven `builtin_actions`; `binary` and `plexd_hooks` absent |

### 8. Spent token cleanup

The unit keeps `/etc` read-only and grants write access to `/etc/plexd/bootstrap-token` alone, so plexd cannot unlink the token it spent and empties the file instead. The phase fails unless `stat -c %s /etc/plexd/bootstrap-token` prints `0`, `journalctl -u plexd` contains `token file emptied, it could not be removed`, and the journal contains neither `failed to delete token file` nor `hook watcher stopped`.

### 9. Periodic loop verification

Waits up to 60 seconds for `heartbeat_count`, `metrics_count`, and `logs_count` to reach >= 2, proving that periodic loops run continuously. Logs work via journald in the systemd container. Audit is tested separately via restart.

### 10. Audit forwarding via service restart

The `ProcessSource` uses `sync.Once` to emit a single `process_start` audit entry per process lifetime. The test restarts the plexd service via `systemctl restart plexd`, creating a new process with a fresh `ProcessSource`, and verifies `audit_count` increases.

### 11. Local endpoint delivery

Polls `GET /test/assertions` until `local_metrics_count`, `local_logs_count`, and `local_audit_count` are all >= 1 (timeout: 60s). Validates that the local endpoint credential chain works with systemd: NSK from registration → secret fetch → AES-256-GCM decryption → Bearer token → HTTPS POST to `plexd-e2e-mockapi:8443`. plexd verifies the mock's leaf there against `/etc/plexd/mock-ca.pem`, which each `local_endpoint.tls_ca_file` names, so the phase also proves that key.

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

   5b. **Forwarding.** The mock's DNS stub on port 53 answers every `A` query with `198.51.100.53` and a name whose first label is `nx` with `NXDOMAIN`. Each change splices `.dns.forwarding` into the live snapshot the way step 5 splices its block, posts it to `POST /test/configure-state`, and lands with a pull the heartbeat asks for, so each wait for the link's domains polls every 3 seconds for up to 90 seconds. The journal lines the step checks are those of the running process (`plexd[<MainPID>]:`).

   1. **Forward zones.** It sets the forward zones `dead.e2e.test` with the resolver `192.0.2.1`, a TEST-NET-1 address that never answers, and `fwd.e2e.test` with the mock's address, and no catch-all. `resolvectl domain plexd0` must list exactly step 5's domains plus `~dead.e2e.test` and `~fwd.e2e.test`, and `resolvectl status plexd0` must still show `-DefaultRoute`. `host.fwd.e2e.test` must then answer `198.51.100.53` on `plexd0`, and `nx.fwd.e2e.test` must fail with `not found`.
   2. **A dead resolver.** `resolvectl query host.dead.e2e.test` runs in the background. A second later the step runs `resolvectl flush-caches`, and `db-1.app.e2e.internal` must answer `10.99.0.2` on `plexd0` within 2 seconds, measured around the `docker exec`, while the background query still runs. The background query must then fail with `server or network returned error SERVFAIL`. plexd gives the resolvers of a forwarded query 4 seconds in total, below the 5 seconds systemd-resolved waits for a server, and answers `SERVFAIL` after them. systemd-resolved asks again after a `SERVFAIL`, first with the same EDNS features and after a second `SERVFAIL` with fewer, so the background query takes three such rounds. The journal must hold `mesh dns resolver does not answer` with `resolver=192.0.2.1` and `zone=dead.e2e.test`.
   3. **Catch-all.** It adds the catch-all with the mock's address. `resolvectl domain plexd0` must list `~.` next to the domains of check 1, and `resolvectl status plexd0` must show `+DefaultRoute`. After `resolvectl flush-caches`, `plexd-e2e-mockapi.plexd-systemd-e2e` must answer the stub's `198.51.100.53` on `plexd0`, not the address step 4 checks, and `db-1.app.e2e.internal` must still answer `10.99.0.2` on `plexd0`. The journal must hold `mesh dns registered with systemd-resolved` with `interface=plexd0` and `default_route=true`.
   4. **No member.** It counts the `dns block carries no forwarding member, keeping the forwarding held` lines, removes the `forwarding` member from the block, and requires the served block to lack it. It reads a `state_count` baseline after the splice, whose own `GET` the count includes, so every pull past the baseline serves the block without the member. It polls `state_count` every 2 seconds for up to 90 seconds until two such pulls have come, and waits 2 more seconds for plexd to handle the second. `resolvectl domain plexd0` must be unchanged, `~.` included, and the journal must hold exactly one more `keeping the forwarding held` line.
   5. **Two empty lists.** It sets both lists empty. `resolvectl domain plexd0` must list exactly step 5's domains, and `resolvectl status plexd0` must show `-DefaultRoute`. After `resolvectl flush-caches`, `plexd-e2e-mockapi.plexd-systemd-e2e` must answer the address step 4 checks without naming `plexd0`, and `host.fwd.e2e.test` must fail. The step leaves the block this way, so step 6 and the phases after it find step 5's registration.
6. **A paused control plane.** It runs `docker pause plexd-e2e-mockapi` for 20 seconds. After 10 seconds it runs `resolvectl flush-caches` in the container. `db-1.app.e2e.internal` must then answer `10.99.0.2` and `db.e2e.internal` must answer `192.0.2.20`, each on `plexd0` with the line `-- Data from: network`, so the answers came from plexd and not from systemd-resolved's cache. After `docker unpause` it waits 2 seconds, so a request plexd sent into the paused mock and that completes once it runs again is not counted, reads `heartbeat_count` and `state_count`, and polls for up to 60 seconds until both have grown: plexd sent a heartbeat and the pull its `reconcile: true` answer asks for. While the mock is paused, `MOCK_PAUSED` is set, and `fail` and the `EXIT` trap both run `docker unpause` first.

### 14. Start after a reboot

A reboot empties `/run`, which takes `/run/plexd` with it. The phase stops plexd, removes `/run/plexd` and starts plexd again, then waits up to 30 s for `/var/run/plexd/api.sock` and expects `systemctl is-active plexd` to print `active`. Every `ReadWritePaths` entry of the unit is optional, so systemd skips the missing directory instead of failing with `226/NAMESPACE`, and plexd recreates it for the node API socket.

The stop also takes the mesh DNS registration with it. Right after `systemctl stop plexd`, `resolvectl query db-1.app.e2e.internal` must fail without naming `10.99.0.2` or `plexd0`, `resolvectl domain` must list no domain that contains `e2e.internal`, and the journal of the stopped process must hold `mesh dns registration reverted` with `interface=plexd0`. These checks sit here and not in the shutdown phase because the opt-out phase leaves nothing registered for the final stop to remove. After the start, the phase polls `db-1.app.e2e.internal` every second until it answers `10.99.0.2` on `plexd0` again, and fails if that takes more than 30 seconds from the phase's start, the stop included. The first pull of the new process serves the block step 5 of the mesh DNS phase configured.

### 15. Mesh DNS opt-out

The phase reads `/etc/plexd/config.yaml`, fails if a line already starts with `dns:`, appends `dns: {enabled: false}` as a block, and runs `systemctl restart plexd`. The journal of the new process must hold `mesh dns disabled by dns.enabled` within 30 seconds, and must not hold `mesh dns listening`. The phase then waits for `state_count` to grow past its value after the restart, for up to 60 seconds from the restart, so a pull carrying the `dns` block reached the new process. `resolvectl status plexd0` must then exit 0 and show no DNS server, and `resolvectl domain plexd0` must list no domain. The restart's stop reverted the registration of the run before, and a disabled resolver registers nothing.

### 16. Public ingress on a bridge

The phase turns the node into a bridge that serves the `bridge.ingress` block of its state pull (see [Public Ingress](../bridge/public-ingress.md) and [ACME & SNI Routing](../bridge/acme-sni.md)). No other e2e suite runs bridge mode: the Docker suite's plexd container cannot write the forwarding sysctl without `--privileged`.

1. **Target.** It builds `test/e2e/meshpeer/Dockerfile` as `plexd-ingress-target:e2e` and starts it as `plexd-e2e-ingress-target` on `plexd-systemd-e2e`. Inside it, `openssl req` creates self-signed certificates for `a.ingress.e2e.test`, `b.ingress.e2e.test` and `wild.ingress.e2e.test`, three `openssl s_server -4 -www` instances serve them on 9441, 9442 and 9443, and a loop of `printf 'plexd-e2e-banner\n' | nc -N -l 9022` writes the banner to each client first. Nothing listens on 9023 until step 20 starts a second banner server there. `socat -T 5 UDP4-RECVFROM:9053,fork,reuseaddr EXEC:/bin/cat` echoes UDP datagrams on 9053: it hands each datagram to a child of its own, whose `cat` writes it back to the sender, so every datagram of every sender is answered, where `busybox nc -lk -u -e` answers only the first. `-T 5` ends a child after 5 seconds without a datagram. `socat TCP4-LISTEN:<port>,fork,reuseaddr EXEC:"/usr/local/bin/http-target.sh <name>"` runs `http-target.sh`, which the image copies from `test/e2e/meshpeer/` to `/usr/local/bin/`, for each connection, on 9081 with the name `api` and on 9082 with `web`: the script reads one request head up to the empty line and answers `200` with `Content-Type: text/plain` and `Connection: close`, and a body whose first line is `target=<name>`, followed by the request line and every header line it read. `openssl req` also creates the two versions of the terminate rule's certificate: self-signed EC P-256 certificates for one day with the subjects `/O=v1/CN=t.ingress.e2e.test` and `/O=v2/CN=t.ingress.e2e.test` and the subject alternative name `DNS:t.ingress.e2e.test`, and the certificate of step 19, one like them with the subject `/CN=h.ingress.e2e.test` and the subject alternative names `DNS:h.ingress.e2e.test` and `DNS:o.ingress.e2e.test`. A second `docker exec` creates the CAs and client certificates of step 21. The phase waits up to 10 seconds until `ss -ltn` shows all six TCP ports, and up to 10 seconds more until `ss -lun` shows `0.0.0.0:9053`.
2. **Pebble.** It starts `ghcr.io/letsencrypt/pebble:2.10.3`, pinned by digest, as `plexd-e2e-pebble` on `plexd-systemd-e2e` with the network alias `pebble`, `--add-host acme.ingress.e2e.test:<bridge>`, `PEBBLE_VA_NOSLEEP=1` and `PEBBLE_WFE_NONCEREJECT=0`, and passes `-config /test/config/plexd-e2e.json`, where `test/e2e/systemd/pebble-config.json` is mounted read-only. That file is Pebble's default `test/config/pebble-config.json` with `"tlsPort": 443`, the port its validator dials for TLS-ALPN-01. The validator resolves `acme.ingress.e2e.test` through the `/etc/hosts` of its container, which `--add-host` points at the bridge. Pebble's listener certificate names `localhost` and `pebble`, so plexd reaches the directory as `https://pebble:14000/dir`. `PEBBLE_VA_NOSLEEP=1` drops the random wait before each validation, and `PEBBLE_WFE_NONCEREJECT=0` stops Pebble from rejecting valid nonces.
3. **Test CA.** It streams `/test/certs/pebble.minica.pem` from the Pebble container into `/etc/plexd/` of the systemd container (`docker cp <pebble>:<file> - | docker cp - <systemd>:/etc/plexd/`, with no file on the host), fails if `/etc/plexd/environment` already exists, and writes `SSL_CERT_FILE=/etc/plexd/pebble.minica.pem` into it. The shipped unit reads that file through `EnvironmentFile=-/etc/plexd/environment` at each start, so the phase writes no drop-in and runs no `systemctl daemon-reload`. The CA stays out of the system trust store, as Pebble's README asks. `curl -sSf --cacert /etc/plexd/pebble.minica.pem https://pebble:14000/dir` in the systemd container must then print the directory within 30 seconds, which proves the name and the trust.
4. **Secret.** It reads each version's certificate and key with `docker exec … cat` into one PEM document, the certificate first, and posts version 1 as the named Secret `tls-term` to `POST /test/configure-secrets` (`{"secrets": [{"name": "tls-term", "version": 1, "value": <pem>}]}`, see [the mock API server](mock-api-server.md)), which must answer `204`. Each later post replaces that set, so the mock serves one version of `tls-term` at a time.
5. **Rules.** `configure_ingress <tag> <rules-json> [acme-json] [secrets-json]` reads the live snapshot, sets `.bridge` to `{relay: null, user_access: null, ingress: {enabled: <enabled>, rules: <rules>}, site_to_site: null}`, or `ingress: null` for the rules `null`, writes into every other block the `enabled` of the shell variable `INGRESS_BLOCK_ENABLED`, which defaults to `true`, adds `acme-json` as `ingress.acme` when it is given and not empty, and replaces the snapshot's `.secrets` with `secrets-json` when it is given; without it the live inventory is kept. It posts the result to `POST /test/configure-state` and injects a `node_state_updated` event, the way `configure_sessions` configures its block. `ingress_rule` renders one rule and takes a Secret name as an optional seventh argument, which becomes `certificate_secret_name`, a target address as an optional eighth, in place of the target container's, and a protocol as an optional ninth, `tcp` unless given. It renders `protocol` on every rule, as the control plane sends it, and names the rule's one target twice, as the control plane sends a rule: as the one entry of `targets`, with the node `...a0b2`, the target's address and the target port, and in `target_node_id`, `target_address` and `target_port`. With `INGRESS_RULE_LEGACY=1` it renders the three members alone, as a control plane that predates `targets` sends a rule. `ingress_rules` sets it for `plain` alone, so the phase serves a rule of either shape. Every rule targets the target container's address, carries `protocol` `tcp`, and the rules are listed in slug order, as the control plane lists them:

   | Slug | Listen port | Mode | SNI host | Target port | Secret |
   | --- | --- | --- | --- | --- | --- |
   | `plain` | 7022 | `passthrough` | none | 9022 | none |
   | `tls-a` | 443 | `passthrough` | `a.ingress.e2e.test` | 9441 | none |
   | `tls-acme` | 443 | `acme` | `acme.ingress.e2e.test` | 9022 | none |
   | `tls-b` | 443 | `passthrough` | `b.ingress.e2e.test` | 9442 | none |
   | `tls-term` | 443 | `terminate` | `t.ingress.e2e.test` | 9022 | `tls-term` |
   | `tls-wild` | 443 | `passthrough` | `*.apps.ingress.e2e.test` | 9443 | none |

   The first block carries `"acme": {"directory_url": "https://pebble:14000/dir"}` and the inventory `[{"name": "tls-term", "version": 1}]`. `tls-term` and `tls-acme` end TLS at the bridge and forward the plaintext to the banner server on 9022.
6. **Port floor.** It writes `1024` to `/proc/sys/net/ipv4/ip_unprivileged_port_start` in the systemd container and reads it back. Docker sets that floor to `0` in a container, which would hide a unit without `CAP_NET_BIND_SERVICE`.
7. **Bridge mode.** Before it appends the bridge block, it reads `ingress_status_count` from `GET /test/assertions` and requires 0: until then the node ran outside bridge mode and sent no ingress status report. It fails if `/etc/plexd/config.yaml` already has a line that starts with `mode:` or `bridge:`, appends the block below, which carries no `ingress_enabled` line, so public ingress runs on its default, and accepts Pebble's directory alone, and runs `systemctl restart plexd`. That is the phase's only restart before its last step: Pebble, the test CA and the environment file are in place before it.
8. **Listeners.** Within 60 seconds the journal of the new process (`plexd[<MainPID>]:`) must hold `ingress listener opened` for `listen_port=443` and for `listen_port=7022`, exactly once each, `ingress manager started`, and `ingress certificate loaded` with `secret=tls-term` and `version=1`. The new process must log no `ingress rule not served` line: every rule of the block, the terminate and the acme rule included, is served. The port floor must still read `1024`. After the listeners are up, within 60 seconds the last report that `GET /test/last-request/ingress-status` returns must read `state` `enabled` with an entry of `listener` `listening` for each of the six ids `...a1f1` to `...a1f6`; `plain` (`...a1f1`) must read `certificate` `not_required` and `dial` `none` without a `dial_age_seconds` or a `targets` key, each of the five other rules must carry `targets` with one entry that names the node `...a0b2` and reads `dial` `none`, and `tls-term` (`...a1f4`) must read `certificate` `ready`. The journal of the process must hold `ingress status: reported` with `state=enabled`, and `ingress_status_count` from `GET /test/assertions` must be at least 1. This check and every later check of a report poll `GET /test/last-request/ingress-status` with `jq -e` every 2 seconds for up to 60 seconds (`wait_ingress_report`).
9. **Termination.** From the target container, `timeout 10 openssl s_client -connect <bridge>:443 -servername t.ingress.e2e.test -ign_eof </dev/null` prints the handshake and then the plaintext the target wrote through the session; the banner server closes after writing, which ends the session. The certificate in that output, read with `openssl x509 -noout -subject`, must have the subject `O=v1, CN=t.ingress.e2e.test`, and the output must hold `plexd-e2e-banner`. The session caused the bridge's first dial for `tls-term`, so its entry must then read `dial` `succeeded` with a numeric `dial_age_seconds`.
10. **Rotation.** It posts version 2 and serves the same block with the inventory `[{"name": "tls-term", "version": 2}]`, so only the inventory of the pull changes, and polls for up to 60 seconds until a handshake with `t.ingress.e2e.test` shows the subject with `O=v2`.
11. **A version that does not load.** It posts version 3 with the value `not a certificate` and lists it. Within 60 seconds the journal must hold `ingress certificate not loaded` with `secret=tls-term`, `version=3`, `reason=certificate_invalid` and `serving_version=2`, and a handshake must then still show `O=v2`.
12. **An unlisted Secret.** It serves the inventory `[]` and polls for up to 60 seconds until the journal holds `ingress certificate dropped` with `secret=tls-term` and `reason=certificate_secret_not_listed` and a handshake with `t.ingress.e2e.test` yields no certificate. The entry of `tls-term` must then read `certificate` `not_ready` with `certificate_reason` `certificate_secret_not_listed`.
13. **ACME.** Within 120 seconds of the restart the journal must hold `ingress certificate obtained` with `sni_host=acme.ingress.e2e.test`: plexd obtained the certificate ahead of the first client, and Pebble validated the name over TLS-ALPN-01 on port 443 of the bridge. A session with `-servername acme.ingress.e2e.test`, run as in step 9, must show an issuer that contains `Pebble Intermediate CA` (`openssl x509 -noout -issuer`; Pebble's leaf certificates carry no subject CN), and its output must hold `plexd-e2e-banner`. `/var/lib/plexd/acme` in the systemd container, `<data_dir>/acme`, where `bridge.acme_cache_dir` points when it is not set, must hold the files `acme_account+key` and `acme.ingress.e2e.test`. The entry of `tls-acme` (`...a1f6`) must read `certificate` `ready`.
14. **A directory outside the bound.** It serves the block with `"acme": {"directory_url": "https://other.invalid/dir"}`. Within 60 seconds the journal must hold `ingress rule not served` with `slug=tls-acme` and `reason=acme_directory_not_allowed`, and the entry of `tls-acme` must read `certificate` `not_ready` with `certificate_reason` `acme_directory_not_allowed`.
15. **Routing.** `openssl s_client -connect <bridge>:443 -servername <name>` piped into `openssl x509 -noout -subject` must print the certificate of `a.ingress.e2e.test` for `a.ingress.e2e.test`, of `b.ingress.e2e.test` for `b.ingress.e2e.test`, and of `wild.ingress.e2e.test` for `x.apps.ingress.e2e.test`. The names `none.ingress.e2e.test` and `x.y.apps.ingress.e2e.test`, and a handshake with `-noservername`, must print no certificate. `nc -w 5 <bridge> 7022 </dev/null` must print `plexd-e2e-banner`: the bridge forwards the plain port without reading.
16. **A changed rule.** It serves `tls-b` with target port 9441, names Pebble's directory again and keeps the inventory `[]`, and polls for up to 60 seconds until `b.ingress.e2e.test` receives the certificate of `a.ingress.e2e.test`. The journal must still hold one `ingress listener opened` line for 443: the table of the port changes without a second bind.
17. **A dial that the policy blocks.** It serves the rules of step 16 and the rule `mesh` (`...a1f7`, port 7023, `passthrough`, no host), whose target is `10.99.0.2:9022`, the mesh address of the fixture's first peer, which no node answers for. The mock registers the node as `10.99.0.1` with `domain_mesh_cidr` `10.99.0.0/24`, so the kernel sends the dial through `plexd0` from the mesh address, where the policy applies. It waits for `ingress listener opened` with `listen_port=7023`, then runs `timeout 30 nc -w 15 <bridge> 7023 </dev/null` in the target container, which returns when the bridge closes the connection, at the latest after `bridge.ingress_dial_timeout` (10 s). The fixture's policy allows `10.99.0.0/24` to itself, so the entry of `mesh` must read `dial` `failed` with a `dial_reason` other than `policy_denied`; the step prints the reason. It then reads the live policy block, and serves one of a new revision whose only rule is the fixture's TCP 443 rule, with a fingerprint computed in the target container as the Docker suite's `serve_policy` computes one (`configure_policy` splices `.policy` and nudges plexd into a pull). Within 60 seconds the journal must hold `policy ruleset applied` with that `revision_id`. A second connection must then make the entry read `dial_reason` `policy_denied`, and the journal must hold `bridge: ingress: dial target failed` with `rule_id` of `mesh` and `reason=policy_denied`. The step serves the fixture's policy again and waits for another `policy ruleset applied` with its `revision_id`.
18. **A udp rule.** It serves the rules of step 16 and two `udp` rules, `passthrough` without a host: `udp-echo` (`...a1f8`, port 7022, the port number of the `tcp` rule `plain`, target port 9053 of the target container) and `udp-mesh` (`...a1f9`, port 7023, target `10.99.0.2:9053`). The block leaves `mesh` out. Within 60 seconds the journal must hold `ingress listener opened` with `protocol=udp` for `listen_port=7022` and for `listen_port=7023`. `printf plexd-e2e-udp | nc -u -w 2 <bridge> 7022` in the target container must then print `plexd-e2e-udp`. Each probe sends from a new source port and so opens a flow of its own, and UDP promises no delivery, so the step repeats the probe, 2 seconds apart, for up to 60 seconds and prints how many probes it took. `nc -w 5 <bridge> 7022 </dev/null` must still print `plexd-e2e-banner`: the `tcp` rule on the same port number keeps its listener. The entry of `udp-echo` must read `listener` `listening`, `certificate` `not_required` and `dial` `succeeded`. After one datagram to 7023 under the fixture's policy, the entry of `udp-mesh` must read a recorded `dial` that is not `failed` with `policy_denied`; the step prints it. The step then serves the policy of step 17 again, whose only rule allows TCP 443, and waits for a second `policy ruleset applied` with its `revision_id`. After three datagrams to 7023 the entry of `udp-mesh` must read `dial` `failed` with `dial_reason` `policy_denied`, and the journal must hold exactly one `bridge: ingress: dial target failed` with `rule_id` of `udp-mesh`, `protocol=udp` and `reason=policy_denied`: the kernel refuses each send, and the bridge logs the failure once per change of the rule's dial, not once per datagram. The step serves the fixture's policy again and waits for another `policy ruleset applied` with its `revision_id`.
19. **Request routing.** It reads the certificate of `h.ingress.e2e.test` and its key with `docker exec … cat` into one PEM document and serves it as version 1 of the Secret `tls-http` with `configure_named_secret <tag> <name> <version> <value>`, which posts to `POST /test/configure-secrets` and which `configure_term_secret` calls with `tls-term`. The post replaces the mock's whole set of named Secrets, and the step lists `tls-http` alone (`[{"name": "tls-http", "version": 1}]`), so `tls-term` stays `not_ready`. The block carries Pebble's directory and the rules of step 18 with five `terminate` rules on port 443 that name `tls-http` and carry `conditions`, all in slug order:

   | Slug | Id | SNI host | Target port | Conditions | `strip_path_prefix` |
   | --- | --- | --- | --- | --- | --- |
   | `http-api` | `...a1fa` | `h.ingress.e2e.test` | 9081 | `path_prefix` `/api` | `true` |
   | `http-beta` | `...a1fb` | `h.ingress.e2e.test` | 9082 | `path_prefix` `/api`, header `x-beta` with the value `1` | absent |
   | `http-down` | `...a1fc` | `h.ingress.e2e.test` | 9099, where nothing listens | `path_prefix` `/down` | absent |
   | `http-only` | `...a1fd` | `o.ingress.e2e.test` | 9081 | `path_prefix` `/only` | absent |
   | `http-web` | `...a1fe` | `h.ingress.e2e.test` | 9082 | `path_prefix` `/` | absent |

   Every probe runs `timeout 10 curl -sS -k --resolve <host>:443:<bridge> https://<host><path>` in the target container (`ingress_curl`), and `target_reply` splits a body into its first line, `target=<name>`, and its second, the request line the server read. The step polls `https://h.ingress.e2e.test/api/users?x=1` every 2 seconds for up to 60 seconds until the body reads `target=api`, which shows that plexd pulled the block, loaded the certificate of `tls-http` and routes the host's requests. The server must have read the request line `GET /users?x=1 HTTP/1.1` and the header lines `X-Forwarded-Prefix: /api`, `X-Forwarded-Proto: https`, `X-Forwarded-For: <target container's address>`, `X-Forwarded-Host: h.ingress.e2e.test` and `Host: h.ingress.e2e.test`: `http-api` strips its prefix and keeps the query, the client is the target container itself, and Go's HTTP/1.1 client writes each header name in canonical case. `/apix` must read `target=web` with a request line that starts `GET /apix `, since `/apix` does not match `/api`, and `/api/users` with `-H 'x-beta: 1'` must read `target=web` with one that starts `GET /api/users `, since `http-beta` has more headers than `http-api`; neither strips. `/` with `--http2` and `-w '\n%{http_version}'` must report version `2` while the request line the server read ends in `HTTP/1.1`, and `/` with `--http1.1` must report `1.1`. `expect_ingress_status` reads `%{http_code}`, and the bridge must answer by itself `404` for `https://o.ingress.e2e.test/other`, `502` for `/down`, `400` for `/api/../x` with `--path-as-is`, and `421` for `/api/users` with `-H 'Host: other.ingress.e2e.test'`. The last report must then read `listener` `listening` and `certificate` `ready` for the five rules, `dial` `succeeded` for `http-api` and `http-web`, `dial` `none` for `http-only`, whose `404` dialled nothing, and `dial` `failed` with `dial_reason` `refused` for `http-down`. The journal holds `ingress rule not served` lines of other rules from the steps before, so the step counts the lines per `rule_id`, over every process, and requires none for any of the five.
20. **Several targets.** It serves the rules of step 19 with two rules of two targets each, with Pebble's directory and the inventory `[{"name": "tls-http", "version": 1}]`: `pool` (`...a1ff`, port 7024, `passthrough`, no host) with the targets 9023 and then 9022 of the target container, and `http-pool` (`...a1d1`, port 443, `terminate`, `h.ingress.e2e.test`, the Secret `tls-http`, `conditions` with `path_prefix` `/pool`) with 9081 and then 9082. `ingress_targets <port>...` renders a `targets` list with one entry per port, in the order given, each with the node `...a0b2` and the target container's address, and `jq` puts it into a rule that `ingress_rule` rendered with the first port, so the three deprecated members name the first target. Nothing listens on 9023 yet. The step waits up to 60 seconds for `ingress listener opened` with `listen_port=7024`, and then for a report in which both rules read `listener` `listening` and `dial` `none`, `http-pool` `certificate` `ready`, and each its two targets in list order with the node `...a0b2` and `dial` `none`. No client has reached either rule then, so the round robin of each starts at its first target. Three runs of `timeout 10 nc -w 5 <bridge> 7024 </dev/null` in the target container must each print `plexd-e2e-banner`: the first connection's dial to 9023 is refused and the bridge dials 9022 for the same connection, and the next two pass 9023 over, which is out for 30 seconds from its failed dial. The entry of `pool` must then read `dial` `succeeded`, its target on 9023 `dial` `failed` with `dial_reason` `refused`, and its target on 9022 `dial` `succeeded`. The step waits up to 60 seconds for a `bridge: ingress: dial target failed` line with `slug=pool` and then requires exactly one, which names `target=<target container's address>:9023` and `reason=refused`. It then starts `while true; do printf 'plexd-e2e-banner-b\n' | nc -N -l 9023; done` in the target container, waits up to 10 seconds until `ss -ltn` shows `0.0.0.0:9023`, and opens a connection to 7024 every 2 seconds, for up to 60 seconds, until one prints `plexd-e2e-banner-b`; it prints how many connections that took. Until the hold-out ends a connection goes to 9022, and the first connection after it dials 9023 again. The entry of `pool` must then read `dial` `succeeded` with both targets `succeeded`. Four requests for `https://h.ingress.e2e.test/pool/x` (`ingress_curl`) must then read `target=api`, `target=web`, `target=api` and `target=web`: `http-pool` wins over `http-web` by its longer prefix, received no request before the four, and gives each request the target after the one the request before went to. The entry of `http-pool` must then read `dial` `succeeded` with both targets `succeeded`.
21. **Client certificates.** The certificates come from a second `docker exec` of step 1, each made by `openssl req -x509` with an EC P-256 key and valid for one day: the CA `CN=plexd-e2e-client-ca` (`/srv/ingress/client-ca.pem`) with `basicConstraints` `critical,CA:TRUE` and `keyUsage` `critical,keyCertSign`, the leaf `CN=plexd-e2e-client` (`/srv/ingress/client.pem`, `/srv/ingress/client.key`) that the CA signs through `-CA` and `-CAkey`, with `basicConstraints` `critical,CA:FALSE`, `keyUsage` `critical,digitalSignature` and `extendedKeyUsage` `clientAuth`, and a second CA `CN=plexd-e2e-stranger-ca` with the leaf `CN=plexd-e2e-stranger` (`/srv/ingress/stranger.pem`, `/srv/ingress/stranger.key`), made alike. The step reads the SHA-256 of the client leaf's DER in the target container with `openssl x509 -outform DER | openssl dgst -sha256 -r` and keeps the 64 hex digits. It serves the rules of step 20, with Pebble's directory and the inventory `[{"name": "tls-http", "version": 1}]`, with `client_auth` on `tls-acme` and on `http-only`, whose `ca_bundle` is the text of `/srv/ingress/client-ca.pem`: `client_auth_rules <bundles-json>` gives each rule whose slug is a key of that object the `client_auth` `{"ca_bundle": <value>}`. The block adds no rule. The last report must then read `listener` `listening`, `certificate` `ready` and `client_auth_enforced` `true` without `client_refusals` for both rules, and no other entry may carry `client_auth_enforced`. `ingress_session <server name> [<s_client option>...]` passes its options to `openssl s_client` after the others: the session with `acme.ingress.e2e.test` and `-cert /srv/ingress/client.pem -key /srv/ingress/client.key` must read `plexd-e2e-banner`, and a session without a certificate and one with the stranger's must read no banner, since the bridge asks for a certificate in the handshake and refuses either client before it dials. `ingress_curl o.ingress.e2e.test /only --cert /srv/ingress/client.pem --key /srv/ingress/client.key` must read `target=api` and, as its only line that starts with `X-Forwarded-Client-Cert:`, the line `X-Forwarded-Client-Cert: Hash=<the 64 hex digits>;Subject="CN=plexd-e2e-client"`, also with `-H 'X-Forwarded-Client-Cert: forged'`, since the bridge drops every `X-Forwarded-*` field the client sent. The request without a certificate must read no line that starts with `target=`. A refusal sends no report by itself and rides the next repeat, so within 60 seconds the last report must read under `client_refusals` the reasons `no_certificate` and `unknown_authority` for `tls-acme` and `no_certificate` alone for `http-only`, each with an `age_seconds` from 0 to 120, and the journal must still hold one `ingress listener opened` line for 443. The step then serves `http-only` with the `ca_bundle` `not a certificate`, which holds no PEM block. Its entry must read `listener` `listening`, `certificate` `not_ready` with `certificate_reason` `client_ca_invalid` and `client_auth_enforced` `true`, and no `client_refusals`, which the changed bundle cleared. The request with the client's certificate must read no `target=` line, since the bridge closes the connection before the handshake, and within 60 seconds the journal must hold `ingress rule not served` with `slug=http-only` and `reason=client_ca_invalid`. Last it serves the rules of step 20 as that step served them, so the later steps start from the rules they expect: both rules must read `listening` and `ready`, no entry may carry `client_auth_enforced` or `client_refusals`, a session with `acme.ingress.e2e.test` without a certificate must read `plexd-e2e-banner` again, `https://o.ingress.e2e.test/only` without a certificate must read `target=api` and no `X-Forwarded-Client-Cert` line, and the journal must still hold one `ingress listener opened` line for 443. The journal runs at Info, so the step reads no `ingress client refused` line, which plexd logs at Debug.
22. **A removed block.** It serves `"ingress": null` and polls for up to 60 seconds until `nc -z` to 443 and to 7022 of the bridge are refused. The journal must hold `ingress listener closed` with `protocol=tcp` for both ports, and within 60 seconds `ingress listener closed` with `protocol=udp` for `listen_port=7022` and for `listen_port=7023`. A datagram `plexd-e2e-udp` to UDP port 7022 must then read nothing back. The last report must then read exactly `{"state":"enabled"}`. The step records `ingress_status_count` once that report arrived, and within 60 seconds the count must exceed it: no rule changes after it, and the suite sets no heartbeat interval, so the rise shows the reporter's repeat on the default of 30 seconds.
23. **A block that does not enable ingress.** It serves the rules again and waits up to 60 seconds until ports 443 and 7022 of the bridge accept. It then serves the same rules with `INGRESS_BLOCK_ENABLED=false`, so the block carries `"enabled": false`. Within 60 seconds `nc -z` to 443 and to 7022 must be refused, and the journal must hold the Warn `ingress: the state pull carries rules but does not enable public ingress, closing every listener`.
24. **Opted out.** It serves the rules with `enabled` true again and waits until 443 and 7022 accept. It then appends the line `  ingress_enabled: false` to `/etc/plexd/config.yaml`, where it joins the bridge block, the file's last block, and runs `systemctl restart plexd`. Within 60 seconds the journal of the new process must hold `ingress status: reported` with `state=opted_out`, `GET /test/last-request/ingress-status` must return `{"state":"opted_out"}`, and the journal must hold the Warn `ingress: the control plane enables public ingress, but bridge.ingress_enabled is false`, which shows that the new process pulled the enabled block. After that Warn, `nc -z` to 443 and to 7022 must be refused, the journal of that process must hold `bridge subsystem initialized` with `ingress=false`, and it must hold neither `ingress manager started` nor `ingress listener opened`.

The phase ends by requiring that the journals of both processes hold no `ingress status: send failed` line, so the mock refused no report. The mock stores a report before it checks it, so the reports the steps read from `GET /test/last-request/ingress-status` do not show this.

The block phase 16 appends:

```yaml
mode: bridge
bridge:
  enabled: true
  access_interface: eth0
  access_subnets: ["198.18.100.0/24"]
  enable_nat: false
  acme_directory_urls: ["https://pebble:14000/dir"]
```

Step 24 appends `  ingress_enabled: false` to it, step 10 of phase 17 appends `  user_access_enabled: false` and `  user_access_listen_port: 51822`, and step 10 of phase 18 appends `  site_to_site_enabled: false` and `  site_to_site_listen_port: 51823`.

### 17. User access through a bridge

The phase serves user access providers on the bridge of phase 16, which still opts out of public ingress and sets no `bridge.user_access_enabled`, so user access runs on its default (see [User Access Integration](../bridge/user-access-integration.md)). It ends with the bridge opted out of user access.

**Setup.** It starts `plexd-e2e-meshnode` and `plexd-e2e-device` from the image phase 16 built, with `--cap-add NET_ADMIN` and `--init`, on `plexd-systemd-e2e`. It reads plexd's public key with `wg show plexd0 public-key` through a container that shares the systemd container's network namespace. The mesh node then becomes the fixture's peer `...a0b2`, with the recipe of the Docker suite's policy phase: its `wg0` gets a key of its own, listen port 51820, the address `10.99.0.3/24`, and plexd as its one peer with the edge PSK the mock derives for that peer, the bridge's address and port 51820 as endpoint, `10.99.0.1/32` as allowed IPs and a keepalive of 5 s. `nc -l -k -v -n 7101` listens on it and logs each peer. The phase splices the mesh node's key and endpoint into peer `...a0b2` of the live snapshot, posts it to `POST /test/configure-state`, requires the live policy to carry the fixture's rule that allows `10.99.0.0/24` to itself, serves it with `configure_policy`, and waits up to 60 seconds for the mesh node's handshake with `plexd0`.

`configure_user_access <tag> <providers-json or null> [secrets-json]` reads the live snapshot, sets `.bridge.user_access` to `{enabled: true, providers: <providers>}`, or to `null` for `null`, leaves the rest of the bridge block as it is, replaces `.secrets` with `secrets-json` when it is given, posts the result to `POST /test/configure-state` and injects a `node_state_updated` event. `wait_user_access_report <tag> <what> <jq-filter>` polls `GET /test/last-request/user-access-status` with `jq -e` every 2 seconds, for 60 seconds unless `UA_REPORT_WAIT` sets another bound. The probe is `nc -z -w 3 10.99.0.3 7101` in the device container. Every `wireguard` provider of the phase has the pool `10.77.0.0/24` and at most 64 devices.

1. **No provider.** Before any provider is served, the last report reads exactly `{"state":"enabled"}`.
2. **A provider.** It serves `field-team` (`...a0e1`, `wireguard`, port 51900) without a device. The report must carry one entry, `up`, with a `public_key` of 44 characters, `connected_devices` 0 and no `reason`. `ip -4 -o address show dev wg-ua-a0a0a0e1` must show `10.77.0.1/24`, and `stat -c %a /var/lib/plexd/user-access/<id>.key` must print `600`.
3. **No device.** The device brings up its `wg0` at `10.77.0.2/24` with a key of its own, the reported key as its peer, the bridge's address and port 51900 as endpoint, `10.99.0.0/24` as allowed IPs and a keepalive of 5 s, and routes `10.99.0.0/24` over it. The probe must fail while the block lists no device.
4. **A device.** It adds the device (`...a0d1`, `e2e-device`) at `10.77.0.2` with its public key. Within 60 seconds the probe must succeed, the mesh node's listener log must name `10.99.0.1`, the bridge's mesh address, and no address of `10.77.0.0/24`, and a report must show `connected_devices` 1.
5. **A restart.** `systemctl restart plexd`. Within 60 seconds the new process (`plexd[<MainPID>]:`) must log `user access provider up` for `field-team`, the report's `public_key` must equal the one of step 2, and the probe must succeed without a change on the device.
6. **A killed process.** `systemctl kill --kill-whom=main -s KILL plexd`. The signal goes to the main process alone: in this container systemd cannot signal the unit's other processes and would fail the command. Right after the kill `/sys/class/net/wg-ua-a0a0a0e1` must still exist. Within 60 seconds the unit must have started a process with another MainPID that logs `user access provider up` for `field-team`. The journal must then hold exactly one line `plexd.service: Sent signal SIGKILL to main process <pid> (plexd) on client request.`, with the MainPID of step 5. The killed process left `plexd0` in the kernel as well, so the new process must log `wireguard: replaced an interface an earlier process left behind` and `wireguard interface configured`, each with `interface=plexd0`, and no `wireguard setup failed`. It must log no `user access provider down` for `field-team`; the report must show the same `public_key`, and the probe must succeed.
7. **A taken port.** It serves `clash` (`...a0e3`, port 51820, which `plexd0` holds) before `field-team`. The report must show `clash` `down` with `bind_failed` and `field-team` `up`, and the probe must still succeed.
8. **A vendor provider.** It adds `tailnet` (`...a0e2`, `tailscale`, `auth_secret_name` `ts-join`) with the inventory `[]`. The report must show it `down` with `auth_secret_not_listed`. It then posts the Secret `ts-join` in version 1 to `POST /test/configure-secrets` and serves the inventory `[{"name": "ts-join", "version": 1}]`. Within 90 seconds the report must show `tailnet` `down` with `client_missing`: the image carries no Tailscale client, so the change proves the fetch of the Secret.
9. **A removed provider.** It serves `clash` and `tailnet` without `field-team`. The report must carry no entry with its id, `wg-ua-a0a0a0e1` must be gone within 30 seconds, the key file must be gone, and the probe must fail.
10. **Opted out.** It serves `kept` (`...a0e4`, port 51901) beside `clash` and `tailnet` and waits up to 90 seconds for it to read `up`. It requires the last block of `/etc/plexd/config.yaml` to be the bridge block and neither key to be set, appends `  user_access_enabled: false` and `  user_access_listen_port: 51822`, and runs `systemctl restart plexd`. Within 60 seconds `GET /test/last-request/user-access-status` must return exactly `{"state":"opted_out"}`, and the journal of the new process must hold the Warn `user access: the control plane enables user access, but bridge.user_access_enabled is false` with `providers=3`. That journal must also hold `user access: opted out by bridge.user_access_enabled, no provider is served`, exactly one Warn `bridge: config: user access keys are ignored, the control plane delivers providers` with `keys=[user_access_listen_port]`, and `bridge subsystem initialized` with `user_access=false`. No interface whose name starts with `wg-ua-` may exist, and the key file of `kept` must still exist.

The phase ends by requiring that the journal holds no `user access status: send failed` line, so the mock refused no report.

### 18. Site-to-site through a bridge

The phase serves site-to-site tunnels on the bridge of phases 16 and 17, which opts out of public ingress and of user access and sets no `bridge.site_to_site_enabled`, so site-to-site runs on its default (see [Site-to-Site VPN](../bridge/site-to-site-vpn.md)). It keeps phase 17's mesh node, the fixture's peer `...a0b2` at `10.99.0.3` with its listener on 7101, and the policy phase 17 served, which allows `10.99.0.0/24` to itself and has no rule to the site's network. It ends with the bridge opted out of site-to-site.

**Setup.** It starts `plexd-e2e-site` from the image phase 16 built, with `--cap-add NET_ADMIN`, on `plexd-systemd-e2e`. The site holds `10.40.0.1/16` on a `wg0` with a key of its own, listens on UDP 51940, routes `10.99.0.0/24` into that interface, and listens on TCP 7201 with a listener that logs each peer. The mesh node runs no plexd, so the phase adds `10.40.0.0/16` to the allowed IPs of its peer, the bridge, and a route for it through its `wg0` by hand.

`configure_site_to_site <tag> <tunnels-json or null> [secrets-json]` and `wait_site_to_site_report <tag> <what> <jq-filter>` are modelled on `configure_user_access` and `wait_user_access_report` of phase 17: the first sets `.bridge.site_to_site` of the live snapshot to `{enabled: true, tunnels: <tunnels>}`, or to `null` for `null`, replaces `.secrets` with `secrets-json` when it is given, posts the result to `POST /test/configure-state` and injects a `node_state_updated` event; the second polls `GET /test/last-request/site-to-site-status` with `jq -e` until the filter holds. The probe is `nc -z -w 3 10.99.0.3 7101` in the site container.

1. **No tunnel.** Before any tunnel is served, the last report reads exactly `{"state":"enabled"}`.
2. **A tunnel.** It serves `branch` (`0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1e1`, `wireguard`, `listen_port` 51930) with the site's address and port 51940 as remote, the site's public key as `remote_public_key`, `allowed_subnets` `["10.40.0.0/16"]` and no Secret. The report must show it `up` with a `public_key` of 44 characters and `established` false. The interface `wg-s2s-a0a0a1e1` must exist, `ip route show 10.40.0.0/16` must name it, and `/var/lib/plexd/site-to-site/<id>.key` must have mode `600`.
3. **The site answers.** The site takes the reported key as its peer, with the bridge's address and port 51930 as endpoint, `10.99.0.0/24` as allowed IPs and a keepalive of 5 s. Within 60 seconds a report must show `established` true. The probe must succeed, and the mesh node's listener must name `10.99.0.1`, the bridge's mesh address: the bridge rewrote the source.
4. **The bridge's policy.** Under the policy of phase 17, which has no rule to `10.40.0.0/16`, the mesh node's `nc -z -w 3 10.40.0.1 7201` must fail. The phase then adds a rule `any` from `10.99.0.0/24` to `10.40.0.0/16` with `configure_policy`. The same probe must succeed, and the site's listener must name `10.99.0.3`. The pair proves that the bridge's compiled policy filters mesh traffic into the tunnel and that its source stays unchanged.
5. **A preshared key.** The tunnel gains `auth_secret_name` `s2s-psk` while the inventory does not list it: the report must show `branch` `down` with `auth_secret_not_listed`. The phase posts the Secret with a value `wg genpsk` printed to `POST /test/configure-secrets` and lists it in the inventory, and the report must show `branch` `up`. The site sets the same preshared key; within 60 seconds `established` must be true and the probe of step 3 must succeed.
6. **A restart.** `systemctl restart plexd`. The report's `public_key` must equal the one of step 2, `established` must return to true, and the probe of step 3 must succeed without a change on the site.
7. **A killed process.** `systemctl kill --kill-whom=main -s KILL plexd`, which leaves the interface in the kernel. Once the unit has started the process again, the report must show `branch` `up` with the same `public_key`, the journal of the new process must hold no `site-to-site tunnel down` line for it, and the probe must succeed.
8. **Tunnels that are down.** It adds a second `wireguard` tunnel on port 51820, which `plexd0` holds, with `allowed_subnets` `["10.41.0.0/16"]`: the report must show it `down` with `bind_failed`, and `branch` `up`. A third, with `remote_host` `nosuch.invalid` and `["10.42.0.0/16"]`, must read `down` with `remote_host_unresolved`. An `openvpn` tunnel with `["10.43.0.0/16"]` that names the Secret `s2s-ovpn`, listed in the inventory, whose value is a static key in OpenVPN's file format, must read `down` with `client_missing`: the image carries no `openvpn`. The step uses `openvpn` because its link is a tun device, which every runner has; whether a runner's kernel has the xfrm interface module is left to `TestNetlinkVPNController_RealLinks`.
9. **A removed tunnel.** It serves the three tunnels of step 8 without `branch`. Its interface, its route and its key file must be gone, the report must carry no entry with its id, and the probe of step 3 must fail.
10. **Opted out.** It serves `kept` (`wireguard`, port 51931, `["10.44.0.0/16"]`) beside the three tunnels of step 8 and waits for it to read `up`. It appends `  site_to_site_enabled: false` and `  site_to_site_listen_port: 51823` to the bridge block of `/etc/plexd/config.yaml` and runs `systemctl restart plexd`. `GET /test/last-request/site-to-site-status` must then return exactly `{"state":"opted_out"}`, no interface whose name starts with `wg-s2s-`, `xf-s2s-` or `ov-s2s-` may exist, and the key file of `kept` must still exist. The journal of the new process must hold `site-to-site: opted out by bridge.site_to_site_enabled, no tunnel is served`, the Warn `site-to-site: the control plane enables site-to-site tunnels, but bridge.site_to_site_enabled is false` with `tunnels=4`, and exactly one Warn `bridge: config: site-to-site keys are ignored, the control plane delivers tunnels` with `keys=[site_to_site_listen_port]`.

The phase ends by requiring that the journal holds no `site-to-site status: send failed` line, so the mock refused no report.

### 19. Custom CA for the control plane

The phase runs `plexd join` four times as root through `docker exec` in the systemd container, outside the unit, against `https://plexd-e2e-mockapi:8444`, the mock's TLS listener for the control plane API. Its leaf names `mock-api`, `localhost` and `plexd-e2e-mockapi`, the mock's CA signed it, and no trust store of the container holds that CA. Each run works in `/tmp/plexd-ca-join/<case>` with a `config.yaml` of the shape below, whose `api` section each case changes, and its own copy of the bootstrap token of phase 5, because a join that registers removes the token file it read. The phase reads `registration_count` from `GET /test/assertions` before and after each run. It redirects the run's stdout and stderr to two files on the host, with no pipe after the command, so the exit code it records is the one of `plexd join`.

```yaml
data_dir: /tmp/plexd-ca-join/<case>/data
api:
  base_url: https://plexd-e2e-mockapi:8444
  tls_ca_file: /etc/plexd/mock-ca.pem
registration:
  project_id: 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0
  resource_handle: e2e-systemd-ca-join
  max_retry_duration: 5s
```

1. **Control.** Without `tls_ca_file`, join must exit non-zero, its stderr must contain `x509: certificate signed by unknown authority`, and `registration_count` must not change. The case proves that plexd trusts the mock's CA through the file alone. Registration retries the failed handshake until `max_retry_duration` ends it after 5 seconds.
2. **A missing file.** With `tls_ca_file: /etc/plexd/missing-ca.pem`, join must exit non-zero, one line of its stderr must contain both `plexd join: create client: api: config: tls_ca_file:` and `/etc/plexd/missing-ca.pem`, and `registration_count` must not change: join stops when it builds its client, before any request.
3. **Both options.** With the CA file and `tls_insecure_skip_verify: true`, join must exit non-zero and its stderr must contain `tls_ca_file and tls_insecure_skip_verify are mutually exclusive`.
4. **The CA file.** With the CA file alone, join must exit `0`, its stdout must contain `node_id:`, and `registration_count` must grow by exactly 1.

The phase then removes `/tmp/plexd-ca-join` and the files on the host. It comes last because a successful registration replaces the public key the mock compares key rotations against, which the earlier phases must not see. Every other phase reaches the control plane over plain HTTP on port 8080.

### 20. Shutdown verification

Stops the service with `systemctl stop plexd`, verifies `inactive` state and exit code 0, checks `journalctl -u plexd` for absence of crash indicators (`core dumped`, `segfault`, `SIGABRT`, `SIGKILL`), and verifies the shutdown message was logged. The crash check leaves out the lines `plexd.service: Sent signal SIGKILL to main process <pid> (plexd) on client request.` with which systemd records the deliberate kills of step 6 of phase 17 and step 7 of phase 18, and checks every other line. It runs with the opt-out of phase 15, the bridge mode, environment file and ingress opt-out of phase 16, the user access opt-out of phase 17 and the site-to-site opt-out of phase 18 in place, so it stops a bridge that opts out of public ingress, of user access and of site-to-site tunnels.

### 21. Cleanup

The `cleanup` function runs on `EXIT` trap (both success and failure). It unpauses the mock API if the mesh DNS phase left it paused, prints diagnostics on failure, then removes the seven containers and the Docker network.

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
    tls_ca_file: /etc/plexd/mock-ca.pem
log_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  file_patterns:
    - "/var/log/plexd/*.log"
  local_endpoint:
    url: https://plexd-e2e-mockapi:8443/local/logs
    secret_key: local-bearer-token
    tls_ca_file: /etc/plexd/mock-ca.pem
audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  local_endpoint:
    url: https://plexd-e2e-mockapi:8443/local/audit
    secret_key: local-bearer-token
    tls_ca_file: /etc/plexd/mock-ca.pem
```

The bootstrap token is written to `/etc/plexd/bootstrap-token` (mode 0600) before the service starts, and the mock's CA to `/etc/plexd/mock-ca.pem` (mode 0644) before the config. No environment file exists until phase 16 writes `/etc/plexd/environment` with `SSL_CERT_FILE=/etc/plexd/pebble.minica.pem`, which the unit reads through `EnvironmentFile=-/etc/plexd/environment`.

The config sets no `dns` key, so the mesh DNS resolver runs with its defaults, enabled on port 5354, until phase 15 appends:

```yaml
dns:
  enabled: false
```

It sets no `mode` key either, so plexd runs as a node until phase 16 appends the bridge block shown there.

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
- Kernel WireGuard on the host: the mesh DNS phase needs `plexd0`, which plexd creates in the container's network namespace, the user access phase needs the provider's interface and the `wg0` of the mesh node and of the device, and the site-to-site phase the tunnel's interface and the site's `wg0`

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

**An ingress probe fails:**

```bash
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager | grep -E 'ingress|bridge|acme'
docker exec plexd-e2e-ingress-target ss -ltn
docker exec plexd-e2e-systemd curl -sS --cacert /etc/plexd/pebble.minica.pem https://pebble:14000/dir
docker exec plexd-e2e-systemd ls -la /var/lib/plexd/acme
docker logs plexd-e2e-pebble
```

Common causes:
- plexd restarts in a loop after the bridge block: `plexd up: bridge setup` in the journal names the failing step, usually the forwarding sysctl or the route for `access_subnets` on `eth0`.
- `bridge: ingress: listen failed` with `hint="ports below 1024 need CAP_NET_BIND_SERVICE"`: the unit in the container lacks the capability.
- `ingress certificate not loaded` with `reason=certificate_fetch_failed` for `secret=tls-term`: the mock serves another version of the Secret than the inventory lists, or none, because the last `POST /test/configure-secrets` set another one.
- `bridge: acme: obtain certificate failed`: its `error` names the failing ACME request. When the `curl` above fails, plexd cannot reach or trust the directory either. When Pebble's log shows a failed validation, it did not reach port 443 of the bridge under `acme.ingress.e2e.test`, which `--add-host` maps to the address of `plexd-e2e-systemd`.
- `ingress rule not served` with `slug=tls-acme` before step 14: `reason=acme_directory_not_allowed` means the block's `directory_url` is not an entry of `bridge.acme_directory_urls`.
- In step 21 the session or the request with the client's certificate reads nothing: a reason under `client_refusals` of the rule's entry, which arrives with the next repeat of the report, names the check the certificate failed, such as `unknown_authority` for a leaf the bundle's CA did not sign and `certificate_invalid` for a leaf whose `extendedKeyUsage` leaves out `clientAuth`, such as `serverAuth` alone; a leaf without the extension is admitted (see [Client Certificates](../bridge/public-ingress.md#client-certificates)). The journal runs at Info, so it holds no `ingress client refused` line.

**No `ingress status: reported` line:**

```bash
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager | grep -E 'ingress status|public ingress|bridge subsystem initialized'
curl -sS http://localhost:18080/test/last-request/ingress-status
curl -sS http://localhost:18080/test/assertions | jq .ingress_status_count
```

Common causes:
- No `ingress status: reporter started` line either: plexd does not run in bridge mode, so it starts no reporter. `bridge subsystem initialized` is missing too, and `plexd up: bridge setup` names the failing step.
- `ingress status: control plane does not accept ingress status reports, retrying every interval` with `status=404`: the mock image has no `ingress-status` route, so its router answers `404`. Rebuild the mock image.
- `ingress status: send failed` with `malformed_ingress_status` in its `error`: the mock refused the body. `GET /test/last-request/ingress-status` returns what plexd sent. From step 21 on, an entry with `client_auth_enforced` or `client_refusals` that the mock refuses as an unknown member means the mock image predates the two members. Rebuild the mock image.
- `ingress status: reported` with the wrong `state`: `state=opted_out` before step 24 means `/etc/plexd/config.yaml` already sets `ingress_enabled: false`, and `state=enabled` after it means the appended line did not join the bridge block.
- `ingress status: send failed` with `invalid_ingress_status` in its `error`: the entries break a rule that ties members together, such as a repeated `id` or a member sent beside a facet that does not call for it. The `detail` names the entry by index.

**A rule entry that does not read as expected:**

```bash
curl -sS http://localhost:18080/test/last-request/ingress-status | jq .
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager | grep -E 'ingress status|dial target failed|policy ruleset applied'
```

Common causes:
- The report still reads the entry of an earlier step: on-change reports go out at most once per 5 s, and the check polls for 60 s. A report that never follows means the change did not reach the manager; the journal lines of the step tell.
- No `client_refusals` in step 21: a refusal sends no report by itself and rides the next repeat, at most 30 seconds later. A repeat without them means the probes without a certificate did not reach the rule's handshake: `openssl s_client` from the target container ends with a TLS alert for a refused client, and with a failed connect for a port that does not answer.
- `mesh` reads `dial_reason` `policy_denied` under the fixture's policy in step 17: the fixture's policy is not the one the node holds. `policy ruleset applied` names the revision it applied.
- `mesh` never reads `policy_denied` after the policy change: no `policy ruleset applied` for the new revision means the pull did not reach the node or the policy did not apply. With the line present, the dial did not leave from the mesh address: `docker exec plexd-e2e-systemd ip route get 10.99.0.2` must name `plexd0` and `src 10.99.0.1`.

**A user access step fails:**

```bash
curl -sS http://localhost:18080/test/last-request/user-access-status | jq .
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager | grep -E 'user access|access interface|mesh source rewrite'
docker run --rm --network container:plexd-e2e-systemd --cap-add NET_ADMIN plexd-ingress-target:e2e wg show
docker exec plexd-e2e-device wg show wg0
docker exec plexd-e2e-meshnode cat /tmp/listen.log
```

Common causes:
- The report shows the provider `down`: its `reason` names the step that failed (see [Reasons](../bridge/user-access-integration.md#reasons)), and the `user access provider down` line carries the error.
- The probe fails although the provider is `up`: the peer key `wg show wg0` lists on the device must equal the report's `public_key`, which a restart or a kill must not change, and the mesh node's `wg show wg0` must list a recent handshake with `plexd0`.

**A site-to-site step fails:**

```bash
curl -sS http://localhost:18080/test/last-request/site-to-site-status | jq .
docker exec plexd-e2e-systemd journalctl -u plexd --no-pager | grep -E 'site-to-site|tunnel interface|mesh source rewrite'
docker run --rm --network container:plexd-e2e-systemd --cap-add NET_ADMIN plexd-ingress-target:e2e wg show
docker exec plexd-e2e-site wg show wg0
docker exec plexd-e2e-meshnode wg show wg0
```

Common causes:
- The report shows the tunnel `down`: its `reason` names the step that failed (see [Site-to-Site VPN](../bridge/site-to-site-vpn.md)), and the `site-to-site tunnel down` line carries the error.
- The tunnel is `up` but `established` stays false: the peer key `wg show wg0` lists on the site must equal the report's `public_key`, which a restart or a kill must not change, and the site's endpoint must name the bridge's address and the tunnel's `listen_port`.
- The site's probe fails although `established` is true: the mesh node must allow `10.40.0.0/16` from the bridge and route it through its `wg0`, and the bridge must route `10.40.0.0/16` through the tunnel's interface.

**Leftover containers from previous run:**

The script performs pre-cleanup, but if issues persist:

```bash
docker rm -f plexd-e2e-mockapi plexd-e2e-systemd plexd-e2e-ingress-target plexd-e2e-pebble plexd-e2e-meshnode plexd-e2e-device plexd-e2e-site
docker network rm plexd-systemd-e2e
```

## Diagnostics Output

On any failure, the `print_diagnostics` function outputs:

| Command | Purpose |
|---------|---------|
| `docker network inspect plexd-systemd-e2e` | Network state and connected containers |
| `docker logs plexd-e2e-mockapi` | Mock API server logs |
| `docker logs plexd-e2e-pebble` | Pebble's log, its stderr included: the ACME requests plexd sent and the validations of the bridge |
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
| `test/e2e/systemd/pebble-config.json` | Pebble's default config with `"tlsPort": 443`; phase 16 mounts it into `plexd-e2e-pebble` as `/test/config/plexd-e2e.json` |
| `test/e2e/systemd/.dockerignore` | Prevents unnecessary files in Docker context |
| `test/e2e/mockapi/Dockerfile` | Mock API image |
| `test/e2e/mockapi/mockapi.go` | Mock API server with `/test/assertions` endpoint |
| `test/e2e/meshpeer/Dockerfile` | Alpine image with `wireguard-tools`, `iproute2`, `netcat-openbsd`, `openssl`, `socat` and `curl`, and `http-target.sh` in `/usr/local/bin/`; phase 16 runs it as the ingress target, phase 17 as the mesh node, as the device and as the short-lived containers that read the systemd container's network state, and phase 18 as the site |
| `test/e2e/meshpeer/http-target.sh` | The HTTP target of step 19 of phase 16: socat runs it per connection, and it answers one request with a body that names the server and repeats the request head it read |
| `deploy/systemd/plexd.service` | Production unit file (copied verbatim into container) |
| `deploy/systemd/plexd-session-helper.socket`, `deploy/systemd/plexd-session-helper@.service` | Session helper units (copied verbatim into container) |
| `Makefile` | `test-e2e-systemd` target |

## See also

- [Docker E2E Test](docker-e2e-test.md) — Docker Compose-based E2E test
- [Kubernetes E2E Test](kubernetes-e2e-test.md) — kind-based Kubernetes E2E test
