# PLAN.md — plexd Implementation Plan

## Context

plexd is a mesh networking agent (Go 1.22+) that runs on nodes, connects to a control plane via HTTPS+SSE, establishes WireGuard tunnels, enforces L3/L4 policies, collects telemetry, and provides access proxy and actions/hooks execution. The project is currently greenfield — only the design document (README.md) and LICENSE exist. This plan covers the full implementation from development environment through production-ready deployment.

This document serves as input for a planning tool that derives detailed requirements, user stories, tasks, tests, and review criteria per step.

**Key principles:**

- **Test-first:** A mock control plane API is established early and expanded alongside every feature. E2E tests validate each phase before the next one begins.
- **MVP-first:** The first milestone is a working registration flow (plexd registers against the control plane and persists its identity). Everything else builds on top.
- **Incremental E2E:** The mock API and E2E test suite grow with each phase. No feature is considered complete without passing E2E tests.

---

## Phase 0: Development Environment & Build System

### 0.1 Go Module & Project Skeleton
Initialize Go module (`go.mod`), create the directory structure as specified in the README (`cmd/plexd/`, `internal/*/`, `pkg/`, `deploy/`, `docs/`). Add `.gitignore`, `.editorconfig`. Set Go 1.22 as minimum version.

### 0.2 Makefile & Build Tooling
Create Makefile with targets: `build`, `test`, `test-e2e`, `lint`, `fmt`, `vet`, `clean`, `install`. Configure `golangci-lint` with a `.golangci.yml`. Add a basic `main.go` in `cmd/plexd/` that compiles and prints version info.

### 0.3 CI/CD Pipeline
Set up GitHub Actions workflows: lint, test, build (matrix: linux/amd64, linux/arm64). Add caching for Go modules. Add a workflow for release builds and container image publishing to `ghcr.io`. Ensure `test-e2e` target runs in CI with Docker available.

### 0.4 Container Build
Create multi-stage `Dockerfile` in `deploy/docker/`. Base image with WireGuard tools, nftables. Build binary in Go builder stage, copy to minimal runtime. Add `docker-compose.yml` for local development/testing.

---

## Phase 1: Mock Control Plane & E2E Test Foundation

The mock control plane is a Go HTTP server (`internal/mockapi/`) that implements the `/v1` endpoints defined in the README. It is built incrementally — each subsequent phase adds the endpoints it needs. The mock API stores state in-memory (no database) and is purpose-built for testing.

### 1.1 Mock API Server Skeleton
Implement `internal/mockapi/` — an `httptest.Server`-based mock that listens on a configurable address. Initial endpoints:

| Endpoint | Behavior |
|---|---|
| `POST /v1/register` | Validate bootstrap token, return node identity, mesh IP, signing key, NSK, empty peer list |
| `GET /health` | Return `200 OK` (used by E2E readiness probes) |

The mock maintains an in-memory node registry and a token store (pre-seeded for tests). Responses match the schemas defined in the README's [Control Plane API Endpoints](#control-plane-api-endpoints) section.

### 1.2 Mock API Test Helpers
Create `internal/mockapi/testutil/` — helper functions for tests:
- `NewTestServer(t *testing.T) *MockServer` — start mock API, return URL, auto-cleanup on test end
- `SeedToken(token string)` — add a valid bootstrap token
- `GetRegisteredNodes() []Node` — inspect mock state
- `AssertNodeRegistered(t, nodeID)` — assertion helpers

### 1.3 E2E Test Framework
Set up `test/e2e/` directory with Docker Compose-based E2E infrastructure:
- `docker-compose.e2e.yml` — mock API container + plexd agent container(s)
- `Makefile` target `test-e2e` builds images and runs the suite
- Go test files using `testing.T` that orchestrate containers, wait for readiness, and assert outcomes
- Helper to start N plexd agents against the mock API

### 1.4 First E2E Test: Smoke
A minimal smoke test that:
1. Starts the mock API
2. Starts one plexd agent with a valid bootstrap token
3. Asserts that plexd exits startup without error
4. (Registration is not yet implemented — this validates the test infrastructure itself)

---

## Phase 2: Configuration & CLI Foundation

### 2.1 Configuration Loading
Implement `internal/config/` — YAML config file parsing (`/etc/plexd/config.yaml`), environment variable override (`PLEXD_*` prefix), defaults, validation. Cover all config sections: api, mode, mesh, token, reconciliation, policy, nat, heartbeat, observability, log forwarding, audit, access, actions, hooks, bridge, nodeapi.

**Unit tests:** Config parsing with defaults, env override precedence, validation errors for missing required fields.

### 2.2 CLI Framework (cobra)
Set up CLI using `cobra` in `cmd/plexd/`. Implement root command with global flags (`--config`, `--log-level`). Add subcommands as stubs: `up`, `join`, `status`, `peers`, `policies`, `install`, `version`, `actions`, `hooks`, `state`. Wire config loading into CLI.

**Unit tests:** Flag parsing, subcommand routing, config file integration.

### 2.3 Structured Logging
Integrate structured logging library (e.g. `slog` or `zerolog`). Configurable log levels (debug, info, warn, error). JSON output format. Wire through all packages via dependency injection or context.

---

## Phase 3: MVP — Registration

**Milestone: plexd can register with the control plane and persist its identity.** This is the MVP — the minimal useful behavior that proves the agent-to-control-plane communication works end-to-end.

### 3.1 HTTP Client Foundation
Implement `internal/api/` — HTTPS client for control plane communication. TLS configuration, retry logic with exponential backoff, timeout handling. Base client with shared authentication (bearer token after registration).

**Unit tests:** Retry behavior, timeout handling, TLS configuration.

### 3.2 Bootstrap Token Handling
Implement token source resolution in `internal/registration/` — check in order: file, env var, cloud metadata. Delete token after successful registration.

**Unit tests:** Token source priority, file reading, env var reading.

### 3.3 Registration Flow
Implement `POST /v1/register` client call. Generate Curve25519 keypair locally. Send token, public key, hostname, metadata. Parse response: node ID, mesh IP, signing public key, NSK, initial peers. Persist node identity and keys to `data_dir` with correct file permissions (0600/0700).

**Unit tests:** Registration request construction, response parsing, key generation, persistence.

### 3.4 Core Agent Startup (Minimal)
Implement minimal `internal/agent/` — startup sequence: load config → check if already registered (identity file exists) → register if needed → log success → exit. No subsystems yet — just the registration path.

**Unit tests:** Agent startup state machine, idempotent registration (skip if already registered).

### 3.5 Mock API Expansion
Extend mock API `POST /v1/register`:
- Token validation (reject expired/reused tokens)
- Return realistic response with generated node ID, mesh IP, signing key, NSK
- Track registration state (reject duplicate registrations from same token)

### 3.6 E2E: Registration
Expand E2E suite:
1. **Successful registration** — plexd registers with valid token, mock API confirms node is registered, plexd identity file exists in data_dir
2. **Invalid token** — plexd fails gracefully with clear error when token is invalid
3. **Idempotent startup** — plexd starts, registers, restarts, does NOT re-register (uses persisted identity)

---

## Phase 4: Heartbeat & Deregistration

### 4.1 Heartbeat
Implement periodic heartbeat (`POST /v1/nodes/{id}/heartbeat`). Payload: timestamp, binary checksum (SHA-256 of `/proc/self/exe`), uptime, mesh status. Configurable interval (default 30s). Handle heartbeat responses (reconcile hint, rotate_keys hint).

**Unit tests:** Heartbeat payload construction, interval timing, response handling.

### 4.2 Graceful Shutdown & Deregistration
Implement signal handling (SIGTERM, SIGINT) and `plexd deregister` command. On shutdown: send `POST /v1/nodes/{id}/deregister`, clean up local resources. Support `--purge` flag for full state cleanup.

**Unit tests:** Signal handling, shutdown sequence, purge behavior.

### 4.3 Mock API Expansion
Add to mock API:
- `POST /v1/nodes/{node_id}/heartbeat` — accept heartbeat, update node last-seen timestamp, optionally return reconcile/rotate_keys hints
- `POST /v1/nodes/{node_id}/deregister` — remove node from registry

### 4.4 E2E: Heartbeat & Deregistration
1. **Heartbeat delivery** — plexd registers, mock API receives heartbeats at expected interval
2. **Graceful shutdown** — send SIGTERM to plexd, mock API receives deregister call
3. **Deregister with purge** — identity file and keys are removed from data_dir

---

## Phase 5: Cryptography & SSE Event Stream

### 5.1 Ed25519 Signature Verification
Implement `internal/crypto/` — Ed25519 public key management, SSE envelope signature verification. Signing key storage and rotation support (two-key transition period). Replay protection: issued_at staleness check (5 min window), nonce tracking with bounded cache.

**Unit tests:** Signature verification, staleness rejection, nonce deduplication, key rotation transition period.

### 5.2 SSE Client & Event Dispatch
Implement SSE client for `GET /v1/nodes/{id}/events`. Persistent connection with automatic reconnection (exponential backoff 1s→60s, ±25% jitter). `Last-Event-ID` header for missed event replay. Event envelope parsing: unwrap signed envelope, verify Ed25519 signature, dispatch by event type. Define event types as Go types with JSON deserialization.

**Unit tests:** SSE parsing, reconnection backoff, Last-Event-ID handling.

### 5.3 Event Handlers Registry
Implement event handler registry/dispatcher. Map event types to handler functions. All SSE event types registered as stubs initially: `peer_added`, `peer_removed`, `peer_key_rotated`, `peer_endpoint_changed`, `policy_updated`, `action_request`, `session_revoked`, `ssh_session_setup`, `rotate_keys`, `signing_key_rotated`, `node_state_updated`, `node_secrets_updated`. Handlers are implemented by respective subsystems in later phases.

### 5.4 Mock API Expansion
Add to mock API:
- `GET /v1/nodes/{node_id}/events` — SSE stream with signed event envelopes. Helper methods to push events into the stream from test code: `mockServer.PushEvent(nodeID, eventType, payload)`
- Mock generates valid Ed25519 signatures for all events
- Support `Last-Event-ID` replay

### 5.5 E2E: SSE Connection
1. **SSE connect** — plexd registers, establishes SSE stream, mock API confirms active connection
2. **Event delivery** — mock API pushes a test event, plexd receives and logs it
3. **SSE reconnect** — kill SSE connection, plexd reconnects with Last-Event-ID, missed events are replayed
4. **Signature rejection** — mock API pushes event with invalid signature, plexd rejects it (verify via logs)

---

## Phase 6: WireGuard Mesh Networking

### 6.1 WireGuard Interface Management
Implement `internal/mesh/` — create/configure WireGuard interface (`plexd0`), manage local keypair generation (Curve25519), set listen port (default 51820), assign mesh IP from 10.100.0.0/16. Use `wgctrl` Go library or shell out to `wg`/`wg-quick`. Interface lifecycle: create on start, remove on shutdown.

**Unit tests:** Interface configuration generation, peer config construction (test with mock wgctrl).

### 6.2 Peer Management
Add/remove/update WireGuard peers. Each peer: public key, PSK, endpoint (IP:port), allowed IPs (mesh IP/32). Handle SSE events: `peer_added` → add peer config, `peer_removed` → remove peer, `peer_key_rotated` → update public key + PSK, `peer_endpoint_changed` → update endpoint. Maintain local peer state map.

**Unit tests:** Peer state map operations, event-to-config mapping.

### 6.3 Key Rotation
Handle `rotate_keys` SSE event. Generate new Curve25519 keypair, report new public key to control plane (`POST /v1/keys/rotate`), receive new PSKs. Update WireGuard interface with new keys. Ensure zero-downtime rotation via transition period.

**Unit tests:** Key rotation state machine, double-key transition.

### 6.4 Mock API Expansion
Add to mock API:
- Registration response now includes realistic peer list (when multiple nodes are registered)
- `POST /v1/keys/rotate` — accept new public key, return updated peer list with new PSKs
- SSE events: `peer_added`, `peer_removed`, `peer_key_rotated`, `peer_endpoint_changed` — pushable from test code
- When a second node registers, mock API automatically pushes `peer_added` to the first node

### 6.5 E2E: Mesh Establishment
1. **Two-node mesh** — register two plexd agents, both receive each other as peers, WireGuard interfaces are created with correct peer configs
2. **Peer added at runtime** — two nodes running, third registers, existing nodes receive `peer_added` via SSE
3. **Peer removed** — deregister one node, others receive `peer_removed`, WireGuard peer is removed
4. **Key rotation** — trigger `rotate_keys`, node generates new key, submits to mock API, receives updated PSKs
5. **Mesh connectivity** — (requires NET_ADMIN in containers) two nodes can ping each other's mesh IP through the WireGuard tunnel

---

## Phase 7: NAT Traversal

### 7.1 STUN Client & NAT Detection
Implement `internal/nat/` — STUN client for public endpoint discovery. Support configurable STUN servers (defaults: `stun.l.google.com:19302`, `stun.cloudflare.com:3478`). NAT type detection: full cone, restricted cone, port-restricted, symmetric. Report discovered endpoint to control plane (`PUT /v1/nodes/{id}/endpoint`).

**Unit tests:** STUN response parsing, NAT type classification.

### 7.2 Endpoint Refresh & Fallback
Periodic endpoint refresh (default 60s). Update control plane with current public endpoint. On symmetric NAT detection, flag node for relay fallback. Integrate with peer endpoint management — update WireGuard peer endpoints when `peer_endpoint_changed` events arrive.

### 7.3 Mock API Expansion
Add to mock API:
- `PUT /v1/nodes/{node_id}/endpoint` — accept endpoint report, return peer endpoints
- Distribute endpoint updates to other registered nodes via `peer_endpoint_changed` SSE events

### 7.4 E2E: NAT Endpoint Reporting
1. **Endpoint report** — plexd starts, performs STUN (or reports a local endpoint in test mode), mock API receives the endpoint
2. **Endpoint exchange** — two nodes report endpoints, each receives the other's endpoint via SSE or endpoint response

---

## Phase 8: State Reconciliation

### 8.1 Full State Pull & Diff
Implement `internal/reconcile/` — periodic full-state pull from control plane (`GET /v1/nodes/{id}/state`). Diff control plane desired state against local actual state (peers, policies, keys, endpoints). Apply corrections for any detected drift.

**Unit tests:** State diff algorithm, correction application.

### 8.2 Drift Reporting
Report drift to control plane (`POST /v1/nodes/{id}/drift`). Drift payload: what changed, expected vs actual values. Reconciliation triggers: periodic timer (default 60s) + SSE reconnection event. Capability updates (`PUT /v1/nodes/{id}/capabilities`).

### 8.3 Mock API Expansion
Add to mock API:
- `GET /v1/nodes/{node_id}/state` — return full desired state (peers, policies, signing keys, metadata, data, secret_refs)
- `POST /v1/nodes/{node_id}/drift` — accept and store drift reports (queryable by tests)
- `PUT /v1/nodes/{node_id}/capabilities` — accept capability updates
- Helper: `mockServer.InjectDrift(nodeID, mutation)` — modify the desired state so reconciliation detects a diff

### 8.4 E2E: Reconciliation
1. **Periodic reconciliation** — plexd pulls state, no drift detected, no corrections applied
2. **Drift correction** — mock API modifies desired state (add a peer), reconciliation detects and corrects it, drift report is sent
3. **SSE reconnect triggers reconciliation** — kill SSE connection, on reconnect plexd immediately reconciles
4. **Capability update** — modify plexd config (add a hook definition), capabilities are reported to mock API

---

## Phase 9: Policy Enforcement

### 9.1 nftables Management
Implement `internal/policy/` — nftables rule management for `plexd0` interface. Create plexd-specific nftables table and chains. Default deny-all stance. Translate policy rules from control plane format to nftables rules (L3: src/dst IP, L4: protocol, port ranges). Apply atomically (nftables transactions).

**Unit tests:** Policy-to-nftables rule translation, diff computation.

### 9.2 Policy Updates & Peer Visibility
Handle `policy_updated` SSE event. Diff incoming policy against current rules, apply changes. Peer visibility filtering: only configure WireGuard peers that the policy authorizes. Log denied packets (configurable). Provide `plexd policies` CLI command to inspect active rules.

### 9.3 E2E: Policy Enforcement
1. **Default deny** — two nodes with tunnel, no policy allows traffic, ping fails
2. **Policy allows traffic** — mock API pushes `policy_updated` allowing ICMP between the nodes, ping succeeds
3. **Policy update** — existing allow rule removed via `policy_updated`, traffic is blocked again
4. **Peer visibility** — node B is not authorized by policy, plexd does not add it as WireGuard peer despite receiving `peer_added`

---

## Phase 10: Observability Pipeline

### 10.1 Metrics Collection
Implement `internal/observe/` — collect node metrics at configurable interval (default 15s). Metrics: CPU, memory, disk, network I/O, tunnel health (handshake age, transfer bytes), peer latency, agent internal stats. Batch delivery to control plane (`POST /v1/nodes/{id}/metrics`, 10s interval or 500 data points, gzip-compressed).

**Unit tests:** Metric collection, batch assembly, gzip encoding.

### 10.2 Log Forwarding
Implement `internal/logs/` — log collection from journald (by unit) and file paths. Configurable filters (unit, path, severity). JSON Lines format, gzip-compressed batch upload (`POST /v1/nodes/{id}/logs`). Batch settings: 10s interval or 1000 lines. Offline ringbuffer: 10,000 entries. Drain buffer on reconnection.

**Unit tests:** Filter matching, batch assembly, ringbuffer overflow behavior.

### 10.3 Audit Collection
Implement `internal/audit/` — Linux auditd event collection via Netlink socket (real-time). Kubernetes audit log file tailing (auto-detected path). Normalize to common JSON schema. Same batch model (`POST /v1/nodes/{id}/audit`) and offline buffer as log forwarding.

### 10.4 Mock API Expansion
Add to mock API:
- `POST /v1/nodes/{node_id}/metrics` — accept gzip-compressed metric batches, store in-memory, queryable by tests
- `POST /v1/nodes/{node_id}/logs` — accept gzip-compressed log batches
- `POST /v1/nodes/{node_id}/audit` — accept gzip-compressed audit batches
- Helpers: `mockServer.GetMetrics(nodeID)`, `mockServer.GetLogs(nodeID)`, `mockServer.GetAuditEvents(nodeID)`

### 10.5 E2E: Observability
1. **Metrics delivery** — plexd runs for 30s, mock API receives at least one metrics batch with expected metric groups
2. **Log forwarding** — plexd generates log output, mock API receives log batch containing plexd unit logs
3. **Offline buffering** — disconnect mock API, plexd buffers data, reconnect, buffered data is drained to mock API

---

## Phase 11: Actions & Hooks

### 11.1 Built-in Actions
Implement `internal/actions/` — built-in action handlers: diagnostics (network tests, interface state), service management (restart, status), health checks. Action execution framework: receive `action_request` SSE event, ACK/NACK to control plane, execute asynchronously, deliver result via callback.

**Unit tests:** Action dispatch, ACK/NACK logic, result construction, timeout enforcement.

### 11.2 Script Hooks
Implement `internal/hooks/` — script hook management from config declarations. SHA-256 checksum verification before execution. inotify file watching for integrity monitoring. Hook parameters, timeout enforcement, user/group execution context. Report integrity violations to control plane.

**Unit tests:** Checksum computation, parameter injection, timeout kill.

### 11.3 CRD Hooks (Kubernetes)
Implement Kubernetes CRD-based hooks. Watch `PlexdHook` custom resources. Execute hooks as Kubernetes Jobs. Image digest (`@sha256:`) enforcement. Job lifecycle management: create, monitor, cleanup. Map hook results back to action callback.

### 11.4 Execution Sandbox
Implement `internal/execution/` — sandbox levels for hook execution. `none`: direct execution. `namespaced`: Linux namespaces (PID, network, mount). `container`: full container isolation via containerd/podman. Max concurrent execution limiting. Timeout enforcement and cleanup.

### 11.5 Mock API Expansion
Add to mock API:
- `POST /v1/nodes/{node_id}/executions/{execution_id}/ack` — receive ACK/NACK, store state
- `POST /v1/nodes/{node_id}/executions/{execution_id}/result` — receive execution result, store state
- Helpers: `mockServer.TriggerAction(nodeID, action)` — push `action_request` SSE event, `mockServer.GetExecutionResult(executionID)`

### 11.6 E2E: Actions & Hooks
1. **Built-in action** — mock API triggers `diagnostics.collect`, plexd ACKs, executes, result callback arrives at mock API with `status: success`
2. **Hook execution** — configure a simple test hook script, mock API triggers it, result arrives with stdout content
3. **Rejected action** — trigger unknown action, plexd NACKs with `reason: unknown action`
4. **Integrity violation** — modify hook script after startup, trigger execution, plexd rejects with integrity violation
5. **Timeout** — trigger hook with 1s timeout and a script that sleeps 10s, result arrives with `status: timeout`
6. **Concurrent limit** — trigger more actions than `max_concurrent`, excess is rejected

---

## Phase 12: Access Proxy & Auth

### 12.1 SSH Tunnel Proxy
Implement `internal/access/` — SSH access mediation. Handle `ssh_session_setup` SSE event. Establish TCP tunnel through mesh to target node. Session environment injection (`PLEXD_SESSION_TOKEN`). Idle timeout enforcement. Handle `session_revoked` event for forced disconnect.

### 12.2 Kubernetes API Proxy
Implement K8s API proxy. Generate scoped kubeconfig with short-lived tokens. Proxy requests through mesh to target cluster's API server. Session-based auth using control plane JWTs. Audit logging of proxied requests.

### 12.3 JWT Session Validation
Implement `internal/auth/` — JWT validation for session tokens. Verify against control plane's Ed25519 signing key. Claims validation: expiry, scope, node binding. Token revocation set. Token refresh handling. Used by both SSH proxy and local action authentication.

**Unit tests:** JWT creation/validation, scope matching patterns, revocation set, expiry handling.

### 12.4 E2E: Access & Auth
1. **SSH session setup** — mock API pushes `ssh_session_setup`, plexd opens listener on mesh interface
2. **Session revocation** — mock API pushes `session_revoked`, plexd adds to revocation set, subsequent action with that token is rejected
3. **Local action with JWT** — execute `plexd actions run` with valid session token, action completes successfully
4. **Expired JWT** — action with expired token is rejected

---

## Phase 13: Local Node API

### 13.1 Unix Socket API Server
Implement `internal/nodeapi/` — HTTP/1.1 server on Unix socket (`/var/run/plexd/api.sock`). Access control via Unix groups (`plexd`, `plexd-secrets`). REST endpoints: GET/PUT/DELETE for metadata, data entries, report entries. Optional TCP listener with bearer token auth.

**Unit tests:** Endpoint routing, access control enforcement, If-Match concurrency control.

### 13.2 Secret Decryption Proxy
Implement secrets endpoint. On GET request, proxy to control plane (`GET /v1/nodes/{id}/secrets/{key}`), decrypt with NSK (AES-256-GCM envelope encryption). Never cache or persist plaintext. Require `plexd-secrets` group membership or valid bearer token.

**Unit tests:** NSK encryption/decryption roundtrip, 503 when control plane unreachable.

### 13.3 Kubernetes CRD State Sync
Implement `PlexdNodeState` CRD controller. Agent manages `.spec` (writes state). Workloads can write `.status`. Sync CRD state with control plane. Map CRD operations to control plane report API. Watch for `.status` changes from workloads.

### 13.4 Mock API Expansion
Add to mock API:
- `GET /v1/nodes/{node_id}/secrets/{key}` — return NSK-encrypted secret value
- `POST /v1/nodes/{node_id}/report` — accept report entry sync
- Helpers: `mockServer.SetSecret(nodeID, key, value)`, `mockServer.GetReports(nodeID)`

### 13.5 E2E: Local Node API
1. **Metadata read** — plexd receives metadata via SSE, local API returns it via Unix socket
2. **Data read** — data entry pushed via SSE, readable via local API
3. **Report write** — write report entry via local API, plexd syncs to mock API
4. **Secret read** — request secret via local API, plexd proxies to mock API, decrypts, returns plaintext
5. **Secret offline** — stop mock API, secret request returns 503

---

## Phase 14: Bridge Mode

### 14.1 Bridge Core & Access Providers
Implement `internal/bridge/` — bridge mode activation when `mode: bridge` in config. User access layer: accept connections from Tailscale, Netbird, WireGuard clients. Route traffic into the plexd mesh. Separate interface management for access network vs mesh network.

### 14.2 Public Ingress & TLS
Implement public ingress with TLS termination. SNI-based routing to mesh targets. Automatic certificate management (Let's Encrypt or provided certs). TCP/UDP port forwarding rules.

### 14.3 Site-to-Site VPN
Implement site-to-site VPN connectivity. WireGuard, IPsec, and OpenVPN peering. Route propagation between site-to-site tunnels and mesh network. Subnet advertisement to control plane.

### 14.4 NAT Relay
Implement relay functionality for nodes behind symmetric NAT. Accept relayed WireGuard traffic. Forward between nodes that cannot establish direct P2P. Minimal overhead, kernel-level forwarding where possible.

### 14.5 E2E: Bridge Mode
1. **Bridge registration** — plexd in bridge mode registers, mock API confirms mode
2. **NAT relay** — two nodes behind simulated NAT, bridge relays traffic between them
3. **User access** — WireGuard client connects to bridge, traffic reaches mesh node

---

## Phase 15: CLI Commands

### 15.1 Status & Peers Commands
Implement `plexd status` (agent state, connectivity, uptime), `plexd peers` (list connected peers, latency, handshake age, endpoints), `plexd version` (binary version, build info, checksum).

### 15.2 Policy & State Commands
Implement `plexd policies` (list active firewall rules, policy version), `plexd state` (inspect node state entries, metadata, data, report).

### 15.3 Actions & Hooks CLI
Implement `plexd actions run <name>` (execute action via Unix socket, display results), `plexd actions list` (available actions), `plexd hooks verify` (check all hook checksums, report integrity), `plexd hooks list` (configured hooks).

### 15.4 Install & Service Management
Implement `plexd install` (create systemd unit file, enable service), `plexd uninstall` (remove systemd unit, clean up). Generate systemd unit with appropriate capabilities and restart policy.

---

## Phase 16: Kubernetes Deployment

### 16.1 CRD Definitions
Create CRD YAML manifests in `deploy/kubernetes/`: `PlexdHook` (v1alpha1) — hook definitions with image, args, timeout, sandbox level. `PlexdNodeState` (v1alpha1) — node state with spec/status split. Include validation schemas.

### 16.2 DaemonSet & RBAC
Create DaemonSet manifest for `plexd-system` namespace. Host networking, `NET_ADMIN`/`NET_RAW` capabilities, `/var/lib/plexd` volume. ServiceAccount, ClusterRole, ClusterRoleBinding for CRD access, node metadata reading, Job management.

### 16.3 Bootstrap Secret & Helm Chart
Create example Secret manifest for bootstrap token (with ESO recommendation). Optionally create Helm chart wrapping all K8s manifests with configurable values (image, config, resources, tolerations, node selectors).

---

## Phase 17: Packaging & Distribution

### 17.1 Binary Release Pipeline
Set up GoReleaser or equivalent. Cross-compilation: linux/amd64, linux/arm64. Binary checksums (SHA-256). GitHub Releases with changelog. Install script (`get.plexsphere.com/plexd`).

### 17.2 Container Image Publishing
Automate container image build and push to `ghcr.io/plexsphere/plexd`. Multi-arch images (amd64, arm64). Tag strategy: `latest`, semver, git SHA. Image signing (cosign/sigstore).

### 17.3 Systemd Integration
Create systemd unit template in `deploy/systemd/`. `After=network-online.target`, restart on failure, capability bounding set. Generate via `plexd install` command. Documentation for manual setup.

---

## Phase 18: Documentation

### 18.1 API Documentation
Generate/maintain OpenAPI spec for local node API. Document SSE event schemas. Document CRD schemas with examples.

### 18.2 Operator Documentation
User-facing documentation: installation guide, configuration reference, troubleshooting guide, bridge mode setup, Kubernetes deployment guide. Developer documentation: architecture overview, contributing guide, adding new actions/hooks.

