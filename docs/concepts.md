# Agent Internals

## Subsystems

These subsystems are initialized and started by `plexd up`:

| Subsystem | Package | Reference |
|-----------|---------|-----------|
| Control Plane Client | `internal/api` | [Control Plane Client](reference/core/control-plane-client.md) |
| Registration | `internal/registration` | [Registration](reference/core/registration.md) |
| Event Verification | `internal/api` (Ed25519Verifier) | [Event Verification](reference/core/event-verification.md) |
| WireGuard | `internal/wireguard` | [WireGuard Tunnel Management](reference/networking/wireguard.md) |
| NAT Traversal | `internal/nat` | [NAT Traversal via STUN](reference/networking/nat-traversal.md) |
| Peer Exchange | `internal/peerexchange` | [Peer Endpoint Exchange](reference/networking/peer-endpoint-exchange.md) |
| Network Policy | `internal/policy` | [Network Policy Enforcement](reference/networking/network-policy.md) |
| Secure Tunneling | `internal/tunnel` | [Secure Access Tunneling](reference/networking/secure-access-tunneling.md) |
| SSE Manager | `internal/api` (SSEManager) | [Control Plane Client](reference/core/control-plane-client.md) |
| Reconciler | `internal/reconcile` | [Configuration Reconciliation](reference/core/reconciliation.md) |
| Heartbeat | `internal/agent` (HeartbeatService) | [Heartbeat Service](reference/core/heartbeat-service.md) |
| Integrity | `internal/integrity` | [Integrity Verification](reference/actions/integrity-verification.md) |
| Actions | `internal/actions` | [Remote Actions and Hooks](reference/actions/remote-actions-hooks.md) |
| Node API | `internal/nodeapi` | [Local Node API](reference/core/nodeapi.md) |
| Metrics | `internal/metrics` | [Metrics Collection & Reporting](reference/observability/metrics-collection.md) |
| Log Forwarding | `internal/logfwd` | [Log Forwarding](reference/observability/log-forwarding.md) |
| Audit Forwarding | `internal/auditfwd` | [Audit Forwarding](reference/observability/audit-forwarding.md) |
| Bridge (bridge mode) | `internal/bridge` | [Bridge Mode](reference/bridge/bridge-mode.md) |

## Startup Sequence (`plexd up`)

The `runUp` function in `cmd/plexd/cmd/up.go` performs initialization before entering steady state:

**Initialization:**

![The initialization of plexd up runs in six groups. Config and logger: parse the config, then set up the logger. Registration: create the control plane client, register the node, create the Ed25519 verifier. Networking, each step after the verifier: initialize WireGuard, NAT and peer exchange, network policy, the tunnel and, in bridge mode only, the bridge. Core services, after all five: create the SSE manager, the reconciler and the heartbeat service. Actions and node API: create the integrity store and verifier, then the action executor with the rollout installer, the capability reporter and the hook watchers, then the node API server. Observability: create the metrics collectors, the log forwarder and the audit forwarder. Last, plexd launches the goroutines via a WaitGroup.](./diagrams/architecture-startup-sequence.svg)

1. **Parse config** — read YAML, apply CLI flag overrides, apply `PLEXD_*` env overrides
2. **Set up logger** — structured `slog` logger with configured level
3. **Create control plane client** — `api.NewControlPlane()` with API config and build version
4. **Register** — `registrar.Register()` loads or creates node identity (fatal on failure)
5. **Create Ed25519 verifier** — decode the control plane's signing public key from identity (the key registration returned, or a newer one a state pull carried and the agent persisted); `signingKeyDispatchHandler`, registered first among the reconcile [dispatch handlers](reference/core/reconciliation.md#registered-dispatch-handlers), installs the key every state pull carries
5a. **Initialize WireGuard** — measure the uplink's path MTU with the STUN servers, create WireGuard interface, configure address and MTU, bring interface up. The interface MTU is sized to the uplink unless `wireguard.mtu` pins it or `nat.enabled` is false (see [MTU detection](reference/networking/wireguard.md#mtu-detection))
5b. **Initialize NAT + Peer Exchange** — create STUN client, NAT discoverer, and peer exchanger
5c. **Initialize Network Policy** — create policy engine, firewall controller, and enforcer
5d. **Initialize Tunnel** — load/generate host key, create JWT verifier and mesh server
5e. **Initialize Bridge** (bridge mode only) — create the bridge manager and run its Setup, and when the configuration still sets one of the replaced user access keys, log one Warn that names them. Unless both `bridge.ingress_enabled` and `bridge.user_access_enabled` are `false`, read the node secret key for `nodeSecretFetcher` (`cmd/plexd/cmd/node_secrets.go`), the fetch of the Secrets the two managers read (an error fails `plexd up`). Unless `bridge.ingress_enabled` is `false`, create the ACME manager over the cache directory (`bridge.acme_cache_dir`, or `<data_dir>/acme`), create the ingress manager with it and the fetcher, and run the ingress manager's Setup. With `bridge.ingress_enabled: false`, create neither manager and log `public ingress: opted out by bridge.ingress_enabled, no public listener is opened` (see [Activation](reference/bridge/public-ingress.md#activation)). The ACME manager has no Setup and starts without an account: `IngressManager.Apply` configures it from the state pull's `bridge.ingress` block (see [ACME and SNI Routing](reference/bridge/acme-sni.md#acmemanager)). Unless `bridge.user_access_enabled` is `false`, create the user access manager with the fetcher, a key store over `<data_dir>/user-access` and the Tailscale and NetBird clients, and run its Setup, which removes the provider interfaces and source rewrites a killed process left behind (an error fails `plexd up`). With `bridge.user_access_enabled: false`, create no user access manager, remove those leftovers once, and log `user access: opted out by bridge.user_access_enabled, no provider is served` (see [Activation](reference/bridge/user-access-integration.md#activation)). With `bridge.site_to_site_enabled`, create the site-to-site manager and run its Setup
6. **Create SSE manager** — `api.NewSSEManager()` with handlers for signing key rotation, WireGuard peer events, tunnel events, policy events, and bridge events (bridge mode)
7. **Create reconciler** — `reconcile.NewReconciler()` with handlers for WireGuard, policy, and bridge reconciliation
8. **Create heartbeat service** — `agent.NewHeartbeatService()` with subsystem status enrichment and key-rotation callback; its credential-refused callback is set in step 12, once the node API server exists
9. **Create integrity store + verifier** — `integrity.NewStore()` and `integrity.NewVerifier()`, for the hook checksums the executor verifies before a run and for the baseline checks of the binary, the hooks directory and the SSH host key that goroutine 10 runs. With integrity enabled and `integrity.binary_path` empty, `integrity.SelfPath()` first sets it to the running executable with symlinks resolved; an error fails `plexd up`
10. **Create action executor** — `actions.NewExecutor()`, register 11 built-in actions, build the rollout installer with `actions.NewRolloutInstaller()` (a constructor error logs `rolled-out hooks disabled`, and the agent runs on without rolled-out hooks), register the installer's `Handle`, when it was built, and then `actions.NewDispatcher()` on the reconciler as dispatch handlers, list the `PlexdHook` resources in a pod's namespace, and build `agent.NewCapabilityReporter()`, which sends nothing until it starts. In a pod, `newPlexdHookRunner()` also builds the PlexdHook runner, which runs a dispatched `PlexdHook` as a Kubernetes Job, and `executor.SetPlexdHookRunner()` hands it over before the reconciler starts. An empty ServiceAccount namespace, an unset `MY_NODE_NAME`, or a Job client that cannot be built logs a `plexd hook runs disabled` warning instead, and the node runs no PlexdHook (see [Kubernetes Deployment](reference/deployment/kubernetes-deployment.md#wiring-in-plexd-up))
11. **Create hook watchers** — `actions.NewHookWatcher()` for `hooks_dir`, with an `onChange` that calls `executor.SetHooks()` and then the reporter's `Notify()`, and, when the installer was built and `actions.rollouts_enabled` is not `false`, `actions.NewRolloutHookWatcher()` for the rollout directory `<data_dir>/hooks`, whose `onChange` calls `executor.SetRolloutHooks()` and `Notify()`. plexd then runs the installer's `Load()`, which restores the rolled-out hooks from `hook_rollouts.json`, pins each to the checksum it was delivered with, and removes every other file of the rollout directory. It then runs one first scan over both directories with `hookDirsReloader.Reload()` and waits for it, for at most 10 seconds, so the executor's hook list is filled before anything reads it and the boot manifest carries the hooks on disk
12. **Create node API server** — `nodeapi.NewServer()`, wire action provider, hook reloader (the same `hookDirsReloader`, so `POST /v1/hooks/reload` rescans both directories), and reconcile handler
13. **Create metrics collectors + manager** — system collector, agent stats collector, `metrics.NewManager()`
14. **Create log sources + forwarder** — platform log source (journald on Linux, the launchd log file on macOS, the Event Log on Windows), file sources from `file_patterns`, `logfwd.NewForwarder()`
15. **Create audit sources + forwarder** — process source, `auditfwd.NewForwarder()`

**Goroutines (the same in node and bridge mode):**

After initialization, goroutines are started via a `sync.WaitGroup`:

1. **SSE Manager** — `sseMgr.Start()` — event stream connection
2. **Heartbeat** — `heartbeat.Run()` — periodic heartbeats
3. **Reconciler** — `reconciler.Run()` — periodic state reconciliation
4. **Node API** — `nodeAPISrv.Start()` — local endpoint (a Unix socket, or a named pipe on Windows) + optional HTTP server
5. **Hook Watcher** — `hookWatcher.Watch()` — filesystem watching for hook changes in `hooks_dir`
6. **Rollout Hook Watcher** — `rolloutWatcher.Watch()` — filesystem watching of the rollout directory; started only when that watcher was built
7. **Rollout Installer** — `rolloutInstaller.Run()` — one pass per `hooks` block the reconciler hands over: fetch, verify, install, and remove rolled-out hooks; started only when the installer was built
8. **Capability Reporter** — `capabilityReporter.Run()` — sends the boot manifest, reports each hook or `PlexdHook` change and each change to the rollout errors, and retries a failed send
9. **PlexdHook Inventory** — `plexdHooks.run()` — watches the `PlexdHook` resources in a pod's namespace; returns at once outside a cluster
10. **Integrity Verifier** — `integrityVerifier.Run()` — checks the binary, `integrity.hooks_dir` and the SSH host key against their baselines once at start and then every `integrity.verify_interval`, reports each change once and then adopts it as the baseline; returns at once when `integrity.enabled` is `false` (see [Integrity Verification](reference/actions/integrity-verification.md#startup-sequence))
11. **Metrics Manager** — `metricsMgr.Run()` — collect and report metrics
12. **Log Forwarder** — `logForwarder.Run()` — collect and forward logs
13. **Audit Forwarder** — `auditForwarder.Run()` — collect and forward audit events
14. **Peer Exchange** — `exchanger.Run()` — STUN discovery and endpoint exchange loop
15. **Mesh Server** — `meshServer.Start()` — tunnel SSH server

The bridge's NAT relay is not a startup goroutine. In bridge mode with `bridge.relay_enabled` set, the reconciler's `RelayReconcileHandler` starts it on the first cycle whose state pull enables it, and stops it when a pull disables it or the bridge tears down (see [NAT Relay](reference/bridge/nat-relay.md#relayreconcilehandler)).

In bridge mode `plexd up` also starts the ingress status reporter, whether or not the bridge opts out of public ingress. It sends `PUT /v1/nodes/{node_id}/ingress-status` once at start, on every change of an ingress rule's listener, certificate or last dial at most once per 5 s, and once per `heartbeat.interval`, with `opted_out` when `bridge.ingress_enabled` is `false`, and otherwise `enabled` with one entry per ingress rule. It ends with the context, without a report at shutdown (see [Ingress Status Report](reference/bridge/public-ingress.md#ingress-status-report)).

## Shutdown Sequence

On SIGTERM or SIGINT:

![SIGTERM or SIGINT cancels the context. The SSE shutdown and the draining of actions both follow, and both lead to the mesh server shutdown. In bridge mode the bridge teardown comes next: the ingress, user access, site-to-site, ACME and bridge teardowns, in that order. Then the firewall and WireGuard are torn down. If the WaitGroup is done within 30 seconds, plexd exits with 0; if not, it forces the exit.](./diagrams/architecture-shutdown-sequence.svg)

1. **Context cancel** — the signal-notify context is cancelled, which signals all goroutines to stop
2. **`sseMgr.Shutdown()`** — close the SSE connection
3. **`executor.Shutdown()`** — drain running actions
4. **`meshServer.Shutdown()`** — stop tunnel SSH server and drain sessions
5. **`ingressMgr.Teardown()`** — close ingress listeners (bridge mode, unless `bridge.ingress_enabled` is `false`)
6. **`userAccessMgr.Teardown()`** — stop the vendor clients and remove the provider interfaces and their source rewrites, keeping the key files (bridge mode, unless `bridge.user_access_enabled` is `false`)
7. **`s2sMgr.Teardown()`** — remove site-to-site tunnels and interfaces (bridge mode)
8. **`acmeMgr.Teardown()`** — retire the ACME account and wait at most 10 s for its certificate requests in flight (bridge mode, unless `bridge.ingress_enabled` is `false`; see [Teardown](reference/bridge/acme-sni.md#teardown))
9. **`bridgeMgr.Teardown()`** — remove bridge routes and forwarding (bridge mode)
10. **`enforcer.Teardown()`** — remove firewall chains and rules
11. **`wgMgr.Teardown()`** — delete WireGuard interface (last, others depend on it)
12. **`wg.Wait()` with 30s timeout** — wait for all goroutines to exit; force exit if timeout exceeded

## Authentication Flow

1. **Bootstrap** — node registers using a bootstrap token (file, env var, or metadata service)
2. **Node Secret Key** — registration returns a `NodeSecretKey` used for all subsequent API authentication
3. **Heartbeat Auth** — each heartbeat uses the node secret key; three heartbeats answered 401 Unauthorized (`unauthorized`, `nsk_invalid` or `nsk_revoked`) with no accepted one between them park the agent, which then stops calling the control plane and probes the credential with the heartbeat (see [Credential Park](reference/core/heartbeat-service.md#credential-park))
4. **Signing Key** — the Ed25519 verifier checks SSE envelopes and ssh session tokens against the Domain signing key. Every successful state pull installs the key its `signing_key` block carries (`verifier.Install`) and persists it into the identity files, so a restart starts from it. A `null` block keeps the installed key, and a key the verifier refuses changes nothing. A `signing_key_rotated` SSE event installs a new key too (`verifier.Rotate`) and can keep the previous key trusted until the rotation's `transition_expires`; a pulled key that differs from the current one ends that grace window, because a node trusts exactly one key of its Domain. The mesh SSH server's JWT verifier (step 5d) is separate: it keeps the key decoded at start and picks up a pulled key only after a restart

## SSE Event Types

The SSE manager processes events in two tiers. Payloads of the reconcile-driving
types are opaque — the reconciler's state pull is authoritative, so those events
only request a reconcile. `session_revoked` is the exception: its payload names
the session to close before the reconcile. `session_connect` drives no reconcile
at all: its payload names a connection to open.

| Event | Tier | Handler |
|-------|------|---------|
| `node_state_updated` | contract | Triggers a reconcile |
| `policy_updated` | contract | `policy.HandlePolicyUpdated` — triggers a reconcile |
| `bridge_config_updated` | contract | `bridge.HandleBridgeConfigUpdated` — triggers a reconcile (bridge mode) |
| `action_request` | contract | Triggers a reconcile — the dispatch rides the `executions` block of the resulting pull |
| `session_setup` | contract | Triggers a reconcile — the session rides the `sessions` block of the resulting pull |
| `session_revoked` | contract | Closes the live session the payload names with the reason it carries (`tunnel.Dispatcher.SessionRevokedHandler`), then triggers a reconcile; the block drain stays the teardown when the event is missed |
| `session_connect` | contract | Opens the connection the payload names for a live ssh session and serves the session's SSH login on it (`tunnel.Dispatcher.SessionConnectHandler`); triggers no reconcile. Only a control plane with [plexsphere/plexsphere#928](https://github.com/plexsphere/plexsphere/issues/928) emits it |
| `node_secrets_updated` | contract | Triggers a reconcile; the inventory rides the `secrets` block of the resulting pull, which feeds the node API's secret index |
| `peer_registered` | documented-coming | Triggers a reconcile |
| `peer_psk_assigned` | documented-coming | Triggers a reconcile |
| `peer_deregistered` | documented-coming | Triggers a reconcile |
| `peer_endpoint_changed` | documented-coming | Triggers a reconcile |
| `peer_key_rotated` | documented-coming | Triggers a reconcile |
| `rotate_keys` | documented-coming | Starts a key rotation (`rotator.RotateNow`) |
| `signing_key_rotated` | documented-coming | Updates the Ed25519 verifier key (`verifier.Rotate`); every state pull also installs the key its `signing_key` block carries (`verifier.Install`) |

**Contract** types are emitted by the control plane today. **Documented-coming**
types are named so the agent can subscribe once the platform's 14-type taxonomy
starts emitting them.

## See Also

- [Architecture](guide/architecture.md) — High-level architecture diagrams, platform support
- [Agent Lifecycle](guide/agent-lifecycle.md) — Lifecycle phases, operational behavior, deregistration
- [Configuration Reference](reference/core/configuration.md) — Full YAML configuration schema
- [CLI Reference](reference/core/cli.md) — Command-line interface and subcommands
- [Environment Variables Reference](reference/core/environment-variables.md) — All `PLEXD_*` overrides
