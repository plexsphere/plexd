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

![The initialization of plexd up runs in six groups, each step after the one before it. Config and pre-flight: parse the config, set up the logger, then build the policy enforcer and pre-flight the firewall. Registration: create the control plane client, start the health listener, register the node, create the Ed25519 verifier. Networking: initialize WireGuard, bind the mesh DNS resolver, initialize NAT and peer exchange, install the firewall baseline, initialize the tunnel and, in bridge mode only, the bridge. Core services: create the SSE manager, the reconciler and the heartbeat service. Actions and node API: create the integrity store and verifier, then the action executor with the rollout installer, the capability reporter and the hook watchers, then the node API server. Observability: create the metrics collectors, the log forwarder and the audit forwarder. Last, plexd launches the goroutines via a WaitGroup.](./diagrams/architecture-startup-sequence.svg)

1. **Parse config** — read YAML, apply CLI flag overrides, apply `PLEXD_*` env overrides
2. **Set up logger** — structured `slog` logger with configured level
2a. **Build the policy enforcer and pre-flight the firewall** — `policy.NewPolicyEngine()`, the platform's firewall controller and `policy.NewEnforcer()`, then `enforcer.Preflight()`, before anything reaches the control plane. A failure ends `plexd up` with `plexd up: firewall baseline pre-flight: ...`, so a node that cannot install a chain exits before it spends a redemption of its bootstrap token (see [Network Policy Enforcement](reference/networking/network-policy.md))
2b. **Check the local endpoints' CA files**: `preflightLocalEndpointTLS()` loads the `tls_ca_file` of every local endpoint that sets a `url`, before anything reaches the control plane. A file that cannot be read or holds no certificate, or one set beside `tls_insecure_skip_verify`, ends `plexd up` with `plexd up: <section>.local_endpoint: ...`, so the start stops before it spends a redemption of the bootstrap token (see [CA bundle](reference/core/configuration.md#ca-bundle))
3. **Create control plane client** — `api.NewControlPlane()` with API config and build version
4. **Register** — build the registrar, start the health listener (step 4a), and only then call `registrar.Register()`, which loads or creates node identity (fatal on failure)
4a. **Start the health listener** — unless `health.enabled` is `false`, `health.NewServer()` builds the listener, its `Listen()` binds `health.listen`, and it serves `/healthz` and `/readyz` in a goroutine before the registration call, so a probe during a slow first registration gets 200 and 503 instead of a refused connection. A failed bind ends `plexd up` with `plexd up: health listener cannot bind <listen> (port already in use on the host network?)`. The listener is marked registered after step 4 and, when WireGuard came up, ready for the data plane after step 5c (see [health](reference/core/configuration.md#health) and [Health checks](how-to/kubernetes-deployment.md#health-checks))
5. **Create Ed25519 verifier** — decode the control plane's signing public key from identity (the key registration returned, or a newer one a state pull carried and the agent persisted); `signingKeyDispatchHandler`, registered first among the reconcile [dispatch handlers](reference/core/reconciliation.md#registered-dispatch-handlers), installs the key every state pull carries. `meshAddressDispatchHandler`, registered right after it, applies the mesh address every state pull carries as `mesh_ip`: a changed address replaces the one on the mesh interface in place, the resolver, the tcp session listeners and the bridge's copies follow it, and plexd persists it into `identity.json`, so a restart starts from it (see [Mesh address changes](reference/networking/wireguard.md#mesh-address-changes))
5a. **Initialize WireGuard** — measure the uplink's path MTU with the STUN servers, create WireGuard interface, configure address and MTU, clamp the MSS of forwarded TCP, bring interface up. The interface MTU is sized to the uplink unless `wireguard.mtu` pins it or `nat.enabled` is false (see [MTU detection](reference/networking/wireguard.md#mtu-detection)). The MSS of the TCP the node forwards across the mesh interface is clamped to the mesh MTU minus 40, in both directions, and a clamp that fails is logged and does not stop the start (see [Forwarded TCP](reference/networking/wireguard.md#forwarded-tcp)). Then build the route controller once and, when the interface came up, hand it to the WireGuard manager, which routes the networks of each peer's `routed_subnets` through the mesh interface on every node (see [Routed subnets](reference/networking/wireguard.md#routed-subnets)); bridge mode drives the same controller
5a-1. **Edge PSKs** — with the interface up and unless `wireguard.edge_psk` turns it off, build the edge PSK store with `wireguard.NewEdgePSKs()` over the client, the node ID and the NSK. It logs `edge psk disabled by wireguard.edge_psk` or `edge psk disabled, the node secret key does not decode` when it builds none
5a-2. **Local endpoint candidates** — with the interface up, build the `nat.CandidateFilter` from `nat.candidate_interfaces`, without the mesh interface and the mesh prefix, which `wgMgr.SetLocalPrefixes()` and the candidate publisher of step 24a read through (see [CandidatePublisher](reference/networking/nat-traversal.md#candidatepublisher))
5a-3. **Bind the mesh DNS resolver** — on Linux, macOS and Windows, with `dns.enabled` on, WireGuard up and a mesh IP that parses, `meshdns.NewManager()` and `mgr.Start()` bind the resolver's sockets, and step 25a serves them. A start that runs no resolver reverts the host's registration and goes on: nothing in this step ends `plexd up` (see [Startup in `plexd up`](reference/networking/mesh-dns.md#startup-in-plexd-up))
5b. **Initialize NAT + Peer Exchange** — create STUN client, NAT discoverer, and peer exchanger
5c. **Install the firewall baseline** — `enforcer.ApplyFirewallRules(nil, <mesh interface>)` installs the deny-by-default chain before the first policy arrives, and a failure ends `plexd up` with `plexd up: install deny-by-default firewall baseline: ...`. When policy is on and WireGuard setup failed, the baseline is installed only if an interface under the mesh name carries the node's mesh IP; otherwise plexd logs the Warn `no interface carries the mesh address under the mesh name, skipping the firewall baseline`. When the interface table cannot be read at all, `plexd up` ends with `plexd up: resolve the mesh interface for the firewall baseline: ...`
5d. **Initialize Tunnel** — load/generate host key, create JWT verifier and mesh server
5e. **Initialize Bridge** (bridge mode only) — create the bridge manager over the route controller of step 5a and run its Setup, and when the configuration still sets one of the replaced user access keys, or one of the replaced site-to-site keys, log one Warn per group that names them. Unless `bridge.ingress_enabled`, `bridge.user_access_enabled` and `bridge.site_to_site_enabled` are all `false`, read the node secret key for `nodeSecretFetcher` (`cmd/plexd/cmd/node_secrets.go`), the fetch of the Secrets the three managers read (an error fails `plexd up`). Unless `bridge.ingress_enabled` is `false`, create the ACME manager over the cache directory (`bridge.acme_cache_dir`, or `<data_dir>/acme`), create the ingress manager with it and the fetcher, and run the ingress manager's Setup. With `bridge.ingress_enabled: false`, create neither manager and log `public ingress: opted out by bridge.ingress_enabled, no public listener is opened` (see [Activation](reference/bridge/public-ingress.md#activation)). The ACME manager has no Setup and starts without an account: `IngressManager.Apply` configures it from the state pull's `bridge.ingress` block (see [ACME and SNI Routing](reference/bridge/acme-sni.md#acmemanager)). Unless `bridge.user_access_enabled` is `false`, create the user access manager with the fetcher, a key store over `<data_dir>/user-access` and the Tailscale and NetBird clients, and run its Setup, which removes the provider interfaces and source rewrites a killed process left behind (an error fails `plexd up`). With `bridge.user_access_enabled: false`, create no user access manager, remove those leftovers once, and log `user access: opted out by bridge.user_access_enabled, no provider is served` (see [Activation](reference/bridge/user-access-integration.md#activation)). Unless `bridge.site_to_site_enabled` is `false`, create the site-to-site manager with the fetcher, a key store over `<data_dir>/site-to-site`, the VPN controller, and the `ipsec` and `openvpn` providers, the first over `bridge.swanctl_conf_dir` (or `<run dir>/swanctl`), and run its Setup, which removes the tunnel interfaces and provider files a killed process left behind (an error fails `plexd up`). With `bridge.site_to_site_enabled: false`, create no site-to-site manager, remove those leftovers once with the same controller and providers (an error is logged and does not stop the start), and log `site-to-site: opted out by bridge.site_to_site_enabled, no tunnel is served` (see [Site-to-Site VPN](reference/bridge/site-to-site-vpn.md))
6. **Create SSE manager** — `api.NewSSEManager()` with handlers for signing key rotation, WireGuard peer events, tunnel events, policy events, and bridge events (bridge mode)
7. **Create reconciler** — `reconcile.NewReconciler()` with handlers for WireGuard, policy, and bridge reconciliation
8. **Create heartbeat service** — `agent.NewHeartbeatService()` with subsystem status enrichment and key-rotation callback; its credential-refused callback is set in step 12, once the node API server exists
9. **Create integrity store + verifier** — `integrity.NewStore()` and `integrity.NewVerifier()`, for the hook checksums the executor verifies before a run and for the baseline checks of the binary, the hooks directory and the SSH host key that step 20c runs. With integrity enabled and `integrity.binary_path` empty, `integrity.SelfPath()` first sets it to the running executable with symlinks resolved; an error fails `plexd up`
10. **Create action executor** — `actions.NewExecutor()`, register 11 built-in actions, build the rollout installer with `actions.NewRolloutInstaller()` (a constructor error logs `rolled-out hooks disabled`, and the agent runs on without rolled-out hooks), register the installer's `Handle`, when it was built, and then `actions.NewDispatcher()` on the reconciler as dispatch handlers, list the `PlexdHook` resources in a pod's namespace, and build `agent.NewCapabilityReporter()`, which sends nothing until it starts. In a pod, `newPlexdHookRunner()` also builds the PlexdHook runner, which runs a dispatched `PlexdHook` as a Kubernetes Job, and `executor.SetPlexdHookRunner()` hands it over before the reconciler starts. An empty ServiceAccount namespace, an unset `MY_NODE_NAME`, or a Job client that cannot be built logs a `plexd hook runs disabled` warning instead, and the node runs no PlexdHook (see [Kubernetes Deployment](reference/deployment/kubernetes-deployment.md#wiring-in-plexd-up))
11. **Create hook watchers** — `actions.NewHookWatcher()` for `hooks_dir`, with an `onChange` that calls `executor.SetHooks()` and then the reporter's `Notify()`, and, when the installer was built and `actions.rollouts_enabled` is not `false`, `actions.NewRolloutHookWatcher()` for the rollout directory `<data_dir>/hooks`, whose `onChange` calls `executor.SetRolloutHooks()` and `Notify()`. plexd then runs the installer's `Load()`, which restores the rolled-out hooks from `hook_rollouts.json`, pins each to the checksum it was delivered with, and removes every other file of the rollout directory. It then runs one first scan over both directories with `hookDirsReloader.Reload()` and waits for it, for at most 10 seconds, so the executor's hook list is filled before anything reads it and the boot manifest carries the hooks on disk
12. **Create node API server** — `nodeapi.NewServer()`, wire action provider, hook reloader (the same `hookDirsReloader`, so `POST /v1/hooks/reload` rescans both directories), and reconcile handler
13. **Create metrics collectors + manager** — system collector, agent stats collector, `metrics.NewManager()`
14. **Create log sources + forwarder** — platform log source (journald on Linux, the launchd log file on macOS, the Event Log on Windows), file sources from `file_patterns`, `logfwd.NewForwarder()`
15. **Create audit sources + forwarder** — process source, `auditfwd.NewForwarder()`

**Goroutines:**

`plexd up` starts these goroutines under one `sync.WaitGroup`. The health listener starts at step 4a, before the registration call; the others start after step 15, in the order of their steps:

| Step | Goroutine | Call | Started when | What it does |
|------|-----------|------|--------------|--------------|
| 4a | Health Listener | `healthSrv.Serve()` | `health.enabled` is not `false` | serves `/healthz` and `/readyz`. When it stops while plexd runs, plexd logs `health listener stopped, terminating` and cancels the context, which starts the shutdown |
| 16 | SSE Manager | `sseMgr.Start()` | always | event stream connection |
| 17 | Heartbeat | `heartbeat.Run()` | always | periodic heartbeats |
| 17a | Handshake Reporter | `handshakeReporter.Run()` | WireGuard is up | sends one handshake report per heartbeat interval (see [Handshake Reporter](reference/core/heartbeat-service.md#handshake-reporter)) |
| 17b | Endpoint Selection | `wgMgr.RunEndpointSelection()` | WireGuard is up | every 5 s (`wireguard.EndpointSelectionInterval`), or, once a pull carried the Domain's [failure-detection time](reference/networking/wireguard.md#failure-detection-time), at the pass interval that time gives (1 s at the default 15 s), tries each peer's dial order until a handshake completes, and probes the relay paths of relayed peers: a path that fell silent on a node that holds no failure-detection time, and every relay path on each pass on a node that holds one; on such a node it also watches the paths to the bridges of the pull's shared subnets and moves a subnet off a bridge whose path died (see [Endpoint selection](reference/networking/wireguard.md#endpoint-selection) and [Shared subnets](reference/networking/wireguard.md#shared-subnets)) |
| 17c | Mesh MTU Re-probe | `wgMgr.RunMTUProbe()` | WireGuard is up | measures the uplink again every 10 minutes (`wireguard.MTUProbeInterval`) (see [Probing again](reference/networking/wireguard.md#probing-again)) |
| 17d | Relay, Ingress, User Access and Site-to-Site Status Reporters (four goroutines) | `relayStatusReporter.Run()`, `ingressStatusReporter.Run()`, `userAccessStatusReporter.Run()`, `siteToSiteStatusReporter.Run()` | bridge mode | the relay status reporter reports the relay's state at the heartbeat interval and sends a last stopped report at shutdown, bounded by 5 s (see [Relay Status Report](reference/bridge/nat-relay.md#relay-status-report)). The ingress, user access and site-to-site status reporters each report whether the bridge opts out of their feature and, unless it does, the state of each ingress rule, provider or tunnel: once at start, on a change at most once per 5 s, and at the heartbeat interval. They send nothing at shutdown (see [Ingress Status Report](reference/bridge/public-ingress.md#ingress-status-report), [User Access Status Report](reference/bridge/user-access-integration.md#user-access-status-report) and [Site-to-Site Status Report](reference/bridge/site-to-site-vpn.md#site-to-site-status-report)) |
| 17e | Policy Status Reporter | `policyStatusReporter.Run()` | always | reports what the node applied, rejected or enforces on every change, and at the heartbeat interval when the drop counters moved or the last send failed (see [Policy status report](reference/networking/network-policy.md#policy-status-report)) |
| 17f | Round-trip Probe | `wgMgr.RunRTTProbe()` | WireGuard is up | once per heartbeat interval sends one probe to UDP port 7911 of each peer with a fresh handshake, answers the peers' probes on the same port of the mesh address, and keeps the latest round-trip time per peer, which the handshake report of step 17a sends as `rtt_microseconds` (see [Round-trip probe](reference/networking/wireguard.md#round-trip-probe)) |
| 18 | Reconciler | `reconciler.Run()` | always | periodic state reconciliation |
| after 18 | Key Rotation Recovery | `rotator.RecoverPending()` | always | resubmits a staged key the control plane has not confirmed, with a capped backoff, and makes no call while nothing is staged (see [Rotation](reference/core/key-storage.md#rotation)) |
| 19 | Node API | `nodeAPISrv.Start()` | always | local endpoint (a Unix socket, or a named pipe on Windows) + optional HTTP server |
| 19a | Status Report Publisher | `statusReports.run()` | always | publishes `status.mesh`, `status.bridge`, `status.user-access`, `status.ingress` and `status.site-to-site` as state reports through the node API, once at start and then at the heartbeat interval, each only when its payload changed |
| 20 | Hook Watcher, Rollout Hook Watcher, Rollout Installer (three goroutines) | `hookWatcher.Watch()`, `rolloutWatcher.Watch()`, `rolloutInstaller.Run()` | always; the watcher and the installer of rollouts only when built | Hook Watcher: filesystem watching for hook changes in `hooks_dir`. Rollout Hook Watcher: filesystem watching of the rollout directory; started only when that watcher was built. Rollout Installer: one pass per `hooks` block the reconciler hands over: fetch, verify, install, and remove rolled-out hooks; started only when the installer was built |
| 20a | Capability Reporter | `capabilityReporter.Run()` | always | sends the boot manifest, reports each hook or `PlexdHook` change and each change to the rollout errors, and retries a failed send |
| 20b | PlexdHook Inventory | `plexdHooks.run()` | always | watches the `PlexdHook` resources in a pod's namespace; returns at once outside a cluster |
| 20c | Integrity Verifier | `integrityVerifier.Run()` | always | checks the binary, `integrity.hooks_dir` and the SSH host key against their baselines once at start and then every `integrity.verify_interval`, reports each change once and then adopts it as the baseline; returns at once when `integrity.enabled` is `false` (see [Integrity Verification](reference/actions/integrity-verification.md#startup-sequence)) |
| 21 | Metrics Manager | `metricsMgr.Run()` | always | collect and report metrics |
| 22 | Log Forwarder | `logForwarder.Run()` | always | collect and forward logs |
| 22a | Connection Log Summary | `enforcer.ConnLogger().Run()` | always | once a minute logs how many connection lines the rate limit dropped and how many records the firewall's reader lost (see [ConnLogger](reference/networking/network-policy.md#connlogger)) |
| 23 | Audit Forwarder | `auditForwarder.Run()` | always | collect and forward audit events |
| 24 | Peer Exchange | `exchanger.Run()` | always | STUN discovery and endpoint exchange loop |
| 24a | Endpoint Candidate Publisher | `candidatePublisher.Run()` | WireGuard is up and `nat.local_candidates` is not `false` | publishes the node's local interface addresses as endpoint candidates (see [CandidatePublisher](reference/networking/nat-traversal.md#candidatepublisher)) |
| 25 | Mesh Server | `meshServer.Start()` | always | tunnel SSH server |
| 25a | Mesh DNS Resolver | `serveMeshDNS()` | step 5a-3 bound the sockets | answers the mesh names on the sockets of step 5a-3. When it stops while plexd runs, plexd logs `mesh dns stopped` and reverts the registration at once (see [Stop, Crash and Opt-Out](reference/networking/mesh-dns.md#stop-crash-and-opt-out)) |

The bridge's NAT relay is not a startup goroutine. In bridge mode with `bridge.relay_enabled` set, the reconciler's `RelayReconcileHandler` starts it on the first cycle whose state pull enables it, and stops it when a pull disables it or the bridge tears down (see [NAT Relay](reference/bridge/nat-relay.md#relayreconcilehandler)).

In bridge mode `plexd up` also starts the ingress status reporter, whether or not the bridge opts out of public ingress. It sends `PUT /v1/nodes/{node_id}/ingress-status` once at start, on every change of an ingress rule's listener, certificate or last dial, of the outcome or reason of the last dial to one of its targets, or of whether the bridge enforces a rule's `client_auth` (`client_auth_enforced`), at most once per 5 s, and once per `heartbeat.interval`, with `opted_out` when `bridge.ingress_enabled` is `false`, and otherwise `enabled` with one entry per ingress rule. A client the bridge refuses for a rule's `client_auth` sends nothing alone: its refusal rides the next report, at the latest one `heartbeat.interval` later. It ends with the context, without a report at shutdown (see [Ingress Status Report](reference/bridge/public-ingress.md#ingress-status-report)). Beside it, and beside the user access status reporter, `plexd up` starts the site-to-site status reporter for every bridge, with no tunnel source when `bridge.site_to_site_enabled` is `false`. It sends `PUT /v1/nodes/{node_id}/site-to-site-status` once at start, on every change of a tunnel's `health`, `reason`, `public_key` or `established` at most once per 5 s, and once per `heartbeat.interval`, with `opted_out` when the bridge opts out, and otherwise `enabled` with one entry per tunnel; it too sends nothing at shutdown (see [Site-to-Site VPN](reference/bridge/site-to-site-vpn.md)).

## Shutdown Sequence

On SIGTERM or SIGINT:

![SIGTERM or SIGINT cancels the context. Then, one after the other, the mesh DNS registration is reverted if the resolver runs, the SSE manager shuts down, the running actions are cancelled and drained, and the mesh server shuts down. In bridge mode the bridge teardown comes next: the ingress, user access, site-to-site, ACME and bridge teardowns, in that order. Then the firewall and WireGuard are torn down, and plexd waits for its goroutines for at most 30 seconds. When all have exited, it returns nil and exits with 0. After 30 seconds it logs the warning drain timeout exceeded, forcing exit, and then returns nil and exits with 0 as well.](./diagrams/architecture-shutdown-sequence.svg)

1. **Context cancel** — the signal-notify context is cancelled, which signals all goroutines to stop, and plexd logs `shutting down`
2. **`dnsMgr.Shutdown()`** — revert the mesh DNS registration within 5 s (`meshDNSRegistrarTimeout`), only when step 5a-3 started a resolver. It goes first because the resolver stopped answering when the context ended, and because the mesh interface still exists. An error logs `mesh dns shutdown error` (see [Stop, Crash and Opt-Out](reference/networking/mesh-dns.md#stop-crash-and-opt-out))
3. **`sseMgr.Shutdown()`** — close the SSE connection
4. **`executor.Shutdown()`** — runs after the SSE shutdown returned: cancel the running actions, refuse new ones, and wait until they have ended
5. **`meshServer.Shutdown()`** — stop tunnel SSH server and drain sessions
6. **`ingressMgr.Teardown()`** — close ingress listeners (bridge mode, unless `bridge.ingress_enabled` is `false`)
7. **`userAccessMgr.Teardown()`** — stop the vendor clients and remove the provider interfaces and their source rewrites, keeping the key files (bridge mode, unless `bridge.user_access_enabled` is `false`)
8. **`s2sMgr.Teardown()`** — remove every tunnel: stop its `openvpn` process or unload its strongSwan connection, and remove its routes, its source rewrite and its interface, keeping the key files (bridge mode, unless `bridge.site_to_site_enabled` is `false`)
9. **`acmeMgr.Teardown()`** — retire the ACME account and wait at most 10 s for its certificate requests in flight (bridge mode, unless `bridge.ingress_enabled` is `false`; see [Teardown](reference/bridge/acme-sni.md#teardown))
10. **`bridgeMgr.Teardown()`** — remove bridge routes and forwarding (bridge mode)
11. **`enforcer.Teardown()`** — remove firewall chains and rules
12. **`wgMgr.Teardown()`** — remove the MSS clamp of forwarded TCP when one is programmed, then the routes of the peers' routed subnets, then delete the WireGuard interface (last, others depend on it); skipped on a platform without a WireGuard controller
13. **`wg.Wait()` for at most 30 s** — wait for all goroutines to exit (`drainTimeout`). When they have not all exited by then, plexd logs the Warn `drain timeout exceeded, forcing exit`. In both cases it logs `plexd stopped`, and `plexd up` returns nil and exits with 0. There is no separate forced exit

## Authentication Flow

1. **Bootstrap** — node registers using a bootstrap token (file, env var, or metadata service)
2. **Node Secret Key** — registration returns the NSK. plexd builds the bearer envelope from it and the node ID and presents that envelope, never the NSK itself, on every later API call (see [BearerToken](reference/core/registration.md#bearertoken))
3. **Heartbeat Auth** — each heartbeat presents the bearer envelope; three heartbeats answered 401 Unauthorized (`unauthorized`, `nsk_invalid` or `nsk_revoked`) with no accepted one between them park the agent, which then stops calling the control plane and probes the credential with the heartbeat (see [Credential Park](reference/core/heartbeat-service.md#credential-park))
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
| `peer_endpoint_changed` | contract | Triggers a reconcile |
| `peer_registered` | documented-coming | Triggers a reconcile |
| `peer_psk_assigned` | documented-coming | Triggers a reconcile |
| `peer_deregistered` | documented-coming | Triggers a reconcile |
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
