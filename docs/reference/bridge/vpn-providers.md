---
title: VPN Providers
package: internal/bridge
feature: PXD-0028
---

# VPN Providers

A `tailscale` or `netbird` user access provider joins the bridge to that vendor's network with the vendor's client, so the users of that network reach the nodes of the bridge's Domain through the bridge. This page covers the two clients, the key they join with and how plexd runs them. The `bridge.user_access` block, the checks, the reasons, the retry and the status report are on [User Access Integration](user-access-integration.md).

A Linux bridge, a macOS bridge and a Windows bridge serve both kinds. On Windows a client's interface takes no rewrite: it is no device of the plexd process, and by the vendors' documentation the client's traffic already carries the bridge's mesh address (see [Windows](user-access-integration.md#windows)). No real client of either kind has run on any platform, macOS and Windows included (see [Testing](#testing)).

## Data Flow

![Users of a tailnet or a NetBird network reach the bridge node over the vendor's overlay network and arrive on the client's interface, such as tailscale0 or wt0. Forwarding with a source rewrite carries their traffic to the mesh WireGuard interface plexd0, which exchanges it with the mesh peers in 10.42.0.0/16. The UserAccessClient for Tailscale or NetBird creates the client's interface; a line joins it to the CommandExecutor, which runs the tailscale and netbird commands. The UserAccessManager calls Start and Stop on the UserAccessClient. The nodeSecretFetcher fetches the Secret's value from the control plane and hands the join key to the UserAccessManager.](../../diagrams/bridge-vpn-providers-data-flow.svg)

The vendor's users reach the bridge through the vendor's network and arrive on the client's interface: for Tailscale the interface that carries the client's address, `tailscale0` on Linux and a `utunN` on macOS, and for NetBird the interface `netbird status --json` names, such as `wt0`. The bridge forwards between that interface and `plexd0` and rewrites the source of what it forwards into the mesh to its own mesh address, as for every kind (see [Policy and Device Traffic](user-access-integration.md#policy-and-device-traffic)). `UserAccessManager` fetches the key from the Secret the provider names and starts the client with it. The client runs its commands through a `CommandExecutor`.

## The Join Key

A provider's `auth_secret_name` names a Secret of the bridge's Project that holds the key the client joins with as plain text: a Tailscale auth key or a NetBird setup key. The bridge reads it in the version its secret inventory lists, the pull's `secrets` block, which `UserAccessPullHandler` hands to the manager on every successful pull (see [Retry](user-access-integration.md#retry)):

1. The inventory does not list the name: `auth_secret_not_listed`. A name the inventory does not list is a Secret the bridge may not read. The control plane checks the read grant when the provider is written, but a grant revoked or a Secret deleted later leaves the provider in the block.
2. The fetch of that version fails: `auth_secret_unreadable`.
3. Otherwise the manager trims white space from both ends of the value and starts the client with it.

The fetch is `nodeSecretFetcher.FetchSecretValue(ctx, name, version)` in `cmd/plexd/cmd/node_secrets.go`. It fetches the sealed envelope of that version with `ControlPlane.FetchSecret`, which sends `GET /v1/nodes/{node_id}/secrets/{name}` with the node's own credential, refuses an envelope of another version, and opens it under the node secret key with `nodeapi.DecryptSecret` (see [GET /v1/nodes/{node_id}/secrets/{key}](../core/api-endpoints.md#get-v1-nodes-node-id-secrets)). The same fetcher reads the certificates of `terminate` ingress rules through `FetchCertificateSecret` (see [Certificates from the Secret Store](public-ingress.md#certificates-from-the-secret-store)). Step 5e of `plexd up` builds it once, in bridge mode, before the ingress, the user access and the site-to-site managers, and only when one of them is built: it reads the node secret key with `identity.SecretKey()`, and an error fails `plexd up` as `plexd up: <error>`. A bridge that opts out of all three reads no node secret key.

| Case | Error |
|---|---|
| `FetchSecret` fails | `fetch secret "<name>" version <v>: <error>`, wrapping the error, such as an `*api.APIError` |
| The envelope holds another version | `fetch secret "<name>": asked for version <v>, got <w>` |
| The envelope does not open under the node secret key | `decrypt secret "<name>" version <v>: <error>` |

A failed fetch is retried like every `auth_secret_unreadable`, after 5 s doubling to 60 s, or after the `Retry-After` of a `429` answer when that is longer. No log line and no error carries the key.

A client that runs keeps its join when the inventory lists a new version of its Secret or stops listing it: the manager reads the inventory only at a join, and the next join, after a restart, a changed `auth_secret_name` or a retry, uses the version listed then.

### The Key on the Command Line

Both clients take the key as an argument: `tailscale up --authkey=<key>` and `netbird up --setup-key <key>`. While the join command runs, at most 60 s, the key is on that process's command line, which other processes of the host can read in the process list. plexd logs neither the key nor the command line, and keeps the key out of its errors.

## UserAccessClient

Interface for the vendor clients, named apart from the control plane's `api.UserAccessProvider`, the provider of the block:

```go
type UserAccessClient interface {
    Name() string
    Start(ctx context.Context, key string, meshCIDR string) error
    Stop() error
    Status() ProviderStatus
}
```

| Method | Description |
|---|---|
| `Name` | The client's identifier, `"tailscale"` or `"netbird"` |
| `Start` | Joins the vendor's network with `key`. An empty key is refused before any command runs. `meshCIDR` is the route a client advertises where its vendor lets it; a client whose vendor defines routes elsewhere ignores it. A daemon the client starts runs under `ctx` and ends with it; the join commands run under a timeout of 60 s derived from `ctx`. An error of the executor stays wrapped, so `errors.Is(err, exec.ErrNotFound)` tells a missing executable |
| `Stop` | Leaves the network and stops what the client started; idempotent when not running |
| `Status` | The client's state: `Running`, `InterfaceName`, `IP` |

All methods are safe for concurrent use. The manager calls `Start` with the context its `Setup` creates and its `Teardown` cancels, not with the context of a reconcile cycle, so a daemon outlives the cycle that started it.

```go
type ProviderStatus struct {
    Running       bool   `json:"running"`
    InterfaceName string `json:"interface_name,omitempty"`
    IP            string `json:"ip,omitempty"`
    Error         string `json:"error,omitempty"`
}
```

### How the Manager Runs a Client

`UserAccessDeps.Clients` holds one client per vendor kind; a kind without a client reads `kind_not_served`. A bridge holds at most one `tailscale` and one `netbird` provider, because one host runs one client of each: a second provider of the same kind reads `invalid_provider`. `plexd up` builds `NewTailscaleProvider` and `NewNetbirdProvider`, each over its own `NewStdCommandExecutor()`.

1. The manager starts the client with the key and the Domain mesh CIDR. A start error that wraps `exec.ErrNotFound` reads `client_missing`, any other `join_failed`.
2. It reads the client's interface from `Status().InterfaceName`. An empty name stops the client and reads `join_failed`.
3. It switches forwarding on between `plexd0` and that interface and adds the source rewrite for it. An error stops the client and reads `setup_failed`.

The provider is then up, and its report entry carries `id` and `health` alone: the vendor's network manages its own keys and devices. A provider that leaves the block, or whose `auth_secret_name` changes, has its client stopped and its source rewrite removed; a changed `auth_secret_name` then starts the client again with the key of the new Secret. `Teardown` stops every client and cancels the context the daemons run under.

## TailscaleProvider

- **File**: `internal/bridge/tailscale.go`
- **Name**: `"tailscale"`
- **Interface name**: the first interface of the host that carries the client's address, read with `net.Interfaces`, and `"tailscale0"` when none carries it or the client lists no address. `tailscaled` names its interface `tailscale0` on Linux and runs on a `utunN` on macOS, and the client reports neither
- **Concurrency**: `sync.Mutex` protects `running`, `ip`, `ifaceName`, `daemonHandle`

```go
func NewTailscaleProvider(exec CommandExecutor, logger *slog.Logger) *TailscaleProvider
```

### Start Sequence

1. Refuse an empty key: `bridge: tailscale: auth key is empty`.
2. Start `tailscaled --state=mem:` with `CommandExecutor.Start` under `ctx`, the manager's context. The daemon runs until `Stop` or until the context ends.
3. Run `tailscale up --authkey=<key> --accept-routes --advertise-routes=<mesh CIDR>` with `CommandExecutor.Run`.
4. Run `tailscale status --json`.
5. Take the first entry of `TailscaleIPs` from the JSON as the client's IP. Take as the interface name that of the first interface that carries the IP, or `tailscale0` when none carries it or `TailscaleIPs` is empty, and mark the client running.

Steps 3 and 4 share one timeout of 60 s derived from `ctx`. A failure rolls back what the earlier steps started:

| Failure | Rollback |
|---|---|
| `tailscale up` fails | Stop the daemon |
| `tailscale status` fails | Run `tailscale down`, stop the daemon |
| The JSON does not parse | Run `tailscale down`, stop the daemon |

`tailscale down` in a rollback runs under the same timeout, so once the timeout has run out it fails at once, and stopping the daemon ends the session.

### Stop Sequence

1. Run `tailscale down`, without a timeout. A failure is logged and does not stop the next step.
2. Stop the daemon: `CommandHandle.Stop` kills the process. A failure is logged.
3. Clear `running`, `ip` and `ifaceName`.

`Stop` returns nil, also after a logged failure, and does nothing when the client does not run.

### The Advertised Route

`tailscale up` advertises the Domain mesh CIDR, `UserAccessDeps.MeshCIDR`, as a route, so the tailnet reaches the mesh through the bridge. `plexd up` sets it to the Domain mesh prefix, masked to its network. When the node has no Domain mesh CIDR, or only the `/32` of its own mesh address, the CIDR is empty and a `tailscale` provider reads `setup_failed` before the inventory is read and before any command runs: the client would join a tailnet that cannot reach the mesh. The CIDR is read once at start, so such a provider stays down until a restart finds one.

### A Reusable Auth Key

`tailscaled` keeps its state in memory (`--state=mem:`), so the client keeps no state across its starts: every join logs in with the auth key again, after a restart of plexd, after a changed `auth_secret_name`, and on a retry after a failed join. The auth key in the Secret must therefore be reusable. A key that Tailscale accepts once serves the first join only.

## NetbirdProvider

- **File**: `internal/bridge/netbird.go`
- **Name**: `"netbird"`
- **Interface name**: the member `interface.name` of `netbird status --json`, such as `"wt0"`
- **Concurrency**: `sync.Mutex` protects `status`

```go
func NewNetbirdProvider(exec CommandExecutor, logger *slog.Logger) *NetbirdProvider
```

### Start Sequence

1. Refuse an empty key: `bridge: netbird: setup key is empty`.
2. Log `starting netbird provider` with the key's length, `setup_key_len`.
3. Run `netbird up --setup-key <key>` with `CommandExecutor.Run`.
4. Run `netbird status --json`.
5. Take `ip`, without a CIDR suffix (`"100.119.0.1/16"` becomes `"100.119.0.1"`), and `interface.name` from the JSON, and mark the client running.

Steps 3 and 4 share one timeout of 60 s derived from `ctx`. plexd starts no NetBird daemon of its own. A failed `netbird status`, or JSON that does not parse, leaves the client as `netbird up` left it: no `netbird down` runs, and the client does not count as running, so the next `Stop` does nothing. The retry runs `netbird up` again.

### Stop Sequence

1. Run `netbird down`, without a timeout. A failure returns `bridge: netbird: down failed: <error>` and keeps the status.
2. Clear the status.

`Stop` does nothing when the client does not run. A failed `netbird down` during `Teardown` is part of `Teardown`'s error, and the source rewrite is removed all the same.

### The Route of a netbird Provider

The route of a `netbird` provider is defined by the operator in NetBird's management service, with the bridge as routing peer: a NetBird client cannot advertise a route, so `NetbirdProvider.Start` ignores the mesh CIDR and plexd advertises nothing. The NetBird network reaches the Domain mesh through the bridge only once that route exists. This deviates from the control plane's agent contract, whose section "User access" says that a `tailscale` or `netbird` provider advertises the Domain mesh CIDR as a route. A `netbird` provider needs no Domain mesh CIDR on the bridge, so it never reads `setup_failed` for a missing one.

## CommandExecutor

Shared abstraction for running the vendor's commands, so a test runs a client without its executables:

```go
type CommandExecutor interface {
    Run(ctx context.Context, name string, args ...string) ([]byte, error)
    Start(ctx context.Context, name string, args ...string) (CommandHandle, error)
}

type CommandHandle interface {
    Stop() error
}
```

| Method | Description |
|---|---|
| `Run` | Runs a command and returns its combined output |
| `Start` | Starts a command without waiting for it; returns a handle to stop it |
| `CommandHandle.Stop` | Kills the process |

`StdCommandExecutor` (`exec_std.go`) implements it with `exec.CommandContext`, which kills a process when its context ends. A command is named without a path, so its executable must be on the `PATH` of the plexd process. A missing executable fails with an error that wraps `exec.ErrNotFound`, which the manager reports as `client_missing`.

## Host Requirements

The host must carry the vendor's client: `tailscaled` and `tailscale` for a `tailscale` provider, `netbird` for a `netbird` provider, each on the `PATH` of the plexd process. Whether a vendor client runs inside the sandbox of `deploy/systemd/plexd.service` is unproven, as no suite runs one.

On macOS launchd starts the daemon with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, so a client installed in any other directory is not found and its provider reads `client_missing`.

On Windows the clients are invoked by name too, from the `PATH` of the `plexd` service, so the directory of each client's executables must be on it, or the provider reads `client_missing`.

## Testing

No test suite runs a real Tailscale or NetBird client; the proof is the command stand-in. `tailscale_test.go` and `netbird_test.go` run each client over a mock `CommandExecutor` and check the exact commands and arguments, the 60 s deadline of the join commands, the refused empty key, the rollback, a missing executable, and that no log line carries the key. `tailscale_test.go` also checks the interface found by the client's address through a seam, since no interface carries the stand-in's address. `provider_integration_test.go` runs the user access manager with both clients over the stand-in, up to the forwarding and the source rewrite of the client's interface, and covers `client_missing` and a client that reports no interface. The systemd suite's user access phase serves a `tailscale` provider on a host without a Tailscale client: it proves the Secret fetch, through the change from `auth_secret_not_listed` to `client_missing`, and nothing of a join (see [Systemd E2E Test](../development/systemd-e2e-test.md#_17-user-access-through-a-bridge)). A real client would need a coordination server in the suite. No real client has run on macOS either, so whether a vendor client's traffic reaches the mesh through a macOS bridge is unproven. No real client has run on Windows either. There plexd adds no rewrite for the client's interface, and that the client's traffic carries the bridge's mesh address rests on the vendors' documentation: Tailscale's [Kernel vs. netstack subnet routing & exit nodes](https://tailscale.com/kb/1177/kernel-vs-userspace-routers), and NetBird's [Masquerade](https://docs.netbird.io/manage/networks/masquerade) and [How Routing Peers Work](https://docs.netbird.io/manage/networks/how-routing-peers-work). Whether a vendor client's traffic reaches the mesh through a Windows bridge is therefore unproven.

## Error Prefixes

| Source | Prefix |
|---|---|
| `TailscaleProvider.Start` (no key) | `bridge: tailscale: auth key is empty` |
| `TailscaleProvider.Start` (daemon) | `bridge: tailscale: start tailscaled: ` |
| `TailscaleProvider.Start` (up) | `bridge: tailscale: tailscale up: ` |
| `TailscaleProvider.Start` (status) | `bridge: tailscale: tailscale status: ` |
| `TailscaleProvider.Start` (parse) | `bridge: tailscale: parse status: ` |
| `NetbirdProvider.Start` (no key) | `bridge: netbird: setup key is empty` |
| `NetbirdProvider.Start` (up) | `bridge: netbird: up failed: ` |
| `NetbirdProvider.Start` (status) | `bridge: netbird: status failed: ` |
| `NetbirdProvider.Start` (parse) | `bridge: netbird: failed to parse status JSON: ` |
| `NetbirdProvider.Stop` (down) | `bridge: netbird: down failed: ` |
| `UserAccessManager.Teardown` (client) | `bridge: user access: stop <kind> client: ` |

The errors of the Secret fetch are listed under [The Join Key](#the-join-key).

## Logging

All log entries use `component=bridge`.

| Level | Message | Keys |
|---|---|---|
| `Info` | `tailscale provider started` | `ip`, `interface` |
| `Info` | `tailscale provider stopped` | (none) |
| `Error` | `bridge: tailscale: tailscale down failed` | `error` |
| `Error` | `bridge: tailscale: stop tailscaled failed` | `error` |
| `Info` | `starting netbird provider` | `setup_key_len` |
| `Debug` | `netbird up completed` | `output` |
| `Info` | `netbird provider started` | `ip`, `interface` |
| `Info` | `stopping netbird provider` | (none) |
| `Debug` | `netbird down completed` | `output` |

The manager's lines, `user access provider up` and `user access provider down` among them, are listed in [User Access Integration](user-access-integration.md#logging).
