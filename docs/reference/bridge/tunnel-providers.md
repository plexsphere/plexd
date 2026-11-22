---
title: Tunnel Providers
package: internal/bridge
feature: PXD-0028
---

# Tunnel Providers

An `ipsec` or `openvpn` site-to-site tunnel runs a daemon on the bridge: an `ipsec` tunnel is an IKEv2 connection of the host's strongSwan bound to an xfrm interface, an `openvpn` tunnel an OpenVPN process on a tun device. A `TunnelProvider` runs the daemon's side of one tunnel on the link the site-to-site manager created before; the manager owns the link, the routes, the forwarding and the source rewrite for every kind. This page covers the two providers, the files plexd writes, the commands it runs, what the host provides and what the remote site sets. The `bridge.site_to_site` block, the checks, the reasons, the retry and the status report are on [Site-to-Site VPN](site-to-site-vpn.md).

A Linux bridge serves both kinds. On macOS and Windows `plexd up` builds no provider, since the xfrm interface and the persistent tun device are Linux kernel features. On both a tunnel of either kind that passes its own [checks](site-to-site-vpn.md#checks) reads `kind_not_served` with the error `no <kind> provider is built in`, and one that fails them reads `invalid_tunnel`. Both providers are tested against the command stand-in only: no test suite runs strongSwan or OpenVPN (see [Testing](#testing)).

## Data Flow

![A remote site, an IKEv2 or OpenVPN peer, reaches the bridge node over IPsec (IKEv2) or OpenVPN and arrives on the tunnel's xfrm interface or tun device, xf-s2s-a0a0a0e2 or ov-s2s-a0a0a0e3. Routes, forwarding and the source rewrite carry the traffic between that link and the mesh WireGuard interface plexd0, which exchanges it with the mesh peers in 10.42.0.0/16, which route the site's networks through the bridge. The VPNController creates the xfrm interface or the tun device; a line joins it to the SiteToSiteManager, which calls CreateTunnel with the key on the IPsecProvider or OpenVPNProvider. The provider writes the tunnel files with mode 0600 under /var/run/plexd/swanctl and /run/plexd/tunnels, and runs swanctl and openvpn through the CommandExecutor, which reaches strongSwan, the host's charon, and one openvpn per tunnel.](../../diagrams/bridge-tunnel-providers-data-flow.svg)

`SiteToSiteManager` brings an `ipsec` or `openvpn` tunnel up as it does a `wireguard` one, up to the daemon (see [Bringing Up a Tunnel](site-to-site-vpn.md#bringing-up-a-tunnel)): it has the `VPNController` create the link, an xfrm interface or a tun device, switches forwarding on between the link and `plexd0`, adds the source rewrite and routes the tunnel's `allowed_subnets` into the link. It then calls the provider's `CreateTunnel` with the tunnel and the value of its Secret. The provider writes the daemon's files and runs its commands through a `CommandExecutor`. Packets between the remote site and the mesh pass the link: strongSwan binds the IPsec security associations to the xfrm interface by its interface id, and the openvpn process reads and writes the tun device.

## The Key

An `ipsec` or `openvpn` tunnel names a Secret in `auth_secret_name`, which holds its key as plain text: the IKE pre-shared key of an `ipsec` tunnel, the OpenVPN static key of an `openvpn` tunnel. The manager reads the Secret in the version the secret inventory lists, as for every kind (see [Bringing Up a Tunnel](site-to-site-vpn.md#bringing-up-a-tunnel)), trims white space from both ends of the value and hands it to the provider as `TunnelConfig.Key`. A Secret the inventory does not list reads `auth_secret_not_listed`, a failed fetch `auth_secret_unreadable`. Each provider checks the key for its own form, and a key it refuses reads `setup_failed`:

| Kind | The key must be | Refused with |
|---|---|---|
| `ipsec` | not empty; any bytes, since it is written in hex | `bridge: ipsec: tunnel <id>: the pre-shared key is empty` |
| `openvpn` | an OpenVPN static key: it holds the lines `-----BEGIN OpenVPN Static key V1-----` and `-----END OpenVPN Static key V1-----`, as `openvpn --genkey secret` writes them | `bridge: openvpn: tunnel <id>: the key is no OpenVPN static key` |

A tunnel whose Secret the inventory lists at a new version is torn down and brought up with that version: strongSwan unloads the connection and loads it again, and the openvpn process starts again (see [A New Secret Version](site-to-site-vpn.md#a-new-secret-version)).

### The Key on Disk

Unlike the vendor clients of user access, both daemons read their key from a file. The pre-shared key of an `ipsec` tunnel is in `<swanctl_conf_dir>/plexd-<id>.conf`, `/var/run/plexd/swanctl/plexd-<id>.conf` by default, and the static key of an `openvpn` tunnel in `/run/plexd/tunnels/plexd-openvpn-<id>.key`. Each file is written with mode 0600 through an atomic write, in a directory the provider creates with mode 0700; a directory that exists keeps its mode. Both directories lie under the run directory, so a reboot empties them. A file lives while its tunnel exists: the provider removes it when the tunnel is torn down, when its creation fails, and when the next start finds it left behind by a killed process. No log line and no error carries a key.

## TunnelProvider

```go
type TunnelConfig struct {
    TunnelID      string   // the tunnel's id, lower case
    InterfaceName string   // the link the manager created
    InterfaceID   uint32   // ipsec: the id of the xfrm interface
    RemoteHost    string
    RemotePort    int
    LocalSubnets  []string // the Domain mesh CIDR
    RemoteSubnets []string // allowed_subnets
    Key           string   // the Secret's value, trimmed of surrounding white space
}

type TunnelProvider interface {
    Name() string // "ipsec" or "openvpn"
    CreateTunnel(ctx context.Context, cfg TunnelConfig) error
    RemoveTunnel(ctx context.Context, tunnelID string) error
    Established(ctx context.Context, tunnelID string) (bool, error)
    Reset(ctx context.Context) error
}

func ValidateTunnelConfig(cfg TunnelConfig) error
```

| Method | Description |
|---|---|
| `Name` | The kind the provider serves, `"ipsec"` or `"openvpn"` |
| `CreateTunnel` | Brings up the daemon's side of the tunnel. A failure leaves no file of the tunnel behind. A daemon the provider starts runs under `ctx` and ends with it |
| `RemoveTunnel` | Tears the tunnel down and removes its files. Idempotent: a tunnel the provider holds no file of returns nil |
| `Established` | Whether the remote site answers. A failed read returns the error |
| `Reset` | Removes the files of every tunnel of the provider, also those a killed process left behind. A provider without any file returns nil |

Every command a provider runs gets the caller's context, and an error of the executor stays wrapped, so `errors.Is(err, exec.ErrNotFound)` tells a missing executable, which the manager reports as `client_missing`. All methods are safe for concurrent use.

`ValidateTunnelConfig` checks what a provider writes into a file, before it writes it: `TunnelID` passes `api.ValidSiteToSiteTunnelID`, `RemoteHost` matches `^[A-Za-z0-9.:-]{1,253}$`, `RemotePort` is 1 to 65535, every local and remote subnet parses as a prefix, and `InterfaceName` matches `^[a-z0-9-]{1,15}$`. So no member can carry a line break, a quote or a brace into a daemon's configuration. `Key` is left to each provider, and no error quotes it.

### How the Manager Runs a Provider

`SiteToSiteDeps.Providers` holds one provider per kind; a kind without one reads `kind_not_served`. `plexd up` builds `NewIPsecProvider` over the resolved `bridge.swanctl_conf_dir` and `NewOpenVPNProvider` over `DefaultTunnelConfigDir`, `/run/plexd/tunnels`, each over its own `NewStdCommandExecutor()`, on every platform but macOS and Windows, where `newTunnelProviders` returns none.

| Call | When | Context |
|---|---|---|
| `CreateTunnel` | The last step of bringing a tunnel up, after the link, the forwarding, the source rewrite and the routes | `ipsec`: a timeout of 30 s. `openvpn`: the manager's context, which `Setup` creates and `Teardown` cancels, because the process ends with the context it was started under |
| `RemoveTunnel` | The first step of tearing a tunnel down | A timeout of 30 s |
| `Established` | Each time the manager builds the status report, for a tunnel that is up | A timeout of 5 s |
| `Reset` | `CleanupSiteToSite`, at the start of `Setup` and once at start on a bridge that opts out | One timeout of 30 s for the cleanup |

`CreateTunnel` gets `LocalSubnets` set to the Domain mesh CIDR. An `ipsec` tunnel on a bridge without one reads `setup_failed` before its provider is called, since it has no local traffic selector; an `openvpn` tunnel needs none. A `CreateTunnel` error that wraps `exec.ErrNotFound` reads `client_missing`, any other error `setup_failed`, and the manager removes the routes, the source rewrite and the link it added.

## IPsecProvider

- **File**: `internal/bridge/ipsec.go`
- **Name**: `"ipsec"`
- **Link**: the xfrm interface `xf-s2s-<last 8 hex digits>`, whose interface id is those digits as a number
- **Concurrency**: `sync.Mutex` serialises the file writes and the loads that read them

```go
func NewIPsecProvider(exec CommandExecutor, confDir string, logger *slog.Logger) *IPsecProvider
```

### The Connection File

`CreateTunnel` writes `<confDir>/plexd-<id>.conf`, a route-based IKEv2 connection bound to the xfrm interface in both directions:

```text
connections {
    plexd-<id> {
        version = 2
        remote_addrs = <remote_host>
        remote_port = <remote_port>
        dpd_delay = 30s
        if_id_in = <interface id>
        if_id_out = <interface id>
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            plexd-<id> {
                local_ts = <Domain mesh CIDR>
                remote_ts = <allowed_subnets joined by ",">
                start_action = start
                close_action = start
                dpd_action = restart
            }
        }
    }
}
secrets {
    ike-plexd-<id> {
        secret = 0x<the key as lower-case hex>
    }
}
```

The bridge starts the connection as soon as it is loaded, starts it again when the remote site closes it, and restarts it when dead peer detection, every 30 s, finds the remote site gone. The hex form of the secret carries any key without quoting. The connection is route-based: the security associations carry the interface id, so the kernel delivers what they decrypt on the xfrm interface, where the source rewrite, which matches the interface a packet arrives on, applies. A policy-based connection would deliver it on the uplink.

The secret names no identity, so strongSwan offers it for any pair of identities. A bridge with one `ipsec` tunnel authenticates with that tunnel's key, as the measurement behind [#212](https://github.com/plexsphere/plexd/issues/212) showed. On a bridge with two or more `ipsec` tunnels whose keys differ, every connection may pick the same key, the first strongSwan loaded, and a tunnel whose remote site holds another key fails to authenticate: it stays `up` with `established` false. Telling the keys apart needs an identity in each secret, and no file with one has been measured yet.

### Commands

| Method | Commands |
|---|---|
| `CreateTunnel` | Refuses an empty key before anything is written. Writes the file, then runs `swanctl --load-all --clear --noprompt`, which loads every connection and secret of the host's `swanctl.conf`, the included files among them, and `swanctl --list-conns`, whose output must hold a line that starts with `plexd-<id>:`. A failed load removes the file and returns the error. A `--list-conns` that fails or does not list the connection removes the file, runs the load again and returns an error; for the missing line it reads `bridge: ipsec: strongSwan did not load the connection, add "include /var/run/plexd/swanctl/*.conf" to /etc/swanctl/swanctl.conf`, with the configured directory |
| `RemoveTunnel` | Removes the file, runs the load, which unloads the connection, and runs `swanctl --terminate --ike plexd-<id>`, whose result it ignores: it fails once the unload has closed the connection. Without a file it runs nothing |
| `Established` | Runs `swanctl --list-sas --ike plexd-<id> --raw`; true when the output holds both `state=ESTABLISHED`, the IKE security association, and `state=INSTALLED`, a child security association |
| `Reset` | Removes every regular file `plexd-*.conf` of the directory. When it removed one, it runs the load and one terminate per removed connection, and logs `ipsec connections of an earlier process removed`. A missing directory and a missing `swanctl` are no error |

A strongSwan daemon that does not run fails every `swanctl` call with exit status 111, so the tunnel reads `setup_failed`, and a host without `swanctl` reads `client_missing`. A `Reset` that removed a file and then fails its load for another reason than a missing `swanctl`, such as a daemon that does not run, fails `Setup` and with it the start of `plexd up`; the file is gone by then, so the next start passes.

## OpenVPNProvider

- **File**: `internal/bridge/openvpn.go`
- **Name**: `"openvpn"`
- **Link**: the persistent tun device `ov-s2s-<last 8 hex digits>`, which the manager creates before the daemon starts
- **Concurrency**: `sync.Mutex` protects the handle of each tunnel's process

```go
func NewOpenVPNProvider(exec CommandExecutor, configDir string, logger *slog.Logger) *OpenVPNProvider
```

### The Configuration File

`CreateTunnel` writes the key to `<configDir>/plexd-openvpn-<id>.key` and this file to `<configDir>/plexd-openvpn-<id>.conf`:

```text
ignore-unknown-option allow-deprecated-insecure-static-crypto
allow-deprecated-insecure-static-crypto
dev <link>
dev-type tun
persist-tun
proto udp
remote <remote_host> <remote_port>
nobind
secret <configDir>/plexd-openvpn-<id>.key
cipher AES-256-CBC
auth SHA256
ping 10
ping-restart 60
management <configDir>/plexd-openvpn-<id>.sock unix
verb 3
```

The tunnel is a point-to-point connection with a static key, on the tun device the manager created, without tunnel addresses: a route names the device itself. The contract names no cipher, and OpenVPN's default for a static key, BF-CBC, is refused by OpenSSL 3, so the file sets `cipher AES-256-CBC` and `auth SHA256`. The static key has no direction, so both ends use it the same way. `allow-deprecated-insecure-static-crypto` keeps a static key working on a release that deprecates it; OpenVPN 2.6 refuses the option alone as unknown and accepts it behind `ignore-unknown-option`. That OpenVPN 2.7 names its override so is an assumption: no 2.7 was at hand. `nobind` leaves the bridge's source port to the kernel. The process pings the remote site every 10 s and restarts the connection after 60 s of silence. Its output goes to the null device, so OpenVPN's own log lines appear nowhere; the management socket is how plexd reads its state.

### Commands

| Method | Commands |
|---|---|
| `CreateTunnel` | Refuses a key without the static key lines before anything is written, and a tunnel whose process already runs. Writes the key and the configuration, then starts `openvpn --config <configDir>/plexd-openvpn-<id>.conf` with `CommandExecutor.Start` under the manager's context. A failed write or start removes the files written before it |
| `RemoveTunnel` | Stops the process, `CommandHandle.Stop` kills it, and removes the configuration, the key and the management socket |
| `Established` | Dials the management socket with a deadline of 2 s, writes `state`, reads to the line `END`, and is true when the second comma-separated field of the last state line is `CONNECTED`. Notification lines that start with `>` are skipped, and an `ERROR:` line fails the read |
| `Reset` | Removes every file of the directory whose name starts with `plexd-openvpn-`, and logs `openvpn files of an earlier process removed` with their number. A missing directory is no error. A process of an earlier plexd is not this provider's to stop: it ends with the unit's control group, and its tun device is deleted with the tunnel links |

The state reads `CONNECTED` while the remote site answers, and `ASSIGN_IP` or `RESOLVE` while it does not. A host without `openvpn` reads `client_missing`.

## What the Report Says

A tunnel that is up reports `established`, which the provider's `Established` decides (see [Tunnel Entries](site-to-site-vpn.md#tunnel-entries)). An `ipsec` or `openvpn` entry carries no `public_key`: the daemon authenticates with the tunnel's Secret.

A daemon that exits after its start is not noticed: `CommandHandle` reports no exit, and strongSwan's daemon is the host's. The tunnel stays `up` with `established` false, since the management socket of an exited `openvpn` does not answer, and `swanctl --list-sas` shows no established security association, or fails while `charon` does not run; the operator reads `connecting`. A tunnel is brought up again when its entry or its Secret's version changes, or when plexd restarts.

## Host Requirements

plexd starts and supervises neither strongSwan's daemon nor a package installation. The host provides:

| Kind | The host's part |
|---|---|
| `ipsec` | strongSwan with `swanctl` and its daemon `charon` running, and the line `include /var/run/plexd/swanctl/*.conf` in `/etc/swanctl/swanctl.conf`, with the configured directory in place of `/var/run/plexd/swanctl` when `bridge.swanctl_conf_dir` sets one. A kernel with xfrm interfaces |
| `openvpn` | OpenVPN installed, `openvpn` on the `PATH` of the plexd process. A kernel with tun devices |
| both | A packet filter that lets the tunnel's traffic in: UDP 500 and 4500 and ESP for `ipsec`, the replies to the bridge's UDP for `openvpn`. plexd opens no port in a host firewall |

The include is what makes plexd's connections load beside the host's own: `swanctl --load-all` reads `/etc/swanctl/swanctl.conf`, and a connection the file does not reach is unloaded. Loading plexd's file alone with `swanctl --load-all --file <file>` would unload every connection the host defines, and a file in a directory the host does not include loads nothing and is missing from `--list-conns`, which is the check `CreateTunnel` makes. An include of a directory that does not exist is no error, so the line can be added before plexd first writes there. plexd writes into the run directory so that `/etc` stays read-only for the unit; the systemd unit does not change. `bridge.swanctl_conf_dir` moves the directory, and must be an absolute path (see [Activation](site-to-site-vpn.md#activation)).

Whether `swanctl` and `openvpn` run inside the sandbox of `deploy/systemd/plexd.service` is unproven, as no suite runs them. plexsphere/plexsphere-node#37 prepares NixOS bridge hosts with both packages, the include line and the packet filter.

## The Remote Site

The remote site is configured by its operator to match the files above.

| Kind | The remote site sets |
|---|---|
| `ipsec` | An IKEv2 connection authenticated on both sides with the pre-shared key the tunnel's Secret holds, answering on `remote_port` at `remote_host`. Its traffic selectors mirror the bridge's: its local selector is the tunnel's `allowed_subnets`, its remote selector the Domain mesh CIDR. The bridge starts the connection, so the remote site may only answer |
| `openvpn` | A static-key tunnel over UDP on `remote_port` at `remote_host`, with the static key the tunnel's Secret holds, used without a direction, `cipher AES-256-CBC` and `auth SHA256`, and `allow-deprecated-insecure-static-crypto` on a release that needs it. The bridge sends from a source port of the kernel's choosing, which changes with every start; an OpenVPN without a `remote` line of its own accepts the bridge from any address and port |

On both kinds the remote site routes the Domain mesh CIDR into its end of the tunnel: a mesh node's packets reach it with the node's own mesh address, and the bridge's replies to traffic the site started come from the mesh addresses it reached (see [Routes and Policy](site-to-site-vpn.md#routes-and-policy)).

## CommandExecutor

Shared abstraction for running the daemons' commands, so a test runs a provider without its executables:

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
| `Run` | Runs a command and returns its combined output; the `IPsecProvider` runs every `swanctl` call with it |
| `Start` | Starts a command without waiting for it and returns a handle to stop it; the `OpenVPNProvider` starts each `openvpn` with it |
| `CommandHandle.Stop` | Kills the process |

`StdCommandExecutor` (`exec_std.go`) implements it with `exec.CommandContext`, which kills a process when its context ends. A command is named without a path, so its executable must be on the `PATH` of the plexd process. A missing executable fails with an error that wraps `exec.ErrNotFound`, which the manager reports as `client_missing`.

## Testing

No test suite runs strongSwan or OpenVPN; the proof of both providers is the command stand-in. `ipsec_test.go` and `openvpn_test.go` run each provider over a mock `CommandExecutor` and check the exact files, their modes and the directory's mode, the commands and their arguments, the refused keys, the include error, the handling of a failed load or listing, `Established` against recorded `swanctl` output and against a test listener on the management socket, and `Reset`. `tunnel_provider_integration_test.go` drives an `ipsec` and an `openvpn` tunnel through the pulls of a real reconciler, with the site-to-site manager and both providers over the stand-in, and serves both on a host without `swanctl` and `openvpn`, where they read `client_missing` and come up once the executables answer. The systemd suite's site-to-site phase serves an `openvpn` tunnel on a host without OpenVPN and proves `client_missing`, nothing of a connection (see [Systemd E2E Test](../development/systemd-e2e-test.md#_18-site-to-site-through-a-bridge)). `TestNetlinkVPNController_RealLinks` proves the xfrm interface and the tun device against the kernel (see [VPNController](site-to-site-vpn.md#vpncontroller)).

The file contents and commands were measured on 2026-11-18 in two `ubuntu:24.04` containers with strongSwan 5.9.13 and OpenVPN 2.6.19: an IKEv2 tunnel through an xfrm interface and a static-key OpenVPN tunnel on a persistent tun device each carried a ping between `10.99.0.1` and `10.30.0.1`. No suite repeats that run, so a change to a file or a command is proven only by the stand-in.

## Error Prefixes

| Source | Prefix |
|---|---|
| `ValidateTunnelConfig` | `bridge: tunnel: invalid tunnel id "<id>"`; `bridge: tunnel <id>: ` for the remote host, the remote port, a subnet and the interface name. Each provider puts `bridge: ipsec: ` or `bridge: openvpn: ` in front |
| `IPsecProvider.CreateTunnel` (no key) | `bridge: ipsec: tunnel <id>: the pre-shared key is empty` |
| `IPsecProvider.CreateTunnel` (directory) | `bridge: ipsec: create <dir>: ` |
| `IPsecProvider.CreateTunnel` (write) | `bridge: ipsec: write the connection of <id>: ` |
| `IPsecProvider.CreateTunnel` (load) | `bridge: ipsec: load the connection of <id>: swanctl --load-all: ` |
| `IPsecProvider.CreateTunnel` (list) | `bridge: ipsec: list the connections for <id>: swanctl --list-conns: ` |
| `IPsecProvider.CreateTunnel` (not loaded) | `bridge: ipsec: strongSwan did not load the connection, add "include <dir>/*.conf" to /etc/swanctl/swanctl.conf` |
| `IPsecProvider.RemoveTunnel` | `bridge: ipsec: invalid tunnel id "<id>"`; `bridge: ipsec: remove the connection of <id>: `; `bridge: ipsec: unload the connection of <id>: ` |
| `IPsecProvider.Established` | `bridge: ipsec: list the security associations of <id>: ` |
| `IPsecProvider.Reset` | `bridge: ipsec: reset: ` |
| `OpenVPNProvider.CreateTunnel` (key) | `bridge: openvpn: tunnel <id>: the key is no OpenVPN static key` |
| `OpenVPNProvider.CreateTunnel` (running) | `bridge: openvpn: tunnel <id> already runs` |
| `OpenVPNProvider.CreateTunnel` (directory) | `bridge: openvpn: create <dir>: ` |
| `OpenVPNProvider.CreateTunnel` (write) | `bridge: openvpn: write the key of <id>: `; `bridge: openvpn: write the configuration of <id>: ` |
| `OpenVPNProvider.CreateTunnel` (start) | `bridge: openvpn: start the tunnel <id>: ` |
| `OpenVPNProvider.RemoveTunnel` | `bridge: openvpn: invalid tunnel id "<id>"`; `bridge: openvpn: stop the tunnel <id>: `; `bridge: openvpn: remove a file of <id>: ` |
| `OpenVPNProvider.Established` | `bridge: openvpn: dial the management socket of <id>: `; `bridge: openvpn: management socket of <id>: ` |
| `OpenVPNProvider.Reset` | `bridge: openvpn: reset: ` |
| `CleanupSiteToSite` | `reset the <kind> provider: ` |
| `SiteToSiteManager.Teardown` | `bridge: site-to-site: remove the <kind> side of <id>: ` |

## Logging

All log entries use `component=bridge`. No log line carries a key.

| Level | Message | Keys |
|---|---|---|
| `Debug` | `ipsec connection loaded` | `tunnel_id`, `connection`, `interface` |
| `Warn` | `bridge: ipsec: unload failed` | `file`, `error`; the load after a failed `--list-conns` failed too |
| `Info` | `ipsec connections of an earlier process removed` | `connections` |
| `Debug` | `openvpn started` | `tunnel_id`, `interface` |
| `Info` | `openvpn files of an earlier process removed` | `files` |

The manager's lines, `site-to-site tunnel up` and `site-to-site tunnel down` among them, are listed in [Site-to-Site VPN](site-to-site-vpn.md#logging).
