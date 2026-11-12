---
title: Platform Support
---

# Platform Support

plexd runs on Linux, macOS and Windows. Every release publishes seven binaries: `plexd-linux-amd64`, `plexd-linux-arm64` and `plexd-linux-mipsle`, `plexd-darwin-amd64` and `plexd-darwin-arm64`, and `plexd-windows-amd64.exe` and `plexd-windows-arm64.exe`, each with a Sigstore bundle. Node mode and bridge mode both work on all three.

The tables below say what each operating system does, feature by feature. Every row names the reference page it is derived from, so a cell that looks surprising can be checked against the page that owns it. Install instructions are in the [bare-metal](../how-to/bare-metal-installation.md), [macOS](../how-to/macos-installation.md) and [Windows](../how-to/windows-installation.md) guides.

## Binaries, installation and operation

| Feature | Linux | macOS | Windows | Source |
|---|---|---|---|---|
| Release binaries | `plexd-linux-{amd64,arm64,mipsle}` | `plexd-darwin-{amd64,arm64}` | `plexd-windows-{amd64,arm64}.exe` | [Release assets](../reference/development/release-workflow.md) |
| Tested in CI | `ubuntu-latest`, amd64 | macOS 26, arm64; the amd64 binary is cross-compiled only | Windows Server 2025, amd64; the arm64 binary is cross-compiled only | [CI workflow](../reference/development/ci-workflow.md) |
| Install script `deploy/install.sh` | yes | yes | no; the install is a manual walkthrough from an elevated PowerShell | [Install script](../reference/deployment/bare-metal-packaging.md) |
| What `plexd install` registers | a systemd unit, written and not enabled | a launchd daemon `com.plexsphere.plexd`, loaded at the next boot | an SCM service `plexd` with automatic start | [plexd install](../reference/core/cli.md) |
| Daemon privileges | root; the unit bounds it to `CAP_NET_ADMIN` and `CAP_NET_RAW` | root | LocalSystem as a service, an elevated Administrator from a console | [Packaging](../reference/deployment/bare-metal-packaging.md) |
| Config, data and runtime directories | `/etc/plexd`, `/var/lib/plexd`, `/var/run/plexd` | `/Library/Application Support/plexd`, `…/plexd/data`, `/var/run/plexd` | `%ProgramData%\plexd`, `…\plexd\data`, `…\plexd\run` | [Platform defaults](../reference/core/configuration.md#platform-defaults) |
| Daemon log | journald | `/Library/Logs/plexd/plexd.log`, rotated by newsyslog | Application Event Log, source `plexd` | [Platform defaults](../reference/core/configuration.md#platform-defaults) |
| `plexd logs` | `journalctl -u plexd` | tails the log file, 100 lines | `Get-WinEvent` through PowerShell; `--follow` is refused | [plexd logs](../reference/core/cli.md) |
| `service.upgrade` | yes | yes | yes; the running image is renamed to `plexd.exe.old` first | [Remote actions](../reference/actions/remote-actions-hooks.md) |
| Kubernetes DaemonSet, cloud-init, OpenWRT | yes | no | no | [Kubernetes](../reference/deployment/kubernetes-deployment.md), [cloud-init](../reference/deployment/cloud-init-deployment.md) |

## Data plane

| Feature | Linux | macOS | Windows | Source |
|---|---|---|---|---|
| WireGuard mesh | the kernel module, through netlink | wireguard-go on a utun device; the kernel names it `utunN` | wireguard-go on a Wintun adapter; `wintun.dll` is embedded in the binary | [Userspace backend](../reference/networking/wireguard.md#userspace-backend) |
| NAT traversal (STUN), peer endpoint exchange, NAT relay | yes | yes | yes | [NAT traversal](../reference/networking/nat-traversal.md) |
| Policy enforcement, IPv4 and IPv6 rules | nftables, an input, a forward and an output chain in table `inet plexd`; governs traffic to the node itself and what the node sends over the mesh too, and replies to tracked connections pass without a rule | a pf anchor; governs traffic to the node itself too, and what the node sends over the mesh through `pass out` lines per rule; replies to what a rule lets in leave through stateless mirror lines, and only TCP keeps state | WFP filters at the IPv4 and IPv6 layers; govern traffic to the node itself too, and what the node sends over the mesh through filters at `ALE_AUTH_CONNECT`; permits are soft, and an allow that names a protocol or a port reaches no forward filter | [What the rules govern](../reference/networking/pf-wfp-firewall.md#what-the-rules-govern), [Connection Tracking](../reference/networking/nftables-firewall.md#connection-tracking) |
| Connection logging, a line in plexd's log for each connection a rule with `log: true` allows | nftables `log group 28772` in front of each logged rule, read over NFLOG; one line per new connection, in, out and forwarded | `log` on pf lines, read from `pflog0` through `/dev/bpf`; one line per TCP connection, one per packet for UDP, ICMP and other protocols; in, out and forwarded | none: a logged rule is enforced like any other, and every apply that holds one logs `policy connection logging unavailable, logged rules are enforced without it` | [Connection logging](../reference/networking/network-policy.md#connection-logging), [Logged rules on Windows](../reference/networking/pf-wfp-firewall.md#logged-rules-on-windows) |
| Secure access tunneling (SSH, Kubernetes API proxy) | yes | yes | yes | [Secure access tunneling](../reference/networking/secure-access-tunneling.md) |
| Mediated ssh sessions (the `ssh` session kind) | yes; processes start through the session helper | yes; processes start through a child session helper with plexd's own privileges | no; entries are settled as unsupported | [SSH Sessions](../reference/networking/secure-access-tunneling.md#ssh-sessions) |
| Mesh DNS | yes; answers the mesh names and forwards the forward zones and a catch-all to the resolvers the Domain or Project names. Registered with systemd-resolved 246 or newer, the forward zones as routing domains and a catch-all as the host's default DNS route, and without one the resolver still answers and forwards on `<mesh IP>:5354` for a local resolver to forward to | yes; answers the mesh names and forwards the forward zones and a catch-all as on Linux, on `127.0.0.1:5354`, because a Mac cannot reach its own utun mesh IP. Registered with `scutil` in configd's dynamic store, from which mDNSResponder takes its per-domain resolvers, the forward zones as supplemental match domains and a catch-all as a default-resolver entry. macOS keeps the primary network service's resolver as a second default resolver, and whether it ever sends that resolver a name the catch-all should take was not measured | yes; answers the mesh names and forwards the forward zones and a catch-all as on Linux, on `127.0.0.1:53`, because the Name Resolution Policy Table sends to port 53 only. Registered with the DNS Client (`Dnscache`) as Name Resolution Policy Table rules, in the Group Policy store too where Group Policy configures the table, with the search domain on the mesh adapter's search list. A catch-all is a rule for `.`, which takes every name no more specific rule matches, the host's DHCP suffixes and Active Directory names included | [Mesh DNS](../reference/networking/mesh-dns.md), [Forwarding](../reference/networking/mesh-dns.md#forwarding), [Registration on macOS](../reference/networking/mesh-dns.md#registration-on-macos), [Registration on Windows](../reference/networking/mesh-dns.md#registration-on-windows) |

## Bridge mode

| Feature | Linux | macOS | Windows | Source |
|---|---|---|---|---|
| Routing and IPv4 forwarding | netlink; a per-interface sysctl | `route(8)`; one global sysctl, restored on teardown | the IP Helper API; a per-interface flag, restored on teardown | [Forwarding](../reference/bridge/route-controllers-macos-windows.md#forwarding) |
| NAT masquerade | nftables | a `nat` rule in the pf anchor | a WinNAT object scoped to the mesh prefix; user-access and site-to-site sources are not translated | [NAT](../reference/networking/pf-wfp-firewall.md#nat) |
| User access (WireGuard interface) | netlink | utun | Wintun | [AccessController](../reference/bridge/user-access-integration.md) |
| Site-to-site VPN (WireGuard tunnels) | netlink | a utun carrying the mesh IP as a `/32` | Wintun | [VPNController](../reference/bridge/site-to-site-vpn.md) |
| User-access providers (Tailscale, Netbird) and site-to-site providers (OpenVPN, IPsec) | the provider binary is invoked by name and must be on `PATH`; no e2e suite exercises one on any platform | same | same | [VPN providers](../reference/bridge/vpn-providers.md), [tunnel providers](../reference/bridge/tunnel-providers.md) |
| Public ingress, ACME, SNI routing | yes | yes | yes | [Public ingress](../reference/bridge/public-ingress.md) |

`bridge.access_interface` carries the name the platform itself knows: a kernel name on Linux and macOS (`eth1`, `en1`), the adapter's friendly name on Windows (`Ethernet`). See [Interface names](../reference/bridge/route-controllers-macos-windows.md#interface-names).

## Observability, node API and actions

| Feature | Linux | macOS | Windows | Source |
|---|---|---|---|---|
| System metrics | `/proc` | sysctl, Mach and the routing socket; best-effort per source | kernel32 and the IP Helper API; best-effort per source | [DarwinSystemReader](../reference/observability/metrics-collection.md#darwinsystemreader) |
| Load average | yes | yes | no, Windows has none; the field is 0 | [WindowsSystemReader](../reference/observability/metrics-collection.md#windowssystemreader) |
| Log forwarding, daemon source | journald; without `journalctl`, as in a container, only the policy connection lines, through a queue source | the launchd log file | the Event Log, provider `plexd` | [DaemonLogSource](../reference/observability/log-forwarding.md#daemonlogsource), [QueueSource](../reference/observability/log-forwarding.md#queuesource) |
| Log forwarding, `file_patterns` | yes | yes | yes | [FileSource](../reference/observability/log-forwarding.md#filesource) |
| Audit forwarding | the daemon's own start event only; the auditd and Kubernetes audit sources are built but not wired into `plexd up` | same | same | [Audit forwarding](../reference/observability/audit-forwarding.md) |
| Local node API endpoint | Unix socket `/var/run/plexd/api.sock` | Unix socket `/var/run/plexd/api.sock` | named pipe `\\.\pipe\plexd` | [Node API](../reference/core/nodeapi.md) |
| Secret-route authorization | `SO_PEERCRED`; root or a member of `plexd-secrets` | `LOCAL_PEERCRED`; root or a member of `plexd-secrets`, created by hand with `dscl` | the client's process token; an elevated Administrator or LocalSystem | [Local peer authorization](../reference/core/nodeapi.md#local-peer-authorization) |
| Built-in actions | all 11 | all 11 | 10 of 11; `service.reload_config` fails, Windows has no reload signal | [Built-in actions](../reference/actions/remote-actions-hooks.md) |
| Hook scripts | yes | yes | no; discovery needs the executable bit, which Windows does not report on a regular file | [DiscoverHooks](../reference/actions/remote-actions-hooks.md) |

## Known limitations

- **Userspace WireGuard on macOS and Windows.** Both run wireguard-go inside the plexd process where Linux uses the kernel module. plexd carries no throughput measurement for either path, so the cost is not quantified here.
- **Windows Defender Firewall may drop inbound handshakes.** plexd's own WFP permits are soft and cannot open a port the host firewall closes. The [Windows guide](../how-to/windows-installation.md) adds the inbound rule for the listen port.
- **pf keeps state for TCP only.** A stateful rule covering every protocol would keep an inbound-initiated UDP or ICMP flow alive after its rule turned into a deny.
- **An `allow` that names a protocol or a port reaches no WFP forward filter.** The WFP forward layers match neither, so on a bridge or relay node the transit traffic it covered falls through to the rules below it, at worst the default deny. Each apply logs how many rules that affects.
- **pf logs every packet of a UDP, ICMP or other non-TCP flow a logged rule allows.** Those lines keep no state, so pf cannot tell a flow's first packet, and the connection lines' rate limit bounds what they add.
- **Windows logs no connections.** A rule with `log: true` is enforced, and every apply that holds one logs `policy connection logging unavailable, logged rules are enforced without it`.
- **WinNAT translates mesh-sourced traffic only.** It is scoped by source prefix rather than by outgoing interface, so a user-access or site-to-site source is not translated on Windows.
- **Only IPv4 forwarding is toggled**, on every platform. An IPv6 subnet in `access_subnets` still gets its route.
- **launchd has no start limit.** A daemon that exits on a configuration error restarts every five seconds until an operator boots it out.
- **launchd has no environment file.** `PLEXD_*` overrides on macOS go into `config.yaml`, or into an `EnvironmentVariables` dict an operator adds to the plist by hand.
- **The SCM restarts indefinitely.** Its recovery actions retry every five seconds and the last action applies to every later failure, so a misconfigured Windows service also restarts until an operator intervenes.
- **macOS resolves system paths only.** There is no per-user fallback under `~/Library`, because the CLI resolves the node API socket without knowing who started the daemon. An unprivileged run sets `--config` and `data_dir` itself.
- **`wg show` needs the Windows service.** A plexd started from a console owns its UAPI pipe, and `wgctrl` requires a LocalSystem-owned one, so it finds no device for a console-started daemon.
- **The Event Log provider name is not an identity.** Any local user can write events under provider `plexd`, and this node forwards them indistinguishably from the service's own records.
- **No hook scripts and no `service.reload_config` on Windows.** Hooks are discovered by their executable bit and run as `#!/bin/sh` scripts; Windows has neither. Restart the service instead of reloading it.
- **`plexd logs --follow` is refused on Windows.** `Get-WinEvent` reads a channel and returns; the Event Log's live feed has no command-line form.

## Keeping this page current

Every row above names the reference page it is derived from. A pull request that adds or removes a `_linux.go`, `_darwin.go` or `_windows.go` implementation, or changes what one of them does, updates the row in the same pull request. Nothing checks this automatically: the [docs build on pull requests](../reference/development/docs-workflow.md) catches a dead link and nothing else.

## See Also

- [Architecture](./architecture.md) — deployment targets and the mesh topology
- [macOS Installation Guide](../how-to/macos-installation.md)
- [Windows Installation Guide](../how-to/windows-installation.md)
- [Configuration Reference](../reference/core/configuration.md) — every field, with its per-platform default
