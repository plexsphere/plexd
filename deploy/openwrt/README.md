# plexd on OpenWRT

plexd runs on OpenWRT as a plain static binary managed by procd. There is no
opkg package yet; installation is manual.

## Requirements

- OpenWRT 22.03 or later (nftables/fw4 based)
- Kernel WireGuard: `opkg update && opkg install kmod-wireguard`
- CA certificates for TLS to the control plane: `opkg install ca-bundle`
  (included by default in most images)
- ~14 MB of free storage for the binary and ~64 MB of free RAM. On devices
  with 16 MB flash (e.g. ramips/mt76x8 boards) use
  [extroot](https://openwrt.org/docs/guide-user/additional-software/extroot_configuration)
  or place the binary on a mounted USB drive.

## Choosing the right binary

| OpenWRT package architecture | plexd release asset |
|---|---|
| `x86_64` | `plexd-linux-amd64` |
| `aarch64_*` | `plexd-linux-arm64` |
| `mipsel_24kc`, `mipsel_74kc` (e.g. ramips) | `plexd-linux-mipsle` |

The `mipsle` build uses soft-float (`GOMIPS=softfloat`) and runs on FPU-less
cores such as the MT76x8 series. Check your device with
`opkg print-architecture`.

## Installation

```sh
# on the router (adjust arch as needed)
wget -O /usr/bin/plexd https://github.com/plexsphere/plexd/releases/latest/download/plexd-linux-mipsle
chmod +x /usr/bin/plexd

mkdir -p /etc/plexd
# create /etc/plexd/config.yaml — see the main README for options

# install the procd init script from this directory
cp plexd.init /etc/init.d/plexd
chmod +x /etc/init.d/plexd
/etc/init.d/plexd enable
/etc/init.d/plexd start
```

Logs go to the system log: `logread -e plexd`.

## Notes

- plexd manages its own nftables tables via netlink and does not modify
  fw4 rules. Make sure fw4 zones do not drop WireGuard traffic on the
  configured listen port.
- journald-based log forwarding is unavailable on OpenWRT (no systemd);
  all other agent features work as on regular Linux.
