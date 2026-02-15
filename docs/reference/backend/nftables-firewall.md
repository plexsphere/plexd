---
title: nftables Firewall Controller
quadrant: backend
package: internal/policy
feature: PXD-0027
---

# nftables Firewall Controller

`NftablesController` is the Linux production implementation of the `FirewallController` interface defined in `internal/policy`. It translates `FirewallRule` entries into nftables expressions and manages them via the `github.com/google/nftables` netlink library.

The controller operates on a single IPv4 table (`plexd`) and creates base chains with a forward hook (`ChainTypeFilter`, `ChainHookForward`, `ChainPriorityFilter`) so that rules are evaluated by the kernel for forwarded traffic. It requires `CAP_NET_ADMIN` and the `//go:build linux` constraint.

## Architecture

```
PolicyEngine
     │
     ▼
┌──────────────┐     ┌────────────────────┐
│ FirewallRule  │────▶│ NftablesController │
│   (slice)    │     └────────┬───────────┘
└──────────────┘              │
                              ▼
                    ┌──────────────────┐
                    │  nftables (nfnl) │
                    │  table: plexd    │
                    │  family: IPv4    │
                    └──────────────────┘
```

The `Enforcer` calls `NftablesController` methods during policy reconciliation. Each method opens a fresh netlink connection, batches operations, and commits atomically via `Flush()`.

## Constructor

```go
func NewNftablesController(logger *slog.Logger) *NftablesController
```

Logger entries use `component=policy`.

## Interface Implementation

`NftablesController` implements `FirewallController`:

| Method        | nftables Operation                                                    |
|---------------|-----------------------------------------------------------------------|
| `EnsureChain` | `AddTable` (idempotent) + `AddChain` + `Flush`                       |
| `ApplyRules`  | `AddTable` + `AddChain` + `FlushChain` + `AddRule` per rule + `Flush`|
| `FlushChain`  | `AddTable` + `FlushChain` + `Flush`                                  |
| `DeleteChain` | `ListChainsOfTableFamily` → `DelChain` + `Flush` if found            |

### EnsureChain

Creates the `plexd` IPv4 table and a base chain with `ChainTypeFilter`, `ChainHookForward`, and `ChainPriorityFilter` within it. This ensures the kernel evaluates the chain's rules for forwarded packets. Both `AddTable` and `AddChain` are idempotent in nftables — re-adding existing objects is a no-op.

### ApplyRules

Atomically replaces all rules in the named chain:

1. Ensures the table and chain exist
2. Flushes existing rules from the chain
3. Converts each `FirewallRule` into nftables expressions
4. Adds all rules to the chain
5. Commits via `Flush()`

If expression building fails for any rule (invalid IP, unsupported protocol/action), the entire operation is aborted before `Flush()`.

### DeleteChain

Lists all IPv4 chains, finds the target by table name + chain name, and deletes it. Returns `nil` if the chain does not exist (idempotent).

## Rule Translation

Each `FirewallRule` is converted to a sequence of nftables expressions:

| FirewallRule Field | nftables Expression                                       | Condition            |
|--------------------|-----------------------------------------------------------|----------------------|
| `Interface`        | `Meta(IIFNAME)` + `Cmp`                                  | Non-empty            |
| `SrcIP`            | `Payload(NetworkHeader, offset=12)` + `Cmp` or `Bitwise` | Non-empty, not `0.0.0.0/0` |
| `DstIP`            | `Payload(NetworkHeader, offset=16)` + `Cmp` or `Bitwise` | Non-empty, not `0.0.0.0/0` |
| `Protocol`         | `Meta(L4PROTO)` + `Cmp`                                  | Non-empty            |
| `Port`             | `Payload(TransportHeader, offset=2)` + `Cmp`             | `> 0`                |
| (always)           | `Counter`                                                 | Always appended      |
| `Action`           | `Verdict(Accept)` or `Verdict(Drop)`                     | `"allow"` or `"deny"`|

### IP Address Matching

| Input Format     | Match Strategy                                 |
|------------------|------------------------------------------------|
| `10.0.0.1`       | Exact match (treated as `/32`)                 |
| `10.0.0.1/32`    | Exact match                                    |
| `10.0.0.0/24`    | Bitwise mask + compare against network address |
| `0.0.0.0/0`      | Skipped (matches all traffic)                  |

### Protocol Mapping

| String  | IP Protocol Number |
|---------|--------------------|
| `"tcp"` | `6` (IPPROTO_TCP)  |
| `"udp"` | `17` (IPPROTO_UDP) |

Unsupported protocols cause `ApplyRules` to return an error.

## nftables Table Layout

```
table ip plexd {
    chain plexd-mesh {
        type filter hook forward priority filter; policy accept;
        # Rules from ApplyRules
        iifname "wg0" ip saddr 10.0.0.1 ip daddr 10.0.0.2 tcp dport 443 counter accept
        iifname "wg0" counter drop  # default deny
    }
}
```

The table name `plexd` is a package-level constant. The chain name is configurable via `Config.ChainName` (default: `plexd-mesh`).

## Error Prefixes

| Method        | Prefix                                           |
|---------------|--------------------------------------------------|
| `EnsureChain` | `policy: nftables: ensure chain`                 |
| `ApplyRules`  | `policy: nftables: apply rules`                  |
| `FlushChain`  | `policy: nftables: flush chain`                  |
| `DeleteChain` | `policy: nftables: delete chain`                 |

## Dependencies

| Package                        | Usage                          |
|--------------------------------|--------------------------------|
| `github.com/google/nftables`  | Netlink-based nftables control |
| `github.com/google/nftables/expr` | Rule expression types      |
| `golang.org/x/sys/unix`       | Protocol number constants      |

## Privileges

All methods require `CAP_NET_ADMIN`. When running without privileges, methods return permission errors wrapped with the appropriate error prefix. Tests that call nftables methods skip with `t.Skipf` when privileges are unavailable.

## Usage

```go
logger := slog.Default()
ctrl := policy.NewNftablesController(logger)

enforcer := policy.NewEnforcer(engine, ctrl, policy.Config{}, logger)
```
