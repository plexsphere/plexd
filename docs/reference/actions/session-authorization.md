---
title: Session-Based Action Authorization
---

# Session-Based Action Authorization

Actions dispatched by the control plane are implicitly authorized: they arrive in the `executions` block of the node's authenticated state pull, so the control plane has already decided the node may run them. Actions triggered locally via `plexd actions run` in an SSH session require explicit authorization through a session-scoped JWT.

## Authorization Flow

```
User                Platform / CP              plexd (Target Node)
 |                       |                            |
 |-- Request SSH ------->|                            |
 |   session             |-- Check RBAC               |
 |                       |   (user x node x actions)  |
 |                       |                            |
 |                       |-- Issue session JWT        |
 |                       |   { sub, node_id,          |
 |                       |     actions, exp }         |
 |                       |                            |
 |                       |-- SSH setup via SSE ------>|
 |                       |   (includes session token) |-- Start SSH session
 |<======== SSH session (tunneled through mesh) =====>|-- Inject PLEXD_SESSION_TOKEN
 |                       |                            |
 |-- plexd actions run -------------------------------->|
 |   diagnostics.collect |                            |-- Read token from env
 |                       |                            |-- Validate JWT (local)
 |                       |                            |-- Check action scope
 |                       |                            |-- Execute
 |<-- Result ----------------------------------------------|
 |                       |<-- Callback (result + -----|
 |                       |    session context)        |
```

## Session JWT Structure

```json
{
  "iss": "plexsphere",
  "sub": "user_abc123",
  "email": "admin@example.com",
  "node_id": "n_xyz789",
  "session_id": "sess_a1b2c3",
  "actions": [
    "diagnostics.*",
    "health.check",
    "hooks/backup"
  ],
  "iat": 1705312200,
  "exp": 1705341000
}
```

The JWT is signed with the control plane's Ed25519 key. plexd receives the corresponding public key during registration and uses it for local validation - no roundtrip required.

## Action Scope Patterns

| Pattern | Matches |
|---|---|
| `*` | All actions and hooks |
| `diagnostics.*` | All actions in the `diagnostics` namespace |
| `hooks/*` | All hooks (script and CRD) |
| `hooks/backup` | Only the `backup` hook |
| `health.check` | Exactly one action |

## Authorization Tiers

| Trigger | Authentication | Authorization |
|---|---|---|
| Pull (control plane) | NSK-authenticated state pull | Pre-authorized by the control plane: an entry in the `executions` block *is* the authorization, and the dispatch decision is the control plane's alone |
| SSH via access proxy | `PLEXD_SESSION_TOKEN` (JWT) | Local JWT validation + action scope check |
| Direct SSH (no token) | No token present | Denied (or control-plane roundtrip if online) |
| Local root access | `--local` flag, root or plexd user only | No scope limit, emergency use |

Trigger attribution — who asked for a control-plane execution — lives in the
control plane's audit trail, not on the node: the pull entry carries no
requester identity.

## Token Revocation

When an SSH session ends (disconnect, admin termination, timeout), the control plane pushes a `session_revoked` SSE event:

```json
{
  "session_id": "sess_a1b2c3",
  "revoked_at": "2025-01-15T12:00:00Z"
}
```

plexd adds the `session_id` to a local revocation set (bounded, TTL = maximum token lifetime). Subsequent action requests using a revoked session token are rejected immediately.

## Local Transport via Unix Socket

The `plexd actions run` CLI does not execute actions directly. It connects to the plexd daemon via a Unix socket (`/var/run/plexd.sock`), ensuring locally triggered actions go through the same path as control-plane-dispatched ones: token validation, integrity checks, sandbox, resource limits, and audit.

```
plexd actions run diagnostics.collect --param include_network=true
       |
       |-- Unix socket (/var/run/plexd.sock) --> plexd daemon
                                                    |-- Validate session JWT
                                                    |-- Check action scope
                                                    |-- Verify hook integrity
                                                    |-- Apply sandbox + limits
                                                    |-- Execute
                                                    +-- Report to control plane
```
