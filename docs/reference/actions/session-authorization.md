---
title: Session-Based Action Authorization
---

# Session-Based Action Authorization

Actions triggered via the control plane SSE stream are implicitly authorized. Actions triggered locally via `plexd actions run` in an SSH session require explicit authorization through a session-scoped JWT.

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

| Trigger | Authentication | Authorization | Audit |
|---|---|---|---|
| SSE (control plane) | Authenticated SSE stream | Pre-authorized by control plane | `triggered_by.type: "control_plane"` |
| SSH via access proxy | `PLEXD_SESSION_TOKEN` (JWT) | Local JWT validation + action scope check | `triggered_by.type: "session"` with user identity |
| Direct SSH (no token) | No token present | Denied (or control-plane roundtrip if online) | `triggered_by.type: "direct_access"` |
| Local root access | `--local` flag, root or plexd user only | No scope limit, emergency use | `triggered_by.type: "local_emergency"` |

## Token Revocation

When an SSH session ends (disconnect, admin termination, timeout), the control plane pushes a `session_revoked` SSE event:

```json
{
  "session_id": "sess_a1b2c3",
  "revoked_at": "2025-01-15T12:00:00Z"
}
```

plexd adds the `session_id` to a local revocation set (bounded, TTL = maximum token lifetime). Subsequent action requests using a revoked session token are rejected immediately.

## Result Callback with Session Context

Actions triggered from an SSH session include the session context in the result callback:

```json
{
  "execution_id": "exec_a1b2c3d4",
  "status": "success",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration": "2.34s",
  "finished_at": "2025-01-15T10:30:02Z",
  "triggered_by": {
    "type": "session",
    "session_id": "sess_a1b2c3",
    "user_id": "user_abc123",
    "email": "admin@example.com"
  }
}
```

## Local Transport via Unix Socket

The `plexd actions run` CLI does not execute actions directly. It connects to the plexd daemon via a Unix socket (`/var/run/plexd.sock`), ensuring locally triggered actions go through the same path as SSE-triggered ones: token validation, integrity checks, sandbox, resource limits, and audit.

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
