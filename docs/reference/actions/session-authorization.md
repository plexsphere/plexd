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
 |                       |-- Session in the state --->|
 |                       |   pull's sessions block    |-- Start SSH session
 |<===== SSH session (relayed over plexd's socket) ==>|-- Inject PLEXD_SESSION_TOKEN
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

Revocation does not depend on a pushed command. When a session ends (disconnect, admin termination, timeout), the control plane drops its entry from the `sessions` block of the node's state pull, and the next reconcile observes the absence: that absence *is* the teardown signal for every session the node has not already closed. plexd closes the session and, for a session whose listener it provisioned, reports a `session_ended` activity row with `terminated_by: plexd_close` (or `ttl_expired` once the session's capped expiry has passed) — the node cannot tell a revocation from a control plane that failed to serve the block, so a drain does not claim an operator action. There is no revocation callback to answer and no terminal status to report — see [Secure Access Tunneling](../networking/secure-access-tunneling.md) for the dispatcher that performs the teardown.

The signed `session_revoked` SSE event closes the session without waiting for the drain. Its payload names the session (`session_id`, and `jti`, which must equal it) and carries `revoked_at` and `revoke_reason`. When the named session is live, plexd closes it, and its `session_ended` row reports `terminated_by: operator_revoke` for an operator-driven reason (`operator_request`, `policy_violation`, `identity_compromise`, `resource_decommissioned`), or `ttl_expired` or `idle_timeout` for the reason of the same name, which the control plane's sweeper sets. An empty or unrecognised reason is reported as `operator_revoke`, with a warning. plexd triggers a reconcile only after the close, so the pull cannot drain the session first, and a later pull that still lists the revoked session does not provision it again. A payload that does not decode, or whose `session_id` is empty or differs from its `jti`, closes nothing and only triggers the reconcile. A node that misses the event converges on its own cadence through the drain, which reports `plexd_close` (or `ttl_expired` once the session's capped expiry has passed). A pull that drains the session before the event arrives reports `plexd_close` too, and the late event then finds no live session to close.

The session JWT itself is not revoked on the node. Token validation consults no revocation set: local validation covers the signature and `exp`, so a token already handed out stays usable for its remaining lifetime. Keeping session tokens short-lived is what bounds that window.

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
