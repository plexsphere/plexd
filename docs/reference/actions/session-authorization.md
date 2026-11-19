---
title: Action Authorization
---

# Action Authorization

A dispatch from the control plane arrives in the `executions` block of the node's NSK-authenticated state pull, and that entry is the authorization.

A local run through `plexd actions run` is authorized by reaching the node API and nothing else. It runs built-in actions only, never a hook, and nothing about it reaches the control plane. `actions.enabled: false` refuses it as it refuses dispatches.

## Authorization Tiers

| Trigger | Authentication | Authorization |
|---|---|---|
| Pull (control plane) | NSK-authenticated state pull | Pre-authorized by the control plane: an entry in the `executions` block *is* the authorization, and the dispatch decision is the control plane's alone. `actions.enabled: false` rejects it with `actions_disabled` |
| `plexd actions run` over the node API socket or pipe | The endpoint's permissions: on Linux and macOS the socket admits root, or the `plexd` group when it is `root:plexd` with mode `0660`; on Windows the pipe admits LocalSystem and elevated Administrators (see [Local peer authorization](../core/nodeapi.md#local-peer-authorization)) | None beyond reaching the endpoint: any built-in action, no hook. Refused while `actions.enabled` is `false` |
| `POST /v1/actions/run` on the optional HTTP listener (`node_api.http_enabled`) | The bearer token in `node_api.http_token_file` | The same as over the socket |

Trigger attribution — who asked for a control-plane execution — lives in the
control plane's audit trail, not on the node: the pull entry carries no
requester identity.

## Running an Action from an SSH Session

![A sequence between the user, the platform's control plane and plexd on the target Node. The user requests an SSH session, and the control plane issues a session token that carries the session id as jti, the login user and exp. The session reaches plexd in the sessions block of the state pull. The user logs in over SSH with the token as password, and plexd verifies the token's signature, session id, user and expiry and starts the user's shell. In that shell the user runs plexd actions run diagnostics.collect, which opens the node API socket, whose mode admits root or the plexd group. plexd runs the action only while actions are enabled and only if the name is a built-in, and returns the result to the user. Nothing is reported to the control plane.](../../diagrams/actions-session-authorization.svg)

A mediated SSH session's token authorizes the SSH login only. plexd checks it at login (see [Authentication](../networking/secure-access-tunneling.md#authentication)), and the token has no action scope. The session refuses `env` requests, and the session helper starts the shell with a scrubbed environment of `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH` and, with a pty, `TERM`, so no token reaches it.

`plexd actions run` from that shell reaches the daemon when the login user can open the socket. When the user cannot, the command fails with `plexd actions run: agent not running or socket unavailable at /var/run/plexd/api.sock: ...`, ending in `permission denied`. A plain SSH login or a console shell follows the same rule.

The run belongs to the CLI's HTTP request, not to the session, and has no Execution to cancel (see [Cancel](remote-actions-hooks.md#cancel)).

## Local Transport

![plexd actions run diagnostics.collect --param include_network=false opens the node API socket /var/run/plexd/api.sock, whose mode admits root or the plexd group. In the plexd daemon, handleRunAction decodes the action and its parameters and calls Executor.RunLocal, which refuses the run while actions.enabled is false, refuses a name that is not a registered built-in, and otherwise runs the built-in. The status, exit code, stdout and stderr go back to the command, and nothing reaches the control plane.](../../diagrams/actions-local-transport.svg)

The CLI dials the platform default: `/var/run/plexd/api.sock` on Linux and macOS, and `\\.\pipe\plexd` on Windows. It does not read `node_api.socket_path` or `PLEXD_NODE_API_SOCKET`, so a daemon moved off the default is out of its reach. It sends `{"action", "parameters"}` to `POST /v1/actions/run`.

`Executor.RunLocal` refuses the run while `actions.enabled` is `false` (`actions are disabled on this node`), refuses any name that is not a registered built-in (`unknown builtin action: <name>`), and otherwise runs the built-in synchronously under the request's context. No hook runs, so no hook integrity check applies. The run gets no execution id and no callback, `handleRunAction` logs nothing, and nothing reaches the control plane.

A refusal comes back as `200` with `status: "error"`, and the CLI prints it and exits 0, as it does for every `200`. See [POST /v1/actions/run](remote-actions-hooks.md#post-v1-actions-run) for the wire format.
