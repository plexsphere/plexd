# Related repositories

Counterpart repositories of the plexd node agent. Each `##` heading is one
repository in `owner/repo` form; `When:` states the condition under which a
change made here warrants a counterpart issue there, and `Not when:` narrows
it.

## plexsphere/plexsphere

plexsphere is the control plane plexd registers with and reconciles against.
plexd is the client of the node-agent half of the platform API: what it expects
is written down in `docs/reference/core/api-endpoints.md` and pinned by the mock
control plane in `test/e2e/mockapi`, which the e2e suites run against.

When: the change makes plexd expect something of the `/v1` surface that the
control plane does not serve yet — an operation the agent starts calling, a
request or response field it starts sending or reading, an authentication
posture that moves between bootstrap token, Node Secret Key and operator
credential, an error code it starts reacting to. Also when a node-authored
payload changes shape (heartbeat and state reports, NAT endpoint discovery,
capability manifest, integrity-violation batches, action-execution and session
callbacks, forwarded observability data); when the registration and credential
model changes (bootstrap-token redemption, NSK issuance, rotation or
revocation, the node signing key); when the cryptographic envelope changes
(secret and edge-PSK unwrapping, HKDF edge-key derivation, signature
verification of events, policies or hooks); when a contract the agent enforces
locally moves and the control plane has to emit the new form — the compiled
policy wire format above all; or when the release artifact set changes in a way
the control plane's release index (`GET /v1/artifacts/plexd/{version}` and its
per-architecture checksums) has to follow.

Not when: the change stays on the node. Tunnel and WireGuard programming,
nftables and host firewall rules, the reconcile loop's internals, bridge and
relay behaviour, the local node API on the Unix socket or the CRD, packaging,
deployment manifests, the docs site, or the e2e harness. Also not when only the
mock API moves to match a contract the control plane already serves: mockapi
follows the contract, it does not define it.

## plexsphere/plexsphere-node

plexsphere-node is the NixOS provisioning toolkit that installs plexd as a host
systemd service. Its `modules/plexd.nix` renders `/etc/plexd/config.yaml`,
opens the WireGuard port and defines the unit; its `packages/plexd.nix` pins a
released binary per architecture by URL and hash.

When: the change alters how plexd is installed, configured or run on a host —
the config file's path, format or the keys the module presets (`api.base_url`,
`wireguard.listen_port` and anything else it has to keep in step), the
out-of-band bootstrap-token contract (`/etc/plexd/bootstrap-token`,
`PLEXD_BOOTSTRAP_TOKEN`), what the systemd unit has to grant the process
(privileges, capabilities, kernel modules, state and runtime directories,
ordering and restart behaviour), or a new host-level prerequisite such as a
port that must be open. Also when the release artifact contract changes: asset
naming, the set of published architectures, static linking, the checksum file,
or the Sigstore bundle each pinned fetch is verified against.

Not when: the work is internal to the agent, or a release carries no change to
any of the above. plexsphere-node consumes plexd as a released binary and moves
its pin on its own schedule, so an ordinary release does not need an issue
there.
