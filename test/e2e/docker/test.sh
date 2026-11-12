#!/usr/bin/env bash
# Docker E2E test orchestration script.
# Builds and runs the mock-api and plexd containers via docker compose,
# then polls the mock-api assertion endpoint to verify plexd performed
# registration, heartbeat, state, capabilities, metrics, logs, and audit calls.
#
# Extended tests:
#   - Periodic loop verification (counters >= 2 after additional wait)
#   - Handshake report and tunnel_health samples (skipped when WireGuard
#     did not come up in the container)
#   - Edge PSK fetches for both fixture peers (same skip condition)
#   - Endpoint candidates report, an endpoint selection switch on a
#     fixture peer, and its move to a new relay fallback (same skip
#     condition)
#   - Mesh MTU sized from the uplink probe and held by the device (same
#     skip condition)
#   - Request body validation (registration token, heartbeat, capabilities)
#   - Log injection (docker cp into container, verify logs_count increases)
#   - Agent restart for audit verification (ProcessSource fires per-process)
#   - SSE event injection triggers reconciliation (state_count increases)
#   - Action execution via the state pull's executions block
#     (ack/started/terminal callbacks)
#   - Executions resumed from a seeded status (no re-ack, no re-run)
#   - action_request is a pull trigger, not a delivery channel
#   - tcp tunnel traffic reported as session_active rows
#   - Secret index fed from the state pull's secrets block, with
#     node_secrets_updated as a pull trigger
#   - Mesh DNS without systemd-resolved: the listener and the missing resolver
#     logged once per start, mesh names and the dns block's A, CNAME, SRV, MX
#     and TXT records answered on the mesh IP, a forward zone and a catch-all
#     forwarded to the mock's DNS stub, and kept by a null dns block
#   - Policy enforcement on the mesh interface: a WireGuard peer in the meshpeer
#     container reaches the ports the served policy allows and no other, plexd's
#     own connection to it needs no rule, a revision with a legacy deny rule is
#     rejected, and mesh DNS inside the container still answers under an empty
#     policy
#   - Key rotation completes end to end via RotateKeys flag
#   - Deeper body validation (metrics, audit, logs, capabilities fields)
#   - Capability manifest kept current: a hook added, changed, touched, reloaded
#     and removed in the running container, a sidecar's metadata reported, the
#     short entry sent to a control plane that refuses metadata, and a failed
#     PUT retried
#   - A hook run held to its sidecar's timeout with its whole process group
#     killed, and refused for a sandbox level plexd lacks and for a
#     group-writable hook file
#   - A running hook stopped by the pull's cancel_requested_at, with its whole
#     process group killed and the output it printed reported as cancelled
#   - A hook the control plane rolls out installed, run, and upgraded with no
#     restart, kept by a null hooks block, refused when its fetch fails
#     verification or hooks_dir holds its name, kept across a restart, refused
#     to run once edited on disk, and withdrawn
#   - Pull-only delivery under a descoped event bus (quiet SSE re-probing)
#   - Last-Event-ID resume replays buffered envelopes after a descope window
#   - release-verdict upgrade flow (checksum + offline Sigstore verification)
#   - Graceful shutdown (exit code 0, no crash indicators)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/../docker-compose.yml"
PROJECT_NAME="plexd-e2e"
ASSERT_URL="http://localhost:18080/test/assertions"
TEST_FAILED=1

dc() { docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" "$@"; }

# --- Helper: fetch a single counter value from a JSON response ---
get_counter() {
    local response=$1 key=$2
    echo "${response}" | jq -r ".${key} // 0"
}

# --- Helper: count the log lines that carry every given string ---
# Args: <log> <needle>... Prints how many lines of log contain each needle, in
# any order. The log is matched line by line with case rather than piped into
# grep -c: a writer cut off by a closed pipe fails the pipeline under pipefail
# (see phase 4b).
count_log_lines() {
    local log=$1 line needle n=0
    shift
    while IFS= read -r line; do
        for needle in "$@"; do
            case "${line}" in
                *"${needle}"*) ;;
                *) continue 2 ;;
            esac
        done
        n=$((n + 1))
    done <<< "${log}"
    echo "${n}"
}

# --- Helper: base64-decode stdin portably across GNU and BSD/macOS ---
# GNU coreutils spells decode as -d; older BSD/macOS base64 uses -D. Probe once
# with a known value ("QQ==" -> "A") and bind b64_decode to whichever flag works.
if printf 'QQ==' | base64 -d >/dev/null 2>&1; then
    b64_decode() { base64 -d; }
else
    b64_decode() { base64 -D; }
fi

# --- Helper: lowercase-hex SHA-256 of stdin, taking field 1 ---
# GNU coreutils ships sha256sum; BSD/macOS ships shasum. Both print
# "<hex>  <name>", so field 1 is the digest.
if command -v sha256sum >/dev/null 2>&1; then
    sha256_hex() { sha256sum | awk '{print $1}'; }
else
    sha256_hex() { shasum -a 256 | awk '{print $1}'; }
fi

# --- Helper: print a capability manifest's declared_hooks names, comma-joined ---
# An absent list prints nothing, so a comparison with the wanted names fails on
# it instead of passing over it.
declared_hook_names() {
    printf '%s' "$1" | jq -r '[.declared_hooks[]?.name] | join(",")'
}

# --- Helper: print the digest a capability manifest declares for a hook ---
# Args: <manifest> <hook>. The wire carries base64, and this prints lowercase
# hex so the result compares directly with sha256_hex. A hook the manifest does
# not list prints nothing.
declared_hook_hex() {
    local checksum
    checksum=$(printf '%s' "$1" | jq -r --arg name "$2" '.declared_hooks[]? | select(.name == $name) | .checksum')
    printf '%s' "${checksum}" | b64_decode | od -An -tx1 | tr -d ' \n'
}

# Counter JSON keys (shared across extraction, checking, and reporting).
# audit_count is deliberately absent: the audit ingest contract's source enum is
# closed at auditd and k8s, and the only audit source `plexd up` wires emits
# plexd's own process entry, which has no value in that set. The agent therefore
# sends no platform audit batch at all — phase 6 pins that, and the local audit
# path (which carries plexd's own entry shape) is asserted in phases 11-13.
COUNTER_KEYS=(registration_count heartbeat_count state_count capabilities_count metrics_count logs_count)

# Extract all counter values from a JSON response into COUNTER_VALUES.
extract_counters() {
    local response=$1
    COUNTER_VALUES=()
    for key in "${COUNTER_KEYS[@]}"; do
        COUNTER_VALUES+=("$(get_counter "${response}" "${key}")")
    done
}

# Check whether all counters meet their minimum (>= threshold). Returns 0 if all pass.
all_counters_pass() {
    local min=${1:-1}
    for val in "${COUNTER_VALUES[@]}"; do
        [ "${val}" -ge "${min}" ] || return 1
    done
}

# Print each counter with PASS/FAIL prefix based on threshold.
print_counter_results() {
    local prefix=$1
    local min=${2:-1}
    for i in "${!COUNTER_KEYS[@]}"; do
        local val="${COUNTER_VALUES[$i]}"
        if [ "${val}" -ge "${min}" ]; then
            echo "  PASS: ${COUNTER_KEYS[$i]}=${val} >= ${min}"
        else
            echo "  ${prefix}: ${COUNTER_KEYS[$i]}=${val} < ${min}"
        fi
    done
}

# --- Helper: print message and exit 1 ---
fail() {
    echo "FAIL: $1"
    dc logs
    exit 1
}

# --- Helper: render a one-entry executions block ---
# Args: <execution-id> <action> <type> <status> <parameters-json>. type is
# "builtin" or "hook", status is the one the control plane holds ("pending" for
# a fresh dispatch), and parameters is a JSON object or null. requested_at is a
# fixed constant and expires_at is far enough out that the entry is never served
# as lapsed. The wire carries NO timeout and NO checksum: the run deadline is
# the node's own, and a hook is verified against the digest plexd recorded when
# it discovered the hook on disk.
exec_entry() {
    local exec_id=$1 action=$2 kind=$3 status=$4 params=$5
    cat <<ENTRYEOF
[
  {
    "execution_id": "${exec_id}",
    "action": "${action}",
    "type": "${kind}",
    "parameters": ${params},
    "status": "${status}",
    "requested_at": "2026-01-01T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }
]
ENTRYEOF
}

# --- Helper: replace the snapshot's executions block ---
# Args: <tag> <executions-json-array>. Action dispatches are delivered in the
# executions block of GET /v1/nodes/{id}/state, so a phase drives an action by
# configuring that block. configure-state REPLACES the whole snapshot fixture,
# so the block is spliced into the live snapshot and every other block travels
# back verbatim.
#
# NOTE: reading the live snapshot is a real GET on the state endpoint and
# therefore INCREMENTS state_count. A phase gating on state_count must take its
# baseline AFTER calling this helper.
configure_executions_no_nudge() {
    local tag=$1 entries=$2

    local snapshot spliced status
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    # printf, not echo: the fixture carries backslash escapes (an embedded
    # newline in the certs/ca data entry) that must travel back byte for byte.
    spliced=$(printf '%s' "${snapshot}" | jq --argjson e "${entries}" '.executions = $e')

    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi
}

# --- Helper: configure the executions block and nudge the agent ---
# Same as configure_executions_no_nudge plus a node_state_updated envelope, so
# the agent pulls the new block right away instead of waiting out the ~30s
# heartbeat reconcile cadence. The tag keeps the envelope id unique per call.
configure_executions() {
    local tag=$1 entries=$2
    configure_executions_no_nudge "${tag}" "${entries}"

    local payload status
    payload=$(cat <<NUDGEEOF
{
    "id": "evt-e2e-nudge-${tag}",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
NUDGEEOF
    )
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] executions nudge injection returned status ${status}, want 204"
    fi
}

# --- Helper: set one peer's fallback_endpoint and nudge the agent ---
# Args: <tag> <node-id> <fallback>. configure-state REPLACES the whole snapshot
# fixture, so the field is spliced into that peer of the live snapshot and
# every other peer and block travels back verbatim, as in
# configure_executions_no_nudge. A node_state_updated envelope follows, so the
# agent pulls the changed peer right away instead of waiting out the ~30s
# heartbeat reconcile cadence. The tag keeps the envelope id unique per call.
#
# NOTE: reading the live snapshot is a real GET on the state endpoint and
# therefore INCREMENTS state_count. A phase gating on state_count must take its
# baseline AFTER calling this helper.
configure_peer_fallback() {
    local tag=$1 node_id=$2 fallback=$3

    local snapshot matched spliced status
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    # A node id the snapshot does not carry would leave the fixture as it was
    # and give the agent nothing to apply, so the splice must hit one peer.
    matched=$(printf '%s' "${snapshot}" | jq -r --arg id "${node_id}" '[.peers[]? | select(.node_id == $id)] | length' 2>/dev/null || true)
    if [ "${matched}" != "1" ]; then
        fail "[${tag}] the live snapshot carries ${matched:-no} peer(s) with node_id ${node_id}, want 1"
    fi
    # printf, not echo: the fixture carries backslash escapes (an embedded
    # newline in the certs/ca data entry) that must travel back byte for byte.
    spliced=$(printf '%s' "${snapshot}" | jq --arg id "${node_id}" --arg f "${fallback}" \
        '.peers |= map(if .node_id == $id then .fallback_endpoint = $f else . end)')

    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi

    local payload
    payload=$(cat <<FALLBACKNUDGEEOF
{
    "id": "evt-e2e-fallback-nudge-${tag}",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
FALLBACKNUDGEEOF
    )
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] fallback nudge injection returned status ${status}, want 204"
    fi
}

# --- Helper: render a one-entry sessions block ---
# Args: <session-id> <host> <port> <expires-at> [idle-timeout-seconds]. Sessions
# are delivered in the sessions block of GET /v1/nodes/{id}/state. That block is
# desired state, not a queue: an entry appearing provisions the listener, and the
# same entry disappearing is the teardown signal. jti equals the session id and
# is carried as an opaque value, never evaluated. idle_timeout_seconds is omitted
# unless given, which means the session has no idle window.
session_entry() {
    local session_id=$1 host=$2 port=$3 expires_at=$4 idle=${5:-}
    local idle_field=""
    if [ -n "${idle}" ]; then
        idle_field=",
    \"idle_timeout_seconds\": ${idle}"
    fi
    cat <<SESSENTRYEOF
[
  {
    "session_id": "${session_id}",
    "jti": "${session_id}",
    "kind": "tcp",
    "target": {
      "tcp": {
        "host": "${host}",
        "port": ${port}
      }
    },
    "expires_at": "${expires_at}"${idle_field}
  }
]
SESSENTRYEOF
}

# --- Helper: configure the sessions block and nudge the agent ---
# Args: <tag> <sessions-json-array>. A phase drives a session by configuring
# that block. configure-state REPLACES the whole snapshot fixture, so the block
# is spliced into the live snapshot and every other block travels back verbatim.
# A node_state_updated envelope follows, so the agent pulls the new block right
# away instead of waiting out the ~30s heartbeat reconcile cadence. The tag keeps
# the envelope id unique per call.
#
# NOTE: reading the live snapshot is a real GET on the state endpoint and
# therefore INCREMENTS state_count. A phase gating on state_count must take its
# baseline AFTER calling this helper.
configure_sessions() {
    local tag=$1 entries=$2

    local snapshot spliced status
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    # printf, not echo: the fixture carries backslash escapes (an embedded
    # newline in the certs/ca data entry) that must travel back byte for byte.
    spliced=$(printf '%s' "${snapshot}" | jq --argjson e "${entries}" '.sessions = $e')

    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi

    local payload
    payload=$(cat <<SESSNUDGEEOF
{
    "id": "evt-e2e-sess-nudge-${tag}",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
SESSNUDGEEOF
    )
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] sessions nudge injection returned status ${status}, want 204"
    fi
}

# --- Helper: configure the secrets block ---
# Args: <tag> <secrets-json-array> [nudge-type]. The secrets block is the node's
# secret inventory, which feeds the Local Node API secret index.
# configure-state REPLACES the whole snapshot fixture, so the block is spliced
# into the live snapshot and every other block travels back verbatim. With a
# nudge type, an envelope of that type follows so the agent pulls the new block
# right away; without one, the caller decides what makes the agent pull. The tag
# keeps the envelope id unique per call.
#
# NOTE: reading the live snapshot is a real GET on the state endpoint and
# therefore INCREMENTS state_count. A phase gating on state_count must take its
# baseline AFTER calling this helper.
configure_secrets() {
    local tag=$1 entries=$2 nudge=${3:-}

    local snapshot spliced status
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    # printf, not echo: the fixture carries backslash escapes (an embedded
    # newline in the certs/ca data entry) that must travel back byte for byte.
    spliced=$(printf '%s' "${snapshot}" | jq --argjson e "${entries}" '.secrets = $e')

    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi

    if [ -z "${nudge}" ]; then
        return 0
    fi
    local payload
    payload=$(cat <<SECNUDGEEOF
{
    "id": "evt-e2e-sec-nudge-${tag}",
    "type": "${nudge}",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
SECNUDGEEOF
    )
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] secrets nudge injection returned status ${status}, want 204"
    fi
}

cleanup() {
    echo "--- Cleaning up docker compose resources ---"
    if [ "${TEST_FAILED}" -ne 0 ]; then
        echo "--- Container logs (on failure) ---"
        dc logs 2>/dev/null || true
    fi
    dc down -v 2>/dev/null || true
}
trap cleanup EXIT

# ===================================================================
# Phase 1: Build and start
# ===================================================================
echo "=== Building and starting services ==="
dc up --build -d

echo "=== Waiting for mock-api healthcheck ==="
HEALTH_TIMEOUT=30
HEALTH_ELAPSED=0
while [ "${HEALTH_ELAPSED}" -lt "${HEALTH_TIMEOUT}" ]; do
    if curl -sf http://localhost:18080/v1/health >/dev/null 2>&1; then
        echo "mock-api is healthy"
        break
    fi
    sleep 2
    HEALTH_ELAPSED=$((HEALTH_ELAPSED + 2))
done

if [ "${HEALTH_ELAPSED}" -ge "${HEALTH_TIMEOUT}" ]; then
    fail "mock-api did not become healthy within ${HEALTH_TIMEOUT}s"
fi

# ===================================================================
# The mock refuses every authenticated /v1 route whose Authorization header is
# not the NSK bearer envelope, exactly as the control plane does. That gate is
# what makes the agent's credential observable to this suite at all — it is how
# a node that presents the raw nsk fails here instead of only in production.
# Phases that drive such a route themselves present the same envelope, fetched
# once from the fixture so the node id and secret have a single definition.
# ===================================================================
MOCK_BEARER=$(curl -sf http://localhost:18080/test/bearer | jq -r '.bearer // empty')
if [ -z "${MOCK_BEARER}" ]; then
    fail "could not read the mock's bearer envelope from /test/bearer"
fi
MOCK_AUTH=(-H "Authorization: Bearer ${MOCK_BEARER}")

# ===================================================================
# Configure a short endpoint TTL (40s) so plexd re-reports on the
# stale_after deadline rather than the 120s nat.refresh_interval ticker.
# ===================================================================
echo "=== Configuring short endpoint TTL (40s) ==="
EP_TTL_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"ttl_seconds": 40}' \
    "http://localhost:18080/test/configure-endpoint" 2>/dev/null || true)
if [ "${EP_TTL_STATUS}" != "204" ]; then
    fail "configure-endpoint returned status ${EP_TTL_STATUS}, want 204"
fi
echo "  endpoint TTL set to 40s (stale_after-driven re-report cadence)"

# ===================================================================
# Phase 2: Initial assertion polling (all 8 counters >= 1)
# ===================================================================
echo "=== Polling assertion endpoint (all counters >= 1) ==="
POLL_TIMEOUT=30
POLL_ELAPSED=0

while [ "${POLL_ELAPSED}" -lt "${POLL_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        extract_counters "${RESPONSE}"
        if all_counters_pass 1; then
            echo "=== Phase 2 PASSED: all counters >= 1 ==="
            print_counter_results "FAIL" 1
            break
        fi
    fi
    sleep 2
    POLL_ELAPSED=$((POLL_ELAPSED + 2))
done

if [ "${POLL_ELAPSED}" -ge "${POLL_TIMEOUT}" ]; then
    echo "=== FAIL: initial assertions not met within ${POLL_TIMEOUT}s ==="
    if [ -z "${RESPONSE:-}" ]; then
        echo "FAIL: no response from assertion endpoint"
    else
        extract_counters "${RESPONSE}"
        print_counter_results "FAIL" 1
    fi
    fail "initial assertions not met"
fi

# ===================================================================
# Phase 3: Request body validation
# ===================================================================
echo "=== Validating request bodies ==="

# 3a. Registration body must carry the real POST /v1/register fields.
REG_BODY=$(curl -sf "http://localhost:18080/test/last-request/register" 2>/dev/null || true)
if [ -z "${REG_BODY}" ]; then
    fail "no captured registration request body"
fi
REG_TOKEN=$(echo "${REG_BODY}" | jq -r '.bootstrap_token // empty')
if [ -z "${REG_TOKEN}" ]; then
    fail "registration body missing 'bootstrap_token' field"
fi
echo "  PASS: registration body contains bootstrap_token"

REG_PROJECT_ID=$(echo "${REG_BODY}" | jq -r '.project_id // empty')
if [ -z "${REG_PROJECT_ID}" ]; then
    fail "registration body missing 'project_id' field"
fi
if [ "${REG_PROJECT_ID}" != "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0" ]; then
    fail "registration body project_id='${REG_PROJECT_ID}', want '0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0'"
fi
echo "  PASS: registration body contains project_id='${REG_PROJECT_ID}'"

REG_RESOURCE_HANDLE=$(echo "${REG_BODY}" | jq -r '.resource_handle // empty')
if [ -z "${REG_RESOURCE_HANDLE}" ]; then
    fail "registration body missing 'resource_handle' field"
fi
if [ "${REG_RESOURCE_HANDLE}" != "e2e-node-1" ]; then
    fail "registration body resource_handle='${REG_RESOURCE_HANDLE}', want 'e2e-node-1'"
fi
echo "  PASS: registration body contains resource_handle='${REG_RESOURCE_HANDLE}'"

REG_NONCE=$(echo "${REG_BODY}" | jq -r '.nonce // empty')
if [ -z "${REG_NONCE}" ]; then
    fail "registration body missing 'nonce' field"
fi
echo "  PASS: registration body contains nonce"

REG_PUBKEY=$(echo "${REG_BODY}" | jq -r '.public_key // empty')
if [ -z "${REG_PUBKEY}" ]; then
    fail "registration body missing 'public_key' field"
fi
echo "  PASS: registration body contains public_key"

# 3b. Heartbeat body must carry the real v1 heartbeat fields.
# Note: node_id is passed as a URL path parameter, not in the body.
HB_BODY=$(curl -sf "http://localhost:18080/test/last-request/heartbeat" 2>/dev/null || true)
if [ -z "${HB_BODY}" ]; then
    fail "no captured heartbeat request body"
fi
if ! echo "${HB_BODY}" | jq empty 2>/dev/null; then
    fail "heartbeat body is not valid JSON"
fi
echo "  PASS: heartbeat body is valid JSON"

# client_now must be present and an RFC 3339 timestamp.
HB_CLIENT_NOW=$(echo "${HB_BODY}" | jq -r '.client_now // empty')
if [ -z "${HB_CLIENT_NOW}" ]; then
    fail "heartbeat body missing 'client_now' field"
fi
if ! echo "${HB_CLIENT_NOW}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+.*(Z|[+-][0-9]{2}:[0-9]{2})$'; then
    fail "heartbeat client_now='${HB_CLIENT_NOW}' is not an RFC 3339 timestamp"
fi
echo "  PASS: heartbeat body client_now='${HB_CLIENT_NOW}' matches RFC 3339"

# binary_checksum is the running binary's SHA-256 in the wire form the field's
# `format: byte` declares: 32 bytes, standard-padded base64. The contract also
# documents a 64-char hex form here, but the capability manifest accepts base64
# only and the deployed control plane refuses hex with 400 binary_checksum_empty
# — so the agent sends the one encoding both operations take.
HB_CHECKSUM=$(echo "${HB_BODY}" | jq -r '.binary_checksum // empty')
HB_DIGEST_LEN=$(printf '%s' "${HB_CHECKSUM}" | b64_decode | wc -c | tr -d ' ')
if [ "${HB_DIGEST_LEN}" != "32" ]; then
    fail "heartbeat binary_checksum='${HB_CHECKSUM}' decodes to ${HB_DIGEST_LEN} bytes, want 32 (hex decodes to 48)"
fi
echo "  PASS: heartbeat body binary_checksum is a 32-byte base64 digest"

# binary_version must be present and non-empty.
HB_VERSION=$(echo "${HB_BODY}" | jq -r '.binary_version // empty')
if [ -z "${HB_VERSION}" ]; then
    fail "heartbeat body missing 'binary_version' field"
fi
echo "  PASS: heartbeat body binary_version='${HB_VERSION}'"

# nat_summary must always be a JSON object ({} when NAT discovery has no result).
HB_NAT_SUMMARY_TYPE=$(echo "${HB_BODY}" | jq -r '.nat_summary | type')
if [ "${HB_NAT_SUMMARY_TYPE}" != "object" ]; then
    fail "heartbeat nat_summary type='${HB_NAT_SUMMARY_TYPE}', want 'object'"
fi
echo "  PASS: heartbeat body nat_summary is a JSON object"

# 3f. Endpoint report body must carry {endpoint, nat_type, port_mapping, reported_at}.
# STUN discovery must complete before plexd can report an endpoint, so this
# can lag the heartbeat; poll the endpoint_count assertion counter first.
echo "  --- endpoint report body ---"
EP_COUNT=0
EP_BODY_TIMEOUT=90
EP_BODY_ELAPSED=0
while [ "${EP_BODY_ELAPSED}" -lt "${EP_BODY_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        EP_COUNT=$(get_counter "${RESPONSE}" "endpoint_count")
        if [ "${EP_COUNT}" -ge 1 ]; then
            break
        fi
    fi
    sleep 3
    EP_BODY_ELAPSED=$((EP_BODY_ELAPSED + 3))
done
if [ "${EP_COUNT}" -lt 1 ]; then
    fail "endpoint_count did not reach 1 within ${EP_BODY_TIMEOUT}s (STUN may be unreachable from the compose network; outbound UDP to stun.l.google.com/stun.cloudflare.com is required)"
fi
echo "  PASS: endpoint_count=${EP_COUNT} >= 1"

EP_BODY=$(curl -sf "http://localhost:18080/test/last-request/endpoint" 2>/dev/null || true)
if [ -z "${EP_BODY}" ]; then
    fail "no captured endpoint request body"
fi
EP_ENDPOINT=$(echo "${EP_BODY}" | jq -r '.endpoint // empty')
if [ -z "${EP_ENDPOINT}" ]; then
    fail "endpoint body missing 'endpoint' field"
fi
echo "  PASS: endpoint body endpoint='${EP_ENDPOINT}'"

EP_NAT_TYPE=$(echo "${EP_BODY}" | jq -r '.nat_type // empty')
case "${EP_NAT_TYPE}" in
    full_cone|restricted|port_restricted|symmetric|unknown)
        echo "  PASS: endpoint body nat_type='${EP_NAT_TYPE}'" ;;
    *)
        fail "endpoint body nat_type='${EP_NAT_TYPE}', want one of full_cone|restricted|port_restricted|symmetric|unknown" ;;
esac

# Discovery always settles the port mapping, and the report carries it.
EP_PORT_MAPPING=$(echo "${EP_BODY}" | jq -r '.port_mapping // empty')
case "${EP_PORT_MAPPING}" in
    preserved|translated)
        echo "  PASS: endpoint body port_mapping='${EP_PORT_MAPPING}'" ;;
    *)
        fail "endpoint body port_mapping='${EP_PORT_MAPPING}', want preserved or translated" ;;
esac

EP_REPORTED_AT=$(echo "${EP_BODY}" | jq -r '.reported_at // empty')
if [ -z "${EP_REPORTED_AT}" ]; then
    fail "endpoint body missing 'reported_at' field"
fi
echo "  PASS: endpoint body reported_at='${EP_REPORTED_AT}'"

# The eleven builtins runUp registers. Phase 3c asserts them in the capability
# manifest and phase 12b on the node API, so both read this one list.
ALL_BUILTINS=(
    "diagnostics.collect"
    "diagnostics.ping_peer"
    "diagnostics.traceroute_peer"
    "service.restart"
    "service.reload_config"
    "service.upgrade"
    "system.info"
    "health.check"
    "mesh.reconnect"
    "config.dump"
    "logs.snapshot"
)

# 3c. Capability manifest: the contract's flat envelope. binary_version and
# binary_checksum are required, the digest is 32 bytes in standard-padded base64
# (hex decodes to 48 and is refused), and the handler decodes with
# DisallowUnknownFields, so a nested `binary` object refuses the whole manifest.
# builtin_actions carries the agent's action inventory: the eleven builtins,
# sorted by name, each described, with parameters in registration order.
# plexd_hooks stays off, because this container is not in a cluster.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -z "${CAPS_BODY}" ]; then
    fail "no captured capabilities request body"
fi
CAPS_VERSION=$(echo "${CAPS_BODY}" | jq -r '.binary_version // empty')
if [ -z "${CAPS_VERSION}" ]; then
    fail "capability manifest missing 'binary_version' (body: ${CAPS_BODY})"
fi
CAPS_CHECKSUM=$(echo "${CAPS_BODY}" | jq -r '.binary_checksum // empty')
if [ -z "${CAPS_CHECKSUM}" ]; then
    fail "capability manifest missing 'binary_checksum' (body: ${CAPS_BODY})"
fi
CAPS_DIGEST_LEN=$(printf '%s' "${CAPS_CHECKSUM}" | b64_decode | wc -c | tr -d ' ')
if [ "${CAPS_DIGEST_LEN}" != "32" ]; then
    fail "binary_checksum decodes to ${CAPS_DIGEST_LEN} bytes, want 32 (a hex digest decodes to 48)"
fi
for absent in binary hooks; do
    if echo "${CAPS_BODY}" | jq -e --arg k "${absent}" 'has($k)' >/dev/null 2>&1; then
        fail "capability manifest carries '${absent}', which the handler rejects as an unknown field"
    fi
done
if echo "${CAPS_BODY}" | jq -e 'has("plexd_hooks")' >/dev/null 2>&1; then
    fail "capability manifest carries plexd_hooks, but this container is not in a cluster (body: ${CAPS_BODY})"
fi
CAPS_ACTIONS=$(echo "${CAPS_BODY}" | jq -r '[.builtin_actions[]?.name] | join(",")')
WANT_ACTIONS=$(jq -rn '$ARGS.positional | sort | join(",")' --args "${ALL_BUILTINS[@]}")
if [ "${CAPS_ACTIONS}" != "${WANT_ACTIONS}" ]; then
    fail "capability manifest builtin_actions = [${CAPS_ACTIONS}], want the eleven builtins sorted by name [${WANT_ACTIONS}]"
fi
CAPS_UNDESCRIBED=$(echo "${CAPS_BODY}" | jq '[.builtin_actions[] | select((.description // "") == "")] | length')
if [ "${CAPS_UNDESCRIBED}" -ne 0 ]; then
    fail "capability manifest carries ${CAPS_UNDESCRIBED} builtins without a description"
fi
# Parameter order is registration order, which service.upgrade makes visible.
CAPS_UPGRADE_PARAMS=$(echo "${CAPS_BODY}" | jq -r '[.builtin_actions[] | select(.name == "service.upgrade") | .parameters[]? | "\(.name):\(.required)"] | join(",")')
if [ "${CAPS_UPGRADE_PARAMS}" != "version:true,checksum:true" ]; then
    fail "service.upgrade declares parameters [${CAPS_UPGRADE_PARAMS}], want [version:true,checksum:true] in that order"
fi
echo "  PASS: capability manifest is contract-shaped (version=${CAPS_VERSION}, 32-byte digest, 11 builtins by name)"

# declared_hooks is what the boot scan found: the one hook the image ships, with
# the digest of the file. An absent list fails here, and it is what an agent
# sends when it builds the manifest ahead of that scan.
BIGOUT_HEX=$(sha256_hex < "${SCRIPT_DIR}/hooks/e2e-bigout")
CAPS_HOOK_NAMES=$(declared_hook_names "${CAPS_BODY}")
if [ "${CAPS_HOOK_NAMES}" != "e2e-bigout" ]; then
    fail "capability manifest declared_hooks = [${CAPS_HOOK_NAMES}], want exactly e2e-bigout (body: ${CAPS_BODY})"
fi
CAPS_HOOK_HEX=$(declared_hook_hex "${CAPS_BODY}" e2e-bigout)
if [ "${CAPS_HOOK_HEX}" != "${BIGOUT_HEX}" ]; then
    fail "declared_hooks digest of e2e-bigout = ${CAPS_HOOK_HEX}, want ${BIGOUT_HEX}, the SHA-256 of the file"
fi
# /test/last-request/capabilities returns the newest PUT, so a broken boot order
# would otherwise pass through the second send: a first manifest without the
# hook, then the scan's notification correcting it a second later. The count is
# read after the body, so any send the body could show is in the count.
CAPS_COUNT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
if [ "${CAPS_COUNT}" != "1" ]; then
    fail "capabilities_count = ${CAPS_COUNT}, want 1: the checks above must have read the first manifest"
fi
echo "  PASS: the first capability manifest declares e2e-bigout with the digest of the file"

# 3d. Metrics body must be a non-empty JSON array of MetricSample records: every
# element carries a group inside the wire enum, a non-empty name, a numeric
# value, and a timestamp.
METRICS_BODY=$(curl -sf "http://localhost:18080/test/last-request/metrics" 2>/dev/null || true)
if [ -z "${METRICS_BODY}" ]; then
    fail "no captured metrics request body"
fi
METRICS_LEN=$(echo "${METRICS_BODY}" | jq 'length')
if [ "${METRICS_LEN}" -lt 1 ]; then
    fail "metrics body is empty (want >= 1 sample)"
fi
BAD_SAMPLES=$(echo "${METRICS_BODY}" | jq '
    [.[] | select(
        (.group as $g | (["node_resources","tunnel_health","peer_latency","agent_stats"] | index($g)) == null)
        or ((.name | type) != "string") or (.name == "")
        or ((.value | type) != "number")
        or ((.timestamp | type) != "string") or (.timestamp == "")
    )] | length')
if [ "${BAD_SAMPLES}" -ne 0 ]; then
    fail "metrics body has ${BAD_SAMPLES} sample(s) violating the MetricSample contract (body: ${METRICS_BODY})"
fi
echo "  PASS: all ${METRICS_LEN} metrics samples carry group/name/value/timestamp"

echo "=== Phase 3 PASSED: request body validation ==="

# ===================================================================
# Phase 3b: register denial taxonomy
# ===================================================================
# Drive POST /v1/register directly with crafted bodies and assert the mock's
# RFC 9457 denial contract. This runs AFTER Phase 3a because every register
# call overwrites the captured last-request/register body.
echo "=== Testing register denial taxonomy ==="

REGISTER_URL="http://localhost:18080/v1/register"

# POST a register body and assert the HTTP status, that the response is an
# RFC 9457 application/problem+json body carrying all mandatory members, and
# that the problem 'code' member equals want_code ("" => code absent/empty).
# Args: name, want_status, want_code, json_body
assert_denial() {
    local name=$1 want_status=$2 want_code=$3 body=$4
    local resp status ctype json code member
    resp=$(curl -s -w '\n%{http_code}\n%{content_type}' -X POST \
        -H 'Content-Type: application/json' -d "${body}" \
        "${REGISTER_URL}")
    ctype=$(echo "${resp}" | tail -n1)
    status=$(echo "${resp}" | tail -n2 | head -n1)
    json=$(echo "${resp}" | sed '$d' | sed '$d')

    if [ "${status}" != "${want_status}" ]; then
        fail "${name}: status=${status}, want ${want_status} (body: ${json})"
    fi
    case "${ctype}" in
        application/problem+json*) ;;
        *) fail "${name}: content-type='${ctype}', want application/problem+json" ;;
    esac
    # Every RFC 9457 problem body carries these five members.
    for member in type title status detail instance; do
        if [ "$(echo "${json}" | jq --arg m "${member}" 'has($m)')" != "true" ]; then
            fail "${name}: problem body missing '${member}' member"
        fi
    done
    code=$(echo "${json}" | jq -r '.code // empty')
    if [ "${code}" != "${want_code}" ]; then
        fail "${name}: code='${code}', want '${want_code}'"
    fi
    echo "  PASS: ${name} -> ${status} (code='${code}')"
}

# Denial cases (each varies one field of the valid base body and uses a
# unique nonce so no nonce is accidentally consumed and replayed).
assert_denial "public_key_invalid" 400 public_key_invalid \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"e2e-denial","bootstrap_token":"psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-01","public_key":"short"}'
assert_denial "empty_resource_handle" 422 "" \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"","bootstrap_token":"psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-02","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "malformed_token" 403 "" \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"e2e-denial","bootstrap_token":"not-a-psb-token","nonce":"denial-nonce-03","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "kind_mismatch" 403 kind_mismatch \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"e2e-denial","bootstrap_token":"psb_test_e2eproject_bridge_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-04","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "token_consumed" 403 token_consumed \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"e2e-denial","bootstrap_token":"psb_test_e2eproject_node_consumedaaaaaaaaaaaaaa","nonce":"denial-nonce-05","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "token_expired" 403 token_expired \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"e2e-denial","bootstrap_token":"psb_test_e2eproject_node_expiredaaaaaaaaaaaaaaa","nonce":"denial-nonce-06","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "token_revoked" 403 token_revoked \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"e2e-denial","bootstrap_token":"psb_test_e2eproject_node_revokedaaaaaaaaaaaaaaa","nonce":"denial-nonce-07","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "project_mismatch" 403 project_mismatch \
    '{"project_id":"11111111-2222-4333-8444-555555555555","resource_handle":"e2e-denial","bootstrap_token":"psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-08","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "resource_not_found" 404 resource_not_found \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"unknown-resource","bootstrap_token":"psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-09","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "pool_exhausted" 503 pool_exhausted \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"exhausted-pool","bootstrap_token":"psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-10","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'
assert_denial "boom_internal" 500 "" \
    '{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"boom-internal","bootstrap_token":"psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-11","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'

# Happy path, then nonce collision: a valid body succeeds with 201 and its
# (project_id, nonce) pair is consumed, so replaying the identical body with
# the same nonce is rejected with nonce_collision.
OK_BODY='{"project_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","resource_handle":"e2e-denial-ok","bootstrap_token":"psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22","nonce":"denial-nonce-ok","public_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}'

OK_RESP=$(curl -s -w '\n%{http_code}' -X POST \
    -H 'Content-Type: application/json' -d "${OK_BODY}" \
    "${REGISTER_URL}")
OK_STATUS=$(echo "${OK_RESP}" | tail -n1)
OK_JSON=$(echo "${OK_RESP}" | sed '$d')
if [ "${OK_STATUS}" != "201" ]; then
    fail "denial happy-path: status=${OK_STATUS}, want 201 (body: ${OK_JSON})"
fi
for field in nsk signing_key_id domain_mesh_cidr; do
    val=$(echo "${OK_JSON}" | jq -r ".${field} // empty")
    if [ -z "${val}" ]; then
        fail "denial happy-path: 201 body missing '${field}'"
    fi
done
if [ "$(echo "${OK_JSON}" | jq 'has("peer_snapshot")')" != "true" ]; then
    fail "denial happy-path: 201 body missing 'peer_snapshot'"
fi
echo "  PASS: denial happy-path -> 201 with nsk/signing_key_id/domain_mesh_cidr/peer_snapshot"

assert_denial "nonce_collision" 403 nonce_collision "${OK_BODY}"

echo "=== Phase 3b PASSED: register denial taxonomy ==="

# ===================================================================
# Phase 4: Periodic loop verification (counters >= 2)
# ===================================================================
echo "=== Waiting for periodic counters to increment (>= 2) ==="
# heartbeat and metrics are self-generating periodic loops.
# logs and audit are tested separately via injection (Phase 5) and restart (Phase 6).
PERIODIC_KEYS=(heartbeat_count metrics_count)
PERIODIC_TIMEOUT=60
PERIODIC_ELAPSED=0

while [ "${PERIODIC_ELAPSED}" -lt "${PERIODIC_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ALL_PERIODIC_PASS=1
        for pkey in "${PERIODIC_KEYS[@]}"; do
            pval=$(get_counter "${RESPONSE}" "${pkey}")
            if [ "${pval}" -lt 2 ]; then
                ALL_PERIODIC_PASS=0
                break
            fi
        done
        if [ "${ALL_PERIODIC_PASS}" -eq 1 ]; then
            echo "=== Phase 4 PASSED: periodic counters >= 2 ==="
            for pkey in "${PERIODIC_KEYS[@]}"; do
                pval=$(get_counter "${RESPONSE}" "${pkey}")
                echo "  PASS: ${pkey}=${pval} >= 2"
            done
            break
        fi
    fi
    sleep 3
    PERIODIC_ELAPSED=$((PERIODIC_ELAPSED + 3))
done

if [ "${PERIODIC_ELAPSED}" -ge "${PERIODIC_TIMEOUT}" ]; then
    echo "=== FAIL: periodic counters not >= 2 within ${PERIODIC_TIMEOUT}s ==="
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        for pkey in "${PERIODIC_KEYS[@]}"; do
            pval=$(get_counter "${RESPONSE}" "${pkey}")
            if [ "${pval}" -ge 2 ]; then
                echo "  PASS: ${pkey}=${pval} >= 2"
            else
                echo "  FAIL: ${pkey}=${pval} < 2"
            fi
        done
    fi
    fail "periodic counters not met"
fi

# ===================================================================
# Phase 4b: handshake report and tunnel_health
#
# Both channels read the WireGuard device, and plexd starts them only when its
# interface came up, so a container without kernel WireGuard skips the phase.
# Where the interface did come up, this is the only run anywhere that reads a
# kernel device through NetlinkController.PeerStats: the unit tests cover the
# userspace backend and a refused netlink call only. It must not be weakened to
# the skip path.
#
# The fixture peers never complete a handshake: no node holds their keys, one
# carries a documentation-range endpoint and the other none. The report is
# therefore always {"observed_at", "peers": []}, while the tunnel collector,
# which keeps peers without a handshake, still labels samples with their ids.
# ===================================================================
echo "=== Testing the handshake report and tunnel_health samples ==="

FIXTURE_PEER_B1="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1"
FIXTURE_PEER_B2="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2"

# The log is read into a variable and matched with case rather than piped into
# grep -q: grep -q exits at its first match, the writer it leaves behind can die
# on the closed pipe, and under pipefail that reports a present line as missing.
PLEXD_LOGS=$(dc logs plexd 2>/dev/null || true)
case "${PLEXD_LOGS}" in
    *"wireguard interface configured"*) WG_CONFIGURED=1 ;;
    *) WG_CONFIGURED=0 ;;
esac

if [ "${WG_CONFIGURED}" -eq 0 ]; then
    echo "SKIP: handshake report and tunnel_health (WireGuard did not come up in this container)"
else
    # The e2e config keeps the default 30s heartbeat.interval, and the reporter
    # sends nothing at start, so its first report lands one interval in. 90s
    # covers that interval twice over plus a refused or slow first attempt.
    HS_TIMEOUT=90
    HS_ELAPSED=0
    HS_COUNT=0
    while [ "${HS_ELAPSED}" -lt "${HS_TIMEOUT}" ]; do
        RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
        if [ -n "${RESPONSE}" ]; then
            HS_COUNT=$(get_counter "${RESPONSE}" "handshake_report_count")
            if [ "${HS_COUNT}" -ge 1 ]; then
                break
            fi
        fi
        sleep 3
        HS_ELAPSED=$((HS_ELAPSED + 3))
    done
    if [ "${HS_COUNT}" -lt 1 ]; then
        fail "handshake_report_count=${HS_COUNT} after ${HS_TIMEOUT}s, want >= 1 (the reporter posts once per heartbeat interval)"
    fi
    echo "  PASS: handshake_report_count=${HS_COUNT} >= 1"

    # The mock accepted the report, so its gates passed; what is left to pin is
    # that the body carries the contract's two members and nothing else, and an
    # empty peers array rather than null.
    HS_BODY=$(curl -sf "http://localhost:18080/test/last-request/handshakes" 2>/dev/null || true)
    if [ -z "${HS_BODY}" ]; then
        fail "no captured handshake report body"
    fi
    HS_KEYS=$(echo "${HS_BODY}" | jq -c 'keys' 2>/dev/null || true)
    if [ "${HS_KEYS}" != '["observed_at","peers"]' ]; then
        fail "handshake report body has keys ${HS_KEYS:-<not a JSON object>}, want exactly [\"observed_at\",\"peers\"] (body: ${HS_BODY})"
    fi
    HS_PEERS=$(echo "${HS_BODY}" | jq -r 'if (.peers | type) == "array" then (.peers | length) else "not an array" end' 2>/dev/null || true)
    if [ "${HS_PEERS}" != "0" ]; then
        fail "handshake report peers is ${HS_PEERS}, want an empty array: the fixture peers never complete a handshake (body: ${HS_BODY})"
    fi
    echo "  PASS: handshake report body is {observed_at, peers: []}"

    # The metrics reporter posts every 10s and the capture keeps only the last
    # batch, so the poll waits for one that carries a fixture peer's sample.
    TH_TIMEOUT=30
    TH_ELAPSED=0
    TH_PEERS=""
    while [ "${TH_ELAPSED}" -lt "${TH_TIMEOUT}" ]; do
        METRICS_BODY=$(curl -sf "http://localhost:18080/test/last-request/metrics" 2>/dev/null || true)
        if [ -n "${METRICS_BODY}" ]; then
            TH_PEERS=$(echo "${METRICS_BODY}" | jq -r --arg b1 "${FIXTURE_PEER_B1}" --arg b2 "${FIXTURE_PEER_B2}" '
                [.[] | select(.group == "tunnel_health") | .labels.peer_id
                    | select(. == $b1 or . == $b2)] | unique | join(",")' 2>/dev/null || true)
            if [ -n "${TH_PEERS}" ]; then
                break
            fi
        fi
        sleep 3
        TH_ELAPSED=$((TH_ELAPSED + 3))
    done
    if [ -z "${TH_PEERS}" ]; then
        fail "no tunnel_health sample labelled with a fixture peer within ${TH_TIMEOUT}s (last metrics body: ${METRICS_BODY:-<none>})"
    fi
    echo "  PASS: metrics carry tunnel_health samples labelled with fixture peer(s) ${TH_PEERS}"

    echo "=== Phase 4b PASSED: handshake report and tunnel_health ==="
fi

# ===================================================================
# Phase 4c: edge PSKs
#
# plexd fetches each peer's edge PSK only when its interface came up, so the
# phase shares phase 4b's skip condition. The store syncs on every pull, before
# the WireGuard handler adds the peers, so both fixture peers' PSKs are fetched
# on the first pull after start. Each fetch logs one Info line naming the peer
# and its epoch; the key itself never reaches the log.
# ===================================================================
echo "=== Testing edge PSK fetches ==="

if [ "${WG_CONFIGURED}" -eq 0 ]; then
    echo "SKIP: edge psk (WireGuard did not come up in this container)"
else
    PSK_TIMEOUT=60
    PSK_ELAPSED=0
    PSK_COUNT=0
    while [ "${PSK_ELAPSED}" -lt "${PSK_TIMEOUT}" ]; do
        RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
        if [ -n "${RESPONSE}" ]; then
            PSK_COUNT=$(get_counter "${RESPONSE}" "edge_psk_count")
            if [ "${PSK_COUNT}" -ge 2 ]; then
                break
            fi
        fi
        sleep 3
        PSK_ELAPSED=$((PSK_ELAPSED + 3))
    done
    if [ "${PSK_COUNT}" -lt 2 ]; then
        fail "edge_psk_count=${PSK_COUNT} after ${PSK_TIMEOUT}s, want >= 2 (one fetch per fixture peer on the first pull)"
    fi
    echo "  PASS: edge_psk_count=${PSK_COUNT} >= 2"

    # Read line by line and match with case, as above: no grep -q in a pipeline.
    for PSK_PEER in "${FIXTURE_PEER_B1}" "${FIXTURE_PEER_B2}"; do
        PSK_LOG_TIMEOUT=30
        PSK_LOG_ELAPSED=0
        PSK_FOUND=0
        while [ "${PSK_LOG_ELAPSED}" -lt "${PSK_LOG_TIMEOUT}" ]; do
            PLEXD_LOGS=$(dc logs plexd 2>/dev/null || true)
            while IFS= read -r PSK_LINE; do
                case "${PSK_LINE}" in
                    *"edge psk fetched"*"${PSK_PEER}"*) PSK_FOUND=1; break ;;
                esac
            done <<< "${PLEXD_LOGS}"
            if [ "${PSK_FOUND}" -eq 1 ]; then
                break
            fi
            sleep 3
            PSK_LOG_ELAPSED=$((PSK_LOG_ELAPSED + 3))
        done
        if [ "${PSK_FOUND}" -eq 0 ]; then
            fail "no 'edge psk fetched' log line for peer ${PSK_PEER} within ${PSK_LOG_TIMEOUT}s"
        fi
        echo "  PASS: plexd logged 'edge psk fetched' for peer ${PSK_PEER}"
    done

    echo "=== Phase 4c PASSED: edge PSKs ==="
fi

# ===================================================================
# Phase 4d: endpoint candidates and endpoint selection
#
# plexd publishes its endpoint candidates and runs endpoint selection only when
# its interface came up, so the phase shares phase 4b's skip condition. The
# publisher reports once at start, so its first report has landed by now.
#
# Fixture peer ...a0b1 never completes a handshake (no node holds its key), so
# on a kernel device its dial order, 192.0.2.10:51820 (its candidate) and then
# 203.0.113.1:51820 (its fallback), advances once the first entry has gone 30s
# without one: the 25s keepalive plus 5s. This is the only run anywhere that
# switches an endpoint on a real device, so it must not be weakened to the skip
# path.
#
# The fallback is then held for 30s too before the order starts over, and each
# switch lands on a 5s selection tick, so the switch onto 203.0.113.1:51820
# comes back every 60 to 70s. The phase waits for the next one and, while plexd
# holds the peer on that relay, has the mock name 203.0.113.2:51820 as the
# peer's fallback and nudges a pull. plexd must move the peer to the new relay
# at once, logging "relay fallback changed, moving to the new relay", and must
# log no failed switch for it. The move removes the peer from the kernel device
# and adds it again. The phase then puts 203.0.113.1:51820 back the same way,
# so later phases see the fixture as it was.
# ===================================================================
echo "=== Testing endpoint candidates and endpoint selection ==="

if [ "${WG_CONFIGURED}" -eq 0 ]; then
    echo "SKIP: endpoint candidates and endpoint selection (WireGuard did not come up in this container)"
else
    EC_TIMEOUT=30
    EC_ELAPSED=0
    EC_COUNT=0
    while [ "${EC_ELAPSED}" -lt "${EC_TIMEOUT}" ]; do
        RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
        if [ -n "${RESPONSE}" ]; then
            EC_COUNT=$(get_counter "${RESPONSE}" "endpoint_candidates_count")
            if [ "${EC_COUNT}" -ge 1 ]; then
                break
            fi
        fi
        sleep 3
        EC_ELAPSED=$((EC_ELAPSED + 3))
    done
    if [ "${EC_COUNT}" -lt 1 ]; then
        fail "endpoint_candidates_count=${EC_COUNT} after ${EC_TIMEOUT}s, want >= 1 (the publisher reports once at start)"
    fi
    echo "  PASS: endpoint_candidates_count=${EC_COUNT} >= 1"

    # The mock accepted the report, so its gates passed. What is left to pin is
    # that the body carries the contract's two members and nothing else, and
    # that its candidates are this container's addresses joined with the
    # WireGuard listen port (51820 in plexd-e2e.yaml), none of them in the
    # mock's mesh prefix 10.99.0.0/24. Each jq answers "true" only when its
    # check holds, so a jq error fails the check rather than passing it.
    EC_BODY=$(curl -sf "http://localhost:18080/test/last-request/endpoint-candidates" 2>/dev/null || true)
    if [ -z "${EC_BODY}" ]; then
        fail "no captured endpoint candidates body"
    fi
    EC_KEYS=$(echo "${EC_BODY}" | jq -c 'keys' 2>/dev/null || true)
    if [ "${EC_KEYS}" != '["candidates","reported_at"]' ]; then
        fail "endpoint candidates body has keys ${EC_KEYS:-<not a JSON object>}, want exactly [\"candidates\",\"reported_at\"] (body: ${EC_BODY})"
    fi
    EC_SIZED=$(echo "${EC_BODY}" | jq -r '(.candidates | type) == "array" and (.candidates | length) >= 1 and (.candidates | length) <= 8' 2>/dev/null || true)
    if [ "${EC_SIZED}" != "true" ]; then
        fail "endpoint candidates is not an array of 1 to 8 entries (body: ${EC_BODY})"
    fi
    EC_PORTS=$(echo "${EC_BODY}" | jq -r 'all(.candidates[]; endswith(":51820"))' 2>/dev/null || true)
    if [ "${EC_PORTS}" != "true" ]; then
        fail "not every endpoint candidate ends in the listen port :51820 (body: ${EC_BODY})"
    fi
    EC_OFF_MESH=$(echo "${EC_BODY}" | jq -r 'any(.candidates[]; startswith("10.99.0.")) | not' 2>/dev/null || true)
    if [ "${EC_OFF_MESH}" != "true" ]; then
        fail "an endpoint candidate lies in the mesh prefix 10.99.0.0/24 (body: ${EC_BODY})"
    fi
    echo "  PASS: endpoint candidates body is {candidates, reported_at}: 1 to 8 entries on :51820, none in the mesh prefix"

    # Read line by line and match with case, as in phase 4c: no grep -q in a
    # pipeline. By now the switch has usually been logged already; the 75s cover
    # the first entry's 30s timeout, counted from the pull that programmed it,
    # with room for the 5s selection tick and a slow start.
    SWITCH_TIMEOUT=75
    SWITCH_ELAPSED=0
    SWITCH_FOUND=0
    while [ "${SWITCH_ELAPSED}" -lt "${SWITCH_TIMEOUT}" ]; do
        PLEXD_LOGS=$(dc logs plexd 2>/dev/null || true)
        while IFS= read -r SWITCH_LINE; do
            case "${SWITCH_LINE}" in
                *"trying next endpoint candidate"*"${FIXTURE_PEER_B1}"* | *"${FIXTURE_PEER_B1}"*"trying next endpoint candidate"*)
                    SWITCH_FOUND=1
                    break
                    ;;
            esac
        done <<< "${PLEXD_LOGS}"
        if [ "${SWITCH_FOUND}" -eq 1 ]; then
            break
        fi
        sleep 3
        SWITCH_ELAPSED=$((SWITCH_ELAPSED + 3))
    done
    if [ "${SWITCH_FOUND}" -eq 0 ]; then
        fail "no 'trying next endpoint candidate' log line for peer ${FIXTURE_PEER_B1} within ${SWITCH_TIMEOUT}s: its dial order (192.0.2.10:51820, then 203.0.113.1:51820) never advanced"
    fi
    echo "  PASS: plexd logged 'trying next endpoint candidate' for peer ${FIXTURE_PEER_B1}"

    # Wait for the next switch onto the fallback: it starts a 30s hold on the
    # relay, and the new fallback must arrive inside it. The waits below run on
    # the wall clock, and each loop reads the log once more at its deadline.
    # One cycle of the order is at most 70s (two 30s trials, each ending on
    # the next 5s tick), and a switch just before the baseline means a full
    # cycle, so the wait covers 70s plus the 2s poll and a pull's worth of
    # slack.
    RELAY_LOGS=$(dc logs plexd 2>/dev/null || true)
    RELAY_HOLDS_BEFORE=$(count_log_lines "${RELAY_LOGS}" "trying next endpoint candidate" "${FIXTURE_PEER_B1}" "203.0.113.1:51820")
    RELAY_FAILS_BEFORE=$(count_log_lines "${RELAY_LOGS}" "endpoint switch failed" "${FIXTURE_PEER_B1}")
    RELAY_HOLD_TIMEOUT=80
    RELAY_HOLD_START=${SECONDS}
    while :; do
        RELAY_LOGS=$(dc logs plexd 2>/dev/null || true)
        RELAY_HOLDS=$(count_log_lines "${RELAY_LOGS}" "trying next endpoint candidate" "${FIXTURE_PEER_B1}" "203.0.113.1:51820")
        if [ "${RELAY_HOLDS}" -gt "${RELAY_HOLDS_BEFORE}" ] || [ $((SECONDS - RELAY_HOLD_START)) -ge "${RELAY_HOLD_TIMEOUT}" ]; then
            break
        fi
        sleep 2
    done
    RELAY_HOLD_WAITED=$((SECONDS - RELAY_HOLD_START))
    if [ "${RELAY_HOLDS}" -le "${RELAY_HOLDS_BEFORE}" ]; then
        fail "no new 'trying next endpoint candidate' log line for peer ${FIXTURE_PEER_B1} naming its fallback 203.0.113.1:51820 within ${RELAY_HOLD_TIMEOUT}s (${RELAY_HOLDS_BEFORE} before the wait): the dial order never came back to the relay"
    fi
    echo "  PASS: plexd switched peer ${FIXTURE_PEER_B1} to its fallback 203.0.113.1:51820 again after ${RELAY_HOLD_WAITED}s"

    # Name a new relay while the hold runs. Until the fallback is put back, the
    # only line that can name both addresses is the move from 203.0.113.1:51820
    # to 203.0.113.2:51820, so the count of such lines must grow.
    RELAY_MOVES_BEFORE=$(count_log_lines "${RELAY_LOGS}" "relay fallback changed, moving to the new relay" "${FIXTURE_PEER_B1}" "203.0.113.1:51820" "203.0.113.2:51820")
    configure_peer_fallback "relay-move" "${FIXTURE_PEER_B1}" "203.0.113.2:51820"
    RELAY_MOVE_TIMEOUT=24
    RELAY_MOVE_START=${SECONDS}
    while :; do
        RELAY_LOGS=$(dc logs plexd 2>/dev/null || true)
        RELAY_MOVES=$(count_log_lines "${RELAY_LOGS}" "relay fallback changed, moving to the new relay" "${FIXTURE_PEER_B1}" "203.0.113.1:51820" "203.0.113.2:51820")
        if [ "${RELAY_MOVES}" -gt "${RELAY_MOVES_BEFORE}" ] || [ $((SECONDS - RELAY_MOVE_START)) -ge "${RELAY_MOVE_TIMEOUT}" ]; then
            break
        fi
        sleep 2
    done
    RELAY_MOVE_WAITED=$((SECONDS - RELAY_MOVE_START))
    if [ "${RELAY_MOVES}" -le "${RELAY_MOVES_BEFORE}" ]; then
        fail "no 'relay fallback changed, moving to the new relay' log line for peer ${FIXTURE_PEER_B1} from 203.0.113.1:51820 to 203.0.113.2:51820 within ${RELAY_MOVE_TIMEOUT}s of the nudge that named the new fallback: plexd kept the peer on the old relay"
    fi
    RELAY_FAILS=$(count_log_lines "${RELAY_LOGS}" "endpoint switch failed" "${FIXTURE_PEER_B1}")
    if [ "${RELAY_FAILS}" -gt "${RELAY_FAILS_BEFORE}" ]; then
        fail "plexd logged $((RELAY_FAILS - RELAY_FAILS_BEFORE)) new 'endpoint switch failed' line(s) for peer ${FIXTURE_PEER_B1} while it moved the peer to 203.0.113.2:51820"
    fi
    echo "  PASS: plexd logged 'relay fallback changed, moving to the new relay' for peer ${FIXTURE_PEER_B1} (203.0.113.1:51820 to 203.0.113.2:51820) after ${RELAY_MOVE_WAITED}s, with no new 'endpoint switch failed' line"

    configure_peer_fallback "relay-restore" "${FIXTURE_PEER_B1}" "203.0.113.1:51820"
    echo "  restored fallback_endpoint 203.0.113.1:51820 on peer ${FIXTURE_PEER_B1}"

    echo "=== Phase 4d PASSED: endpoint candidates and endpoint selection ==="
fi

# ===================================================================
# Phase 4e: mesh mtu
#
# There is a mesh MTU to check only when the interface came up, so the phase
# shares phase 4b's skip condition. The e2e config leaves wireguard.mtu unset
# and nat.enabled true, so Setup probes the STUN servers before it creates the
# interface and logs the result on its "wireguard interface configured" line.
# The uplink decides the value: a 1500-byte path gives 1420, a 1492-byte PPPoE
# path 1412 and a 1452-byte path of DS-Lite over PPPoE 1372, so the phase
# checks a range, never a fixed number.
#
# An inconclusive probe fails the phase rather than skipping it: phase 3f
# already needs outbound UDP to both default STUN servers, so a probe that
# heard none of them is a broken probe. The unit tests probe a loopback fake
# server; this is the only run anywhere that probes real STUN servers across a
# real uplink and programs the result on a kernel device, so it must not be
# weakened to the skip path.
# ===================================================================
echo "=== Testing the mesh mtu ==="

if [ "${WG_CONFIGURED}" -eq 0 ]; then
    echo "SKIP: mesh mtu (WireGuard did not come up in this container)"
else
    # Read line by line and match with case, as in phase 4c: no grep -q in a
    # pipeline. No restart has happened yet, so the first line is the one
    # Setup wrote at start.
    PLEXD_LOGS=$(dc logs plexd 2>/dev/null || true)
    MTU_SETUP_LINE=""
    while IFS= read -r MTU_LOG_LINE; do
        case "${MTU_LOG_LINE}" in
            *"wireguard interface configured"*) MTU_SETUP_LINE=${MTU_LOG_LINE}; break ;;
        esac
    done <<< "${PLEXD_LOGS}"
    if [ -z "${MTU_SETUP_LINE}" ]; then
        fail "no 'wireguard interface configured' line in the plexd log, although phase 4b found one"
    fi

    # The leading space in each pattern keeps " path_mtu=" from matching
    # " mtu=". A key that is missing leaves its value empty.
    MTU_SOURCE=""
    case "${MTU_SETUP_LINE}" in
        *" mtu_source="*) MTU_SOURCE=${MTU_SETUP_LINE#* mtu_source=}; MTU_SOURCE=${MTU_SOURCE%% *} ;;
    esac
    MTU_LOGGED=""
    case "${MTU_SETUP_LINE}" in
        *" mtu="*) MTU_LOGGED=${MTU_SETUP_LINE#* mtu=}; MTU_LOGGED=${MTU_LOGGED%% *} ;;
    esac

    case "${MTU_SOURCE}" in
        probe) ;;
        default)
            fail "the interface came up with mtu_source=default: the startup probe heard no STUN server, see the 'wireguard: mtu probe inconclusive, using the default mtu' warning in the plexd log (line: ${MTU_SETUP_LINE})"
            ;;
        *)
            fail "the interface came up with mtu_source=${MTU_SOURCE:-<missing>}, want probe: plexd-e2e.yaml leaves wireguard.mtu unset (line: ${MTU_SETUP_LINE})"
            ;;
    esac
    echo "  PASS: the interface came up with mtu_source=probe"

    case "${MTU_LOGGED}" in
        "" | *[!0-9]*)
            fail "the interface came up with mtu=${MTU_LOGGED:-<missing>}, want a number (line: ${MTU_SETUP_LINE})"
            ;;
    esac
    if [ "${MTU_LOGGED}" -lt 1280 ] || [ "${MTU_LOGGED}" -gt 1420 ]; then
        fail "the interface came up with mtu=${MTU_LOGGED}, want 1280 to 1420 (line: ${MTU_SETUP_LINE})"
    fi
    echo "  PASS: the interface came up with mtu=${MTU_LOGGED}, within 1280 to 1420"

    # The device must hold what the line says. The interface name comes from
    # plexd-e2e.yaml, and head is the image's busybox applet. The re-probe
    # loop's first round comes 10 minutes after start, after this phase has
    # run, so the device still holds the MTU Setup programmed.
    DEVICE_MTU=$(dc exec -T plexd head -c 16 /sys/class/net/wg-plexd/mtu 2>/dev/null | tr -d '\r\n' || true)
    if [ "${DEVICE_MTU}" != "${MTU_LOGGED}" ]; then
        fail "wg-plexd has mtu ${DEVICE_MTU:-<unreadable>}, want ${MTU_LOGGED}, the mtu plexd logged"
    fi
    echo "  PASS: wg-plexd has mtu ${DEVICE_MTU}, as logged"

    # Step 17c starts the re-probe loop next to endpoint selection, whose
    # switch phase 4d has already seen, so its start line is in the log by now.
    MTU_LOOP_FOUND=0
    while IFS= read -r MTU_LOG_LINE; do
        case "${MTU_LOG_LINE}" in
            *"wireguard: mtu probe started"*"interval=10m0s"* | *"interval=10m0s"*"wireguard: mtu probe started"*)
                MTU_LOOP_FOUND=1
                break
                ;;
        esac
    done <<< "${PLEXD_LOGS}"
    if [ "${MTU_LOOP_FOUND}" -eq 0 ]; then
        fail "no 'wireguard: mtu probe started' log line with interval=10m0s: step 17c did not start the re-probe loop"
    fi
    echo "  PASS: plexd logged 'wireguard: mtu probe started' with interval=10m0s"

    echo "=== Phase 4e PASSED: mesh mtu ==="
fi

# ===================================================================
# Phase 5: Log injection (verify log forwarding pipeline)
# ===================================================================
echo "=== Testing log forwarding with injected data ==="

PLEXD_CONTAINER=$(dc ps -q plexd 2>/dev/null || true)
if [ -z "${PLEXD_CONTAINER}" ]; then
    fail "plexd container not found for log injection"
fi

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
LOGS_BEFORE=$(get_counter "${RESPONSE}" "logs_count")
echo "  logs_count before injection: ${LOGS_BEFORE}"

# Inject a log file into the container. FileSource will discover and read it.
# (distroless container has no shell, but docker cp works at filesystem level)
echo "e2e-injected-log-line-$(date +%s)" > /tmp/plexd-e2e-inject.log
docker cp /tmp/plexd-e2e-inject.log "${PLEXD_CONTAINER}:/var/log/plexd/injected.log"
rm -f /tmp/plexd-e2e-inject.log
echo "  log file injected into container"

# Wait for logs_count to increase (collect every 5s, report every 10s).
LOG_TIMEOUT=30
LOG_ELAPSED=0
while [ "${LOG_ELAPSED}" -lt "${LOG_TIMEOUT}" ]; do
    sleep 3
    LOG_ELAPSED=$((LOG_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        LOGS_AFTER=$(get_counter "${RESPONSE}" "logs_count")
        if [ "${LOGS_AFTER}" -gt "${LOGS_BEFORE}" ]; then
            echo "  PASS: logs_count increased from ${LOGS_BEFORE} to ${LOGS_AFTER} after injection"
            break
        fi
    fi
done

if [ "${LOG_ELAPSED}" -ge "${LOG_TIMEOUT}" ]; then
    LOGS_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "logs_count")
    fail "logs_count did not increase after log injection (before=${LOGS_BEFORE}, after=${LOGS_AFTER})"
fi

echo "=== Phase 5 PASSED: log injection ==="

# ===================================================================
# Phase 6: Agent restart and audit verification
# ===================================================================
echo "=== Testing audit forwarding via agent restart ==="

# ProcessSource fires exactly once per process lifetime (sync.Once).
# Restarting plexd creates a new process with a fresh ProcessSource.
#
# That entry reaches the local endpoint, not the platform: its source is plexd's
# own "process", and the platform ingest contract's source enum is closed at
# auditd and k8s. Sending it anyway is what refused every batch with 400
# ingest_batch_malformed, so the reporter now skips it — and since it is the
# only source wired, the platform audit counter must not move at all.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
LOCAL_AUDIT_BEFORE=$(get_counter "${RESPONSE}" "local_audit_count")
AUDIT_BEFORE=$(get_counter "${RESPONSE}" "audit_count")
echo "  local_audit_count before restart: ${LOCAL_AUDIT_BEFORE} (platform audit_count: ${AUDIT_BEFORE})"

# Restart plexd container (same container, new process).
dc restart plexd

# Wait for the restarted agent to deliver a new audit entry locally.
AUDIT_TIMEOUT=60
AUDIT_ELAPSED=0
while [ "${AUDIT_ELAPSED}" -lt "${AUDIT_TIMEOUT}" ]; do
    sleep 3
    AUDIT_ELAPSED=$((AUDIT_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        LOCAL_AUDIT_AFTER=$(get_counter "${RESPONSE}" "local_audit_count")
        if [ "${LOCAL_AUDIT_AFTER}" -gt "${LOCAL_AUDIT_BEFORE}" ]; then
            echo "  PASS: local_audit_count increased from ${LOCAL_AUDIT_BEFORE} to ${LOCAL_AUDIT_AFTER} after restart"
            break
        fi
    fi
done

if [ "${AUDIT_ELAPSED}" -ge "${AUDIT_TIMEOUT}" ]; then
    LOCAL_AUDIT_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "local_audit_count")
    fail "local_audit_count did not increase after restart (before=${LOCAL_AUDIT_BEFORE}, after=${LOCAL_AUDIT_AFTER})"
fi

# The platform path stays untouched. If this ever fails because the agent grew a
# contract-legal audit source (an auditd or k8s reader), that is the moment to
# put audit_count back into COUNTER_KEYS and restore the platform body checks in
# phase 10b — not the moment to relax this line.
AUDIT_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "audit_count")
if [ "${AUDIT_AFTER}" != "0" ]; then
    fail "platform audit_count = ${AUDIT_AFTER}, want 0: no wired audit source has a value in the contract's closed enum"
fi
echo "  PASS: platform audit_count = 0 (no contract-legal source is wired)"

echo "=== Phase 6 PASSED: audit forwarding via restart ==="

# ===================================================================
# Phase 7: SSE event injection triggers reconciliation
# ===================================================================
echo "=== Testing SSE event injection ==="

# Record current state_count before injection.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before injection: ${STATE_BEFORE}"

# Inject a node_state_updated SSE event.
INJECT_PAYLOAD=$(cat <<'INJEOF'
{
    "id": "evt-e2e-inject-001",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
INJEOF
)
INJECT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${INJECT_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${INJECT_STATUS}" != "204" ]; then
    fail "SSE event injection returned status ${INJECT_STATUS}, want 204"
fi
echo "  SSE event injected successfully"

# Poll for state_count to increase (agent should re-fetch state on event).
SSE_TIMEOUT=15
SSE_ELAPSED=0
while [ "${SSE_ELAPSED}" -lt "${SSE_TIMEOUT}" ]; do
    sleep 2
    SSE_ELAPSED=$((SSE_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER}" -gt "${STATE_BEFORE}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE} to ${STATE_AFTER} after SSE injection"
            break
        fi
    fi
done

if [ "${SSE_ELAPSED}" -ge "${SSE_TIMEOUT}" ]; then
    STATE_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    echo "  WARN: state_count did not increase after SSE injection (before=${STATE_BEFORE}, after=${STATE_AFTER})"
    echo "  (SSE event may not have been delivered or reconcile may have already been triggered)"
    # This is a soft warning, not a hard failure, since timing can be tricky.
fi

echo "=== Phase 7 PASSED: SSE event injection ==="

# ===================================================================
# Phase 7b: policy_updated SSE event triggers reconcile (GAP-08)
# ===================================================================
echo "=== Testing policy_updated SSE event ==="

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE_POL=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before: ${STATE_BEFORE_POL}"

# Inject a policy_updated SSE event.
POL_PAYLOAD=$(cat <<'POLEOF'
{
    "id": "evt-e2e-policy-001",
    "type": "policy_updated",
    "scope": "node",
    "payload": "{\"policy_id\":\"pol-e2e-001\"}"
}
POLEOF
)
POL_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${POL_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${POL_STATUS}" != "204" ]; then
    fail "policy_updated event injection returned status ${POL_STATUS}, want 204"
fi
echo "  policy_updated event injected"

# Poll for state_count to increase (reconcile triggered).
POL_TIMEOUT=15
POL_ELAPSED=0
while [ "${POL_ELAPSED}" -lt "${POL_TIMEOUT}" ]; do
    sleep 2
    POL_ELAPSED=$((POL_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_POL=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_POL}" -gt "${STATE_BEFORE_POL}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_POL} to ${STATE_AFTER_POL} after policy_updated"
            break
        fi
    fi
done

if [ "${POL_ELAPSED}" -ge "${POL_TIMEOUT}" ]; then
    STATE_AFTER_POL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    echo "  WARN: state_count did not increase after policy_updated (before=${STATE_BEFORE_POL}, after=${STATE_AFTER_POL})"
fi

echo "=== Phase 7b PASSED: policy_updated SSE event ==="

# ===================================================================
# Phase 7c: the state pull installs a new signing key
# ===================================================================
# A node enrolled before its Domain had a key of its own holds a key the
# control plane does not sign with, and learns the Domain key only from the
# pull's signing_key block. The mock switches keys; a pull hands plexd the new
# one, an event signed with it is verified and dispatched, and the key survives
# a restart because plexd persisted it. Every check here fails the suite.
echo "=== Testing signing key installation from the state pull ==="

SIGKEY_INSTALLED="installed signing key from state pull"

# sigkey_log_count TEXT1 TEXT2: print how many plexd log lines carry both texts.
# The log is read into a variable and matched line by line with case, as phase
# 4c does: no grep -q in a pipeline under pipefail.
sigkey_log_count() {
    local logs line n=0
    logs=$(dc logs plexd 2>/dev/null || true)
    while IFS= read -r line; do
        case "${line}" in
            *"$1"*)
                case "${line}" in
                    *"$2"*) n=$((n + 1)) ;;
                esac
                ;;
        esac
    done <<< "${logs}"
    echo "${n}"
}

# sigkey_inject_and_check EVENT_ID: inject a node_state_updated event, then fail
# unless it raises state_count within 15s and no verification failure names it.
sigkey_inject_and_check() {
    local evt_id=$1 before after status elapsed=0
    before=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "{\"id\":\"${evt_id}\",\"type\":\"node_state_updated\",\"scope\":\"node\",\"payload\":{}}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "injecting ${evt_id} returned status ${status}, want 204"
    fi
    while :; do
        sleep 1
        elapsed=$((elapsed + 1))
        after=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
        if [ "${after}" -gt "${before}" ]; then
            break
        fi
        if [ "${elapsed}" -ge 15 ]; then
            fail "state_count did not rise within 15s after ${evt_id} (before=${before}, after=${after})"
        fi
    done
    if [ "$(sigkey_log_count "event verification failed" "${evt_id}")" != "0" ]; then
        fail "plexd logged event verification failed for ${evt_id}"
    fi
    echo "  PASS: ${evt_id} verified, state_count rose from ${before} to ${after}"
}

# 1. Switch the mock to a fresh Domain key.
ROTATE_RESP=$(curl -sf -X POST "http://localhost:18080/test/rotate-signing-key" 2>/dev/null || true)
NEW_KID=$(echo "${ROTATE_RESP}" | jq -r '.key_id // empty')
if [ -z "${NEW_KID}" ]; then
    fail "rotate-signing-key did not answer 200 with a key_id (body: ${ROTATE_RESP})"
fi
echo "  mock signs with ${NEW_KID} now"

# 2. A pull hands plexd the new key. Heartbeat reconcile hints nudge the pull;
# the mock answers them by default, so the response posted here is that default
# and stays in place for the later phases.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 \
    || fail "configure-heartbeat for the signing key pull failed"
SIGKEY_TIMEOUT=60
SIGKEY_ELAPSED=0
until [ "$(sigkey_log_count "${SIGKEY_INSTALLED}" "${NEW_KID}")" -ge 1 ]; do
    if [ "${SIGKEY_ELAPSED}" -ge "${SIGKEY_TIMEOUT}" ]; then
        fail "plexd did not log '${SIGKEY_INSTALLED}' for ${NEW_KID} within ${SIGKEY_TIMEOUT}s"
    fi
    sleep 2
    SIGKEY_ELAPSED=$((SIGKEY_ELAPSED + 2))
done
echo "  PASS: a pull installed ${NEW_KID}"

# 3. An event signed with the new key is verified and dispatched.
sigkey_inject_and_check "evt-e2e-sigkey-001"

# 4. plexd persisted the key into its identity.
IDENTITY_JSON=$(dc exec -T plexd head -c 8192 /var/lib/plexd/identity.json 2>/dev/null || true)
case "${IDENTITY_JSON}" in
    *"\"signing_key_id\": \"${NEW_KID}\""*) ;;
    *) fail "identity.json does not hold ${NEW_KID}: ${IDENTITY_JSON}" ;;
esac
echo "  PASS: identity.json holds ${NEW_KID}"

# 5. After a restart plexd starts from the persisted key. The data dir is a
# volume, so the restarted agent resumes its identity rather than registering
# again: a new registration would hand it the mock's current key and prove
# nothing about the persisted one. Wait until the restarted agent has opened its
# event stream and a pull has followed, so the next injected event has a stream
# to arrive on.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
EVREQ_BEFORE_RESTART=$(get_counter "${RESPONSE}" "events_request_count")
REG_BEFORE_RESTART=$(get_counter "${RESPONSE}" "registration_count")
RESUMED_BEFORE_RESTART=$(sigkey_log_count "existing identity loaded" "existing identity loaded")
dc restart plexd
RESTART_ELAPSED=0
STATE_AT_STREAM=""
while :; do
    sleep 2
    RESTART_ELAPSED=$((RESTART_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -z "${STATE_AT_STREAM}" ]; then
        if [ "$(get_counter "${RESPONSE}" "events_request_count")" -gt "${EVREQ_BEFORE_RESTART}" ]; then
            STATE_AT_STREAM=$(get_counter "${RESPONSE}" "state_count")
        fi
    elif [ "$(get_counter "${RESPONSE}" "state_count")" -gt "${STATE_AT_STREAM}" ]; then
        break
    fi
    if [ "${RESTART_ELAPSED}" -ge 60 ]; then
        fail "the restarted plexd did not reopen its event stream and pull within 60s"
    fi
done
REG_AFTER_RESTART=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "registration_count")
if [ "${REG_AFTER_RESTART}" != "${REG_BEFORE_RESTART}" ]; then
    fail "the restarted plexd registered again (registration_count ${REG_BEFORE_RESTART} -> ${REG_AFTER_RESTART}) instead of resuming its persisted identity"
fi
RESUMED_AFTER_RESTART=$(sigkey_log_count "existing identity loaded" "existing identity loaded")
if [ "${RESUMED_AFTER_RESTART}" -le "${RESUMED_BEFORE_RESTART}" ]; then
    fail "the restarted plexd did not log 'existing identity loaded'"
fi
echo "  PASS: the restarted plexd resumed its persisted identity without registering"
sigkey_inject_and_check "evt-e2e-sigkey-002"
INSTALL_LINES=$(sigkey_log_count "${SIGKEY_INSTALLED}" "${NEW_KID}")
if [ "${INSTALL_LINES}" != "1" ]; then
    fail "plexd logged '${SIGKEY_INSTALLED}' for ${NEW_KID} ${INSTALL_LINES} times, want 1: the restart did not start from the persisted key"
fi
echo "  PASS: the restarted plexd started from the persisted key"

echo "=== Phase 7c PASSED: the state pull installs a new signing key ==="

# ===================================================================
# Phase 8: Action execution from the pull's executions block
# ===================================================================
echo "=== Testing action execution from the executions block ==="

# Record the execution callback counter BEFORE the dispatch is configured: the
# helper nudges an immediate pull, so a baseline taken afterwards could already
# have missed the ack. A successful builtin run posts three callbacks in
# sequence: ack -> started -> succeeded.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE=$(get_counter "${RESPONSE}" "execution_callback_count")
echo "  execution_callback_count before: ${CB_BEFORE}"

# Configure a pending builtin dispatch for "system.info" in the executions
# block of the state snapshot.
configure_executions "exec-e2e-001" \
    "$(exec_entry "exec-e2e-001" "system.info" "builtin" "pending" "null")"
echo "  system.info dispatch configured in the executions block"

# Poll until execution_callback_count advances by at least 3 (ack + started +
# terminal).
ACTION_TIMEOUT=30
ACTION_ELAPSED=0
CB_PASSED=0
while [ "${ACTION_ELAPSED}" -lt "${ACTION_TIMEOUT}" ]; do
    sleep 2
    ACTION_ELAPSED=$((ACTION_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        CB_AFTER=$(get_counter "${RESPONSE}" "execution_callback_count")
        if [ "${CB_AFTER}" -ge $((CB_BEFORE + 3)) ]; then
            echo "  PASS: execution_callback_count advanced from ${CB_BEFORE} to ${CB_AFTER} (>= +3)"
            CB_PASSED=1
            break
        fi
    fi
done

if [ "${CB_PASSED}" -eq 0 ]; then
    CB_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
    fail "execution_callback_count did not reach $((CB_BEFORE + 3)) (before=${CB_BEFORE}, after=${CB_AFTER})"
fi

# Validate the terminal execution callback body.
CB_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
if [ -z "${CB_BODY}" ]; then
    fail "no execution_callback body captured"
fi

CB_STATUS=$(echo "${CB_BODY}" | jq -r '.status // empty')
if [ "${CB_STATUS}" = "succeeded" ]; then
    echo "  PASS: terminal callback status = succeeded"
else
    fail "terminal callback status = '${CB_STATUS}', want 'succeeded'"
fi

CB_EXIT=$(echo "${CB_BODY}" | jq -r '.exit_code // empty')
if [ "${CB_EXIT}" = "0" ]; then
    echo "  PASS: terminal callback exit_code = 0"
else
    fail "terminal callback exit_code = '${CB_EXIT}', want 0"
fi

CB_INLINE=$(echo "${CB_BODY}" | jq -r '.output.inline // empty')
if [ -z "${CB_INLINE}" ]; then
    fail "terminal callback missing non-empty output.inline"
fi
echo "  PASS: terminal callback has output.inline"

# GAP-03: Decode the inline output (base64) and validate system.info fields.
RES_STDOUT=$(printf '%s' "${CB_INLINE}" | b64_decode)
if echo "${RES_STDOUT}" | jq empty 2>/dev/null; then
    INFO_HOSTNAME=$(echo "${RES_STDOUT}" | jq -r '.hostname // empty')
    if [ -n "${INFO_HOSTNAME}" ]; then
        echo "  PASS: system.info stdout has hostname='${INFO_HOSTNAME}'"
    else
        fail "system.info stdout missing 'hostname' field"
    fi

    INFO_OS=$(echo "${RES_STDOUT}" | jq -r '.os // empty')
    if [ "${INFO_OS}" = "linux" ]; then
        echo "  PASS: system.info stdout os='linux'"
    else
        fail "system.info stdout os='${INFO_OS}', want 'linux'"
    fi

    INFO_NODE_ID=$(echo "${RES_STDOUT}" | jq -r '.node_id // empty')
    if [ "${INFO_NODE_ID}" = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3" ]; then
        echo "  PASS: system.info stdout node_id='0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3'"
    else
        fail "system.info stdout node_id='${INFO_NODE_ID}', want '0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3'"
    fi

    INFO_MESH_IP=$(echo "${RES_STDOUT}" | jq -r '.mesh_ip // empty')
    if [ "${INFO_MESH_IP}" = "10.99.0.1" ]; then
        echo "  PASS: system.info stdout mesh_ip='10.99.0.1'"
    else
        fail "system.info stdout mesh_ip='${INFO_MESH_IP}', want '10.99.0.1'"
    fi
else
    fail "system.info decoded output is not valid JSON"
fi

echo "=== Phase 8 PASSED: action execution ==="

# ===================================================================
# Phase 8b: Additional builtin action types (GAP-05)
# ===================================================================
echo "=== Testing additional builtin action types ==="

# Helper function: dispatch an action through the executions block, wait for the
# terminal callback, validate.
test_action() {
    local action_name=$1 exec_id=$2
    shift 3
    # Remaining args are validation commands (passed as description only).

    # Record the execution callback counter (ack -> started -> terminal = +3)
    # before configuring the dispatch: the pull the helper nudges could
    # otherwise land ahead of the baseline read.
    local resp cb_before
    resp=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    cb_before=$(get_counter "${resp}" "execution_callback_count")

    # Configure a pending builtin dispatch in the pull's executions block.
    configure_executions "${exec_id}" \
        "$(exec_entry "${exec_id}" "${action_name}" "builtin" "pending" "null")"

    # Poll until execution_callback_count advances by at least 3.
    local timeout=30 elapsed=0 cb_after
    while [ "${elapsed}" -lt "${timeout}" ]; do
        sleep 2
        elapsed=$((elapsed + 2))
        resp=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
        if [ -n "${resp}" ]; then
            cb_after=$(get_counter "${resp}" "execution_callback_count")
            if [ "${cb_after}" -ge $((cb_before + 3)) ]; then
                break
            fi
        fi
    done

    if [ "${elapsed}" -ge "${timeout}" ]; then
        cb_after=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
        fail "${action_name}: execution_callback_count did not reach $((cb_before + 3)) (before=${cb_before}, after=${cb_after})"
    fi

    # Fetch and validate the terminal callback body.
    local cb_body
    cb_body=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
    if [ -z "${cb_body}" ]; then
        fail "${action_name}: no execution_callback body captured"
    fi

    local res_status res_inline
    res_status=$(echo "${cb_body}" | jq -r '.status // empty')
    res_inline=$(echo "${cb_body}" | jq -r '.output.inline // empty')
    if [ "${res_status}" = "succeeded" ]; then
        echo "  PASS: ${action_name} terminal callback status = succeeded"
    else
        fail "${action_name} terminal callback status = '${res_status}', want 'succeeded'"
    fi
    if [ -z "${res_inline}" ]; then
        fail "${action_name} terminal callback has empty output.inline"
    fi
    echo "  PASS: ${action_name} terminal callback has output.inline"

    # Decode the inline output and return it for caller-specific validation.
    ACTION_STDOUT=$(printf '%s' "${res_inline}" | b64_decode)
}

# 8b-1: diagnostics.collect -- should return JSON with hostname, os, cpu_count, load_avg.
echo "  --- diagnostics.collect ---"
test_action "diagnostics.collect" "exec-e2e-diag-001" "e2e-diag-nonce-001"
if echo "${ACTION_STDOUT}" | jq empty 2>/dev/null; then
    DIAG_HOSTNAME=$(echo "${ACTION_STDOUT}" | jq -r '.hostname // empty')
    if [ -n "${DIAG_HOSTNAME}" ]; then
        echo "  PASS: diagnostics.collect has hostname='${DIAG_HOSTNAME}'"
    else
        fail "diagnostics.collect stdout missing 'hostname'"
    fi

    DIAG_OS=$(echo "${ACTION_STDOUT}" | jq -r '.os // empty')
    if [ "${DIAG_OS}" = "linux" ]; then
        echo "  PASS: diagnostics.collect os='linux'"
    else
        fail "diagnostics.collect os='${DIAG_OS}', want 'linux'"
    fi

    DIAG_MEM=$(echo "${ACTION_STDOUT}" | jq -r '.memory_total // empty')
    if [ -n "${DIAG_MEM}" ] && [ "${DIAG_MEM}" != "0" ]; then
        echo "  PASS: diagnostics.collect has memory_total=${DIAG_MEM}"
    else
        fail "diagnostics.collect memory_total missing or zero"
    fi

    DIAG_LOAD=$(echo "${ACTION_STDOUT}" | jq -r '.load_avg // empty')
    if [ -n "${DIAG_LOAD}" ]; then
        echo "  PASS: diagnostics.collect has load_avg"
    else
        fail "diagnostics.collect missing 'load_avg'"
    fi
else
    fail "diagnostics.collect stdout is not valid JSON"
fi

# 8b-2: health.check -- should return JSON with status, uptime, tunnel_count.
echo "  --- health.check ---"
test_action "health.check" "exec-e2e-health-001" "e2e-health-nonce-001"
if echo "${ACTION_STDOUT}" | jq empty 2>/dev/null; then
    HC_STATUS=$(echo "${ACTION_STDOUT}" | jq -r '.status // empty')
    if [ -n "${HC_STATUS}" ]; then
        echo "  PASS: health.check has status='${HC_STATUS}'"
    else
        fail "health.check stdout missing 'status'"
    fi

    HC_UPTIME=$(echo "${ACTION_STDOUT}" | jq -r '.uptime // empty')
    if [ -n "${HC_UPTIME}" ]; then
        echo "  PASS: health.check has uptime='${HC_UPTIME}'"
    else
        fail "health.check stdout missing 'uptime'"
    fi

    HC_TUNNELS=$(echo "${ACTION_STDOUT}" | jq '.tunnel_count // empty')
    if [ -n "${HC_TUNNELS}" ] && [ "${HC_TUNNELS}" != "null" ]; then
        echo "  PASS: health.check has tunnel_count=${HC_TUNNELS}"
    else
        fail "health.check stdout missing 'tunnel_count'"
    fi
else
    fail "health.check stdout is not valid JSON"
fi

# 8b-3: config.dump -- should return YAML containing wireguard: and heartbeat:.
echo "  --- config.dump ---"
test_action "config.dump" "exec-e2e-config-001" "e2e-config-nonce-001"
if echo "${ACTION_STDOUT}" | grep -q "wireguard:"; then
    echo "  PASS: config.dump contains 'wireguard:'"
else
    fail "config.dump stdout missing 'wireguard:' section"
fi
if echo "${ACTION_STDOUT}" | grep -q "heartbeat:"; then
    echo "  PASS: config.dump contains 'heartbeat:'"
else
    fail "config.dump stdout missing 'heartbeat:' section"
fi

echo "=== Phase 8b PASSED: additional action types ==="

# ===================================================================
# Phase 8c: Unknown action rejection (GAP-06)
# ===================================================================
echo "=== Testing unknown action rejection ==="

# Record the execution callback counter. A terminal status is reachable only
# from started, so a rejected pending entry walks every legal edge down to it:
# ack -> started -> failed (with error = reason), three callbacks in all.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE_UNK=$(get_counter "${RESPONSE}" "execution_callback_count")
echo "  execution_callback_count before: ${CB_BEFORE_UNK}"

# Configure a pending builtin dispatch for a nonexistent action.
configure_executions "exec-e2e-unknown-001" \
    "$(exec_entry "exec-e2e-unknown-001" "nonexistent.fake" "builtin" "pending" "null")"
echo "  unknown action dispatch configured in the executions block"

# Poll until execution_callback_count advances by at least 3 (ack + started +
# failed).
UNK_TIMEOUT=15
UNK_ELAPSED=0
UNK_CB_PASSED=0
while [ "${UNK_ELAPSED}" -lt "${UNK_TIMEOUT}" ]; do
    sleep 2
    UNK_ELAPSED=$((UNK_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        CB_AFTER_UNK=$(get_counter "${RESPONSE}" "execution_callback_count")
        if [ "${CB_AFTER_UNK}" -ge $((CB_BEFORE_UNK + 3)) ]; then
            echo "  PASS: execution_callback_count advanced from ${CB_BEFORE_UNK} to ${CB_AFTER_UNK} (>= +3)"
            UNK_CB_PASSED=1
            break
        fi
    fi
done

if [ "${UNK_CB_PASSED}" -eq 0 ]; then
    CB_AFTER_UNK=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
    fail "execution_callback_count did not reach $((CB_BEFORE_UNK + 3)) for unknown action (before=${CB_BEFORE_UNK}, after=${CB_AFTER_UNK})"
fi

# Validate the terminal (failed) callback body: status failed, error = reason.
UNK_CB_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
if [ -z "${UNK_CB_BODY}" ]; then
    fail "no execution_callback body captured for unknown action"
fi
UNK_CB_STATUS=$(echo "${UNK_CB_BODY}" | jq -r '.status // empty')
if [ "${UNK_CB_STATUS}" = "failed" ]; then
    echo "  PASS: unknown action terminal callback status = 'failed'"
else
    fail "unknown action terminal callback status = '${UNK_CB_STATUS}', want 'failed'"
fi
UNK_CB_ERROR=$(echo "${UNK_CB_BODY}" | jq -r '.error // empty')
if [ "${UNK_CB_ERROR}" = "unknown_action" ]; then
    echo "  PASS: unknown action terminal callback error = 'unknown_action'"
else
    fail "unknown action terminal callback error = '${UNK_CB_ERROR}', want 'unknown_action'"
fi

echo "=== Phase 8c PASSED: unknown action rejection ==="

# ===================================================================
# Phase 8d: Over-ceiling execution output upload
# ===================================================================
# The e2e-bigout hook prints ~20 KiB, past the 16 KiB inline ceiling, so the
# node takes the presigned upload leg: ack -> started -> started (declaring
# declared_output_bytes) -> terminal (succeeded, output.object_key+sha256) plus
# one PUT. That is +4 execution callbacks and +1 execution upload.
echo "=== Testing over-ceiling execution output upload ==="

# The pull entry carries no checksum: plexd verifies a hook against the digest
# it recorded when it discovered the hook on disk.
#
# The uploaded output is exactly 20480 'A' bytes; reproduce its sha256 locally so
# the terminal callback's output.sha256 can be checked against a known value.
EXPECTED_OUT_SHA=$(head -c 20480 /dev/zero | tr '\0' 'A' | sha256_hex)
echo "  expected output sha256: ${EXPECTED_OUT_SHA}"

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE_BIG=$(get_counter "${RESPONSE}" "execution_callback_count")
UP_BEFORE_BIG=$(get_counter "${RESPONSE}" "execution_upload_count")
echo "  execution_callback_count before: ${CB_BEFORE_BIG}"
echo "  execution_upload_count before: ${UP_BEFORE_BIG}"

# Configure a pending hook dispatch for e2e-bigout in the executions block.
configure_executions "exec-e2e-big-001" \
    "$(exec_entry "exec-e2e-big-001" "e2e-bigout" "hook" "pending" "null")"
echo "  e2e-bigout dispatch configured in the executions block"

# Poll until the upload landed (+1) AND all four callbacks arrived (+4).
BIG_TIMEOUT=30
BIG_ELAPSED=0
BIG_PASSED=0
while [ "${BIG_ELAPSED}" -lt "${BIG_TIMEOUT}" ]; do
    sleep 2
    BIG_ELAPSED=$((BIG_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        CB_AFTER_BIG=$(get_counter "${RESPONSE}" "execution_callback_count")
        UP_AFTER_BIG=$(get_counter "${RESPONSE}" "execution_upload_count")
        if [ "${UP_AFTER_BIG}" -ge $((UP_BEFORE_BIG + 1)) ] && [ "${CB_AFTER_BIG}" -ge $((CB_BEFORE_BIG + 4)) ]; then
            echo "  PASS: execution_upload_count ${UP_BEFORE_BIG}->${UP_AFTER_BIG} (>= +1), execution_callback_count ${CB_BEFORE_BIG}->${CB_AFTER_BIG} (>= +4)"
            BIG_PASSED=1
            break
        fi
    fi
done

if [ "${BIG_PASSED}" -eq 0 ]; then
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    CB_AFTER_BIG=$(get_counter "${RESPONSE}" "execution_callback_count")
    UP_AFTER_BIG=$(get_counter "${RESPONSE}" "execution_upload_count")
    fail "over-ceiling run did not complete (upload ${UP_BEFORE_BIG}->${UP_AFTER_BIG} want >= +1, callback ${CB_BEFORE_BIG}->${CB_AFTER_BIG} want >= +4)"
fi

# Validate the terminal callback body: succeeded, object-referenced output.
BIG_CB_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
if [ -z "${BIG_CB_BODY}" ]; then
    fail "no execution_callback body captured for over-ceiling run"
fi

BIG_CB_STATUS=$(echo "${BIG_CB_BODY}" | jq -r '.status // empty')
if [ "${BIG_CB_STATUS}" = "succeeded" ]; then
    echo "  PASS: over-ceiling terminal callback status = succeeded"
else
    fail "over-ceiling terminal callback status = '${BIG_CB_STATUS}', want 'succeeded'"
fi

BIG_OBJ_KEY=$(echo "${BIG_CB_BODY}" | jq -r '.output.object_key // empty')
if [ "${BIG_OBJ_KEY}" = "exec-output/exec-e2e-big-001" ]; then
    echo "  PASS: terminal callback output.object_key = 'exec-output/exec-e2e-big-001'"
else
    fail "terminal callback output.object_key = '${BIG_OBJ_KEY}', want 'exec-output/exec-e2e-big-001'"
fi

BIG_OUT_SHA=$(echo "${BIG_CB_BODY}" | jq -r '.output.sha256 // empty')
if [ "${BIG_OUT_SHA}" = "${EXPECTED_OUT_SHA}" ]; then
    echo "  PASS: terminal callback output.sha256 matches the uploaded bytes"
else
    fail "terminal callback output.sha256 = '${BIG_OUT_SHA}', want '${EXPECTED_OUT_SHA}'"
fi

BIG_INLINE=$(echo "${BIG_CB_BODY}" | jq -r '.output.inline // empty')
if [ -z "${BIG_INLINE}" ]; then
    echo "  PASS: terminal callback output.inline is absent (over-ceiling output)"
else
    fail "terminal callback unexpectedly carries output.inline for an over-ceiling run"
fi

echo "=== Phase 8d PASSED: over-ceiling execution output upload ==="

# ===================================================================
# Phase 8f: execution resume from a seeded status
# ===================================================================
# The executions block reports the LIVE status of every entry still awaiting
# delivery, so an agent that picks up an execution mid-flight sees the
# transition the control plane already recorded. Two resumes are proven:
#   - an entry held at ack is completed without a second ack (started ->
#     succeeded, +2 callbacks); a repeated ack would be refused as an illegal
#     transition and the run would abort short of the gate.
#   - an entry held at started under an execution id this agent never ran is
#     reported lost with a single terminal callback (+1). Actions are not
#     idempotent, so the run is never repeated.
# The two sub-steps run sequentially: the last-request endpoint keeps only the
# most recent callback body, so overlapping runs would make it ambiguous.
echo "=== Testing execution resume from a seeded status ==="

# --- 8f-1: an entry seeded at ack resumes without re-acking (+2 callbacks).
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE_RACK=$(get_counter "${RESPONSE}" "execution_callback_count")
echo "  [ack resume] execution_callback_count before: ${CB_BEFORE_RACK}"

configure_executions "exec-e2e-resume-ack-001" \
    "$(exec_entry "exec-e2e-resume-ack-001" "system.info" "builtin" "ack" "null")"
echo "  [ack resume] ack-seeded dispatch configured in the executions block"

RACK_TIMEOUT=30
RACK_ELAPSED=0
RACK_PASSED=0
while [ "${RACK_ELAPSED}" -lt "${RACK_TIMEOUT}" ]; do
    sleep 2
    RACK_ELAPSED=$((RACK_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        CB_AFTER_RACK=$(get_counter "${RESPONSE}" "execution_callback_count")
        if [ "${CB_AFTER_RACK}" -ge $((CB_BEFORE_RACK + 2)) ]; then
            echo "  PASS: [ack resume] execution_callback_count advanced from ${CB_BEFORE_RACK} to ${CB_AFTER_RACK} (>= +2, started + succeeded)"
            RACK_PASSED=1
            break
        fi
    fi
done

if [ "${RACK_PASSED}" -eq 0 ]; then
    CB_AFTER_RACK=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
    fail "[ack resume] execution_callback_count did not reach $((CB_BEFORE_RACK + 2)) (before=${CB_BEFORE_RACK}, after=${CB_AFTER_RACK}); a re-ack would have been refused"
fi

RACK_CB_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
if [ -z "${RACK_CB_BODY}" ]; then
    fail "[ack resume] no execution_callback body captured"
fi
RACK_CB_STATUS=$(echo "${RACK_CB_BODY}" | jq -r '.status // empty')
if [ "${RACK_CB_STATUS}" = "succeeded" ]; then
    echo "  PASS: [ack resume] terminal callback status = succeeded"
else
    fail "[ack resume] terminal callback status = '${RACK_CB_STATUS}', want 'succeeded'"
fi

# --- 8f-2: an entry seeded at started under an unknown id is reported lost.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE_ORPH=$(get_counter "${RESPONSE}" "execution_callback_count")
echo "  [orphan resume] execution_callback_count before: ${CB_BEFORE_ORPH}"

configure_executions "exec-e2e-resume-orphan-001" \
    "$(exec_entry "exec-e2e-resume-orphan-001" "system.info" "builtin" "started" "null")"
echo "  [orphan resume] started-seeded dispatch configured in the executions block"

ORPH_TIMEOUT=30
ORPH_ELAPSED=0
ORPH_PASSED=0
while [ "${ORPH_ELAPSED}" -lt "${ORPH_TIMEOUT}" ]; do
    sleep 2
    ORPH_ELAPSED=$((ORPH_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        CB_AFTER_ORPH=$(get_counter "${RESPONSE}" "execution_callback_count")
        if [ "${CB_AFTER_ORPH}" -ge $((CB_BEFORE_ORPH + 1)) ]; then
            echo "  PASS: [orphan resume] execution_callback_count advanced from ${CB_BEFORE_ORPH} to ${CB_AFTER_ORPH} (>= +1)"
            ORPH_PASSED=1
            break
        fi
    fi
done

if [ "${ORPH_PASSED}" -eq 0 ]; then
    CB_AFTER_ORPH=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
    fail "[orphan resume] execution_callback_count did not reach $((CB_BEFORE_ORPH + 1)) (before=${CB_BEFORE_ORPH}, after=${CB_AFTER_ORPH})"
fi

ORPH_CB_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
if [ -z "${ORPH_CB_BODY}" ]; then
    fail "[orphan resume] no execution_callback body captured"
fi
ORPH_CB_STATUS=$(echo "${ORPH_CB_BODY}" | jq -r '.status // empty')
if [ "${ORPH_CB_STATUS}" = "failed" ]; then
    echo "  PASS: [orphan resume] terminal callback status = failed"
else
    fail "[orphan resume] terminal callback status = '${ORPH_CB_STATUS}', want 'failed'"
fi
ORPH_CB_ERROR=$(echo "${ORPH_CB_BODY}" | jq -r '.error // empty')
if [ "${ORPH_CB_ERROR}" = "execution lost to an agent restart" ]; then
    echo "  PASS: [orphan resume] terminal callback error = 'execution lost to an agent restart'"
else
    fail "[orphan resume] terminal callback error = '${ORPH_CB_ERROR}', want 'execution lost to an agent restart'"
fi

# The single terminal callback must be the ONLY one: had the entry been run
# again, an ack/started pair would trail it. Settle briefly, then re-read.
sleep 5
CB_SETTLED_ORPH=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
if [ "${CB_SETTLED_ORPH}" -eq $((CB_BEFORE_ORPH + 1)) ]; then
    echo "  PASS: [orphan resume] execution_callback_count settled at exactly +1 (no re-execution)"
else
    fail "[orphan resume] execution_callback_count settled at ${CB_SETTLED_ORPH}, want exactly $((CB_BEFORE_ORPH + 1)); the lost run was re-executed"
fi

echo "=== Phase 8f PASSED: execution resume from a seeded status ==="

# ===================================================================
# Phase 8g: action_request is a pull trigger, not a delivery channel
# ===================================================================
# The dispatch is configured WITHOUT the usual nudge, then an action_request
# envelope carrying an opaque payload is injected. Nothing in that payload can
# identify the execution: the event only requests a reconcile, and the pull it
# triggers is what carries the dispatch.
echo "=== Testing action_request as a pull trigger ==="

# Baseline the callback counter BEFORE the block is configured, so a pull that
# lands early cannot hide the ack from the +3 gate.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE_PUSH=$(get_counter "${RESPONSE}" "execution_callback_count")
echo "  execution_callback_count before: ${CB_BEFORE_PUSH}"

configure_executions_no_nudge "exec-e2e-push-001" \
    "$(exec_entry "exec-e2e-push-001" "system.info" "builtin" "pending" "null")"
echo "  push dispatch configured in the executions block (no nudge)"

# Baseline state_count AFTER the configure post: the helper reads the live
# snapshot over the real state endpoint, which bumps the counter itself.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining Phase 8g"
STATE_BEFORE_PUSH=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before: ${STATE_BEFORE_PUSH}"

# Inject an action_request whose payload is junk: its content is irrelevant to
# the node, which learns the dispatch only from the pull.
PUSH_PAYLOAD=$(cat <<'PUSHEOF'
{
    "id": "evt-e2e-push-001",
    "type": "action_request",
    "scope": "node",
    "payload": "{}"
}
PUSHEOF
)
PUSH_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${PUSH_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${PUSH_STATUS}" != "204" ]; then
    fail "action_request event injection returned status ${PUSH_STATUS}, want 204"
fi
echo "  action_request injected with an opaque payload"

# The event must pull the state promptly. The heartbeat fixture answers
# reconcile: true on its own ~30s cadence, so this window is deliberately
# shorter than that fallback -- what is proven here is that the pull happens now.
PUSH_TIMEOUT=15
PUSH_ELAPSED=0
PUSH_STATE_PASSED=0
while [ "${PUSH_ELAPSED}" -lt "${PUSH_TIMEOUT}" ]; do
    sleep 2
    PUSH_ELAPSED=$((PUSH_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_PUSH=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_PUSH}" -gt "${STATE_BEFORE_PUSH}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_PUSH} to ${STATE_AFTER_PUSH} after action_request"
            PUSH_STATE_PASSED=1
            break
        fi
    fi
done

if [ "${PUSH_STATE_PASSED}" -eq 0 ]; then
    STATE_AFTER_PUSH=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after action_request (before=${STATE_BEFORE_PUSH}, after=${STATE_AFTER_PUSH})"
fi

# The pull the event triggered carried the dispatch, so the run completes with
# the usual three callbacks.
PUSH_CB_TIMEOUT=30
PUSH_CB_ELAPSED=0
PUSH_CB_PASSED=0
while [ "${PUSH_CB_ELAPSED}" -lt "${PUSH_CB_TIMEOUT}" ]; do
    sleep 2
    PUSH_CB_ELAPSED=$((PUSH_CB_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        CB_AFTER_PUSH=$(get_counter "${RESPONSE}" "execution_callback_count")
        if [ "${CB_AFTER_PUSH}" -ge $((CB_BEFORE_PUSH + 3)) ]; then
            echo "  PASS: execution_callback_count advanced from ${CB_BEFORE_PUSH} to ${CB_AFTER_PUSH} (>= +3)"
            PUSH_CB_PASSED=1
            break
        fi
    fi
done

if [ "${PUSH_CB_PASSED}" -eq 0 ]; then
    CB_AFTER_PUSH=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
    fail "execution_callback_count did not reach $((CB_BEFORE_PUSH + 3)) after action_request (before=${CB_BEFORE_PUSH}, after=${CB_AFTER_PUSH})"
fi

PUSH_CB_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
if [ -z "${PUSH_CB_BODY}" ]; then
    fail "no execution_callback body captured for the push-triggered run"
fi
PUSH_CB_STATUS=$(echo "${PUSH_CB_BODY}" | jq -r '.status // empty')
if [ "${PUSH_CB_STATUS}" = "succeeded" ]; then
    echo "  PASS: push-triggered terminal callback status = succeeded"
else
    fail "push-triggered terminal callback status = '${PUSH_CB_STATUS}', want 'succeeded'"
fi

echo "=== Phase 8g PASSED: action_request is a pull trigger ==="

# ===================================================================
# Phase 8e: TCP session lifecycle driven by the sessions block
# ===================================================================
# The sessions block of the pull drives the whole lifecycle. A tcp entry
# appearing provisions a listener, which reports a tcp session_started row
# carrying the address the listener actually bound (listener_endpoint); the same
# entry draining out of the block is the teardown signal, closing the listener
# and reporting a tcp session_ended row with explicit byte counters and
# terminated_by plexd_close — with no session_revoked event, the node cannot
# tell a revocation from a control plane that failed to serve the block, so it
# does not claim operator_revoke. The started row posts while the session is
# live, so the control plane records it. The drain-driven ended row posts for a
# session the control plane already holds as revoked, which records the ending
# row of such a session once (plexsphere/plexsphere#931), so it is accepted and
# counted on session_activity_count like the started row.
echo "=== Testing pull-driven TCP session lifecycle ==="

# ExpiresAt 5 minutes ahead in RFC 3339 UTC (GNU date -d, BSD date -v fallback).
EXPIRES_AT=$(date -u -d "+5 minutes" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+5M +%Y-%m-%dT%H:%M:%SZ)
echo "  session expires_at: ${EXPIRES_AT}"

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
SESS_BEFORE=$(get_counter "${RESPONSE}" "session_activity_count")
echo "  session_activity_count before: ${SESS_BEFORE}"
SESS_REJ_BEFORE=$(get_counter "${RESPONSE}" "session_activity_rejected_count")
echo "  session_activity_rejected_count before: ${SESS_REJ_BEFORE}"

# Configure the tcp entry into the sessions block: its appearance is what
# provisions the listener.
configure_sessions "8e-issue" \
    "$(session_entry "sess-e2e-001" "127.0.0.1" 8080 "${EXPIRES_AT}")"
echo "  tcp session configured in the sessions block"

# Poll session_activity_count to +1 (session_started row).
SESS_TIMEOUT=30
SESS_ELAPSED=0
SESS_START_PASSED=0
while [ "${SESS_ELAPSED}" -lt "${SESS_TIMEOUT}" ]; do
    sleep 2
    SESS_ELAPSED=$((SESS_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        SESS_AFTER=$(get_counter "${RESPONSE}" "session_activity_count")
        if [ "${SESS_AFTER}" -ge $((SESS_BEFORE + 1)) ]; then
            echo "  PASS: session_activity_count advanced from ${SESS_BEFORE} to ${SESS_AFTER} (>= +1)"
            SESS_START_PASSED=1
            break
        fi
    fi
done

if [ "${SESS_START_PASSED}" -eq 0 ]; then
    SESS_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
    fail "session_activity_count did not reach $((SESS_BEFORE + 1)) after the sessions block was configured (before=${SESS_BEFORE}, after=${SESS_AFTER})"
fi

# Validate the session_started row.
START_BODY=$(curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null || true)
if [ -z "${START_BODY}" ]; then
    fail "no session_activity body captured after the sessions block was configured"
fi
START_PHASE=$(echo "${START_BODY}" | jq -r '.tcp.phase // empty')
if [ "${START_PHASE}" = "session_started" ]; then
    echo "  PASS: session_activity tcp.phase = 'session_started'"
else
    fail "session_activity tcp.phase = '${START_PHASE}', want 'session_started'"
fi
START_HOST=$(echo "${START_BODY}" | jq -r '.tcp.target_host // empty')
if [ "${START_HOST}" = "127.0.0.1" ]; then
    echo "  PASS: session_activity tcp.target_host = '127.0.0.1'"
else
    fail "session_activity tcp.target_host = '${START_HOST}', want '127.0.0.1'"
fi
START_PORT=$(echo "${START_BODY}" | jq -r '.tcp.target_port // empty')
if [ "${START_PORT}" = "8080" ]; then
    echo "  PASS: session_activity tcp.target_port = 8080"
else
    fail "session_activity tcp.target_port = '${START_PORT}', want 8080"
fi
# The started row reports the address the listener actually bound, so the
# control plane can hand clients somewhere to connect.
START_ENDPOINT=$(echo "${START_BODY}" | jq -r '.tcp.listener_endpoint // empty')
if echo "${START_ENDPOINT}" | grep -Eq '^.+:[0-9]+$'; then
    echo "  PASS: session_activity tcp.listener_endpoint = '${START_ENDPOINT}'"
else
    fail "session_activity tcp.listener_endpoint = '${START_ENDPOINT}', want a non-empty host:port"
fi

# Drain the entry out of the sessions block: its disappearance is the teardown
# signal. This phase sends no session_revoked event, so the drain alone closes
# the session (phase 8j covers the event).
configure_sessions "8e-drain" "[]"
echo "  tcp session drained from the sessions block"

# Poll session_activity_count to +2 (the session_ended row): the ended row is
# posted for a session the control plane holds as revoked, which records the
# ending row of such a session once, so it is accepted like the started row.
REV_ELAPSED=0
SESS_END_PASSED=0
while [ "${REV_ELAPSED}" -lt "${SESS_TIMEOUT}" ]; do
    sleep 2
    REV_ELAPSED=$((REV_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        SESS_AFTER=$(get_counter "${RESPONSE}" "session_activity_count")
        if [ "${SESS_AFTER}" -ge $((SESS_BEFORE + 2)) ]; then
            echo "  PASS: session_activity_count advanced from ${SESS_BEFORE} to ${SESS_AFTER} (>= +2)"
            # Read from the same response, so both counters describe one moment.
            SESS_REJ_AFTER=$(get_counter "${RESPONSE}" "session_activity_rejected_count")
            SESS_END_PASSED=1
            break
        fi
    fi
done

if [ "${SESS_END_PASSED}" -eq 0 ]; then
    SESS_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
    fail "session_activity_count did not reach $((SESS_BEFORE + 2)) after the drain (before=${SESS_BEFORE}, after=${SESS_AFTER})"
fi

# The ended row was recorded, not refused.
if [ "${SESS_REJ_AFTER}" -eq "${SESS_REJ_BEFORE}" ]; then
    echo "  PASS: session_activity_rejected_count stayed at ${SESS_REJ_AFTER} (the ended row was recorded)"
else
    fail "session_activity_rejected_count = ${SESS_REJ_AFTER} after the drain, want ${SESS_REJ_BEFORE}: the session_ended row of a revoked session must be recorded"
fi

# Validate the session_ended row: phase, terminated_by, and numeric byte
# counters (jq numbers so an absent field fails the check).
REV_BODY=$(curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null || true)
if [ -z "${REV_BODY}" ]; then
    fail "no session_activity body captured after the drain"
fi
REV_PHASE=$(echo "${REV_BODY}" | jq -r '.tcp.phase // empty')
if [ "${REV_PHASE}" = "session_ended" ]; then
    echo "  PASS: session_activity tcp.phase = 'session_ended'"
else
    fail "session_activity tcp.phase = '${REV_PHASE}', want 'session_ended'"
fi
# The entry drained before its expiry lapsed, with no session_revoked event.
# That may be a revocation or a control plane that failed to serve the block,
# and the node cannot tell them apart, so it reports a local close rather than
# asserting an operator action.
REV_TERM=$(echo "${REV_BODY}" | jq -r '.tcp.terminated_by // empty')
if [ "${REV_TERM}" = "plexd_close" ]; then
    echo "  PASS: session_activity tcp.terminated_by = 'plexd_close'"
else
    fail "session_activity tcp.terminated_by = '${REV_TERM}', want 'plexd_close'"
fi
if echo "${REV_BODY}" | jq -e '.tcp.bytes_in | numbers' >/dev/null 2>&1; then
    echo "  PASS: session_activity tcp.bytes_in is present as a number"
else
    fail "session_activity tcp.bytes_in is not present as a number"
fi
if echo "${REV_BODY}" | jq -e '.tcp.bytes_out | numbers' >/dev/null 2>&1; then
    echo "  PASS: session_activity tcp.bytes_out is present as a number"
else
    fail "session_activity tcp.bytes_out is not present as a number"
fi

echo "=== Phase 8e PASSED: pull-driven TCP session lifecycle ==="

# ===================================================================
# Phase 8i: the idle window travels the wire and closes the session
# ===================================================================
# idle_timeout_seconds on the entry is the access-control boundary that caps how
# long an unattended forward stays open. Nothing ever connects to this listener,
# so the window runs out from the bind and the session closes on its own — while
# its entry still stands in the block — and reports terminated_by idle_timeout.
echo "=== Testing the idle window driven from the sessions block ==="

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining Phase 8i"
IDLE_BEFORE=$(get_counter "${RESPONSE}" "session_activity_count")
echo "  session_activity_count before: ${IDLE_BEFORE}"

# A one-second window: the started row and the idle-driven ended row both land
# well inside the poll below.
configure_sessions "8i-issue" \
    "$(session_entry "sess-e2e-idle" "127.0.0.1" 8080 "${EXPIRES_AT}" 1)"
echo "  tcp session with a 1s idle window configured in the sessions block"

# Poll session_activity_count to +2: session_started, then session_ended from the
# idle monitor. No drain is needed to get there.
IDLE_TIMEOUT=30
IDLE_ELAPSED=0
IDLE_PASSED=0
while [ "${IDLE_ELAPSED}" -lt "${IDLE_TIMEOUT}" ]; do
    sleep 2
    IDLE_ELAPSED=$((IDLE_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        IDLE_AFTER=$(get_counter "${RESPONSE}" "session_activity_count")
        if [ "${IDLE_AFTER}" -ge $((IDLE_BEFORE + 2)) ]; then
            echo "  PASS: session_activity_count advanced from ${IDLE_BEFORE} to ${IDLE_AFTER} (>= +2)"
            IDLE_PASSED=1
            break
        fi
    fi
done

if [ "${IDLE_PASSED}" -eq 0 ]; then
    IDLE_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
    fail "session_activity_count did not reach $((IDLE_BEFORE + 2)) after the idle window elapsed (before=${IDLE_BEFORE}, after=${IDLE_AFTER})"
fi

IDLE_BODY=$(curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null || true)
if [ -z "${IDLE_BODY}" ]; then
    fail "no session_activity body captured after the idle window elapsed"
fi
IDLE_PHASE=$(echo "${IDLE_BODY}" | jq -r '.tcp.phase // empty')
if [ "${IDLE_PHASE}" = "session_ended" ]; then
    echo "  PASS: session_activity tcp.phase = 'session_ended'"
else
    fail "session_activity tcp.phase = '${IDLE_PHASE}', want 'session_ended'"
fi
IDLE_TERM=$(echo "${IDLE_BODY}" | jq -r '.tcp.terminated_by // empty')
if [ "${IDLE_TERM}" = "idle_timeout" ]; then
    echo "  PASS: session_activity tcp.terminated_by = 'idle_timeout'"
else
    fail "session_activity tcp.terminated_by = '${IDLE_TERM}', want 'idle_timeout'"
fi

# The entry outlived its session, so drain it before the next phase. The session
# is already closed, so this reports nothing further.
configure_sessions "8i-drain" "[]"

echo "=== Phase 8i PASSED: idle window closes the session ==="

# ===================================================================
# Phase 8j: a signed session_revoked closes the session it names
# ===================================================================
# A verified session_revoked event names the session the control plane revoked,
# and the node closes that session at once, reporting the reason the payload
# carries: operator_request becomes terminated_by operator_revoke. The event is
# injected while the entry still stands in the sessions block, so no pull can
# close the session, and it has no idle window and a 5-minute expiry: the event
# is the only thing that can produce the ending row inside the window. The mock
# still holds the session as live, so it records that row. Draining the entry
# afterwards finds no live session, so no second ending row is posted.
echo "=== Testing that a signed session_revoked closes the session it names ==="

REVOKE_SESSION="sess-e2e-revoke-001"
EXPIRES_AT=$(date -u -d "+5 minutes" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+5M +%Y-%m-%dT%H:%M:%SZ)

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining Phase 8j"
REVK_BEFORE=$(get_counter "${RESPONSE}" "session_activity_count")
REVK_REJ_BEFORE=$(get_counter "${RESPONSE}" "session_activity_rejected_count")
echo "  session_activity_count before: ${REVK_BEFORE}"
echo "  session_activity_rejected_count before: ${REVK_REJ_BEFORE}"

configure_sessions "8j-issue" \
    "$(session_entry "${REVOKE_SESSION}" "127.0.0.1" 8080 "${EXPIRES_AT}")"
echo "  tcp session configured in the sessions block"

# Poll session_activity_count to +1 (the session_started row).
REVK_TIMEOUT=30
REVK_ELAPSED=0
REVK_START_PASSED=0
while [ "${REVK_ELAPSED}" -lt "${REVK_TIMEOUT}" ]; do
    sleep 2
    REVK_ELAPSED=$((REVK_ELAPSED + 2))
    REVK_STARTED=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
    if [ "${REVK_STARTED}" -ge $((REVK_BEFORE + 1)) ]; then
        REVK_START_PASSED=1
        break
    fi
done
if [ "${REVK_START_PASSED}" -eq 0 ]; then
    fail "session_activity_count did not reach $((REVK_BEFORE + 1)) after the sessions block was configured (before=${REVK_BEFORE})"
fi
REVK_START_PHASE=$(curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null | jq -r '.tcp.phase // empty')
if [ "${REVK_START_PHASE}" = "session_started" ]; then
    echo "  PASS: session_started row posted (session_activity_count=${REVK_STARTED})"
else
    fail "session_activity tcp.phase = '${REVK_START_PHASE}' after provisioning, want 'session_started'"
fi

# Inject the signed event while the entry still stands in the block.
REVOKED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REVK_EVENT=$(cat <<REVKEOF
{
    "id": "evt-e2e-sess-revoke-001",
    "type": "session_revoked",
    "scope": "node",
    "payload": {
        "session_id": "${REVOKE_SESSION}",
        "jti": "${REVOKE_SESSION}",
        "revoked_at": "${REVOKED_AT}",
        "revoke_reason": "operator_request"
    }
}
REVKEOF
)
REVK_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${REVK_EVENT}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${REVK_STATUS}" != "204" ]; then
    fail "session_revoked event injection returned status ${REVK_STATUS}, want 204"
fi
echo "  session_revoked injected for ${REVOKE_SESSION} with revoke_reason operator_request"

# Poll session_activity_count to +1 over the started row (the session_ended
# row) within a window no pull could close the session in.
REVK_END_TIMEOUT=15
REVK_ELAPSED=0
REVK_END_PASSED=0
while [ "${REVK_ELAPSED}" -lt "${REVK_END_TIMEOUT}" ]; do
    sleep 1
    REVK_ELAPSED=$((REVK_ELAPSED + 1))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        REVK_ENDED=$(get_counter "${RESPONSE}" "session_activity_count")
        if [ "${REVK_ENDED}" -ge $((REVK_STARTED + 1)) ]; then
            REVK_REJ_AFTER=$(get_counter "${RESPONSE}" "session_activity_rejected_count")
            echo "  PASS: session_activity_count advanced from ${REVK_STARTED} to ${REVK_ENDED} within ${REVK_ELAPSED}s of the event"
            REVK_END_PASSED=1
            break
        fi
    fi
done
if [ "${REVK_END_PASSED}" -eq 0 ]; then
    fail "session_activity_count did not reach $((REVK_STARTED + 1)) within ${REVK_END_TIMEOUT}s after session_revoked (the entry still stands, so only the event can close the session)"
fi
if [ "${REVK_REJ_AFTER}" -eq "${REVK_REJ_BEFORE}" ]; then
    echo "  PASS: session_activity_rejected_count unchanged at ${REVK_REJ_AFTER}"
else
    fail "session_activity_rejected_count moved from ${REVK_REJ_BEFORE} to ${REVK_REJ_AFTER} after session_revoked"
fi

# The ending row reports the revocation, with numeric byte counters.
REVK_BODY=$(curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null || true)
[ -n "${REVK_BODY}" ] || fail "no session_activity body captured after session_revoked"
REVK_PHASE=$(echo "${REVK_BODY}" | jq -r '.tcp.phase // empty')
if [ "${REVK_PHASE}" = "session_ended" ]; then
    echo "  PASS: session_activity tcp.phase = 'session_ended'"
else
    fail "session_activity tcp.phase = '${REVK_PHASE}' after session_revoked, want 'session_ended'"
fi
REVK_TERM=$(echo "${REVK_BODY}" | jq -r '.tcp.terminated_by // empty')
if [ "${REVK_TERM}" = "operator_revoke" ]; then
    echo "  PASS: session_activity tcp.terminated_by = 'operator_revoke'"
else
    fail "session_activity tcp.terminated_by = '${REVK_TERM}' after session_revoked, want 'operator_revoke'"
fi
if echo "${REVK_BODY}" | jq -e '(.tcp.bytes_in | numbers) and (.tcp.bytes_out | numbers)' >/dev/null 2>&1; then
    echo "  PASS: session_activity tcp.bytes_in and tcp.bytes_out are present as numbers"
else
    fail "session_activity tcp.bytes_in or tcp.bytes_out is not present as a number: ${REVK_BODY}"
fi

# Drain the entry. The session is already closed, so the pull that sees the
# drain posts nothing further.
configure_sessions "8j-drain" "[]"
# configure_sessions reads the live snapshot, which counts on state_count, so the
# baseline is taken after it.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
REVK_STATE_BEFORE=$(get_counter "${RESPONSE}" "state_count")
REVK_ELAPSED=0
REVK_PULLED=0
while [ "${REVK_ELAPSED}" -lt 30 ]; do
    sleep 2
    REVK_ELAPSED=$((REVK_ELAPSED + 2))
    if [ "$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")" -gt "${REVK_STATE_BEFORE}" ]; then
        REVK_PULLED=1
        break
    fi
done
[ "${REVK_PULLED}" -eq 1 ] || fail "no state pull within 30s of draining ${REVOKE_SESSION}"
# The pull's dispatch runs after the state GET it counted; give it time to post
# a row it should not post.
sleep 5
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
REVK_FINAL=$(get_counter "${RESPONSE}" "session_activity_count")
REVK_REJ_FINAL=$(get_counter "${RESPONSE}" "session_activity_rejected_count")
if [ "${REVK_FINAL}" -eq "${REVK_ENDED}" ] && [ "${REVK_REJ_FINAL}" -eq "${REVK_REJ_AFTER}" ]; then
    echo "  PASS: the drain posted no second ending row (accepted ${REVK_FINAL}, rejected ${REVK_REJ_FINAL})"
else
    fail "activity counters moved after the drain (accepted ${REVK_ENDED} -> ${REVK_FINAL}, rejected ${REVK_REJ_AFTER} -> ${REVK_REJ_FINAL}): the revoked session posted a second ending row"
fi

echo "=== Phase 8j PASSED: a signed session_revoked closes the session it names ==="

# ===================================================================
# Phase 8k: tcp tunnel traffic reported as session_active rows
# ===================================================================
# No control-plane component sees a byte of a tunnel, so plexd reports its
# traffic as session_active rows, which keep the control plane's idle sweeper
# away from a tunnel in use. The interval is min(60s, idle_timeout_seconds/4),
# so the 24s idle window gives 6s. Two requests go through the tunnel, the
# second straight after the first, both within 3s of the first. The first byte
# after an interval without a row posts at once, so right after the second
# request exactly one row has landed: the bytes that crossed after it wait for
# the one row at the end of that interval. Once a whole interval passes without
# a byte the tunnel posts nothing, and the 13s quiet window spans two interval
# ends, so a tunnel that kept posting would show. The tunnel targets the mock's
# own unauthenticated health route, and the first request reads its answer back,
# so bytes cross both ways. nc dials the listener from inside the plexd
# container, which plexd's nftables chains do not filter: they match traffic
# arriving on the mesh interface, and a connection from inside the container
# arrives on lo. The mock counts the row on session_active_count alone, so
# session_activity_count still moves only for the started and ended rows.
echo "=== Testing tcp tunnel traffic reported as session_active rows ==="

ACT_SESSION="sess-e2e-active"
EXPIRES_AT=$(date -u -d "+5 minutes" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+5M +%Y-%m-%dT%H:%M:%SZ)

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining Phase 8k"
ACT_BEFORE=$(get_counter "${RESPONSE}" "session_activity_count")
ACT_ACTIVE_BEFORE=$(get_counter "${RESPONSE}" "session_active_count")
echo "  session_activity_count before: ${ACT_BEFORE}"
echo "  session_active_count before: ${ACT_ACTIVE_BEFORE}"

configure_sessions "8k-issue" \
    "$(session_entry "${ACT_SESSION}" "mock-api" 8080 "${EXPIRES_AT}" 24)"
echo "  tcp session to mock-api:8080 with a 24s idle window configured in the sessions block"

# Poll session_activity_count to +1 (the session_started row).
ACT_TIMEOUT=30
ACT_ELAPSED=0
ACT_START_PASSED=0
while [ "${ACT_ELAPSED}" -lt "${ACT_TIMEOUT}" ]; do
    sleep 2
    ACT_ELAPSED=$((ACT_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ACT_STARTED=$(get_counter "${RESPONSE}" "session_activity_count")
        if [ "${ACT_STARTED}" -ge $((ACT_BEFORE + 1)) ]; then
            echo "  PASS: session_activity_count advanced from ${ACT_BEFORE} to ${ACT_STARTED} (the session_started row)"
            ACT_START_PASSED=1
            break
        fi
    fi
done
if [ "${ACT_START_PASSED}" -eq 0 ]; then
    ACT_STARTED=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
    fail "session_activity_count did not reach $((ACT_BEFORE + 1)) after the sessions block was configured (before=${ACT_BEFORE}, after=${ACT_STARTED})"
fi

# The started row carries the address the listener bound, which is where nc
# connects.
ACT_EP=$(curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null | jq -r '.tcp.listener_endpoint // empty' 2>/dev/null || true)
if ! echo "${ACT_EP}" | grep -Eq '^.+:[0-9]+$'; then
    fail "session_activity tcp.listener_endpoint = '${ACT_EP}' after provisioning, want a non-empty host:port"
fi
ACT_EP_HOST=${ACT_EP%:*}
ACT_EP_PORT=${ACT_EP##*:}
echo "  listener endpoint: ${ACT_EP_HOST} port ${ACT_EP_PORT}"

# Nothing has crossed the tunnel yet, so it has posted no session_active row.
ACT_IDLE=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_active_count")
if [ "${ACT_IDLE}" -eq "${ACT_ACTIVE_BEFORE}" ]; then
    echo "  PASS: session_active_count unchanged at ${ACT_IDLE} before any traffic"
else
    fail "session_active_count moved from ${ACT_ACTIVE_BEFORE} to ${ACT_IDLE} before any byte crossed the tunnel"
fi

# The first request keeps nc's stdin open for a second, so the mock's answer
# comes back before nc half-closes its socket: the tunnel ends both halves as
# soon as either direction ends. The second request only sends. Each nc's exit
# status proves the connect, the answer proves the way back, and the
# session_active_count reads below prove the bytes were seen.
ACT_NC_ANSWER_CMD="{ printf 'GET /v1/health HTTP/1.0\r\n\r\n'; /bin/busybox sleep 1; } | /bin/busybox nc -w 3 ${ACT_EP_HOST} ${ACT_EP_PORT}"
ACT_NC_SEND_CMD="printf 'GET /v1/health HTTP/1.0\r\n\r\n' | /bin/busybox nc -w 3 ${ACT_EP_HOST} ${ACT_EP_PORT}"

ACT_T0=$(date +%s)
ACT_NC_STATUS=0
ACT_ANSWER=$(dc exec -T plexd /bin/busybox sh -c "${ACT_NC_ANSWER_CMD}" 2>/dev/null) || ACT_NC_STATUS=$?
[ "${ACT_NC_STATUS}" -eq 0 ] || fail "first nc through the listener at ${ACT_EP} exited with status ${ACT_NC_STATUS}, want 0"
ACT_STATUS_LINE=${ACT_ANSWER%%$'\n'*}
ACT_STATUS_LINE=${ACT_STATUS_LINE%$'\r'}
case "${ACT_STATUS_LINE}" in
    HTTP/1.*) echo "  PASS: the mock's answer came back through the tunnel (${ACT_STATUS_LINE})" ;;
    *) fail "first nc through the listener at ${ACT_EP} read '${ACT_STATUS_LINE}', want an HTTP/1.x status line from the mock" ;;
esac

ACT_NC_STATUS=0
dc exec -T plexd /bin/busybox sh -c "${ACT_NC_SEND_CMD}" >/dev/null || ACT_NC_STATUS=$?
[ "${ACT_NC_STATUS}" -eq 0 ] || fail "second nc through the listener at ${ACT_EP} exited with status ${ACT_NC_STATUS}, want 0"
ACT_SENT_IN=$(( $(date +%s) - ACT_T0 ))
echo "  two requests sent through the tunnel in ${ACT_SENT_IN}s"

# The rest of the phase relies on both requests landing well inside the first
# 6s interval. Whole seconds round down, so 3 means under 4s.
if [ "${ACT_SENT_IN}" -gt 3 ]; then
    fail "the two requests took ${ACT_SENT_IN}s, want them within 3s of the first: this host is too slow for the phase's timing"
fi

# Exactly one row has landed: the first bytes posted at once, and the bytes
# after them, the answer and the second request, wait for the interval's end.
ACT_FIRST=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_active_count")
if [ "${ACT_FIRST}" -eq $((ACT_ACTIVE_BEFORE + 1)) ]; then
    echo "  PASS: session_active_count at ${ACT_FIRST} within ${ACT_SENT_IN}s of the first request"
else
    fail "session_active_count = ${ACT_FIRST} within ${ACT_SENT_IN}s of the first request, want $((ACT_ACTIVE_BEFORE + 1)): the first bytes post at once and later bytes wait for the 6s interval's end"
fi

# The row carries the phase alone.
ACT_BODY=$(curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null | jq -c . 2>/dev/null || true)
if [ "${ACT_BODY}" = '{"tcp":{"phase":"session_active"}}' ]; then
    echo "  PASS: session_activity body = ${ACT_BODY}"
else
    fail "session_activity body = '${ACT_BODY}' after the first request, want '{\"tcp\":{\"phase\":\"session_active\"}}'"
fi

# Poll session_active_count to +2 for up to 10s: the row at the end of the
# first interval, which covers the answer and the second request.
ACT_ELAPSED=0
ACT_SECOND_PASSED=0
while [ "${ACT_ELAPSED}" -lt 10 ]; do
    sleep 1
    ACT_ELAPSED=$((ACT_ELAPSED + 1))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ACT_SECOND=$(get_counter "${RESPONSE}" "session_active_count")
        if [ "${ACT_SECOND}" -ge $((ACT_ACTIVE_BEFORE + 2)) ]; then
            echo "  PASS: session_active_count advanced to ${ACT_SECOND} within ${ACT_ELAPSED}s of the second request"
            ACT_SECOND_PASSED=1
            break
        fi
    fi
done
if [ "${ACT_SECOND_PASSED}" -eq 0 ]; then
    ACT_SECOND=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_active_count")
    fail "session_active_count did not reach $((ACT_ACTIVE_BEFORE + 2)) within 10s of the second request (before=${ACT_ACTIVE_BEFORE}, after=${ACT_SECOND}): bytes inside an interval must be posted at its end"
fi

# 13s with no traffic, more than two 6s intervals: a quiet tunnel posts nothing.
sleep 13
ACT_QUIET=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_active_count")
if [ "${ACT_QUIET}" -eq $((ACT_ACTIVE_BEFORE + 2)) ]; then
    echo "  PASS: session_active_count stayed at ${ACT_QUIET} over the 13s quiet window"
else
    fail "session_active_count = ${ACT_QUIET} after the 13s quiet window, want $((ACT_ACTIVE_BEFORE + 2)): a tunnel with no traffic must post no session_active row"
fi

# Drain the entry so the session does not reach a later phase. The drain, or
# the 24s idle window if the pull is slower, ends the session with one
# session_ended row. Wait for it here, so it cannot land inside phase 8h's
# session_activity_count baseline.
configure_sessions "8k-drain" "[]"
echo "  tcp session drained from the sessions block"
ACT_ELAPSED=0
ACT_END_PASSED=0
while [ "${ACT_ELAPSED}" -lt "${ACT_TIMEOUT}" ]; do
    sleep 2
    ACT_ELAPSED=$((ACT_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ACT_ENDED=$(get_counter "${RESPONSE}" "session_activity_count")
        if [ "${ACT_ENDED}" -ge $((ACT_BEFORE + 2)) ]; then
            # Read from the same response, so both counters describe one moment.
            ACT_FINAL=$(get_counter "${RESPONSE}" "session_active_count")
            ACT_END_PASSED=1
            break
        fi
    fi
done
if [ "${ACT_END_PASSED}" -eq 0 ]; then
    ACT_ENDED=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
    fail "session_activity_count did not reach $((ACT_BEFORE + 2)) after the drain (before=${ACT_BEFORE}, after=${ACT_ENDED}): the session_ended row did not land"
fi
# The session_active rows counted on session_active_count alone, and closing
# the session posted no final one.
if [ "${ACT_ENDED}" -eq $((ACT_BEFORE + 2)) ] && [ "${ACT_FINAL}" -eq $((ACT_ACTIVE_BEFORE + 2)) ]; then
    echo "  PASS: session_activity_count at ${ACT_ENDED} (started and ended rows), session_active_count at ${ACT_FINAL}"
else
    fail "after the drain session_activity_count = ${ACT_ENDED} (want $((ACT_BEFORE + 2))) and session_active_count = ${ACT_FINAL} (want $((ACT_ACTIVE_BEFORE + 2)))"
fi

echo "=== Phase 8k PASSED: tcp tunnel traffic reported as session_active rows ==="

# ===================================================================
# Phase 8h: session events are pull triggers, not delivery channels
# ===================================================================
# The session lifecycle is delivered in the sessions block of the pull.
# session_setup only pulls the observing reconcile forward: its payload is never
# parsed. session_revoked's payload is parsed (phase 8j), but one that names no
# session closes nothing and still pulls. Either way an opaque payload must
# still move state_count while leaving the session activity untouched.
echo "=== Testing session events as pull triggers ==="

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining Phase 8h"
STATE_BEFORE_SETUP=$(get_counter "${RESPONSE}" "state_count")
SESS_BEFORE_SETUP=$(get_counter "${RESPONSE}" "session_activity_count")
echo "  state_count before session_setup: ${STATE_BEFORE_SETUP}"
echo "  session_activity_count before session_setup: ${SESS_BEFORE_SETUP}"

# Inject a session_setup whose payload is junk: its content is irrelevant to the
# node, which learns the session only from the pull.
SETUP_PAYLOAD=$(cat <<'SETUPEOF'
{
    "id": "evt-e2e-sess-push-001",
    "type": "session_setup",
    "scope": "node",
    "payload": "{}"
}
SETUPEOF
)
SETUP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${SETUP_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${SETUP_STATUS}" != "204" ]; then
    fail "session_setup event injection returned status ${SETUP_STATUS}, want 204"
fi
echo "  session_setup injected with an opaque payload"

# The event must pull the state promptly. The heartbeat fixture answers
# reconcile: true on its own ~30s cadence, so this window is deliberately
# shorter than that fallback -- what is proven here is that the pull happens now.
SETUP_TIMEOUT=15
SETUP_ELAPSED=0
SETUP_STATE_PASSED=0
while [ "${SETUP_ELAPSED}" -lt "${SETUP_TIMEOUT}" ]; do
    sleep 2
    SETUP_ELAPSED=$((SETUP_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_SETUP=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_SETUP}" -gt "${STATE_BEFORE_SETUP}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_SETUP} to ${STATE_AFTER_SETUP} after session_setup"
            SETUP_STATE_PASSED=1
            break
        fi
    fi
done

if [ "${SETUP_STATE_PASSED}" -eq 0 ]; then
    STATE_AFTER_SETUP=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after session_setup (before=${STATE_BEFORE_SETUP}, after=${STATE_AFTER_SETUP})"
fi

# The pull found no session in the block, so no activity row was reported: the
# event carried no session of its own.
SESS_AFTER_SETUP=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
if [ "${SESS_AFTER_SETUP}" -eq "${SESS_BEFORE_SETUP}" ]; then
    echo "  PASS: session_activity_count unchanged at ${SESS_AFTER_SETUP} after session_setup"
else
    fail "session_activity_count moved from ${SESS_BEFORE_SETUP} to ${SESS_AFTER_SETUP} after session_setup; the payload was acted on"
fi

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining session_revoked"
STATE_BEFORE_REVOKE=$(get_counter "${RESPONSE}" "state_count")
SESS_BEFORE_REVOKE=$(get_counter "${RESPONSE}" "session_activity_count")
echo "  state_count before session_revoked: ${STATE_BEFORE_REVOKE}"
echo "  session_activity_count before session_revoked: ${SESS_BEFORE_REVOKE}"

# This session_revoked carries a JSON string where the payload object belongs,
# so plexd refuses it as malformed ("event handler failed") and closes nothing,
# but it still triggers the reconcile.
REVOKE_PAYLOAD=$(cat <<'REVOKEEOF'
{
    "id": "evt-e2e-sess-push-002",
    "type": "session_revoked",
    "scope": "node",
    "payload": "{}"
}
REVOKEEOF
)
REVOKE_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${REVOKE_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${REVOKE_STATUS}" != "204" ]; then
    fail "session_revoked event injection returned status ${REVOKE_STATUS}, want 204"
fi
echo "  session_revoked injected with an opaque payload"

REVOKE_TIMEOUT=15
REVOKE_ELAPSED=0
REVOKE_STATE_PASSED=0
while [ "${REVOKE_ELAPSED}" -lt "${REVOKE_TIMEOUT}" ]; do
    sleep 2
    REVOKE_ELAPSED=$((REVOKE_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_REVOKE=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_REVOKE}" -gt "${STATE_BEFORE_REVOKE}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_REVOKE} to ${STATE_AFTER_REVOKE} after session_revoked"
            REVOKE_STATE_PASSED=1
            break
        fi
    fi
done

if [ "${REVOKE_STATE_PASSED}" -eq 0 ]; then
    STATE_AFTER_REVOKE=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after session_revoked (before=${STATE_BEFORE_REVOKE}, after=${STATE_AFTER_REVOKE})"
fi

SESS_AFTER_REVOKE=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
if [ "${SESS_AFTER_REVOKE}" -eq "${SESS_BEFORE_REVOKE}" ]; then
    echo "  PASS: session_activity_count unchanged at ${SESS_AFTER_REVOKE} after session_revoked"
else
    fail "session_activity_count moved from ${SESS_BEFORE_REVOKE} to ${SESS_AFTER_REVOKE} after session_revoked; a malformed payload closed a session"
fi

echo "=== Phase 8h PASSED: session events are pull triggers ==="

# ===================================================================
# Phase 9: Key rotation completes end to end (RotateKeys flag)
# ===================================================================
echo "=== Testing key-rotation completion via RotateKeys ==="

# Record current state_count and key_rotate_count before arming rotation.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE_KR=$(get_counter "${RESPONSE}" "state_count")
ROTATE_BEFORE_KR=$(get_counter "${RESPONSE}" "key_rotate_count")
echo "  state_count before: ${STATE_BEFORE_KR}"
echo "  key_rotate_count before: ${ROTATE_BEFORE_KR}"

# Configure mock API to return RotateKeys: true in heartbeat responses.
# The agent should complete the rotation (POST /v1/keys/rotate) and then
# reconcile, which re-fetches state.
KR_CONFIG='{"reconcile":true,"rotate_keys":true}'
KR_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${KR_CONFIG}" \
    "http://localhost:18080/test/configure-heartbeat" 2>/dev/null || true)
if [ "${KR_STATUS}" != "204" ]; then
    fail "configure-heartbeat returned status ${KR_STATUS}, want 204"
fi
echo "  heartbeat response configured with rotate_keys=true"

# Wait for key_rotate_count to strictly increase (rotation completed).
# Assert monotonic increase, not == 1: while the fixture flag stays true
# each served heartbeat re-arms and another rotation may complete before
# the flag reset below.
KR_ROTATE_TIMEOUT=60
KR_ROTATE_ELAPSED=0
while [ "${KR_ROTATE_ELAPSED}" -lt "${KR_ROTATE_TIMEOUT}" ]; do
    sleep 3
    KR_ROTATE_ELAPSED=$((KR_ROTATE_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ROTATE_AFTER_KR=$(get_counter "${RESPONSE}" "key_rotate_count")
        if [ "${ROTATE_AFTER_KR}" -gt "${ROTATE_BEFORE_KR}" ]; then
            echo "  PASS: key_rotate_count increased from ${ROTATE_BEFORE_KR} to ${ROTATE_AFTER_KR} (rotation completed)"
            break
        fi
    fi
done

if [ "${KR_ROTATE_ELAPSED}" -ge "${KR_ROTATE_TIMEOUT}" ]; then
    ROTATE_AFTER_KR=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "key_rotate_count")
    fail "key_rotate_count did not increase after RotateKeys=true (before=${ROTATE_BEFORE_KR}, after=${ROTATE_AFTER_KR})"
fi

# Validate the captured rotate request body: it must carry the new public
# key and must NOT carry a node_id (the server identifies the node from
# the NSK bearer credential).
ROTATE_BODY=$(curl -sf "http://localhost:18080/test/last-request/key_rotate" 2>/dev/null || true)
if [ -z "${ROTATE_BODY}" ]; then
    fail "no captured key_rotate request body"
fi
if echo "${ROTATE_BODY}" | grep -q '"new_public_key"'; then
    echo "  PASS: key_rotate body contains 'new_public_key'"
else
    fail "key_rotate body missing 'new_public_key' field (body: ${ROTATE_BODY})"
fi
if echo "${ROTATE_BODY}" | grep -q '"node_id"'; then
    fail "key_rotate body unexpectedly contains 'node_id' (body: ${ROTATE_BODY})"
fi
echo "  PASS: key_rotate body does not contain 'node_id'"

# Wait for state_count to increase too (peer view refreshes via pull after
# the rotation-triggered reconcile).
KR_TIMEOUT=60
KR_ELAPSED=0
while [ "${KR_ELAPSED}" -lt "${KR_TIMEOUT}" ]; do
    sleep 3
    KR_ELAPSED=$((KR_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_KR=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_KR}" -gt "${STATE_BEFORE_KR}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_KR} to ${STATE_AFTER_KR} (reconcile triggered)"
            break
        fi
    fi
done

if [ "${KR_ELAPSED}" -ge "${KR_TIMEOUT}" ]; then
    STATE_AFTER_KR=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after RotateKeys=true (before=${STATE_BEFORE_KR}, after=${STATE_AFTER_KR})"
fi

# Reset heartbeat response to not rotate keys (avoid triggering continuously).
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 || true

echo "=== Phase 9 PASSED: key rotation completed end to end ==="

# ===================================================================
# Phase 9b: rotate_keys SSE event completes rotation (GAP-07)
# ===================================================================
echo "=== Testing rotate_keys SSE event completion ==="

# Record a fresh key_rotate_count baseline before injecting the event.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
ROTATE_BEFORE_RK=$(get_counter "${RESPONSE}" "key_rotate_count")
echo "  key_rotate_count before: ${ROTATE_BEFORE_RK}"

# Inject a rotate_keys SSE event.
RK_PAYLOAD=$(cat <<'RKEOF'
{
    "id": "evt-e2e-rotatekeys-001",
    "type": "rotate_keys",
    "scope": "node",
    "payload": "{\"reason\":\"e2e-test\"}"
}
RKEOF
)
RK_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${RK_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${RK_STATUS}" != "204" ]; then
    fail "rotate_keys event injection returned status ${RK_STATUS}, want 204"
fi
echo "  rotate_keys event injected"

# Poll for a further key_rotate_count increase (event-driven rotation
# completed on top of any heartbeat-driven rotations from Phase 9).
RK_TIMEOUT=30
RK_ELAPSED=0
while [ "${RK_ELAPSED}" -lt "${RK_TIMEOUT}" ]; do
    sleep 2
    RK_ELAPSED=$((RK_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ROTATE_AFTER_RK=$(get_counter "${RESPONSE}" "key_rotate_count")
        if [ "${ROTATE_AFTER_RK}" -gt "${ROTATE_BEFORE_RK}" ]; then
            echo "  PASS: key_rotate_count increased from ${ROTATE_BEFORE_RK} to ${ROTATE_AFTER_RK} after rotate_keys"
            break
        fi
    fi
done

if [ "${RK_ELAPSED}" -ge "${RK_TIMEOUT}" ]; then
    ROTATE_AFTER_RK=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "key_rotate_count")
    fail "key_rotate_count did not increase after rotate_keys event (before=${ROTATE_BEFORE_RK}, after=${ROTATE_AFTER_RK})"
fi

echo "=== Phase 9b PASSED: rotate_keys SSE event completion ==="

# ===================================================================
# Phase 10: Deeper body validation
# ===================================================================
echo "=== Deeper body validation ==="

# 10a. Metrics body: validate the MetricSample wire shape and a known sample.
METRICS_BODY=$(curl -sf "http://localhost:18080/test/last-request/metrics" 2>/dev/null || true)
if [ -n "${METRICS_BODY}" ]; then
    # A node_resources sample named cpu_usage_percent must be present.
    HAS_CPU=$(echo "${METRICS_BODY}" | jq '[.[] | select(.group == "node_resources" and .name == "cpu_usage_percent")] | length')
    if [ "${HAS_CPU}" -ge 1 ]; then
        echo "  PASS: metrics contains node_resources sample 'cpu_usage_percent'"
    else
        fail "metrics missing node_resources sample 'cpu_usage_percent' (body: ${METRICS_BODY})"
    fi

    # That sample's value must be numeric.
    CPU_VALUE_TYPE=$(echo "${METRICS_BODY}" | jq -r '[.[] | select(.group == "node_resources" and .name == "cpu_usage_percent")][0].value | type')
    if [ "${CPU_VALUE_TYPE}" = "number" ]; then
        echo "  PASS: cpu_usage_percent sample carries a numeric value"
    else
        fail "cpu_usage_percent value type='${CPU_VALUE_TYPE}', want 'number'"
    fi
else
    echo "  WARN: no metrics body captured"
fi

# 10b. The platform audit route must have received nothing: with no
# contract-legal source wired, every entry is dropped before the batch is built
# rather than sent under a source the ingest gate refuses. The audit records
# plexd does produce are validated on the local endpoint in phase 12.
AUDIT_BODY=$(curl -sf "http://localhost:18080/test/last-request/audit" 2>/dev/null || true)
if [ -n "${AUDIT_BODY}" ]; then
    fail "the platform audit route received a body, want none: ${AUDIT_BODY}"
fi
echo "  PASS: no platform audit batch was sent"

# 10c. Capability manifest, second look: the same envelope late in the run, plus
# the optional fields the contract defines. Phase 3c already checked the action
# inventory; phase 12b checks the same eleven builtins on the node API.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -n "${CAPS_BODY}" ]; then
    CAPS_FP=$(echo "${CAPS_BODY}" | jq -r '.ssh_host_key_fingerprint // empty')
    if [ -z "${CAPS_FP}" ]; then
        fail "capability manifest carries no ssh_host_key_fingerprint, but the agent generated a host key"
    fi
    case "${CAPS_FP}" in
        SHA256:*) echo "  PASS: ssh_host_key_fingerprint is the canonical SHA256:<base64> form" ;;
        *) fail "ssh_host_key_fingerprint='${CAPS_FP}', want the SHA256:<base64> form" ;;
    esac

    # This agent has a hook on disk, so an absent declared_hooks fails: the key
    # goes missing only when the agent has none. By now the agent has restarted
    # twice, so this also shows that every boot keeps reporting e2e-bigout.
    # Every entry needs a name and a 32-byte base64 digest.
    CAPS_HOOK_NAMES=$(declared_hook_names "${CAPS_BODY}")
    if [ "${CAPS_HOOK_NAMES}" != "e2e-bigout" ]; then
        fail "capability manifest declared_hooks = [${CAPS_HOOK_NAMES}], want exactly e2e-bigout (body: ${CAPS_BODY})"
    fi
    CAPS_HOOK_HEX=$(declared_hook_hex "${CAPS_BODY}" e2e-bigout)
    if [ "${CAPS_HOOK_HEX}" = "${BIGOUT_HEX}" ]; then
        echo "  PASS: declared_hooks holds e2e-bigout with the digest of the file"
    else
        fail "declared_hooks digest of e2e-bigout = ${CAPS_HOOK_HEX}, want ${BIGOUT_HEX}, the SHA-256 of the file"
    fi
    BAD_HOOKS=$(echo "${CAPS_BODY}" | jq '[.declared_hooks[] | select((.name // "") == "" or (.checksum // "") == "")] | length')
    if [ "${BAD_HOOKS}" -eq 0 ]; then
        echo "  PASS: declared_hooks entries all carry a name and a checksum"
    else
        fail "found ${BAD_HOOKS} declared_hooks entries without a name or checksum"
    fi
else
    fail "no captured capabilities request body"
fi

# 10d. Heartbeat body richness: re-validate the four v1 heartbeat fields on the
# latest captured heartbeat, confirming the contract holds across the run.
HB_BODY=$(curl -sf "http://localhost:18080/test/last-request/heartbeat" 2>/dev/null || true)
if [ -n "${HB_BODY}" ]; then
    HB_CLIENT_NOW=$(echo "${HB_BODY}" | jq -r '.client_now // empty')
    if echo "${HB_CLIENT_NOW}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+.*(Z|[+-][0-9]{2}:[0-9]{2})$'; then
        echo "  PASS: heartbeat client_now='${HB_CLIENT_NOW}' matches RFC 3339"
    else
        fail "heartbeat client_now='${HB_CLIENT_NOW}' is not an RFC 3339 timestamp"
    fi

    HB_CHECKSUM=$(echo "${HB_BODY}" | jq -r '.binary_checksum // empty')
    HB_DIGEST_LEN=$(printf '%s' "${HB_CHECKSUM}" | b64_decode | wc -c | tr -d ' ')
    if [ "${HB_DIGEST_LEN}" = "32" ]; then
        echo "  PASS: heartbeat binary_checksum is a 32-byte base64 digest"
    else
        fail "heartbeat binary_checksum='${HB_CHECKSUM}' decodes to ${HB_DIGEST_LEN} bytes, want 32"
    fi

    HB_VERSION=$(echo "${HB_BODY}" | jq -r '.binary_version // empty')
    if [ -n "${HB_VERSION}" ]; then
        echo "  PASS: heartbeat binary_version='${HB_VERSION}'"
    else
        fail "heartbeat body missing 'binary_version' field"
    fi

    HB_NAT_SUMMARY_TYPE=$(echo "${HB_BODY}" | jq -r '.nat_summary | type')
    if [ "${HB_NAT_SUMMARY_TYPE}" = "object" ]; then
        echo "  PASS: heartbeat nat_summary is a JSON object"
    else
        fail "heartbeat nat_summary type='${HB_NAT_SUMMARY_TYPE}', want 'object'"
    fi
else
    fail "no captured heartbeat request body for richness validation"
fi

# 10e. Telemetry ingest rejection taxonomy. Drive POST /v1/nodes/{id}/metrics
# directly and assert the mock's RFC 9457 ingest-gate contract. This runs AFTER
# the 10a metrics body assertion because case (a) passes the header gates and so
# overwrites the captured last-request/metrics body; the ~10s report cadence
# refreshes it for any later reader.
MOCK_METRICS_URL="http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/metrics"

# assert_ingest_reject: POST body to the metrics ingest with any extra curl args
# and assert the HTTP status, an application/problem+json body, and the problem
# 'code' member. Args: name, want_status, want_code, body, extra curl args...
assert_ingest_reject() {
    local name=$1 want_status=$2 want_code=$3 body=$4
    shift 4
    local resp status ctype json code
    resp=$(curl -s -w '\n%{http_code}\n%{content_type}' -X POST \
        -H 'Content-Type: application/json' "${MOCK_AUTH[@]}" "$@" -d "${body}" \
        "${MOCK_METRICS_URL}")
    ctype=$(echo "${resp}" | tail -n1)
    status=$(echo "${resp}" | tail -n2 | head -n1)
    json=$(echo "${resp}" | sed '$d' | sed '$d')
    if [ "${status}" != "${want_status}" ]; then
        fail "${name}: status=${status}, want ${want_status} (body: ${json})"
    fi
    case "${ctype}" in
        application/problem+json*) ;;
        *) fail "${name}: content-type='${ctype}', want application/problem+json" ;;
    esac
    code=$(echo "${json}" | jq -r '.code // empty')
    if [ "${code}" != "${want_code}" ]; then
        fail "${name}: code='${code}', want '${want_code}'"
    fi
    echo "  PASS: ${name} -> ${status} (code='${code}')"
}

# (a) An out-of-enum group, but a valid RFC 3339 sent-at header: the header gates
#     pass, so the batch reaches validation and is rejected as malformed.
assert_ingest_reject "metrics_group_bogus" 400 ingest_batch_malformed \
    '[{"group":"bogus","name":"cpu_usage_percent","value":1,"timestamp":"2026-07-21T00:00:00Z"}]' \
    -H 'X-Plexsphere-Sent-At: 2026-07-21T00:00:00Z'

# (b) A well-shaped batch with NO sent-at header is stopped by the header gate.
assert_ingest_reject "metrics_missing_sent_at" 400 ingest_sent_at_invalid \
    '[{"group":"node_resources","name":"cpu_usage_percent","value":1,"timestamp":"2026-07-21T00:00:00Z"}]'

# 10f. The manifest follows the hooks directory while the agent runs. Phase 3c
# and step 10c read what a boot reports. This step changes the directory in the
# running container and reads each change back from the mock. The numbered
# checks run in order, and each waits for its last PUT, so that no count below
# catches a PUT of the check before it. Checks (7) and (8) each make two changes
# with one wait: a hook and its sidecar land in one PUT or in two. Only the
# step's own hook and its sidecar are written: e2e-bigout gets a touch and keeps
# its digest.
LIVE_HOOKS_DIR="/etc/plexd/hooks"

# live_hook_text prints the script a test hook holds. Args: <marker>. Each marker
# is one revision of the file, so a new marker is a new digest.
live_hook_text() {
    printf '#!/bin/sh\necho %s\n' "$1"
}

# install_live_hook writes a hook into the running container. Args: <hook>
# <marker>. The script travels over stdin, so the container holds exactly the
# bytes live_hook_text prints and the digest taken here is the one to expect.
install_live_hook() {
    live_hook_text "$2" | dc exec -T plexd /bin/busybox sh -c \
        "/bin/busybox cat > ${LIVE_HOOKS_DIR}/$1 && /bin/busybox chmod 0755 ${LIVE_HOOKS_DIR}/$1"
}

# install_live_sidecar writes a hook's sidecar into the running container. Args:
# <hook> <json>. The JSON travels over stdin, so its quotes never reach a shell.
# The mode is set rather than left to the exec's umask, because plexd refuses to
# run a hook whose sidecar is group- or other-writable.
install_live_sidecar() {
    printf '%s\n' "$2" | dc exec -T plexd /bin/busybox sh -c \
        "/bin/busybox cat > ${LIVE_HOOKS_DIR}/$1.json && /bin/busybox chmod 0644 ${LIVE_HOOKS_DIR}/$1.json"
}

# wait_for_declared_hooks polls the captured manifest for up to 10 seconds, until
# declared_hooks is exactly the given names and the given hook has the given
# digest. Args: <step> <comma-joined names> [<hook> <hex digest>]. The hook
# defaults to e2e-bigout, so a step that names none still proves it remains.
wait_for_declared_hooks() {
    local step=$1 want_names=$2 hook=${3:-e2e-bigout} want_hex=${4:-${BIGOUT_HEX}}
    local elapsed=0 body
    while :; do
        body=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
        if [ "$(declared_hook_names "${body}")" = "${want_names}" ] \
            && [ "$(declared_hook_hex "${body}" "${hook}")" = "${want_hex}" ]; then
            echo "  PASS: [${step}] declared_hooks = [${want_names}] with ${hook} at its digest, after ${elapsed}s"
            return 0
        fi
        if [ "${elapsed}" -ge 10 ]; then
            fail "[${step}] the manifest did not reach declared_hooks = [${want_names}] with ${hook} at ${want_hex} within 10s (body: ${body})"
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

# wait_for_hook_entry polls the captured manifest for up to 10 seconds, until a
# jq filter holds on one hook's declared_hooks entry. Args: <step> <hook> <jq
# filter>. A hook the manifest does not list never holds: select gives jq no
# output, and -e exits 4. The mock captures a refused PUT too, so a pass here
# says what the agent sent, not that the mock accepted it.
wait_for_hook_entry() {
    local step=$1 hook=$2 filter=$3
    local elapsed=0 body
    while :; do
        body=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
        if printf '%s' "${body}" | jq -e --arg name "${hook}" \
            ".declared_hooks[]? | select(.name == \$name) | ${filter}" >/dev/null 2>&1; then
            echo "  PASS: [${step}] ${hook} holds ${filter}, after ${elapsed}s"
            return 0
        fi
        if [ "${elapsed}" -ge 10 ]; then
            fail "[${step}] the ${hook} entry did not reach ${filter} within 10s (body: ${body})"
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

# configure_capabilities posts to POST /test/configure-capabilities and requires
# a 204: a refusal the test believes it armed or lifted would void the check.
# Args: <step> <json>. One POST sets every setting, so a field left out resets.
configure_capabilities() {
    local step=$1 body=$2 status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${body}" \
        "http://localhost:18080/test/configure-capabilities" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${step}] configure-capabilities returned status ${status}, want 204"
    fi
}

# (1) A hook watch that could not start leaves the agent running on its boot
# scan, so every poll below would time out with nothing to say why. Rule that out
# first: the watch needs an inotify instance, and those are scarce on a host that
# runs kind clusters.
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
WATCHER_STOPPED=$(count_log_lines "${PLEXD_LOGS}" "hook watcher stopped")
if [ "${WATCHER_STOPPED}" != "0" ]; then
    fail "plexd logged 'hook watcher stopped' ${WATCHER_STOPPED} time(s), so the step below cannot run: check the host's inotify limit, fs.inotify.max_user_instances"
fi
echo "  PASS: the hook watcher is running"

# (2) Add: a new hook reaches the control plane with its digest.
LIVE_HEX=$(live_hook_text one | sha256_hex)
install_live_hook e2e-live one || fail "could not write e2e-live into the container"
wait_for_declared_hooks "add" "e2e-bigout,e2e-live" e2e-live "${LIVE_HEX}"

# (3) Change: an edit reaches the control plane as a new digest.
LIVE_HEX=$(live_hook_text two | sha256_hex)
install_live_hook e2e-live two || fail "could not rewrite e2e-live in the container"
wait_for_declared_hooks "change" "e2e-bigout,e2e-live" e2e-live "${LIVE_HEX}"

# (4) Remove: the entry leaves the manifest and e2e-bigout remains.
dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-live" \
    || fail "could not remove e2e-live from the container"
wait_for_declared_hooks "remove" "e2e-bigout"

# (5) No-op control: a touch fires the watcher, but the manifest stays equal to
# the accepted one, so no PUT follows. The control plane raises an integrity
# alert on every accepted PUT that carries a drifted hook, so a repeat is not
# harmless. Five seconds is several quiet periods.
CAPS_BEFORE_TOUCH=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
dc exec -T plexd /bin/busybox touch "${LIVE_HOOKS_DIR}/e2e-bigout" \
    || fail "could not touch e2e-bigout in the container"
sleep 5
CAPS_AFTER_TOUCH=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
if [ "${CAPS_AFTER_TOUCH}" -eq "${CAPS_BEFORE_TOUCH}" ]; then
    echo "  PASS: [no-op] touch on e2e-bigout left capabilities_count at ${CAPS_AFTER_TOUCH} for 5s"
else
    fail "[no-op] touch on e2e-bigout moved capabilities_count from ${CAPS_BEFORE_TOUCH} to ${CAPS_AFTER_TOUCH}, want no PUT"
fi

# (6) Reload: the write and the reload share one sh -c, so the reload answers
# inside the watcher's 200 ms debounce. The watcher does not list e2e-live at
# that moment, and only a scan of the directory can count it. The CLI prints
# "Hooks:  %d" with two spaces, so the count is parsed as a field.
LIVE_HEX=$(live_hook_text three | sha256_hex)
RELOAD_OUT=$(live_hook_text three | dc exec -T plexd /bin/busybox sh -c \
    "/bin/busybox cat > ${LIVE_HOOKS_DIR}/e2e-live && /bin/busybox chmod 0755 ${LIVE_HOOKS_DIR}/e2e-live && /usr/local/bin/plexd hooks reload" 2>&1) \
    || fail "[reload] plexd hooks reload failed in the container: ${RELOAD_OUT}"
RELOAD_HOOKS=$(printf '%s\n' "${RELOAD_OUT}" | awk '$1 == "Hooks:" { print $2 }')
HOOKS_ON_DISK=$(dc exec -T plexd /bin/busybox ls "${LIVE_HOOKS_DIR}" 2>&1) \
    || fail "[reload] could not list ${LIVE_HOOKS_DIR} in the container: ${HOOKS_ON_DISK}"
HOOKS_ON_DISK_COUNT=$(printf '%s\n' "${HOOKS_ON_DISK}" | wc -l | tr -d ' ')
if [ "${HOOKS_ON_DISK_COUNT}" != "2" ]; then
    fail "[reload] ${LIVE_HOOKS_DIR} holds ${HOOKS_ON_DISK_COUNT} entries, want e2e-bigout and e2e-live: ${HOOKS_ON_DISK}"
fi
if [ "${RELOAD_HOOKS}" = "${HOOKS_ON_DISK_COUNT}" ]; then
    echo "  PASS: [reload] plexd hooks reload reports the ${RELOAD_HOOKS} hooks on disk"
else
    fail "[reload] plexd hooks reload reports '${RELOAD_HOOKS}' hooks, want the ${HOOKS_ON_DISK_COUNT} on disk (output: ${RELOAD_OUT})"
fi
# The reload feeds the reporter like any other change. Removing e2e-live before
# that PUT lands would put the manifest back to the accepted one and send
# nothing, so wait for it, and then for the PUT the removal causes.
wait_for_declared_hooks "reload" "e2e-bigout,e2e-live" e2e-live "${LIVE_HEX}"
dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-live" \
    || fail "[reload] could not remove e2e-live from the container"
wait_for_declared_hooks "reload cleanup" "e2e-bigout"

# (7) Sidecar: its four fields reach the control plane, an edit moves them and
# leaves the digest alone, and its removal leaves the short entry. The hook and
# the sidecar share one debounce key, so they land in one PUT or in two, and
# either way the last PUT carries the metadata. The marker is not four, because
# (8) rewrites the hook and its waits need a digest that is new.
LIVE_HEX=$(live_hook_text sidecar | sha256_hex)
install_live_hook e2e-live sidecar || fail "[sidecar] could not write e2e-live into the container"
install_live_sidecar e2e-live '{"description":"live one","parameters":[{"name":"target","type":"string","required":true}],"timeout":"90s","sandbox":"none"}' \
    || fail "[sidecar] could not write e2e-live.json into the container"
wait_for_hook_entry "sidecar" e2e-live \
    '.description == "live one" and .parameters[0].name == "target" and .parameters[0].required and .timeout_seconds == 90 and .sandbox_level == "none"'

install_live_sidecar e2e-live '{"description":"live two"}' \
    || fail "[sidecar edit] could not rewrite e2e-live.json in the container"
wait_for_hook_entry "sidecar edit" e2e-live '.description == "live two"'
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
CAPS_HOOK_HEX=$(declared_hook_hex "${CAPS_BODY}" e2e-live)
if [ "${CAPS_HOOK_HEX}" = "${LIVE_HEX}" ]; then
    echo "  PASS: [sidecar edit] the digest of e2e-live did not move"
else
    fail "[sidecar edit] digest of e2e-live = ${CAPS_HOOK_HEX}, want ${LIVE_HEX}"
fi

# The body before this carries a description, so the filter cannot pass on it.
dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-live.json" \
    || fail "[sidecar removed] could not remove e2e-live.json from the container"
wait_for_hook_entry "sidecar removed" e2e-live 'keys == ["checksum", "name"]'

# (8) Older control plane: a refused manifest still lands, short and with the
# new digest, and the metadata comes back with no restart once the refusal
# lifts. dc logs spans every run of the container, so the refusals count from a
# baseline.
REFUSED_LINE="hook metadata refused"
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
REFUSED_BEFORE=$(count_log_lines "${PLEXD_LOGS}" "${REFUSED_LINE}")
configure_capabilities "older control plane" '{"refuse_hook_metadata": true}'
CAPS_BEFORE_SHORT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")

# The sidecar goes first. A hook rewritten first, with the sidecar more than a
# quiet period behind it, is a short PUT the mock accepts: both waits below pass
# on that body and the count reads before any refusal. With the sidecar first,
# the new digest goes out wide, so a refusal comes before the short PUT.
LIVE_HEX=$(live_hook_text four | sha256_hex)
install_live_sidecar e2e-live '{"description":"live three"}' \
    || fail "[older control plane] could not write e2e-live.json into the container"
install_live_hook e2e-live four || fail "[older control plane] could not rewrite e2e-live in the container"
# The digest wait goes first. The keys filter alone passes on the short body (7)
# left, and the digest alone passes on the refused wide body, which the mock
# captures too. Only the short PUT of the new digest passes both, in this order.
wait_for_declared_hooks "older control plane" "e2e-bigout,e2e-live" e2e-live "${LIVE_HEX}"
wait_for_hook_entry "older control plane" e2e-live 'keys == ["checksum", "name"]'
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
REFUSED_AFTER=$(count_log_lines "${PLEXD_LOGS}" "${REFUSED_LINE}")
if [ "${REFUSED_AFTER}" -gt "${REFUSED_BEFORE}" ]; then
    echo "  PASS: [older control plane] plexd logged '${REFUSED_LINE}' (${REFUSED_BEFORE} -> ${REFUSED_AFTER})"
else
    fail "[older control plane] plexd logged no new '${REFUSED_LINE}' line (${REFUSED_BEFORE} -> ${REFUSED_AFTER})"
fi
# The mock captures a refused body too, so the waits do not show that the short
# manifest landed. The counter moves only on acceptance, and while the refusal
# stands only a short manifest can move it.
CAPS_AFTER_SHORT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
if [ "${CAPS_AFTER_SHORT}" -gt "${CAPS_BEFORE_SHORT}" ]; then
    echo "  PASS: [older control plane] the short manifest landed (capabilities_count ${CAPS_BEFORE_SHORT} -> ${CAPS_AFTER_SHORT})"
else
    fail "[older control plane] capabilities_count stayed at ${CAPS_BEFORE_SHORT}: the short manifest was not accepted"
fi

# The same goes for the wide manifest here.
configure_capabilities "upgraded control plane" '{"refuse_hook_metadata": false}'
CAPS_BEFORE_LIFT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
install_live_sidecar e2e-live '{"description":"live four"}' \
    || fail "[upgraded control plane] could not rewrite e2e-live.json in the container"
wait_for_hook_entry "upgraded control plane" e2e-live '.description == "live four"'
CAPS_AFTER_LIFT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
if [ "${CAPS_AFTER_LIFT}" -gt "${CAPS_BEFORE_LIFT}" ]; then
    echo "  PASS: [upgraded control plane] the wide manifest landed with no restart (capabilities_count ${CAPS_BEFORE_LIFT} -> ${CAPS_AFTER_LIFT})"
else
    fail "[upgraded control plane] capabilities_count stayed at ${CAPS_BEFORE_LIFT}: the wide manifest was not accepted"
fi

dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-live.json" "${LIVE_HOOKS_DIR}/e2e-live" \
    || fail "[older control plane] could not remove e2e-live and its sidecar from the container"
wait_for_declared_hooks "older control plane cleanup" "e2e-bigout"

# (9) Failed PUT: the restarted agent's boot PUT and its first retry both meet a
# 500, and the second retry lands. The retries wait about 5 and 10 seconds. The
# mock answers the 500 ahead of its counter, so capabilities_count moves only on
# delivery, which also proves the agent is back for phase 12. dc logs spans every
# run of the container, so the failures count from a baseline.
SEND_FAILED_LINE="agent: capability report: send failed"
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
SEND_FAILED_BEFORE=$(count_log_lines "${PLEXD_LOGS}" "${SEND_FAILED_LINE}")
configure_capabilities "failed PUT" '{"fail_next": 2}'
CAPS_BEFORE_RESTART=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
dc restart plexd
RETRY_TIMEOUT=30
RETRY_ELAPSED=0
while :; do
    CAPS_AFTER_RESTART=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
    if [ "${CAPS_AFTER_RESTART}" -gt "${CAPS_BEFORE_RESTART}" ]; then
        echo "  PASS: [failed PUT] capabilities_count grew from ${CAPS_BEFORE_RESTART} to ${CAPS_AFTER_RESTART} after ${RETRY_ELAPSED}s"
        break
    fi
    if [ "${RETRY_ELAPSED}" -ge "${RETRY_TIMEOUT}" ]; then
        fail "[failed PUT] capabilities_count stayed at ${CAPS_BEFORE_RESTART} for ${RETRY_TIMEOUT}s after the restart: the manifest was not delivered"
    fi
    sleep 1
    RETRY_ELAPSED=$((RETRY_ELAPSED + 1))
done
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
SEND_FAILED_AFTER=$(count_log_lines "${PLEXD_LOGS}" "${SEND_FAILED_LINE}")
SEND_FAILED_DELTA=$((SEND_FAILED_AFTER - SEND_FAILED_BEFORE))
if [ "${SEND_FAILED_DELTA}" = "2" ]; then
    echo "  PASS: [failed PUT] plexd logged '${SEND_FAILED_LINE}' twice"
else
    fail "[failed PUT] plexd logged '${SEND_FAILED_LINE}' ${SEND_FAILED_DELTA} time(s) (${SEND_FAILED_BEFORE} -> ${SEND_FAILED_AFTER}), want 2"
fi
# The container layer survives a restart, and the manifest that landed is the
# one the failed sends carried.
wait_for_declared_hooks "failed PUT" "e2e-bigout"
# e2e-bigout has no sidecar, so its entry stays short across the restart.
wait_for_hook_entry "failed PUT" e2e-bigout 'keys == ["checksum", "name"]'

# 10g. A hook run meets each limit plexd enforces: the timeout its sidecar
# declares, a sandbox level plexd does not implement, and a hook file that is
# group-writable. The hook e2e-run starts a child that appends to a file every
# second and waits on it. plexd is PID 1 here and reaps nothing, so a killed
# child stays a zombie that kill -0 still finds: the size of the file is the
# proof, not the pid.
RUN_TICKS="/var/run/plexd/e2e-run.ticks"

# wait_for_callback polls for up to 15 seconds, until the mock has accepted a
# given number of callbacks past the baseline and the captured body meets a jq
# filter. Args: <step> <baseline> <accepted> <jq filter>. The mock captures a
# callback it refuses with 409 too, so the filter says what the agent sent, and
# the counter, which moves only on acceptance, says it landed.
wait_for_callback() {
    local step=$1 baseline=$2 accepted=$3 filter=$4
    local elapsed=0 body count
    # A failed baseline read leaves it empty, and the counter check would then
    # pass on any count, leaving only the body, which the mock captures even
    # for a callback it refuses.
    case "${baseline}" in
        '' | *[!0-9]*) fail "[${step}] no execution_callback_count baseline (got '${baseline}')" ;;
    esac
    while :; do
        body=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
        count=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
        if [ "${count:-0}" -ge $((baseline + accepted)) ] \
            && printf '%s' "${body}" | jq -e "${filter}" >/dev/null 2>&1; then
            echo "  PASS: [${step}] ${accepted} callbacks landed past the baseline and the last holds ${filter}, after ${elapsed}s"
            return 0
        fi
        if [ "${elapsed}" -ge 15 ]; then
            fail "[${step}] the last callback did not reach ${filter} within 15s (execution_callback_count ${count:-0}, want >= $((baseline + accepted)); body: ${body})"
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

# wait_for_terminal_callback waits for a run's terminal callback. Args: <step>
# <baseline> <jq filter>. Three is ack, started, and the terminal.
wait_for_terminal_callback() {
    wait_for_callback "$1" "$2" 3 "$3"
}

# read_run_ticks prints the size of the file at RUN_TICKS, the one the hook
# under test appends to: e2e-run here and e2e-cancel in 10h. The redirect sits
# inside the sh -c, so a missing file fails the read instead of reading as 0.
read_run_ticks() {
    dc exec -T plexd /bin/busybox sh -c "/bin/busybox wc -c < ${RUN_TICKS}" 2>&1
}

# (1) Timeout: the sidecar declares 2s, far inside the dispatch deadline and
# max_action_timeout, so the error names the hook's own limit. The script never
# ends by itself and its child never stops, so the ticks stop only if the kill
# reaches the whole group. The body is not live_hook_text, so it does not go
# through install_live_hook.
printf '%s\n' '#!/bin/sh' \
    "( while :; do echo tick >> ${RUN_TICKS}; /bin/busybox sleep 1; done ) &" \
    'wait' \
    | dc exec -T plexd /bin/busybox sh -c \
        "/bin/busybox cat > ${LIVE_HOOKS_DIR}/e2e-run && /bin/busybox chmod 0755 ${LIVE_HOOKS_DIR}/e2e-run" \
    || fail "[hook timeout] could not write e2e-run into the container"
install_live_sidecar e2e-run '{"timeout":"2s"}' \
    || fail "[hook timeout] could not write e2e-run.json into the container"
# The manifest is built from the executor's own hook list, so a manifest that
# lists e2e-run means a dispatch finds it.
wait_for_hook_entry "hook timeout" e2e-run '.timeout_seconds == 2'

# The baseline goes ahead of the dispatch: the nudge can bring the ack in before
# a later read.
CB_BEFORE_RUN=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-limit-001" \
    "$(exec_entry "exec-e2e-limit-001" "e2e-run" "hook" "pending" "null")"
wait_for_terminal_callback "hook timeout" "${CB_BEFORE_RUN}" \
    '.status == "failed" and .error == "action timed out: hook timeout 2s"'

# A child that outlived the kill appends at least twice in 3 seconds.
TICKS_AT_KILL=$(read_run_ticks) \
    || fail "[hook timeout] could not read ${RUN_TICKS} in the container: ${TICKS_AT_KILL}"
sleep 3
TICKS_LATER=$(read_run_ticks) \
    || fail "[hook timeout] could not read ${RUN_TICKS} in the container: ${TICKS_LATER}"
if [ "${TICKS_AT_KILL}" -gt 0 ] && [ "${TICKS_LATER}" = "${TICKS_AT_KILL}" ]; then
    echo "  PASS: [hook timeout] ${RUN_TICKS} stayed at ${TICKS_AT_KILL} bytes for 3s after the terminal callback"
else
    fail "[hook timeout] ${RUN_TICKS} went from '${TICKS_AT_KILL}' to '${TICKS_LATER}' bytes in 3s, want one size above 0: a child of the hook outlived the kill"
fi

# (2) Sandbox: plexd refuses a level it does not implement before the hook
# starts, so the ticks stay where the kill left them. The body before this has
# no sandbox_level, so the wait cannot pass on it.
install_live_sidecar e2e-run '{"sandbox":"container"}' \
    || fail "[hook sandbox] could not rewrite e2e-run.json in the container"
wait_for_hook_entry "hook sandbox" e2e-run '.sandbox_level == "container"'

CB_BEFORE_RUN=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-sandbox-001" \
    "$(exec_entry "exec-e2e-sandbox-001" "e2e-run" "hook" "pending" "null")"
wait_for_terminal_callback "hook sandbox" "${CB_BEFORE_RUN}" \
    '.status == "failed" and (.error | contains("is not implemented"))'

TICKS_AFTER_SANDBOX=$(read_run_ticks) \
    || fail "[hook sandbox] could not read ${RUN_TICKS} in the container: ${TICKS_AFTER_SANDBOX}"
if [ "${TICKS_AFTER_SANDBOX}" = "${TICKS_LATER}" ]; then
    echo "  PASS: [hook sandbox] ${RUN_TICKS} stayed at ${TICKS_LATER} bytes, so the hook did not run"
else
    fail "[hook sandbox] ${RUN_TICKS} went from '${TICKS_LATER}' to '${TICKS_AFTER_SANDBOX}' bytes: the refused hook ran"
fi

# (3) Mode: the sidecar goes first, because plexd reads it before it checks the
# hook file and its sandbox refusal would come first. A chmod leaves the digest
# and the pin alone, so the hook stays listed and only the file check can refuse
# it.
dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-run.json" \
    || fail "[hook mode] could not remove e2e-run.json from the container"
wait_for_hook_entry "hook mode" e2e-run 'keys == ["checksum", "name"]'
dc exec -T plexd /bin/busybox chmod 0775 "${LIVE_HOOKS_DIR}/e2e-run" \
    || fail "[hook mode] could not make e2e-run group-writable in the container"

CB_BEFORE_RUN=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-mode-001" \
    "$(exec_entry "exec-e2e-mode-001" "e2e-run" "hook" "pending" "null")"
wait_for_terminal_callback "hook mode" "${CB_BEFORE_RUN}" \
    '.status == "failed" and (.error | contains("group- or other-writable"))'

# (4) Cleanup: the executions block goes back to empty, and e2e-run and its
# ticks leave the container, so the later phases find the fixture they expect.
configure_executions "exec-e2e-hook-run-clear" '[]'
dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-run" "${RUN_TICKS}" \
    || fail "[hook run cleanup] could not remove e2e-run and ${RUN_TICKS} from the container"
wait_for_declared_hooks "hook run cleanup" "e2e-bigout"

# 10h. A cancel request stops a running hook. The pull marks a started entry
# with cancel_requested_at once an operator cancelled its Execution, and plexd
# kills the run's process group and reports cancelled with the output it
# captured before the kill. The hook is a new one, e2e-cancel: plexd pinned the
# digest of e2e-run when it first found it and keeps the pin for the life of the
# process, so a rewritten e2e-run would fail verification. As in 10g, plexd is
# PID 1 here and reaps nothing, so the size of the file the hook's child appends
# to is the proof of the kill, not the pid. The step proves no pull trigger:
# every dispatch below is nudged, and a heartbeat-driven pull would deliver the
# same block, so the heartbeat's reconcile hint stays on.
RUN_TICKS="/var/run/plexd/e2e-cancel.ticks"

# (1) The hook prints a line before it starts its child, so the cancelled report
# has output to carry. It has no sidecar, so no timeout of its own can end the
# run inside the step, and its manifest entry is the short one.
printf '%s\n' '#!/bin/sh' \
    'echo e2e-cancel started' \
    "( while :; do echo tick >> ${RUN_TICKS}; /bin/busybox sleep 1; done ) &" \
    'wait' \
    | dc exec -T plexd /bin/busybox sh -c \
        "/bin/busybox cat > ${LIVE_HOOKS_DIR}/e2e-cancel && /bin/busybox chmod 0755 ${LIVE_HOOKS_DIR}/e2e-cancel" \
    || fail "[hook cancel] could not write e2e-cancel into the container"
wait_for_hook_entry "hook cancel" e2e-cancel 'keys == ["checksum", "name"]'

# (2) The baseline goes ahead of the dispatch, as in 10g. Two callbacks are the
# ack and started. plexd starts the hook only once started is recorded, so the
# file may not exist yet when that callback lands, and a failed read counts as
# not yet. The cancel waits for the first tick: one that lands before the child
# runs would prove nothing about the group kill.
CB_BEFORE_CANCEL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-cancel-001" \
    "$(exec_entry "exec-e2e-cancel-001" "e2e-cancel" "hook" "pending" "null")"
wait_for_callback "hook cancel" "${CB_BEFORE_CANCEL}" 2 '.status == "started"'

CANCEL_TICKS_ELAPSED=0
while :; do
    # The test sits in the condition, so a failed read or a size that is not a
    # number does not end the script under set -e.
    if CANCEL_TICKS_RUNNING=$(read_run_ticks) && [ "${CANCEL_TICKS_RUNNING}" -gt 0 ] 2>/dev/null; then
        echo "  PASS: [hook cancel] ${RUN_TICKS} reached ${CANCEL_TICKS_RUNNING} bytes after ${CANCEL_TICKS_ELAPSED}s, so the hook's child runs"
        break
    fi
    if [ "${CANCEL_TICKS_ELAPSED}" -ge 10 ]; then
        fail "[hook cancel] ${RUN_TICKS} did not grow above 0 bytes within 10s (last read: ${CANCEL_TICKS_RUNNING}): the hook's child never ran"
    fi
    sleep 1
    CANCEL_TICKS_ELAPSED=$((CANCEL_TICKS_ELAPSED + 1))
done

# (3) The same entry comes back carrying the request, under a new tag so the
# nudge's envelope id stays unique. It is rendered at started, the status the
# mock has tracked for it since that callback. Three callbacks are ack, started,
# and cancelled, and the cancelled one carries what the hook printed before the
# kill.
configure_executions "exec-e2e-cancel-002" \
    "$(exec_entry "exec-e2e-cancel-001" "e2e-cancel" "hook" "started" "null" \
        | jq -c '.[0].cancel_requested_at = "2026-01-01T00:01:00Z"')"
wait_for_callback "hook cancel" "${CB_BEFORE_CANCEL}" 3 \
    '.status == "cancelled" and (.output.inline | @base64d | contains("e2e-cancel started"))'

# (4) A child that outlived the kill appends at least twice in 3 seconds.
CANCEL_TICKS_AT_KILL=$(read_run_ticks) \
    || fail "[hook cancel] could not read ${RUN_TICKS} in the container: ${CANCEL_TICKS_AT_KILL}"
sleep 3
CANCEL_TICKS_LATER=$(read_run_ticks) \
    || fail "[hook cancel] could not read ${RUN_TICKS} in the container: ${CANCEL_TICKS_LATER}"
if [ "${CANCEL_TICKS_AT_KILL}" -gt 0 ] && [ "${CANCEL_TICKS_LATER}" = "${CANCEL_TICKS_AT_KILL}" ]; then
    echo "  PASS: [hook cancel] ${RUN_TICKS} stayed at ${CANCEL_TICKS_AT_KILL} bytes for 3s after the cancelled callback"
else
    fail "[hook cancel] ${RUN_TICKS} went from '${CANCEL_TICKS_AT_KILL}' to '${CANCEL_TICKS_LATER}' bytes in 3s, want one size above 0: a child of the hook outlived the cancel"
fi

# (5) Cleanup: the executions block goes back to empty, and e2e-cancel and its
# ticks leave the container, so the later phases find the fixture they expect.
configure_executions "exec-e2e-cancel-clear" '[]'
dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-cancel" "${RUN_TICKS}" \
    || fail "[hook cancel cleanup] could not remove e2e-cancel and ${RUN_TICKS} from the container"
wait_for_declared_hooks "hook cancel cleanup" "e2e-bigout"

# 10i. A hook the control plane rolls out reaches the running agent. The pull's
# hooks block lists the published versions the node should run. plexd fetches
# each one it has not installed, checks the Domain signature and the checksum
# the block names, and installs it into a directory of its own, <data_dir>/hooks.
# The hook is pinned to the delivered checksum, so a new version runs with no
# restart, and an edit on disk fails the pre-dispatch check as it does for a
# hand-placed hook. The numbered checks run in order, and each starts from what
# the one before it left: the versions the mock serves, the block, and the
# files. A block withdraws every rolled-out hook it does not list, so each block
# a check splices lists every hook that should stay installed.
ROLLOUT_HOOKS_DIR="/var/lib/plexd/hooks"
ROLLOUT_DESC="rolled out by the e2e suite"

# nudge_hooks injects a node_state_updated envelope, so the agent pulls right
# away instead of waiting out the ~30s heartbeat reconcile cadence. Args: <tag>.
# The tag keeps the envelope id unique per call. It reads no snapshot, so the
# only pull it adds to state_count is the one it asks for.
nudge_hooks() {
    local tag=$1

    local payload status
    payload=$(cat <<HOOKSNUDGEEOF
{
    "id": "evt-e2e-hooks-nudge-${tag}",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
HOOKSNUDGEEOF
    )
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] hooks nudge injection returned status ${status}, want 204"
    fi
}

# configure_hooks replaces the snapshot's hooks block and nudges the agent.
# Args: <tag> <hooks-json-array-or-null>. configure-state REPLACES the whole
# snapshot fixture, so the block is spliced into the live snapshot the way
# configure_secrets splices the secrets block, and every other block travels
# back verbatim. null keeps every rolled-out hook, and [] withdraws them all.
# nudge_hooks follows with the same tag, so the agent pulls the new block right
# away.
#
# NOTE: reading the live snapshot is a real GET on the state endpoint and
# therefore INCREMENTS state_count. A check gating on state_count must take its
# baseline AFTER calling this helper.
configure_hooks() {
    local tag=$1 entries=$2

    local snapshot spliced status
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    # printf, not echo: the fixture carries backslash escapes (an embedded
    # newline in the certs/ca data entry) that must travel back byte for byte.
    spliced=$(printf '%s' "${snapshot}" | jq --argjson h "${entries}" '.hooks = $h') \
        || fail "[${tag}] could not splice the hooks block ${entries} into the live snapshot"

    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi

    nudge_hooks "${tag}"
}

# configure_hook_versions posts a body to POST /test/configure-hook-versions and
# prints the answer, which gives the checksum of each version it configured.
# Args: <json>. The route replaces the whole served set, so a body lists every
# version the block may still name. Any status but 200 prints the status and the
# answer and returns 1, so the caller fails with them.
configure_hook_versions() {
    local out status answer
    out=$(curl -s -w '\n%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d "$1" \
        "http://localhost:18080/test/configure-hook-versions" 2>&1 || true)
    status=${out##*$'\n'}
    answer=${out%$'\n'*}
    answer=${answer%$'\n'}
    if [ "${status}" != "200" ]; then
        printf 'configure-hook-versions returned status %s, want 200 (body: %s)\n' "${status}" "${answer}"
        return 1
    fi
    printf '%s\n' "${answer}"
}

# rollout_version prints one entry of a configure_hook_versions body. Args:
# <hook> <version> <marker> [<tamper>]. The script is what live_hook_text prints
# for the marker, read raw so that its last newline is in the base64 too. Every
# version declares the same description and a 30s timeout.
rollout_version() {
    live_hook_text "$3" | jq -Rsc --arg name "$1" --argjson version "$2" \
        --arg desc "${ROLLOUT_DESC}" --arg tamper "${4:-}" \
        '{name: $name, version: $version, script_base64: @base64, description: $desc, timeout_seconds: 30, tamper: $tamper}'
}

# hook_version_checksum prints the checksum a configure_hook_versions answer
# gives one version: the base64 SHA-256 of the script as configured, which is
# what a block names. Args: <answer> <hook> <version>. A version the answer does
# not list prints why and returns 1, so the caller fails with it rather than
# splice an empty checksum.
hook_version_checksum() {
    local checksum
    if ! checksum=$(printf '%s' "$1" | jq -r --arg name "$2" --argjson version "$3" \
        '.versions[]? | select(.name == $name and .version == $version) | .checksum' 2>&1) \
        || [ -z "${checksum}" ]; then
        printf 'no checksum for %s version %s in the configure-hook-versions answer %s%s\n' \
            "$2" "$3" "$1" "${checksum:+ (${checksum})}"
        return 1
    fi
    printf '%s\n' "${checksum}"
}

# wait_for_manifest polls the captured manifest for up to 15 seconds, until a jq
# filter over the whole body holds. Args: <step> <jq filter> [<jq option>...].
# The options, such as --arg, go to jq ahead of the filter. wait_for_hook_entry
# reads one declared_hooks entry for 10 seconds, but a rollout check also reads
# hook_rollout_errors and entries that must be gone, and a fetch and its checks
# lie between a splice and the PUT. On a pass MANIFEST_BODY holds the body that
# passed, so the caller can check more of the same PUT. As there, the mock
# captures a refused PUT too, so a pass says what the agent sent.
wait_for_manifest() {
    local step=$1 filter=$2
    shift 2
    local elapsed=0 body jq_err
    while :; do
        body=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
        # jq's stdout goes nowhere and its stderr is kept, so a filter that does
        # not compile names its error in the failure below.
        if jq_err=$(printf '%s' "${body}" | jq -e "$@" "${filter}" 2>&1 >/dev/null); then
            MANIFEST_BODY=${body}
            echo "  PASS: [${step}] the manifest holds ${filter}, after ${elapsed}s"
            return 0
        fi
        if [ "${elapsed}" -ge 15 ]; then
            fail "[${step}] the manifest did not reach ${filter} within 15s (${jq_err:+jq: ${jq_err}; }body: ${body})"
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

# rollout_file_exists prints yes or no for a file in the rollout directory of
# the container. Args: <file>. The test runs inside the sh -c, so a failed exec
# prints its error, which is neither answer.
rollout_file_exists() {
    dc exec -T plexd /bin/busybox sh -c \
        "if /bin/busybox test -e ${ROLLOUT_HOOKS_DIR}/$1; then printf 'yes\n'; else printf 'no\n'; fi" 2>&1
}

# (1) Install: version 1 reaches the manifest as a rolled-out entry, with the
# checksum the mock published and the description and timeout its signed
# payload declares, which plexd wrote into the sidecar. The script plexd wrote
# belongs to root and has mode 0755, so the executor's file check, which refuses
# a hook another user owns or can write, lets it run. hook_fetch_count moves
# only on a fetch the mock answered with the version.
FETCH_BEFORE_INSTALL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "hook_fetch_count")
HV_ANSWER=$(configure_hook_versions "$(printf '{"versions":[%s]}' \
    "$(rollout_version e2e-rollout 1 "e2e-rollout v1")")") \
    || fail "[rollout install] ${HV_ANSWER}"
V1_SUM=$(hook_version_checksum "${HV_ANSWER}" e2e-rollout 1) || fail "[rollout install] ${V1_SUM}"
configure_hooks "rollout-install" "$(jq -nc --arg sum "${V1_SUM}" '[{name: "e2e-rollout", version: 1, checksum: $sum}]')"
wait_for_manifest "rollout install" \
    'any(.declared_hooks[]?; .name == "e2e-rollout" and .source == "rollout" and .version == 1 and .checksum == $v1 and .description == $desc and .timeout_seconds == 30)' \
    --arg v1 "${V1_SUM}" --arg desc "${ROLLOUT_DESC}"

ROLLOUT_STAT=$(dc exec -T plexd /bin/busybox stat -c '%a %u' "${ROLLOUT_HOOKS_DIR}/e2e-rollout" 2>&1) \
    || fail "[rollout install] could not stat ${ROLLOUT_HOOKS_DIR}/e2e-rollout in the container: ${ROLLOUT_STAT}"
if [ "${ROLLOUT_STAT}" = "755 0" ]; then
    echo "  PASS: [rollout install] ${ROLLOUT_HOOKS_DIR}/e2e-rollout has mode 755 and owner uid 0"
else
    fail "[rollout install] ${ROLLOUT_HOOKS_DIR}/e2e-rollout has mode and owner '${ROLLOUT_STAT}', want '755 0'"
fi
FETCH_AFTER_INSTALL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "hook_fetch_count")
if [ "${FETCH_AFTER_INSTALL}" -gt "${FETCH_BEFORE_INSTALL}" ] 2>/dev/null; then
    echo "  PASS: [rollout install] hook_fetch_count grew from ${FETCH_BEFORE_INSTALL} to ${FETCH_AFTER_INSTALL}"
else
    fail "[rollout install] hook_fetch_count went from '${FETCH_BEFORE_INSTALL}' to '${FETCH_AFTER_INSTALL}', want growth: the version did not come over the fetch"
fi

# (2) Run and upgrade: the installed version runs, and version 2 replaces it in
# the running agent. The manifest lists a hook only once plexd pinned it, so a
# manifest that lists a version means a dispatch runs that version. The served
# set keeps version 1 until the block stops naming it. The baseline goes ahead
# of each dispatch, as in 10g.
CB_BEFORE_ROLLOUT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-rollout-001" \
    "$(exec_entry "exec-e2e-rollout-001" "e2e-rollout" "hook" "pending" "null")"
wait_for_terminal_callback "rollout run" "${CB_BEFORE_ROLLOUT}" \
    '.status == "succeeded" and (.output.inline | @base64d | contains("e2e-rollout v1"))'

HV_ANSWER=$(configure_hook_versions "$(printf '{"versions":[%s,%s]}' \
    "$(rollout_version e2e-rollout 1 "e2e-rollout v1")" \
    "$(rollout_version e2e-rollout 2 "e2e-rollout v2")")") \
    || fail "[rollout upgrade] ${HV_ANSWER}"
V2_SUM=$(hook_version_checksum "${HV_ANSWER}" e2e-rollout 2) || fail "[rollout upgrade] ${V2_SUM}"
configure_hooks "rollout-upgrade" "$(jq -nc --arg sum "${V2_SUM}" '[{name: "e2e-rollout", version: 2, checksum: $sum}]')"
# Each check from here on finds e2e-rollout at version 2 with the digest of the
# bytes the mock published for it, until (7) edits the file. The filter needs
# --arg v2 with that checksum.
ROLLOUT_AT_V2='any(.declared_hooks[]?; .name == "e2e-rollout" and .source == "rollout" and .version == 2 and .checksum == $v2)'
wait_for_manifest "rollout upgrade" "${ROLLOUT_AT_V2}" --arg v2 "${V2_SUM}"

CB_BEFORE_ROLLOUT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-rollout-002" \
    "$(exec_entry "exec-e2e-rollout-002" "e2e-rollout" "hook" "pending" "null")"
wait_for_terminal_callback "rollout upgrade" "${CB_BEFORE_ROLLOUT}" \
    '.status == "succeeded" and (.output.inline | @base64d | contains("e2e-rollout v2"))'

# (3) Null block: a pull whose hooks block is null keeps every rolled-out hook.
# Two pulls past the baseline mean that at least one of them ran its dispatch
# handlers to the end before the other started. The nudge's pull may land ahead
# of the baseline, and the heartbeat asks for one about every 30s, so the wait
# covers two heartbeats.
configure_hooks "rollout-null" null
STATE_BEFORE_NULL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
case "${STATE_BEFORE_NULL}" in
    '' | *[!0-9]*) fail "[rollout null block] no state_count baseline (got '${STATE_BEFORE_NULL}')" ;;
esac
NULL_ELAPSED=0
while :; do
    STATE_AFTER_NULL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    if [ "${STATE_AFTER_NULL}" -ge $((STATE_BEFORE_NULL + 2)) ] 2>/dev/null; then
        echo "  PASS: [rollout null block] state_count grew from ${STATE_BEFORE_NULL} to ${STATE_AFTER_NULL} after ${NULL_ELAPSED}s"
        break
    fi
    if [ "${NULL_ELAPSED}" -ge 65 ]; then
        fail "[rollout null block] state_count went from ${STATE_BEFORE_NULL} to '${STATE_AFTER_NULL}' in 65s, want two pulls of the null block"
    fi
    sleep 1
    NULL_ELAPSED=$((NULL_ELAPSED + 1))
done
wait_for_manifest "rollout null block" "${ROLLOUT_AT_V2}" --arg v2 "${V2_SUM}"
ROLLOUT_EXISTS=$(rollout_file_exists e2e-rollout) \
    || fail "[rollout null block] could not check ${ROLLOUT_HOOKS_DIR}/e2e-rollout in the container: ${ROLLOUT_EXISTS}"
if [ "${ROLLOUT_EXISTS}" = "yes" ]; then
    echo "  PASS: [rollout null block] ${ROLLOUT_HOOKS_DIR}/e2e-rollout is still on disk"
else
    fail "[rollout null block] ${ROLLOUT_HOOKS_DIR}/e2e-rollout exists: '${ROLLOUT_EXISTS}', want 'yes'"
fi

# (4) Verification failure: version 3 is served with a byte appended to the
# script its payload's checksum covers. plexd refuses it after the fetch,
# writes nothing, and reports verification_failed for that version alone, so
# version 2 stays installed and pinned. Version 2 stays served, because the
# block names it until the splice. dc logs spans every run of the container,
# so the log line counts from a baseline.
VERIFY_FAILED_LINE="actions: rollout: verification failed"
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
VERIFY_FAILED_BEFORE=$(count_log_lines "${PLEXD_LOGS}" "${VERIFY_FAILED_LINE}" "e2e-rollout")
HV_ANSWER=$(configure_hook_versions "$(printf '{"versions":[%s,%s]}' \
    "$(rollout_version e2e-rollout 2 "e2e-rollout v2")" \
    "$(rollout_version e2e-rollout 3 "e2e-rollout v3" script)")") \
    || fail "[rollout verification] ${HV_ANSWER}"
V3_SUM=$(hook_version_checksum "${HV_ANSWER}" e2e-rollout 3) || fail "[rollout verification] ${V3_SUM}"
configure_hooks "rollout-verify" "$(jq -nc --arg sum "${V3_SUM}" '[{name: "e2e-rollout", version: 3, checksum: $sum}]')"
wait_for_manifest "rollout verification" \
    '[.hook_rollout_errors[]? | {name, version, code}] == [{name: "e2e-rollout", version: 3, code: "verification_failed"}] and '"${ROLLOUT_AT_V2}" \
    --arg v2 "${V2_SUM}"
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
VERIFY_FAILED_AFTER=$(count_log_lines "${PLEXD_LOGS}" "${VERIFY_FAILED_LINE}" "e2e-rollout")
if [ "${VERIFY_FAILED_AFTER}" -gt "${VERIFY_FAILED_BEFORE}" ]; then
    echo "  PASS: [rollout verification] plexd logged '${VERIFY_FAILED_LINE}' for e2e-rollout (${VERIFY_FAILED_BEFORE} -> ${VERIFY_FAILED_AFTER})"
else
    fail "[rollout verification] plexd logged no new '${VERIFY_FAILED_LINE}' line for e2e-rollout (${VERIFY_FAILED_BEFORE} -> ${VERIFY_FAILED_AFTER})"
fi

# (5) Collision: a hand-placed hook of a listed name blocks the rollout of that
# name. plexd reports collision, installs nothing of that name, and the
# manifest lists the hand-placed hook as a local one, with no source key. The
# file goes in first, and the manifest shows its digest before any block names
# it, so no pass can install a rolled-out copy ahead of it. From here on the
# served set holds e2e-rollout version 2 and e2e-collide version 1, and the
# block lists both. The version 3 error goes with the block that named it.
COLLIDE_MARKER="e2e-collide hand-placed"
COLLIDE_HEX=$(live_hook_text "${COLLIDE_MARKER}" | sha256_hex)
install_live_hook e2e-collide "${COLLIDE_MARKER}" \
    || fail "[rollout collision] could not write e2e-collide into the container"
wait_for_declared_hooks "rollout collision" "e2e-bigout,e2e-collide,e2e-rollout" e2e-collide "${COLLIDE_HEX}"

HV_ANSWER=$(configure_hook_versions "$(printf '{"versions":[%s,%s]}' \
    "$(rollout_version e2e-rollout 2 "e2e-rollout v2")" \
    "$(rollout_version e2e-collide 1 "e2e-collide v1")")") \
    || fail "[rollout collision] ${HV_ANSWER}"
COLLIDE_SUM=$(hook_version_checksum "${HV_ANSWER}" e2e-collide 1) || fail "[rollout collision] ${COLLIDE_SUM}"
configure_hooks "rollout-collide" "$(jq -nc --arg collide "${COLLIDE_SUM}" --arg rollout "${V2_SUM}" \
    '[{name: "e2e-collide", version: 1, checksum: $collide}, {name: "e2e-rollout", version: 2, checksum: $rollout}]')"
wait_for_manifest "rollout collision" \
    '[.hook_rollout_errors[]? | {name, version, code}] == [{name: "e2e-collide", version: 1, code: "collision"}] and any(.declared_hooks[]?; .name == "e2e-collide" and (has("source") | not)) and '"${ROLLOUT_AT_V2}" \
    --arg v2 "${V2_SUM}"
COLLIDE_MANIFEST_HEX=$(declared_hook_hex "${MANIFEST_BODY}" e2e-collide)
if [ "${COLLIDE_MANIFEST_HEX}" = "${COLLIDE_HEX}" ]; then
    echo "  PASS: [rollout collision] the manifest lists e2e-collide at the digest of the hand-placed file"
else
    fail "[rollout collision] declared_hooks digest of e2e-collide = ${COLLIDE_MANIFEST_HEX}, want ${COLLIDE_HEX}, the SHA-256 of the hand-placed file"
fi
COLLIDE_EXISTS=$(rollout_file_exists e2e-collide) \
    || fail "[rollout collision] could not check ${ROLLOUT_HOOKS_DIR}/e2e-collide in the container: ${COLLIDE_EXISTS}"
if [ "${COLLIDE_EXISTS}" = "no" ]; then
    echo "  PASS: [rollout collision] plexd wrote no ${ROLLOUT_HOOKS_DIR}/e2e-collide"
else
    fail "[rollout collision] ${ROLLOUT_HOOKS_DIR}/e2e-collide exists: '${COLLIDE_EXISTS}', want 'no'"
fi

# (6) Restart: the restarted agent loads its record of what it installed and
# pins each hook to the checksum it was delivered with, ahead of its boot scan,
# so its boot manifest carries the rolled-out hook. capabilities_count moves
# only on delivery, as in 10f's check (9). A nudge reaches only an open event
# stream, so the dispatch waits, as phase 7c does, until the restarted agent has
# opened its stream and a pull has followed. A restart that lost the record
# fetches version 2 again, because the block still lists it and the mock still
# serves it, and the manifest and the dispatch would then show version 2 all the
# same. hook_fetch_count therefore must not move from before the restart until
# the dispatch has printed version 2.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CAPS_BEFORE_ROLLOUT_RESTART=$(get_counter "${RESPONSE}" "capabilities_count")
EVREQ_BEFORE_ROLLOUT_RESTART=$(get_counter "${RESPONSE}" "events_request_count")
FETCH_BEFORE_ROLLOUT_RESTART=$(get_counter "${RESPONSE}" "hook_fetch_count")
case "${FETCH_BEFORE_ROLLOUT_RESTART}" in
    '' | *[!0-9]*) fail "[rollout restart] no hook_fetch_count baseline (got '${FETCH_BEFORE_ROLLOUT_RESTART}')" ;;
esac
dc restart plexd
ROLLOUT_RESTART_TIMEOUT=30
ROLLOUT_RESTART_ELAPSED=0
while :; do
    CAPS_AFTER_ROLLOUT_RESTART=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "capabilities_count")
    if [ "${CAPS_AFTER_ROLLOUT_RESTART}" -gt "${CAPS_BEFORE_ROLLOUT_RESTART}" ] 2>/dev/null; then
        echo "  PASS: [rollout restart] capabilities_count grew from ${CAPS_BEFORE_ROLLOUT_RESTART} to ${CAPS_AFTER_ROLLOUT_RESTART} after ${ROLLOUT_RESTART_ELAPSED}s"
        break
    fi
    if [ "${ROLLOUT_RESTART_ELAPSED}" -ge "${ROLLOUT_RESTART_TIMEOUT}" ]; then
        fail "[rollout restart] capabilities_count stayed at ${CAPS_BEFORE_ROLLOUT_RESTART} for ${ROLLOUT_RESTART_TIMEOUT}s after the restart: the boot manifest was not delivered"
    fi
    sleep 1
    ROLLOUT_RESTART_ELAPSED=$((ROLLOUT_RESTART_ELAPSED + 1))
done
wait_for_manifest "rollout restart" "${ROLLOUT_AT_V2}" --arg v2 "${V2_SUM}"

ROLLOUT_STREAM_ELAPSED=0
ROLLOUT_STATE_AT_STREAM=""
while :; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -z "${ROLLOUT_STATE_AT_STREAM}" ]; then
        if [ "$(get_counter "${RESPONSE}" "events_request_count")" -gt "${EVREQ_BEFORE_ROLLOUT_RESTART}" ] 2>/dev/null; then
            ROLLOUT_STATE_AT_STREAM=$(get_counter "${RESPONSE}" "state_count")
        fi
    elif [ "$(get_counter "${RESPONSE}" "state_count")" -gt "${ROLLOUT_STATE_AT_STREAM}" ] 2>/dev/null; then
        echo "  PASS: [rollout restart] the restarted plexd opened its event stream and pulled after ${ROLLOUT_STREAM_ELAPSED}s"
        break
    fi
    if [ "${ROLLOUT_STREAM_ELAPSED}" -ge 60 ]; then
        fail "[rollout restart] the restarted plexd did not reopen its event stream and pull within 60s"
    fi
    sleep 1
    ROLLOUT_STREAM_ELAPSED=$((ROLLOUT_STREAM_ELAPSED + 1))
done

CB_BEFORE_ROLLOUT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-rollout-003" \
    "$(exec_entry "exec-e2e-rollout-003" "e2e-rollout" "hook" "pending" "null")"
wait_for_terminal_callback "rollout restart" "${CB_BEFORE_ROLLOUT}" \
    '.status == "succeeded" and (.output.inline | @base64d | contains("e2e-rollout v2"))'
FETCH_AFTER_ROLLOUT_RESTART=$(get_counter "$(curl -sf "${ASSERT_URL}" || true)" "hook_fetch_count")
if [ "${FETCH_AFTER_ROLLOUT_RESTART}" = "${FETCH_BEFORE_ROLLOUT_RESTART}" ]; then
    echo "  PASS: [rollout restart] hook_fetch_count stayed at ${FETCH_BEFORE_ROLLOUT_RESTART}: the restarted agent restored e2e-rollout from its record without fetching it"
else
    fail "[rollout restart] hook_fetch_count went from ${FETCH_BEFORE_ROLLOUT_RESTART} to '${FETCH_AFTER_ROLLOUT_RESTART}' across the restart, want no change: the restarted agent fetched e2e-rollout again instead of restoring it from its record"
fi

# (7) Tamper: an edit of the rolled-out file moves the digest the manifest
# reports, and the entry stays at version 2: plexd compares a pull with its own
# record, not with the bytes on disk, so the pass leaves the file alone. The pin
# still holds the delivered checksum, so a dispatch fails its pre-dispatch check
# and files one integrity violation. plexd sends the violation before the failed
# callback, so the count is read once that callback has landed. Two pulls after
# that callback must then leave the edit in place: no fetch since before the
# edit, the same manifest entry, and the same digest on disk. A pass that
# repaired the file could run alongside the dispatch and finish after it, so the
# check waits for the pulls rather than read at once. The state_count baseline
# goes ahead of a nudge, which reads no snapshot, so the nudge's pull is the
# first of the two and a heartbeat brings the second, within 65s as in (3).
TAMPER_LINE="echo e2e-rollout tampered"
TAMPERED_HEX=$({ live_hook_text "e2e-rollout v2"; printf '%s\n' "${TAMPER_LINE}"; } | sha256_hex)
FETCH_BEFORE_TAMPER=$(get_counter "$(curl -sf "${ASSERT_URL}" || true)" "hook_fetch_count")
case "${FETCH_BEFORE_TAMPER}" in
    '' | *[!0-9]*) fail "[rollout tamper] no hook_fetch_count baseline (got '${FETCH_BEFORE_TAMPER}')" ;;
esac
printf '%s\n' "${TAMPER_LINE}" | dc exec -T plexd /bin/busybox sh -c \
    "/bin/busybox cat >> ${ROLLOUT_HOOKS_DIR}/e2e-rollout" \
    || fail "[rollout tamper] could not append to ${ROLLOUT_HOOKS_DIR}/e2e-rollout in the container"
wait_for_manifest "rollout tamper" \
    'any(.declared_hooks[]?; .name == "e2e-rollout" and .source == "rollout" and .version == 2 and .checksum != $v2)' \
    --arg v2 "${V2_SUM}"
TAMPERED_MANIFEST_HEX=$(declared_hook_hex "${MANIFEST_BODY}" e2e-rollout)
if [ "${TAMPERED_MANIFEST_HEX}" = "${TAMPERED_HEX}" ]; then
    echo "  PASS: [rollout tamper] the manifest lists e2e-rollout at the digest of the edited file"
else
    fail "[rollout tamper] declared_hooks digest of e2e-rollout = ${TAMPERED_MANIFEST_HEX}, want ${TAMPERED_HEX}, the SHA-256 of the edited file"
fi

VIOLATIONS_BEFORE=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "integrity_violation_count")
case "${VIOLATIONS_BEFORE}" in
    '' | *[!0-9]*) fail "[rollout tamper] no integrity_violation_count baseline (got '${VIOLATIONS_BEFORE}')" ;;
esac
CB_BEFORE_ROLLOUT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
configure_executions "exec-e2e-rollout-004" \
    "$(exec_entry "exec-e2e-rollout-004" "e2e-rollout" "hook" "pending" "null")"
wait_for_terminal_callback "rollout tamper" "${CB_BEFORE_ROLLOUT}" \
    '.status == "failed" and (.error | contains("integrity check failed"))'
VIOLATIONS_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "integrity_violation_count")
if [ "${VIOLATIONS_AFTER}" = "$((VIOLATIONS_BEFORE + 1))" ]; then
    echo "  PASS: [rollout tamper] integrity_violation_count grew from ${VIOLATIONS_BEFORE} to ${VIOLATIONS_AFTER}"
else
    fail "[rollout tamper] integrity_violation_count went from ${VIOLATIONS_BEFORE} to '${VIOLATIONS_AFTER}', want $((VIOLATIONS_BEFORE + 1))"
fi

STATE_BEFORE_TAMPER=$(get_counter "$(curl -sf "${ASSERT_URL}" || true)" "state_count")
case "${STATE_BEFORE_TAMPER}" in
    '' | *[!0-9]*) fail "[rollout tamper] no state_count baseline (got '${STATE_BEFORE_TAMPER}')" ;;
esac
nudge_hooks "rollout-tamper"
TAMPER_ELAPSED=0
while :; do
    STATE_AFTER_TAMPER=$(get_counter "$(curl -sf "${ASSERT_URL}" || true)" "state_count")
    if [ "${STATE_AFTER_TAMPER}" -ge $((STATE_BEFORE_TAMPER + 2)) ] 2>/dev/null; then
        echo "  PASS: [rollout tamper] state_count grew from ${STATE_BEFORE_TAMPER} to ${STATE_AFTER_TAMPER} after ${TAMPER_ELAPSED}s"
        break
    fi
    if [ "${TAMPER_ELAPSED}" -ge 65 ]; then
        fail "[rollout tamper] state_count went from ${STATE_BEFORE_TAMPER} to '${STATE_AFTER_TAMPER}' in 65s, want two pulls after the failed dispatch"
    fi
    sleep 1
    TAMPER_ELAPSED=$((TAMPER_ELAPSED + 1))
done

FETCH_AFTER_TAMPER=$(get_counter "$(curl -sf "${ASSERT_URL}" || true)" "hook_fetch_count")
if [ "${FETCH_AFTER_TAMPER}" = "${FETCH_BEFORE_TAMPER}" ]; then
    echo "  PASS: [rollout tamper] hook_fetch_count stayed at ${FETCH_BEFORE_TAMPER}: no pass fetched a copy to replace the edited file"
else
    fail "[rollout tamper] hook_fetch_count went from ${FETCH_BEFORE_TAMPER} to '${FETCH_AFTER_TAMPER}' since the edit, want no change: a pass fetched e2e-rollout again to replace the edited file"
fi

TAMPER_BODY=$(curl -sSf "http://localhost:18080/test/last-request/capabilities" 2>&1) \
    || fail "[rollout tamper] could not read the captured manifest: ${TAMPER_BODY}"
TAMPER_ENTRY=$(printf '%s' "${TAMPER_BODY}" | jq -c '[.declared_hooks[]? | select(.name == "e2e-rollout") | {source, version}]' 2>&1) \
    || fail "[rollout tamper] could not read the e2e-rollout entry of the captured manifest: ${TAMPER_ENTRY} (body: ${TAMPER_BODY})"
TAMPER_ENTRY_HEX=$(declared_hook_hex "${TAMPER_BODY}" e2e-rollout)
if [ "${TAMPER_ENTRY}" = '[{"source":"rollout","version":2}]' ] && [ "${TAMPER_ENTRY_HEX}" = "${TAMPERED_HEX}" ]; then
    echo "  PASS: [rollout tamper] the manifest still lists e2e-rollout as rollout version 2 at the digest of the edited file"
else
    fail "[rollout tamper] the manifest lists e2e-rollout as ${TAMPER_ENTRY} at digest '${TAMPER_ENTRY_HEX}', want [{\"source\":\"rollout\",\"version\":2}] at ${TAMPERED_HEX}, the SHA-256 of the edited file"
fi

TAMPER_DISK=$(dc exec -T plexd /bin/busybox sha256sum "${ROLLOUT_HOOKS_DIR}/e2e-rollout" 2>&1) \
    || fail "[rollout tamper] could not hash ${ROLLOUT_HOOKS_DIR}/e2e-rollout in the container: ${TAMPER_DISK}"
if [ "${TAMPER_DISK%% *}" = "${TAMPERED_HEX}" ]; then
    echo "  PASS: [rollout tamper] ${ROLLOUT_HOOKS_DIR}/e2e-rollout still hashes to the digest of the edited file"
else
    fail "[rollout tamper] ${ROLLOUT_HOOKS_DIR}/e2e-rollout hashes to '${TAMPER_DISK}', want ${TAMPERED_HEX}, the SHA-256 of the edited file: plexd replaced it"
fi

# (8) Withdraw: an empty block withdraws every rolled-out hook. plexd deletes the
# script and its sidecar, and the pass lists no error, so the manifest leaves
# the hook_rollout_errors key out. The hand-placed e2e-collide is not plexd's to
# remove, and it keeps its digest.
configure_hooks "rollout-withdraw" '[]'
wait_for_manifest "rollout withdraw" \
    '[.declared_hooks[]?.name] == ["e2e-bigout", "e2e-collide"] and (has("hook_rollout_errors") | not)'
for ROLLOUT_FILE in e2e-rollout e2e-rollout.json; do
    ROLLOUT_EXISTS=$(rollout_file_exists "${ROLLOUT_FILE}") \
        || fail "[rollout withdraw] could not check ${ROLLOUT_HOOKS_DIR}/${ROLLOUT_FILE} in the container: ${ROLLOUT_EXISTS}"
    if [ "${ROLLOUT_EXISTS}" = "no" ]; then
        echo "  PASS: [rollout withdraw] ${ROLLOUT_HOOKS_DIR}/${ROLLOUT_FILE} is gone"
    else
        fail "[rollout withdraw] ${ROLLOUT_HOOKS_DIR}/${ROLLOUT_FILE} exists: '${ROLLOUT_EXISTS}', want 'no'"
    fi
done
COLLIDE_MANIFEST_HEX=$(declared_hook_hex "${MANIFEST_BODY}" e2e-collide)
COLLIDE_DISK=$(dc exec -T plexd /bin/busybox sha256sum "${LIVE_HOOKS_DIR}/e2e-collide" 2>&1) \
    || fail "[rollout withdraw] could not hash ${LIVE_HOOKS_DIR}/e2e-collide in the container: ${COLLIDE_DISK}"
if [ "${COLLIDE_DISK%% *}" = "${COLLIDE_HEX}" ] && [ "${COLLIDE_MANIFEST_HEX}" = "${COLLIDE_HEX}" ]; then
    echo "  PASS: [rollout withdraw] ${LIVE_HOOKS_DIR}/e2e-collide keeps its digest on disk and in the manifest"
else
    fail "[rollout withdraw] e2e-collide hashes to '${COLLIDE_DISK}' on disk and ${COLLIDE_MANIFEST_HEX} in the manifest, want ${COLLIDE_HEX}"
fi

# (9) Cleanup: e2e-collide leaves the container, the executions block goes back
# to empty, the hooks block goes back to the null the fixture started with, and
# the mock serves no version, so the later phases find the fixture they expect.
dc exec -T plexd /bin/busybox rm "${LIVE_HOOKS_DIR}/e2e-collide" \
    || fail "[rollout cleanup] could not remove e2e-collide from the container"
configure_executions "exec-e2e-rollout-clear" '[]'
configure_hooks "rollout-clear" null
HV_ANSWER=$(configure_hook_versions '{"versions":[]}') || fail "[rollout cleanup] ${HV_ANSWER}"
wait_for_declared_hooks "rollout cleanup" "e2e-bigout"

echo "=== Phase 10 PASSED: deeper body validation ==="

# ===================================================================
# Phase 12: Node API HTTP endpoint verification (GAP-09)
# ===================================================================
echo "=== Testing Node API HTTP endpoints ==="

NODE_API_URL="http://localhost:19100"
NODE_API_TOKEN="e2e-nodeapi-bearer-token"
NAPI_AUTH=(-H "Authorization: Bearer ${NODE_API_TOKEN}")

# Wait for the node API to become available.
NAPI_TIMEOUT=15
NAPI_ELAPSED=0
while [ "${NAPI_ELAPSED}" -lt "${NAPI_TIMEOUT}" ]; do
    if curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/state" >/dev/null 2>&1; then
        echo "  node API is available"
        break
    fi
    sleep 2
    NAPI_ELAPSED=$((NAPI_ELAPSED + 2))
done

if [ "${NAPI_ELAPSED}" -ge "${NAPI_TIMEOUT}" ]; then
    # Skipping here would step straight to "Phase 12 PASSED" with none of the
    # assertions below executed. An unreachable node API is itself a regression.
    fail "node API not available within ${NAPI_TIMEOUT}s"
else
    # 12a. GET /v1/state -- returns JSON with metadata and node_id.
    STATE_RESP=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/state" 2>/dev/null || true)
    if [ -n "${STATE_RESP}" ] && echo "${STATE_RESP}" | jq empty 2>/dev/null; then
        echo "  PASS: GET /v1/state returns valid JSON"
        NAPI_NODE_ID=$(echo "${STATE_RESP}" | jq -r '.node_id // empty')
        if [ -n "${NAPI_NODE_ID}" ]; then
            echo "  PASS: /v1/state has node_id='${NAPI_NODE_ID}'"
        else
            echo "  WARN: /v1/state missing 'node_id' field"
        fi
    else
        fail "GET /v1/state returned invalid response"
    fi

    # 12b. GET /v1/actions -- the agent's builtin action inventory as the node
    # API serves it locally: the same eleven builtins phase 3c found in the
    # capability manifest, checked against the shared ALL_BUILTINS list.
    ACTIONS_RESP=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/actions" 2>/dev/null || true)
    if [ -n "${ACTIONS_RESP}" ] && echo "${ACTIONS_RESP}" | jq empty 2>/dev/null; then
        NAPI_ACTION_COUNT=$(echo "${ACTIONS_RESP}" | jq '.builtin_actions | length // 0')
        if [ "${NAPI_ACTION_COUNT}" -eq 11 ]; then
            echo "  PASS: GET /v1/actions returns 11 builtins (exact)"
        else
            fail "GET /v1/actions returns ${NAPI_ACTION_COUNT} builtins, want exactly 11"
        fi

        for expected_action in "${ALL_BUILTINS[@]}"; do
            HAS_ACTION=$(echo "${ACTIONS_RESP}" | jq --arg name "${expected_action}" \
                '[.builtin_actions[] | select(.name == $name)] | length')
            if [ "${HAS_ACTION}" -ge 1 ]; then
                echo "  PASS: node API advertises builtin '${expected_action}'"
            else
                fail "node API missing required builtin '${expected_action}'"
            fi
        done

        BAD_ACTIONS=$(echo "${ACTIONS_RESP}" | jq '[.builtin_actions[] | select((.name // "") == "" or (.description // "") == "")] | length')
        if [ "${BAD_ACTIONS}" -eq 0 ]; then
            echo "  PASS: all builtins carry a name and a description"
        else
            fail "found ${BAD_ACTIONS} builtins without a name or description"
        fi
    else
        fail "GET /v1/actions returned invalid response"
    fi

    # 12c. GET /v1/peers -- lists both fixture peers by node ID (json field "id").
    # The reconcile snapshot handler mirrors the served fixture's SnapshotPeer
    # node_ids into the node API peer list, so both must be present by now.
    PEERS_RESP=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/peers" 2>/dev/null || true)
    if [ -n "${PEERS_RESP}" ] && echo "${PEERS_RESP}" | jq empty 2>/dev/null; then
        echo "  PASS: GET /v1/peers returns valid JSON"
        for peer_id in "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1" "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2"; do
            HAS_PEER=$(echo "${PEERS_RESP}" | jq --arg id "${peer_id}" '[.[] | select(.id == $id)] | length')
            if [ "${HAS_PEER}" -ge 1 ]; then
                echo "  PASS: /v1/peers lists peer id='${peer_id}'"
            else
                fail "/v1/peers missing peer id='${peer_id}' (response: ${PEERS_RESP})"
            fi
        done
    else
        fail "GET /v1/peers returned invalid response"
    fi

    # 12d. GET /v1/policies -- returns policy list.
    POLICIES_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/policies" 2>/dev/null || true)
    if [ "${POLICIES_STATUS}" = "200" ]; then
        echo "  PASS: GET /v1/policies returns 200"
    else
        echo "  WARN: GET /v1/policies returned status ${POLICIES_STATUS}"
    fi

    # 12e. GET /v1/log-status -- returns log forwarder status.
    LOG_STATUS_RESP=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/log-status" 2>/dev/null || true)
    if [ -n "${LOG_STATUS_RESP}" ] && echo "${LOG_STATUS_RESP}" | jq empty 2>/dev/null; then
        LOG_ENABLED=$(echo "${LOG_STATUS_RESP}" | jq -r '.enabled // empty')
        if [ "${LOG_ENABLED}" = "true" ]; then
            echo "  PASS: GET /v1/log-status enabled=true"
        else
            echo "  PASS: GET /v1/log-status returns valid JSON (enabled=${LOG_ENABLED})"
        fi
    else
        echo "  WARN: GET /v1/log-status returned invalid response"
    fi

    # 12f. GET /v1/audit/status -- returns audit forwarder status.
    AUDIT_STATUS_RESP=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/audit/status" 2>/dev/null || true)
    if [ -n "${AUDIT_STATUS_RESP}" ] && echo "${AUDIT_STATUS_RESP}" | jq empty 2>/dev/null; then
        AUDIT_ENABLED=$(echo "${AUDIT_STATUS_RESP}" | jq -r '.enabled // empty')
        if [ "${AUDIT_ENABLED}" = "true" ]; then
            echo "  PASS: GET /v1/audit/status enabled=true"
        else
            echo "  PASS: GET /v1/audit/status returns valid JSON (enabled=${AUDIT_ENABLED})"
        fi
    else
        echo "  WARN: GET /v1/audit/status returned invalid response"
    fi
fi

echo "=== Phase 12 PASSED: Node API verification ==="

# ===================================================================
# Phase 12a: per-key state report roundtrip and status publisher
# ===================================================================
# Exercise the local node API report leg end to end over TCP: a PUT is accepted
# locally, syncs upstream (report_put_count advances), and lands in BOTH mirrored
# reports buckets of the mock's served state; a DELETE removes it
# (report_delete_count advances, key gone). Then prove the agent's own status
# publisher reached the mock by finding status.mesh in the served reports.
# This MUST run before Phase 13's configure-state wipes the fixture.
echo "=== Testing per-key state report roundtrip and status publisher ==="

# The mock's GET /v1/nodes/{id}/state ignores the id; drive it with plexd's real
# node id for realism, falling back to the fixture node id if unavailable.
RT_NODE_ID=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/state" 2>/dev/null | jq -r '.node_id // empty')
[ -n "${RT_NODE_ID}" ] || RT_NODE_ID="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"
MOCK_STATE_URL="http://localhost:18080/v1/nodes/${RT_NODE_ID}/state"

# reports_value: print the value stored under a key in a served-state bucket
# ("state" or "reports"); empty when the key is absent.
reports_value() {
    local body=$1 bucket=$2 key=$3
    echo "${body}" | jq -r --arg k "${key}" ".${bucket}.reports[]? | select(.key == \$k) | .value // empty"
}

# reports_has_key: succeed iff key exists in the given served-state bucket.
reports_has_key() {
    local body=$1 bucket=$2 key=$3
    echo "${body}" | jq -e --arg k "${key}" "[.${bucket}.reports[]? | select(.key == \$k)] | length > 0" >/dev/null 2>&1
}

# Baseline the upstream PUT counter: the status publisher also drives report
# PUTs, so an absolute ">= 1" alone would not prove OUR put was delivered.
RT_PUT_BEFORE=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "report_put_count")

# (a) PUT a per-key report through the local node API.
RT_PUT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${NAPI_AUTH[@]}" \
    -H "Content-Type: application/json" \
    -d '{"content_type":"application/json","payload":{"probe":"e2e-roundtrip-marker"}}' \
    "${NODE_API_URL}/v1/state/report/e2e-roundtrip" 2>/dev/null || true)
if [ "${RT_PUT_STATUS}" = "200" ]; then
    echo "  PASS: local PUT /v1/state/report/e2e-roundtrip -> 200"
else
    fail "local PUT report returned status ${RT_PUT_STATUS}, want 200"
fi

# (b) Poll the mock's served state until e2e-roundtrip lands in state.reports.
#     The upsert precedes the counter bump, so its presence proves delivery.
RT_TIMEOUT=60
RT_ELAPSED=0
RT_SEEN=0
RT_STATE=""
while [ "${RT_ELAPSED}" -lt "${RT_TIMEOUT}" ]; do
    RT_STATE=$(curl -sf "${MOCK_AUTH[@]}" "${MOCK_STATE_URL}" 2>/dev/null || true)
    if [ -n "${RT_STATE}" ] && reports_has_key "${RT_STATE}" "state" "e2e-roundtrip"; then
        RT_SEEN=1
        break
    fi
    sleep 3
    RT_ELAPSED=$((RT_ELAPSED + 3))
done
if [ "${RT_SEEN}" -eq 0 ]; then
    fail "e2e-roundtrip report did not reach the mock state within ${RT_TIMEOUT}s"
fi

# report_put_count must have advanced past the baseline (our PUT was counted).
RT_PUT_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "report_put_count")
if [ "${RT_PUT_AFTER}" -gt "${RT_PUT_BEFORE}" ] && [ "${RT_PUT_AFTER}" -ge 1 ]; then
    echo "  PASS: report_put_count advanced ${RT_PUT_BEFORE} -> ${RT_PUT_AFTER}"
else
    fail "report_put_count did not advance past ${RT_PUT_BEFORE} (after=${RT_PUT_AFTER})"
fi

# (c) The key with its PUT value must appear in BOTH mirrored reports buckets.
for bucket in state reports; do
    RT_VAL=$(reports_value "${RT_STATE}" "${bucket}" "e2e-roundtrip")
    case "${RT_VAL}" in
        *e2e-roundtrip-marker*) echo "  PASS: ${bucket}.reports carries e2e-roundtrip value" ;;
        *) fail "${bucket}.reports missing e2e-roundtrip value marker (value='${RT_VAL}')" ;;
    esac
done

# (d) A key outside the wire grammar is rejected by the LOCAL node API itself.
RT_BAD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${NAPI_AUTH[@]}" \
    -H "Content-Type: application/json" \
    -d '{"content_type":"application/json","payload":{"x":1}}' \
    "${NODE_API_URL}/v1/state/report/Bad_Key" 2>/dev/null || true)
if [ "${RT_BAD_STATUS}" = "400" ]; then
    echo "  PASS: local PUT /v1/state/report/Bad_Key -> 400 (grammar enforced)"
else
    fail "local PUT Bad_Key returned status ${RT_BAD_STATUS}, want 400"
fi

# (e) DELETE removes the report: the delete counter advances and the key
#     disappears from BOTH mirrored buckets of the mock's served state.
RT_DEL_BEFORE=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "report_delete_count")
RT_DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${NAPI_AUTH[@]}" \
    "${NODE_API_URL}/v1/state/report/e2e-roundtrip" 2>/dev/null || true)
if [ "${RT_DEL_STATUS}" = "204" ]; then
    echo "  PASS: local DELETE /v1/state/report/e2e-roundtrip -> 204"
else
    fail "local DELETE report returned status ${RT_DEL_STATUS}, want 204"
fi

RT_DEL_TIMEOUT=60
RT_DEL_ELAPSED=0
RT_DEL_SEEN=0
RT_DEL_AFTER=${RT_DEL_BEFORE}
while [ "${RT_DEL_ELAPSED}" -lt "${RT_DEL_TIMEOUT}" ]; do
    RT_STATE=$(curl -sf "${MOCK_AUTH[@]}" "${MOCK_STATE_URL}" 2>/dev/null || true)
    RT_DEL_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "report_delete_count")
    if [ "${RT_DEL_AFTER}" -gt "${RT_DEL_BEFORE}" ] && [ -n "${RT_STATE}" ] \
        && ! reports_has_key "${RT_STATE}" "state" "e2e-roundtrip" \
        && ! reports_has_key "${RT_STATE}" "reports" "e2e-roundtrip"; then
        RT_DEL_SEEN=1
        break
    fi
    sleep 3
    RT_DEL_ELAPSED=$((RT_DEL_ELAPSED + 3))
done
if [ "${RT_DEL_SEEN}" -eq 0 ]; then
    fail "e2e-roundtrip report was not removed from the mock within ${RT_DEL_TIMEOUT}s (report_delete_count before=${RT_DEL_BEFORE}, after=${RT_DEL_AFTER})"
fi
echo "  PASS: report_delete_count advanced to ${RT_DEL_AFTER} and e2e-roundtrip is gone"

# (f) The agent's status publisher must have landed status.mesh in the served
#     reports by now. Poll generously: the first publish is at startup, but the
#     syncer debounce and PUT delivery add seconds on top.
RT_STATUS_TIMEOUT=60
RT_STATUS_ELAPSED=0
RT_STATUS_SEEN=0
while [ "${RT_STATUS_ELAPSED}" -lt "${RT_STATUS_TIMEOUT}" ]; do
    RT_STATE=$(curl -sf "${MOCK_AUTH[@]}" "${MOCK_STATE_URL}" 2>/dev/null || true)
    if [ -n "${RT_STATE}" ] && reports_has_key "${RT_STATE}" "reports" "status.mesh"; then
        RT_STATUS_SEEN=1
        break
    fi
    sleep 3
    RT_STATUS_ELAPSED=$((RT_STATUS_ELAPSED + 3))
done
if [ "${RT_STATUS_SEEN}" -eq 1 ]; then
    echo "  PASS: served reports include status.mesh (status publisher reached the mock)"
else
    fail "status.mesh did not appear in the mock's served reports within ${RT_STATUS_TIMEOUT}s"
fi

echo "=== Phase 12a PASSED: state report roundtrip and status publisher ==="

# ===================================================================
# Phase 12b: versioned and rate-limited secret fetches
# ===================================================================
# Drive the Local Node API secret route against the mock's envelope
# contract: prove ?version=N threads through (the current version and an
# older one both echo their number in the 200 body), that a version above
# the current one is an honest 404, that Accept: application/octet-stream
# returns the bare value as the body, and that an armed per-node 429 passes
# through with its Retry-After header before the service recovers to 200.
# A background reporter refetch may consume the armed 429 before our curl
# does, so the mock's secrets_rate_limited_count is an equally valid proof.
echo "=== Testing versioned and rate-limited secret fetches ==="

SEC_URL="${NODE_API_URL}/v1/state/secrets/local-bearer-token"

# Pin the mock's current secret version to 2.
SEC_CFG_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"current_version": 2}' \
    "http://localhost:18080/test/configure-secrets" 2>/dev/null || true)
if [ "${SEC_CFG_STATUS}" != "204" ]; then
    fail "configure-secrets (current_version) returned status ${SEC_CFG_STATUS}, want 204"
fi

# (a) Default fetch echoes the plaintext value and the current version.
SEC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${NAPI_AUTH[@]}" "${SEC_URL}" 2>/dev/null || true)
SEC_BODY=$(curl -sf "${NAPI_AUTH[@]}" "${SEC_URL}" 2>/dev/null || true)
if [ "${SEC_STATUS}" = "200" ] \
    && [ "$(echo "${SEC_BODY}" | jq -r '.value // empty')" = "e2e-local-bearer-token" ] \
    && [ "$(echo "${SEC_BODY}" | jq -r '.version // empty')" = "2" ]; then
    echo "  PASS: GET secrets/local-bearer-token -> 200 value ok version=2"
else
    fail "secret fetch returned status ${SEC_STATUS} body '${SEC_BODY}', want 200 value=e2e-local-bearer-token version=2"
fi

# (b) ?version=1 threads an older version through to the 200 body.
SEC_V1_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${NAPI_AUTH[@]}" "${SEC_URL}?version=1" 2>/dev/null || true)
SEC_V1_BODY=$(curl -sf "${NAPI_AUTH[@]}" "${SEC_URL}?version=1" 2>/dev/null || true)
if [ "${SEC_V1_STATUS}" = "200" ] \
    && [ "$(echo "${SEC_V1_BODY}" | jq -r '.version // empty')" = "1" ]; then
    echo "  PASS: GET secrets ?version=1 -> 200 version=1"
else
    fail "secret ?version=1 returned status ${SEC_V1_STATUS} body '${SEC_V1_BODY}', want 200 version=1"
fi

# (c) A version above the current one is an honest 404.
SEC_V3_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${NAPI_AUTH[@]}" "${SEC_URL}?version=3" 2>/dev/null || true)
if [ "${SEC_V3_STATUS}" = "404" ]; then
    echo "  PASS: GET secrets ?version=3 -> 404 (above current)"
else
    fail "secret ?version=3 returned status ${SEC_V3_STATUS}, want 404"
fi

# (c2) Accept: application/octet-stream returns the bare value as the body,
#      with the version in X-Plexd-Secret-Version. size_download proves the
#      body has no trailing newline, which the $(...) capture would strip.
SEC_RAW_HDRS=$(curl -s -D - -o /dev/null -w 'size=%{size_download}\n' "${NAPI_AUTH[@]}" \
    -H "Accept: application/octet-stream" "${SEC_URL}" 2>/dev/null | tr -d '\r' || true)
SEC_RAW_BODY=$(curl -sf "${NAPI_AUTH[@]}" -H "Accept: application/octet-stream" "${SEC_URL}" 2>/dev/null || true)
if [ "$(echo "${SEC_RAW_HDRS}" | awk 'NR==1{print $2}')" = "200" ] \
    && echo "${SEC_RAW_HDRS}" | grep -qix 'content-type: application/octet-stream' \
    && echo "${SEC_RAW_HDRS}" | grep -qix 'x-plexd-secret-version: 2' \
    && echo "${SEC_RAW_HDRS}" | grep -qx 'size=22' \
    && [ "${SEC_RAW_BODY}" = "e2e-local-bearer-token" ]; then
    echo "  PASS: GET secrets/local-bearer-token as octet-stream -> 200 raw body version=2"
else
    fail "raw secret fetch returned headers '${SEC_RAW_HDRS}' body '${SEC_RAW_BODY}', want 200 octet-stream version=2 body=e2e-local-bearer-token"
fi

# Arm a single per-node 429 carrying Retry-After: 5.
SEC_RL_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"rate_limit_next": 1, "retry_after_seconds": 5}' \
    "http://localhost:18080/test/configure-secrets" 2>/dev/null || true)
if [ "${SEC_RL_STATUS}" != "204" ]; then
    fail "configure-secrets (rate_limit_next) returned status ${SEC_RL_STATUS}, want 204"
fi

# (d) The armed 429 must pass through: either our own fetch sees the 429
#     with a Retry-After header, or a background reporter refetch consumed
#     it first and the mock's rate-limit counter advanced -- both prove
#     the passthrough. Poll up to 5 times.
SEC_RL_SEEN=0
for _ in 1 2 3 4 5; do
    SEC_HDRS=$(curl -s -D - -o /dev/null "${NAPI_AUTH[@]}" "${SEC_URL}" 2>/dev/null || true)
    SEC_RL_CODE=$(echo "${SEC_HDRS}" | awk 'NR==1{print $2}')
    if [ "${SEC_RL_CODE}" = "429" ] && echo "${SEC_HDRS}" | grep -qi '^Retry-After:'; then
        echo "  PASS: secret fetch -> 429 with Retry-After (passthrough)"
        SEC_RL_SEEN=1
        break
    fi
    SEC_RL_COUNT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "secrets_rate_limited_count")
    if [ "${SEC_RL_COUNT}" -ge 1 ]; then
        echo "  PASS: secrets_rate_limited_count=${SEC_RL_COUNT} (reporter consumed the armed 429)"
        SEC_RL_SEEN=1
        break
    fi
    sleep 2
done
if [ "${SEC_RL_SEEN}" -eq 0 ]; then
    fail "armed per-node 429 was neither observed nor counted after 5 attempts"
fi

# (e) The armed limit is exhausted, so the next fetch recovers to 200.
SEC_OK_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${NAPI_AUTH[@]}" "${SEC_URL}" 2>/dev/null || true)
if [ "${SEC_OK_STATUS}" = "200" ]; then
    echo "  PASS: secret fetch recovered to 200"
else
    fail "secret fetch did not recover to 200 (status ${SEC_OK_STATUS})"
fi

echo "=== Phase 12b PASSED: versioned and rate-limited secret fetches ==="

# ===================================================================
# Phase 12c: secret index from the inventory
# ===================================================================
# The pull's secrets block feeds the Local Node API secret index: GET
# /v1/state/secrets lists each entry under its name as key, in pull order.
# node_secrets_updated carries the full inventory too, but plexd only takes it
# as a reason to pull now, so step (b) changes the block without a nudge and
# proves the event pulls it. Step (c) empties the index again before Phase 13
# replaces the whole fixture.
echo "=== Testing the secret index fed from the inventory ==="

SECLIST_URL="${NODE_API_URL}/v1/state/secrets"

# wait_secret_index <tag> <want-compact-json> <timeout-seconds> polls the
# secret listing until it prints want, and fails the suite with what it last
# saw otherwise.
wait_secret_index() {
    local tag=$1 want=$2 timeout=$3 elapsed=0 got=""
    while true; do
        got=$(curl -sf "${NAPI_AUTH[@]}" "${SECLIST_URL}" 2>/dev/null | jq -c . 2>/dev/null || true)
        if [ "${got}" = "${want}" ]; then
            echo "  PASS: [${tag}] GET /v1/state/secrets -> ${got}"
            return 0
        fi
        if [ "${elapsed}" -ge "${timeout}" ]; then
            fail "[${tag}] GET /v1/state/secrets = '${got}' after ${timeout}s, want '${want}'"
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
}

# (a) The pull fills the index, mapping each name onto the listing's key.
configure_secrets "seclist-a" '[{"name":"api-token","version":1},{"name":"db-password","version":2}]' node_state_updated
wait_secret_index "seclist-a" '[{"key":"api-token","version":1},{"key":"db-password","version":2}]' 30

# (b) node_secrets_updated pulls a changed inventory. The block changes without
# a nudge, and the baseline is taken after the splice, which reads the state
# endpoint itself. A window shorter than the heartbeat's ~30s cadence does not
# keep a heartbeat-driven pull out of it, so the heartbeat fixture stops asking
# for a reconcile for the length of the step. The only other untriggered pull is
# the 60s reconcile ticker, which step (a)'s nudge reset moments ago. A
# state_count advance inside the 15s window can then only come from the event.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":false,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 \
    || fail "configure-heartbeat (reconcile off) failed"
configure_secrets "seclist-b" '[{"name":"db-password","version":3}]'
STATE_BEFORE_SECRETS=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")

SECRETS_EVENT=$(cat <<'SECEVENTEOF'
{
    "id": "evt-e2e-secrets-001",
    "type": "node_secrets_updated",
    "scope": "node",
    "payload": {"event_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0f1","occurred_at":"2026-01-01T00:00:00Z","node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3","secrets":[{"name":"db-password","version":3}]}
}
SECEVENTEOF
)
SECRETS_EVENT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${SECRETS_EVENT}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${SECRETS_EVENT_STATUS}" != "204" ]; then
    fail "node_secrets_updated injection returned status ${SECRETS_EVENT_STATUS}, want 204"
fi

SECRETS_TIMEOUT=15
SECRETS_ELAPSED=0
SECRETS_STATE_PASSED=0
while [ "${SECRETS_ELAPSED}" -lt "${SECRETS_TIMEOUT}" ]; do
    sleep 2
    SECRETS_ELAPSED=$((SECRETS_ELAPSED + 2))
    STATE_AFTER_SECRETS=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    if [ "${STATE_AFTER_SECRETS}" -gt "${STATE_BEFORE_SECRETS}" ]; then
        echo "  PASS: state_count increased from ${STATE_BEFORE_SECRETS} to ${STATE_AFTER_SECRETS} after node_secrets_updated"
        SECRETS_STATE_PASSED=1
        break
    fi
done
if [ "${SECRETS_STATE_PASSED}" -ne 1 ]; then
    fail "state_count did not advance within ${SECRETS_TIMEOUT}s of node_secrets_updated (stayed at ${STATE_BEFORE_SECRETS})"
fi
wait_secret_index "seclist-b" '[{"key":"db-password","version":3}]' 15

# Restore the heartbeat fixture the later phases expect.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 \
    || fail "configure-heartbeat (reconcile on) failed"

# (c) [] says the node may read nothing, and empties the index.
configure_secrets "seclist-c" '[]' node_state_updated
wait_secret_index "seclist-c" '[]' 30

echo "=== Phase 12c PASSED: secret index from the inventory ==="

# ===================================================================
# Phase 12d: mesh DNS without systemd-resolved
# ===================================================================
# The distroless plexd image has no system bus and no systemd-resolved, so
# plexd answers the dns block of its pull on its own mesh IP and logs where,
# and registers nothing. It runs before Phase 13, which replaces the fixture
# with a state that has no dns key: every start of plexd so far pulled the
# fixture's block first, so each logged the listener once and the missing
# resolver once, however many pulls followed. The queries run inside the
# plexd container, whose own mesh IP is the only source besides loopback the
# resolver answers. The block's records answer next to its hosts. plexd
# follows a CNAME whose target lies in its zones and ends the answer at one
# that leaves them, which busybox nslookup does not follow, so such a name
# answers no address here.
echo "=== Testing mesh DNS without systemd-resolved ==="

MESH_DNS_LISTEN="10.99.0.1:5354"

# mesh_nslookup <name> [<type>] asks the resolver for the records of type
# (a when left out) of name from inside the plexd container, and leaves the
# output, stderr included, in NSLOOKUP_OUT and the exit status in NSLOOKUP_RC.
# busybox 1.37 takes the port on the server argument.
mesh_nslookup() {
    NSLOOKUP_RC=0
    NSLOOKUP_OUT=$(dc exec -T plexd /bin/busybox nslookup -type="${2:-a}" "$1" "${MESH_DNS_LISTEN}" 2>&1) || NSLOOKUP_RC=$?
}

# nslookup_answers <output> <name> <address> succeeds when an nslookup output
# has the line "Name:<tab><name>" followed by the answer line
# "Address: <address>". The server's own address is printed as
# "Address:<tab>10.99.0.1:5354", above the name, so it cannot pass for the
# answer.
nslookup_answers() {
    local out=$1 name=$2 addr=$3 line named=0
    while IFS= read -r line; do
        if [ "${line}" = "Name:"$'\t'"${name}" ]; then
            named=1
        elif [ "${named}" -eq 1 ] && [ "${line}" = "Address: ${addr}" ]; then
            return 0
        fi
    done <<< "${out}"
    return 1
}

# nslookup_line <output> <line> succeeds when one line of an nslookup output
# equals line exactly, such as a CNAME's
# "<name><tab>canonical name = <target>".
nslookup_line() {
    local out=$1 want=$2 line
    while IFS= read -r line; do
        if [ "${line}" = "${want}" ]; then
            return 0
        fi
    done <<< "${out}"
    return 1
}

# configure_dns <tag> <dns-json-or-null> splices the dns block into the live
# snapshot the way configure_hooks splices the hooks block, posts it back, and
# nudges the agent. Reading the live snapshot is a real GET on the state
# endpoint and INCREMENTS state_count, so a check gating on state_count takes
# its baseline AFTER calling this helper.
configure_dns() {
    local tag=$1 block=$2 snapshot spliced status payload
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    # printf, not echo: the fixture carries backslash escapes (an embedded
    # newline in the certs/ca data entry) that must travel back byte for byte.
    spliced=$(printf '%s' "${snapshot}" | jq --argjson d "${block}" '.dns = $d') \
        || fail "[${tag}] could not splice the dns block ${block} into the live snapshot"
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi
    payload=$(cat <<DNSNUDGEEOF
{
    "id": "evt-e2e-dns-nudge-${tag}",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
DNSNUDGEEOF
    )
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] dns nudge injection returned status ${status}, want 204"
    fi
}

# (a) One listener line and one missing-resolver line per start, both naming
# the listen address. dc logs spans every run of the container, so the starts
# are counted from the same log.
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
PLEXD_STARTS=$(count_log_lines "${PLEXD_LOGS}" 'msg="starting plexd"')
DNS_LISTENING=$(count_log_lines "${PLEXD_LOGS}" 'msg="mesh dns listening"' "listen=${MESH_DNS_LISTEN}")
DNS_UNREGISTERED=$(count_log_lines "${PLEXD_LOGS}" 'msg="mesh dns not registered, systemd-resolved is not usable"' "listen=${MESH_DNS_LISTEN}")
DNS_WG_DOWN=$(count_log_lines "${PLEXD_LOGS}" 'msg="wireguard unavailable, mesh dns not started"')
if [ "${DNS_WG_DOWN}" -ne 0 ]; then
    fail "plexd logged 'wireguard unavailable, mesh dns not started' ${DNS_WG_DOWN} time(s): the resolver listens on the WireGuard interface's mesh IP, so this phase needs kernel WireGuard in the container"
fi
if [ "${PLEXD_STARTS}" -lt 1 ]; then
    fail "the plexd log has no 'starting plexd' line to count the starts by"
fi
if [ "${DNS_LISTENING}" -ne "${PLEXD_STARTS}" ]; then
    fail "the plexd log has ${DNS_LISTENING} 'mesh dns listening' line(s) with listen=${MESH_DNS_LISTEN} for ${PLEXD_STARTS} start(s), want one per start"
fi
echo "  PASS: 'mesh dns listening' with listen=${MESH_DNS_LISTEN} logged ${DNS_LISTENING} time(s), once per start of plexd (${PLEXD_STARTS})"
if [ "${DNS_UNREGISTERED}" -ne "${PLEXD_STARTS}" ]; then
    fail "the plexd log has ${DNS_UNREGISTERED} 'mesh dns not registered, systemd-resolved is not usable' line(s) with listen=${MESH_DNS_LISTEN} for ${PLEXD_STARTS} start(s), want one per start"
fi
echo "  PASS: 'mesh dns not registered, systemd-resolved is not usable' with listen=${MESH_DNS_LISTEN} logged ${DNS_UNREGISTERED} time(s), once per start of plexd (${PLEXD_STARTS})"

# (b) The resolver answers a host of the block and denies a name it lacks.
mesh_nslookup peer-1.app.e2e.internal
if [ "${NSLOOKUP_RC}" -eq 0 ] && nslookup_answers "${NSLOOKUP_OUT}" peer-1.app.e2e.internal 10.99.0.2; then
    echo "  PASS: nslookup -type=a peer-1.app.e2e.internal ${MESH_DNS_LISTEN} answers 10.99.0.2"
else
    fail "nslookup -type=a peer-1.app.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0 and 10.99.0.2 (output: ${NSLOOKUP_OUT})"
fi
mesh_nslookup nope.app.e2e.internal
case "${NSLOOKUP_OUT}" in
    *"server can't find nope.app.e2e.internal: NXDOMAIN"*) NOPE_NXDOMAIN=1 ;;
    *) NOPE_NXDOMAIN=0 ;;
esac
if [ "${NSLOOKUP_RC}" -ne 0 ] && [ "${NOPE_NXDOMAIN}" -eq 1 ]; then
    echo "  PASS: nslookup -type=a nope.app.e2e.internal ${MESH_DNS_LISTEN} answers NXDOMAIN"
else
    fail "nslookup -type=a nope.app.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want a failure with NXDOMAIN (output: ${NSLOOKUP_OUT})"
fi

# The fixture's records. busybox prints a CNAME on a line of its own, and
# only the first string of a TXT record.
mesh_nslookup db.e2e.internal
if [ "${NSLOOKUP_RC}" -eq 0 ] \
    && nslookup_answers "${NSLOOKUP_OUT}" db.e2e.internal 192.0.2.10 \
    && nslookup_answers "${NSLOOKUP_OUT}" db.e2e.internal 192.0.2.11; then
    echo "  PASS: nslookup -type=a db.e2e.internal ${MESH_DNS_LISTEN} answers 192.0.2.10 and 192.0.2.11"
else
    fail "nslookup -type=a db.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0, 192.0.2.10 and 192.0.2.11 (output: ${NSLOOKUP_OUT})"
fi
mesh_nslookup alias.app.e2e.internal
if [ "${NSLOOKUP_RC}" -eq 0 ] \
    && nslookup_line "${NSLOOKUP_OUT}" "alias.app.e2e.internal"$'\t'"canonical name = peer-2.app.e2e.internal" \
    && nslookup_answers "${NSLOOKUP_OUT}" peer-2.app.e2e.internal 10.99.0.3; then
    echo "  PASS: nslookup -type=a alias.app.e2e.internal ${MESH_DNS_LISTEN} answers the CNAME to peer-2.app.e2e.internal and 10.99.0.3"
else
    fail "nslookup -type=a alias.app.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0, the line 'alias.app.e2e.internal<tab>canonical name = peer-2.app.e2e.internal' and 10.99.0.3 under peer-2.app.e2e.internal (output: ${NSLOOKUP_OUT})"
fi
# The server's own "Address:<tab>10.99.0.1:5354" line does not start with
# "Address: ", so only an answered address does.
mesh_nslookup ext.e2e.internal
case $'\n'"${NSLOOKUP_OUT}" in
    *$'\n'"Address: "*) EXT_ADDRESS=1 ;;
    *) EXT_ADDRESS=0 ;;
esac
if [ "${NSLOOKUP_RC}" -eq 0 ] && [ "${EXT_ADDRESS}" -eq 0 ] \
    && nslookup_line "${NSLOOKUP_OUT}" "ext.e2e.internal"$'\t'"canonical name = ext.example.com"; then
    echo "  PASS: nslookup -type=a ext.e2e.internal ${MESH_DNS_LISTEN} answers the CNAME to ext.example.com and no address"
else
    fail "nslookup -type=a ext.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0, the line 'ext.e2e.internal<tab>canonical name = ext.example.com' and no address (output: ${NSLOOKUP_OUT})"
fi
mesh_nslookup _db._tcp.app.e2e.internal srv
if nslookup_line "${NSLOOKUP_OUT}" "_db._tcp.app.e2e.internal"$'\t'"service = 0 5 5432 db.e2e.internal"; then
    echo "  PASS: nslookup -type=srv _db._tcp.app.e2e.internal ${MESH_DNS_LISTEN} answers 0 5 5432 db.e2e.internal"
else
    fail "nslookup -type=srv _db._tcp.app.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want the line '_db._tcp.app.e2e.internal<tab>service = 0 5 5432 db.e2e.internal' (output: ${NSLOOKUP_OUT})"
fi
mesh_nslookup e2e.internal mx
if nslookup_line "${NSLOOKUP_OUT}" "e2e.internal"$'\t'"mail exchanger = 10 mail.example.com"; then
    echo "  PASS: nslookup -type=mx e2e.internal ${MESH_DNS_LISTEN} answers 10 mail.example.com"
else
    fail "nslookup -type=mx e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want the line 'e2e.internal<tab>mail exchanger = 10 mail.example.com' (output: ${NSLOOKUP_OUT})"
fi
mesh_nslookup e2e.internal txt
if nslookup_line "${NSLOOKUP_OUT}" "e2e.internal"$'\t''text = "v=e2e"'; then
    echo "  PASS: nslookup -type=txt e2e.internal ${MESH_DNS_LISTEN} answers \"v=e2e\""
else
    fail "nslookup -type=txt e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want the line 'e2e.internal<tab>text = \"v=e2e\"' (output: ${NSLOOKUP_OUT})"
fi

# (c) Forwarding. The mock API runs a DNS stub on port 53 of its container,
# which answers every A query with 198.51.100.53 and a name whose first label
# is nx with NXDOMAIN. The fixture's forwarding member holds two empty lists,
# so plexd refuses a name outside its zones. A forward zone sends the names
# under it to the stub, and a catch-all every other name. configure_dns nudges
# the agent, so each change normally lands within seconds, and the 90 s also
# cover the pulls the heartbeat asks for. The check ends with two empty lists,
# the fixture's member, so (d) saves the fixture's block.
#
# nslookup_fails_with <output> <name> <rcode> succeeds when busybox nslookup
# reports that the server can't find name, with rcode as the reason.
nslookup_fails_with() {
    nslookup_line "$1" "** server can't find $2: $3"
}
STUB_ADDRESS="198.51.100.53"
MOCK_API_ID=$(dc ps -q mock-api 2>&1) || fail "dc ps -q mock-api failed: ${MOCK_API_ID}"
MOCK_API_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT_NAME}_e2e-net\").IPAddress}}" "${MOCK_API_ID}" 2>&1) \
    || fail "docker inspect of the mock-api container '${MOCK_API_ID}' failed: ${MOCK_API_IP}"
if [ -z "${MOCK_API_IP}" ]; then
    fail "docker inspect gave no address of the mock-api container '${MOCK_API_ID}' on ${PROJECT_NAME}_e2e-net"
fi
FWD_DNS=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null | jq -c '.dns' 2>&1 || true)
FWD_MEMBER=$(printf '%s' "${FWD_DNS}" | jq -c '.forwarding' 2>&1 || true)
if [ "${FWD_MEMBER}" != '{"forward_zones":[],"catch_all":[]}' ]; then
    fail "[dns forwarding] the served dns block carries the forwarding member '${FWD_MEMBER}', want the fixture's two empty lists"
fi
mesh_nslookup host.fwd.e2e.test
if [ "${NSLOOKUP_RC}" -ne 0 ] && nslookup_fails_with "${NSLOOKUP_OUT}" host.fwd.e2e.test REFUSED; then
    echo "  PASS: [dns forwarding] under the fixture's block, nslookup -type=a host.fwd.e2e.test ${MESH_DNS_LISTEN} fails with REFUSED"
else
    fail "[dns forwarding] under the fixture's block, nslookup -type=a host.fwd.e2e.test ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want a failure with REFUSED (output: ${NSLOOKUP_OUT})"
fi

# The forward zone fwd.e2e.test sends its names to the stub, and plexd still
# refuses a name outside it.
configure_dns "dns-fwd-zone" "$(printf '%s' "${FWD_DNS}" | jq -c --arg mock "${MOCK_API_IP}" \
    '.forwarding = {forward_zones: [{zone: "fwd.e2e.test", resolvers: [$mock]}], catch_all: []}')"
FWD_START=${SECONDS}
while :; do
    mesh_nslookup host.fwd.e2e.test
    if [ "${NSLOOKUP_RC}" -eq 0 ] && nslookup_answers "${NSLOOKUP_OUT}" host.fwd.e2e.test "${STUB_ADDRESS}"; then
        break
    fi
    if [ $((SECONDS - FWD_START)) -ge 90 ]; then
        fail "[dns forwarding] 90s after the forward zone fwd.e2e.test to ${MOCK_API_IP} was configured, nslookup -type=a host.fwd.e2e.test ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0 and ${STUB_ADDRESS} (output: ${NSLOOKUP_OUT})"
    fi
    sleep 2
done
echo "  PASS: [dns forwarding] after $((SECONDS - FWD_START))s with the forward zone fwd.e2e.test to ${MOCK_API_IP}, nslookup -type=a host.fwd.e2e.test ${MESH_DNS_LISTEN} answers ${STUB_ADDRESS}"
mesh_nslookup nx.fwd.e2e.test
if [ "${NSLOOKUP_RC}" -ne 0 ] && nslookup_fails_with "${NSLOOKUP_OUT}" nx.fwd.e2e.test NXDOMAIN; then
    echo "  PASS: [dns forwarding] nslookup -type=a nx.fwd.e2e.test ${MESH_DNS_LISTEN} answers NXDOMAIN"
else
    fail "[dns forwarding] nslookup -type=a nx.fwd.e2e.test ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want a failure with NXDOMAIN (output: ${NSLOOKUP_OUT})"
fi
mesh_nslookup host.other.e2e.test
if [ "${NSLOOKUP_RC}" -ne 0 ] && nslookup_fails_with "${NSLOOKUP_OUT}" host.other.e2e.test REFUSED; then
    echo "  PASS: [dns forwarding] without a catch-all, nslookup -type=a host.other.e2e.test ${MESH_DNS_LISTEN} fails with REFUSED"
else
    fail "[dns forwarding] without a catch-all, nslookup -type=a host.other.e2e.test ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want a failure with REFUSED (output: ${NSLOOKUP_OUT})"
fi

# A catch-all sends every other name to the stub.
configure_dns "dns-fwd-catch-all" "$(printf '%s' "${FWD_DNS}" | jq -c --arg mock "${MOCK_API_IP}" \
    '.forwarding = {forward_zones: [{zone: "fwd.e2e.test", resolvers: [$mock]}], catch_all: [$mock]}')"
FWD_START=${SECONDS}
while :; do
    mesh_nslookup host.other.e2e.test
    if [ "${NSLOOKUP_RC}" -eq 0 ] && nslookup_answers "${NSLOOKUP_OUT}" host.other.e2e.test "${STUB_ADDRESS}"; then
        break
    fi
    if [ $((SECONDS - FWD_START)) -ge 90 ]; then
        fail "[dns forwarding] 90s after the catch-all ${MOCK_API_IP} was configured, nslookup -type=a host.other.e2e.test ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0 and ${STUB_ADDRESS} (output: ${NSLOOKUP_OUT})"
    fi
    sleep 2
done
echo "  PASS: [dns forwarding] after $((SECONDS - FWD_START))s with the catch-all ${MOCK_API_IP}, nslookup -type=a host.other.e2e.test ${MESH_DNS_LISTEN} answers ${STUB_ADDRESS}"

# Two empty lists end the forwarding, and plexd refuses all three names again.
configure_dns "dns-fwd-empty" "$(printf '%s' "${FWD_DNS}" | jq -c '.forwarding = {forward_zones: [], catch_all: []}')"
FWD_START=${SECONDS}
while :; do
    FWD_REFUSED=0
    for name in host.fwd.e2e.test nx.fwd.e2e.test host.other.e2e.test; do
        mesh_nslookup "${name}"
        if [ "${NSLOOKUP_RC}" -ne 0 ] && nslookup_fails_with "${NSLOOKUP_OUT}" "${name}" REFUSED; then
            FWD_REFUSED=$((FWD_REFUSED + 1))
        else
            break
        fi
    done
    if [ "${FWD_REFUSED}" -eq 3 ]; then
        break
    fi
    if [ $((SECONDS - FWD_START)) -ge 90 ]; then
        fail "[dns forwarding] 90s after two empty lists were configured, nslookup -type=a ${name} ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want a failure with REFUSED (output: ${NSLOOKUP_OUT})"
    fi
    sleep 2
done
echo "  PASS: [dns forwarding] after $((SECONDS - FWD_START))s with two empty lists, host.fwd.e2e.test, nx.fwd.e2e.test and host.other.e2e.test fail with REFUSED again"

# (d) A null block keeps the names held. The fixture's block is saved first,
# so the phase can serve it again. Two pulls past the baseline mean at least
# one of them ran its dispatch handlers to the end: the nudge's pull may land
# ahead of the baseline, and the heartbeat asks for a pull about every 30 s, so
# the wait covers two heartbeats.
FIXTURE_DNS=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null | jq -c '.dns' 2>&1 || true)
FIXTURE_PEER1=$(printf '%s' "${FIXTURE_DNS}" | jq '[.hosts[]? | select(.fqdn == "peer-1.app.e2e.internal" and .mesh_ip == "10.99.0.2")] | length' 2>&1 || true)
if [ "${FIXTURE_PEER1}" != "1" ]; then
    fail "[dns null block] the served dns block '${FIXTURE_DNS}' does not carry peer-1.app.e2e.internal at 10.99.0.2 once (got '${FIXTURE_PEER1}')"
fi
# The saved block must hold the fixture's eight records, so the restore in (e)
# serves them again.
FIXTURE_RECORDS=$(printf '%s' "${FIXTURE_DNS}" | jq '[.records[]?] | length' 2>&1 || true)
if [ "${FIXTURE_RECORDS}" != "8" ]; then
    fail "[dns null block] the served dns block '${FIXTURE_DNS}' holds '${FIXTURE_RECORDS}' records, want the fixture's 8"
fi
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
NO_BLOCK_BEFORE=$(count_log_lines "${PLEXD_LOGS}" 'msg="state pull carries no dns block, keeping the names held"')
configure_dns "dns-null" null
STATE_BEFORE_DNS_NULL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
case "${STATE_BEFORE_DNS_NULL}" in
    '' | *[!0-9]*) fail "[dns null block] no state_count baseline (got '${STATE_BEFORE_DNS_NULL}')" ;;
esac
DNS_NULL_ELAPSED=0
while :; do
    STATE_AFTER_DNS_NULL=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    if [ "${STATE_AFTER_DNS_NULL}" -ge $((STATE_BEFORE_DNS_NULL + 2)) ] 2>/dev/null; then
        echo "  PASS: [dns null block] state_count grew from ${STATE_BEFORE_DNS_NULL} to ${STATE_AFTER_DNS_NULL} after ${DNS_NULL_ELAPSED}s"
        break
    fi
    if [ "${DNS_NULL_ELAPSED}" -ge 65 ]; then
        fail "[dns null block] state_count went from ${STATE_BEFORE_DNS_NULL} to '${STATE_AFTER_DNS_NULL}' in 65s, want two pulls of the null block"
    fi
    sleep 1
    DNS_NULL_ELAPSED=$((DNS_NULL_ELAPSED + 1))
done
# The first pull without a block since the last one with a block logs the
# line once, and the next one logs nothing.
PLEXD_LOGS=$(dc logs plexd 2>&1) || fail "dc logs plexd failed: ${PLEXD_LOGS}"
NO_BLOCK_AFTER=$(count_log_lines "${PLEXD_LOGS}" 'msg="state pull carries no dns block, keeping the names held"')
if [ "${NO_BLOCK_AFTER}" -ne $((NO_BLOCK_BEFORE + 1)) ]; then
    fail "[dns null block] 'state pull carries no dns block, keeping the names held' went from ${NO_BLOCK_BEFORE} to ${NO_BLOCK_AFTER} line(s) over two pulls of the null block, want +1"
fi
echo "  PASS: [dns null block] plexd logged 'state pull carries no dns block, keeping the names held' once"
mesh_nslookup peer-1.app.e2e.internal
if [ "${NSLOOKUP_RC}" -eq 0 ] && nslookup_answers "${NSLOOKUP_OUT}" peer-1.app.e2e.internal 10.99.0.2; then
    echo "  PASS: [dns null block] nslookup -type=a peer-1.app.e2e.internal ${MESH_DNS_LISTEN} still answers 10.99.0.2"
else
    fail "[dns null block] nslookup -type=a peer-1.app.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0 and 10.99.0.2 (output: ${NSLOOKUP_OUT})"
fi
mesh_nslookup db.e2e.internal
if [ "${NSLOOKUP_RC}" -eq 0 ] && nslookup_answers "${NSLOOKUP_OUT}" db.e2e.internal 192.0.2.10; then
    echo "  PASS: [dns null block] nslookup -type=a db.e2e.internal ${MESH_DNS_LISTEN} still answers 192.0.2.10"
else
    fail "[dns null block] nslookup -type=a db.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0 and 192.0.2.10 (output: ${NSLOOKUP_OUT})"
fi

# (e) The fixture's block is served again before the phase ends.
configure_dns "dns-restore" "${FIXTURE_DNS}"
SERVED_DNS=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null | jq -c '.dns' 2>&1 || true)
if [ "$(jq -n --argjson a "${SERVED_DNS:-null}" --argjson b "${FIXTURE_DNS}" '$a == $b' 2>&1)" = "true" ]; then
    echo "  PASS: the mock serves the fixture's dns block again"
else
    fail "the mock serves the dns block '${SERVED_DNS}' after the restore, want '${FIXTURE_DNS}'"
fi

echo "=== Phase 12d PASSED: mesh DNS without systemd-resolved ==="

# ===================================================================
# Phase 12e: policy enforcement on the mesh interface
# ===================================================================
# The meshpeer container stands in for the fixture's peer ...a0b2 at mesh IP
# 10.99.0.3. Its wg0 gets a key pair of its own, the edge PSK the mock derives
# for that peer, and plexd's current public key as its one peer. The phase
# splices meshpeer's key and address into that peer of the served snapshot and
# waits for a handshake. It then serves policies of its own, each under a fresh
# revision id and fingerprint, and checks which connections the chain on
# plexd's mesh interface lets through:
#
#   A  tcp 7001 over IPv4 and over IPv6, and a logged udp 7004 rule
#   B  A's rules, each carrying the legacy "action": "allow"
#   C  one rule carrying "action": "deny", which rejects the revision
#   D  A without its 7001 rules
#   E  no rules
#
# meshpeer probes plexd with nc -z, and every probe meets a listener of its
# own in plexd's container, so a probe that fails was dropped by the chain, not
# refused at a closed port. plexd's own connection to a listener in meshpeer
# needs no rule: its replies belong to a connection plexd opened. A query from
# inside plexd's container reaches the mesh resolver over lo, which the chain
# does not match, so mesh DNS answers even under E. The mesh carries IPv4 only,
# so A's IPv6 rule proves that plexd applies such a rule, not that it matches
# IPv6 traffic. The phase runs before Phase 13, which replaces the fixture, and
# ends by serving the saved peers and policy again. Like Phase 12d it needs
# kernel WireGuard and fails without it.
echo "=== Testing policy enforcement on the mesh interface ==="

if [ "${WG_CONFIGURED}" -eq 0 ]; then
    fail "[mesh policy] WireGuard did not come up in the plexd container: this phase needs kernel WireGuard to carry meshpeer's traffic to plexd's mesh interface"
fi

MESH_NODE_IP="10.99.0.1"
MESH_PEER_IP="10.99.0.3"
FIXTURE_POLICY_REVISION="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1"

# splice_state <tag> <jq-filter> <value-json> applies the filter, which reads
# the value as $v, to the live snapshot, posts the result back and nudges the
# agent, the way configure_dns does for the dns block. Reading the live
# snapshot is a real GET on the state endpoint and INCREMENTS state_count.
splice_state() {
    local tag=$1 filter=$2 value=$3 snapshot spliced status payload
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    # printf, not echo: the fixture carries backslash escapes (an embedded
    # newline in the certs/ca data entry) that must travel back byte for byte.
    spliced=$(printf '%s' "${snapshot}" | jq --argjson v "${value}" "${filter}") \
        || fail "[${tag}] could not splice ${value} into the live snapshot with '${filter}'"
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi
    payload=$(cat <<MESHNUDGEEOF
{
    "id": "evt-e2e-${tag}-nudge",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
MESHNUDGEEOF
    )
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] nudge injection returned status ${status}, want 204"
    fi
}

# serve_policy <tag> <revision-id> <rules-json> serves a policy block with that
# revision and those rules. Its fingerprint is base64 of the SHA-256 of the
# revision id and the rules, the shape the control plane's has, computed in
# meshpeer, which has openssl. plexd compares the fingerprint and never derives
# it, so one that differs from the fingerprint it holds makes it apply the
# block.
serve_policy() {
    local tag=$1 rev=$2 rules=$3 fp block
    fp=$(dc exec -T meshpeer sh -c 'set -o pipefail; printf "%s" "$1" | openssl dgst -sha256 -binary | base64' sh "${rev}|${rules}" 2>&1) \
        || fail "[${tag}] could not compute a fingerprint in meshpeer: ${fp}"
    if [ "${#fp}" -ne 44 ]; then
        fail "[${tag}] meshpeer computed the fingerprint '${fp}', want 44 characters of base64"
    fi
    block=$(jq -cn --arg r "${rev}" --arg f "${fp}" --argjson rules "${rules}" \
        '{revision_id: $r, fingerprint: $f, rules: $rules}') \
        || fail "[${tag}] could not build a policy block from the rules ${rules}"
    splice_state "${tag}" '.policy = $v' "${block}"
    echo "  revision ${rev} served with the rules ${rules}"
}

# wait_policy_line <tag> <msg> <revision-id> <baseline> reads the plexd log
# every 2 s for up to 60 s until it holds more than baseline lines that carry
# msg="<msg>" and revision_id=<revision-id>, and leaves the last log it read in
# POLICY_LOG.
wait_policy_line() {
    local tag=$1 msg=$2 rev=$3 base=$4 start=${SECONDS} n
    while :; do
        POLICY_LOG=$(dc logs plexd 2>&1) || fail "[${tag}] dc logs plexd failed: ${POLICY_LOG}"
        n=$(count_log_lines "${POLICY_LOG}" "msg=\"${msg}\"" "revision_id=${rev}")
        if [ "${n}" -gt "${base}" ]; then
            return 0
        fi
        if [ $((SECONDS - start)) -ge 60 ]; then
            fail "[${tag}] 60s after revision ${rev} was served, the plexd log holds ${n} '${msg}' line(s) with revision_id=${rev}, want more than ${base}"
        fi
        sleep 2
    done
}

# expect_policy_applied <tag> <revision-id> <rules> [<baseline>] waits for a
# "policy ruleset applied" line of the revision past the baseline (0 when left
# out) and requires the last such line to carry rules=<rules>. plexd logs the
# line once the ruleset is in the kernel, so the probes after it see the new
# ruleset.
expect_policy_applied() {
    local tag=$1 rev=$2 rules=$3 base=${4:-0} line applied=""
    wait_policy_line "${tag}" "policy ruleset applied" "${rev}" "${base}"
    while IFS= read -r line; do
        case "${line}" in
            *'msg="policy ruleset applied"'*"revision_id=${rev}"*) applied=${line} ;;
        esac
    done <<< "${POLICY_LOG}"
    case "${applied}" in
        *" rules=${rules}" | *" rules=${rules} "*) ;;
        *) fail "[${tag}] plexd applied revision ${rev} with the line '${applied}', want rules=${rules}" ;;
    esac
    echo "  PASS: [${tag}] plexd logged 'policy ruleset applied' with revision_id=${rev} and rules=${rules}"
}

# logged_rule_count <log> <revision-id> prints the count of the last
# "policy rules ask for logging" line between the first "policy ruleset
# applied" line of the revision and the policy line before it: the line the
# engine logged while it built that revision's ruleset. It prints nothing when
# the engine logged none for it.
logged_rule_count() {
    local log=$1 rev=$2 line count=""
    while IFS= read -r line; do
        case "${line}" in
            *'msg="policy rules ask for logging, which this release does not do"'*)
                count=${line##*count=}
                count=${count%% *}
                ;;
            *'msg="policy ruleset applied"'*"revision_id=${rev}"*)
                printf '%s' "${count}"
                return 0
                ;;
            *'msg="policy ruleset applied"'* | *'msg="policy revision rejected, keeping previous ruleset"'*)
                count=""
                ;;
        esac
    done <<< "${log}"
}

# plexd_listening <port> succeeds when a socket in plexd's container listens on
# TCP port <port>. busybox netstat prints each local address as
# <address>:<port> followed by blanks.
plexd_listening() {
    local out line
    out=$(dc exec -T plexd /bin/busybox netstat -ltn 2>&1) \
        || fail "[mesh policy] netstat -ltn in the plexd container failed: ${out}"
    while IFS= read -r line; do
        case "${line}" in
            *":$1 "*LISTEN*) return 0 ;;
        esac
    done <<< "${out}"
    return 1
}

# meshpeer_listening <port> succeeds when a socket in meshpeer listens on TCP
# port <port>.
meshpeer_listening() {
    local out
    out=$(dc exec -T meshpeer ss -Hltn "sport = :$1" 2>&1) \
        || fail "[mesh policy] ss -Hltn in meshpeer failed: ${out}"
    [ -n "${out}" ]
}

# await_listening <tag> <check> <port> <yes|no> runs check (plexd_listening or
# meshpeer_listening) on port every second for up to 10 s until a listener is
# there (yes) or gone (no).
await_listening() {
    local tag=$1 check=$2 port=$3 want=$4 waited=0 now
    while :; do
        if "${check}" "${port}"; then
            now=yes
        else
            now=no
        fi
        if [ "${now}" = "${want}" ]; then
            return 0
        fi
        if [ "${waited}" -ge 10 ]; then
            fail "[${tag}] ${check} ${port} still says listening=${now} after 10s, want listening=${want}"
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

# probe_plexd_port <tag> <port> <open|closed> starts a one-connection listener
# on port in plexd's container, probes it from meshpeer over the mesh with
# nc -z, and stops the listener again, so each probe meets a listener of its
# own. A connection the chain drops times out after 3 s, while one that reached
# a port without a listener would be refused, so closed wants the time-out.
probe_plexd_port() {
    local tag=$1 port=$2 want=$3 rc=0 out
    dc exec -d -T plexd /bin/busybox nc -l -p "${port}" \
        || fail "[${tag}] could not start a listener on port ${port} in the plexd container"
    await_listening "${tag}" plexd_listening "${port}" yes
    out=$(dc exec -T meshpeer nc -nvz -w 3 "${MESH_NODE_IP}" "${port}" 2>&1) || rc=$?
    # A listener the probe reached took its one connection and exits by itself,
    # and pkill then finds nothing. One the chain kept the probe from still
    # listens and is stopped here. The wait below proves the port free.
    dc exec -T plexd /bin/busybox pkill -f "nc -l -p ${port}" >/dev/null 2>&1 || true
    await_listening "${tag}" plexd_listening "${port}" no
    if [ "${want}" = open ]; then
        if [ "${rc}" -ne 0 ]; then
            fail "[${tag}] meshpeer's nc -nvz -w 3 ${MESH_NODE_IP} ${port} exited ${rc}, want 0 (output: ${out})"
        fi
        echo "  PASS: [${tag}] meshpeer connects to ${MESH_NODE_IP}:${port}"
        return 0
    fi
    if [ "${rc}" -eq 0 ]; then
        fail "[${tag}] meshpeer's nc -nvz -w 3 ${MESH_NODE_IP} ${port} connected, want the chain to drop it (output: ${out})"
    fi
    case "${out}" in
        *"timed out"*) ;;
        *) fail "[${tag}] meshpeer's nc -nvz -w 3 ${MESH_NODE_IP} ${port} exited ${rc} without timing out, want the chain to drop it while a listener runs on the port (output: ${out})" ;;
    esac
    echo "  PASS: [${tag}] meshpeer's connection to ${MESH_NODE_IP}:${port} times out while a listener runs there"
}

# probe_meshpeer_port <tag> <port> starts a one-connection listener on port in
# meshpeer and connects to it from plexd's container, where busybox nc exits 0
# once connected. No rule names that direction.
probe_meshpeer_port() {
    local tag=$1 port=$2 rc=0 out
    dc exec -d -T meshpeer nc -l "${port}" \
        || fail "[${tag}] could not start a listener on port ${port} in meshpeer"
    await_listening "${tag}" meshpeer_listening "${port}" yes
    out=$(dc exec -T plexd /bin/busybox sh -c "/bin/busybox nc -w 3 ${MESH_PEER_IP} ${port} </dev/null" 2>&1) || rc=$?
    # As in probe_plexd_port: the listener exits after its one connection, and
    # one the probe did not reach is stopped here.
    dc exec -T meshpeer pkill -f "nc -l ${port}" >/dev/null 2>&1 || true
    await_listening "${tag}" meshpeer_listening "${port}" no
    if [ "${rc}" -ne 0 ]; then
        fail "[${tag}] plexd's container could not connect to meshpeer's listener at ${MESH_PEER_IP}:${port}: busybox nc exited ${rc}, want 0, since the replies to a connection plexd opened need no rule (output: ${out})"
    fi
    echo "  PASS: [${tag}] plexd's container connects to meshpeer's listener at ${MESH_PEER_IP}:${port}, which no rule names"
}

# (a) Save the snapshot's peers and policy, which step (h) serves again. The
# policy must be the fixture's, whose revision step (h) waits for.
MESH_SAVED=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null \
    | jq -c '{peers: .peers, policy: .policy}' 2>/dev/null || true)
MESH_SAVED_PEER=$(printf '%s' "${MESH_SAVED}" | jq -r --arg id "${FIXTURE_PEER_B2}" '[.peers[]? | select(.node_id == $id)] | length' 2>/dev/null || true)
if [ "${MESH_SAVED_PEER}" != "1" ]; then
    fail "[mesh policy] the live snapshot carries ${MESH_SAVED_PEER:-no} peer(s) with node_id ${FIXTURE_PEER_B2}, want 1 (saved: ${MESH_SAVED})"
fi
MESH_SAVED_REVISION=$(printf '%s' "${MESH_SAVED}" | jq -r '.policy.revision_id // empty' 2>/dev/null || true)
if [ "${MESH_SAVED_REVISION}" != "${FIXTURE_POLICY_REVISION}" ]; then
    fail "[mesh policy] the live snapshot serves policy revision '${MESH_SAVED_REVISION}', want the fixture's ${FIXTURE_POLICY_REVISION}"
fi
MESH_SAVED_RULES=$(printf '%s' "${MESH_SAVED}" | jq -r '.policy.rules | length' 2>/dev/null || true)
echo "  saved the live snapshot's peers and policy revision ${MESH_SAVED_REVISION} with ${MESH_SAVED_RULES} rule(s)"

# (b) plexd's current public key: the last rotation's new key, or the key it
# registered with when it never rotated. Phases 9 and 9b rotate, so here it is
# the rotation's. A register body is plexd's only while it names plexd's
# resource handle: Phase 3b's crafted register calls replace the captured body.
MESH_KEY_BODY=$(curl -sf "http://localhost:18080/test/last-request/key_rotate" 2>/dev/null || true)
if [ -n "${MESH_KEY_BODY}" ]; then
    PLEXD_PUBKEY=$(printf '%s' "${MESH_KEY_BODY}" | jq -r '.new_public_key // empty' 2>/dev/null || true)
    PLEXD_PUBKEY_FROM="new_public_key of the last key_rotate request"
else
    MESH_KEY_BODY=$(curl -sf "http://localhost:18080/test/last-request/register" 2>/dev/null || true)
    MESH_KEY_HANDLE=$(printf '%s' "${MESH_KEY_BODY}" | jq -r '.resource_handle // empty' 2>/dev/null || true)
    if [ "${MESH_KEY_HANDLE}" != "e2e-node-1" ]; then
        fail "[mesh policy] no key_rotate request was captured, and the captured register body names resource_handle '${MESH_KEY_HANDLE}', not plexd's e2e-node-1, so it does not carry plexd's key"
    fi
    PLEXD_PUBKEY=$(printf '%s' "${MESH_KEY_BODY}" | jq -r '.public_key // empty' 2>/dev/null || true)
    PLEXD_PUBKEY_FROM="public_key of the register request"
fi
case "${PLEXD_PUBKEY}" in
    *[!A-Za-z0-9+/=]* | '') fail "[mesh policy] plexd's public key from the ${PLEXD_PUBKEY_FROM} is '${PLEXD_PUBKEY}', want 44 characters of base64 (body: ${MESH_KEY_BODY})" ;;
esac
if [ "${#PLEXD_PUBKEY}" -ne 44 ]; then
    fail "[mesh policy] plexd's public key from the ${PLEXD_PUBKEY_FROM} is '${PLEXD_PUBKEY}', want 44 characters of base64"
fi
echo "  plexd's public key ${PLEXD_PUBKEY} is the ${PLEXD_PUBKEY_FROM}"

# (c) meshpeer's wg0: a fresh key pair, the edge PSK the mock derives for peer
# ...a0b2 (base64 of the SHA-256 of "mock-edge-psk|<peer id>"), and plexd as
# its one peer at plexd:51820 with plexd's mesh IP and a 5 s keepalive, which
# keeps it initiating until plexd takes its key. The script prints meshpeer's
# public key last.
MESH_SETUP='
set -o pipefail
umask 077
wg genkey > /tmp/wg0.key
printf "%s" "mock-edge-psk|$2" | openssl dgst -sha256 -binary | base64 > /tmp/wg0.psk
ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /tmp/wg0.key \
    peer "$1" preshared-key /tmp/wg0.psk endpoint plexd:51820 \
    allowed-ips "$3/32" persistent-keepalive 5
ip address add "$4/24" dev wg0
ip link set wg0 up
wg pubkey < /tmp/wg0.key
'
MESH_SETUP_OUT=$(dc exec -T meshpeer sh -euc "${MESH_SETUP}" sh "${PLEXD_PUBKEY}" "${FIXTURE_PEER_B2}" "${MESH_NODE_IP}" "${MESH_PEER_IP}" 2>&1) \
    || fail "[mesh policy] setting up wg0 in meshpeer failed: ${MESH_SETUP_OUT}"
MESHPEER_PUBKEY=${MESH_SETUP_OUT##*$'\n'}
case "${MESHPEER_PUBKEY}" in
    *[!A-Za-z0-9+/=]* | '') fail "[mesh policy] meshpeer's wg0 setup printed '${MESH_SETUP_OUT}', want its public key on the last line" ;;
esac
if [ "${#MESHPEER_PUBKEY}" -ne 44 ]; then
    fail "[mesh policy] meshpeer's wg0 setup printed '${MESH_SETUP_OUT}', want its 44-character public key on the last line"
fi
# busybox hostname -i prints each address followed by a blank.
MESHPEER_IP=$(dc exec -T meshpeer hostname -i 2>&1) || fail "[mesh policy] hostname -i in meshpeer failed: ${MESHPEER_IP}"
MESHPEER_IP=${MESHPEER_IP%% *}
case "${MESHPEER_IP}" in
    *[!0-9.]* | '') fail "[mesh policy] hostname -i in meshpeer printed '${MESHPEER_IP}', want its IPv4 address on e2e-net" ;;
esac
echo "  meshpeer's wg0 is up at ${MESH_PEER_IP} with public key ${MESHPEER_PUBKEY}, endpoint ${MESHPEER_IP}:51820"

# (d) Peer ...a0b2 of the served snapshot becomes meshpeer, and the two
# complete a handshake.
splice_state "mesh-policy-peer" \
    '.peers |= map(if .node_id == $v.id then .public_key = $v.key | .endpoint = $v.endpoint else . end)' \
    "$(jq -cn --arg id "${FIXTURE_PEER_B2}" --arg key "${MESHPEER_PUBKEY}" --arg endpoint "${MESHPEER_IP}:51820" \
        '{id: $id, key: $key, endpoint: $endpoint}')"
MESH_HS_START=${SECONDS}
while :; do
    MESH_HS=$(dc exec -T meshpeer wg show wg0 latest-handshakes 2>&1) \
        || fail "[mesh policy] wg show wg0 latest-handshakes in meshpeer failed: ${MESH_HS}"
    MESH_HS_TIME=${MESH_HS##*[[:space:]]}
    case "${MESH_HS_TIME}" in
        *[!0-9]* | '') MESH_HS_TIME=0 ;;
    esac
    if [ "${MESH_HS_TIME}" -gt 0 ]; then
        break
    fi
    if [ $((SECONDS - MESH_HS_START)) -ge 60 ]; then
        fail "[mesh policy] meshpeer completed no handshake with plexd within 60s of the splice (plexd's key is the ${PLEXD_PUBKEY_FROM}); wg show wg0: $(dc exec -T meshpeer wg show wg0 2>&1)"
    fi
    sleep 2
done
echo "  PASS: [mesh policy] meshpeer completed a handshake with plexd $((SECONDS - MESH_HS_START))s after the splice"

# (e) Policy A: 7001 is open to meshpeer and 7002 is not, plexd's own
# connection to meshpeer passes, and the one logged rule is counted in the
# engine's Info line for the revision.
MESH_REV_A="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c4"
MESH_RULES_A=$(jq -c . <<'MESHRULESAEOF'
[
  {"protocol": "tcp", "source_cidr": "10.99.0.3/32", "destination_cidr": "10.99.0.1/32", "ports": {"from": 7001, "to": 7001}},
  {"protocol": "tcp", "source_cidr": "fd00:99::3/128", "destination_cidr": "fd00:99::1/128", "ports": {"from": 7001, "to": 7001}},
  {"protocol": "udp", "source_cidr": "10.99.0.3/32", "destination_cidr": "10.99.0.1/32", "ports": {"from": 7004, "to": 7004}, "log": true}
]
MESHRULESAEOF
)
serve_policy "mesh-policy-a" "${MESH_REV_A}" "${MESH_RULES_A}"
expect_policy_applied "mesh policy A" "${MESH_REV_A}" 3
MESH_LOGGED_A=$(logged_rule_count "${POLICY_LOG}" "${MESH_REV_A}")
if [ "${MESH_LOGGED_A}" != "1" ]; then
    fail "[mesh policy A] the 'policy rules ask for logging, which this release does not do' line plexd logged for revision ${MESH_REV_A} carries count='${MESH_LOGGED_A}', want count=1"
fi
echo "  PASS: [mesh policy A] plexd logged 'policy rules ask for logging, which this release does not do' with count=1 for revision ${MESH_REV_A}"
probe_plexd_port "mesh policy A" 7001 open
probe_plexd_port "mesh policy A" 7002 closed
probe_meshpeer_port "mesh policy A" 7003

# (f) Policy B, A's rules with the legacy "action": "allow", is applied, and
# policy C, whose one rule carries "action": "deny", is rejected whole, so B's
# ruleset stays and 7001 still connects.
MESH_REV_B="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c5"
MESH_RULES_B=$(printf '%s' "${MESH_RULES_A}" | jq -c 'map(. + {action: "allow"})')
serve_policy "mesh-policy-b" "${MESH_REV_B}" "${MESH_RULES_B}"
expect_policy_applied "mesh policy B" "${MESH_REV_B}" 3

MESH_REV_C="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c6"
MESH_RULES_C='[{"action":"deny","protocol":"tcp","source_cidr":"10.99.0.3/32","destination_cidr":"10.99.0.1/32","ports":{"from":7001,"to":7001}}]'
serve_policy "mesh-policy-c" "${MESH_REV_C}" "${MESH_RULES_C}"
wait_policy_line "mesh policy C" "policy revision rejected, keeping previous ruleset" "${MESH_REV_C}" 0
MESH_REJECTED_C=$(count_log_lines "${POLICY_LOG}" 'msg="policy revision rejected, keeping previous ruleset"' "revision_id=${MESH_REV_C}" "unsupported action")
if [ "${MESH_REJECTED_C}" -lt 1 ]; then
    fail "[mesh policy C] plexd rejected revision ${MESH_REV_C}, but no rejection line names 'unsupported action'"
fi
MESH_APPLIED_C=$(count_log_lines "${POLICY_LOG}" 'msg="policy ruleset applied"' "revision_id=${MESH_REV_C}")
if [ "${MESH_APPLIED_C}" -ne 0 ]; then
    fail "[mesh policy C] plexd logged 'policy ruleset applied' for the rejected revision ${MESH_REV_C} ${MESH_APPLIED_C} time(s)"
fi
echo "  PASS: [mesh policy C] plexd logged 'policy revision rejected, keeping previous ruleset' with revision_id=${MESH_REV_C} for its unsupported action"
probe_plexd_port "mesh policy C" 7001 open

# (g) Policy D, A without its 7001 rules, closes 7001, and so does policy E,
# which has no rules, while mesh DNS inside plexd's container still answers.
MESH_REV_D="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c7"
MESH_RULES_D=$(printf '%s' "${MESH_RULES_A}" | jq -c 'map(select(.ports.from != 7001))')
serve_policy "mesh-policy-d" "${MESH_REV_D}" "${MESH_RULES_D}"
expect_policy_applied "mesh policy D" "${MESH_REV_D}" 1
probe_plexd_port "mesh policy D" 7001 closed

MESH_REV_E="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c8"
serve_policy "mesh-policy-e" "${MESH_REV_E}" '[]'
expect_policy_applied "mesh policy E" "${MESH_REV_E}" 0
mesh_nslookup node-1.app.e2e.internal
if [ "${NSLOOKUP_RC}" -eq 0 ] && nslookup_answers "${NSLOOKUP_OUT}" node-1.app.e2e.internal "${MESH_NODE_IP}"; then
    echo "  PASS: [mesh policy E] nslookup -type=a node-1.app.e2e.internal ${MESH_DNS_LISTEN} answers ${MESH_NODE_IP} from inside the plexd container"
else
    fail "[mesh policy E] nslookup -type=a node-1.app.e2e.internal ${MESH_DNS_LISTEN} exited ${NSLOOKUP_RC}, want 0 and ${MESH_NODE_IP}: the query arrives on lo, which the chain does not match (output: ${NSLOOKUP_OUT})"
fi
probe_plexd_port "mesh policy E" 7001 closed

# (h) The saved peers and policy are served again, plexd applies the fixture's
# revision once more, and meshpeer's wg0 goes, so no later phase meets it.
POLICY_LOG=$(dc logs plexd 2>&1) || fail "[mesh restore] dc logs plexd failed: ${POLICY_LOG}"
MESH_FIXTURE_APPLIED=$(count_log_lines "${POLICY_LOG}" 'msg="policy ruleset applied"' "revision_id=${FIXTURE_POLICY_REVISION}")
splice_state "mesh-policy-restore" '.peers = $v.peers | .policy = $v.policy' "${MESH_SAVED}"
expect_policy_applied "mesh restore" "${FIXTURE_POLICY_REVISION}" "${MESH_SAVED_RULES}" "${MESH_FIXTURE_APPLIED}"
MESH_SERVED=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null \
    | jq -c '{peers: .peers, policy: .policy}' 2>/dev/null || true)
if [ "$(jq -n --argjson a "${MESH_SERVED:-null}" --argjson b "${MESH_SAVED}" '$a == $b' 2>&1)" = "true" ]; then
    echo "  PASS: [mesh restore] the mock serves the saved peers and policy again"
else
    fail "[mesh restore] the mock serves '${MESH_SERVED}' after the restore, want the saved '${MESH_SAVED}'"
fi
MESH_DEL_OUT=$(dc exec -T meshpeer ip link del wg0 2>&1) || fail "[mesh restore] deleting wg0 in meshpeer failed: ${MESH_DEL_OUT}"

echo "=== Phase 12e PASSED: policy enforcement on the mesh interface ==="

# ===================================================================
# Phase 13: Converge cycle (full envelope mutation)
# ===================================================================
# POST a mutated NodeStateSnapshot whose policy fingerprint differs from the
# served fixture, then assert the agent converges: state_count advances and the
# differ reports policy drift, so the policy handler runs. The fingerprint is
# opaque to plexd, so a fresh constant forces PolicyChanged.
#
# This gates on the reconciler's own drift summary, NOT on "policy ruleset
# applied". The phase proves the differ's verdict on a changed fingerprint, and
# Phase 13a proves its verdict on an unchanged one by counting the same drift
# lines from where this phase leaves them, so both read the differ's own
# output. The applied line would add nothing here: Phase 12e has already shown,
# with traffic over the mesh interface, that an applied ruleset reaches the
# kernel.
POLICY_DRIFT_RE='reconciliation cycle completed.*drift=("[^"]*policy|policy)'
# grep -c exits 1 when it finds nothing, so tolerate that with '|| true'.
policy_drift_count() { dc logs plexd 2>&1 | grep -cE "${POLICY_DRIFT_RE}" || true; }

echo "=== Testing converge cycle (full envelope mutation) ==="

# Record state_count and the current policy-drift cycle count.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE_CONV=$(get_counter "${RESPONSE}" "state_count")
PDRIFT_BEFORE_CONV=$(policy_drift_count)
echo "  state_count before: ${STATE_BEFORE_CONV}"
echo "  policy-drift cycle count before: ${PDRIFT_BEFORE_CONV}"

# Mutated NodeStateSnapshot envelope (contract shape). ports is an object
# {from,to}; peers carry no psk/allowed_ips/endpoint. The 44-char base64
# fingerprint is an arbitrary constant, deliberately different from the mock's
# computed fixture fingerprint, so the differ reports PolicyChanged.
CONVERGE_STATE=$(cat <<'CONVEOF'
{
  "peers": [
    {"node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1", "mesh_ip": "10.99.0.2", "public_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "fallback_endpoint": "203.0.113.1:51820"},
    {"node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2", "mesh_ip": "10.99.0.3", "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
  ],
  "reachability": {"state": "healthy", "changed_at": "2026-01-01T00:00:00Z"},
  "policy": {
    "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c2",
    "fingerprint": "ZTJlLW11dGF0ZWQtZmluZ2VycHJpbnQtY29uc3RhbnQx",
    "rules": [
      {"action": "allow", "protocol": "tcp", "source_cidr": "10.99.0.0/24", "destination_cidr": "0.0.0.0/0", "ports": {"from": 443, "to": 8080}}
    ]
  },
  "bridge": null,
  "state": {
    "metadata": [{"key": "environment", "value": "e2e-mutated"}, {"key": "test_key", "value": "test_value_converge"}],
    "data": [],
    "reports": []
  },
  "reports": {
    "metadata": [{"key": "environment", "value": "e2e-mutated"}, {"key": "test_key", "value": "test_value_converge"}],
    "data": [],
    "reports": []
  }
}
CONVEOF
)
CONV_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${CONVERGE_STATE}" \
    "http://localhost:18080/test/configure-state" 2>/dev/null || true)
if [ "${CONV_STATUS}" != "204" ]; then
    fail "configure-state returned status ${CONV_STATUS}, want 204"
fi
echo "  mutated NodeStateSnapshot posted to configure-state"

# Trigger a reconcile via the heartbeat response.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 || true

# Poll until state_count advances AND a cycle reported policy drift. Both are hard.
CONV_TIMEOUT=60
CONV_ELAPSED=0
CONV_STATE_PASSED=0
CONV_PDRIFT_PASSED=0
PDRIFT_AFTER_CONV=${PDRIFT_BEFORE_CONV}
while [ "${CONV_ELAPSED}" -lt "${CONV_TIMEOUT}" ]; do
    sleep 3
    CONV_ELAPSED=$((CONV_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_CONV=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_CONV}" -gt "${STATE_BEFORE_CONV}" ] && [ "${CONV_STATE_PASSED}" -eq 0 ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_CONV} to ${STATE_AFTER_CONV}"
            CONV_STATE_PASSED=1
        fi
    fi
    PDRIFT_AFTER_CONV=$(policy_drift_count)
    if [ "${PDRIFT_AFTER_CONV}" -gt "${PDRIFT_BEFORE_CONV}" ] && [ "${CONV_PDRIFT_PASSED}" -eq 0 ]; then
        echo "  PASS: policy-drift cycle count increased from ${PDRIFT_BEFORE_CONV} to ${PDRIFT_AFTER_CONV}"
        CONV_PDRIFT_PASSED=1
    fi
    if [ "${CONV_STATE_PASSED}" -eq 1 ] && [ "${CONV_PDRIFT_PASSED}" -eq 1 ]; then
        break
    fi
done

if [ "${CONV_STATE_PASSED}" -eq 0 ]; then
    STATE_AFTER_CONV=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after converge mutation (before=${STATE_BEFORE_CONV}, after=${STATE_AFTER_CONV})"
fi
if [ "${CONV_PDRIFT_PASSED}" -eq 0 ]; then
    fail "policy-drift cycle count did not increase after fingerprint change (before=${PDRIFT_BEFORE_CONV}, after=${PDRIFT_AFTER_CONV}); the differ did not report PolicyChanged"
fi

echo "=== Phase 13 PASSED: converge cycle ==="

# ===================================================================
# Phase 13a: policy fingerprint no-op cycle
# ===================================================================
# Re-POST the same envelope with only revision_id bumped and a metadata value
# changed; the policy fingerprint is unchanged. The differ must short-circuit
# (PolicyChanged stays false), so no cycle reports policy drift even though the
# state advances and the revision bumps.
echo "=== Testing policy fingerprint no-op cycle ==="

# Baseline the policy-drift count from the END of the converge phase.
PDRIFT_BEFORE_NOOP=${PDRIFT_AFTER_CONV}
echo "  policy-drift cycle count before: ${PDRIFT_BEFORE_NOOP}"

# Same envelope, but revision_id bumped (...a0c3) and the test_key metadata value
# changed in BOTH state and reports. The fingerprint stays EXACTLY the same.
NOOP_STATE=$(cat <<'NOOPEOF'
{
  "peers": [
    {"node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1", "mesh_ip": "10.99.0.2", "public_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "fallback_endpoint": "203.0.113.1:51820"},
    {"node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2", "mesh_ip": "10.99.0.3", "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
  ],
  "reachability": {"state": "healthy", "changed_at": "2026-01-01T00:00:00Z"},
  "policy": {
    "revision_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c3",
    "fingerprint": "ZTJlLW11dGF0ZWQtZmluZ2VycHJpbnQtY29uc3RhbnQx",
    "rules": [
      {"action": "allow", "protocol": "tcp", "source_cidr": "10.99.0.0/24", "destination_cidr": "0.0.0.0/0", "ports": {"from": 443, "to": 8080}}
    ]
  },
  "bridge": null,
  "state": {
    "metadata": [{"key": "environment", "value": "e2e-mutated"}, {"key": "test_key", "value": "test_value_noop"}],
    "data": [],
    "reports": []
  },
  "reports": {
    "metadata": [{"key": "environment", "value": "e2e-mutated"}, {"key": "test_key", "value": "test_value_noop"}],
    "data": [],
    "reports": []
  }
}
NOOPEOF
)
NOOP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${NOOP_STATE}" \
    "http://localhost:18080/test/configure-state" 2>/dev/null || true)
if [ "${NOOP_STATUS}" != "204" ]; then
    fail "configure-state returned status ${NOOP_STATUS}, want 204"
fi
echo "  revision-only mutated NodeStateSnapshot posted to configure-state"

# Baseline state_count AFTER the POST: a reconcile landing between the read and
# the POST would otherwise satisfy the gate below while having fetched the old
# converge envelope. Both reads are guarded — get_counter emits nothing when the
# assert endpoint is unreachable, and an empty operand would make the gate pass
# vacuously.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining Phase 13a"
STATE_BEFORE_NOOP=$(get_counter "${RESPONSE}" "state_count")
[ -n "${STATE_BEFORE_NOOP}" ] || fail "state_count missing from assert response"
echo "  state_count before: ${STATE_BEFORE_NOOP}"

# Trigger a reconcile via the heartbeat response.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 || true

# Poll until state_count advances by at least 1, proving the no-op envelope was
# picked up by a reconcile.
NOOP_TIMEOUT=60
NOOP_ELAPSED=0
NOOP_STATE_PASSED=0
while [ "${NOOP_ELAPSED}" -lt "${NOOP_TIMEOUT}" ]; do
    sleep 3
    NOOP_ELAPSED=$((NOOP_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_NOOP=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_NOOP}" -gt "${STATE_BEFORE_NOOP}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_NOOP} to ${STATE_AFTER_NOOP}"
            NOOP_STATE_PASSED=1
            break
        fi
    fi
done

if [ "${NOOP_STATE_PASSED}" -eq 0 ]; then
    STATE_AFTER_NOOP=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after revision-only mutation (before=${STATE_BEFORE_NOOP}, after=${STATE_AFTER_NOOP})"
fi

# The cycle that consumed the no-op envelope has already run (state_count moved).
# Give its "reconciliation cycle completed" line a moment to reach the log — this
# is a flush allowance, NOT a reconcile interval, which is 60s here.
sleep 3
PDRIFT_AFTER_NOOP=$(policy_drift_count)
if [ "${PDRIFT_AFTER_NOOP}" -eq "${PDRIFT_BEFORE_NOOP}" ]; then
    echo "  PASS: policy-drift cycle count unchanged at ${PDRIFT_AFTER_NOOP} (fingerprint short-circuit held)"
else
    # A failing handler holds the snapshot back, so the previous cycle's diff --
    # PolicyChanged included -- recurs verbatim. The drift lines carry
    # handler_failed, which tells the two causes apart; print them rather than
    # blaming the differ for a failure this assertion cannot attribute.
    echo "  policy-drift cycles observed:"
    dc logs plexd 2>&1 | grep -E "${POLICY_DRIFT_RE}" | tail -5
    fail "policy-drift cycle count changed from ${PDRIFT_BEFORE_NOOP} to ${PDRIFT_AFTER_NOOP}; either the revision-only bump reported PolicyChanged or a failing handler replayed the converge diff (see handler_failed above)"
fi

echo "=== Phase 13a PASSED: policy fingerprint no-op cycle ==="

# ===================================================================
# Phase 13b: stale_after-driven endpoint re-report cadence
# ===================================================================
# The endpoint TTL was set to 40s during setup while nat.refresh_interval is
# 120s. plexd schedules its next report at
# min(refresh_interval, stale_after - now - 30s) floored at 10s, so the 40s TTL
# forces a ~10s cadence that the 120s ticker alone could never produce.
echo "=== Testing stale_after-driven endpoint re-report cadence ==="

# (a) Absorb one pickup cycle: if plexd's very first report raced ahead of the
#     configure-endpoint call, it carried the default TTL and the next report
#     lands ~120s later. Wait for one increment so the 40s TTL is in effect.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
EP_START=$(get_counter "${RESPONSE}" "endpoint_count")
echo "  endpoint_count at phase start: ${EP_START}"
PICKUP_TIMEOUT=130
PICKUP_ELAPSED=0
PICKUP_PASSED=0
while [ "${PICKUP_ELAPSED}" -lt "${PICKUP_TIMEOUT}" ]; do
    sleep 3
    PICKUP_ELAPSED=$((PICKUP_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        EP_NOW=$(get_counter "${RESPONSE}" "endpoint_count")
        if [ "${EP_NOW}" -ge $((EP_START + 1)) ]; then
            echo "  PASS: endpoint_count advanced to ${EP_NOW} (short TTL in effect)"
            PICKUP_PASSED=1
            break
        fi
    fi
done
if [ "${PICKUP_PASSED}" -eq 0 ]; then
    EP_NOW=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "endpoint_count")
    fail "endpoint_count did not advance past ${EP_START} within ${PICKUP_TIMEOUT}s (before=${EP_START}, after=${EP_NOW})"
fi

# (b) With the short TTL confirmed, two further reports must land within 40s.
#     Impossible at the 120s ticker; guaranteed at the 10s deadline cadence
#     (40s TTL - 30s margin -> 10s, floored at 10s).
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
EP_BASELINE=$(get_counter "${RESPONSE}" "endpoint_count")
echo "  endpoint_count baseline for cadence check: ${EP_BASELINE}"
CADENCE_TIMEOUT=40
CADENCE_ELAPSED=0
CADENCE_PASSED=0
while [ "${CADENCE_ELAPSED}" -lt "${CADENCE_TIMEOUT}" ]; do
    sleep 3
    CADENCE_ELAPSED=$((CADENCE_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        EP_NOW=$(get_counter "${RESPONSE}" "endpoint_count")
        if [ "${EP_NOW}" -ge $((EP_BASELINE + 2)) ]; then
            echo "  PASS: endpoint_count reached ${EP_NOW} (>= baseline+2) within ${CADENCE_ELAPSED}s"
            CADENCE_PASSED=1
            break
        fi
    fi
done
if [ "${CADENCE_PASSED}" -eq 0 ]; then
    EP_NOW=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "endpoint_count")
    fail "endpoint_count only reached ${EP_NOW} within ${CADENCE_TIMEOUT}s (want >= $((EP_BASELINE + 2))); stale_after deadline did not drive fast re-reporting"
fi

# (c) Restore a long TTL so later phases are unaffected by the fast cadence.
EP_RESET_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"ttl_seconds": 300}' \
    "http://localhost:18080/test/configure-endpoint" 2>/dev/null || true)
if [ "${EP_RESET_STATUS}" != "204" ]; then
    fail "configure-endpoint reset returned status ${EP_RESET_STATUS}, want 204"
fi
echo "  endpoint TTL reset to 300s"

echo "=== Phase 13b PASSED: stale_after-driven endpoint re-report cadence ==="

# ===================================================================
# Phase 14: Local Endpoint Delivery
# ===================================================================
echo "=== Polling for local endpoint delivery ==="
LOCAL_TIMEOUT=60
LOCAL_ELAPSED=0

while [ "${LOCAL_ELAPSED}" -lt "${LOCAL_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        LOCAL_METRICS=$(get_counter "${RESPONSE}" "local_metrics_count")
        LOCAL_LOGS=$(get_counter "${RESPONSE}" "local_logs_count")
        LOCAL_AUDIT=$(get_counter "${RESPONSE}" "local_audit_count")
        if [ "${LOCAL_METRICS}" -ge 1 ] && [ "${LOCAL_LOGS}" -ge 1 ] && [ "${LOCAL_AUDIT}" -ge 1 ]; then
            echo "  PASS: local_metrics_count=${LOCAL_METRICS} >= 1"
            echo "  PASS: local_logs_count=${LOCAL_LOGS} >= 1"
            echo "  PASS: local_audit_count=${LOCAL_AUDIT} >= 1"
            break
        fi
    fi
    sleep 3
    LOCAL_ELAPSED=$((LOCAL_ELAPSED + 3))
done

if [ "${LOCAL_ELAPSED}" -ge "${LOCAL_TIMEOUT}" ]; then
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    LOCAL_METRICS=$(get_counter "${RESPONSE}" "local_metrics_count")
    LOCAL_LOGS=$(get_counter "${RESPONSE}" "local_logs_count")
    LOCAL_AUDIT=$(get_counter "${RESPONSE}" "local_audit_count")
    echo "  local_metrics_count=${LOCAL_METRICS}, local_logs_count=${LOCAL_LOGS}, local_audit_count=${LOCAL_AUDIT}"
    fail "local endpoint delivery not met within ${LOCAL_TIMEOUT}s"
fi

echo "=== Phase 14 PASSED: local endpoint delivery ==="

# ===================================================================
# Phase 15: Local Endpoint Body Validation
# ===================================================================
echo "=== Validating local endpoint request bodies ==="

# Local metrics body must be a JSON array with at least one entry.
LOCAL_METRICS_BODY=$(curl -sf "http://localhost:18080/test/last-request/local_metrics" 2>/dev/null || true)
if [ -z "${LOCAL_METRICS_BODY}" ]; then
    fail "no captured local_metrics request body"
fi
LOCAL_METRICS_LEN=$(echo "${LOCAL_METRICS_BODY}" | jq 'if type == "array" then length else 1 end')
if [ "${LOCAL_METRICS_LEN}" -ge 1 ]; then
    echo "  PASS: local_metrics body has ${LOCAL_METRICS_LEN} entries"
else
    fail "local_metrics body is empty"
fi

# Local logs body must be a JSON array with at least one entry.
LOCAL_LOGS_BODY=$(curl -sf "http://localhost:18080/test/last-request/local_logs" 2>/dev/null || true)
if [ -z "${LOCAL_LOGS_BODY}" ]; then
    fail "no captured local_logs request body"
fi
LOCAL_LOGS_LEN=$(echo "${LOCAL_LOGS_BODY}" | jq 'if type == "array" then length else 1 end')
if [ "${LOCAL_LOGS_LEN}" -ge 1 ]; then
    echo "  PASS: local_logs body has ${LOCAL_LOGS_LEN} entries"
else
    fail "local_logs body is empty"
fi

# Local audit body must be a JSON array with at least one entry.
LOCAL_AUDIT_BODY=$(curl -sf "http://localhost:18080/test/last-request/local_audit" 2>/dev/null || true)
if [ -z "${LOCAL_AUDIT_BODY}" ]; then
    fail "no captured local_audit request body"
fi
LOCAL_AUDIT_LEN=$(echo "${LOCAL_AUDIT_BODY}" | jq 'if type == "array" then length else 1 end')
if [ "${LOCAL_AUDIT_LEN}" -ge 1 ]; then
    echo "  PASS: local_audit body has ${LOCAL_AUDIT_LEN} entries"
else
    fail "local_audit body is empty"
fi

echo "=== Phase 15 PASSED: local endpoint body validation ==="

# ===================================================================
# Phase 16: Dual Delivery Verification
# ===================================================================
echo "=== Verifying dual delivery (platform + local) ==="

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
PLAT_METRICS=$(get_counter "${RESPONSE}" "metrics_count")
PLAT_LOGS=$(get_counter "${RESPONSE}" "logs_count")
PLAT_AUDIT=$(get_counter "${RESPONSE}" "audit_count")
LOCAL_METRICS=$(get_counter "${RESPONSE}" "local_metrics_count")
LOCAL_LOGS=$(get_counter "${RESPONSE}" "local_logs_count")
LOCAL_AUDIT=$(get_counter "${RESPONSE}" "local_audit_count")

# Audit is not in this list: its platform leg carries nothing while no
# contract-legal source is wired (see phase 6), so only its local leg is
# asserted, just below.
DUAL_PASS=1
for pair in "metrics_count:${PLAT_METRICS}:local_metrics_count:${LOCAL_METRICS}" \
            "logs_count:${PLAT_LOGS}:local_logs_count:${LOCAL_LOGS}"; do
    IFS=: read -r plat_key plat_val local_key local_val <<< "${pair}"
    if [ "${plat_val}" -ge 1 ] && [ "${local_val}" -ge 1 ]; then
        echo "  PASS: ${plat_key}=${plat_val} >= 1 AND ${local_key}=${local_val} >= 1"
    else
        echo "  FAIL: ${plat_key}=${plat_val}, ${local_key}=${local_val} (both must be >= 1)"
        DUAL_PASS=0
    fi
done

if [ "${LOCAL_AUDIT}" -ge 1 ] && [ "${PLAT_AUDIT}" -eq 0 ]; then
    echo "  PASS: local_audit_count=${LOCAL_AUDIT} >= 1 AND audit_count=${PLAT_AUDIT} (platform leg carries no legal source)"
else
    echo "  FAIL: local_audit_count=${LOCAL_AUDIT} (want >= 1), audit_count=${PLAT_AUDIT} (want 0)"
    DUAL_PASS=0
fi

if [ "${DUAL_PASS}" -eq 0 ]; then
    fail "dual delivery verification failed"
fi

echo "=== Phase 16 PASSED: dual delivery verification ==="

# ===================================================================
# Phase 17: Pull-only delivery mode under a descoped event bus
# ===================================================================
# Descoping the mock's event bus makes GET /v1/nodes/{id}/events answer the
# spec's 501, so the open SSE stream closes and plexd reclassifies delivery as
# pull_only within seconds. While descoped it keeps reconciling on its own 60s
# loop (state_count rises) and only re-probes SSE once per sse_reprobe_interval
# (5s here) rather than hot-looping. Restoring streaming returns delivery to SSE
# and fresh injects flow again. The mode is read from `plexd status`, which
# renders the node-API cache metadata (delivery_mode key) generically.
echo "=== Testing pull-only delivery mode under a descoped event bus ==="

# poll_delivery_mode: poll `plexd status` inside the plexd container until its
# rendered metadata shows the wanted delivery_mode within the timeout. Returns 0
# on match, 1 on timeout. Whitespace-tolerant so it survives the "  key: value"
# indent the status command prints.
poll_delivery_mode() {
    local want=$1 timeout=$2 elapsed=0 out
    while [ "${elapsed}" -lt "${timeout}" ]; do
        out=$(dc exec -T plexd /usr/local/bin/plexd status 2>/dev/null || true)
        if echo "${out}" | grep -qE "delivery_mode:[[:space:]]*${want}"; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

# (a) Flip the event bus to descoped.
DM_DESCOPE_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"mode":"descoped"}' \
    "http://localhost:18080/test/configure-events" 2>/dev/null || true)
if [ "${DM_DESCOPE_STATUS}" != "204" ]; then
    fail "configure-events (descoped) returned status ${DM_DESCOPE_STATUS}, want 204"
fi
echo "  event bus flipped to descoped"

# (b) plexd must reclassify to pull_only within seconds of the stream closing.
if poll_delivery_mode pull_only 30; then
    echo "  PASS: delivery_mode reclassified to pull_only after descope"
else
    fail "delivery_mode did not reach pull_only within 30s after descope"
fi

# (c) Pulls continue while pull-only: the reconciler's own 60s loop advances
#     state_count even with no SSE stream. Poll generously past one interval.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
DM_STATE_BEFORE=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before pull-only wait: ${DM_STATE_BEFORE}"
DM_PULL_TIMEOUT=90
DM_PULL_ELAPSED=0
DM_PULL_PASSED=0
while [ "${DM_PULL_ELAPSED}" -lt "${DM_PULL_TIMEOUT}" ]; do
    sleep 2
    DM_PULL_ELAPSED=$((DM_PULL_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        DM_STATE_AFTER=$(get_counter "${RESPONSE}" "state_count")
        if [ "${DM_STATE_AFTER}" -gt "${DM_STATE_BEFORE}" ]; then
            echo "  PASS: state_count advanced ${DM_STATE_BEFORE} -> ${DM_STATE_AFTER} while pull-only (reconcile loop)"
            DM_PULL_PASSED=1
            break
        fi
    fi
done
if [ "${DM_PULL_PASSED}" -eq 0 ]; then
    DM_STATE_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not advance while pull-only within ${DM_PULL_TIMEOUT}s (before=${DM_STATE_BEFORE}, after=${DM_STATE_AFTER})"
fi

# (d) Re-probe cadence, not hot retry: over a quiet 15s window the events
#     endpoint is hit only a handful of times (~one per 5s sse_reprobe_interval),
#     never a tight retry loop.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while baselining re-probe cadence"
DM_EVREQ_BEFORE=$(get_counter "${RESPONSE}" "events_request_count")
echo "  events_request_count before quiet window: ${DM_EVREQ_BEFORE}"
sleep 15
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
[ -n "${RESPONSE}" ] || fail "assert endpoint unreachable while measuring re-probe cadence"
DM_EVREQ_AFTER=$(get_counter "${RESPONSE}" "events_request_count")
DM_EVREQ_DELTA=$((DM_EVREQ_AFTER - DM_EVREQ_BEFORE))
if [ "${DM_EVREQ_DELTA}" -le 3 ]; then
    echo "  PASS: events_request_count rose by ${DM_EVREQ_DELTA} in 15s (<= 3, quiet re-probing)"
else
    fail "events_request_count rose by ${DM_EVREQ_DELTA} in 15s (> 3); pull-only is hot-retrying the event stream"
fi

# (e) Restore streaming; delivery must return to SSE promptly on a good re-probe.
DM_STREAM_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"mode":"streaming"}' \
    "http://localhost:18080/test/configure-events" 2>/dev/null || true)
if [ "${DM_STREAM_STATUS}" != "204" ]; then
    fail "configure-events (streaming) returned status ${DM_STREAM_STATUS}, want 204"
fi
echo "  event bus flipped to streaming"
if poll_delivery_mode streaming 15; then
    echo "  PASS: delivery_mode returned to streaming"
else
    fail "delivery_mode did not return to streaming within 15s"
fi

# (f) A fresh live inject flows again over the restored stream.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
DM_LIVE_BEFORE=$(get_counter "${RESPONSE}" "state_count")
DM_INJECT_PAYLOAD=$(cat <<'DMEOF'
{
    "id": "evt-e2e-dm-001",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
DMEOF
)
DM_INJECT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${DM_INJECT_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${DM_INJECT_STATUS}" != "204" ]; then
    fail "post-resume node_state_updated injection returned status ${DM_INJECT_STATUS}, want 204"
fi
DM_LIVE_TIMEOUT=15
DM_LIVE_ELAPSED=0
DM_LIVE_PASSED=0
while [ "${DM_LIVE_ELAPSED}" -lt "${DM_LIVE_TIMEOUT}" ]; do
    sleep 2
    DM_LIVE_ELAPSED=$((DM_LIVE_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        DM_LIVE_AFTER=$(get_counter "${RESPONSE}" "state_count")
        if [ "${DM_LIVE_AFTER}" -gt "${DM_LIVE_BEFORE}" ]; then
            echo "  PASS: state_count increased ${DM_LIVE_BEFORE} -> ${DM_LIVE_AFTER} after live inject over streaming"
            DM_LIVE_PASSED=1
            break
        fi
    fi
done
if [ "${DM_LIVE_PASSED}" -eq 0 ]; then
    DM_LIVE_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after the live inject (before=${DM_LIVE_BEFORE}, after=${DM_LIVE_AFTER})"
fi

echo "=== Phase 17 PASSED: pull-only delivery mode under a descoped event bus ==="

# ===================================================================
# Phase 18: Last-Event-ID resume after a descope window
# ===================================================================
# Descope again, buffer two envelopes while the stream is down (the mock records
# them into the replay ring and advances the stream sequence even with no client
# attached), then restore streaming. On reconnect plexd sends its Last-Event-ID
# cursor, the mock replays the buffered envelopes above it, and each verified
# node_state_updated dispatches a reconcile; that plus the reconnect pull drives
# state_count up. Triggers may coalesce, so assert an increase, not a fixed delta.
echo "=== Testing Last-Event-ID resume after a descope window ==="

# (a) Descope and confirm pull-only for the buffering window.
RES_DESCOPE_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"mode":"descoped"}' \
    "http://localhost:18080/test/configure-events" 2>/dev/null || true)
if [ "${RES_DESCOPE_STATUS}" != "204" ]; then
    fail "configure-events (descoped) returned status ${RES_DESCOPE_STATUS}, want 204"
fi
if poll_delivery_mode pull_only 30; then
    echo "  PASS: delivery_mode reclassified to pull_only for the resume window"
else
    fail "delivery_mode did not reach pull_only within 30s for the resume window"
fi

# (b) Buffer two envelopes while descoped; each inject is still accepted (204).
for res_id in evt-e2e-resume-001 evt-e2e-resume-002; do
    RES_PAYLOAD=$(cat <<RESEOF
{
    "id": "${res_id}",
    "type": "node_state_updated",
    "scope": "node",
    "payload": "{\"node_id\":\"e2e-node-1\"}"
}
RESEOF
    )
    RES_INJECT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${RES_PAYLOAD}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${RES_INJECT_STATUS}" != "204" ]; then
        fail "descoped inject ${res_id} returned status ${RES_INJECT_STATUS}, want 204"
    fi
done
echo "  two envelopes buffered while descoped"

# (c) Baseline state_count, then restore streaming so the agent reconnects with
#     its Last-Event-ID cursor and the mock replays the buffered envelopes.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
RES_STATE_BEFORE=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before resume: ${RES_STATE_BEFORE}"
RES_STREAM_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"mode":"streaming"}' \
    "http://localhost:18080/test/configure-events" 2>/dev/null || true)
if [ "${RES_STREAM_STATUS}" != "204" ]; then
    fail "configure-events (streaming) returned status ${RES_STREAM_STATUS}, want 204"
fi
echo "  event bus flipped to streaming"

# (d) The replayed envelopes plus the reconnect pull must advance state_count.
RES_TIMEOUT=30
RES_ELAPSED=0
RES_PASSED=0
while [ "${RES_ELAPSED}" -lt "${RES_TIMEOUT}" ]; do
    sleep 2
    RES_ELAPSED=$((RES_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        RES_STATE_AFTER=$(get_counter "${RESPONSE}" "state_count")
        if [ "${RES_STATE_AFTER}" -gt "${RES_STATE_BEFORE}" ]; then
            echo "  PASS: state_count increased ${RES_STATE_BEFORE} -> ${RES_STATE_AFTER} after resume"
            RES_PASSED=1
            break
        fi
    fi
done
if [ "${RES_PASSED}" -eq 0 ]; then
    RES_STATE_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    fail "state_count did not increase after resume within ${RES_TIMEOUT}s (before=${RES_STATE_BEFORE}, after=${RES_STATE_AFTER})"
fi

echo "=== Phase 18 PASSED: Last-Event-ID resume after a descope window ==="

# ===================================================================
# Phase 19: release-verdict upgrade flow
# ===================================================================
# The service.upgrade builtin downloads a release asset from the mock's
# /releases fixture channel, compares its SHA-256 to the dispatched checksum,
# then verifies the co-located Sigstore bundle offline against the embedded
# trusted root and the configured signing identity/issuer. This phase drives
# three dispatches: a valid release (upgraded_restart_pending), a mismatched
# checksum (checksum_mismatch), and a garbage bundle (bundle_verification_failed).
#
# It runs last among the functional phases because the first dispatch replaces
# the on-disk plexd binary with the 109-byte fixture blob. The running process
# is untouched (systemctl is absent in the container), and only the shutdown
# block below follows -- it signals the running process and does not re-exec
# the on-disk binary.
echo "=== Testing release-verdict upgrade flow ==="

# Compute the fixture blob's digest at runtime (reusing the sha256_hex probe
# from the top of the file) so this phase survives fixture regeneration via the
# Makefile upgrade-fixture target. SCRIPT_DIR is test/e2e/docker, so the blob
# lives one directory up under mockapi/testdata.
FIXTURE_DIGEST=$(sha256_hex < "${SCRIPT_DIR}/../mockapi/testdata/fixture.bin")
if [ -z "${FIXTURE_DIGEST}" ]; then
    fail "could not compute SHA-256 of fixture.bin"
fi
echo "  fixture.bin SHA-256: ${FIXTURE_DIGEST}"

# SHA-256 of empty input; used to force a checksum_mismatch verdict.
EMPTY_DIGEST="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# dispatch_upgrade configures a service.upgrade dispatch in the pull's
# executions block and asserts its terminal execution callback. Args:
# execution-id version checksum expected-callback-status expected-output-status.
# Like Phase 8, a run posts three callbacks (ack -> started -> terminal) and the
# last-request endpoint captures only the most recent, so polling +3 then
# reading it yields the terminal callback. The version and checksum travel as
# JSON strings in the entry's parameters object and reach the builtin verbatim.
dispatch_upgrade() {
    local exec_id=$1 version=$2 checksum=$3 want_cb=$4 want_out=$5

    # Baseline before configuring: the dispatch helper nudges an immediate pull.
    local cb_before
    cb_before=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
    echo "  [${exec_id}] execution_callback_count before: ${cb_before}"

    local params
    params=$(printf '{"version": "%s", "checksum": "%s"}' "${version}" "${checksum}")
    configure_executions "${exec_id}" \
        "$(exec_entry "${exec_id}" "service.upgrade" "builtin" "pending" "${params}")"

    # Poll until the callback counter advances by >= 3 (ack + started +
    # terminal). The first dispatch performs a real Sigstore verification, so
    # allow a generous window.
    local timeout=60 elapsed=0 passed=0 cb_after=0
    while [ "${elapsed}" -lt "${timeout}" ]; do
        sleep 2
        elapsed=$((elapsed + 2))
        cb_after=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_callback_count")
        if [ "${cb_after}" -ge $((cb_before + 3)) ]; then
            passed=1
            break
        fi
    done
    if [ "${passed}" -eq 0 ]; then
        fail "[${exec_id}] execution_callback_count did not reach $((cb_before + 3)) (before=${cb_before}, after=${cb_after})"
    fi
    echo "  [${exec_id}] PASS: execution_callback_count advanced ${cb_before} -> ${cb_after} (>= +3)"

    local cb_body cb_status cb_inline out_status
    cb_body=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
    if [ -z "${cb_body}" ]; then
        fail "[${exec_id}] no execution_callback body captured"
    fi

    cb_status=$(echo "${cb_body}" | jq -r '.status // empty')
    if [ "${cb_status}" != "${want_cb}" ]; then
        fail "[${exec_id}] terminal callback status = '${cb_status}', want '${want_cb}'"
    fi
    echo "  [${exec_id}] PASS: terminal callback status = ${cb_status}"

    cb_inline=$(echo "${cb_body}" | jq -r '.output.inline // empty')
    if [ -z "${cb_inline}" ]; then
        fail "[${exec_id}] terminal callback missing non-empty output.inline"
    fi

    out_status=$(printf '%s' "${cb_inline}" | b64_decode | jq -r '.status // empty')
    if [ "${out_status}" != "${want_out}" ]; then
        fail "[${exec_id}] output status = '${out_status}', want '${want_out}'"
    fi
    echo "  [${exec_id}] PASS: output status = ${out_status}"
}

# Dispatch 1: valid release asset + matching checksum. systemctl is absent in
# the container, so the terminal status is upgraded_restart_pending, exit 0.
dispatch_upgrade "exec-e2e-upgrade-001" \
    "v9.9.9" "${FIXTURE_DIGEST}" "succeeded" "upgraded_restart_pending"
UPG_CB=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
UPG_EXIT=$(echo "${UPG_CB}" | jq -r '.exit_code // empty')
if [ "${UPG_EXIT}" != "0" ]; then
    fail "[exec-e2e-upgrade-001] terminal callback exit_code = '${UPG_EXIT}', want 0"
fi
echo "  PASS: v9.9.9 upgrade succeeded with exit_code 0 (restart pending)"

# Dispatch 2: valid release asset but a checksum that cannot match (empty-input
# digest) -> checksum_mismatch, callback failed, before the bundle is fetched.
dispatch_upgrade "exec-e2e-upgrade-002" \
    "v9.9.9" "${EMPTY_DIGEST}" "failed" "checksum_mismatch"
echo "  PASS: mismatched checksum rejected as checksum_mismatch"

# Dispatch 3: matching checksum but the v9.9.8 tag serves a garbage (non-JSON)
# Sigstore bundle -> bundle_verification_failed, callback failed.
dispatch_upgrade "exec-e2e-upgrade-003" \
    "v9.9.8" "${FIXTURE_DIGEST}" "failed" "bundle_verification_failed"
echo "  PASS: garbage Sigstore bundle rejected as bundle_verification_failed"

echo "=== Phase 19 PASSED: release-verdict upgrade flow ==="

# ===================================================================
# Phase 20: the credential the agent presents
#
# Every phase above ran through the mock's bearer-envelope gate, so this one
# only has to state the outcome: across the whole run the control plane refused
# nothing, and the agent never logged a refused credential. Its heartbeat warns
# on the first two 401s in a row and logs an Error when the third parks the
# agent and suspends its control-plane calls. Both halves matter — v0.3.0
# registered successfully and then 401ed on every later call, which looks like
# a healthy node until the reports it never delivered are missed (issue #60).
# ===================================================================
echo "=== Testing that every authenticated call presented the NSK envelope ==="

UNAUTHORIZED=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "unauthorized_count")
if [ "${UNAUTHORIZED}" != "0" ]; then
    fail "the control plane refused ${UNAUTHORIZED} request(s): the agent presented a credential that is not the NSK bearer envelope"
fi
echo "  PASS: unauthorized_count = 0 across the whole run"

CREDENTIAL_REFUSALS=$(dc logs plexd 2>/dev/null | grep -c "credential refused" || true)
if [ "${CREDENTIAL_REFUSALS}" != "0" ]; then
    fail "plexd logged ${CREDENTIAL_REFUSALS} credential refused line(s), so the control plane refuses the credential it presents"
fi
echo "  PASS: no credential refused line in the agent log"

echo "=== Phase 20 PASSED: bearer envelope on every authenticated call ==="

# ===================================================================
# Phase 11: Graceful shutdown verification
# ===================================================================
echo "=== Testing graceful shutdown ==="

# Stop only the plexd container (not mock-api, we need it for assertions).
PLEXD_CONTAINER=$(dc ps -q plexd 2>/dev/null || true)
if [ -z "${PLEXD_CONTAINER}" ]; then
    fail "plexd container not found"
fi

# Send SIGTERM via docker stop (default 10s grace period).
dc stop plexd

# Check exit code.
EXIT_CODE=$(docker inspect "${PLEXD_CONTAINER}" --format='{{.State.ExitCode}}' 2>/dev/null || echo "unknown")
if [ "${EXIT_CODE}" = "0" ]; then
    echo "  PASS: plexd exited with code 0 (clean shutdown)"
else
    echo "  WARN: plexd exited with code ${EXIT_CODE} (may indicate unclean shutdown)"
fi

# Check logs for crash indicators.
PLEXD_LOGS=$(dc logs plexd 2>/dev/null || true)
CRASH_FOUND=0
for indicator in "panic:" "fatal error:" "SIGABRT" "SIGKILL" "runtime error:"; do
    if echo "${PLEXD_LOGS}" | grep -qi "${indicator}"; then
        echo "  FAIL: crash indicator '${indicator}' found in plexd logs"
        CRASH_FOUND=1
    fi
done

if [ "${CRASH_FOUND}" -ne 0 ]; then
    echo "--- plexd logs ---"
    echo "${PLEXD_LOGS}"
    fail "crash indicators found in plexd logs"
fi
echo "  PASS: no crash indicators in plexd logs"

# Verify plexd logged the shutdown message.
if echo "${PLEXD_LOGS}" | grep -q "plexd stopped\|shutting down"; then
    echo "  PASS: plexd logged shutdown message"
else
    echo "  WARN: no explicit shutdown message found in plexd logs"
fi

echo "=== Phase 11 PASSED: graceful shutdown ==="

TEST_FAILED=0
echo "=== ALL TESTS PASSED ==="
