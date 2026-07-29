#!/usr/bin/env bash
# Docker E2E test orchestration script.
# Builds and runs the mock-api and plexd containers via docker compose,
# then polls the mock-api assertion endpoint to verify plexd performed
# registration, heartbeat, state, capabilities, metrics, logs, and audit calls.
#
# Extended tests:
#   - Periodic loop verification (counters >= 2 after additional wait)
#   - Request body validation (registration token, heartbeat, capabilities)
#   - Log injection (docker cp into container, verify logs_count increases)
#   - Agent restart for audit verification (ProcessSource fires per-process)
#   - SSE event injection triggers reconciliation (state_count increases)
#   - Action execution via the state pull's executions block
#     (ack/started/terminal callbacks)
#   - Executions resumed from a seeded status (no re-ack, no re-run)
#   - action_request is a pull trigger, not a delivery channel
#   - Key rotation completes end to end via RotateKeys flag
#   - Deeper body validation (metrics, audit, logs, capabilities fields)
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

# 3f. Endpoint report body must carry {endpoint, nat_type, reported_at}.
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

EP_REPORTED_AT=$(echo "${EP_BODY}" | jq -r '.reported_at // empty')
if [ -z "${EP_REPORTED_AT}" ]; then
    fail "endpoint body missing 'reported_at' field"
fi
echo "  PASS: endpoint body reported_at='${EP_REPORTED_AT}'"

# 3c. Capability manifest: the contract's flat envelope. binary_version and
# binary_checksum are required, the digest is 32 bytes in standard-padded base64
# (hex decodes to 48 and is refused), and the shape carries nothing else — the
# handler decodes with DisallowUnknownFields, so a nested `binary` object or a
# `builtin_actions` list refuses the whole manifest. The agent's action list is
# asserted where it is actually served, on the node API in phase 12b.
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
for absent in builtin_actions binary hooks; do
    if echo "${CAPS_BODY}" | jq -e --arg k "${absent}" 'has($k)' >/dev/null 2>&1; then
        fail "capability manifest carries '${absent}', which the handler rejects as an unknown field"
    fi
done
echo "  PASS: capability manifest is contract-shaped (version=${CAPS_VERSION}, 32-byte digest)"

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
# terminated_by plexd_close — the node cannot tell a revocation from a control
# plane that failed to serve the block, so it never claims operator_revoke.
echo "=== Testing pull-driven TCP session lifecycle ==="

# ExpiresAt 5 minutes ahead in RFC 3339 UTC (GNU date -d, BSD date -v fallback).
EXPIRES_AT=$(date -u -d "+5 minutes" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+5M +%Y-%m-%dT%H:%M:%SZ)
echo "  session expires_at: ${EXPIRES_AT}"

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
SESS_BEFORE=$(get_counter "${RESPONSE}" "session_activity_count")
echo "  session_activity_count before: ${SESS_BEFORE}"

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
# signal, there is no separate revocation event.
configure_sessions "8e-drain" "[]"
echo "  tcp session drained from the sessions block"

# Poll session_activity_count to +2 (session_ended row).
REV_ELAPSED=0
SESS_END_PASSED=0
while [ "${REV_ELAPSED}" -lt "${SESS_TIMEOUT}" ]; do
    sleep 2
    REV_ELAPSED=$((REV_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        SESS_AFTER=$(get_counter "${RESPONSE}" "session_activity_count")
        if [ "${SESS_AFTER}" -ge $((SESS_BEFORE + 2)) ]; then
            echo "  PASS: session_activity_count advanced to ${SESS_AFTER} (>= +2)"
            SESS_END_PASSED=1
            break
        fi
    fi
done

if [ "${SESS_END_PASSED}" -eq 0 ]; then
    SESS_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "session_activity_count")
    fail "session_activity_count did not reach $((SESS_BEFORE + 2)) after the drain (before=${SESS_BEFORE}, after=${SESS_AFTER})"
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
# The entry drained before its expiry lapsed. That may be a revocation or a
# control plane that failed to serve the block, and the node cannot tell them
# apart, so it reports a local close rather than asserting an operator action.
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
# Phase 8h: session events are pull triggers, not delivery channels
# ===================================================================
# The session lifecycle is delivered in the sessions block of the pull.
# session_setup and session_revoked only pull the observing reconcile forward:
# nothing in their payloads is parsed, so an opaque payload must still move
# state_count while leaving the session activity untouched.
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

# session_revoked is the same shape of trigger: the drain in the sessions block
# is the teardown signal, the event only asks for a reconcile.
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
    fail "session_activity_count moved from ${SESS_BEFORE_REVOKE} to ${SESS_AFTER_REVOKE} after session_revoked; the payload was acted on"
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
# the optional fields the contract defines. The agent's builtin action list is
# not part of this body — the contract has no field for it — so the eleven
# builtins are asserted against the node API in phase 12b, which is what serves
# them.
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

    # declared_hooks is optional and absent when the agent advertises none; when
    # present every entry needs a name and a 32-byte base64 digest.
    BAD_HOOKS=$(echo "${CAPS_BODY}" | jq '[.declared_hooks[]? | select((.name // "") == "" or (.checksum // "") == "")] | length')
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

    # 12b. GET /v1/actions -- the agent's builtin action inventory. This is the
    # only surface that carries it: the capability manifest has no field for an
    # action list, so what the control plane never learns is asserted here
    # instead, in full.
    ACTIONS_RESP=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/actions" 2>/dev/null || true)
    if [ -n "${ACTIONS_RESP}" ] && echo "${ACTIONS_RESP}" | jq empty 2>/dev/null; then
        NAPI_ACTION_COUNT=$(echo "${ACTIONS_RESP}" | jq '.builtin_actions | length // 0')
        if [ "${NAPI_ACTION_COUNT}" -eq 11 ]; then
            echo "  PASS: GET /v1/actions returns 11 builtins (exact)"
        else
            fail "GET /v1/actions returns ${NAPI_ACTION_COUNT} builtins, want exactly 11"
        fi

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
# the current one is an honest 404, and that an armed per-node 429 passes
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
# Phase 13: Converge cycle (full envelope mutation)
# ===================================================================
# POST a mutated NodeStateSnapshot whose policy fingerprint differs from the
# served fixture, then assert the agent converges: state_count advances and the
# differ reports policy drift, so the policy handler runs. The fingerprint is
# opaque to plexd, so a fresh constant forces PolicyChanged.
#
# This gates on the reconciler's own drift summary, NOT on "policy ruleset
# applied". This container's kernel exposes no nftables backend, so no rule can
# reach the kernel here and the handler no longer claims an apply it did not
# perform — the drift summary is the signal that actually holds. Proving rule
# installation needs an environment with a working nftables backend.
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
# nothing, and the agent never logged the auth failure that would have driven a
# re-registration loop. Both halves matter — v0.3.0 registered successfully and
# then 401ed on every later call, which looks like a healthy node until the
# reports it never delivered are missed (issue #60).
# ===================================================================
echo "=== Testing that every authenticated call presented the NSK envelope ==="

UNAUTHORIZED=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "unauthorized_count")
if [ "${UNAUTHORIZED}" != "0" ]; then
    fail "the control plane refused ${UNAUTHORIZED} request(s): the agent presented a credential that is not the NSK bearer envelope"
fi
echo "  PASS: unauthorized_count = 0 across the whole run"

AUTH_FAILURES=$(dc logs plexd 2>/dev/null | grep -c "heartbeat auth failure" || true)
if [ "${AUTH_FAILURES}" != "0" ]; then
    fail "plexd logged ${AUTH_FAILURES} heartbeat auth failure(s), so the credential it presents is being refused"
fi
echo "  PASS: no heartbeat auth failure in the agent log"

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
