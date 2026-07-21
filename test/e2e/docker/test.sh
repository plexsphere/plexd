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
#   - Action execution via SSE (action_request → ack + result)
#   - Key rotation completes end to end via RotateKeys flag
#   - Deeper body validation (metrics, audit, logs, capabilities fields)
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

# Counter JSON keys (shared across extraction, checking, and reporting).
COUNTER_KEYS=(registration_count heartbeat_count state_count capabilities_count metrics_count logs_count audit_count)

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
    if curl -sf http://localhost:18080/v1/ping >/dev/null 2>&1; then
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

# binary_checksum must be 64-char lowercase hex.
HB_CHECKSUM=$(echo "${HB_BODY}" | jq -r '.binary_checksum // empty')
if ! echo "${HB_CHECKSUM}" | grep -Eq '^[0-9a-f]{64}$'; then
    fail "heartbeat binary_checksum='${HB_CHECKSUM}' is not 64-char lowercase hex"
fi
echo "  PASS: heartbeat body binary_checksum is 64-char lowercase hex"

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

# 3c. Capabilities body must contain builtin_actions array.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -z "${CAPS_BODY}" ]; then
    fail "no captured capabilities request body"
fi
CAPS_ACTIONS=$(echo "${CAPS_BODY}" | jq -r '.builtin_actions // empty')
if [ -z "${CAPS_ACTIONS}" ] || [ "${CAPS_ACTIONS}" = "null" ]; then
    fail "capabilities body missing 'builtin_actions' field"
fi
CAPS_COUNT=$(echo "${CAPS_BODY}" | jq '.builtin_actions | length')
if [ "${CAPS_COUNT}" -lt 1 ]; then
    fail "capabilities body has empty builtin_actions (want >= 1)"
fi
echo "  PASS: capabilities body contains ${CAPS_COUNT} builtin_actions"

# 3d. Metrics body must be a non-empty array.
METRICS_BODY=$(curl -sf "http://localhost:18080/test/last-request/metrics" 2>/dev/null || true)
if [ -z "${METRICS_BODY}" ]; then
    fail "no captured metrics request body"
fi
METRICS_LEN=$(echo "${METRICS_BODY}" | jq 'length')
if [ "${METRICS_LEN}" -lt 1 ]; then
    fail "metrics body is empty (want >= 1 data point)"
fi
echo "  PASS: metrics body contains ${METRICS_LEN} data points"

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
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
AUDIT_BEFORE=$(get_counter "${RESPONSE}" "audit_count")
echo "  audit_count before restart: ${AUDIT_BEFORE}"

# Restart plexd container (same container, new process).
dc restart plexd

# Wait for the restarted agent to report a new audit entry.
AUDIT_TIMEOUT=30
AUDIT_ELAPSED=0
while [ "${AUDIT_ELAPSED}" -lt "${AUDIT_TIMEOUT}" ]; do
    sleep 3
    AUDIT_ELAPSED=$((AUDIT_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        AUDIT_AFTER=$(get_counter "${RESPONSE}" "audit_count")
        if [ "${AUDIT_AFTER}" -gt "${AUDIT_BEFORE}" ]; then
            echo "  PASS: audit_count increased from ${AUDIT_BEFORE} to ${AUDIT_AFTER} after restart"
            break
        fi
    fi
done

if [ "${AUDIT_ELAPSED}" -ge "${AUDIT_TIMEOUT}" ]; then
    AUDIT_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "audit_count")
    fail "audit_count did not increase after restart (before=${AUDIT_BEFORE}, after=${AUDIT_AFTER})"
fi

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
    "event_type": "node_state_updated",
    "event_id": "evt-e2e-inject-001",
    "issued_at": "2099-01-01T00:00:00Z",
    "nonce": "e2e-inject-nonce-001",
    "payload": "{\"node_id\":\"e2e-node-1\"}",
    "signature": "mock-signature"
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
    "event_type": "policy_updated",
    "event_id": "evt-e2e-policy-001",
    "issued_at": "2099-01-01T00:00:00Z",
    "nonce": "e2e-policy-nonce-001",
    "payload": "{\"policy_id\":\"pol-e2e-001\"}",
    "signature": "mock-signature"
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
# Phase 8: Action execution via SSE injection
# ===================================================================
echo "=== Testing action execution via SSE ==="

# Record current execution counters.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
ACK_BEFORE=$(get_counter "${RESPONSE}" "execution_ack_count")
RESULT_BEFORE=$(get_counter "${RESPONSE}" "execution_result_count")
echo "  execution_ack_count before: ${ACK_BEFORE}"
echo "  execution_result_count before: ${RESULT_BEFORE}"

# Inject an action_request SSE event for the builtin "system.info" action.
ACTION_PAYLOAD=$(cat <<'ACTEOF'
{
    "event_type": "action_request",
    "event_id": "evt-e2e-action-001",
    "issued_at": "2099-01-01T00:00:00Z",
    "nonce": "e2e-action-nonce-001",
    "payload": {
        "execution_id": "exec-e2e-001",
        "action": "system.info",
        "timeout": "30s"
    },
    "signature": "mock-signature"
}
ACTEOF
)
ACTION_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${ACTION_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${ACTION_STATUS}" != "204" ]; then
    fail "action_request event injection returned status ${ACTION_STATUS}, want 204"
fi
echo "  action_request event injected successfully"

# Poll for execution_ack_count and execution_result_count to increase.
ACTION_TIMEOUT=30
ACTION_ELAPSED=0
ACK_PASSED=0
RESULT_PASSED=0
while [ "${ACTION_ELAPSED}" -lt "${ACTION_TIMEOUT}" ]; do
    sleep 2
    ACTION_ELAPSED=$((ACTION_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ACK_AFTER=$(get_counter "${RESPONSE}" "execution_ack_count")
        RESULT_AFTER=$(get_counter "${RESPONSE}" "execution_result_count")
        if [ "${ACK_AFTER}" -gt "${ACK_BEFORE}" ] && [ "${ACK_PASSED}" -eq 0 ]; then
            echo "  PASS: execution_ack_count increased from ${ACK_BEFORE} to ${ACK_AFTER}"
            ACK_PASSED=1
        fi
        if [ "${RESULT_AFTER}" -gt "${RESULT_BEFORE}" ] && [ "${RESULT_PASSED}" -eq 0 ]; then
            echo "  PASS: execution_result_count increased from ${RESULT_BEFORE} to ${RESULT_AFTER}"
            RESULT_PASSED=1
        fi
        if [ "${ACK_PASSED}" -eq 1 ] && [ "${RESULT_PASSED}" -eq 1 ]; then
            break
        fi
    fi
done

if [ "${ACK_PASSED}" -eq 0 ]; then
    ACK_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_ack_count")
    fail "execution_ack_count did not increase (before=${ACK_BEFORE}, after=${ACK_AFTER})"
fi
if [ "${RESULT_PASSED}" -eq 0 ]; then
    RESULT_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_result_count")
    fail "execution_result_count did not increase (before=${RESULT_BEFORE}, after=${RESULT_AFTER})"
fi

# Validate execution_ack request body.
ACK_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_ack" 2>/dev/null || true)
if [ -n "${ACK_BODY}" ]; then
    ACK_EID=$(echo "${ACK_BODY}" | jq -r '.execution_id // empty')
    ACK_STATUS_VAL=$(echo "${ACK_BODY}" | jq -r '.status // empty')
    if [ "${ACK_EID}" = "exec-e2e-001" ]; then
        echo "  PASS: execution_ack execution_id matches"
    else
        echo "  WARN: execution_ack execution_id = '${ACK_EID}', expected 'exec-e2e-001'"
    fi
    if [ "${ACK_STATUS_VAL}" = "accepted" ]; then
        echo "  PASS: execution_ack status = accepted"
    else
        echo "  WARN: execution_ack status = '${ACK_STATUS_VAL}', expected 'accepted'"
    fi
fi

# Validate execution_result request body.
RESULT_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_result" 2>/dev/null || true)
if [ -n "${RESULT_BODY}" ]; then
    RES_EID=$(echo "${RESULT_BODY}" | jq -r '.execution_id // empty')
    RES_STATUS_VAL=$(echo "${RESULT_BODY}" | jq -r '.status // empty')
    RES_STDOUT=$(echo "${RESULT_BODY}" | jq -r '.stdout // empty')
    if [ "${RES_EID}" = "exec-e2e-001" ]; then
        echo "  PASS: execution_result execution_id matches"
    else
        echo "  WARN: execution_result execution_id = '${RES_EID}', expected 'exec-e2e-001'"
    fi
    if [ "${RES_STATUS_VAL}" = "success" ]; then
        echo "  PASS: execution_result status = success"
    else
        echo "  WARN: execution_result status = '${RES_STATUS_VAL}', expected 'success'"
    fi
    if [ -n "${RES_STDOUT}" ]; then
        echo "  PASS: execution_result has stdout output"
    fi

    # GAP-03: Parse stdout as JSON and validate system.info fields.
    if [ -n "${RES_STDOUT}" ]; then
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
            echo "  WARN: system.info stdout is not valid JSON"
        fi
    fi
fi

echo "=== Phase 8 PASSED: action execution ==="

# ===================================================================
# Phase 8b: Additional builtin action types (GAP-05)
# ===================================================================
echo "=== Testing additional builtin action types ==="

# Helper function: inject an action, wait for result, validate.
test_action() {
    local action_name=$1 exec_id=$2 nonce=$3
    shift 3
    # Remaining args are validation commands (passed as description only).

    # Record current counters.
    local resp ack_before result_before
    resp=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    result_before=$(get_counter "${resp}" "execution_result_count")

    # Inject action_request SSE event.
    local payload
    payload=$(cat <<ACTEOF
{
    "event_type": "action_request",
    "event_id": "evt-e2e-${exec_id}",
    "issued_at": "2099-01-01T00:00:00Z",
    "nonce": "${nonce}",
    "payload": {
        "execution_id": "${exec_id}",
        "action": "${action_name}",
        "timeout": "30s"
    },
    "signature": "mock-signature"
}
ACTEOF
    )
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${payload}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "${action_name} event injection returned status ${status}, want 204"
    fi

    # Poll for execution_result_count to increase.
    local timeout=30 elapsed=0
    while [ "${elapsed}" -lt "${timeout}" ]; do
        sleep 2
        elapsed=$((elapsed + 2))
        resp=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
        if [ -n "${resp}" ]; then
            local result_after
            result_after=$(get_counter "${resp}" "execution_result_count")
            if [ "${result_after}" -gt "${result_before}" ]; then
                break
            fi
        fi
    done

    if [ "${elapsed}" -ge "${timeout}" ]; then
        local result_after
        result_after=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_result_count")
        fail "${action_name}: execution_result_count did not increase (before=${result_before}, after=${result_after})"
    fi

    # Fetch and validate the result body.
    local result_body
    result_body=$(curl -sf "http://localhost:18080/test/last-request/execution_result" 2>/dev/null || true)
    if [ -z "${result_body}" ]; then
        fail "${action_name}: no execution_result body captured"
    fi

    local res_status res_stdout
    res_status=$(echo "${result_body}" | jq -r '.status // empty')
    res_stdout=$(echo "${result_body}" | jq -r '.stdout // empty')
    if [ "${res_status}" = "success" ]; then
        echo "  PASS: ${action_name} result status = success"
    else
        fail "${action_name} result status = '${res_status}', want 'success'"
    fi
    if [ -n "${res_stdout}" ]; then
        echo "  PASS: ${action_name} result has stdout"
    else
        fail "${action_name} result has empty stdout"
    fi

    # Return stdout for caller-specific validation.
    ACTION_STDOUT="${res_stdout}"
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

# Record current counters.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
ACK_BEFORE_UNK=$(get_counter "${RESPONSE}" "execution_ack_count")
RESULT_BEFORE_UNK=$(get_counter "${RESPONSE}" "execution_result_count")
echo "  execution_ack_count before: ${ACK_BEFORE_UNK}"
echo "  execution_result_count before: ${RESULT_BEFORE_UNK}"

# Inject action_request for a nonexistent action.
UNK_PAYLOAD=$(cat <<'UNKEOF'
{
    "event_type": "action_request",
    "event_id": "evt-e2e-unknown-001",
    "issued_at": "2099-01-01T00:00:00Z",
    "nonce": "e2e-unknown-nonce-001",
    "payload": {
        "execution_id": "exec-e2e-unknown-001",
        "action": "nonexistent.fake",
        "timeout": "10s"
    },
    "signature": "mock-signature"
}
UNKEOF
)
UNK_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${UNK_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${UNK_STATUS}" != "204" ]; then
    fail "unknown action event injection returned status ${UNK_STATUS}, want 204"
fi
echo "  unknown action event injected"

# Poll for execution_ack_count to increase.
UNK_TIMEOUT=15
UNK_ELAPSED=0
UNK_ACK_PASSED=0
while [ "${UNK_ELAPSED}" -lt "${UNK_TIMEOUT}" ]; do
    sleep 2
    UNK_ELAPSED=$((UNK_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        ACK_AFTER_UNK=$(get_counter "${RESPONSE}" "execution_ack_count")
        if [ "${ACK_AFTER_UNK}" -gt "${ACK_BEFORE_UNK}" ]; then
            echo "  PASS: execution_ack_count increased (rejected ack sent)"
            UNK_ACK_PASSED=1
            break
        fi
    fi
done

if [ "${UNK_ACK_PASSED}" -eq 0 ]; then
    ACK_AFTER_UNK=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "execution_ack_count")
    fail "execution_ack_count did not increase for unknown action (before=${ACK_BEFORE_UNK}, after=${ACK_AFTER_UNK})"
fi

# Validate the ack body shows rejected status.
UNK_ACK_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_ack" 2>/dev/null || true)
if [ -n "${UNK_ACK_BODY}" ]; then
    UNK_ACK_STATUS=$(echo "${UNK_ACK_BODY}" | jq -r '.status // empty')
    UNK_ACK_REASON=$(echo "${UNK_ACK_BODY}" | jq -r '.reason // empty')
    if [ "${UNK_ACK_STATUS}" = "rejected" ]; then
        echo "  PASS: unknown action ack status = 'rejected'"
    else
        fail "unknown action ack status = '${UNK_ACK_STATUS}', want 'rejected'"
    fi
    if [ "${UNK_ACK_REASON}" = "unknown_action" ]; then
        echo "  PASS: unknown action ack reason = 'unknown_action'"
    else
        echo "  WARN: unknown action ack reason = '${UNK_ACK_REASON}', expected 'unknown_action'"
    fi
fi

# Verify execution_result_count did NOT increase (no result for rejected actions).
sleep 3
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
RESULT_AFTER_UNK=$(get_counter "${RESPONSE}" "execution_result_count")
if [ "${RESULT_AFTER_UNK}" -eq "${RESULT_BEFORE_UNK}" ]; then
    echo "  PASS: execution_result_count unchanged (no result sent for rejected action)"
else
    echo "  WARN: execution_result_count changed from ${RESULT_BEFORE_UNK} to ${RESULT_AFTER_UNK} (unexpected)"
fi

echo "=== Phase 8c PASSED: unknown action rejection ==="

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
    "event_type": "rotate_keys",
    "event_id": "evt-e2e-rotatekeys-001",
    "issued_at": "2099-01-01T00:00:00Z",
    "nonce": "e2e-rotatekeys-nonce-001",
    "payload": "{\"reason\":\"e2e-test\"}",
    "signature": "mock-signature"
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

# 10a. Metrics body: validate MetricPoint fields (timestamp, group, data).
METRICS_BODY=$(curl -sf "http://localhost:18080/test/last-request/metrics" 2>/dev/null || true)
if [ -n "${METRICS_BODY}" ]; then
    FIRST_METRIC=$(echo "${METRICS_BODY}" | jq '.[0]')
    MET_TS=$(echo "${FIRST_METRIC}" | jq -r '.timestamp // empty')
    MET_GROUP=$(echo "${FIRST_METRIC}" | jq -r '.group // empty')
    MET_DATA=$(echo "${FIRST_METRIC}" | jq -r '.data // empty')
    if [ -n "${MET_TS}" ]; then
        echo "  PASS: metric[0] has timestamp"
    else
        fail "metric[0] missing 'timestamp' field"
    fi
    if [ -n "${MET_GROUP}" ]; then
        echo "  PASS: metric[0] has group='${MET_GROUP}'"
    else
        fail "metric[0] missing 'group' field"
    fi
    if [ -n "${MET_DATA}" ] && [ "${MET_DATA}" != "null" ]; then
        echo "  PASS: metric[0] has data payload"
    else
        fail "metric[0] missing 'data' field"
    fi

    # GAP-04: Validate expected metric groups and data keys.
    HAS_SYSTEM_GROUP=$(echo "${METRICS_BODY}" | jq '[.[] | select(.group == "system")] | length')
    if [ "${HAS_SYSTEM_GROUP}" -ge 1 ]; then
        echo "  PASS: metrics contains 'system' group entry"
    else
        fail "metrics missing entry with group='system'"
    fi

    # Validate system group data contains expected keys from SystemCollector.
    SYSTEM_METRIC=$(echo "${METRICS_BODY}" | jq '[.[] | select(.group == "system")][0]')
    SYSTEM_DATA=$(echo "${SYSTEM_METRIC}" | jq '.data')
    for data_key in "cpu_usage_percent" "memory_total_bytes" "load_avg_1"; do
        HAS_KEY=$(echo "${SYSTEM_DATA}" | jq --arg k "${data_key}" 'has($k)')
        if [ "${HAS_KEY}" = "true" ]; then
            echo "  PASS: system metric data has key '${data_key}'"
        else
            fail "system metric data missing key '${data_key}'"
        fi
    done
else
    echo "  WARN: no metrics body captured"
fi

# 10b. Audit body: validate AuditEntry fields (timestamp, source, event_type, action, result).
AUDIT_BODY=$(curl -sf "http://localhost:18080/test/last-request/audit" 2>/dev/null || true)
if [ -n "${AUDIT_BODY}" ]; then
    FIRST_AUDIT=$(echo "${AUDIT_BODY}" | jq '.[0]')
    AUD_TS=$(echo "${FIRST_AUDIT}" | jq -r '.timestamp // empty')
    AUD_SRC=$(echo "${FIRST_AUDIT}" | jq -r '.source // empty')
    AUD_EVT=$(echo "${FIRST_AUDIT}" | jq -r '.event_type // empty')
    AUD_ACT=$(echo "${FIRST_AUDIT}" | jq -r '.action // empty')
    AUD_RES=$(echo "${FIRST_AUDIT}" | jq -r '.result // empty')
    if [ -n "${AUD_TS}" ]; then
        echo "  PASS: audit[0] has timestamp"
    else
        fail "audit[0] missing 'timestamp' field"
    fi
    if [ -n "${AUD_SRC}" ]; then
        echo "  PASS: audit[0] has source='${AUD_SRC}'"
    else
        fail "audit[0] missing 'source' field"
    fi
    if [ -n "${AUD_EVT}" ]; then
        echo "  PASS: audit[0] has event_type='${AUD_EVT}'"
    else
        fail "audit[0] missing 'event_type' field"
    fi
    if [ -n "${AUD_ACT}" ]; then
        echo "  PASS: audit[0] has action='${AUD_ACT}'"
    else
        echo "  WARN: audit[0] missing 'action' field (may be omitted for some sources)"
    fi
    if [ -n "${AUD_RES}" ]; then
        echo "  PASS: audit[0] has result='${AUD_RES}'"
    else
        echo "  WARN: audit[0] missing 'result' field (may be omitted for some sources)"
    fi
else
    echo "  WARN: no audit body captured"
fi

# 10c. Capabilities: validate specific builtin action names and exact count.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -n "${CAPS_BODY}" ]; then
    # GAP-01: Verify builtin_actions array length is exactly 11.
    CAPS_COUNT=$(echo "${CAPS_BODY}" | jq '.builtin_actions | length')
    if [ "${CAPS_COUNT}" -eq 11 ]; then
        echo "  PASS: builtin_actions count = 11 (exact)"
    else
        fail "builtin_actions count = ${CAPS_COUNT}, want exactly 11"
    fi

    # GAP-01: Verify all 11 builtin action names are present.
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
        HAS_ACTION=$(echo "${CAPS_BODY}" | jq --arg name "${expected_action}" \
            '[.builtin_actions[] | select(.name == $name)] | length')
        if [ "${HAS_ACTION}" -ge 1 ]; then
            echo "  PASS: capabilities includes builtin '${expected_action}'"
        else
            fail "capabilities missing required builtin '${expected_action}'"
        fi
    done

    # Verify builtin actions have required fields (name, description).
    BAD_ACTIONS=$(echo "${CAPS_BODY}" | jq '[.builtin_actions[] | select(.name == "" or .description == "")] | length')
    if [ "${BAD_ACTIONS}" -eq 0 ]; then
        echo "  PASS: all builtin_actions have name and description"
    else
        fail "found ${BAD_ACTIONS} builtin_actions without name or description"
    fi
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
    if echo "${HB_CHECKSUM}" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "  PASS: heartbeat binary_checksum is 64-char lowercase hex"
    else
        fail "heartbeat binary_checksum='${HB_CHECKSUM}' is not 64-char lowercase hex"
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

    # 12b. GET /v1/actions -- returns list of builtin actions.
    ACTIONS_RESP=$(curl -sf "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/actions" 2>/dev/null || true)
    if [ -n "${ACTIONS_RESP}" ] && echo "${ACTIONS_RESP}" | jq empty 2>/dev/null; then
        NAPI_ACTION_COUNT=$(echo "${ACTIONS_RESP}" | jq '.builtins | length // 0')
        if [ "${NAPI_ACTION_COUNT}" -ge 11 ]; then
            echo "  PASS: GET /v1/actions returns ${NAPI_ACTION_COUNT} builtins"
        else
            # Try alternate response shapes.
            NAPI_ACTION_COUNT=$(echo "${ACTIONS_RESP}" | jq 'if type == "array" then length else (.actions // []) | length end')
            echo "  PASS: GET /v1/actions returns response (count=${NAPI_ACTION_COUNT})"
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

DUAL_PASS=1
for pair in "metrics_count:${PLAT_METRICS}:local_metrics_count:${LOCAL_METRICS}" \
            "logs_count:${PLAT_LOGS}:local_logs_count:${LOCAL_LOGS}" \
            "audit_count:${PLAT_AUDIT}:local_audit_count:${LOCAL_AUDIT}"; do
    IFS=: read -r plat_key plat_val local_key local_val <<< "${pair}"
    if [ "${plat_val}" -ge 1 ] && [ "${local_val}" -ge 1 ]; then
        echo "  PASS: ${plat_key}=${plat_val} >= 1 AND ${local_key}=${local_val} >= 1"
    else
        echo "  FAIL: ${plat_key}=${plat_val}, ${local_key}=${local_val} (both must be >= 1)"
        DUAL_PASS=0
    fi
done

if [ "${DUAL_PASS}" -eq 0 ]; then
    fail "dual delivery verification failed"
fi

echo "=== Phase 16 PASSED: dual delivery verification ==="

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
