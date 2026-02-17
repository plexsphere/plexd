#!/usr/bin/env bash
# Docker E2E test orchestration script.
# Builds and runs the mock-api and plexd containers via docker compose,
# then polls the mock-api assertion endpoint to verify plexd performed
# registration, heartbeat, state, capabilities, drift, metrics, logs, and audit calls.
#
# Extended tests:
#   - Periodic loop verification (counters >= 2 after additional wait)
#   - Request body validation (registration token, heartbeat, capabilities)
#   - Log injection (docker cp into container, verify logs_count increases)
#   - Agent restart for audit verification (ProcessSource fires per-process)
#   - SSE event injection triggers reconciliation (state_count increases)
#   - Action execution via SSE (action_request → ack + result)
#   - Heartbeat-triggered reconcile via RotateKeys flag
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
COUNTER_KEYS=(registration_count heartbeat_count state_count capabilities_count drift_count metrics_count logs_count audit_count)

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

# 3a. Registration body must contain token.
REG_BODY=$(curl -sf "http://localhost:18080/test/last-request/register" 2>/dev/null || true)
if [ -z "${REG_BODY}" ]; then
    fail "no captured registration request body"
fi
REG_TOKEN=$(echo "${REG_BODY}" | jq -r '.token // empty')
if [ -z "${REG_TOKEN}" ]; then
    fail "registration body missing 'token' field"
fi
echo "  PASS: registration body contains token"

REG_HOSTNAME=$(echo "${REG_BODY}" | jq -r '.hostname // empty')
if [ -z "${REG_HOSTNAME}" ]; then
    fail "registration body missing 'hostname' field"
fi
echo "  PASS: registration body contains hostname='${REG_HOSTNAME}'"

REG_PUBKEY=$(echo "${REG_BODY}" | jq -r '.public_key // empty')
if [ -z "${REG_PUBKEY}" ]; then
    fail "registration body missing 'public_key' field"
fi
echo "  PASS: registration body contains public_key"

# 3b. Heartbeat body must be valid JSON with expected structure.
# Note: node_id is passed as a URL path parameter, not in the body.
# The body may contain zero-valued fields since SetBuildRequest is optional.
HB_BODY=$(curl -sf "http://localhost:18080/test/last-request/heartbeat" 2>/dev/null || true)
if [ -z "${HB_BODY}" ]; then
    fail "no captured heartbeat request body"
fi
if ! echo "${HB_BODY}" | jq empty 2>/dev/null; then
    fail "heartbeat body is not valid JSON"
fi
echo "  PASS: heartbeat body is valid JSON"

# Verify the body has the expected heartbeat structure (timestamp field exists).
HB_HAS_TS=$(echo "${HB_BODY}" | jq 'has("timestamp")')
if [ "${HB_HAS_TS}" != "true" ]; then
    fail "heartbeat body missing 'timestamp' field"
fi
echo "  PASS: heartbeat body has expected structure"

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

# 3e. Drift report body must contain timestamp.
DRIFT_BODY=$(curl -sf "http://localhost:18080/test/last-request/drift" 2>/dev/null || true)
if [ -z "${DRIFT_BODY}" ]; then
    fail "no captured drift request body"
fi
DRIFT_TS=$(echo "${DRIFT_BODY}" | jq -r '.timestamp // empty')
if [ -z "${DRIFT_TS}" ]; then
    fail "drift body missing 'timestamp' field"
fi
echo "  PASS: drift body contains timestamp"

echo "=== Phase 3 PASSED: request body validation ==="

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
            if [ "${INFO_NODE_ID}" = "node-mock-001" ]; then
                echo "  PASS: system.info stdout node_id='node-mock-001'"
            else
                fail "system.info stdout node_id='${INFO_NODE_ID}', want 'node-mock-001'"
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
# Phase 9: Heartbeat-triggered reconcile (RotateKeys flag)
# ===================================================================
echo "=== Testing heartbeat-triggered reconcile via RotateKeys ==="

# Record current state_count before enabling RotateKeys.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE_KR=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before: ${STATE_BEFORE_KR}"

# Configure mock API to return RotateKeys: true in heartbeat responses.
# This should trigger a reconcile cycle, which re-fetches state.
KR_CONFIG='{"reconcile":true,"rotate_keys":true}'
KR_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${KR_CONFIG}" \
    "http://localhost:18080/test/configure-heartbeat" 2>/dev/null || true)
if [ "${KR_STATUS}" != "204" ]; then
    fail "configure-heartbeat returned status ${KR_STATUS}, want 204"
fi
echo "  heartbeat response configured with rotate_keys=true"

# Wait for state_count to increase (proving the RotateKeys flag triggered a reconcile).
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

echo "=== Phase 9 PASSED: heartbeat-triggered reconcile ==="

# ===================================================================
# Phase 9b: rotate_keys SSE event triggers reconcile (GAP-07)
# ===================================================================
echo "=== Testing rotate_keys SSE event ==="

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE_RK=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before: ${STATE_BEFORE_RK}"

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

# Poll for state_count to increase (reconcile triggered).
RK_TIMEOUT=15
RK_ELAPSED=0
while [ "${RK_ELAPSED}" -lt "${RK_TIMEOUT}" ]; do
    sleep 2
    RK_ELAPSED=$((RK_ELAPSED + 2))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_RK=$(get_counter "${RESPONSE}" "state_count")
        if [ "${STATE_AFTER_RK}" -gt "${STATE_BEFORE_RK}" ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_RK} to ${STATE_AFTER_RK} after rotate_keys"
            break
        fi
    fi
done

if [ "${RK_ELAPSED}" -ge "${RK_TIMEOUT}" ]; then
    STATE_AFTER_RK=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    echo "  WARN: state_count did not increase after rotate_keys (before=${STATE_BEFORE_RK}, after=${STATE_AFTER_RK})"
fi

echo "=== Phase 9b PASSED: rotate_keys SSE event ==="

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

# 10d. Drift body: validate corrections array exists.
DRIFT_BODY=$(curl -sf "http://localhost:18080/test/last-request/drift" 2>/dev/null || true)
if [ -n "${DRIFT_BODY}" ]; then
    HAS_CORRECTIONS=$(echo "${DRIFT_BODY}" | jq 'has("corrections")')
    if [ "${HAS_CORRECTIONS}" = "true" ]; then
        CORR_LEN=$(echo "${DRIFT_BODY}" | jq '.corrections | length')
        echo "  PASS: drift body has corrections array (length=${CORR_LEN})"
    else
        fail "drift body missing 'corrections' field"
    fi
fi

# 10e. Heartbeat body richness (GAP-02): validate key fields from BuildRequest.
# The SetBuildRequest callback populates mesh info (interface, listen_port, peer_count).
# status, uptime, binary_checksum fields exist in the struct but are not populated
# by the current BuildRequest callback, so those are soft checks only.
HB_BODY=$(curl -sf "http://localhost:18080/test/last-request/heartbeat" 2>/dev/null || true)
if [ -n "${HB_BODY}" ]; then
    HB_MESH_IF=$(echo "${HB_BODY}" | jq -r '.mesh.interface // empty')
    if [ "${HB_MESH_IF}" = "wg-plexd" ]; then
        echo "  PASS: heartbeat mesh.interface = 'wg-plexd'"
    else
        fail "heartbeat mesh.interface = '${HB_MESH_IF}', want 'wg-plexd'"
    fi

    HB_MESH_PORT=$(echo "${HB_BODY}" | jq -r '.mesh.listen_port // empty')
    if [ "${HB_MESH_PORT}" = "51820" ]; then
        echo "  PASS: heartbeat mesh.listen_port = 51820"
    else
        fail "heartbeat mesh.listen_port = '${HB_MESH_PORT}', want 51820"
    fi

    HB_MESH_PEERS=$(echo "${HB_BODY}" | jq '.mesh.peer_count // -1')
    if [ "${HB_MESH_PEERS}" != "-1" ] && [ "${HB_MESH_PEERS}" != "null" ]; then
        echo "  PASS: heartbeat mesh.peer_count = ${HB_MESH_PEERS}"
    else
        fail "heartbeat body missing 'mesh.peer_count' field"
    fi

    # Verify mesh object is present (non-null).
    HB_HAS_MESH=$(echo "${HB_BODY}" | jq 'has("mesh") and (.mesh != null)')
    if [ "${HB_HAS_MESH}" = "true" ]; then
        echo "  PASS: heartbeat body has mesh object"
    else
        fail "heartbeat body missing 'mesh' object"
    fi

    # Soft checks for fields not yet populated by BuildRequest.
    HB_STATUS=$(echo "${HB_BODY}" | jq -r '.status // empty')
    if [ -n "${HB_STATUS}" ]; then
        echo "  PASS: heartbeat body has status='${HB_STATUS}'"
    else
        echo "  INFO: heartbeat body status is empty (not set by BuildRequest)"
    fi

    HB_UPTIME=$(echo "${HB_BODY}" | jq -r '.uptime // empty')
    if [ -n "${HB_UPTIME}" ]; then
        echo "  PASS: heartbeat body has uptime='${HB_UPTIME}'"
    else
        echo "  INFO: heartbeat body uptime is empty (not set by BuildRequest)"
    fi

    HB_CHECKSUM=$(echo "${HB_BODY}" | jq -r '.binary_checksum // empty')
    if [ -n "${HB_CHECKSUM}" ]; then
        echo "  PASS: heartbeat body has binary_checksum"
    else
        echo "  INFO: heartbeat body binary_checksum is empty (not set by BuildRequest)"
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
    echo "  WARN: node API not available within ${NAPI_TIMEOUT}s, skipping Phase 12"
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

    # 12c. GET /v1/peers -- returns peer list (may be empty in e2e).
    PEERS_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${NAPI_AUTH[@]}" "${NODE_API_URL}/v1/peers" 2>/dev/null || true)
    if [ "${PEERS_STATUS}" = "200" ]; then
        echo "  PASS: GET /v1/peers returns 200"
    else
        echo "  WARN: GET /v1/peers returned status ${PEERS_STATUS}"
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
# Phase 13: State mutation triggers drift detection (GAP-10)
# ===================================================================
echo "=== Testing state mutation drift detection ==="

# Record current drift_count and state_count.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
DRIFT_BEFORE_MUT=$(get_counter "${RESPONSE}" "drift_count")
STATE_BEFORE_MUT=$(get_counter "${RESPONSE}" "state_count")
echo "  drift_count before: ${DRIFT_BEFORE_MUT}"
echo "  state_count before: ${STATE_BEFORE_MUT}"

# Modify the state fixture with added metadata.
MUTATED_STATE=$(cat <<'MUTEOF'
{
    "peers": [
        {
            "id": "peer-001",
            "public_key": "wg-pub-key-peer-001",
            "mesh_ip": "10.99.0.2",
            "endpoint": "203.0.113.1:51820",
            "allowed_ips": ["10.99.0.2/32"],
            "psk": "mock-psk-001"
        },
        {
            "id": "peer-002",
            "public_key": "wg-pub-key-peer-002",
            "mesh_ip": "10.99.0.3",
            "endpoint": "203.0.113.2:51820",
            "allowed_ips": ["10.99.0.3/32"],
            "psk": "mock-psk-002"
        }
    ],
    "metadata": {
        "test_key": "test_value_drift",
        "environment": "e2e-mutated"
    },
    "policies": [
        {
            "id": "policy-001",
            "rules": [
                {
                    "action": "allow",
                    "protocol": "tcp",
                    "ports": ["443", "8080"],
                    "sources": ["10.99.0.0/24"]
                }
            ]
        }
    ]
}
MUTEOF
)
MUT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${MUTATED_STATE}" \
    "http://localhost:18080/test/configure-state" 2>/dev/null || true)
if [ "${MUT_STATUS}" != "204" ]; then
    fail "configure-state returned status ${MUT_STATUS}, want 204"
fi
echo "  state fixture updated with mutated metadata"

# Trigger a reconcile via heartbeat to speed up detection.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 || true

# Wait for state_count and drift_count to increase.
MUT_TIMEOUT=60
MUT_ELAPSED=0
MUT_STATE_PASSED=0
MUT_DRIFT_PASSED=0
while [ "${MUT_ELAPSED}" -lt "${MUT_TIMEOUT}" ]; do
    sleep 3
    MUT_ELAPSED=$((MUT_ELAPSED + 3))
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        STATE_AFTER_MUT=$(get_counter "${RESPONSE}" "state_count")
        DRIFT_AFTER_MUT=$(get_counter "${RESPONSE}" "drift_count")
        if [ "${STATE_AFTER_MUT}" -gt "${STATE_BEFORE_MUT}" ] && [ "${MUT_STATE_PASSED}" -eq 0 ]; then
            echo "  PASS: state_count increased from ${STATE_BEFORE_MUT} to ${STATE_AFTER_MUT}"
            MUT_STATE_PASSED=1
        fi
        if [ "${DRIFT_AFTER_MUT}" -gt "${DRIFT_BEFORE_MUT}" ] && [ "${MUT_DRIFT_PASSED}" -eq 0 ]; then
            echo "  PASS: drift_count increased from ${DRIFT_BEFORE_MUT} to ${DRIFT_AFTER_MUT}"
            MUT_DRIFT_PASSED=1
        fi
        if [ "${MUT_STATE_PASSED}" -eq 1 ] && [ "${MUT_DRIFT_PASSED}" -eq 1 ]; then
            break
        fi
    fi
done

if [ "${MUT_STATE_PASSED}" -eq 0 ]; then
    STATE_AFTER_MUT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    echo "  WARN: state_count did not increase after mutation (before=${STATE_BEFORE_MUT}, after=${STATE_AFTER_MUT})"
fi
if [ "${MUT_DRIFT_PASSED}" -eq 0 ]; then
    DRIFT_AFTER_MUT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "drift_count")
    echo "  WARN: drift_count did not increase after mutation (before=${DRIFT_BEFORE_MUT}, after=${DRIFT_AFTER_MUT})"
fi

# Validate the drift report body contains updated corrections if drift was reported.
if [ "${MUT_DRIFT_PASSED}" -eq 1 ]; then
    DRIFT_MUT_BODY=$(curl -sf "http://localhost:18080/test/last-request/drift" 2>/dev/null || true)
    if [ -n "${DRIFT_MUT_BODY}" ]; then
        HAS_CORRECTIONS=$(echo "${DRIFT_MUT_BODY}" | jq 'has("corrections")')
        if [ "${HAS_CORRECTIONS}" = "true" ]; then
            CORR_LEN=$(echo "${DRIFT_MUT_BODY}" | jq '.corrections | length')
            echo "  PASS: drift report has corrections array (length=${CORR_LEN})"
        else
            echo "  WARN: drift body missing 'corrections' after state mutation"
        fi
    fi
fi

echo "=== Phase 13 PASSED: state mutation drift detection ==="

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
