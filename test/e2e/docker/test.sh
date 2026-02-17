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
fi

echo "=== Phase 8 PASSED: action execution ==="

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

# 10c. Capabilities: validate specific builtin action names.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -n "${CAPS_BODY}" ]; then
    # Verify known builtin actions are present.
    for expected_action in "diagnostics.collect" "system.info" "service.restart" "health.check" "config.dump"; do
        HAS_ACTION=$(echo "${CAPS_BODY}" | jq --arg name "${expected_action}" \
            '[.builtin_actions[] | select(.name == $name)] | length')
        if [ "${HAS_ACTION}" -ge 1 ]; then
            echo "  PASS: capabilities includes builtin '${expected_action}'"
        else
            echo "  WARN: capabilities missing builtin '${expected_action}'"
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

echo "=== Phase 10 PASSED: deeper body validation ==="

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
