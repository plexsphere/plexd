#!/usr/bin/env bash
# Docker E2E test orchestration script.
# Builds and runs the mock-api and plexd containers via docker compose,
# then polls the mock-api assertion endpoint to verify plexd performed
# registration, heartbeat, state, capabilities, drift, metrics, logs, and audit calls.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/../docker-compose.yml"
PROJECT_NAME="plexd-e2e"

dc() { docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" "$@"; }

# Counter JSON keys (shared across extraction, checking, and reporting).
COUNTER_KEYS=(registration_count heartbeat_count state_count capabilities_count drift_count metrics_count logs_count audit_count)

# Extract all counter values from a JSON response into COUNTER_VALUES.
extract_counters() {
    local response=$1
    COUNTER_VALUES=()
    for key in "${COUNTER_KEYS[@]}"; do
        COUNTER_VALUES+=("$(echo "${response}" | jq -r ".${key} // 0")")
    done
}

# Check whether all counters meet their minimum (>= 1). Returns 0 if all pass.
all_counters_pass() {
    for val in "${COUNTER_VALUES[@]}"; do
        [ "${val}" -ge 1 ] || return 1
    done
}

# Print each counter with PASS/FAIL prefix based on threshold.
print_counter_results() {
    local prefix=$1
    for i in "${!COUNTER_KEYS[@]}"; do
        local val="${COUNTER_VALUES[$i]}"
        if [ "${val}" -ge 1 ]; then
            echo "  PASS: ${COUNTER_KEYS[$i]}=${val} >= 1"
        else
            echo "  ${prefix}: ${COUNTER_KEYS[$i]}=${val} < 1"
        fi
    done
}

cleanup() {
    echo "--- Cleaning up docker compose resources ---"
    dc down -v 2>/dev/null || true
}
trap cleanup EXIT

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
    echo "FAIL: mock-api did not become healthy within ${HEALTH_TIMEOUT}s"
    dc logs
    exit 1
fi

echo "=== Polling assertion endpoint ==="
ASSERT_URL="http://localhost:18080/test/assertions"
POLL_TIMEOUT=30
POLL_ELAPSED=0

while [ "${POLL_ELAPSED}" -lt "${POLL_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        extract_counters "${RESPONSE}"
        if all_counters_pass; then
            echo "=== SUCCESS ==="
            print_counter_results "FAIL"
            exit 0
        fi
    fi
    sleep 2
    POLL_ELAPSED=$((POLL_ELAPSED + 2))
done

echo "=== FAIL: assertions not met within ${POLL_TIMEOUT}s ==="
if [ -z "${RESPONSE}" ]; then
    echo "FAIL: no response from assertion endpoint"
else
    extract_counters "${RESPONSE}"
    print_counter_results "FAIL"
fi
echo "--- Container logs ---"
dc logs
exit 1
