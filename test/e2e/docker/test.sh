#!/usr/bin/env bash
# Docker E2E test orchestration script.
# Builds and runs the mock-api and plexd containers via docker compose,
# then polls the mock-api assertion endpoint to verify plexd performed
# registration, heartbeat, and metadata calls.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/../docker-compose.yml"
PROJECT_NAME="plexd-e2e"

dc() { docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" "$@"; }

check_assertion() {
    local label=$1 actual=$2 min=$3
    if [ "${actual}" -ge "${min}" ]; then
        echo "  PASS: ${label}=${actual} >= ${min}"
    else
        echo "  FAIL: ${label}=${actual} < ${min}"
    fi
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
        REG_COUNT=$(echo "${RESPONSE}" | jq -r '.registration_count // 0')
        HB_COUNT=$(echo "${RESPONSE}" | jq -r '.heartbeat_count // 0')
        STATE_COUNT=$(echo "${RESPONSE}" | jq -r '.state_count // 0')

        if [ "${REG_COUNT}" -ge 1 ] && [ "${HB_COUNT}" -ge 1 ] && [ "${STATE_COUNT}" -ge 1 ]; then
            echo "=== SUCCESS ==="
            echo "  registration_count: ${REG_COUNT}"
            echo "  heartbeat_count:    ${HB_COUNT}"
            echo "  state_count:        ${STATE_COUNT}"
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
    REG_COUNT=$(echo "${RESPONSE}" | jq -r '.registration_count // 0')
    HB_COUNT=$(echo "${RESPONSE}" | jq -r '.heartbeat_count // 0')
    STATE_COUNT=$(echo "${RESPONSE}" | jq -r '.state_count // 0')
    check_assertion "registration_count" "${REG_COUNT}" 1
    check_assertion "heartbeat_count" "${HB_COUNT}" 1
    check_assertion "state_count" "${STATE_COUNT}" 1
fi
echo "--- Container logs ---"
dc logs
exit 1
