#!/usr/bin/env bash
# Systemd E2E test orchestration script.
# Builds and runs an Ubuntu-based systemd container alongside the mock-api,
# installs plexd via the install script, enables and starts the systemd
# service, then polls the mock-api assertion endpoint to verify plexd
# performed registration and heartbeat calls. Finally, validates clean
# shutdown via systemctl stop.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
NETWORK_NAME="plexd-systemd-e2e"
MOCKAPI_CONTAINER="plexd-e2e-mockapi"
SYSTEMD_CONTAINER="plexd-e2e-systemd"
MOCKAPI_IMAGE="mockapi:e2e-systemd"
SYSTEMD_IMAGE="plexd-systemd:e2e"
TIMEOUT="${TIMEOUT:-60}"
TEST_FAILED=1

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
            echo "  ${prefix}: ${COUNTER_KEYS[$i]}=${val} (want >= 1)"
        fi
    done
}

# --- Diagnostics function (REQ-008) ---
print_diagnostics() {
    echo "--- Diagnostics ---"
    echo "==> Network inspect:"
    docker network inspect "${NETWORK_NAME}" 2>/dev/null || true
    echo "==> Mock-API container logs:"
    docker logs "${MOCKAPI_CONTAINER}" 2>/dev/null || true
    echo "==> Systemd container systemctl status:"
    docker exec "${SYSTEMD_CONTAINER}" systemctl status plexd --no-pager 2>/dev/null || true
    echo "==> Systemd container journalctl plexd:"
    docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager -n 100 2>/dev/null || true
    echo "==> Systemd container journalctl (full):"
    docker exec "${SYSTEMD_CONTAINER}" journalctl --no-pager -n 50 2>/dev/null || true
    echo "==> Systemd container process list:"
    docker exec "${SYSTEMD_CONTAINER}" ps aux 2>/dev/null || true
    echo "==> Systemd container /etc/plexd/:"
    docker exec "${SYSTEMD_CONTAINER}" ls -la /etc/plexd/ 2>/dev/null || true
    echo "==> Systemd container /usr/local/bin/plexd:"
    docker exec "${SYSTEMD_CONTAINER}" ls -la /usr/local/bin/plexd 2>/dev/null || true
    echo "--- End diagnostics ---"
}

# --- Helper: print message, dump diagnostics, and exit 1 ---
fail() {
    echo "FAIL: $1"
    print_diagnostics
    exit 1
}

# --- Cleanup trap (REQ-002, REQ-006) ---
cleanup() {
    echo "--- Cleaning up ---"
    if [ "${TEST_FAILED}" -ne 0 ]; then
        print_diagnostics
    fi
    docker rm -f "${MOCKAPI_CONTAINER}" 2>/dev/null || true
    docker rm -f "${SYSTEMD_CONTAINER}" 2>/dev/null || true
    docker network rm "${NETWORK_NAME}" 2>/dev/null || true
    rm -f "${REPO_ROOT}/plexd-linux-amd64"
}
trap cleanup EXIT

# --- Pre-flight checks ---
for cmd in docker curl jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "FAIL: required command '${cmd}' not found"
        exit 1
    fi
done

# --- Pre-cleanup for idempotency (handles SIGKILL from previous run) ---
echo "=== Removing pre-existing containers and network (if any) ==="
docker rm -f "${MOCKAPI_CONTAINER}" 2>/dev/null || true
docker rm -f "${SYSTEMD_CONTAINER}" 2>/dev/null || true
docker network rm "${NETWORK_NAME}" 2>/dev/null || true

# --- Build images (REQ-001) ---
echo "=== Building mock-api image ==="
docker build -f "${REPO_ROOT}/test/e2e/mockapi/Dockerfile" -t "${MOCKAPI_IMAGE}" "${REPO_ROOT}"

echo "=== Building systemd container image ==="
docker build -f "${SCRIPT_DIR}/Dockerfile" -t "${SYSTEMD_IMAGE}" "${SCRIPT_DIR}"

echo "=== Building plexd binary ==="
GO_VERSION=$(sed -n 's/^go \(.*\)/\1/p' "${REPO_ROOT}/go.mod")
docker run --rm \
    -v "${REPO_ROOT}:/build" \
    -w /build \
    "golang:${GO_VERSION}-alpine" \
    sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o /build/plexd-linux-amd64 ./cmd/plexd'

# --- Create network (REQ-002) ---
echo "=== Creating Docker network ==="
docker network create "${NETWORK_NAME}"

# --- Start mock-api container (REQ-004) ---
echo "=== Starting mock-api container ==="
docker run -d \
    --name "${MOCKAPI_CONTAINER}" \
    --network "${NETWORK_NAME}" \
    -p 18080:8080 \
    "${MOCKAPI_IMAGE}" \
    -addr :8080

# Wait for mock-api to be ready (probe via published port).
echo "=== Waiting for mock-api readiness ==="
HEALTH_TIMEOUT=30
HEALTH_ELAPSED=0
while [ "${HEALTH_ELAPSED}" -lt "${HEALTH_TIMEOUT}" ]; do
    if curl -sf "http://localhost:18080/v1/ping" >/dev/null 2>&1; then
        echo "mock-api is ready"
        break
    fi
    sleep 2
    HEALTH_ELAPSED=$((HEALTH_ELAPSED + 2))
done

if [ "${HEALTH_ELAPSED}" -ge "${HEALTH_TIMEOUT}" ]; then
    fail "mock-api did not become ready within ${HEALTH_TIMEOUT}s"
fi

# --- Start systemd container and install plexd (REQ-002, REQ-003, REQ-007) ---
echo "=== Starting systemd container ==="
docker run -d \
    --name "${SYSTEMD_CONTAINER}" \
    --network "${NETWORK_NAME}" \
    --privileged \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "${REPO_ROOT}/plexd-linux-amd64:/opt/plexd-binary:ro" \
    -v "${REPO_ROOT}/deploy/systemd/plexd.service:/opt/plexd.service:ro" \
    "${SYSTEMD_IMAGE}"

# Wait for systemd to finish booting inside the container.
echo "=== Waiting for systemd to boot ==="
BOOT_TIMEOUT=30
BOOT_ELAPSED=0
while [ "${BOOT_ELAPSED}" -lt "${BOOT_TIMEOUT}" ]; do
    if docker exec "${SYSTEMD_CONTAINER}" systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"; then
        echo "systemd is running"
        break
    fi
    sleep 2
    BOOT_ELAPSED=$((BOOT_ELAPSED + 2))
done

if [ "${BOOT_ELAPSED}" -ge "${BOOT_TIMEOUT}" ]; then
    fail "systemd did not boot within ${BOOT_TIMEOUT}s"
fi

# Install plexd binary and service unit (REQ-003, REQ-007).
echo "=== Installing plexd into systemd container ==="
docker exec "${SYSTEMD_CONTAINER}" bash -c \
    'cp /opt/plexd-binary /usr/local/bin/plexd && chmod +x /usr/local/bin/plexd && cp /opt/plexd.service /etc/systemd/system/plexd.service'

# Write plexd config pointing at mock-api (REQ-004).
docker exec "${SYSTEMD_CONTAINER}" bash -c "cat > /etc/plexd/config.yaml <<EOF
api:
  baseurl: http://${MOCKAPI_CONTAINER}:8080

registration:
  datadir: /var/lib/plexd

node_api:
  datadir: /var/lib/plexd

heartbeat:
  nodeid: e2e-systemd-node
EOF"

# Write environment file with bootstrap token.
docker exec "${SYSTEMD_CONTAINER}" bash -c 'echo "PLEXD_BOOTSTRAP_TOKEN=e2e-test-token" > /etc/plexd/environment && chmod 600 /etc/plexd/environment'

# Pre-create hooks directory (ProtectSystem=full makes /etc read-only for the service).
docker exec "${SYSTEMD_CONTAINER}" mkdir -p /etc/plexd/hooks

# --- Start service and poll assertions (REQ-003, REQ-004) ---
echo "=== Enabling and starting plexd service ==="
docker exec "${SYSTEMD_CONTAINER}" systemctl daemon-reload
docker exec "${SYSTEMD_CONTAINER}" systemctl enable --now plexd

# Give the service a moment to start.
sleep 3

echo "=== Verifying plexd service is active ==="
if ! docker exec "${SYSTEMD_CONTAINER}" systemctl is-active plexd; then
    fail "plexd service is not active"
fi

# Poll mock-api assertion endpoint (REQ-004).
echo "=== Polling assertion endpoint ==="
ASSERT_URL="http://localhost:18080/test/assertions"
POLL_ELAPSED=0

while [ "${POLL_ELAPSED}" -lt "${TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        extract_counters "${RESPONSE}"
        if all_counters_pass; then
            echo "=== Assertions passed ==="
            print_counter_results "FAIL"
            break
        fi
    fi
    sleep 3
    POLL_ELAPSED=$((POLL_ELAPSED + 3))
done

if [ "${POLL_ELAPSED}" -ge "${TIMEOUT}" ]; then
    echo "=== FAIL: assertions not met within ${TIMEOUT}s ==="
    if [ -z "${RESPONSE:-}" ]; then
        echo "  no response from assertion endpoint"
    else
        extract_counters "${RESPONSE}"
        print_counter_results "FAIL"
    fi
    fail "assertions not met within ${TIMEOUT}s"
fi

# --- Clean shutdown verification (REQ-005) ---
echo "=== Stopping plexd service ==="
docker exec "${SYSTEMD_CONTAINER}" systemctl stop plexd

echo "=== Verifying clean shutdown ==="
EXIT_CODE=$(docker exec "${SYSTEMD_CONTAINER}" bash -c 'systemctl show plexd -p ExecMainStatus --value')
SERVICE_STATE=$(docker exec "${SYSTEMD_CONTAINER}" systemctl is-active plexd 2>/dev/null || true)

if [ "${SERVICE_STATE}" = "inactive" ]; then
    echo "  PASS: service state is inactive"
else
    fail "service state is '${SERVICE_STATE}', expected 'inactive'"
fi

if [ "${EXIT_CODE}" = "0" ]; then
    echo "  PASS: exit code is 0 (clean shutdown)"
else
    echo "  WARN: exit code is ${EXIT_CODE} (non-zero, may indicate unclean shutdown)"
fi

# Check journalctl for crash indicators (REQ-005, task 1.6).
echo "=== Checking for crash indicators in journalctl ==="
CRASH_OUTPUT=$(docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager 2>/dev/null || true)
CRASH_FOUND=0
for indicator in "core dumped" "segfault" "SIGABRT" "SIGKILL"; do
    if echo "${CRASH_OUTPUT}" | grep -qi "${indicator}"; then
        echo "  FAIL: crash indicator '${indicator}' found in journalctl"
        CRASH_FOUND=1
    fi
done

if [ "${CRASH_FOUND}" -ne 0 ]; then
    echo "--- journalctl output ---"
    echo "${CRASH_OUTPUT}"
    echo "--- end journalctl output ---"
    fail "crash indicators found in journalctl"
fi
echo "  PASS: no crash indicators found"

TEST_FAILED=0
echo "=== ALL TESTS PASSED ==="
