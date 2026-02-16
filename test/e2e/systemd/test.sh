#!/usr/bin/env bash
# Systemd E2E test orchestration script.
# Builds and runs an Ubuntu-based systemd container alongside the mock-api,
# installs plexd via the install script, enables and starts the systemd
# service, then polls the mock-api assertion endpoint to verify plexd
# performed registration and heartbeat calls. Finally, validates clean
# shutdown via systemctl stop.
#
# Extended tests:
#   - Request body validation (registration token, heartbeat, capabilities)
#   - Periodic loop verification (heartbeat/metrics/logs counters >= 2)
#   - Audit forwarding via service restart (ProcessSource fires per-process)
#   - Shutdown log message verification
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
            echo "  ${prefix}: ${COUNTER_KEYS[$i]}=${val} (want >= ${min})"
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
  base_url: http://${MOCKAPI_CONTAINER}:8080

registration:
  data_dir: /var/lib/plexd

node_api:
  data_dir: /var/lib/plexd

heartbeat:
  node_id: e2e-systemd-node

metrics:
  enabled: true
  collect_interval: 5s
  report_interval: 10s

log_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  file_patterns:
    - \"/var/log/plexd/*.log\"

audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
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
        print_counter_results "FAIL" 1
    fi
    fail "assertions not met within ${TIMEOUT}s"
fi

# --- Request body validation ---
echo "=== Validating request bodies ==="

# Registration body must contain token and hostname.
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

# Heartbeat body must be valid JSON with expected structure.
# Note: node_id is passed as a URL path parameter, not in the body.
HB_BODY=$(curl -sf "http://localhost:18080/test/last-request/heartbeat" 2>/dev/null || true)
if [ -z "${HB_BODY}" ]; then
    fail "no captured heartbeat request body"
fi
if ! echo "${HB_BODY}" | jq empty 2>/dev/null; then
    fail "heartbeat body is not valid JSON"
fi
echo "  PASS: heartbeat body is valid JSON"
HB_HAS_TS=$(echo "${HB_BODY}" | jq 'has("timestamp")')
if [ "${HB_HAS_TS}" != "true" ]; then
    fail "heartbeat body missing 'timestamp' field"
fi
echo "  PASS: heartbeat body has expected structure"

# Capabilities body must contain builtin_actions array.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -z "${CAPS_BODY}" ]; then
    fail "no captured capabilities request body"
fi
CAPS_COUNT=$(echo "${CAPS_BODY}" | jq '.builtin_actions | length')
if [ "${CAPS_COUNT}" -lt 1 ]; then
    fail "capabilities body has empty builtin_actions (want >= 1)"
fi
echo "  PASS: capabilities body contains ${CAPS_COUNT} builtin_actions"

echo "=== Request body validation PASSED ==="

# --- Periodic loop verification (counters >= 2) ---
echo "=== Waiting for periodic counters to increment (>= 2) ==="
# heartbeat and metrics are self-generating; logs works via journald in systemd containers.
# audit uses ProcessSource (sync.Once) so it stays at 1 — tested separately via restart below.
PERIODIC_KEYS=(heartbeat_count metrics_count logs_count)
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
            echo "=== Periodic counters PASSED (>= 2) ==="
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

# --- Audit forwarding via service restart ---
echo "=== Testing audit forwarding via service restart ==="
# ProcessSource fires exactly once per process lifetime (sync.Once).
# Restarting the service creates a new process with a fresh ProcessSource.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
AUDIT_BEFORE=$(get_counter "${RESPONSE}" "audit_count")
echo "  audit_count before restart: ${AUDIT_BEFORE}"

docker exec "${SYSTEMD_CONTAINER}" systemctl restart plexd

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

echo "=== Audit forwarding via restart PASSED ==="

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

# Verify plexd logged the shutdown message.
if echo "${CRASH_OUTPUT}" | grep -q "plexd stopped\|shutting down"; then
    echo "  PASS: plexd logged shutdown message"
else
    echo "  WARN: no explicit shutdown message found in journalctl"
fi

TEST_FAILED=0
echo "=== ALL TESTS PASSED ==="
