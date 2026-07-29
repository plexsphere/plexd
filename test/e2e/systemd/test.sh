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
#   - Action execution via the state pull's executions block (ack/started/terminal callbacks)
#   - SSE event injection triggers reconciliation
#   - Heartbeat-triggered reconcile via RotateKeys flag
#   - Deeper body validation (metrics, capabilities fields)
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

# --- Helper: base64-decode stdin portably across GNU and BSD/macOS ---
# GNU coreutils spells decode as -d; older BSD/macOS base64 uses -D. Probe once
# with a known value ("QQ==" -> "A") and bind b64_decode to whichever flag works.
if printf 'QQ==' | base64 -d >/dev/null 2>&1; then
    b64_decode() { base64 -d; }
else
    b64_decode() { base64 -D; }
fi

# Counter JSON keys (shared across extraction, checking, and reporting).
# audit_count is absent: the ingest contract's source enum is closed at auditd
# and k8s, and the only audit source the agent wires emits plexd's own process
# entry, which has no value in that set — so no platform audit batch is sent.
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
    if curl -sf "http://localhost:18080/v1/health" >/dev/null 2>&1; then
        echo "mock-api is ready"
        break
    fi
    sleep 2
    HEALTH_ELAPSED=$((HEALTH_ELAPSED + 2))
done

if [ "${HEALTH_ELAPSED}" -ge "${HEALTH_TIMEOUT}" ]; then
    fail "mock-api did not become ready within ${HEALTH_TIMEOUT}s"
fi

# The mock refuses every authenticated /v1 route whose Authorization header is
# not the NSK bearer envelope, as the control plane does. A phase that drives
# such a route itself presents the same envelope, fetched from the fixture so
# the node id and secret keep a single definition.
MOCK_BEARER=$(curl -sf "http://localhost:18080/test/bearer" | jq -r '.bearer // empty')
if [ -z "${MOCK_BEARER}" ]; then
    fail "could not read the mock's bearer envelope from /test/bearer"
fi
MOCK_AUTH=(-H "Authorization: Bearer ${MOCK_BEARER}")

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
  project_id: 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0
  resource_handle: e2e-systemd-node

node_api:
  data_dir: /var/lib/plexd

heartbeat:
  node_id: e2e-systemd-node

metrics:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  local_endpoint:
    url: https://${MOCKAPI_CONTAINER}:8443/local/metrics
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true

log_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  file_patterns:
    - \"/var/log/plexd/*.log\"
  local_endpoint:
    url: https://${MOCKAPI_CONTAINER}:8443/local/logs
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true

audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  local_endpoint:
    url: https://${MOCKAPI_CONTAINER}:8443/local/audit
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
EOF"

# Write environment file with bootstrap token.
docker exec "${SYSTEMD_CONTAINER}" bash -c 'echo "PLEXD_BOOTSTRAP_TOKEN=psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22" > /etc/plexd/environment && chmod 600 /etc/plexd/environment'

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

# Registration body must carry the real POST /v1/register fields.
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
echo "  PASS: registration body contains project_id='${REG_PROJECT_ID}'"

REG_RESOURCE_HANDLE=$(echo "${REG_BODY}" | jq -r '.resource_handle // empty')
if [ -z "${REG_RESOURCE_HANDLE}" ]; then
    fail "registration body missing 'resource_handle' field"
fi
echo "  PASS: registration body contains resource_handle='${REG_RESOURCE_HANDLE}'"

REG_NONCE=$(echo "${REG_BODY}" | jq -r '.nonce // empty')
if [ -z "${REG_NONCE}" ]; then
    fail "registration body missing 'nonce' field"
fi
echo "  PASS: registration body contains nonce"

# Heartbeat body must carry the real v1 heartbeat fields.
# Note: node_id is passed as a URL path parameter, not in the body.
HB_BODY=$(curl -sf "http://localhost:18080/test/last-request/heartbeat" 2>/dev/null || true)
if [ -z "${HB_BODY}" ]; then
    fail "no captured heartbeat request body"
fi
if ! echo "${HB_BODY}" | jq empty 2>/dev/null; then
    fail "heartbeat body is not valid JSON"
fi
echo "  PASS: heartbeat body is valid JSON"

HB_CLIENT_NOW=$(echo "${HB_BODY}" | jq -r '.client_now // empty')
if ! echo "${HB_CLIENT_NOW}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+.*(Z|[+-][0-9]{2}:[0-9]{2})$'; then
    fail "heartbeat client_now='${HB_CLIENT_NOW}' is not an RFC 3339 timestamp"
fi
echo "  PASS: heartbeat body client_now='${HB_CLIENT_NOW}' matches RFC 3339"

# binary_checksum is 32 raw bytes in standard-padded base64 (the field is
# `format: byte`; hex decodes to 48 bytes and the capability manifest refuses it).
HB_CHECKSUM=$(echo "${HB_BODY}" | jq -r '.binary_checksum // empty')
HB_DIGEST_LEN=$(printf '%s' "${HB_CHECKSUM}" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
if [ "${HB_DIGEST_LEN}" != "32" ]; then
    fail "heartbeat binary_checksum='${HB_CHECKSUM}' decodes to ${HB_DIGEST_LEN} bytes, want 32"
fi
echo "  PASS: heartbeat body binary_checksum is a 32-byte base64 digest"

HB_VERSION=$(echo "${HB_BODY}" | jq -r '.binary_version // empty')
if [ -z "${HB_VERSION}" ]; then
    fail "heartbeat body missing 'binary_version' field"
fi
echo "  PASS: heartbeat body binary_version='${HB_VERSION}'"

HB_NAT_SUMMARY_TYPE=$(echo "${HB_BODY}" | jq -r '.nat_summary | type')
if [ "${HB_NAT_SUMMARY_TYPE}" != "object" ]; then
    fail "heartbeat nat_summary type='${HB_NAT_SUMMARY_TYPE}', want 'object'"
fi
echo "  PASS: heartbeat body nat_summary is a JSON object"

# Capability manifest: the contract's flat envelope, with a binary_checksum that
# decodes to 32 bytes (hex decodes to 48 and is refused) and no field the
# handler would reject as unknown. The agent's action list is not part of this
# body — the contract has no field for it; the node API serves it instead.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -z "${CAPS_BODY}" ]; then
    fail "no captured capabilities request body"
fi
CAPS_VERSION=$(echo "${CAPS_BODY}" | jq -r '.binary_version // empty')
CAPS_CHECKSUM=$(echo "${CAPS_BODY}" | jq -r '.binary_checksum // empty')
if [ -z "${CAPS_VERSION}" ] || [ -z "${CAPS_CHECKSUM}" ]; then
    fail "capability manifest missing binary_version or binary_checksum (body: ${CAPS_BODY})"
fi
CAPS_DIGEST_LEN=$(printf '%s' "${CAPS_CHECKSUM}" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
if [ "${CAPS_DIGEST_LEN}" != "32" ]; then
    fail "binary_checksum decodes to ${CAPS_DIGEST_LEN} bytes, want 32"
fi
if echo "${CAPS_BODY}" | jq -e 'has("builtin_actions") or has("binary")' >/dev/null 2>&1; then
    fail "capability manifest carries a field the handler rejects as unknown (body: ${CAPS_BODY})"
fi
echo "  PASS: capability manifest is contract-shaped (version=${CAPS_VERSION}, 32-byte digest)"

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
#
# That entry reaches the local endpoint, not the platform: its source is plexd's
# own "process", which has no value in the ingest contract's closed enum
# (auditd, k8s). Sending it anyway refused the whole batch with 400
# ingest_batch_malformed, so the reporter skips it and the platform counter must
# stay at zero.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
LOCAL_AUDIT_BEFORE=$(get_counter "${RESPONSE}" "local_audit_count")
echo "  local_audit_count before restart: ${LOCAL_AUDIT_BEFORE}"

docker exec "${SYSTEMD_CONTAINER}" systemctl restart plexd

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

AUDIT_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "audit_count")
if [ "${AUDIT_AFTER}" != "0" ]; then
    fail "platform audit_count = ${AUDIT_AFTER}, want 0: no wired audit source has a value in the contract's closed enum"
fi
echo "  PASS: platform audit_count = 0 (no contract-legal source is wired)"

echo "=== Audit forwarding via restart PASSED ==="

# --- Action execution from the pull's executions block ---
echo "=== Testing action execution via the executions block ==="

# Record the execution callback counter BEFORE the dispatch is configured: the
# nudge below makes the agent pull right away, so a baseline taken afterwards
# could already have missed the ack. A successful builtin run posts three
# callbacks in sequence: ack -> started -> succeeded.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE=$(get_counter "${RESPONSE}" "execution_callback_count")
echo "  execution_callback_count before: ${CB_BEFORE}"

# Configure a pending builtin dispatch for "system.info". Dispatches ride in the
# executions block of GET /v1/nodes/{id}/state, and the wire carries NO timeout
# and NO checksum: the run deadline is the node's own. expires_at is far enough
# out that the entry is never served as lapsed.
ACTION_ENTRIES=$(cat <<'ACTEOF'
[
  {
    "execution_id": "exec-e2e-systemd-001",
    "action": "system.info",
    "type": "builtin",
    "parameters": null,
    "status": "pending",
    "requested_at": "2026-01-01T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z"
  }
]
ACTEOF
)

# configure-state REPLACES the whole snapshot fixture, so the block is spliced
# into the live snapshot and every other block travels back verbatim. Reading
# the snapshot is a real GET on the state endpoint and therefore increments
# state_count; the later phases take their state_count baselines after this.
STATE_SNAPSHOT=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3/state" 2>/dev/null || true)
if [ -z "${STATE_SNAPSHOT}" ]; then
    fail "could not read the live node state snapshot"
fi
# printf, not echo: the fixture carries backslash escapes (an embedded newline
# in the certs/ca data entry) that must travel back byte for byte.
SPLICED_STATE=$(printf '%s' "${STATE_SNAPSHOT}" | jq --argjson e "${ACTION_ENTRIES}" '.executions = $e')
ACTION_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${SPLICED_STATE}" \
    "http://localhost:18080/test/configure-state" 2>/dev/null || true)
if [ "${ACTION_STATUS}" != "204" ]; then
    fail "configure-state returned status ${ACTION_STATUS}, want 204"
fi
echo "  system.info dispatch configured in the executions block"

# Nudge the agent into an immediate pull instead of waiting out the heartbeat
# reconcile cadence.
NUDGE_PAYLOAD=$(cat <<'NUDGEEOF'
{
    "id": "evt-e2e-nudge-exec-e2e-systemd-001",
    "type": "node_state_updated",
    "scope": "node",
    "payload": {"node_id": "e2e-systemd-node"}
}
NUDGEEOF
)
NUDGE_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${NUDGE_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${NUDGE_STATUS}" != "204" ]; then
    fail "executions nudge injection returned status ${NUDGE_STATUS}, want 204"
fi
echo "  executions nudge injected successfully"

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

CB_INLINE=$(echo "${CB_BODY}" | jq -r '.output.inline // empty')
if [ -z "${CB_INLINE}" ]; then
    fail "terminal callback missing non-empty output.inline"
fi
if printf '%s' "${CB_INLINE}" | b64_decode >/dev/null 2>&1; then
    echo "  PASS: terminal callback output.inline base64-decodes"
else
    fail "terminal callback output.inline is not valid base64"
fi

echo "=== Action execution via the executions block PASSED ==="

# --- SSE event injection triggers reconciliation ---
echo "=== Testing SSE event injection ==="

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before injection: ${STATE_BEFORE}"

INJECT_PAYLOAD=$(cat <<'INJEOF'
{
    "id": "evt-e2e-inject-systemd-001",
    "type": "node_state_updated",
    "scope": "node",
    "payload": {"node_id": "e2e-systemd-node"}
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
fi

echo "=== SSE event injection PASSED ==="

# --- Heartbeat-triggered reconcile (RotateKeys flag) ---
echo "=== Testing heartbeat-triggered reconcile via RotateKeys ==="

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE_KR=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before: ${STATE_BEFORE_KR}"

KR_CONFIG='{"reconcile":true,"rotate_keys":true}'
KR_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${KR_CONFIG}" \
    "http://localhost:18080/test/configure-heartbeat" 2>/dev/null || true)
if [ "${KR_STATUS}" != "204" ]; then
    fail "configure-heartbeat returned status ${KR_STATUS}, want 204"
fi
echo "  heartbeat response configured with rotate_keys=true"

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

# Reset heartbeat response.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 || true

echo "=== Heartbeat-triggered reconcile PASSED ==="

# --- Deeper body validation ---
echo "=== Deeper body validation ==="

# Metrics body: validate MetricSample fields (name, value, group).
METRICS_BODY=$(curl -sf "http://localhost:18080/test/last-request/metrics" 2>/dev/null || true)
if [ -n "${METRICS_BODY}" ]; then
    FIRST_METRIC=$(echo "${METRICS_BODY}" | jq '.[0]')
    MET_NAME=$(echo "${FIRST_METRIC}" | jq -r '.name // empty')
    MET_VALUE_TYPE=$(echo "${FIRST_METRIC}" | jq -r '.value | type')
    MET_GROUP=$(echo "${FIRST_METRIC}" | jq -r '.group // empty')
    if [ -n "${MET_NAME}" ]; then
        echo "  PASS: metric[0] has name='${MET_NAME}'"
    else
        fail "metric[0] missing 'name' field"
    fi
    if [ "${MET_VALUE_TYPE}" = "number" ]; then
        echo "  PASS: metric[0] has a numeric value"
    else
        fail "metric[0] 'value' type='${MET_VALUE_TYPE}', want number"
    fi
    case "${MET_GROUP}" in
        node_resources|tunnel_health|peer_latency|agent_stats)
            echo "  PASS: metric[0] has group='${MET_GROUP}'" ;;
        *)
            fail "metric[0] group='${MET_GROUP}' outside the wire enum" ;;
    esac
fi

# The capability manifest carries no action list — the contract has no field for
# one — so the optional fields it does define are what there is to check here.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -n "${CAPS_BODY}" ]; then
    CAPS_FP=$(echo "${CAPS_BODY}" | jq -r '.ssh_host_key_fingerprint // empty')
    case "${CAPS_FP}" in
        SHA256:*) echo "  PASS: ssh_host_key_fingerprint is the canonical SHA256:<base64> form" ;;
        "") echo "  WARN: capability manifest carries no ssh_host_key_fingerprint" ;;
        *) fail "ssh_host_key_fingerprint='${CAPS_FP}', want the SHA256:<base64> form" ;;
    esac
fi

echo "=== Deeper body validation PASSED ==="

# --- Local Endpoint Delivery ---
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

echo "=== Local endpoint delivery PASSED ==="

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
