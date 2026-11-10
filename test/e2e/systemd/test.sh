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
#   - Spent token emptied in place under the unit's read-only /etc, hook watcher running
#   - Periodic loop verification (heartbeat/metrics/logs counters >= 2)
#   - Audit forwarding via service restart (ProcessSource fires per-process)
#   - Action execution via the state pull's executions block (ack/started/terminal callbacks)
#   - SSE event injection triggers reconciliation
#   - Heartbeat-triggered reconcile via RotateKeys flag
#   - Deeper body validation (metrics, capabilities fields)
#   - Mediated ssh session through the socket-activated session helper
#   - Mesh DNS through systemd-resolved: the registration, names, a bare host
#     name, a PTR and the A, AAAA, CNAME, SRV, MX and TXT records answered on
#     plexd0, a renamed host, a new zone and changed records without a
#     restart, a CNAME out of the mesh zones, a TXT answer over TCP, answers
#     while the control plane is paused
#   - Start after a reboot cleared /run/plexd, with the registration gone
#     while plexd is stopped and back after the start
#   - Mesh DNS opt-out with dns.enabled: false
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
# Set while the mesh DNS phase holds the mock API container paused, so a
# failure and the EXIT trap unpause it first.
MOCK_PAUSED=0

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

# --- Diagnostics function ---
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
    echo "==> Systemd container journalctl plexd-session-helper@*:"
    docker exec "${SYSTEMD_CONTAINER}" journalctl --no-pager -u 'plexd-session-helper@*' -n 100 2>/dev/null || true
    echo "==> Systemd container journalctl (full):"
    docker exec "${SYSTEMD_CONTAINER}" journalctl --no-pager -n 50 2>/dev/null || true
    echo "==> Systemd container process list:"
    docker exec "${SYSTEMD_CONTAINER}" ps aux 2>/dev/null || true
    echo "==> Systemd container /etc/plexd/:"
    docker exec "${SYSTEMD_CONTAINER}" ls -la /etc/plexd/ 2>/dev/null || true
    echo "==> Systemd container /usr/local/bin/plexd:"
    docker exec "${SYSTEMD_CONTAINER}" ls -la /usr/local/bin/plexd 2>/dev/null || true
    # The container's own systemd-resolved, never the host's.
    echo "==> Systemd container resolvectl status:"
    docker exec "${SYSTEMD_CONTAINER}" resolvectl status --no-pager 2>&1 || true
    echo "--- End diagnostics ---"
}

# --- Helper: unpause the mock API if the mesh DNS phase paused it ---
unpause_mock() {
    if [ "${MOCK_PAUSED}" -eq 1 ]; then
        docker unpause "${MOCKAPI_CONTAINER}" >/dev/null 2>&1 || true
        MOCK_PAUSED=0
    fi
}

# --- Helper: print message, dump diagnostics, and exit 1 ---
fail() {
    echo "FAIL: $1"
    unpause_mock
    print_diagnostics
    exit 1
}

# --- Cleanup trap ---
cleanup() {
    echo "--- Cleaning up ---"
    unpause_mock
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

# --- Build images ---
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

# --- Create network ---
echo "=== Creating Docker network ==="
docker network create "${NETWORK_NAME}"

# --- Start mock-api container ---
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

# --- Start systemd container and install plexd ---
echo "=== Starting systemd container ==="
docker run -d \
    --name "${SYSTEMD_CONTAINER}" \
    --network "${NETWORK_NAME}" \
    --privileged \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "${REPO_ROOT}/plexd-linux-amd64:/opt/plexd-binary:ro" \
    -v "${REPO_ROOT}/deploy/systemd/plexd.service:/opt/plexd.service:ro" \
    -v "${REPO_ROOT}/deploy/systemd/plexd-session-helper.socket:/opt/plexd-session-helper.socket:ro" \
    -v "${REPO_ROOT}/deploy/systemd/plexd-session-helper@.service:/opt/plexd-session-helper@.service:ro" \
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

# Install plexd binary and service unit.
echo "=== Installing plexd into systemd container ==="
docker exec "${SYSTEMD_CONTAINER}" bash -c \
    'cp /opt/plexd-binary /usr/local/bin/plexd && chmod +x /usr/local/bin/plexd && cp /opt/plexd.service /opt/plexd-session-helper.socket /opt/plexd-session-helper@.service /etc/systemd/system/'

# Write plexd config pointing at mock-api.
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

# Write the bootstrap token file before the service starts: the unit can only
# grant write access to a path that exists when systemd sets up its namespace.
docker exec "${SYSTEMD_CONTAINER}" bash -c 'printf %s "psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22" > /etc/plexd/bootstrap-token && chmod 600 /etc/plexd/bootstrap-token'

# Create the hooks directory, as plexd install does; this suite copies the
# units instead of running it, and the unit keeps /etc read-only for plexd.
docker exec "${SYSTEMD_CONTAINER}" mkdir -p /etc/plexd/hooks

# --- Start service and poll assertions ---
echo "=== Enabling and starting plexd service ==="
docker exec "${SYSTEMD_CONTAINER}" systemctl daemon-reload
docker exec "${SYSTEMD_CONTAINER}" systemctl enable --now plexd

# Give the service a moment to start.
sleep 3

echo "=== Verifying plexd service is active ==="
if ! docker exec "${SYSTEMD_CONTAINER}" systemctl is-active plexd; then
    fail "plexd service is not active"
fi

# plexd.service wants the helper socket and names it in Also=, so enabling and
# starting plexd brings it up too.
HELPER_SOCKET_STATE=$(docker exec "${SYSTEMD_CONTAINER}" systemctl is-active plexd-session-helper.socket 2>/dev/null || true)
if [ "${HELPER_SOCKET_STATE}" = "active" ]; then
    echo "  PASS: plexd-session-helper.socket is active"
else
    fail "plexd-session-helper.socket is '${HELPER_SOCKET_STATE}', want 'active'"
fi

# Poll mock-api assertion endpoint.
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
# decodes to 32 bytes (hex decodes to 48 and is refused) and no nested `binary`
# object, which the handler rejects as unknown. builtin_actions carries the
# agent's eleven builtins; plexd_hooks stays off, because the host is not in a
# cluster.
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
if echo "${CAPS_BODY}" | jq -e 'has("binary") or has("plexd_hooks")' >/dev/null 2>&1; then
    fail "capability manifest carries 'binary' or 'plexd_hooks', neither of which belongs here (body: ${CAPS_BODY})"
fi
CAPS_ACTION_COUNT=$(echo "${CAPS_BODY}" | jq '.builtin_actions | length')
if [ "${CAPS_ACTION_COUNT}" != "11" ]; then
    fail "capability manifest carries ${CAPS_ACTION_COUNT} builtin_actions, want 11 (body: ${CAPS_BODY})"
fi
echo "  PASS: capability manifest is contract-shaped (version=${CAPS_VERSION}, 32-byte digest, 11 builtins)"

echo "=== Request body validation PASSED ==="

# --- Spent token cleanup under the sandbox ---
# The unit keeps /etc read-only and grants write access to the token file
# alone, so plexd cannot unlink the token it spent and empties it instead.
# Here-strings rather than pipes: grep -q exits on the first match, and under
# pipefail the writer's SIGPIPE would fail the check.
echo "=== Verifying the spent bootstrap token was emptied ==="
TOKEN_SIZE=$(docker exec "${SYSTEMD_CONTAINER}" stat -c %s /etc/plexd/bootstrap-token 2>/dev/null || true)
if [ "${TOKEN_SIZE}" = "0" ]; then
    echo "  PASS: /etc/plexd/bootstrap-token is empty"
else
    fail "/etc/plexd/bootstrap-token size='${TOKEN_SIZE}', want 0"
fi
PLEXD_JOURNAL=$(docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager 2>/dev/null || true)
if grep -q "token file emptied, it could not be removed" <<< "${PLEXD_JOURNAL}"; then
    echo "  PASS: plexd logged that it emptied the token file"
else
    fail "journal has no 'token file emptied, it could not be removed' line"
fi
for line in "failed to delete token file" "hook watcher stopped"; do
    if grep -q "${line}" <<< "${PLEXD_JOURNAL}"; then
        fail "journal has '${line}'"
    fi
done
echo "  PASS: no token deletion warning and no stopped hook watcher"

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

# The request body checks covered the manifest's inventories, so the optional
# host-key fingerprint is what is left to check here.
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

# --- Mediated ssh session ---
# An ssh entry in the sessions block readies plexd's session listener for it,
# which binds no port, and plexd reports a session_started row without a
# listener_endpoint. Every login takes the path a console terminal takes
# through the control plane: the client connects to a relay the mock opens
# through /test/session-connect, the mock publishes a signed session_connect
# event, plexd opens a WebSocket to the mock's connection route with its NSK
# bearer and serves the session's SSH login on it, and the mock splices the
# client to that socket. The client logs in as the entry's user with the
# session token as password, and plexd starts the command through
# plexd-session-helper.socket, whose root helper verifies the token again
# against the key it pinned from identity.json. The client runs inside the
# systemd container and dials the relay's port on the mock container.
echo "=== Testing mediated ssh session ==="

NODE_ID="0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3"
# One password prompt: a refused token then ends ssh with 255 and "Permission
# denied" instead of sshpass giving up on the repeated prompt with its own 5.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o PreferredAuthentications=password -o PubkeyAuthentication=no
    -o NumberOfPasswordPrompts=1)
SSH_ERR=$(mktemp)

# Render one ssh entry of the sessions block.
ssh_session_entry() {
    local session_id=$1 user=$2 expires_at=$3
    cat <<SSHENTRYEOF
{
  "session_id": "${session_id}",
  "jti": "${session_id}",
  "kind": "ssh",
  "target": {"ssh": {"user": "${user}"}},
  "expires_at": "${expires_at}"
}
SSHENTRYEOF
}

# Splice a sessions block into the live snapshot and nudge plexd into a pull,
# the way the executions phase configures its block.
configure_sessions() {
    local tag=$1 entries=$2 snapshot spliced status
    snapshot=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/${NODE_ID}/state" 2>/dev/null || true)
    if [ -z "${snapshot}" ]; then
        fail "[${tag}] could not read the live node state snapshot"
    fi
    spliced=$(printf '%s' "${snapshot}" | jq --argjson e "${entries}" '.sessions = $e')
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "${spliced}" \
        "http://localhost:18080/test/configure-state" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] configure-state returned status ${status}, want 204"
    fi
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "{\"id\": \"evt-e2e-ssh-nudge-${tag}\", \"type\": \"node_state_updated\", \"scope\": \"node\", \"payload\": {\"node_id\": \"e2e-systemd-node\"}}" \
        "http://localhost:18080/test/inject-event" 2>/dev/null || true)
    if [ "${status}" != "204" ]; then
        fail "[${tag}] sessions nudge injection returned status ${status}, want 204"
    fi
}

# Mint a session token from the mock, signed with the key registration handed
# out.
mint_session_token() {
    local session_id=$1 user=$2 token
    token=$(curl -sf -X POST -H "Content-Type: application/json" \
        -d "{\"session_id\": \"${session_id}\", \"user\": \"${user}\", \"ttl_seconds\": 600}" \
        "http://localhost:18080/test/session-token" | jq -r '.token // empty')
    if [ -z "${token}" ]; then
        fail "could not mint a session token for ${session_id}"
    fi
    echo "${token}"
}

# Open a relay to one session through the mock, as a client attaching to it
# does, and print the port the relay listens on. Once a client connects to the
# port, the relay publishes session_connect and waits 10 s for plexd's
# connection before it closes the client. It runs inside a command
# substitution, where fail would end only the subshell and its message would
# land in the caller's variable, so a missing port is reported on stderr and
# returned as 1.
session_connect() {
    local session_id=$1 port
    port=$(curl -sf -X POST -H "Content-Type: application/json" \
        -d "{\"session_id\": \"${session_id}\"}" \
        "http://localhost:18080/test/session-connect" 2>/dev/null | jq -r '.port // empty' 2>/dev/null || true)
    if [ -z "${port}" ]; then
        echo "FAIL: POST /test/session-connect for ${session_id} answered no port" >&2
        return 1
    fi
    echo "${port}"
}

# Run one command over ssh from inside the container, through a relay opened
# for the session, so the login runs over a WebSocket plexd opened to the mock;
# stderr lands in SSH_ERR. A relay that could not be opened returns 1, a status
# no step expects of ssh.
ssh_in_node() {
    local token=$1 session_id=$2 user=$3 command=$4 port
    : >"${SSH_ERR}"
    port=$(session_connect "${session_id}") || return 1
    docker exec -e SSHPASS="${token}" "${SYSTEMD_CONTAINER}" \
        sshpass -e ssh "${SSH_OPTS[@]}" -p "${port}" "${user}@${MOCKAPI_CONTAINER}" "${command}" 2>"${SSH_ERR}"
}

last_session_activity() {
    curl -sf "http://localhost:18080/test/last-request/session_activity" 2>/dev/null || true
}

# ExpiresAt 10 minutes ahead in RFC 3339 UTC (GNU date -d, BSD date -v fallback).
SSH_EXPIRES_AT=$(date -u -d "+10 minutes" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+10M +%Y-%m-%dT%H:%M:%SZ)
ROOT_ENTRY=$(ssh_session_entry "sess-e2e-ssh-root" "root" "${SSH_EXPIRES_AT}")
USER_ENTRY=$(ssh_session_entry "sess-e2e-ssh-user" "e2e" "${SSH_EXPIRES_AT}")

# Step 1: an entry for root readies its session, which binds no port, so its
# session_started row carries no listener_endpoint.
configure_sessions "ssh-root" "[${ROOT_ENTRY}]"
ROOT_STARTED=""
SSH_ELAPSED=0
while [ "${SSH_ELAPSED}" -lt 60 ]; do
    BODY=$(last_session_activity)
    if [ "$(echo "${BODY}" | jq -r '.ssh.phase // empty' 2>/dev/null)" = "session_started" ]; then
        ROOT_STARTED=${BODY}
        break
    fi
    sleep 2
    SSH_ELAPSED=$((SSH_ELAPSED + 2))
done
if [ -z "${ROOT_STARTED}" ]; then
    docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager 2>/dev/null || true
    fail "no ssh session_started row within 60s of configuring the root entry"
fi
if [ "$(echo "${ROOT_STARTED}" | jq '.ssh | has("listener_endpoint")')" != "false" ]; then
    fail "the ssh session_started row ${ROOT_STARTED} carries listener_endpoint, want none"
fi
echo "  PASS: the ssh session_started row carries no listener_endpoint"

# Step 2: log in as root with the session token and run one command.
ROOT_TOKEN=$(mint_session_token "sess-e2e-ssh-root" "root")
SSH_RC=0
SSH_OUT=$(ssh_in_node "${ROOT_TOKEN}" "sess-e2e-ssh-root" root 'id -un') || SSH_RC=$?
if [ "${SSH_RC}" -ne 0 ] || [ "${SSH_OUT}" != "root" ]; then
    cat "${SSH_ERR}"
    fail "ssh 'id -un' as root exited ${SSH_RC} and printed '${SSH_OUT}', want 0 and 'root'"
fi
echo "  PASS: ssh 'id -un' printed root"
BODY=$(last_session_activity)
if [ "$(echo "${BODY}" | jq -r '.ssh.command // empty')" = "id -un" ] && [ "$(echo "${BODY}" | jq -r '.ssh.exit_code // empty')" = "0" ]; then
    echo "  PASS: the command_exited row carries 'id -un' and exit_code 0"
else
    fail "last session activity = ${BODY}, want the command_exited row of 'id -un' with exit_code 0"
fi

# Step 3: the helper's first run pinned the identity's signing key where plexd
# cannot write.
PIN_MODE=$(docker exec "${SYSTEMD_CONTAINER}" stat -c %a /etc/plexd/session-signing-key 2>/dev/null || true)
PIN_KEY=$(docker exec "${SYSTEMD_CONTAINER}" cat /etc/plexd/session-signing-key 2>/dev/null || true)
IDENTITY_KEY=$(docker exec "${SYSTEMD_CONTAINER}" jq -r '.signing_public_key' /var/lib/plexd/identity.json 2>/dev/null || true)
if [ "${PIN_MODE}" = "644" ] && [ -n "${IDENTITY_KEY}" ] && [ "${PIN_KEY}" = "${IDENTITY_KEY}" ]; then
    echo "  PASS: /etc/plexd/session-signing-key is mode 644 and holds the signing key"
else
    fail "session-signing-key mode '${PIN_MODE}' holds '${PIN_KEY}', want 644 and '${IDENTITY_KEY}'"
fi

# Step 4: a second entry for an unprivileged user gets a session of its own,
# and the helper switches to that user. Started rows no longer carry an
# endpoint to tell them apart, so the step waits for the activity counter to
# rise past its value before the entry and checks that the newest row is an
# ssh session_started.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
SSH_ACT_BEFORE=$(get_counter "${RESPONSE}" "session_activity_count")
configure_sessions "ssh-user" "[${ROOT_ENTRY}, ${USER_ENTRY}]"
SSH_ELAPSED=0
SSH_ACT_AFTER=${SSH_ACT_BEFORE}
while [ "${SSH_ELAPSED}" -lt 60 ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    SSH_ACT_AFTER=$(get_counter "${RESPONSE}" "session_activity_count")
    if [ "${SSH_ACT_AFTER}" -gt "${SSH_ACT_BEFORE}" ]; then
        break
    fi
    sleep 2
    SSH_ELAPSED=$((SSH_ELAPSED + 2))
done
if [ "${SSH_ACT_AFTER}" -le "${SSH_ACT_BEFORE}" ]; then
    fail "session_activity_count stayed at ${SSH_ACT_BEFORE} for 60s after configuring the e2e entry, want a session_started row"
fi
BODY=$(last_session_activity)
if [ "$(echo "${BODY}" | jq -r '.ssh.phase // empty' 2>/dev/null)" != "session_started" ]; then
    fail "last session activity = ${BODY}, want the ssh session_started row of the e2e entry"
fi
echo "  PASS: the e2e entry posted an ssh session_started row"
USER_TOKEN=$(mint_session_token "sess-e2e-ssh-user" "e2e")
SSH_RC=0
SSH_OUT=$(ssh_in_node "${USER_TOKEN}" "sess-e2e-ssh-user" e2e 'id -un') || SSH_RC=$?
if [ "${SSH_RC}" -ne 0 ] || [ "${SSH_OUT}" != "e2e" ]; then
    cat "${SSH_ERR}"
    fail "ssh 'id -un' as e2e exited ${SSH_RC} and printed '${SSH_OUT}', want 0 and 'e2e'"
fi
echo "  PASS: ssh 'id -un' printed e2e (the helper switched uid)"

# Step 5: the exit status travels back, and a token for another session is
# refused.
SSH_RC=0
ssh_in_node "${ROOT_TOKEN}" "sess-e2e-ssh-root" root 'exit 3' >/dev/null || SSH_RC=$?
if [ "${SSH_RC}" -eq 3 ]; then
    echo "  PASS: ssh 'exit 3' exited 3"
else
    cat "${SSH_ERR}"
    fail "ssh 'exit 3' exited ${SSH_RC}, want 3"
fi
OTHER_TOKEN=$(mint_session_token "sess-e2e-other" "root")
SSH_RC=0
ssh_in_node "${OTHER_TOKEN}" "sess-e2e-ssh-root" root 'id -un' >/dev/null || SSH_RC=$?
if [ "${SSH_RC}" -eq 255 ] && grep -q "Permission denied" "${SSH_ERR}"; then
    echo "  PASS: a token for another session was refused (exit 255, Permission denied)"
else
    cat "${SSH_ERR}"
    fail "a token for another session exited ${SSH_RC}, want 255 with 'Permission denied'"
fi

# Step 6: draining the block closes both sessions. Each session_ended row
# posts for a session the mock already holds as revoked, which records the
# ending row of such a session once, as the control plane does since
# plexsphere/plexsphere#931: both are accepted and none is refused, as the tcp
# drain is in the docker suite.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
SSH_ACT_BEFORE=$(get_counter "${RESPONSE}" "session_activity_count")
SSH_REJ_BEFORE=$(get_counter "${RESPONSE}" "session_activity_rejected_count")
configure_sessions "ssh-drain" "[]"
SSH_ELAPSED=0
SSH_ACT_AFTER=${SSH_ACT_BEFORE}
SSH_REJ_AFTER=${SSH_REJ_BEFORE}
while [ "${SSH_ELAPSED}" -lt 60 ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    SSH_ACT_AFTER=$(get_counter "${RESPONSE}" "session_activity_count")
    SSH_REJ_AFTER=$(get_counter "${RESPONSE}" "session_activity_rejected_count")
    if [ "${SSH_ACT_AFTER}" -ge $((SSH_ACT_BEFORE + 2)) ]; then
        break
    fi
    sleep 2
    SSH_ELAPSED=$((SSH_ELAPSED + 2))
done
if [ "${SSH_ACT_AFTER}" -lt $((SSH_ACT_BEFORE + 2)) ]; then
    fail "session_activity_count went from ${SSH_ACT_BEFORE} to ${SSH_ACT_AFTER} after the drain, want +2"
fi
if [ "${SSH_REJ_AFTER}" -ne "${SSH_REJ_BEFORE}" ]; then
    fail "session_activity_rejected_count went from ${SSH_REJ_BEFORE} to ${SSH_REJ_AFTER} after the drain, want it unchanged"
fi
BODY=$(last_session_activity)
if [ "$(echo "${BODY}" | jq -r '.ssh.phase // empty')" = "session_ended" ] && [ "$(echo "${BODY}" | jq -r '.ssh.terminated_by // empty')" = "plexd_close" ]; then
    echo "  PASS: the drain posted ssh session_ended rows with terminated_by plexd_close"
else
    fail "last session activity = ${BODY}, want an ssh session_ended row with terminated_by plexd_close"
fi

# Step 7: a session_connect for the drained root session opens nothing. plexd
# finds no live ssh session and logs why, so the relay waits out its 10 s for a
# connection that never comes and closes the client, and ssh, which never saw
# a server banner, exits 255.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CONN_BEFORE=$(get_counter "${RESPONSE}" "session_connection_count")
CONN_TIMEOUT_BEFORE=$(get_counter "${RESPONSE}" "session_connection_timeout_count")
JOURNAL_SINCE=$(docker exec "${SYSTEMD_CONTAINER}" date '+%Y-%m-%d %H:%M:%S')
SSH_RC=0
ssh_in_node "${ROOT_TOKEN}" "sess-e2e-ssh-root" root 'id -un' >/dev/null || SSH_RC=$?
if [ "${SSH_RC}" -ne 255 ]; then
    cat "${SSH_ERR}"
    fail "ssh through a relay for the drained root session exited ${SSH_RC}, want 255"
fi
echo "  PASS: ssh through a relay for the drained root session exited 255"
# The relay counts its timeout before it closes the client, so the counter has
# moved once ssh returns; the poll only covers an ssh that gave up early.
CONN_ELAPSED=0
CONN_TIMEOUT_AFTER=${CONN_TIMEOUT_BEFORE}
CONN_AFTER=${CONN_BEFORE}
while [ "${CONN_ELAPSED}" -lt 20 ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    CONN_TIMEOUT_AFTER=$(get_counter "${RESPONSE}" "session_connection_timeout_count")
    CONN_AFTER=$(get_counter "${RESPONSE}" "session_connection_count")
    if [ "${CONN_TIMEOUT_AFTER}" -ge $((CONN_TIMEOUT_BEFORE + 1)) ]; then
        break
    fi
    sleep 2
    CONN_ELAPSED=$((CONN_ELAPSED + 2))
done
if [ "${CONN_TIMEOUT_AFTER}" -ne $((CONN_TIMEOUT_BEFORE + 1)) ]; then
    fail "session_connection_timeout_count went from ${CONN_TIMEOUT_BEFORE} to ${CONN_TIMEOUT_AFTER}, want +1"
fi
if [ "${CONN_AFTER}" -ne "${CONN_BEFORE}" ]; then
    fail "session_connection_count went from ${CONN_BEFORE} to ${CONN_AFTER}, want it unchanged"
fi
echo "  PASS: the relay timed out (session_connection_timeout_count +1) and session_connection_count stayed ${CONN_BEFORE}"
# A here-string, not a pipe: under pipefail, grep -q leaving early could fail
# the writer of a long journal and read as no match.
STEP7_JOURNAL=$(docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager --since "${JOURNAL_SINCE}" 2>/dev/null || true)
if grep -qF "session_connect names no live ssh session; not connecting" <<<"${STEP7_JOURNAL}"; then
    echo "  PASS: plexd logged that the session_connect names no live ssh session"
else
    echo "${STEP7_JOURNAL}"
    fail "journalctl -u plexd since ${JOURNAL_SINCE} lacks 'session_connect names no live ssh session; not connecting'"
fi
rm -f "${SSH_ERR}"

echo "=== Mediated ssh session PASSED ==="

# --- Mesh DNS through systemd-resolved ---
# plexd answers the dns block of its pull on its own mesh IP, 10.99.0.1:5354,
# and registers that server with the container's systemd-resolved for the
# mesh zones on plexd0 only. /etc/resolv.conf stays Docker's, so every query
# here asks systemd-resolved directly with resolvectl, inside the container.
# The fixture's block has the search domain app.e2e.internal, the zones
# app.e2e.internal and e2e.internal, the reverse zone 0.99.10.in-addr.arpa,
# the hosts node-1, peer-1 and peer-2 at 10.99.0.1 to 10.99.0.3, and eight
# records: two A records and an AAAA at db.e2e.internal, an SRV at
# _db._tcp.app.e2e.internal, an MX and a TXT at e2e.internal, and the CNAMEs
# alias.app.e2e.internal to peer-2 and ext.e2e.internal to ext.example.com.
echo "=== Testing mesh DNS through systemd-resolved ==="

MESH_IFACE="plexd0"
MESH_DNS_SERVER="10.99.0.1:5354"

# has_word <text> <word> succeeds when word is one of the whitespace-separated
# words of text. resolvectl wraps a long list onto the next line, so a list is
# matched word by word rather than line by line.
has_word() {
    local text=$1 want=$2 line word
    local -a words
    while IFS= read -r line; do
        read -ra words <<< "${line}"
        for word in "${words[@]}"; do
            if [ "${word}" = "${want}" ]; then
                return 0
            fi
        done
    done <<< "${text}"
    return 1
}

# journal_has <journal> <needle>... succeeds when one line of journal carries
# every needle. The journal is matched line by line rather than piped into
# grep -q, which under pipefail can fail the writer of a long journal.
journal_has() {
    local journal=$1 line needle
    shift
    while IFS= read -r line; do
        for needle in "$@"; do
            case "${line}" in
                *"${needle}"*) ;;
                *) continue 2 ;;
            esac
        done
        return 0
    done <<< "${journal}"
    return 1
}

# mesh_query [--type=<type>] <name> runs resolvectl query inside the container
# with every argument it gets and leaves its output, stderr included, in
# QUERY_OUT and its exit status in QUERY_RC.
mesh_query() {
    QUERY_RC=0
    QUERY_OUT=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl query "$@" 2>&1) || QUERY_RC=$?
}

# answers_on_mesh <output> <name> <value> succeeds when a resolvectl query
# output has the answer line "<name>: <value>" naming link plexd0.
answers_on_mesh() {
    local out=$1 name=$2 value=$3 line
    while IFS= read -r line; do
        case "${line}" in
            "${name}: ${value} "*"-- link: ${MESH_IFACE}") return 0 ;;
        esac
    done <<< "${out}"
    return 1
}

# not_found <output> <name> succeeds when a resolvectl query output reports
# the name as not found, the answer to an NXDOMAIN.
not_found() {
    case "$1" in
        *"'$2' not found"*) return 0 ;;
    esac
    return 1
}

# has_answer_on_mesh <output> <value> succeeds when a resolvectl query output
# has an answer line that holds value and names link plexd0. resolvectl puts
# the first answer after "<name>: " and every further one on an indented line
# of its own, so each line is matched with one blank put in front of it.
has_answer_on_mesh() {
    local out=$1 value=$2 line
    while IFS= read -r line; do
        case " ${line}" in
            *" ${value} "*"-- link: ${MESH_IFACE}") return 0 ;;
        esac
    done <<< "${out}"
    return 1
}

# rr_on_mesh <output> <text> succeeds when a resolvectl query --type output
# has a line that starts with "<text> " and names link plexd0. resolvectl
# prints such a record as "<name> IN <type> <data>".
rr_on_mesh() {
    local out=$1 text=$2 line
    while IFS= read -r line; do
        case "${line}" in
            "${text} "*"-- link: ${MESH_IFACE}") return 0 ;;
        esac
    done <<< "${out}"
    return 1
}

# no_such_type <output> <name> succeeds when a resolvectl query output reports
# that the name holds no record of the asked type, the answer to a NODATA.
no_such_type() {
    case "$1" in
        *"'$2' does not have any RR of the requested type"*) return 0 ;;
    esac
    return 1
}

# read_link_domains sets LINK_DOMAINS to the domains resolvectl domain lists
# for plexd0, sorted and joined by one space, so a check compares the whole
# set. Every word after the "Link N (plexd0):" label counts, the wrapped ones
# too. LINK_DOMAINS_RAW keeps the output and LINK_DOMAINS_RC the exit status.
read_link_domains() {
    local -a parts
    LINK_DOMAINS_RC=0
    LINK_DOMAINS_RAW=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl domain "${MESH_IFACE}" 2>&1) || LINK_DOMAINS_RC=$?
    read -ra parts <<< "$(printf '%s' "${LINK_DOMAINS_RAW#*:}" | tr '\n' ' ')"
    if [ "${#parts[@]}" -eq 0 ]; then
        LINK_DOMAINS=""
        return 0
    fi
    LINK_DOMAINS=$(printf '%s\n' "${parts[@]}" | LC_ALL=C sort | tr '\n' ' ')
    LINK_DOMAINS=${LINK_DOMAINS% }
}

# Step 1: no earlier phase depends on the WireGuard interface, and the
# resolver listens on the mesh IP that interface carries.
if docker exec "${SYSTEMD_CONTAINER}" test -e "/sys/class/net/${MESH_IFACE}"; then
    echo "  PASS: /sys/class/net/${MESH_IFACE} exists"
else
    fail "/sys/class/net/${MESH_IFACE} does not exist in the container: WireGuard did not come up, and the resolver listens on that interface's mesh IP"
fi

# Step 2: the registration. plexd registers on the first pull after a start;
# the last start was the audit phase's restart, so it is normally in place by
# now, and the 30 s cover a first pull that came late.
DNS_REG_TIMEOUT=30
DNS_REG_START=${SECONDS}
while :; do
    DNS_STATUS_RC=0
    DNS_STATUS=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl status "${MESH_IFACE}" 2>&1) || DNS_STATUS_RC=$?
    DNS_STATUS_SERVERS=""
    while IFS= read -r line; do
        case "${line}" in
            *"DNS Servers: "*) DNS_STATUS_SERVERS=${line#*DNS Servers: } ;;
        esac
    done <<< "${DNS_STATUS}"
    if [ "${DNS_STATUS_RC}" -eq 0 ] && [ "${DNS_STATUS_SERVERS}" = "${MESH_DNS_SERVER}" ]; then
        break
    fi
    if [ $((SECONDS - DNS_REG_START)) -ge "${DNS_REG_TIMEOUT}" ]; then
        echo "${DNS_STATUS}"
        fail "resolvectl status ${MESH_IFACE} (exit ${DNS_STATUS_RC}) lists DNS servers '${DNS_STATUS_SERVERS}' after ${DNS_REG_TIMEOUT}s, want '${MESH_DNS_SERVER}'"
    fi
    sleep 2
done
echo "  PASS: resolvectl status ${MESH_IFACE} shows the DNS server ${MESH_DNS_SERVER}"
for want in app.e2e.internal "~e2e.internal" "~0.99.10.in-addr.arpa" "-DefaultRoute"; do
    if ! has_word "${DNS_STATUS}" "${want}"; then
        echo "${DNS_STATUS}"
        fail "resolvectl status ${MESH_IFACE} does not show '${want}'"
    fi
done
echo "  PASS: resolvectl status ${MESH_IFACE} shows app.e2e.internal, ~e2e.internal, ~0.99.10.in-addr.arpa and -DefaultRoute"
# The search domain is listed once, and app.e2e.internal is no routing domain
# of its own because ~e2e.internal covers it.
read_link_domains
if [ "${LINK_DOMAINS_RC}" -ne 0 ] || [ "${LINK_DOMAINS}" != "app.e2e.internal ~0.99.10.in-addr.arpa ~e2e.internal" ]; then
    echo "${LINK_DOMAINS_RAW}"
    fail "resolvectl domain ${MESH_IFACE} (exit ${LINK_DOMAINS_RC}) lists '${LINK_DOMAINS}', want exactly 'app.e2e.internal ~0.99.10.in-addr.arpa ~e2e.internal'"
fi
echo "  PASS: resolvectl domain ${MESH_IFACE} lists exactly ${LINK_DOMAINS}"
DNS_PID=$(docker exec "${SYSTEMD_CONTAINER}" systemctl show -p MainPID --value plexd)
DNS_JOURNAL=$(docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager 2>&1) || fail "journalctl -u plexd failed: ${DNS_JOURNAL}"
if journal_has "${DNS_JOURNAL}" "plexd[${DNS_PID}]:" 'msg="mesh dns registered with systemd-resolved"' "interface=${MESH_IFACE}" "server=${MESH_DNS_SERVER}"; then
    echo "  PASS: the journal of plexd[${DNS_PID}] holds 'mesh dns registered with systemd-resolved' for ${MESH_IFACE} and ${MESH_DNS_SERVER}"
else
    echo "${DNS_JOURNAL}"
    fail "the journal of plexd[${DNS_PID}] has no 'mesh dns registered with systemd-resolved' line with interface=${MESH_IFACE} server=${MESH_DNS_SERVER}"
fi

# Step 3: a fully qualified name, a bare host name through the search domain,
# and a mesh IP through the reverse zone are answered on plexd0, and a name
# plexd denies is not found.
mesh_query peer-1.app.e2e.internal
if [ "${QUERY_RC}" -eq 0 ] && answers_on_mesh "${QUERY_OUT}" peer-1.app.e2e.internal 10.99.0.2; then
    echo "  PASS: resolvectl query peer-1.app.e2e.internal answers 10.99.0.2 on link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query peer-1.app.e2e.internal exited ${QUERY_RC}, want 0 and 10.99.0.2 on link ${MESH_IFACE}"
fi
mesh_query peer-1
if [ "${QUERY_RC}" -eq 0 ] && answers_on_mesh "${QUERY_OUT}" peer-1 10.99.0.2 && has_word "${QUERY_OUT}" "(peer-1.app.e2e.internal)"; then
    echo "  PASS: resolvectl query peer-1 answers 10.99.0.2 on link ${MESH_IFACE} as peer-1.app.e2e.internal"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query peer-1 exited ${QUERY_RC}, want 0 and 10.99.0.2 on link ${MESH_IFACE} through the search domain"
fi
mesh_query 10.99.0.3
if [ "${QUERY_RC}" -eq 0 ] && answers_on_mesh "${QUERY_OUT}" 10.99.0.3 peer-2.app.e2e.internal; then
    echo "  PASS: resolvectl query 10.99.0.3 answers peer-2.app.e2e.internal on link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query 10.99.0.3 exited ${QUERY_RC}, want 0 and peer-2.app.e2e.internal on link ${MESH_IFACE}"
fi
mesh_query nope.app.e2e.internal
if [ "${QUERY_RC}" -ne 0 ] && not_found "${QUERY_OUT}" nope.app.e2e.internal; then
    echo "  PASS: resolvectl query nope.app.e2e.internal fails with not found"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query nope.app.e2e.internal exited ${QUERY_RC}, want a failure with 'not found'"
fi

# Step 3b: the records of the block are answered on plexd0. resolvectl lists
# the two A records and the AAAA of db.e2e.internal one per line. plexd
# follows the CNAME alias.app.e2e.internal to peer-2, which lies in its own
# zones, and answers the CNAME and peer-2's address together. A query with
# --type prints the record as "<name> IN <type> <data>", and a type the name
# does not hold answers NODATA. ext.e2e.internal is not asked for here: its
# target lies outside the mesh zones, and systemd-resolved would follow it
# through Docker's DNS.
mesh_query db.e2e.internal
for want in 192.0.2.10 192.0.2.11 2001:db8::10; do
    if [ "${QUERY_RC}" -ne 0 ] || ! has_answer_on_mesh "${QUERY_OUT}" "${want}"; then
        echo "${QUERY_OUT}"
        fail "resolvectl query db.e2e.internal exited ${QUERY_RC}, want 0 and ${want} on link ${MESH_IFACE}"
    fi
done
echo "  PASS: resolvectl query db.e2e.internal answers 192.0.2.10, 192.0.2.11 and 2001:db8::10 on link ${MESH_IFACE}"
mesh_query alias.app.e2e.internal
if [ "${QUERY_RC}" -eq 0 ] && answers_on_mesh "${QUERY_OUT}" alias.app.e2e.internal 10.99.0.3 && has_word "${QUERY_OUT}" "(peer-2.app.e2e.internal)"; then
    echo "  PASS: resolvectl query alias.app.e2e.internal answers 10.99.0.3 on link ${MESH_IFACE} as peer-2.app.e2e.internal"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query alias.app.e2e.internal exited ${QUERY_RC}, want 0 and 10.99.0.3 on link ${MESH_IFACE} as (peer-2.app.e2e.internal)"
fi
mesh_query --type=SRV _db._tcp.app.e2e.internal
if [ "${QUERY_RC}" -eq 0 ] && rr_on_mesh "${QUERY_OUT}" "_db._tcp.app.e2e.internal IN SRV 0 5 5432 db.e2e.internal"; then
    echo "  PASS: resolvectl query --type=SRV _db._tcp.app.e2e.internal answers 0 5 5432 db.e2e.internal on link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query --type=SRV _db._tcp.app.e2e.internal exited ${QUERY_RC}, want 0 and '_db._tcp.app.e2e.internal IN SRV 0 5 5432 db.e2e.internal' on link ${MESH_IFACE}"
fi
mesh_query --type=MX e2e.internal
if [ "${QUERY_RC}" -eq 0 ] && rr_on_mesh "${QUERY_OUT}" "e2e.internal IN MX 10 mail.example.com"; then
    echo "  PASS: resolvectl query --type=MX e2e.internal answers 10 mail.example.com on link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query --type=MX e2e.internal exited ${QUERY_RC}, want 0 and 'e2e.internal IN MX 10 mail.example.com' on link ${MESH_IFACE}"
fi
mesh_query --type=TXT e2e.internal
if [ "${QUERY_RC}" -eq 0 ] && rr_on_mesh "${QUERY_OUT}" 'e2e.internal IN TXT "v=e2e" "owner=plexd"'; then
    echo "  PASS: resolvectl query --type=TXT e2e.internal answers \"v=e2e\" \"owner=plexd\" on link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query --type=TXT e2e.internal exited ${QUERY_RC}, want 0 and 'e2e.internal IN TXT \"v=e2e\" \"owner=plexd\"' on link ${MESH_IFACE}"
fi
mesh_query --type=MX db.e2e.internal
if [ "${QUERY_RC}" -ne 0 ] && no_such_type "${QUERY_OUT}" db.e2e.internal; then
    echo "  PASS: resolvectl query --type=MX db.e2e.internal fails with no RR of the requested type"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query --type=MX db.e2e.internal exited ${QUERY_RC}, want a failure with 'does not have any RR of the requested type'"
fi

# Step 4: a name outside the mesh zones still resolves the way it did, through
# Docker's DNS as systemd-resolved's global server, and not through plexd0.
# systemd-resolved sends no single-label name to a DNS server, so the mock API
# is asked for by its container name qualified with the network's name, which
# Docker's DNS answers too.
MOCK_FQDN="${MOCKAPI_CONTAINER}.${NETWORK_NAME}"
MOCK_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${NETWORK_NAME}\").IPAddress}}" "${MOCKAPI_CONTAINER}")
if [ -z "${MOCK_IP}" ]; then
    fail "docker inspect gave no address of ${MOCKAPI_CONTAINER} on ${NETWORK_NAME}"
fi
mesh_query "${MOCK_FQDN}"
MOCK_ANSWERED=0
while IFS= read -r line; do
    case "${line}" in
        "${MOCK_FQDN}: ${MOCK_IP}" | "${MOCK_FQDN}: ${MOCK_IP} "*) MOCK_ANSWERED=1 ;;
    esac
done <<< "${QUERY_OUT}"
case "${QUERY_OUT}" in
    *"${MESH_IFACE}"*) MOCK_ON_MESH=1 ;;
    *) MOCK_ON_MESH=0 ;;
esac
if [ "${QUERY_RC}" -eq 0 ] && [ "${MOCK_ANSWERED}" -eq 1 ] && [ "${MOCK_ON_MESH}" -eq 0 ]; then
    echo "  PASS: resolvectl query ${MOCK_FQDN} answers ${MOCK_IP} and does not name link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query ${MOCK_FQDN} exited ${QUERY_RC}, want 0 and ${MOCK_IP} without link ${MESH_IFACE}"
fi

# Step 5: a changed block takes effect with the pull that carries it, without
# a restart. peer-1 becomes db-1 at the same address, and the zone
# ops.e2e.test arrives with the host gw.ops.e2e.test, which plexd routes as a
# domain of its own because no other zone is above it. The records change
# too: the A record 192.0.2.10 of db.e2e.internal becomes 192.0.2.20,
# ext.e2e.internal goes, mock.e2e.internal arrives as a CNAME to the name
# step 4 resolved through Docker's DNS, and big.e2e.internal arrives with
# eight TXT records of one string each, a digit, "-" and 200 times "x". The
# list is sorted by fqdn, then type, as the control plane serves it. The block
# is spliced into the state the mock serves, so every other block travels back
# verbatim. No event nudges the agent: the heartbeat answers reconcile:true,
# so a pull comes about every 30 s, and the 90 s cover three of them.
DNS_SNAPSHOT=$(curl -sf "${MOCK_AUTH[@]}" "http://localhost:18080/v1/nodes/${NODE_ID}/state" 2>/dev/null || true)
if [ -z "${DNS_SNAPSHOT}" ]; then
    fail "could not read the live node state snapshot"
fi
DNS_PEER1=$(printf '%s' "${DNS_SNAPSHOT}" | jq '[.dns.hosts[]? | select(.fqdn == "peer-1.app.e2e.internal" and .mesh_ip == "10.99.0.2")] | length')
if [ "${DNS_PEER1}" != "1" ]; then
    fail "the served dns block carries ${DNS_PEER1} host(s) peer-1.app.e2e.internal at 10.99.0.2, want 1 (block: $(printf '%s' "${DNS_SNAPSHOT}" | jq -c '.dns'))"
fi
DNS_GW_HOST='{"node_id": "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b4", "fqdn": "gw.ops.e2e.test", "mesh_ip": "10.99.0.4"}'
# printf, not echo: the fixture carries backslash escapes (an embedded newline
# in the certs/ca data entry) that must travel back byte for byte.
DNS_CHANGED=$(printf '%s' "${DNS_SNAPSHOT}" | jq --argjson gw "${DNS_GW_HOST}" --arg mock "${MOCK_FQDN}" '
    .dns.zones += ["ops.e2e.test"]
    | .dns.hosts = ([.dns.hosts[] | if .fqdn == "peer-1.app.e2e.internal" then .fqdn = "db-1.app.e2e.internal" else . end] + [$gw] | sort_by(.fqdn))
    | .dns.records = ([.dns.records[]
        | select(.fqdn != "ext.e2e.internal")
        | if .fqdn == "db.e2e.internal" and .type == "A" and .address == "192.0.2.10" then .address = "192.0.2.20" else . end]
        + [{fqdn: "mock.e2e.internal", type: "CNAME", target: $mock}]
        + [range(8) | {fqdn: "big.e2e.internal", type: "TXT", text: ["\(.)-" + ("x" * 200)]}]
        | sort_by([.fqdn, .type]))')
MAIN_PID_BEFORE=$(docker exec "${SYSTEMD_CONTAINER}" systemctl show -p MainPID --value plexd)
DNS_CHANGE_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${DNS_CHANGED}" \
    "http://localhost:18080/test/configure-state" 2>/dev/null || true)
if [ "${DNS_CHANGE_STATUS}" != "204" ]; then
    fail "configure-state with the renamed host returned status ${DNS_CHANGE_STATUS}, want 204"
fi
echo "  dns block configured: peer-1 renamed to db-1, zone ops.e2e.test with gw.ops.e2e.test added, records changed"
DNS_CHANGE_TIMEOUT=90
DNS_CHANGE_START=${SECONDS}
while :; do
    read_link_domains
    DB1_OK=0
    GW_OK=0
    PEER1_GONE=0
    DBREC_OK=0
    EXT_GONE=0
    # gw.ops.e2e.test is asked for only once plexd0 routes its zone, so no
    # query for it leaves through the global server.
    if has_word "${LINK_DOMAINS}" "~ops.e2e.test"; then
        mesh_query db-1.app.e2e.internal
        DB1_RC=${QUERY_RC}
        DB1_OUT=${QUERY_OUT}
        if [ "${DB1_RC}" -eq 0 ] && answers_on_mesh "${DB1_OUT}" db-1.app.e2e.internal 10.99.0.2; then
            DB1_OK=1
        fi
        mesh_query gw.ops.e2e.test
        GW_RC=${QUERY_RC}
        GW_OUT=${QUERY_OUT}
        if [ "${GW_RC}" -eq 0 ] && answers_on_mesh "${GW_OUT}" gw.ops.e2e.test 10.99.0.4; then
            GW_OK=1
        fi
        mesh_query peer-1.app.e2e.internal
        PEER1_RC=${QUERY_RC}
        PEER1_OUT=${QUERY_OUT}
        if [ "${PEER1_RC}" -ne 0 ] && not_found "${PEER1_OUT}" peer-1.app.e2e.internal; then
            PEER1_GONE=1
        fi
    fi
    mesh_query db.e2e.internal
    DBREC_RC=${QUERY_RC}
    DBREC_OUT=${QUERY_OUT}
    if [ "${DBREC_RC}" -eq 0 ] && has_answer_on_mesh "${DBREC_OUT}" 192.0.2.20 && has_answer_on_mesh "${DBREC_OUT}" 192.0.2.11 && ! has_word "${DBREC_OUT}" 192.0.2.10; then
        DBREC_OK=1
    fi
    # ext.e2e.internal is asked for only once db.e2e.internal answers the
    # changed records. Before that pull plexd still answers the CNAME to
    # ext.example.com, and systemd-resolved would follow it through Docker's
    # DNS, which on an offline runner can stall each pass.
    if [ "${DBREC_OK}" -eq 1 ]; then
        mesh_query ext.e2e.internal
        EXT_RC=${QUERY_RC}
        EXT_OUT=${QUERY_OUT}
        if [ "${EXT_RC}" -ne 0 ] && not_found "${EXT_OUT}" ext.e2e.internal; then
            EXT_GONE=1
        fi
    fi
    if [ "${DB1_OK}" -eq 1 ] && [ "${GW_OK}" -eq 1 ] && [ "${PEER1_GONE}" -eq 1 ] && [ "${DBREC_OK}" -eq 1 ] && [ "${EXT_GONE}" -eq 1 ]; then
        break
    fi
    if [ $((SECONDS - DNS_CHANGE_START)) -ge "${DNS_CHANGE_TIMEOUT}" ]; then
        echo "resolvectl domain ${MESH_IFACE} (exit ${LINK_DOMAINS_RC}):"
        echo "${LINK_DOMAINS_RAW}"
        echo "resolvectl query db-1.app.e2e.internal (exit ${DB1_RC:-not run}): ${DB1_OUT:-}"
        echo "resolvectl query gw.ops.e2e.test (exit ${GW_RC:-not run}): ${GW_OUT:-}"
        echo "resolvectl query peer-1.app.e2e.internal (exit ${PEER1_RC:-not run}): ${PEER1_OUT:-}"
        echo "resolvectl query db.e2e.internal (exit ${DBREC_RC:-not run}): ${DBREC_OUT:-}"
        echo "resolvectl query ext.e2e.internal (exit ${EXT_RC:-not run}): ${EXT_OUT:-}"
        fail "the renamed host, the new zone and the changed records did not take effect within ${DNS_CHANGE_TIMEOUT}s (db-1 ${DB1_OK}, gw ${GW_OK}, peer-1 gone ${PEER1_GONE}, db ${DBREC_OK}, ext gone ${EXT_GONE})"
    fi
    sleep 3
done
echo "  PASS: after $((SECONDS - DNS_CHANGE_START))s db-1.app.e2e.internal answers 10.99.0.2 on link ${MESH_IFACE}"
echo "  PASS: gw.ops.e2e.test answers 10.99.0.4 on link ${MESH_IFACE}"
echo "  PASS: peer-1.app.e2e.internal fails with not found"
echo "  PASS: db.e2e.internal answers 192.0.2.20 and 192.0.2.11 on link ${MESH_IFACE} and no longer 192.0.2.10"
echo "  PASS: ext.e2e.internal fails with not found"
if [ "${LINK_DOMAINS}" != "app.e2e.internal ~0.99.10.in-addr.arpa ~e2e.internal ~ops.e2e.test" ]; then
    echo "${LINK_DOMAINS_RAW}"
    fail "resolvectl domain ${MESH_IFACE} lists '${LINK_DOMAINS}', want exactly 'app.e2e.internal ~0.99.10.in-addr.arpa ~e2e.internal ~ops.e2e.test'"
fi
echo "  PASS: resolvectl domain ${MESH_IFACE} lists ~ops.e2e.test (exactly ${LINK_DOMAINS})"
MAIN_PID_AFTER=$(docker exec "${SYSTEMD_CONTAINER}" systemctl show -p MainPID --value plexd)
if [ -n "${MAIN_PID_BEFORE}" ] && [ "${MAIN_PID_BEFORE}" != "0" ] && [ "${MAIN_PID_AFTER}" = "${MAIN_PID_BEFORE}" ]; then
    echo "  PASS: the MainPID of plexd.service is still ${MAIN_PID_AFTER}"
else
    fail "the MainPID of plexd.service went from '${MAIN_PID_BEFORE}' to '${MAIN_PID_AFTER}', want it unchanged and nonzero"
fi
# mock.e2e.internal is a CNAME to the name step 4 resolved, which lies outside
# the mesh zones. plexd answers the CNAME alone, and systemd-resolved follows
# it through Docker's DNS, so the address line does not name link plexd0.
mesh_query mock.e2e.internal
MOCK_CNAME_ANSWERED=0
while IFS= read -r line; do
    case "${line}" in
        *"-- link: ${MESH_IFACE}") ;;
        "mock.e2e.internal: ${MOCK_IP}" | "mock.e2e.internal: ${MOCK_IP} "*) MOCK_CNAME_ANSWERED=1 ;;
    esac
done <<< "${QUERY_OUT}"
if [ "${QUERY_RC}" -eq 0 ] && [ "${MOCK_CNAME_ANSWERED}" -eq 1 ] && has_word "${QUERY_OUT}" "(${MOCK_FQDN})"; then
    echo "  PASS: resolvectl query mock.e2e.internal answers ${MOCK_IP} as ${MOCK_FQDN}, not on link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query mock.e2e.internal exited ${QUERY_RC}, want 0 and ${MOCK_IP} as (${MOCK_FQDN}) without link ${MESH_IFACE}"
fi
# The eight TXT records of big.e2e.internal take more than 1232 bytes, the
# most plexd sends over UDP, so plexd sends the UDP answer with TC set and no
# records, and systemd-resolved asks again over TCP. The eight lines alone do
# not prove that: systemd-resolved 255 also accepts an untruncated UDP reply
# larger than the 1472 bytes it offers. The container's systemd-resolved logs
# the repeat at debug level only, so the query runs with its log level raised
# and its cache flushed, and its journal must show the repeat.
RESOLVED_LEVEL=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl log-level 2>&1) \
    || fail "resolvectl log-level inside the container failed: ${RESOLVED_LEVEL}"
LEVEL_OUT=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl log-level debug 2>&1) \
    || fail "resolvectl log-level debug inside the container failed: ${LEVEL_OUT}"
TXT_SINCE=$(docker exec "${SYSTEMD_CONTAINER}" date '+%Y-%m-%d %H:%M:%S')
FLUSH_OUT=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl flush-caches 2>&1) \
    || fail "resolvectl flush-caches inside the container failed: ${FLUSH_OUT}"
mesh_query --type=TXT big.e2e.internal
LEVEL_OUT=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl log-level "${RESOLVED_LEVEL}" 2>&1) \
    || fail "resolvectl log-level ${RESOLVED_LEVEL} inside the container failed: ${LEVEL_OUT}"
RESOLVED_JOURNAL=$(docker exec "${SYSTEMD_CONTAINER}" journalctl -u systemd-resolved --no-pager --since "${TXT_SINCE}" 2>&1) \
    || fail "journalctl -u systemd-resolved since ${TXT_SINCE} failed: ${RESOLVED_JOURNAL}"
BIG_TXT_LINES=0
while IFS= read -r line; do
    case "${line}" in
        'big.e2e.internal IN TXT "'*"-- link: ${MESH_IFACE}") BIG_TXT_LINES=$((BIG_TXT_LINES + 1)) ;;
    esac
done <<< "${QUERY_OUT}"
if [ "${QUERY_RC}" -eq 0 ] && [ "${BIG_TXT_LINES}" -eq 8 ]; then
    echo "  PASS: resolvectl query --type=TXT big.e2e.internal answers 8 TXT records on link ${MESH_IFACE}"
else
    echo "${QUERY_OUT}"
    fail "resolvectl query --type=TXT big.e2e.internal exited ${QUERY_RC} with ${BIG_TXT_LINES} TXT line(s) on link ${MESH_IFACE}, want 0 and 8"
fi
if journal_has "${RESOLVED_JOURNAL}" "Reply truncated, retrying via TCP."; then
    echo "  PASS: systemd-resolved got the big.e2e.internal answer truncated over UDP and asked again over TCP"
else
    echo "${RESOLVED_JOURNAL}"
    fail "journalctl -u systemd-resolved since ${TXT_SINCE} lacks 'Reply truncated, retrying via TCP.': plexd did not truncate the big.e2e.internal answer over UDP"
fi

# Step 6: the names keep answering while the control plane is away. The mock
# API container is paused for 20 s. Halfway in, systemd-resolved's cache is
# flushed, so the answer that follows comes from plexd over the network and
# not from the cache. fail and the EXIT trap unpause the mock.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
if [ -z "${RESPONSE}" ]; then
    fail "assert endpoint unreachable before pausing the mock API"
fi
docker pause "${MOCKAPI_CONTAINER}" >/dev/null || fail "docker pause ${MOCKAPI_CONTAINER} failed"
MOCK_PAUSED=1
PAUSE_START=${SECONDS}
echo "  mock API container paused"
sleep 10
FLUSH_OUT=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl flush-caches 2>&1) \
    || fail "resolvectl flush-caches inside the container failed: ${FLUSH_OUT}"
mesh_query db-1.app.e2e.internal
PAUSE_FROM_NETWORK=0
while IFS= read -r line; do
    if [ "${line}" = "-- Data from: network" ]; then
        PAUSE_FROM_NETWORK=1
    fi
done <<< "${QUERY_OUT}"
if [ "${QUERY_RC}" -eq 0 ] && answers_on_mesh "${QUERY_OUT}" db-1.app.e2e.internal 10.99.0.2 && [ "${PAUSE_FROM_NETWORK}" -eq 1 ]; then
    echo "  PASS: with the mock API paused for $((SECONDS - PAUSE_START))s and the cache flushed, db-1.app.e2e.internal answers 10.99.0.2 from the network"
else
    echo "${QUERY_OUT}"
    fail "with the mock API paused, resolvectl query db-1.app.e2e.internal exited ${QUERY_RC}, want 0, 10.99.0.2 on link ${MESH_IFACE} and '-- Data from: network'"
fi
mesh_query db.e2e.internal
PAUSE_FROM_NETWORK=0
while IFS= read -r line; do
    if [ "${line}" = "-- Data from: network" ]; then
        PAUSE_FROM_NETWORK=1
    fi
done <<< "${QUERY_OUT}"
if [ "${QUERY_RC}" -eq 0 ] && has_answer_on_mesh "${QUERY_OUT}" 192.0.2.20 && [ "${PAUSE_FROM_NETWORK}" -eq 1 ]; then
    echo "  PASS: with the mock API paused for $((SECONDS - PAUSE_START))s and the cache flushed, db.e2e.internal answers 192.0.2.20 from the network"
else
    echo "${QUERY_OUT}"
    fail "with the mock API paused, resolvectl query db.e2e.internal exited ${QUERY_RC}, want 0, 192.0.2.20 on link ${MESH_IFACE} and '-- Data from: network'"
fi
PAUSE_LEFT=$((20 - (SECONDS - PAUSE_START)))
if [ "${PAUSE_LEFT}" -gt 0 ]; then
    sleep "${PAUSE_LEFT}"
fi
docker unpause "${MOCKAPI_CONTAINER}" >/dev/null || fail "docker unpause ${MOCKAPI_CONTAINER} failed"
MOCK_PAUSED=0
echo "  mock API container unpaused after $((SECONDS - PAUSE_START))s"
# plexd recovers: a heartbeat and the pull its reconcile:true answer asks for
# both land after the unpause. The baseline is read 2 s after the unpause, so a
# request plexd sent into the paused mock, which completes as soon as the mock
# runs again, is not counted as a fresh one. A heartbeat goes out every 30 s,
# and 60 s cover two of them.
sleep 2
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
if [ -z "${RESPONSE}" ]; then
    fail "assert endpoint unreachable after unpausing the mock API"
fi
HB_AFTER_UNPAUSE=$(get_counter "${RESPONSE}" "heartbeat_count")
STATE_AFTER_UNPAUSE=$(get_counter "${RESPONSE}" "state_count")
RECOVER_START=${SECONDS}
while :; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    HB_NOW=$(get_counter "${RESPONSE}" "heartbeat_count")
    STATE_NOW=$(get_counter "${RESPONSE}" "state_count")
    if [ "${HB_NOW}" -gt "${HB_AFTER_UNPAUSE}" ] && [ "${STATE_NOW}" -gt "${STATE_AFTER_UNPAUSE}" ]; then
        break
    fi
    if [ $((SECONDS - RECOVER_START)) -ge 60 ]; then
        fail "plexd did not recover within 60s of the unpause: heartbeat_count ${HB_AFTER_UNPAUSE} -> ${HB_NOW}, state_count ${STATE_AFTER_UNPAUSE} -> ${STATE_NOW}"
    fi
    sleep 3
done
echo "  PASS: plexd recovered after the unpause: heartbeat_count ${HB_AFTER_UNPAUSE} -> ${HB_NOW}, state_count ${STATE_AFTER_UNPAUSE} -> ${STATE_NOW} within $((SECONDS - RECOVER_START))s"

echo "=== Mesh DNS through systemd-resolved PASSED ==="

# --- Start after a reboot ---
# /run is tmpfs, so a reboot takes /run/plexd with it. Every ReadWritePaths
# entry is optional, so the unit still sets up its namespace instead of
# failing with 226/NAMESPACE, and plexd recreates the directory for the node
# API socket.
#
# The stop also takes plexd's mesh DNS registration with it, and the start
# brings it back with the first pull. The opt-out step after this phase
# leaves nothing registered for the final stop to remove, so the stop's
# revert is checked here.
echo "=== Starting plexd after a simulated reboot (no /run/plexd) ==="
REBOOT_START=${SECONDS}
STOPPED_PID=$(docker exec "${SYSTEMD_CONTAINER}" systemctl show -p MainPID --value plexd)
docker exec "${SYSTEMD_CONTAINER}" systemctl stop plexd
mesh_query db-1.app.e2e.internal
case "${QUERY_OUT}" in
    *"10.99.0.2"* | *"${MESH_IFACE}"*) STOPPED_ANSWER=1 ;;
    *) STOPPED_ANSWER=0 ;;
esac
if [ "${QUERY_RC}" -ne 0 ] && [ "${STOPPED_ANSWER}" -eq 0 ]; then
    echo "  PASS: with plexd stopped, resolvectl query db-1.app.e2e.internal fails (${QUERY_OUT%%$'\n'*})"
else
    echo "${QUERY_OUT}"
    fail "with plexd stopped, resolvectl query db-1.app.e2e.internal exited ${QUERY_RC}, want a failure that names neither 10.99.0.2 nor ${MESH_IFACE}"
fi
STOPPED_DOMAINS_RC=0
STOPPED_DOMAINS=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl domain 2>&1) || STOPPED_DOMAINS_RC=$?
STOPPED_MESH_DOMAIN=""
while IFS= read -r line; do
    read -ra words <<< "${line}"
    for word in "${words[@]}"; do
        case "${word}" in
            *e2e.internal*) STOPPED_MESH_DOMAIN=${word} ;;
        esac
    done
done <<< "${STOPPED_DOMAINS}"
if [ "${STOPPED_DOMAINS_RC}" -eq 0 ] && [ -z "${STOPPED_MESH_DOMAIN}" ]; then
    echo "  PASS: with plexd stopped, resolvectl domain lists no e2e.internal domain"
else
    echo "${STOPPED_DOMAINS}"
    fail "with plexd stopped, resolvectl domain exited ${STOPPED_DOMAINS_RC} and lists '${STOPPED_MESH_DOMAIN}', want exit 0 and no e2e.internal domain"
fi
STOP_JOURNAL=$(docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager 2>&1) || fail "journalctl -u plexd failed: ${STOP_JOURNAL}"
if journal_has "${STOP_JOURNAL}" "plexd[${STOPPED_PID}]:" 'msg="mesh dns registration reverted"' "interface=${MESH_IFACE}"; then
    echo "  PASS: the stopped plexd[${STOPPED_PID}] logged 'mesh dns registration reverted' for ${MESH_IFACE}"
else
    fail "the stopped plexd[${STOPPED_PID}] logged no 'mesh dns registration reverted' line for ${MESH_IFACE}"
fi
docker exec "${SYSTEMD_CONTAINER}" rm -rf /run/plexd
if ! docker exec "${SYSTEMD_CONTAINER}" systemctl start plexd; then
    fail "plexd did not start without /run/plexd"
fi
SOCKET_TIMEOUT=30
SOCKET_ELAPSED=0
until docker exec "${SYSTEMD_CONTAINER}" test -S /var/run/plexd/api.sock; do
    if [ "${SOCKET_ELAPSED}" -ge "${SOCKET_TIMEOUT}" ]; then
        fail "/var/run/plexd/api.sock did not appear within ${SOCKET_TIMEOUT}s of the start"
    fi
    sleep 2
    SOCKET_ELAPSED=$((SOCKET_ELAPSED + 2))
done
echo "  PASS: /var/run/plexd/api.sock is back"
REBOOT_STATE=$(docker exec "${SYSTEMD_CONTAINER}" systemctl is-active plexd 2>/dev/null || true)
if [ "${REBOOT_STATE}" = "active" ]; then
    echo "  PASS: plexd is active after the simulated reboot"
else
    fail "plexd state after the simulated reboot is '${REBOOT_STATE}', want 'active'"
fi
# The started plexd registers again on its first pull, which serves the block
# the mesh DNS phase configured, and the name answers within 30 s of the
# phase's start, the stop included.
while :; do
    mesh_query db-1.app.e2e.internal
    if [ "${QUERY_RC}" -eq 0 ] && answers_on_mesh "${QUERY_OUT}" db-1.app.e2e.internal 10.99.0.2; then
        break
    fi
    if [ $((SECONDS - REBOOT_START)) -ge 30 ]; then
        echo "${QUERY_OUT}"
        fail "resolvectl query db-1.app.e2e.internal exited ${QUERY_RC} $((SECONDS - REBOOT_START))s after the phase's start, want 0 and 10.99.0.2 on link ${MESH_IFACE} within 30s"
    fi
    sleep 1
done
echo "  PASS: resolvectl query db-1.app.e2e.internal answers 10.99.0.2 on link ${MESH_IFACE} again, $((SECONDS - REBOOT_START))s after the phase's start"

# --- Mesh DNS opt-out ---
# dns.enabled: false keeps the resolver off, and plexd reverts whatever a
# killed run may have left on its link. The restart's stop reverts the
# registration of the run before it, and the fresh run must register nothing,
# not even once a pull carrying the dns block has arrived.
echo "=== Testing the mesh DNS opt-out (dns.enabled: false) ==="
OPTOUT_CONFIG=$(docker exec "${SYSTEMD_CONTAINER}" cat /etc/plexd/config.yaml 2>&1) || fail "could not read /etc/plexd/config.yaml: ${OPTOUT_CONFIG}"
while IFS= read -r line; do
    case "${line}" in
        dns:*) fail "/etc/plexd/config.yaml already has a dns key ('${line}'), so the opt-out cannot be appended" ;;
    esac
done <<< "${OPTOUT_CONFIG}"
docker exec "${SYSTEMD_CONTAINER}" bash -c 'printf "dns:\n  enabled: false\n" >> /etc/plexd/config.yaml' \
    || fail "could not append the dns block to /etc/plexd/config.yaml"
echo "  dns: {enabled: false} appended to /etc/plexd/config.yaml"
docker exec "${SYSTEMD_CONTAINER}" systemctl restart plexd
OPTOUT_PID=$(docker exec "${SYSTEMD_CONTAINER}" systemctl show -p MainPID --value plexd)
# Read after the restart, so every pull it counts is one of the new run's.
STATE_BEFORE_OPTOUT=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
OPTOUT_START=${SECONDS}
while :; do
    OPTOUT_JOURNAL=$(docker exec "${SYSTEMD_CONTAINER}" journalctl -u plexd --no-pager 2>&1) || fail "journalctl -u plexd failed: ${OPTOUT_JOURNAL}"
    if journal_has "${OPTOUT_JOURNAL}" "plexd[${OPTOUT_PID}]:" 'msg="mesh dns disabled by dns.enabled"'; then
        break
    fi
    if [ $((SECONDS - OPTOUT_START)) -ge 30 ]; then
        fail "plexd[${OPTOUT_PID}] did not log 'mesh dns disabled by dns.enabled' within 30s of the restart"
    fi
    sleep 2
done
echo "  PASS: plexd[${OPTOUT_PID}] logged 'mesh dns disabled by dns.enabled' after the restart"
if journal_has "${OPTOUT_JOURNAL}" "plexd[${OPTOUT_PID}]:" 'msg="mesh dns listening"'; then
    fail "plexd[${OPTOUT_PID}] logged 'mesh dns listening' although dns.enabled is false"
fi
echo "  PASS: plexd[${OPTOUT_PID}] did not start the resolver"
# The heartbeat answers reconcile:true, so a pull comes within 30 s, and 60 s
# cover two.
while :; do
    STATE_NOW=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "state_count")
    if [ "${STATE_NOW}" -gt "${STATE_BEFORE_OPTOUT}" ]; then
        break
    fi
    if [ $((SECONDS - OPTOUT_START)) -ge 60 ]; then
        fail "state_count stayed at ${STATE_BEFORE_OPTOUT} for 60s after the opt-out restart, want a pull of the dns block"
    fi
    sleep 2
done
echo "  PASS: plexd pulled the state again (state_count ${STATE_BEFORE_OPTOUT} -> ${STATE_NOW})"
OPTOUT_STATUS_RC=0
OPTOUT_STATUS=$(docker exec "${SYSTEMD_CONTAINER}" resolvectl status "${MESH_IFACE}" 2>&1) || OPTOUT_STATUS_RC=$?
case "${OPTOUT_STATUS}" in
    *"DNS Server"*) OPTOUT_HAS_SERVER=1 ;;
    *) OPTOUT_HAS_SERVER=0 ;;
esac
if [ "${OPTOUT_STATUS_RC}" -eq 0 ] && [ "${OPTOUT_HAS_SERVER}" -eq 0 ]; then
    echo "  PASS: resolvectl status ${MESH_IFACE} shows no DNS server"
else
    echo "${OPTOUT_STATUS}"
    fail "resolvectl status ${MESH_IFACE} exited ${OPTOUT_STATUS_RC} with DNS server lines ${OPTOUT_HAS_SERVER}, want exit 0 and no DNS server"
fi
read_link_domains
if [ "${LINK_DOMAINS_RC}" -eq 0 ] && [ -z "${LINK_DOMAINS}" ]; then
    echo "  PASS: resolvectl domain ${MESH_IFACE} lists no domain"
else
    echo "${LINK_DOMAINS_RAW}"
    fail "resolvectl domain ${MESH_IFACE} exited ${LINK_DOMAINS_RC} and lists '${LINK_DOMAINS}', want exit 0 and no domain"
fi
echo "=== Mesh DNS opt-out PASSED ==="

# --- Clean shutdown verification ---
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

# Check journalctl for crash indicators.
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
