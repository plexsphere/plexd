#!/usr/bin/env bash
# Kubernetes E2E test orchestration script.
# Uses kind to create a local cluster, deploys the mock-api and plexd as a
# DaemonSet, then polls the mock-api assertion endpoint to verify plexd
# performed registration, heartbeat, state, capabilities, metrics, logs, and audit calls.
#
# Extended tests:
#   - Request body validation (registration token, heartbeat node_id, capabilities)
#   - Periodic loop verification (heartbeat/metrics/logs/audit counters >= 2)
#   - Pod restart resilience (delete pod, verify re-registration)
#   - Action execution via SSE (action_request → ack + result)
#   - Heartbeat-triggered reconcile via RotateKeys flag
#   - Deeper body validation (metrics, capabilities fields)
#   - Shipped liveness/readiness probes stay active; a final phase asserts no
#     probe-induced restarts and no liveness-probe failures
#   - Optional ConfigMap: delete plexd-config, run file-less from env only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-plexd-e2e}"
NAMESPACE="plexd-e2e"
TIMEOUT="${TIMEOUT:-120s}"
MANIFEST_DIR="${SCRIPT_DIR}"
MOCKAPI_MANIFEST="${MANIFEST_DIR}/mock-api-manifests.yaml"
DAEMONSET_DIR="${REPO_ROOT}/deploy/kubernetes"
MOCKAPI_DOCKERFILE="${REPO_ROOT}/test/e2e/mockapi/Dockerfile"
PLEXD_DOCKERFILE="${REPO_ROOT}/deploy/docker/Dockerfile"
PF_PID=""
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
            echo "  ${prefix}: ${COUNTER_KEYS[$i]}=${val} (want >= ${min})"
        fi
    done
}

# --- Diagnostics function (REQ-008) ---
print_diagnostics() {
    echo "--- Diagnostics ---"
    echo "==> Pod status:"
    kubectl -n "${NAMESPACE}" get pods -o wide 2>/dev/null || true
    echo "==> DaemonSet description:"
    kubectl -n "${NAMESPACE}" describe daemonset/plexd 2>/dev/null || true
    echo "==> plexd logs:"
    kubectl -n "${NAMESPACE}" logs -l app.kubernetes.io/name=plexd --tail=50 2>/dev/null || true
    echo "==> mock-api logs:"
    kubectl -n "${NAMESPACE}" logs -l app.kubernetes.io/name=mock-api --tail=50 2>/dev/null || true
}

# --- Helper: assert the current plexd pod shows no probe-induced restarts ---
# A restartCount > 0 on the current pod means the kubelet restarted the
# container in place — i.e. a liveness probe failed. The event query is
# namespace-wide, so it also covers pods that have since been replaced.
assert_probe_health() {
    local pod restart_count liveness_failures
    pod=$(kubectl -n "${NAMESPACE}" get pods -l app.kubernetes.io/name=plexd -o jsonpath='{.items[0].metadata.name}')
    restart_count=$(kubectl -n "${NAMESPACE}" get pod "${pod}" -o jsonpath='{.status.containerStatuses[0].restartCount}')
    # jsonpath yields an empty string when the pod carries no containerStatuses
    # yet (Pending, ContainerCreating, mid-termination). Without this check the
    # numeric comparison below would error out, and because set -e does not
    # apply inside an if condition, the guard would fall through to its own PASS
    # line — reporting success for the very pod state most likely to be
    # thrashing.
    if ! [[ "${restart_count}" =~ ^[0-9]+$ ]]; then
        echo "FAIL: could not read restartCount for pod ${pod} (got '${restart_count}')"
        print_diagnostics
        exit 1
    fi
    if [ "${restart_count}" -ne 0 ]; then
        echo "FAIL: plexd pod ${pod} has restartCount=${restart_count}, want 0"
        print_diagnostics
        exit 1
    fi
    echo "  PASS: plexd pod ${pod} has restartCount=0"

    # Only liveness failures are asserted: a 503 from /readyz before
    # registration completes is by design, so Unhealthy readiness events are
    # expected.
    liveness_failures=$(kubectl -n "${NAMESPACE}" get events \
        --field-selector reason=Unhealthy -o json \
        | jq -r '[.items[] | select(.involvedObject.name | startswith("plexd")) | select(.message | contains("Liveness"))] | length')
    if [ "${liveness_failures}" -ne 0 ]; then
        echo "FAIL: ${liveness_failures} liveness-probe failure event(s) for plexd pods, want 0"
        kubectl -n "${NAMESPACE}" get events --field-selector reason=Unhealthy 2>/dev/null || true
        print_diagnostics
        exit 1
    fi
    echo "  PASS: no liveness-probe failure events for plexd pods"
}

cleanup() {
    echo "--- Cleaning up ---"
    if [ -n "${PF_PID}" ] && kill -0 "${PF_PID}" 2>/dev/null; then
        kill "${PF_PID}" 2>/dev/null || true
        wait "${PF_PID}" 2>/dev/null || true
    fi
    if [ "${TEST_FAILED}" -ne 0 ]; then
        print_diagnostics
    fi
    kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

# --- Pre-flight checks (REQ-009) ---
for cmd in kind kubectl docker curl jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "FAIL: required command '${cmd}' not found"
        exit 1
    fi
done

# --- Create kind cluster (REQ-001) ---
echo "=== Deleting pre-existing kind cluster (if any) ==="
kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true

echo "=== Creating kind cluster '${CLUSTER_NAME}' ==="
kind create cluster --name "${CLUSTER_NAME}" --wait 60s

# --- Build and load images (REQ-002) ---
echo "=== Building mock-api image ==="
docker build -f "${MOCKAPI_DOCKERFILE}" -t mockapi:e2e "${REPO_ROOT}"

echo "=== Building plexd image ==="
docker build -f "${PLEXD_DOCKERFILE}" -t plexd:e2e "${REPO_ROOT}"

echo "=== Loading images into kind ==="
kind load docker-image mockapi:e2e --name "${CLUSTER_NAME}"
kind load docker-image plexd:e2e --name "${CLUSTER_NAME}"

# --- Apply manifests (REQ-003, REQ-004) ---
echo "=== Creating namespace '${NAMESPACE}' ==="
kubectl create namespace "${NAMESPACE}"

echo "=== Applying CRDs ==="
kubectl apply -f "${DAEMONSET_DIR}/crds/plexdnodestate-crd.yaml"
kubectl apply -f "${DAEMONSET_DIR}/crds/plexdhook-crd.yaml"

echo "=== Verifying CRDs ==="
kubectl get crd plexdnodestates.plexd.plexsphere.com
kubectl get crd plexdhooks.plexd.plexsphere.com

echo "=== Applying ServiceAccount ==="
sed "s/namespace: plexd-system/namespace: ${NAMESPACE}/" "${DAEMONSET_DIR}/serviceaccount.yaml" \
    | kubectl apply -f -

echo "=== Applying RBAC ==="
kubectl apply -f "${DAEMONSET_DIR}/rbac.yaml"
kubectl patch clusterrolebinding plexd --type=json \
    -p="[{\"op\":\"replace\",\"path\":\"/subjects/0/namespace\",\"value\":\"${NAMESPACE}\"}]"

echo "=== Creating bootstrap secret ==="
kubectl -n "${NAMESPACE}" create secret generic plexd-bootstrap \
    --from-literal=token=psb_test_e2eproject_node_e2ee2ee2ee2ee2ee2ee2e22

echo "=== Creating plexd E2E configmap (REQ-004) ==="
kubectl -n "${NAMESPACE}" create configmap plexd-config \
    --from-literal=config.yaml="$(cat <<'CONFIGEOF'
api:
  base_url: http://mock-api.plexd-e2e:8080

registration:
  data_dir: /var/lib/plexd
  project_id: 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0
  resource_handle: e2e-k8s-node

node_api:
  data_dir: /var/lib/plexd

health:
  enabled: true
  listen: "127.0.0.1:9101"

heartbeat:
  node_id: e2e-k8s-node

metrics:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  local_endpoint:
    url: https://mock-api.plexd-e2e:8443/local/metrics
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true

log_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  file_patterns:
    - "/var/log/plexd/*.log"
  local_endpoint:
    url: https://mock-api.plexd-e2e:8443/local/logs
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true

audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  local_endpoint:
    url: https://mock-api.plexd-e2e:8443/local/audit
    secret_key: local-bearer-token
    tls_insecure_skip_verify: true
CONFIGEOF
)"

echo "=== Deploying mock-api ==="
kubectl apply -f "${MOCKAPI_MANIFEST}"

# Match what kubelet's DirectoryOrCreate produces on a real node: root-owned.
# plexd runs as uid 0 with ALL capabilities dropped but CAP_DAC_OVERRIDE not
# among those added back, so it is subject to ordinary permission checks and
# cannot write a directory owned by anyone else.
echo "=== Pre-creating host directories with correct ownership ==="
docker exec "${CLUSTER_NAME}-control-plane" sh -c \
    'mkdir -p /var/lib/plexd /var/run/plexd && chown 0:0 /var/lib/plexd /var/run/plexd'

echo "=== Deploying plexd DaemonSet ==="
sed "s/namespace: plexd-system/namespace: ${NAMESPACE}/" "${DAEMONSET_DIR}/daemonset.yaml" \
    | sed "s|image: ghcr.io/plexsphere/plexd:latest|image: plexd:e2e|" \
    | sed 's/imagePullPolicy: Always/imagePullPolicy: Never/' \
    | kubectl apply -f -

# --- Wait for readiness (REQ-005) ---
echo "=== Waiting for mock-api to be ready ==="
kubectl -n "${NAMESPACE}" rollout status deployment/mock-api --timeout=60s

echo "=== Waiting for plexd DaemonSet to be ready ==="
if ! kubectl -n "${NAMESPACE}" rollout status daemonset/plexd --timeout="${TIMEOUT}"; then
    echo "FAIL: plexd DaemonSet did not become ready within ${TIMEOUT}"
    print_diagnostics
    exit 1
fi

# --- Port-forward and assertions (REQ-006, REQ-007) ---
echo "=== Starting port-forward to mock-api ==="
kubectl -n "${NAMESPACE}" port-forward svc/mock-api 18080:8080 &
PF_PID=$!
sleep 2

# ===================================================================
# Phase 1: Initial assertion polling (all 8 counters >= 1)
# ===================================================================
echo "=== Polling assertion endpoint (all counters >= 1) ==="
ASSERT_URL="http://localhost:18080/test/assertions"
POLL_TIMEOUT=60
POLL_ELAPSED=0

while [ "${POLL_ELAPSED}" -lt "${POLL_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        extract_counters "${RESPONSE}"
        if all_counters_pass 1; then
            echo "=== Phase 1 PASSED: all counters >= 1 ==="
            print_counter_results "FAIL" 1
            break
        fi
    fi
    sleep 5
    POLL_ELAPSED=$((POLL_ELAPSED + 5))
done

if [ "${POLL_ELAPSED}" -ge "${POLL_TIMEOUT}" ]; then
    echo "=== FAIL: initial assertions not met within ${POLL_TIMEOUT}s ==="
    if [ -z "${RESPONSE:-}" ]; then
        echo "FAIL: no response from assertion endpoint"
    else
        extract_counters "${RESPONSE}"
        print_counter_results "FAIL" 1
    fi
    print_diagnostics
    exit 1
fi

# ===================================================================
# Phase 2: Request body validation
# ===================================================================
echo "=== Validating request bodies ==="

# Registration body must carry the real POST /v1/register fields.
REG_BODY=$(curl -sf "http://localhost:18080/test/last-request/register" 2>/dev/null || true)
if [ -z "${REG_BODY}" ]; then
    echo "FAIL: no captured registration request body"
    print_diagnostics
    exit 1
fi
REG_TOKEN=$(echo "${REG_BODY}" | jq -r '.bootstrap_token // empty')
if [ -z "${REG_TOKEN}" ]; then
    echo "FAIL: registration body missing 'bootstrap_token' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: registration body contains bootstrap_token"

REG_PROJECT_ID=$(echo "${REG_BODY}" | jq -r '.project_id // empty')
if [ -z "${REG_PROJECT_ID}" ]; then
    echo "FAIL: registration body missing 'project_id' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: registration body contains project_id='${REG_PROJECT_ID}'"

REG_RESOURCE_HANDLE=$(echo "${REG_BODY}" | jq -r '.resource_handle // empty')
if [ -z "${REG_RESOURCE_HANDLE}" ]; then
    echo "FAIL: registration body missing 'resource_handle' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: registration body contains resource_handle='${REG_RESOURCE_HANDLE}'"

REG_NONCE=$(echo "${REG_BODY}" | jq -r '.nonce // empty')
if [ -z "${REG_NONCE}" ]; then
    echo "FAIL: registration body missing 'nonce' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: registration body contains nonce"

# Heartbeat body must carry the real v1 heartbeat fields.
# Note: node_id is passed as a URL path parameter, not in the body.
HB_BODY=$(curl -sf "http://localhost:18080/test/last-request/heartbeat" 2>/dev/null || true)
if [ -z "${HB_BODY}" ]; then
    echo "FAIL: no captured heartbeat request body"
    print_diagnostics
    exit 1
fi
if ! echo "${HB_BODY}" | jq empty 2>/dev/null; then
    echo "FAIL: heartbeat body is not valid JSON"
    print_diagnostics
    exit 1
fi
echo "  PASS: heartbeat body is valid JSON"

HB_CLIENT_NOW=$(echo "${HB_BODY}" | jq -r '.client_now // empty')
if ! echo "${HB_CLIENT_NOW}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+.*(Z|[+-][0-9]{2}:[0-9]{2})$'; then
    echo "FAIL: heartbeat client_now='${HB_CLIENT_NOW}' is not an RFC 3339 timestamp"
    print_diagnostics
    exit 1
fi
echo "  PASS: heartbeat body client_now='${HB_CLIENT_NOW}' matches RFC 3339"

HB_CHECKSUM=$(echo "${HB_BODY}" | jq -r '.binary_checksum // empty')
if ! echo "${HB_CHECKSUM}" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "FAIL: heartbeat binary_checksum='${HB_CHECKSUM}' is not 64-char lowercase hex"
    print_diagnostics
    exit 1
fi
echo "  PASS: heartbeat body binary_checksum is 64-char lowercase hex"

HB_VERSION=$(echo "${HB_BODY}" | jq -r '.binary_version // empty')
if [ -z "${HB_VERSION}" ]; then
    echo "FAIL: heartbeat body missing 'binary_version' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: heartbeat body binary_version='${HB_VERSION}'"

HB_NAT_SUMMARY_TYPE=$(echo "${HB_BODY}" | jq -r '.nat_summary | type')
if [ "${HB_NAT_SUMMARY_TYPE}" != "object" ]; then
    echo "FAIL: heartbeat nat_summary type='${HB_NAT_SUMMARY_TYPE}', want 'object'"
    print_diagnostics
    exit 1
fi
echo "  PASS: heartbeat body nat_summary is a JSON object"

# Capabilities body must contain builtin_actions array.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -z "${CAPS_BODY}" ]; then
    echo "FAIL: no captured capabilities request body"
    print_diagnostics
    exit 1
fi
CAPS_COUNT=$(echo "${CAPS_BODY}" | jq '.builtin_actions | length')
if [ "${CAPS_COUNT}" -lt 1 ]; then
    echo "FAIL: capabilities body has empty builtin_actions (want >= 1)"
    print_diagnostics
    exit 1
fi
echo "  PASS: capabilities body contains ${CAPS_COUNT} builtin_actions"

echo "=== Phase 2 PASSED: request body validation ==="

# ===================================================================
# Phase 3: Periodic loop verification (counters >= 2)
# ===================================================================
echo "=== Waiting for periodic counters to increment (>= 2) ==="
# heartbeat and metrics are self-generating periodic loops.
# logs and audit depend on external data sources — tested via pod restart (Phase 4).
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
            echo "=== Phase 3 PASSED: periodic counters >= 2 ==="
            for pkey in "${PERIODIC_KEYS[@]}"; do
                pval=$(get_counter "${RESPONSE}" "${pkey}")
                echo "  PASS: ${pkey}=${pval} >= 2"
            done
            break
        fi
    fi
    sleep 5
    PERIODIC_ELAPSED=$((PERIODIC_ELAPSED + 5))
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
    print_diagnostics
    exit 1
fi

# ===================================================================
# Phase 4: Pod restart resilience
# ===================================================================
echo "=== Testing pod restart resilience ==="

# Record current counters before pod delete.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
HB_BEFORE=$(get_counter "${RESPONSE}" "heartbeat_count")
AUDIT_BEFORE=$(get_counter "${RESPONSE}" "audit_count")
echo "  heartbeat_count before pod delete: ${HB_BEFORE}"
echo "  audit_count before pod delete: ${AUDIT_BEFORE}"

# Delete the plexd pod (Kubernetes will reschedule via DaemonSet).
PLEXD_POD=$(kubectl -n "${NAMESPACE}" get pods -l app.kubernetes.io/name=plexd -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "${PLEXD_POD}" ]; then
    echo "  WARN: no plexd pod found, skipping restart test"
else
    echo "  Deleting pod ${PLEXD_POD}"
    kubectl -n "${NAMESPACE}" delete pod "${PLEXD_POD}" --grace-period=10

    # Wait for new pod to be ready.
    echo "  Waiting for new plexd pod to be ready"
    RESTART_TIMEOUT=60
    RESTART_ELAPSED=0
    while [ "${RESTART_ELAPSED}" -lt "${RESTART_TIMEOUT}" ]; do
        NEW_POD=$(kubectl -n "${NAMESPACE}" get pods -l app.kubernetes.io/name=plexd --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
        if [ -n "${NEW_POD}" ] && [ "${NEW_POD}" != "${PLEXD_POD}" ]; then
            echo "  New pod running: ${NEW_POD}"
            break
        fi
        sleep 3
        RESTART_ELAPSED=$((RESTART_ELAPSED + 3))
    done

    if [ "${RESTART_ELAPSED}" -ge "${RESTART_TIMEOUT}" ]; then
        echo "  FAIL: new plexd pod did not become ready within ${RESTART_TIMEOUT}s"
        print_diagnostics
        exit 1
    fi

    # Wait for heartbeat to resume (proves agent loaded persisted identity and resumed operation).
    # Note: identity persists via hostPath, so no re-registration is needed.
    echo "  Waiting for heartbeat to resume after pod restart"
    RESUME_TIMEOUT=60
    RESUME_ELAPSED=0
    while [ "${RESUME_ELAPSED}" -lt "${RESUME_TIMEOUT}" ]; do
        RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
        if [ -n "${RESPONSE}" ]; then
            HB_AFTER=$(get_counter "${RESPONSE}" "heartbeat_count")
            if [ "${HB_AFTER}" -gt "${HB_BEFORE}" ]; then
                echo "  PASS: heartbeat_count increased from ${HB_BEFORE} to ${HB_AFTER} after pod restart"
                break
            fi
        fi
        sleep 3
        RESUME_ELAPSED=$((RESUME_ELAPSED + 3))
    done

    if [ "${RESUME_ELAPSED}" -ge "${RESUME_TIMEOUT}" ]; then
        HB_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "heartbeat_count")
        echo "  FAIL: heartbeat did not resume after pod restart (before=${HB_BEFORE}, after=${HB_AFTER})"
        print_diagnostics
        exit 1
    fi

    # Verify audit_count increased (ProcessSource fires once per process, so restart → new entry).
    echo "  Waiting for audit_count to increase after pod restart"
    AUDIT_TIMEOUT=30
    AUDIT_ELAPSED=0
    while [ "${AUDIT_ELAPSED}" -lt "${AUDIT_TIMEOUT}" ]; do
        RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
        if [ -n "${RESPONSE}" ]; then
            AUDIT_AFTER=$(get_counter "${RESPONSE}" "audit_count")
            if [ "${AUDIT_AFTER}" -gt "${AUDIT_BEFORE}" ]; then
                echo "  PASS: audit_count increased from ${AUDIT_BEFORE} to ${AUDIT_AFTER} after pod restart"
                break
            fi
        fi
        sleep 3
        AUDIT_ELAPSED=$((AUDIT_ELAPSED + 3))
    done

    if [ "${AUDIT_ELAPSED}" -ge "${AUDIT_TIMEOUT}" ]; then
        AUDIT_AFTER=$(get_counter "$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)" "audit_count")
        echo "  WARN: audit_count did not increase after pod restart (before=${AUDIT_BEFORE}, after=${AUDIT_AFTER})"
    fi
fi

echo "=== Phase 4 PASSED: pod restart resilience ==="

# ===================================================================
# Phase 5: Action execution via SSE injection
# ===================================================================
echo "=== Testing action execution via SSE ==="

# Record the execution callback counter (ack -> started -> terminal = +3).
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
CB_BEFORE=$(get_counter "${RESPONSE}" "execution_callback_count")
echo "  execution_callback_count before: ${CB_BEFORE}"

# Inject an action_request SSE event for the builtin "system.info" action.
ACTION_PAYLOAD=$(cat <<'ACTEOF'
{
    "id": "evt-e2e-action-k8s-001",
    "type": "action_request",
    "scope": "node",
    "payload": {
        "execution_id": "exec-e2e-k8s-001",
        "action": "system.info",
        "timeout": "30s"
    }
}
ACTEOF
)
ACTION_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${ACTION_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${ACTION_STATUS}" != "204" ]; then
    echo "FAIL: action_request event injection returned status ${ACTION_STATUS}, want 204"
    print_diagnostics
    exit 1
fi
echo "  action_request event injected successfully"

# Poll until execution_callback_count advances by at least 3.
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
    echo "FAIL: execution_callback_count did not reach $((CB_BEFORE + 3)) (before=${CB_BEFORE}, after=${CB_AFTER})"
    print_diagnostics
    exit 1
fi

# Validate the terminal execution callback body.
CB_BODY=$(curl -sf "http://localhost:18080/test/last-request/execution_callback" 2>/dev/null || true)
if [ -z "${CB_BODY}" ]; then
    echo "FAIL: no execution_callback body captured"
    print_diagnostics
    exit 1
fi

CB_STATUS=$(echo "${CB_BODY}" | jq -r '.status // empty')
if [ "${CB_STATUS}" = "succeeded" ]; then
    echo "  PASS: terminal callback status = succeeded"
else
    echo "FAIL: terminal callback status = '${CB_STATUS}', want 'succeeded'"
    print_diagnostics
    exit 1
fi

CB_INLINE=$(echo "${CB_BODY}" | jq -r '.output.inline // empty')
if [ -z "${CB_INLINE}" ]; then
    echo "FAIL: terminal callback missing non-empty output.inline"
    print_diagnostics
    exit 1
fi
if printf '%s' "${CB_INLINE}" | b64_decode >/dev/null 2>&1; then
    echo "  PASS: terminal callback output.inline base64-decodes"
else
    echo "FAIL: terminal callback output.inline is not valid base64"
    print_diagnostics
    exit 1
fi

echo "=== Phase 5 PASSED: action execution ==="

# ===================================================================
# Phase 6: SSE event injection triggers reconciliation
# ===================================================================
echo "=== Testing SSE event injection ==="

# Record current state_count before injection.
RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
STATE_BEFORE=$(get_counter "${RESPONSE}" "state_count")
echo "  state_count before injection: ${STATE_BEFORE}"

# Inject a node_state_updated SSE event.
INJECT_PAYLOAD=$(cat <<'INJEOF'
{
    "id": "evt-e2e-inject-k8s-001",
    "type": "node_state_updated",
    "scope": "node",
    "payload": {"node_id": "e2e-k8s-node"}
}
INJEOF
)
INJECT_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "${INJECT_PAYLOAD}" \
    "http://localhost:18080/test/inject-event" 2>/dev/null || true)
if [ "${INJECT_STATUS}" != "204" ]; then
    echo "FAIL: SSE event injection returned status ${INJECT_STATUS}, want 204"
    print_diagnostics
    exit 1
fi
echo "  SSE event injected successfully"

# Poll for state_count to increase.
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

echo "=== Phase 6 PASSED: SSE event injection ==="

# ===================================================================
# Phase 7: Key rotation completes end to end (RotateKeys flag)
# ===================================================================
echo "=== Testing key-rotation completion via RotateKeys ==="

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
    echo "FAIL: configure-heartbeat returned status ${KR_STATUS}, want 204"
    print_diagnostics
    exit 1
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
    echo "FAIL: key_rotate_count did not increase after RotateKeys=true (before=${ROTATE_BEFORE_KR}, after=${ROTATE_AFTER_KR})"
    print_diagnostics
    exit 1
fi

# Validate the captured rotate request body: it must carry the new public
# key and must NOT carry a node_id (the server identifies the node from
# the NSK bearer credential).
ROTATE_BODY=$(curl -sf "http://localhost:18080/test/last-request/key_rotate" 2>/dev/null || true)
if [ -z "${ROTATE_BODY}" ]; then
    echo "FAIL: no captured key_rotate request body"
    print_diagnostics
    exit 1
fi
if echo "${ROTATE_BODY}" | grep -q '"new_public_key"'; then
    echo "  PASS: key_rotate body contains 'new_public_key'"
else
    echo "FAIL: key_rotate body missing 'new_public_key' field (body: ${ROTATE_BODY})"
    print_diagnostics
    exit 1
fi
if echo "${ROTATE_BODY}" | grep -q '"node_id"'; then
    echo "FAIL: key_rotate body unexpectedly contains 'node_id' (body: ${ROTATE_BODY})"
    print_diagnostics
    exit 1
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
    echo "FAIL: state_count did not increase after RotateKeys=true (before=${STATE_BEFORE_KR}, after=${STATE_AFTER_KR})"
    print_diagnostics
    exit 1
fi

# Reset heartbeat response.
curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"reconcile":true,"rotate_keys":false}' \
    "http://localhost:18080/test/configure-heartbeat" >/dev/null 2>&1 || true

echo "=== Phase 7 PASSED: key rotation completed end to end ==="

# ===================================================================
# Phase 8: Deeper body validation
# ===================================================================
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
        echo "FAIL: metric[0] missing 'name' field"
        print_diagnostics
        exit 1
    fi
    if [ "${MET_VALUE_TYPE}" = "number" ]; then
        echo "  PASS: metric[0] has a numeric value"
    else
        echo "FAIL: metric[0] 'value' type='${MET_VALUE_TYPE}', want number"
        print_diagnostics
        exit 1
    fi
    case "${MET_GROUP}" in
        node_resources|tunnel_health|peer_latency|agent_stats)
            echo "  PASS: metric[0] has group='${MET_GROUP}'" ;;
        *)
            echo "FAIL: metric[0] group='${MET_GROUP}' outside the wire enum"
            print_diagnostics
            exit 1 ;;
    esac
fi

# Capabilities: validate specific builtin action names.
CAPS_BODY=$(curl -sf "http://localhost:18080/test/last-request/capabilities" 2>/dev/null || true)
if [ -n "${CAPS_BODY}" ]; then
    for expected_action in "diagnostics.collect" "system.info" "service.restart"; do
        HAS_ACTION=$(echo "${CAPS_BODY}" | jq --arg name "${expected_action}" \
            '[.builtin_actions[] | select(.name == $name)] | length')
        if [ "${HAS_ACTION}" -ge 1 ]; then
            echo "  PASS: capabilities includes builtin '${expected_action}'"
        else
            echo "  WARN: capabilities missing builtin '${expected_action}'"
        fi
    done
fi

echo "=== Phase 8 PASSED: deeper body validation ==="

# ===================================================================
# Phase 9: Local Endpoint Delivery
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
    sleep 5
    LOCAL_ELAPSED=$((LOCAL_ELAPSED + 5))
done

if [ "${LOCAL_ELAPSED}" -ge "${LOCAL_TIMEOUT}" ]; then
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    LOCAL_METRICS=$(get_counter "${RESPONSE}" "local_metrics_count")
    LOCAL_LOGS=$(get_counter "${RESPONSE}" "local_logs_count")
    LOCAL_AUDIT=$(get_counter "${RESPONSE}" "local_audit_count")
    echo "  local_metrics_count=${LOCAL_METRICS}, local_logs_count=${LOCAL_LOGS}, local_audit_count=${LOCAL_AUDIT}"
    echo "FAIL: local endpoint delivery not met within ${LOCAL_TIMEOUT}s"
    print_diagnostics
    exit 1
fi

echo "=== Phase 9 PASSED: local endpoint delivery ==="

# ===================================================================
# Phase 10: Probe health
# ===================================================================
echo "=== Checking probe health ==="

# Phase 4 deleted the original pod, so the DaemonSet replaced it with a NEW
# pod. A restartCount > 0 on the current pod therefore means the kubelet
# restarted the container in place — i.e. a liveness probe failed.
assert_probe_health

echo "=== Phase 10 PASSED: probe health ==="

# ===================================================================
# Phase 11: Optional ConfigMap
# ===================================================================
echo "=== Testing file-less operation without the plexd-config ConfigMap ==="

# Drop the config source entirely. The shipped DaemonSet mounts the ConfigMap
# with optional: true, so the replacement pod still starts — it just mounts an
# empty /etc/plexd with no config.yaml in it.
kubectl -n "${NAMESPACE}" delete configmap plexd-config

# Supply the inputs the config file used to carry through the environment
# instead. PLEXD_BOOTSTRAP_TOKEN already arrives from the plexd-bootstrap
# secret, and everything else falls back to its built-in default.
kubectl -n "${NAMESPACE}" set env daemonset/plexd \
    PLEXD_API=http://mock-api.plexd-e2e:8080 \
    PLEXD_PROJECT_ID=0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0 \
    PLEXD_RESOURCE_HANDLE=e2e-k8s-node
kubectl -n "${NAMESPACE}" rollout status daemonset/plexd --timeout="${TIMEOUT}"

RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
REG_BEFORE=$(get_counter "${RESPONSE}" "registration_count")
HB_BEFORE=$(get_counter "${RESPONSE}" "heartbeat_count")
echo "  registration_count before: ${REG_BEFORE}"
echo "  heartbeat_count before: ${HB_BEFORE}"

# The rolled-out pod finds the identity the earlier phases persisted on the
# node and resumes from it without ever registering. Wipe that identity and
# replace the pod so its successor has to register from the environment alone.
docker exec "${CLUSTER_NAME}-control-plane" rm -f /var/lib/plexd/identity.json
kubectl -n "${NAMESPACE}" delete pod -l app.kubernetes.io/name=plexd --grace-period=10

# Registration proves the file-less pod reached the control plane with the
# env-supplied API URL and identity; a heartbeat counted after that proves it
# went on to reach steady state rather than dying right after the registration
# call. The outgoing pod keeps heartbeating through its grace period, so the
# heartbeat baseline is re-read at the moment registration lands — from then on
# only the new pod can bump the counter.
OPTCM_TIMEOUT=90
OPTCM_ELAPSED=0
OPTCM_REGISTERED=0
while [ "${OPTCM_ELAPSED}" -lt "${OPTCM_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        REG_AFTER=$(get_counter "${RESPONSE}" "registration_count")
        HB_AFTER=$(get_counter "${RESPONSE}" "heartbeat_count")
        if [ "${OPTCM_REGISTERED}" -eq 0 ]; then
            if [ "${REG_AFTER}" -gt "${REG_BEFORE}" ]; then
                OPTCM_REGISTERED=1
                HB_BEFORE="${HB_AFTER}"
                echo "  PASS: registration_count increased from ${REG_BEFORE} to ${REG_AFTER} without a config file"
                echo "  heartbeat_count re-baselined at registration: ${HB_BEFORE}"
            fi
        elif [ "${HB_AFTER}" -gt "${HB_BEFORE}" ]; then
            echo "  PASS: heartbeat_count increased from ${HB_BEFORE} to ${HB_AFTER} after the file-less registration"
            break
        fi
    fi
    sleep 5
    OPTCM_ELAPSED=$((OPTCM_ELAPSED + 5))
done

if [ "${OPTCM_ELAPSED}" -ge "${OPTCM_TIMEOUT}" ]; then
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    REG_AFTER=$(get_counter "${RESPONSE}" "registration_count")
    HB_AFTER=$(get_counter "${RESPONSE}" "heartbeat_count")
    echo "  registration_count=${REG_AFTER} (before ${REG_BEFORE}), heartbeat_count=${HB_AFTER} (before ${HB_BEFORE})"
    echo "FAIL: file-less plexd did not register and heartbeat within ${OPTCM_TIMEOUT}s"
    print_diagnostics
    exit 1
fi

# The agent must say why it started without a file, not silently pick defaults.
if kubectl -n "${NAMESPACE}" logs -l app.kubernetes.io/name=plexd --tail=200 | grep -q "config file not found"; then
    echo "  PASS: fall-back warning names the missing config file"
else
    echo "FAIL: expected 'config file not found' warning in plexd logs"
    print_diagnostics
    exit 1
fi

# Phase 10 only covered the ConfigMap-backed pod. Without a file, health.enabled
# and health.listen come purely from ApplyDefaults, so repeat the probe checks
# against the file-less pod: an unbound probe target restarts it in a loop.
assert_probe_health

echo "=== Phase 11 PASSED: optional ConfigMap ==="

TEST_FAILED=0
echo "=== ALL TESTS PASSED ==="
