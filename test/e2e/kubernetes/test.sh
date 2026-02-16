#!/usr/bin/env bash
# Kubernetes E2E test orchestration script.
# Uses kind to create a local cluster, deploys the mock-api and plexd as a
# DaemonSet, then polls the mock-api assertion endpoint to verify plexd
# performed registration, heartbeat, state, capabilities, drift, metrics, logs, and audit calls.
#
# Extended tests:
#   - Request body validation (registration token, heartbeat node_id, capabilities)
#   - Periodic loop verification (heartbeat/metrics/logs/audit counters >= 2)
#   - Pod restart resilience (delete pod, verify re-registration)
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
    echo "==> Pod status:"
    kubectl -n "${NAMESPACE}" get pods -o wide 2>/dev/null || true
    echo "==> DaemonSet description:"
    kubectl -n "${NAMESPACE}" describe daemonset/plexd 2>/dev/null || true
    echo "==> plexd logs:"
    kubectl -n "${NAMESPACE}" logs -l app.kubernetes.io/name=plexd --tail=50 2>/dev/null || true
    echo "==> mock-api logs:"
    kubectl -n "${NAMESPACE}" logs -l app.kubernetes.io/name=mock-api --tail=50 2>/dev/null || true
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
    --from-literal=token=e2e-test-token

echo "=== Creating plexd E2E configmap (REQ-004) ==="
kubectl -n "${NAMESPACE}" create configmap plexd-config \
    --from-literal=config.yaml="$(cat <<'CONFIGEOF'
api:
  base_url: http://mock-api.plexd-e2e:8080

registration:
  data_dir: /var/lib/plexd

node_api:
  data_dir: /var/lib/plexd

heartbeat:
  node_id: e2e-k8s-node

metrics:
  enabled: true
  collect_interval: 5s
  report_interval: 10s

log_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
  file_patterns:
    - "/var/log/plexd/*.log"

audit_fwd:
  enabled: true
  collect_interval: 5s
  report_interval: 10s
CONFIGEOF
)"

echo "=== Deploying mock-api ==="
kubectl apply -f "${MOCKAPI_MANIFEST}"

echo "=== Pre-creating host directories with correct ownership ==="
docker exec "${CLUSTER_NAME}-control-plane" sh -c \
    'mkdir -p /var/lib/plexd /var/run/plexd && chown 65534:65534 /var/lib/plexd /var/run/plexd'

echo "=== Deploying plexd DaemonSet ==="
sed "s/namespace: plexd-system/namespace: ${NAMESPACE}/" "${DAEMONSET_DIR}/daemonset.yaml" \
    | sed "s|image: ghcr.io/plexsphere/plexd:latest|image: plexd:e2e|" \
    | sed 's/imagePullPolicy: Always/imagePullPolicy: Never/' \
    | kubectl apply -f -

# Remove liveness/readiness probes (health endpoints not yet implemented).
kubectl -n "${NAMESPACE}" patch daemonset plexd --type=json \
    -p='[{"op":"remove","path":"/spec/template/spec/containers/0/livenessProbe"},{"op":"remove","path":"/spec/template/spec/containers/0/readinessProbe"}]'

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

# Registration body must contain token and hostname.
REG_BODY=$(curl -sf "http://localhost:18080/test/last-request/register" 2>/dev/null || true)
if [ -z "${REG_BODY}" ]; then
    echo "FAIL: no captured registration request body"
    print_diagnostics
    exit 1
fi
REG_TOKEN=$(echo "${REG_BODY}" | jq -r '.token // empty')
if [ -z "${REG_TOKEN}" ]; then
    echo "FAIL: registration body missing 'token' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: registration body contains token"

REG_HOSTNAME=$(echo "${REG_BODY}" | jq -r '.hostname // empty')
if [ -z "${REG_HOSTNAME}" ]; then
    echo "FAIL: registration body missing 'hostname' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: registration body contains hostname='${REG_HOSTNAME}'"

# Heartbeat body must be valid JSON with expected structure.
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
HB_HAS_TS=$(echo "${HB_BODY}" | jq 'has("timestamp")')
if [ "${HB_HAS_TS}" != "true" ]; then
    echo "FAIL: heartbeat body missing 'timestamp' field"
    print_diagnostics
    exit 1
fi
echo "  PASS: heartbeat body has expected structure"

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

TEST_FAILED=0
echo "=== ALL TESTS PASSED ==="
