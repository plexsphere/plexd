#!/usr/bin/env bash
# Kubernetes E2E test orchestration script.
# Uses kind to create a local cluster, deploys the mock-api and plexd as a
# DaemonSet, then polls the mock-api assertion endpoint to verify plexd
# performed registration, heartbeat, state, capabilities, drift, metrics, logs, and audit calls.
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

echo "=== Polling assertion endpoint ==="
ASSERT_URL="http://localhost:18080/test/assertions"
POLL_TIMEOUT=60
POLL_ELAPSED=0

while [ "${POLL_ELAPSED}" -lt "${POLL_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        extract_counters "${RESPONSE}"
        if all_counters_pass; then
            echo "=== PASS ==="
            print_counter_results "FAIL"
            TEST_FAILED=0
            exit 0
        fi
    fi
    sleep 5
    POLL_ELAPSED=$((POLL_ELAPSED + 5))
done

echo "=== FAIL: assertions not met within ${POLL_TIMEOUT}s ==="
if [ -z "${RESPONSE:-}" ]; then
    echo "FAIL: no response from assertion endpoint"
else
    extract_counters "${RESPONSE}"
    print_counter_results "FAIL"
fi
print_diagnostics
exit 1
