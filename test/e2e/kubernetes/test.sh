#!/usr/bin/env bash
# Kubernetes E2E test orchestration script.
# Uses kind to create a local cluster, deploys the mock-api and plexd as a
# DaemonSet, then polls the mock-api assertion endpoint to verify plexd
# performed registration, heartbeat, and metadata calls.
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
kubectl -n "${NAMESPACE}" apply -f "${DAEMONSET_DIR}/serviceaccount.yaml" --dry-run=client -o yaml \
    | sed "s/namespace: plexd-system/namespace: ${NAMESPACE}/" \
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
  baseurl: http://mock-api.plexd-e2e:8080

registration:
  datadir: /var/lib/plexd

node_api:
  datadir: /var/lib/plexd

heartbeat:
  nodeid: e2e-k8s-node
CONFIGEOF
)"

echo "=== Deploying mock-api ==="
kubectl apply -f "${MOCKAPI_MANIFEST}"

echo "=== Deploying plexd DaemonSet ==="
kubectl -n "${NAMESPACE}" apply -f "${DAEMONSET_DIR}/daemonset.yaml" --dry-run=client -o yaml \
    | sed "s/namespace: plexd-system/namespace: ${NAMESPACE}/" \
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

echo "=== Polling assertion endpoint ==="
ASSERT_URL="http://localhost:18080/test/assertions"
POLL_TIMEOUT=60
POLL_ELAPSED=0

while [ "${POLL_ELAPSED}" -lt "${POLL_TIMEOUT}" ]; do
    RESPONSE=$(curl -sf "${ASSERT_URL}" 2>/dev/null || true)
    if [ -n "${RESPONSE}" ]; then
        REG_COUNT=$(echo "${RESPONSE}" | jq -r '.registration_count // 0')
        HB_COUNT=$(echo "${RESPONSE}" | jq -r '.heartbeat_count // 0')

        if [ "${REG_COUNT}" -ge 1 ] && [ "${HB_COUNT}" -ge 1 ]; then
            echo "=== PASS ==="
            echo "  PASS: registration_count=${REG_COUNT} >= 1"
            echo "  PASS: heartbeat_count=${HB_COUNT} >= 1"
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
    REG_COUNT=$(echo "${RESPONSE}" | jq -r '.registration_count // 0')
    HB_COUNT=$(echo "${RESPONSE}" | jq -r '.heartbeat_count // 0')
    echo "  FAIL: registration_count=${REG_COUNT} (want >= 1)"
    echo "  FAIL: heartbeat_count=${HB_COUNT} (want >= 1)"
fi
print_diagnostics
exit 1
