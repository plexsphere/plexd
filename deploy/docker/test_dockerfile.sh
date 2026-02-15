#!/bin/sh
# Tests for deploy/docker/Dockerfile
# Run: sh deploy/docker/test_dockerfile.sh
#
# Prerequisites: docker, hadolint (optional)
# The script builds the image once and runs all validation tests against it.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile"
IMAGE_TAG="plexd-test:$$"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
    printf "  PASS: %s\n" "$1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
    printf "  FAIL: %s\n" "$1"
}

cleanup() {
    for tag in "${IMAGE_TAG}" "${IMAGE_TAG}-version"; do
        if docker image inspect "${tag}" >/dev/null 2>&1; then
            docker rmi "${tag}" >/dev/null 2>&1 || true
        fi
    done
}
trap cleanup EXIT

# --- Tests ---

test_hadolint_passes() {
    if command -v hadolint >/dev/null 2>&1; then
        if hadolint "${DOCKERFILE}"; then
            pass "hadolint passes with no errors"
        else
            fail "hadolint reported errors"
        fi
    else
        pass "hadolint not installed (skipped)"
    fi
}

test_module_cache_layer() {
    # Verify COPY go.mod go.sum appears before COPY . .
    gomod_line=$(grep -n "COPY go\.mod go\.sum" "${DOCKERFILE}" | head -1 | cut -d: -f1)
    copyall_line=$(grep -n "COPY \. \." "${DOCKERFILE}" | head -1 | cut -d: -f1)
    if [ -n "${gomod_line}" ] && [ -n "${copyall_line}" ] && [ "${gomod_line}" -lt "${copyall_line}" ]; then
        pass "module cache layer: COPY go.mod go.sum before COPY . ."
    else
        fail "module cache layer: COPY go.mod go.sum must appear before COPY . ."
    fi
}

test_docker_build_succeeds() {
    if docker build -f "${DOCKERFILE}" -t "${IMAGE_TAG}" "${REPO_ROOT}"; then
        pass "docker build succeeds"
    else
        fail "docker build failed"
        exit 1
    fi
}

test_version_args_injected() {
    if docker build -f "${DOCKERFILE}" \
        --build-arg VERSION=1.0.0-test \
        --build-arg COMMIT=abc1234 \
        --build-arg DATE=2026-01-01T00:00:00Z \
        -t "${IMAGE_TAG}-version" "${REPO_ROOT}" >/dev/null 2>&1; then
        version_output=$(docker run --rm "${IMAGE_TAG}-version" --version 2>&1 || true)
        if printf '%s' "${version_output}" | grep -q "1.0.0-test"; then
            pass "version args injected: VERSION=1.0.0-test"
        else
            fail "version args injected: expected '1.0.0-test' in output, got: ${version_output}"
        fi
    else
        fail "version args injected: build with --build-arg failed"
    fi
}

test_runs_as_nonroot() {
    user=$(docker inspect --format '{{.Config.User}}' "${IMAGE_TAG}")
    if [ "${user}" = "65534:65534" ]; then
        pass "runs as non-root user 65534:65534"
    else
        fail "runs as non-root: expected User=65534:65534, got '${user}'"
    fi
}

test_binary_is_static() {
    # Extract binary and check with file command
    container_id=$(docker create "${IMAGE_TAG}")
    tmpbin=$(mktemp)
    docker cp "${container_id}:/usr/local/bin/plexd" "${tmpbin}" 2>/dev/null
    docker rm "${container_id}" >/dev/null 2>&1
    file_output=$(file "${tmpbin}")
    rm -f "${tmpbin}"
    if printf '%s' "${file_output}" | grep -q "statically linked"; then
        pass "binary is statically linked"
    else
        fail "binary is statically linked: file reports: ${file_output}"
    fi
}

test_exposed_ports() {
    ports=$(docker inspect --format '{{json .Config.ExposedPorts}}' "${IMAGE_TAG}")
    if ! printf '%s' "${ports}" | grep -q "9100/tcp"; then
        fail "exposed ports: missing 9100/tcp (got: ${ports})"
        return
    fi
    if ! printf '%s' "${ports}" | grep -q "51820/udp"; then
        fail "exposed ports: missing 51820/udp (got: ${ports})"
        return
    fi
    pass "exposed ports: 9100/tcp and 51820/udp"
}

test_entrypoint() {
    entrypoint=$(docker inspect --format '{{json .Config.Entrypoint}}' "${IMAGE_TAG}")
    if [ "${entrypoint}" = '"/usr/local/bin/plexd"' ] || [ "${entrypoint}" = '["/usr/local/bin/plexd"]' ]; then
        pass "entrypoint is /usr/local/bin/plexd"
    else
        fail "entrypoint: expected [\"/usr/local/bin/plexd\"], got ${entrypoint}"
    fi
}

test_image_size() {
    size_bytes=$(docker inspect --format '{{.Size}}' "${IMAGE_TAG}")
    size_mb=$((size_bytes / 1048576))
    if [ "${size_mb}" -lt 30 ]; then
        pass "image size under 30MB (${size_mb}MB)"
    else
        fail "image size under 30MB: got ${size_mb}MB"
    fi
}

test_directories_exist() {
    # Use docker create + export to check directory existence in distroless
    container_id=$(docker create "${IMAGE_TAG}")
    result="ok"
    for dir in var/lib/plexd var/run/plexd etc/plexd; do
        if ! docker export "${container_id}" | tar -t "${dir}/" >/dev/null 2>&1; then
            result="missing /${dir}"
            break
        fi
    done
    docker rm "${container_id}" >/dev/null 2>&1
    if [ "${result}" = "ok" ]; then
        pass "directories exist: /var/lib/plexd, /var/run/plexd, /etc/plexd"
    else
        fail "directories exist: ${result}"
    fi
}

test_dockerignore_excludes_git() {
    # Verify .git is not in the build context by checking the image layers
    # Build with a debug stage that lists the context
    cat > "/tmp/Dockerfile.context-check.$$" <<'CTXEOF'
FROM alpine:3.21
WORKDIR /check
COPY . .
RUN if [ -d .git ]; then echo "GIT_FOUND"; else echo "GIT_EXCLUDED"; fi > /result
CTXEOF
    build_output=$(docker build -f "/tmp/Dockerfile.context-check.$$" -t "plexd-ctx-check:$$" "${REPO_ROOT}" 2>&1)
    rm -f "/tmp/Dockerfile.context-check.$$"
    container_id=$(docker create "plexd-ctx-check:$$")
    result=$(docker cp "${container_id}:/result" - 2>/dev/null | tar -xO 2>/dev/null || echo "ERROR")
    docker rm "${container_id}" >/dev/null 2>&1
    docker rmi "plexd-ctx-check:$$" >/dev/null 2>&1 || true
    if printf '%s' "${result}" | grep -q "GIT_EXCLUDED"; then
        pass ".dockerignore excludes .git"
    else
        fail ".dockerignore excludes .git: .git was found in build context"
    fi
}

# --- Run tests ---

printf "Running Dockerfile tests...\n\n"

printf "Static checks (no build required):\n"
test_hadolint_passes
test_module_cache_layer

printf "\nBuilding image...\n"
test_docker_build_succeeds

printf "\nImage validation:\n"
test_version_args_injected
test_runs_as_nonroot
test_binary_is_static
test_exposed_ports
test_entrypoint
test_image_size
test_directories_exist
test_dockerignore_excludes_git

printf "\nResults: %d run, %d passed, %d failed\n" "${TESTS_RUN}" "${TESTS_PASSED}" "${TESTS_FAILED}"

if [ "${TESTS_FAILED}" -gt 0 ]; then
    exit 1
fi
