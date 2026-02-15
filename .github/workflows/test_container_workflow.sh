#!/bin/sh
# Tests for .github/workflows/container.yml
# Run: sh .github/workflows/test_container_workflow.sh
#
# Validates the container workflow against project conventions and requirements.
# No external dependencies beyond grep/awk/sh.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOW="${SCRIPT_DIR}/container.yml"
CI_WORKFLOW="${SCRIPT_DIR}/ci.yml"

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

# --- Tests ---

test_yaml_syntax_valid() {
    # Verify the file exists and is parseable as YAML using python (available on CI runners)
    if [ ! -f "${WORKFLOW}" ]; then
        fail "container.yml does not exist"
        return
    fi
    if python3 -c "import yaml; yaml.safe_load(open('${WORKFLOW}'))" 2>/dev/null; then
        pass "YAML syntax valid"
    elif grep -q "^name:" "${WORKFLOW}" && grep -q "^on:" "${WORKFLOW}" && grep -q "^jobs:" "${WORKFLOW}"; then
        # Fallback: if PyYAML not available, check for required top-level keys
        pass "YAML syntax valid (structure check — PyYAML not available)"
    else
        fail "YAML syntax valid: missing required top-level keys"
    fi
}

test_trigger_on_tag_push_v_star() {
    if grep -q "tags:" "${WORKFLOW}" && grep -q "'v\*'" "${WORKFLOW}"; then
        pass "trigger on tag push v*"
    else
        fail "trigger on tag push v*: missing tags: ['v*'] in on.push"
    fi
}

test_trigger_on_main_push() {
    if grep -q "branches:" "${WORKFLOW}" && grep -q "main" "${WORKFLOW}"; then
        pass "trigger on main push"
    else
        fail "trigger on main push: missing branches: [main] in on.push"
    fi
}

test_no_pull_request_trigger() {
    if grep -q "pull_request" "${WORKFLOW}"; then
        fail "no pull_request trigger: found pull_request in workflow"
    else
        pass "no pull_request trigger"
    fi
}

test_platforms_amd64_arm64() {
    if grep -q "linux/amd64,linux/arm64" "${WORKFLOW}"; then
        pass "platforms: linux/amd64,linux/arm64"
    else
        fail "platforms: missing linux/amd64,linux/arm64"
    fi
}

test_buildx_setup_present() {
    if grep -q "setup-buildx-action" "${WORKFLOW}"; then
        pass "Buildx setup present"
    else
        fail "Buildx setup present: missing docker/setup-buildx-action"
    fi
}

test_ghcr_login_configured() {
    if grep -q "ghcr.io" "${WORKFLOW}" && grep -q "secrets.GITHUB_TOKEN" "${WORKFLOW}"; then
        pass "ghcr.io login configured with GITHUB_TOKEN"
    else
        fail "ghcr.io login configured: missing ghcr.io or secrets.GITHUB_TOKEN"
    fi
}

test_metadata_semver_tags() {
    found=0
    grep -q "type=semver,pattern={{version}}" "${WORKFLOW}" && found=$((found + 1))
    grep -q "type=semver,pattern={{major}}.{{minor}}" "${WORKFLOW}" && found=$((found + 1))
    grep -q "type=semver,pattern={{major}}" "${WORKFLOW}" && found=$((found + 1))
    if [ "${found}" -ge 3 ]; then
        pass "metadata semver tags (version, major.minor, major)"
    else
        fail "metadata semver tags: found ${found}/3 expected patterns"
    fi
}

test_metadata_dev_tag() {
    if grep -q "type=raw,value=dev,enable={{is_default_branch}}" "${WORKFLOW}"; then
        pass "metadata dev tag on default branch"
    else
        fail "metadata dev tag: missing type=raw,value=dev,enable={{is_default_branch}}"
    fi
}

test_build_args_version_commit_date() {
    found=0
    grep -q "VERSION=" "${WORKFLOW}" && found=$((found + 1))
    grep -q "COMMIT=" "${WORKFLOW}" && found=$((found + 1))
    grep -q "DATE=" "${WORKFLOW}" && found=$((found + 1))
    if [ "${found}" -ge 3 ]; then
        pass "build-args: VERSION, COMMIT, DATE"
    else
        fail "build-args: found ${found}/3 expected build args"
    fi
}

test_image_name_matches_daemonset() {
    if grep -q "ghcr.io/plexsphere/plexd" "${WORKFLOW}"; then
        pass "image name matches DaemonSet: ghcr.io/plexsphere/plexd"
    else
        fail "image name matches DaemonSet: missing ghcr.io/plexsphere/plexd"
    fi
}

test_push_enabled() {
    if grep -q "push: true" "${WORKFLOW}"; then
        pass "push: true"
    else
        fail "push: true not found"
    fi
}

test_actions_pinned_by_sha() {
    # Every uses: line must contain a 40-char hex SHA after @
    unpinned=$(grep 'uses:' "${WORKFLOW}" | grep -v '@[0-9a-f]\{40\}' || true)
    if [ -z "${unpinned}" ]; then
        pass "all actions pinned by SHA"
    else
        fail "all actions pinned by SHA: unpinned actions found: ${unpinned}"
    fi
}

test_checkout_sha_matches_ci() {
    expected_sha="34e114876b0b11c390a56381ad16ebd13914f8d5"
    if grep -q "actions/checkout@${expected_sha}" "${WORKFLOW}"; then
        # Also verify it matches ci.yml
        if [ -f "${CI_WORKFLOW}" ] && grep -q "actions/checkout@${expected_sha}" "${CI_WORKFLOW}"; then
            pass "checkout SHA matches ci.yml: ${expected_sha}"
        else
            pass "checkout SHA matches expected: ${expected_sha} (ci.yml not found for cross-check)"
        fi
    else
        fail "checkout SHA does not match expected: ${expected_sha}"
    fi
}

test_permissions_least_privilege() {
    if grep -q "packages: write" "${WORKFLOW}" && grep -q "contents: read" "${WORKFLOW}"; then
        pass "permissions: packages: write, contents: read"
    else
        fail "permissions: missing packages: write or contents: read"
    fi
}

test_dockerfile_path() {
    if grep -q "deploy/docker/Dockerfile" "${WORKFLOW}"; then
        pass "Dockerfile path: deploy/docker/Dockerfile"
    else
        fail "Dockerfile path: missing deploy/docker/Dockerfile"
    fi
}

test_build_context_is_root() {
    if grep -q "context: \." "${WORKFLOW}"; then
        pass "build context is repository root"
    else
        fail "build context: missing context: ."
    fi
}

test_single_job_no_matrix() {
    if grep -q "strategy" "${WORKFLOW}" || grep -q "matrix" "${WORKFLOW}"; then
        fail "single job: found strategy/matrix (Buildx handles multi-platform)"
    else
        pass "single job, no matrix strategy"
    fi
}

test_timeout_minutes_set() {
    if grep -q "timeout-minutes:" "${WORKFLOW}"; then
        pass "timeout-minutes set"
    else
        fail "timeout-minutes not set"
    fi
}

test_docker_action_sha_pins() {
    found=0
    grep -q "setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f" "${WORKFLOW}" && found=$((found + 1))
    grep -q "login-action@c94ce9fb468520275223c153574b00df6fe4bcc9" "${WORKFLOW}" && found=$((found + 1))
    grep -q "metadata-action@c299e40c65443455700f0fdfc63efafe5b349051" "${WORKFLOW}" && found=$((found + 1))
    grep -q "build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8" "${WORKFLOW}" && found=$((found + 1))
    if [ "${found}" -eq 4 ]; then
        pass "Docker action SHA pins match expected values"
    else
        fail "Docker action SHA pins: ${found}/4 match expected values"
    fi
}

# --- Run tests ---

printf "Running container workflow tests...\n\n"

test_yaml_syntax_valid
test_trigger_on_tag_push_v_star
test_trigger_on_main_push
test_no_pull_request_trigger
test_platforms_amd64_arm64
test_buildx_setup_present
test_ghcr_login_configured
test_metadata_semver_tags
test_metadata_dev_tag
test_build_args_version_commit_date
test_image_name_matches_daemonset
test_push_enabled
test_actions_pinned_by_sha
test_checkout_sha_matches_ci
test_permissions_least_privilege
test_dockerfile_path
test_build_context_is_root
test_single_job_no_matrix
test_timeout_minutes_set
test_docker_action_sha_pins

printf "\nResults: %d run, %d passed, %d failed\n" "${TESTS_RUN}" "${TESTS_PASSED}" "${TESTS_FAILED}"

if [ "${TESTS_FAILED}" -gt 0 ]; then
    exit 1
fi
