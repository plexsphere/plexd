#!/bin/sh
# Tests for deploy/install.sh
# Run: sh deploy/install_test.sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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

# Source install.sh functions without running main
PLEXD_INSTALL_TEST=1
export PLEXD_INSTALL_TEST
. "${SCRIPT_DIR}/install.sh"

# --- Tests ---

test_detect_os_linux() {
    # On Linux, detect_os should succeed without error
    OS_NAME="$(uname -s)"
    if [ "${OS_NAME}" = "Linux" ]; then
        detect_os 2>/dev/null
        pass "detect_os succeeds on Linux"
    else
        pass "detect_os skipped (not running on Linux)"
    fi
}

test_detect_arch_amd64() {
    MACHINE="$(uname -m)"
    if [ "${MACHINE}" = "x86_64" ]; then
        detect_arch 2>/dev/null
        if [ "${ARCH}" = "amd64" ]; then
            pass "detect_arch maps x86_64 to amd64"
        else
            fail "detect_arch maps x86_64 to ${ARCH}, expected amd64"
        fi
    else
        pass "detect_arch amd64 skipped (not on x86_64)"
    fi
}

test_detect_arch_arm64() {
    MACHINE="$(uname -m)"
    if [ "${MACHINE}" = "aarch64" ]; then
        detect_arch 2>/dev/null
        if [ "${ARCH}" = "arm64" ]; then
            pass "detect_arch maps aarch64 to arm64"
        else
            fail "detect_arch maps aarch64 to ${ARCH}, expected arm64"
        fi
    else
        pass "detect_arch arm64 skipped (not on aarch64)"
    fi
}

test_detect_arch_current() {
    # Verify detect_arch succeeds on current platform
    detect_arch 2>/dev/null
    if [ -n "${ARCH}" ]; then
        pass "detect_arch detects current architecture: ${ARCH}"
    else
        fail "detect_arch failed to detect architecture"
    fi
}

# fake_uname shadows the uname binary with a shell function, so both platform
# branches are exercised whatever host runs these tests. A function takes
# precedence over a PATH lookup, and unfake_uname removes it again.
fake_uname() {
    _fake_os="$1"
    _fake_machine="$2"
    # Invoked indirectly, by the detect_* functions under test.
    # shellcheck disable=SC2329
    uname() {
        case "$1" in
            -s) echo "${_fake_os}" ;;
            -m) echo "${_fake_machine}" ;;
        esac
    }
}

unfake_uname() {
    unset -f uname
}

test_detect_os_darwin() {
    fake_uname Darwin arm64
    detect_os 2>/dev/null
    unfake_uname
    if [ "${OS_NAME}" = "darwin" ]; then
        pass "detect_os maps Darwin to darwin"
    else
        fail "detect_os set OS_NAME=${OS_NAME}, expected darwin"
    fi
}

test_detect_os_unsupported() {
    fake_uname FreeBSD amd64
    # fatal exits, so the call runs in a subshell; an if condition also
    # suppresses errexit, leaving the failure for this test to report.
    if ( detect_os ) 2>/dev/null; then
        unfake_uname
        fail "detect_os accepted an unsupported operating system"
    else
        unfake_uname
        pass "detect_os rejects an unsupported operating system"
    fi
}

test_detect_arch_arm64_darwin() {
    fake_uname Darwin arm64
    detect_arch 2>/dev/null
    unfake_uname
    if [ "${ARCH}" = "arm64" ]; then
        pass "detect_arch maps arm64 to arm64"
    else
        fail "detect_arch mapped arm64 to ${ARCH}, expected arm64"
    fi
}

test_resolve_binary_name_darwin() {
    fake_uname Darwin arm64
    detect_os 2>/dev/null
    detect_arch 2>/dev/null
    unfake_uname
    resolve_binary_name
    if [ "${BINARY_NAME}" = "plexd-darwin-arm64" ]; then
        pass "resolve_binary_name builds plexd-darwin-arm64"
    else
        fail "resolve_binary_name built ${BINARY_NAME}, expected plexd-darwin-arm64"
    fi
}

test_service_start_command() {
    OS_NAME="linux"
    linux_cmd="$(service_start_command)"
    OS_NAME="darwin"
    darwin_cmd="$(service_start_command)"
    OS_NAME=""

    if [ "${linux_cmd}" = "systemctl enable --now plexd" ] &&
       [ "${darwin_cmd}" = "launchctl bootstrap system ${LAUNCHD_PLIST}" ]; then
        pass "service_start_command prints the service manager command per platform"
    else
        fail "service_start_command printed '${linux_cmd}' and '${darwin_cmd}'"
    fi
}

test_parse_args_token() {
    TOKEN=""
    parse_args --token "test-token-123"
    if [ "${TOKEN}" = "test-token-123" ]; then
        pass "parse_args --token"
    else
        fail "parse_args --token: got '${TOKEN}', expected 'test-token-123'"
    fi
    TOKEN=""
}

test_parse_args_api_url() {
    API_URL=""
    parse_args --api-url "https://api.example.com"
    if [ "${API_URL}" = "https://api.example.com" ]; then
        pass "parse_args --api-url"
    else
        fail "parse_args --api-url: got '${API_URL}', expected 'https://api.example.com'"
    fi
    API_URL=""
}

test_parse_args_version() {
    VERSION="latest"
    parse_args --version "v1.2.3"
    if [ "${VERSION}" = "v1.2.3" ]; then
        pass "parse_args --version"
    else
        fail "parse_args --version: got '${VERSION}', expected 'v1.2.3'"
    fi
    VERSION="latest"
}

test_parse_args_no_start() {
    NO_START=""
    parse_args --no-start
    if [ "${NO_START}" = "1" ]; then
        pass "parse_args --no-start"
    else
        fail "parse_args --no-start: got '${NO_START}', expected '1'"
    fi
    NO_START=""
}

test_parse_args_combined() {
    TOKEN=""
    API_URL=""
    VERSION="latest"
    NO_START=""
    parse_args --token "abc" --api-url "https://x.io" --version "v2.0" --no-start
    result="ok"
    if [ "${TOKEN}" != "abc" ]; then result="fail: token=${TOKEN}"; fi
    if [ "${API_URL}" != "https://x.io" ]; then result="fail: api_url=${API_URL}"; fi
    if [ "${VERSION}" != "v2.0" ]; then result="fail: version=${VERSION}"; fi
    if [ "${NO_START}" != "1" ]; then result="fail: no_start=${NO_START}"; fi
    if [ "${result}" = "ok" ]; then
        pass "parse_args combined flags"
    else
        fail "parse_args combined flags: ${result}"
    fi
    TOKEN=""
    API_URL=""
    VERSION="latest"
    NO_START=""
}

test_find_sha256_cmd() {
    find_sha256_cmd 2>/dev/null
    if [ -n "${SHA256_CMD}" ]; then
        pass "find_sha256_cmd found: ${SHA256_CMD}"
    else
        fail "find_sha256_cmd did not find a SHA-256 tool"
    fi
}

test_find_download_cmd() {
    find_download_cmd 2>/dev/null
    if [ -n "${DOWNLOAD_CMD}" ]; then
        pass "find_download_cmd found: ${DOWNLOAD_CMD}"
    else
        fail "find_download_cmd did not find a download tool"
    fi
}

# --- Run tests ---

printf "Running install.sh tests...\n"
test_detect_os_linux
test_detect_os_darwin
test_detect_os_unsupported
test_detect_arch_amd64
test_detect_arch_arm64
test_detect_arch_arm64_darwin
test_detect_arch_current
test_resolve_binary_name_darwin
test_service_start_command
test_parse_args_token
test_parse_args_api_url
test_parse_args_version
test_parse_args_no_start
test_parse_args_combined
test_find_sha256_cmd
test_find_download_cmd

printf "\nResults: %d run, %d passed, %d failed\n" "${TESTS_RUN}" "${TESTS_PASSED}" "${TESTS_FAILED}"

if [ "${TESTS_FAILED}" -gt 0 ]; then
    exit 1
fi
