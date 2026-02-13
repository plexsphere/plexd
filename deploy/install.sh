#!/bin/sh
# plexd install script
# Usage: curl -fsSL https://get.plexsphere.io/install.sh | sh -s -- [OPTIONS]
#
# Options:
#   --token VALUE     Bootstrap token for enrollment
#   --api-url URL     Control plane API URL
#   --version VERSION Version to install (default: latest)
#   --no-start        Don't start the service after install

set -eu

# --- Configuration ---
PLEXD_ARTIFACT_URL="${PLEXD_ARTIFACT_URL:-https://artifacts.plexsphere.io/plexd}"
VERSION="latest"
TOKEN=""
API_URL=""
NO_START=""
TMPDIR_PATH=""

# --- Output helpers ---
info() { printf '[INFO] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1" >&2; }
fatal() { printf '[FATAL] %s\n' "$1" >&2; cleanup; exit 1; }

cleanup() {
    if [ -n "${TMPDIR_PATH}" ] && [ -d "${TMPDIR_PATH}" ]; then
        rm -rf "${TMPDIR_PATH}"
    fi
}
trap cleanup EXIT

# --- Detection functions ---

detect_os() {
    OS="$(uname -s)"
    case "${OS}" in
        Linux) ;;
        *) fatal "unsupported operating system: ${OS}. Only Linux is supported." ;;
    esac
}

detect_arch() {
    MACHINE="$(uname -m)"
    case "${MACHINE}" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)       fatal "unsupported architecture: ${MACHINE}. Supported: x86_64 (amd64), aarch64 (arm64)." ;;
    esac
}

find_sha256_cmd() {
    if command -v sha256sum >/dev/null 2>&1; then
        SHA256_CMD="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        SHA256_CMD="shasum -a 256"
    else
        fatal "no SHA-256 tool found. Install sha256sum or shasum."
    fi
}

find_download_cmd() {
    if command -v curl >/dev/null 2>&1; then
        DOWNLOAD_CMD="curl"
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOAD_CMD="wget"
    else
        fatal "no download tool found. Install curl or wget."
    fi
}

# --- Download function ---

download() {
    url="$1"
    dest="$2"
    case "${DOWNLOAD_CMD}" in
        curl) curl -fsSL -o "${dest}" "${url}" ;;
        wget) wget -q -O "${dest}" "${url}" ;;
    esac
}

# --- Checksum verification ---

verify_checksum() {
    binary_path="$1"
    checksum_path="$2"
    binary_name="$3"

    expected="$(grep "${binary_name}" "${checksum_path}" | awk '{print $1}')"
    if [ -z "${expected}" ]; then
        fatal "checksum not found for ${binary_name} in checksum file"
    fi

    actual="$(${SHA256_CMD} "${binary_path}" | awk '{print $1}')"
    if [ "${expected}" != "${actual}" ]; then
        fatal "checksum mismatch for ${binary_name}: expected ${expected}, got ${actual}"
    fi

    info "checksum verified: ${actual}"
}

# --- Argument parsing ---

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --token)
                [ $# -ge 2 ] || fatal "--token requires a value"
                TOKEN="$2"
                shift 2
                ;;
            --api-url)
                [ $# -ge 2 ] || fatal "--api-url requires a value"
                API_URL="$2"
                shift 2
                ;;
            --version)
                [ $# -ge 2 ] || fatal "--version requires a value"
                VERSION="$2"
                shift 2
                ;;
            --no-start)
                NO_START="1"
                shift
                ;;
            *)
                fatal "unknown option: $1"
                ;;
        esac
    done
}

# --- Main ---

main() {
    parse_args "$@"

    info "plexd installer"
    info "version: ${VERSION}"

    # Pre-flight checks
    detect_os
    detect_arch
    find_sha256_cmd
    find_download_cmd

    info "detected: Linux ${ARCH}"

    # Create temp directory
    TMPDIR_PATH="$(mktemp -d)"

    # Download binary and checksum
    BINARY_NAME="plexd-linux-${ARCH}"
    BINARY_URL="${PLEXD_ARTIFACT_URL}/${VERSION}/${BINARY_NAME}"
    CHECKSUM_URL="${PLEXD_ARTIFACT_URL}/${VERSION}/checksums.sha256"

    info "downloading ${BINARY_URL}"
    download "${BINARY_URL}" "${TMPDIR_PATH}/${BINARY_NAME}"

    info "downloading checksums"
    download "${CHECKSUM_URL}" "${TMPDIR_PATH}/checksums.sha256"

    # Verify checksum
    verify_checksum "${TMPDIR_PATH}/${BINARY_NAME}" "${TMPDIR_PATH}/checksums.sha256" "${BINARY_NAME}"

    # Make executable
    chmod +x "${TMPDIR_PATH}/${BINARY_NAME}"

    # Run plexd install
    info "running plexd install"
    set -- install
    if [ -n "${TOKEN}" ]; then
        set -- "$@" --token "${TOKEN}"
    fi
    if [ -n "${API_URL}" ]; then
        set -- "$@" --api-url "${API_URL}"
    fi
    "${TMPDIR_PATH}/${BINARY_NAME}" "$@"

    # Start service unless --no-start
    if [ -z "${NO_START}" ]; then
        info "enabling and starting plexd service"
        systemctl enable --now plexd
    else
        info "skipping service start (--no-start)"
    fi

    # Summary
    info "---"
    info "plexd installed successfully"
    info "  binary:  /usr/local/bin/plexd"
    info "  config:  /etc/plexd/config.yaml"
    info "  service: plexd.service"
    info ""
    info "next steps:"
    if [ -z "${TOKEN}" ]; then
        info "  1. Provide a bootstrap token: plexd join"
    fi
    info "  - Check status: systemctl status plexd"
    info "  - View logs:    journalctl -u plexd -f"
}

# Guard for testing: source functions without running main
if [ "${PLEXD_INSTALL_TEST:-}" != "1" ]; then
    main "$@"
fi
