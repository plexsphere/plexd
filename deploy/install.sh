#!/bin/sh
# plexd install script
# Usage: curl -fsSL https://get.plexsphere.com/install.sh | sh -s -- [OPTIONS]
#
# Options:
#   --token VALUE     Bootstrap token for enrollment
#   --api-url URL     Control plane API URL
#   --version VERSION Version to install (default: latest)
#   --no-start        Don't start the service after install

set -eu

# --- Configuration ---
PLEXD_ARTIFACT_URL="${PLEXD_ARTIFACT_URL:-https://artifacts.plexsphere.com/plexd}"
VERSION="latest"
TOKEN=""
API_URL=""
NO_START=""
TMPDIR_PATH=""
OS_NAME=""
ARCH=""
BINARY_NAME=""

# LAUNCHD_PLIST is where plexd install writes the LaunchDaemon definition on
# macOS. launchctl is given the path, and the summary prints it.
LAUNCHD_PLIST="/Library/LaunchDaemons/com.plexsphere.plexd.plist"

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

# detect_os sets OS_NAME to the GOOS the release assets are named after.
# Windows is absent because a POSIX script cannot serve it; that install is the
# manual walkthrough in the Windows installation guide.
detect_os() {
    OS="$(uname -s)"
    case "${OS}" in
        Linux)  OS_NAME="linux" ;;
        Darwin) OS_NAME="darwin" ;;
        *) fatal "unsupported operating system: ${OS}. Supported: Linux, Darwin (macOS)." ;;
    esac
}

# detect_arch sets ARCH to the GOARCH the release assets are named after.
# Linux reports aarch64 where macOS reports arm64 for the same silicon, so both
# spellings map to the one release name.
detect_arch() {
    MACHINE="$(uname -m)"
    case "${MACHINE}" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        arm64)   ARCH="arm64" ;;
        *)       fatal "unsupported architecture: ${MACHINE}. Supported: x86_64 (amd64), aarch64 or arm64 (arm64)." ;;
    esac
}

# resolve_binary_name sets BINARY_NAME to the release asset for this host.
# These are the names release.yml publishes and internal/upgrade/fetcher.go
# resolves, so they cannot drift from either.
resolve_binary_name() {
    BINARY_NAME="plexd-${OS_NAME}-${ARCH}"
}

# service_start_command prints the command that starts plexd through the host's
# service manager. It is the single source of truth for that command:
# start_service runs what it prints.
service_start_command() {
    case "${OS_NAME}" in
        linux)  echo "systemctl enable --now plexd" ;;
        darwin) echo "launchctl bootstrap system ${LAUNCHD_PLIST}" ;;
        *)      return 1 ;;
    esac
}

# start_service starts plexd through the host's service manager.
start_service() {
    start_cmd="$(service_start_command)" || fatal "no service start command for ${OS_NAME}"
    info "starting plexd service: ${start_cmd}"
    # Word splitting is intended here and safe: the string comes from the fixed
    # literals in service_start_command, never from an argument, and neither
    # path contains a space.
    # shellcheck disable=SC2086
    ${start_cmd}
}

# print_summary reports where the install put things and what to run next.
print_summary() {
    info "---"
    info "plexd installed successfully"
    info "  binary:  /usr/local/bin/plexd"
    case "${OS_NAME}" in
        linux)
            info "  config:  /etc/plexd/config.yaml"
            info "  service: plexd.service"
            ;;
        darwin)
            info "  config:  /Library/Application Support/plexd/config.yaml"
            info "  service: com.plexsphere.plexd"
            ;;
    esac
    info ""
    info "next steps:"
    if [ -z "${TOKEN}" ]; then
        info "  1. Provide a bootstrap token: plexd join"
    fi
    case "${OS_NAME}" in
        linux)
            info "  - Check status: systemctl status plexd"
            ;;
        darwin)
            info "  - Check status: sudo launchctl print system/com.plexsphere.plexd"
            ;;
    esac
    info "  - View logs:    plexd logs -f"
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

# --- Group creation ---

# The daemon chowns its API socket to root:plexd with mode 0660 and narrows it
# to 0600 when the group is missing, so without these groups only root reaches
# the local node API. Failure is not fatal: plexd itself still runs. The plexd
# group takes effect only for a daemon that carries CAP_CHOWN -- the systemd
# unit does not, so there the socket stays at 0600 and plexd-secrets is what
# these two groups buy. See docs/reference/core/nodeapi.md.
ensure_groups() {
    if ! command -v groupadd >/dev/null 2>&1; then
        warn "groupadd not found; create the plexd and plexd-secrets groups by hand, or only root reaches the node API"
        return 0
    fi
    for group in plexd plexd-secrets; do
        if getent group "${group}" >/dev/null 2>&1; then
            continue
        fi
        if groupadd --system "${group}"; then
            info "created system group ${group}"
        else
            warn "could not create the ${group} group; only root reaches the node API"
        fi
    done
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

    info "detected: ${OS_NAME} ${ARCH}"

    # Create temp directory
    TMPDIR_PATH="$(mktemp -d)"

    # Download binary and checksum
    resolve_binary_name
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

    # Create the groups the node API socket is chowned to
    ensure_groups

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
        start_service
    else
        info "skipping service start (--no-start)"
    fi

    print_summary
}

# Guard for testing: source functions without running main
if [ "${PLEXD_INSTALL_TEST:-}" != "1" ]; then
    main "$@"
fi
