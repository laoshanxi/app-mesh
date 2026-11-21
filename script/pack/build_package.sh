#!/usr/bin/env bash
################################################################################
# Build Script for App-Mesh Packages
################################################################################
set -euo pipefail

export PACKAGE_HOME="${CMAKE_INSTALL_PREFIX:-}"
export INSTALL_LOCATION="/opt/appmesh"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO" "$@"; }
die() { log "ERROR" "$@" && exit 1; }

[[ -z "${CMAKE_SOURCE_DIR:-}" ]] && die "CMAKE_SOURCE_DIR is not set"
[[ -z "${CMAKE_BINARY_DIR:-}" ]] && die "CMAKE_BINARY_DIR is not set"
[[ ! -d "${CMAKE_BINARY_DIR}" ]] && die "Directory ${CMAKE_BINARY_DIR} does not exist"
[[ -z "${CMAKE_INSTALL_PREFIX:-}" ]] && die "CMAKE_INSTALL_PREFIX is not set"
[[ ! -d "${PACKAGE_HOME}" ]] && die "Package root does not exist: ${PACKAGE_HOME}"

export GOARCH
GOARCH=$(go env GOARCH)

################################################################################
# Copy the Dex server binaries into the main package. install_build_deps.sh
# installs dex/dexuser into /usr/local/bin; the passhash helper is repo-native
# (src/apps/identity) and already staged by cmake.
################################################################################
copy_dex() {
    local bin
    for bin in /usr/local/bin/dex /usr/local/bin/dexuser; do
        [[ -x "$bin" ]] || die "Dex binary not found at ${bin} (install_build_deps.sh installs it there)"
        # The packaged dex must be the fork build: upstream dex silently ignores
        # oauth2.pkce, so the appmesh- version stamp proves PKCE enforcement is real.
        if [[ "$bin" == */dex ]] && ! "$bin" version 2>/dev/null | grep -q 'appmesh-'; then
            die "Dex at ${bin} is not the fork build (no appmesh- version stamp): rebuild it with install_build_deps.sh"
        fi
        install -m 755 "$bin" "${PACKAGE_HOME}/bin/$(basename "$bin")"
        info "Copied $(basename "$bin") into the main package ($("$bin" version 2>/dev/null || echo 'version unknown'))"
    done
}

info "Packaging contents of: ${PACKAGE_HOME}"
# Clean previous artifacts
find . -maxdepth 1 -type f \( -name "*.rpm" -o -name "*.deb" \) -delete

if [[ "$OSTYPE" != "linux"* ]]; then
    die "Unsupported platform: $OSTYPE"
fi

# Dex is a mandatory content of the main package.
copy_dex

    # Render nfpm config
    envsubst <"${CMAKE_SOURCE_DIR}/script/pack/nfpm.yaml" >"${CMAKE_BINARY_DIR}/nfpm_config.yaml"
    if grep -q '\${[^}]*}' "${CMAKE_BINARY_DIR}/nfpm_config.yaml"; then
        die "Variables not substituted in nfpm.yaml"
    fi

    export GLIBC_VERSION
    GLIBC_VERSION=$(ldd --version | awk 'NR==1{print $NF}')
    export GCC_VERSION
    GCC_VERSION=$(gcc -dumpversion)
    export ARCH
    ARCH=$(arch)

    info "Building DEB/RPM (GLIBC: $GLIBC_VERSION, GCC: $GCC_VERSION, ARCH: $ARCH)"
    nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager deb
    nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager rpm

# Rename packages
for pkg in appmesh*.{rpm,deb}; do
    export PACKAGE_FILE_NAME="${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERSION}_glibc_${GLIBC_VERSION}_${ARCH}.${pkg##*.}"
    mv "$pkg" "${PACKAGE_FILE_NAME}" && info "Created: ${PACKAGE_FILE_NAME}"
done

info "Build completed successfully!"
