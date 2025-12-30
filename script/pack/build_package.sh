#!/usr/bin/env bash
################################################################################
# Build Script for App-Mesh Packages
################################################################################
set -e

export PACKAGE_HOME="${CMAKE_INSTALL_PREFIX}"
export INSTALL_LOCATION="/opt/appmesh"
export GOARCH=$(go env GOARCH)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
die() { log "ERROR $@" && exit 1; }

[[ -z "${CMAKE_BINARY_DIR:-}" ]] && die "CMAKE_BINARY_DIR is not set"
[[ ! -d "${CMAKE_BINARY_DIR}" ]] && die "Directory ${CMAKE_BINARY_DIR} does not exist"


info "Packaging contents of: ${PACKAGE_HOME}"
# Clean previous artifacts
find . -maxdepth 1 -type f \( -name "*.rpm" -o -name "*.deb" -o -name "*.pkg" \) -delete

if [[ "$OSTYPE" == "linux"* ]]; then
    # Render nfpm config
    envsubst <"${CMAKE_SOURCE_DIR}/script/pack/nfpm.yaml" >"${CMAKE_BINARY_DIR}/nfpm_config.yaml"
    if grep -q '\${[^}]*}' "${CMAKE_BINARY_DIR}/nfpm_config.yaml"; then
        die "Variables not substituted in nfpm.yaml"
    fi

    export GLIBC_VERSION=$(ldd --version | awk 'NR==1{print $NF}')
    export GCC_VERSION=$(gcc -dumpversion)
    export ARCH=$(arch)

    info "Building DEB/RPM (GLIBC: $GLIBC_VERSION, GCC: $GCC_VERSION, ARCH: $ARCH)"
    nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager deb
    nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager rpm

    # Rename packages
    for pkg in appmesh*.{rpm,deb}; do
        export PACKAGE_FILE_NAME="${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERSION}_glibc_${GLIBC_VERSION}_${ARCH}.${pkg##*.}"
        mv "$pkg" "${PACKAGE_FILE_NAME}" && info "Created: ${PACKAGE_FILE_NAME}"
    done

elif [[ "$OSTYPE" == "darwin"* ]]; then
    export MACOS_VERSION=$(sw_vers -productVersion | cut -d '.' -f1)
    export CLANG_VERSION=$(clang --version | awk -F ' ' '/Apple clang version/ {print $4}' | cut -d '.' -f1)
    export PACKAGE_FILE_NAME="${CMAKE_BINARY_DIR}/${PROJECT_NAME}_${PROJECT_VERSION}_clang_${CLANG_VERSION}_macos_${MACOS_VERSION}_${GOARCH}.pkg"

    pkgbuild --root "${PACKAGE_HOME}" \
             --scripts "${CMAKE_BINARY_DIR}/pkg_scripts" \
             --identifier "com.laoshanxi.appmesh" \
             --version "${PROJECT_VERSION}" \
             --install-location "${INSTALL_LOCATION}" \
             "${PACKAGE_FILE_NAME}"
else
    die "Unsupported platform: $OSTYPE"
fi

info "Build completed successfully!"
