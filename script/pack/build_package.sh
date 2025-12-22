#!/usr/bin/env bash
################################################################################
# Build Script for App-Mesh Packages v2.0.0
#
# Purpose: Builds RPM/DEB packages for Linux and TAR.GZ for macOS
# Dependencies:
#   - CMake build environment
#   - nfpm (for Linux packaging)
#   - go (for GOARCH detection)
#   - Required development libraries
################################################################################

# Enable strict error handling
set -e #uo pipefail

###################
# Helper Functions
###################

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
error() { log "ERROR $@"; }
die() { error "$@" && exit 1; }
copy() { cp "$1" "$2/" || return 0; }

validate_environment() {
    [[ -z "${CMAKE_BINARY_DIR:-}" ]] && die "CMAKE_BINARY_DIR is not set"
    [[ ! -d "${CMAKE_BINARY_DIR}" ]] && die "Directory ${CMAKE_BINARY_DIR} does not exist"

    export INSTALL_LOCATION="/opt/appmesh"
    export PACKAGE_HOME="${CMAKE_INSTALL_PREFIX}"
    export GOARCH=$(go env GOARCH)
}

create_directory_structure() {
    rm -rf "${PACKAGE_HOME}"/{ssl,script,apps}
    mkdir -p "${PACKAGE_HOME}"/{ssl,script,apps}
}

copy_configuration_files() {
    local service_file="appmesh.systemd.service"
    [[ "$OSTYPE" == "darwin"* ]] && service_file="appmesh.launchd.plist"

    # Copy service file
    cp "${CMAKE_SOURCE_DIR}/script/pack/$service_file" "${PACKAGE_HOME}/script/"

    # Copy script files
    cp "${CMAKE_SOURCE_DIR}/src/daemon/rest/openapi.yaml" "${PACKAGE_HOME}/script/"
    cp "${CMAKE_SOURCE_DIR}/src/daemon/rest/index.html" "${PACKAGE_HOME}/script/"
    cp "${CMAKE_SOURCE_DIR}/script/pack/"{setup.sh,entrypoint.sh,appmesh*.sh,*.html} "${PACKAGE_HOME}/script/"
    cp "${CMAKE_SOURCE_DIR}/script/docker/"{prom*.yml,docker*.yaml} "${PACKAGE_HOME}/script/"
    cp "${CMAKE_SOURCE_DIR}/src/cli/"{bash_completion.sh,container_monitor.py,appmesh_agent.py} "${PACKAGE_HOME}/script/"

    # Copy binary support files
    cp ${CMAKE_SOURCE_DIR}/src/sdk/python/py_*.py "${PACKAGE_HOME}/bin/"

    # Copy SSL files
    cp "${CMAKE_SOURCE_DIR}/script/ssl/generate_ssl_cert.sh" /usr/local/bin/{cfssl,cfssljson} "${PACKAGE_HOME}/ssl/"

    # Copy app configs
    cp "${CMAKE_SOURCE_DIR}/script/apps/"*.yaml "${PACKAGE_HOME}/apps/"

    # Copy main configs
    local config_files=(
        "src/daemon/config.yaml"
        "src/daemon/security/security.yaml"
        "src/daemon/security/oauth2.yaml"
        "src/sdk/agent/pkg/cloud/consul.yaml"
    )
    for file in "${config_files[@]}"; do
        cp "${CMAKE_SOURCE_DIR}/${file}" "${PACKAGE_HOME}/"
    done

    chmod +x "${PACKAGE_HOME}/script/"*.sh
}

build_packages() {
    envsubst <"${CMAKE_SOURCE_DIR}/script/pack/nfpm.yaml" >"${CMAKE_BINARY_DIR}/nfpm_config.yaml"
    if grep -q '\${[^}]*}' "${CMAKE_BINARY_DIR}/nfpm_config.yaml"; then
        die "Some variables were not substituted in nfpm.yaml."
    fi

    info "Packaging the following files(${PACKAGE_HOME}):"
    find "${PACKAGE_HOME}" -type d -exec sh -c 'echo "${1%/}/"' _ {} \; -o -type f -print | sed "s|^${PACKAGE_HOME}/||" | sort | grep -v '^$' | sed 's/^/ - /'

    if [[ "$OSTYPE" == "linux"* ]]; then
        local GLIBC_VERSION=$(ldd --version | awk 'NR==1{print $NF}')
        local GCC_VERSION=$(gcc -dumpversion)
        local ARCH=$(arch)

        info "Building for Linux (GLIBC: $GLIBC_VERSION, GCC: $GCC_VERSION, ARCH: $ARCH)"

        nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager deb
        nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager rpm

        for pkg in appmesh*.{rpm,deb}; do
            local PACKAGE_FILE_NAME="${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERSION}_glibc_${GLIBC_VERSION}_${ARCH}.${pkg##*.}"
            mv "$pkg" "${PACKAGE_FILE_NAME}" && info "Package built: ${PACKAGE_FILE_NAME}"
        done
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        local MACOS_VERSION=$(sw_vers -productVersion | cut -d '.' -f1)
        local CLANG_VERSION=$(clang --version | awk -F ' ' '/Apple clang version/ {print $4}' | cut -d '.' -f1)
        local PACKAGE_FILE_NAME="${CMAKE_BINARY_DIR}/${PROJECT_NAME}_${PROJECT_VERSION}_clang_${CLANG_VERSION}_macos_${MACOS_VERSION}_${GOARCH}.pkg"

        info "Building for macOS (Version: $MACOS_VERSION, Clang: $CLANG_VERSION, ARCH: $GOARCH)"
        mkdir -p "${CMAKE_BINARY_DIR}/pkg_scripts"
        cp "${CMAKE_SOURCE_DIR}/script/pack/post_install.sh" "${CMAKE_BINARY_DIR}/pkg_scripts/postinstall"
        cp "${CMAKE_SOURCE_DIR}/script/pack/pre_uninstall.sh" "${CMAKE_BINARY_DIR}/pkg_scripts/preuninstall"
        cp "${CMAKE_SOURCE_DIR}/script/pack/post_uninstall.sh" "${CMAKE_BINARY_DIR}/pkg_scripts/postuninstall"
        chmod +x ${CMAKE_BINARY_DIR}/pkg_scripts/*
        pkgbuild --root "${PACKAGE_HOME}" --scripts "${CMAKE_BINARY_DIR}/pkg_scripts" --identifier "com.laoshanxi.appmesh" --version "${PROJECT_VERSION}" --install-location /opt/appmesh "${PACKAGE_FILE_NAME}"
    else
        die "Unsupported platform: $OSTYPE"
    fi
}

###################
# Main Execution
###################

main() {
    validate_environment
    create_directory_structure
    copy_configuration_files
    build_packages
    info "Build completed successfully!"
}

# Clean existing packages
find . -maxdepth 1 -type f \( -name "*.rpm" -o -name "*.deb" -o -name "*.gz" \) -delete

# Execute main function
main
