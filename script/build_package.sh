#!/usr/bin/env bash
################################################################################
# Build Script for App-Mesh Packages v2.0.0
#
# Purpose: Builds RPM/DEB packages for Linux and TAR.GZ for macOS
# Dependencies:
#   - CMake build environment
#   - nfpm (for Linux packaging)
#   - patchelf (for Linux binary modifications)
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

validate_environment() {
    [[ -z "${CMAKE_BINARY_DIR:-}" ]] && die "CMAKE_BINARY_DIR is not set"
    [[ ! -d "${CMAKE_BINARY_DIR}" ]] && die "Directory ${CMAKE_BINARY_DIR} does not exist"

    export INSTALL_LOCATION="/opt/appmesh"
    export PACKAGE_HOME="${CMAKE_BINARY_DIR}/nfpm_home"
    export GOARCH=$(go env GOARCH)
}

setup_platform_specifics() {
    if [[ "$OSTYPE" == "linux"* ]]; then
        export LD_LIBRARY_PATH="/usr/local/ssl/lib:/usr/local/lib64:/usr/local/lib:${LD_LIBRARY_PATH:-}"
        LIBRARY_INSPECTOR="ldd"
        LIBRARY_EXTRACTOR="awk '{print \$3}'"
    else
        local ARCHITECTURE=$(uname -m)
        local BREW_DIR="/opt/homebrew"
        [[ "$ARCHITECTURE" != "arm64" ]] && BREW_DIR="/usr/local"
        export DYLD_LIBRARY_PATH="$BREW_DIR/lib:$BREW_DIR/lib64:/usr/local/ssl/lib:${DYLD_LIBRARY_PATH:-}"
        LIBRARY_INSPECTOR="otool -L"
        LIBRARY_EXTRACTOR="awk '{print \$1}'"
    fi
}

create_directory_structure() {
    rm -rf "${PACKAGE_HOME}"
    mkdir -p "${PACKAGE_HOME}"/{ssl,script,lib64,bin,apps}
}

copy_binaries() {
    cp "${CMAKE_BINARY_DIR}/gen/"{appc,appsvc,agent} "${PACKAGE_HOME}/bin/"
}

patch_linux_libraries() {
    # Version compatibility for libreadline
    if [[ "$OSTYPE" == "linux"* ]]; then
        local LIB_READLINE_VER=$(ldd "${PACKAGE_HOME}/bin/appc" | awk '/libreadline.so/ {print $1}')
        if [[ -n "$LIB_READLINE_VER" ]]; then
            local LIB_READLINE=$(echo "$LIB_READLINE_VER" | sed 's/\.[0-9.]*$//')
            for bin in appc appsvc; do
                info "Patching readline for: ${bin}"
                patchelf --replace-needed "$LIB_READLINE_VER" "$LIB_READLINE" "${PACKAGE_HOME}/bin/$bin"
            done
        fi
    fi
}

copy_configuration_files() {
    local service_file="appmesh.systemd.service"
    [[ "$OSTYPE" == "darwin"* ]] && service_file="appmesh.launchd.plist"

    # Copy service file
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/$service_file" "${PACKAGE_HOME}/script/"

    # Copy script files
    cp "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/rest/openapi.yaml" "${PACKAGE_HOME}/script/"
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/"{setup.sh,entrypoint.sh,app*.sh,prom*.yml,docker*.yaml,*.html} "${PACKAGE_HOME}/script/"
    cp "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/"{bash_completion.sh,container_monitor.py,appmesh_arm.py} "${PACKAGE_HOME}/script/"

    # Copy binary support files
    cp "${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/python/py_exec.py" "${PACKAGE_HOME}/bin/"

    # Copy SSL files
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/generate_ssl_cert.sh" /usr/local/bin/{cfssl,cfssljson} "${PACKAGE_HOME}/ssl/"

    # Copy app configs
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/apps/"*.yaml "${PACKAGE_HOME}/apps/"

    # Copy main configs
    local config_files=(
        "src/daemon/config.yaml"
        "src/daemon/security/security.yaml"
        "src/daemon/security/ldapplugin/ldap.yaml"
        "src/daemon/security/oauth2.yaml"
        "src/sdk/agent/pkg/cloud/consul.yaml"
    )
    for file in "${config_files[@]}"; do
        cp "${CMAKE_CURRENT_SOURCE_DIR}/${file}" "${PACKAGE_HOME}/"
    done

    chmod +x "${PACKAGE_HOME}/script/"*.sh
}

copy_libraries() {
    local dependencies=(boost curl ACE libssl libcrypto log4cpp oath yaml)
    for dep in "${dependencies[@]}"; do
        $LIBRARY_INSPECTOR "${CMAKE_BINARY_DIR}/gen/appsvc" | grep "$dep" | eval $LIBRARY_EXTRACTOR |
            while read -r lib; do
                [[ -f "$lib" ]] && cp "$lib" "${PACKAGE_HOME}/lib64/"
            done
    done
}

handle_macos_specifics() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # Handle openldap dependency (required by curl)
        $LIBRARY_INSPECTOR "${CMAKE_BINARY_DIR}/gen/appsvc" | grep curl | eval $LIBRARY_EXTRACTOR |
            xargs $LIBRARY_INSPECTOR | grep "openldap" | eval $LIBRARY_EXTRACTOR |
            while read -r lib; do
                [[ -f "$lib" ]] && cp "$lib" "${PACKAGE_HOME}/lib64/"
            done

        # Handle libicu dependency (required by libboost_regex)
        $LIBRARY_INSPECTOR "${CMAKE_BINARY_DIR}/gen/appc" | grep libboost_regex | eval $LIBRARY_EXTRACTOR |
            xargs $LIBRARY_INSPECTOR | grep "libicu" | eval $LIBRARY_EXTRACTOR |
            while read -r lib; do
                [[ -f "$lib" ]] && cp "$lib" "${PACKAGE_HOME}/lib64/"
            done

        # Handle boost_atomic dependency (required by libboost_filesystem)
        local boost_filesystem=$($LIBRARY_INSPECTOR "${CMAKE_BINARY_DIR}/gen/appc" | grep libboost_filesystem | eval $LIBRARY_EXTRACTOR)
        local boost_atomic="$(dirname "$boost_filesystem")/libboost_atomic.dylib"
        [[ -f "$boost_atomic" ]] && cp "$boost_atomic" "${PACKAGE_HOME}/lib64/"

        # Modify ping arguments for macOS
        sed -i '' 's/ -w / -t /g' "${PACKAGE_HOME}/apps/ping.yaml"
        # Replace LD_LIBRARY_PATH to DYLD_LIBRARY_PATH for macOS
        sed -i '' 's/LD_LIBRARY_PATH/DYLD_LIBRARY_PATH/g' "${PACKAGE_HOME}/script/"*
    fi
}

build_packages() {
    envsubst <"${CMAKE_CURRENT_SOURCE_DIR}/script/nfpm.yaml" >"${CMAKE_BINARY_DIR}/nfpm_config.yaml"
    if grep -q '\${[^}]*}' "${CMAKE_BINARY_DIR}/nfpm_config.yaml"; then
        die "Some variables were not substituted in nfpm.yaml."
    fi

    info "Packaging the following files:"
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
        pkgbuild --root "${PACKAGE_HOME}" --identifier "com.laoshanxi.appmesh" --version "${APPMESH_VERSION}" --install-location /opt/appmesh ${PACKAGE_FILE_NAME}
    else
        die "Unsupported platform: $OSTYPE"
    fi
}

###################
# Main Execution
###################

main() {
    validate_environment
    setup_platform_specifics
    create_directory_structure
    copy_binaries
    patch_linux_libraries
    copy_configuration_files
    copy_libraries
    handle_macos_specifics
    build_packages
    info "Build completed successfully!"
}

# Clean existing packages
find . -maxdepth 1 -type f \( -name "*.rpm" -o -name "*.deb" -o -name "*.gz" \) -delete

# Execute main function
main
