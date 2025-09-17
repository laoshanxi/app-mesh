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
copy() { rm -f "$2/$(basename "$1")" && cp "$1" "$2/"; }

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

copy_configuration_files() {
    local service_file="appmesh.systemd.service"
    [[ "$OSTYPE" == "darwin"* ]] && service_file="appmesh.launchd.plist"

    # Copy service file
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/pack/$service_file" "${PACKAGE_HOME}/script/"

    # Copy script files
    cp "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/appc.sh" "${PACKAGE_HOME}/script/"
    cp "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/rest/openapi.yaml" "${PACKAGE_HOME}/script/"
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/pack/"{setup.sh,entrypoint.sh,appmesh*.sh,*.html} "${PACKAGE_HOME}/script/"
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/docker/"{prom*.yml,docker*.yaml} "${PACKAGE_HOME}/script/"
    cp "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/"{bash_completion.sh,container_monitor.py,appmesh_agent.py} "${PACKAGE_HOME}/script/"

    # Copy binary support files
    cp ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/python/py_*.py "${PACKAGE_HOME}/bin/"

    # Copy SSL files
    cp "${CMAKE_CURRENT_SOURCE_DIR}/script/ssl/generate_ssl_cert.sh" /usr/local/bin/{cfssl,cfssljson} "${PACKAGE_HOME}/ssl/"

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

copy_dependency_chain() {
    # Usage: copy_dependency_chain <binary> <primary_pattern> <secondary_pattern> [mode]
    # mode: "copy" (default) - copy found libs; "list" - print found primary libs to stdout
    local binary="$1"
    local primary_pattern="$2"
    local secondary_pattern="$3"
    local mode="${4:-copy}"

    info "Resolving dependencies matching '$primary_pattern' from $binary (mode=$mode)"
    local primary_libs
    primary_libs=$($LIBRARY_INSPECTOR "$binary" | grep "$primary_pattern" | eval $LIBRARY_EXTRACTOR || true)

    if [[ -z "$primary_libs" ]]; then
        info "No dependencies matching '$primary_pattern' found in $binary"
        return 0
    fi

    # If caller requested list mode, print the primary libs and return
    if [[ "$mode" == "list" ]]; then
        echo "$primary_libs" | while read -r lib; do
            [[ -n "$lib" ]] && printf "%s\n" "$lib"
        done
        return 0
    fi

    # Default behaviour: copy primary libs and optional secondary libs
    echo "$primary_libs" | while read -r lib; do
        [[ -f "$lib" ]] || continue
        info "Found primary dependency: $lib"
        copy "$lib" "${PACKAGE_HOME}/lib64"

        if [[ -n "$secondary_pattern" ]]; then
            $LIBRARY_INSPECTOR "$lib" | grep "$secondary_pattern" | eval $LIBRARY_EXTRACTOR |
                while read -r sec_lib; do
                    [[ -f "$sec_lib" ]] || continue
                    info "Found secondary dependency: $sec_lib"
                    copy "$sec_lib" "${PACKAGE_HOME}/lib64"
                done
        fi
    done
}

# get_dependencies: return direct dependencies (one level) of a binary matching pattern
# Usage: get_dependencies <binary> <pattern>
# Prints matching library paths, one per line. Does not copy.
get_dependencies() {
    # get_dependencies <binary> <pattern>
    # Prints matching library paths (one per line). Caller can capture with
    # readarray -t arr < <(get_dependencies ...)
    local binary="$1"
    local pattern="$2"
    [[ -f "$binary" ]] || return 0
    $LIBRARY_INSPECTOR "$binary" | grep "$pattern" | eval $LIBRARY_EXTRACTOR || true
}

copy_libraries() {
    local dependencies=(boost curl ACE libssl libcrypto log4cpp oath yaml)
    local bin_path="${CMAKE_BINARY_DIR}/gen/appsvc"
    for dep in "${dependencies[@]}"; do
        info "Scanning appsvc for dependency: $dep"
        while IFS= read -r lib; do
            [[ -n "$lib" ]] && copy "$lib" "${PACKAGE_HOME}/lib64"
        done < <(get_dependencies "$bin_path" "$dep")
    done
}

handle_macos_specifics() {
    if [[ "$OSTYPE" != "darwin"* ]]; then
        return 0
    fi

    info "Handling macOS specific dependency chains..."

    # 1) curl (from appsvc) -> openldap -> libsasl2
    # Get curl-related libs from appsvc, then inspect them for openldap, then from libldap find libsasl2.
    while IFS= read -r curl_lib; do
        [[ -n "$curl_lib" ]] || continue
        while IFS= read -r ldap_lib; do
            [[ -n "$ldap_lib" ]] || continue
            info "Copying openldap dependency: $ldap_lib"
            copy "$ldap_lib" "${PACKAGE_HOME}/lib64"

            while IFS= read -r sasl_lib; do
                [[ -n "$sasl_lib" ]] || continue
				[[ -f "$sasl_lib" ]] || continue
                info "Copying sasl2 dependency: $sasl_lib"
                copy "$sasl_lib" "${PACKAGE_HOME}/lib64"
            done < <(get_dependencies "$ldap_lib" "libsasl2")
        done < <(get_dependencies "$curl_lib" "openldap")
    done < <(get_dependencies "${CMAKE_BINARY_DIR}/gen/appsvc" "curl")

    # 2) boost_regex -> libicu (inspect libs referenced by appc's libboost_regex)
    # find libboost_regex linked libs, copy them and then copy their libicu deps
    while IFS= read -r boost_regex_lib; do
        [[ -n "$boost_regex_lib" ]] || continue
        info "Copying libboost_regex dependency: $boost_regex_lib"
        copy "$boost_regex_lib" "${PACKAGE_HOME}/lib64"
        while IFS= read -r icu_lib; do
            [[ -n "$icu_lib" ]] || continue
            info "Copying libicu dependency: $icu_lib"
            copy "$icu_lib" "${PACKAGE_HOME}/lib64"
        done < <(get_dependencies "$boost_regex_lib" "libicu")
    done < <(get_dependencies "${CMAKE_BINARY_DIR}/gen/appc" "libboost_regex")

    # 3) boost_filesystem -> libboost_atomic (explicit sibling library)
    local boost_filesystem=$($LIBRARY_INSPECTOR "${CMAKE_BINARY_DIR}/gen/appc" | grep libboost_filesystem | eval $LIBRARY_EXTRACTOR)
    if [[ -n "$boost_filesystem" ]]; then
        local boost_atomic="$(dirname "$boost_filesystem")/libboost_atomic.dylib"
        if [[ -f "$boost_atomic" ]]; then
            info "Copying boost_atomic dependency: $boost_atomic"
            copy "$boost_atomic" "${PACKAGE_HOME}/lib64"
        fi
    fi

    # Replace LD_LIBRARY_PATH to DYLD_LIBRARY_PATH for macOS
    sed -i '' 's/LD_LIBRARY_PATH/DYLD_LIBRARY_PATH/g' "${PACKAGE_HOME}/script/"*
}

build_packages() {
    envsubst <"${CMAKE_CURRENT_SOURCE_DIR}/script/pack/nfpm.yaml" >"${CMAKE_BINARY_DIR}/nfpm_config.yaml"
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
        mkdir -p "${CMAKE_BINARY_DIR}/pkg_scripts"
        cp "${CMAKE_CURRENT_SOURCE_DIR}/script/pack/post_install.sh" "${CMAKE_BINARY_DIR}/pkg_scripts/postinstall"
        cp "${CMAKE_CURRENT_SOURCE_DIR}/script/pack/pre_uninstall.sh" "${CMAKE_BINARY_DIR}/pkg_scripts/preuninstall"
        cp "${CMAKE_CURRENT_SOURCE_DIR}/script/pack/post_uninstall.sh" "${CMAKE_BINARY_DIR}/pkg_scripts/postuninstall"
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
    setup_platform_specifics
    create_directory_structure
    copy_binaries
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
