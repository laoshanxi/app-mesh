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
    cp "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/rest/index.html" "${PACKAGE_HOME}/script/"
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

# resolve_macos_dylib_path: Resolves @rpath/@loader_path references in macOS dylib paths
# Usage: resolve_macos_dylib_path <dylib_path> <binary_path>
# Returns the actual file path or the input if unresolvable
resolve_macos_dylib_path() {
    local dylib_path="$1"
    local binary_path="$2"

    # If it's already a real path, return it
    [[ -f "$dylib_path" ]] && { echo "$dylib_path"; return 0; }

    local binary_dir=$(dirname "$binary_path")
    local lib_name=$(basename "$dylib_path")
    local resolved

    # Handle @rpath/@loader_path
    if [[ "$dylib_path" == @rpath/* ]]; then
        resolved="${dylib_path#@rpath/}"
    elif [[ "$dylib_path" == @loader_path/* ]]; then
        resolved="${dylib_path#@loader_path/}"
    else
        echo "$dylib_path"
        return 0
    fi

    # Search paths: relative to binary, system paths, and Homebrew
    local BREW_DIR="/opt/homebrew"
    [[ "$(uname -m)" != "arm64" ]] && BREW_DIR="/usr/local"
    
    local search_paths=(
        "$binary_dir"
        "$binary_dir/lib"
        "$binary_dir/lib64"
        "/usr/local/lib"
        "/usr/local/lib64"
        "$BREW_DIR/lib"
        "$BREW_DIR/lib64"
        "$BREW_DIR/opt"
    )

    # Try exact match in each search path
    for dir in "${search_paths[@]}"; do
        [[ -f "$dir/$resolved" ]] && { echo "$dir/$resolved"; return 0; }
    done

    # Fallback: search Homebrew for library by name
    local found=$(find "$BREW_DIR" -name "$lib_name" -type f 2>/dev/null | head -1)
    [[ -n "$found" ]] && { echo "$found"; return 0; }

    # Unresolvable: return original
    echo "$dylib_path"
}

copy_libraries() {
    local dependencies=(boost curl ACE libssl libcrypto yaml websockets uriparser spdlog libfmt)
    for bin_path in "${CMAKE_BINARY_DIR}/gen/appc" "${CMAKE_BINARY_DIR}/gen/appsvc"; do
        for dep in "${dependencies[@]}"; do
            info "Scanning $bin_path for dependency: $dep"
            while IFS= read -r lib; do
                if [[ -n "$lib" ]]; then
                    # Resolve @rpath/@loader_path on macOS
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        lib=$(resolve_macos_dylib_path "$lib" "$bin_path")
                    fi
                    [[ -f "$lib" ]] && copy "$lib" "${PACKAGE_HOME}/lib64"
                fi
            done < <(get_dependencies "$bin_path" "$dep")
        done
    done
}

handle_macos_specifics() {
    if [[ "$OSTYPE" != "darwin"* ]]; then
        return 0
    fi

    info "Handling macOS specific dependency chains..."

    # Helper to copy a library and its transitive dependencies matching a pattern
    copy_transitive() {
        local binary="$1"
        local primary_pattern="$2"
        local secondary_pattern="$3"
        
        while IFS= read -r lib; do
            [[ -n "$lib" ]] || continue
            [[ -f "$lib" ]] || continue
            info "Copying dependency: $lib"
            copy "$lib" "${PACKAGE_HOME}/lib64"
            
            # Copy secondary dependencies
            if [[ -n "$secondary_pattern" ]]; then
                while IFS= read -r sec_lib; do
                    [[ -n "$sec_lib" ]] || continue
                    [[ -f "$sec_lib" ]] || continue
                    info "Copying transitive dependency: $sec_lib"
                    copy "$sec_lib" "${PACKAGE_HOME}/lib64"
                done < <(get_dependencies "$lib" "$secondary_pattern")
            fi
        done < <(get_dependencies "$binary" "$primary_pattern")
    }

    # 1) curl -> openldap -> libsasl2
    copy_transitive "${CMAKE_BINARY_DIR}/gen/appsvc" "curl" "openldap" | while read -r ldap; do
        while IFS= read -r sasl; do
            [[ -n "$sasl" ]] || continue
            [[ -f "$sasl" ]] || continue
            info "Copying libsasl2: $sasl"
            copy "$sasl" "${PACKAGE_HOME}/lib64"
        done < <(get_dependencies "$ldap" "libsasl2")
    done

    # 2) boost_regex -> libicu
    copy_transitive "${CMAKE_BINARY_DIR}/gen/appc" "libboost_regex" "libicu"

    # Replace LD_LIBRARY_PATH to DYLD_LIBRARY_PATH for macOS
    sed -i '' 's/LD_LIBRARY_PATH/DYLD_LIBRARY_PATH/g' "${PACKAGE_HOME}/script/"*
}

build_packages() {
    envsubst <"${CMAKE_CURRENT_SOURCE_DIR}/script/pack/nfpm.yaml" >"${CMAKE_BINARY_DIR}/nfpm_config.yaml"
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
