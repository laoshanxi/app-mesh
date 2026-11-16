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
        install -m 755 "$bin" "${PACKAGE_HOME}/bin/$(basename "$bin")"
        info "Copied $(basename "$bin") into the main package ($("$bin" version 2>/dev/null || echo 'version unknown'))"
    done
}

################################################################################
# macOS Code Signing Function
################################################################################
codesign_macos_binaries() {
    local package_root="$1"
    [[ -z "$package_root" ]] && die "package_root parameter required"
    [[ ! -d "$package_root" ]] && die "Package root does not exist: $package_root"

    info "Ad-hoc code signing binaries and libraries in $package_root..."

    local signed_count=0
    local failed_count=0
    local lib_suffix=".dylib"

    # Find and sign all dylibs and executable files
    while IFS= read -r -d '' file; do
        if codesign --force --sign - "$file" 2>/dev/null; then
            ((signed_count++))
        else
            log "WARNING: Failed to sign: $file"
            ((failed_count++))
        fi
    done < <(find "$package_root" -type f \( -name "*${lib_suffix}" -o -perm -111 \) -print0)

    info "Code signing completed: $signed_count signed, $failed_count failed"
    return 0
}

info "Packaging contents of: ${PACKAGE_HOME}"
# Clean previous artifacts
find . -maxdepth 1 -type f \( -name "*.rpm" -o -name "*.deb" -o -name "*.pkg" \) -delete

if [[ "$OSTYPE" == "linux"* ]]; then
    # Dex is a mandatory content of the Linux and macOS main packages.
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

elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Dex is a mandatory content of the Linux and macOS main packages.
    copy_dex

    export MACOS_VERSION
    MACOS_VERSION=$(sw_vers -productVersion | cut -d '.' -f1)
    export CLANG_VERSION
    CLANG_VERSION=$(clang --version | awk -F ' ' '/Apple clang version/ {print $4}' | cut -d '.' -f1)
    export PACKAGE_FILE_NAME="${CMAKE_BINARY_DIR}/${PROJECT_NAME}_${PROJECT_VERSION}_clang_${CLANG_VERSION}_macos_${MACOS_VERSION}_${GOARCH}.pkg"

    # Generate component plist to enable relocation
    COMPONENT_PLIST="${CMAKE_BINARY_DIR}/component.plist"

    # Analyze the root to create an initial plist
    pkgbuild --analyze --root "${PACKAGE_HOME}" "${COMPONENT_PLIST}"

    # Patch the plist to allow relocation (BundleIsRelocatable = true)
    # We also ensure the BundlePostInstallScriptPath is respected
    plutil -replace BundleIsRelocatable -bool YES "${COMPONENT_PLIST}" 2>/dev/null || \
    sed -i '' 's/<false\/>/<true\/>/g' "${COMPONENT_PLIST}" # Fallback if plutil fails

    # Code sign all binaries and libraries before packaging
    codesign_macos_binaries "${PACKAGE_HOME}"

    info "Building Relocatable PKG..."
    pkgbuild --root "${PACKAGE_HOME}" \
             --component-plist "${COMPONENT_PLIST}" \
             --scripts "${CMAKE_BINARY_DIR}/pkg_scripts" \
             --identifier "com.laoshanxi.appmesh" \
             --version "${PROJECT_VERSION}" \
             --install-location "${INSTALL_LOCATION}" \
             "${PACKAGE_FILE_NAME}"
else
    die "Unsupported platform: $OSTYPE"
fi

info "Build completed successfully!"
