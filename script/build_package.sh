#!/usr/bin/env bash
################################################################################
## This script builds rpm/deb packages and is launched by a CMake command.
################################################################################

set -ex # Exit on error and enable command tracing

# Validate CMAKE_BINARY_DIR
if [[ -z "${CMAKE_BINARY_DIR}" || ! -d "${CMAKE_BINARY_DIR}" ]]; then
    echo "Error: CMAKE_BINARY_DIR does not exist or is not set."
    exit 1
fi

# Remove existing package files
rm -f ./*.rpm ./*.deb

# Set up environment variables (also for nfpm)
export PACKAGE_HOME="${CMAKE_BINARY_DIR}/nfpm_home"
export INSTALL_LOCATION="/opt/appmesh"
export GOARCH=$(go env GOARCH)

# Create required directories
rm -rf "${PACKAGE_HOME}"
mkdir -p "${PACKAGE_HOME}"/{ssl,script,lib64,bin}

# Copy binary files
cp "${CMAKE_BINARY_DIR}/gen/"{appc,appsvc,agent} "${PACKAGE_HOME}/bin/"

# version compatibility for libreadline
LIB_READLINE_VER=$(ldd "${PACKAGE_HOME}/bin/appc" | awk '/libreadline.so/ {print $1}')
LIB_READLINE=$(echo "$LIB_READLINE_VER" | sed 's/\.[0-9.]*$//')
if [[ "$OSTYPE" == "linux"* ]]; then
    # Linux environment
    for bin in appc appsvc; do
        patchelf --replace-needed "$LIB_READLINE_VER" "$LIB_READLINE" "${PACKAGE_HOME}/bin/$bin" --debug || true
    done
fi

# Copy configuration and script files
cp "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/"{config.yaml,security/security.yaml,security/ldapplugin/ldap.yaml} "${PACKAGE_HOME}/"
cp "${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/agent/pkg/cloud/consul-api-config.yaml" "${PACKAGE_HOME}/"
cp "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/rest/openapi.yaml" "${PACKAGE_HOME}/script/"
cp "${CMAKE_CURRENT_SOURCE_DIR}/script/"{app*.sh,*.service,prom*.yml,docker*.yaml,*.html} "${PACKAGE_HOME}/script/"
cp "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/"{bash_completion.sh,container_monitor.py,appmesh_arm.py} "${PACKAGE_HOME}/script/"
cp "${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/python/py_exec.py" "${PACKAGE_HOME}/bin/"
cp "${CMAKE_CURRENT_SOURCE_DIR}/script/ssl_cert_generate.sh" /usr/local/bin/{cfssl,cfssljson} "${PACKAGE_HOME}/ssl/"
cp -r "${CMAKE_CURRENT_SOURCE_DIR}/script/apps" "${PACKAGE_HOME}/"

chmod +x "${PACKAGE_HOME}/script/"*.sh

# Update dynamic library path based on the OS and architecture
if [[ "$OSTYPE" == "linux"* ]]; then
    # Linux
    export LD_LIBRARY_PATH="/usr/local/ssl/lib:/usr/local/lib64:/usr/local/lib:${LD_LIBRARY_PATH:-}"
    LIBRARY_INSPECTOR="ldd"
    LIBRARY_EXTRACTOR="awk '{print \$3}'"
else
    # macOS
    ARCHITECTURE=$(uname -m)
    if [[ "$ARCHITECTURE" == "arm64" ]]; then
        BREW_DIR="/opt/homebrew"
    else
        BREW_DIR="/usr/local"
    fi
    export DYLD_LIBRARY_PATH="$BREW_DIR/lib:$BREW_DIR/lib64:/usr/local/ssl/lib:${DYLD_LIBRARY_PATH:-}"
    LIBRARY_INSPECTOR="otool -L"
    LIBRARY_EXTRACTOR="awk '{print \$1}'"
fi
# Copy necessary libraries
dependencies=(boost curl curlpp ACE libssl libcrypto log4cpp oath yaml)
for dep in "${dependencies[@]}"; do
    # Inspect dependencies and extract library paths
    $LIBRARY_INSPECTOR "${CMAKE_BINARY_DIR}/gen/appsvc" | grep "$dep" | eval $LIBRARY_EXTRACTOR | xargs -I{} bash -c 'echo "Copying: {}"; cp {} "${PACKAGE_HOME}/lib64" || true'
done

# Substitute nfpm config with environment variables
envsubst <"${CMAKE_CURRENT_SOURCE_DIR}/script/nfpm.yaml" | tee "${CMAKE_BINARY_DIR}/nfpm_config.yaml"

if [[ "$OSTYPE" == "linux"* ]]; then
    # Linux logic for GLIBC and GCC versions
    GLIBC_VERSION=$(ldd --version | awk 'NR==1{print $NF}')
    GCC_VERSION=$(gcc -dumpversion)

    echo "GLIBC Version: $GLIBC_VERSION"
    echo "GCC Version: $GCC_VERSION"

    # Build packages using nfpm
    nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager deb
    nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager rpm

    # Rename output packages with additional information
    ARCH=$(arch)
    for pkg in appmesh*.{rpm,deb}; do
        mv "$pkg" "${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERSION}_glibc_${GLIBC_VERSION}_${ARCH}.${pkg##*.}"
    done
else
    # macOS does not use GLIBC; instead, check the macOS version
    MACOS_VERSION=$(sw_vers -productVersion)
    # Extract the Clang version
    CLANG_VERSION=$(clang --version | awk '/Apple clang version/ {print $4}')

    echo "macOS Version: $MACOS_VERSION"
    echo "Clang Version: $CLANG_VERSION"
fi
