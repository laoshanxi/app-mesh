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
for bin in appc appsvc; do
    patchelf --replace-needed "$LIB_READLINE_VER" "$LIB_READLINE" "${PACKAGE_HOME}/bin/$bin" --debug
done

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

# Update LD_LIBRARY_PATH for next ldd find correct dependencies
export LD_LIBRARY_PATH="/usr/local/ssl/lib:/usr/local/lib64:/usr/local/lib:${LD_LIBRARY_PATH:-}"

# Copy necessary libraries
dependencies=(boost curl curlpp ACE libssl libcrypto log4cpp oath yaml)
for dep in "${dependencies[@]}"; do
    ldd "${CMAKE_BINARY_DIR}/gen/appsvc" | grep "$dep" | awk '{print $3}' | xargs -I{} cp {} "${PACKAGE_HOME}/lib64"
done

# Get GLIBC and GCC versions
GLIBC_VERSION=$(ldd --version | awk 'NR==1{print $NF}')
GCC_VERSION=$(gcc -dumpversion)

# Substitute nfpm config with environment variables
envsubst <"${CMAKE_CURRENT_SOURCE_DIR}/script/nfpm.yaml" | tee "${CMAKE_BINARY_DIR}/nfpm_config.yaml"

# Build packages using nfpm
nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager deb
nfpm pkg --config "${CMAKE_BINARY_DIR}/nfpm_config.yaml" --packager rpm

# Rename output packages with additional information
ARCH=$(arch)
for pkg in appmesh*.{rpm,deb}; do
    mv "$pkg" "${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERSION}_glibc_${GLIBC_VERSION}_${ARCH}.${pkg##*.}"
done
