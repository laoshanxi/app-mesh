#!/usr/bin/env bash
################################################################################
## Script to install 3rd-party dependency libraries for macOS
################################################################################

# Fail on any error and undefined variables
set -euo pipefail

# Define key directories
SRC_DIR=$(dirname $(dirname $(dirname $(readlink -f "$0"))))
TMP_DIR=$(mktemp -d $(pwd)/appmesh.tmp)
BUILD_THREADS=$(sysctl -n hw.ncpu || echo 4)

cleanup() {
	echo "Cleaning up temporary directory..."
	rm -rf "${TMP_DIR}"
}

# Set up trap for cleanup
trap cleanup EXIT

# Change to temporary directory
cd "${TMP_DIR}"

# brew dependencies
BREW_PACKAGES=(
	wget
	cmake
	go
	openssl@3
	boost
	log4cpp
	openldap
	cryptopp
	oath-toolkit
	yaml-cpp
	nlohmann-json
	msgpack-cxx
)

# Ensure brew is available
if ! command -v brew &>/dev/null; then
	echo "Installing Homebrew"
	NONINTERACTIVE=1
	/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
	brew install "${BREW_PACKAGES[@]}"
fi

# Install curl and ace from custom formulas
for formula in curl ace; do
	wget "https://github.com/laoshanxi/homebrew-core/raw/refs/heads/master/Formula/${formula:0:1}/${formula}.rb"
	brew reinstall --build-from-source --verbose "./${formula}.rb"
done

# Install Go tools
echo "Installing Go tools..."
export GO111MODULE=on
export GOBIN=/usr/local/bin
go install github.com/cloudflare/cfssl/cmd/cfssl@latest
go install github.com/cloudflare/cfssl/cmd/cfssljson@latest
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

echo "Installing hashidsxx..."
cd ${TMP_DIR}
sudo mkdir -p /usr/local/include/hashidsxx
git clone --depth=1 https://github.com/schoentoon/hashidsxx.git
sudo cp -rf hashidsxx/* /usr/local/include/hashidsxx/

echo "Installing croncpp..."
cd ${TMP_DIR}
git clone --depth=1 https://github.com/mariusbancila/croncpp.git
sudo cp croncpp/include/croncpp.h /usr/local/include/

echo "Installing wildcards..."
cd ${TMP_DIR}
git clone --depth=1 https://github.com/laoshanxi/wildcards.git
sudo mkdir -p /usr/local/include/wildcards
sudo cp -rf wildcards/single_include/* /usr/local/include/wildcards

echo "Installing prometheus-cpp..."
cd ${TMP_DIR}
sudo mkdir -p /usr/local/src/prometheus
git clone --depth=1 https://github.com/jupp0r/prometheus-cpp.git
sudo cp -rf prometheus-cpp/core/src/* /usr/local/src/prometheus/
sudo cp -rf prometheus-cpp/core/include/prometheus /usr/local/include/
sudo tee /usr/local/include/prometheus/detail/core_export.h <<EOF
#ifndef PROMETHEUS_CPP_CORE_EXPORT
#define PROMETHEUS_CPP_CORE_EXPORT
#endif
EOF

echo "Installing jwt-cpp..."
cd ${TMP_DIR}
git clone --depth=1 https://github.com/Thalhammer/jwt-cpp.git
sudo cp -rf jwt-cpp/include/jwt-cpp /usr/local/include/

echo "Building and installing ldap-cpp..."
cd ${TMP_DIR}
git clone --depth=1 https://github.com/AndreyBarmaley/ldap-cpp.git
cd ldap-cpp
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF ..
make
sudo make install

echo "Building and installing QR-Code-generator..."
cd ${TMP_DIR}
git clone --depth=1 https://github.com/nayuki/QR-Code-generator.git
cd QR-Code-generator/cpp
sudo cp qrcodegen.* /usr/local/include/
make || ar -crs libqrcodegencpp.a qrcodegen.o
sudo cp libqrcodegencpp.a /usr/local/lib/

echo "Installing Catch2..."
cd ${TMP_DIR}
git clone --depth=1 -b v2.x https://github.com/catchorg/Catch2.git
sudo cp Catch2/single_include/catch2/catch.hpp /usr/local/include/

echo "Build completed successfully!"
