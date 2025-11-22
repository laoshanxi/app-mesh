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
	go clean -cache -fuzzcache -modcache
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
	log4cpp
	openldap
	cryptopp
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
fi

# Install the packages, skipping if they are already installed
for package in "${BREW_PACKAGES[@]}"; do
    if command -v "$package" &>/dev/null; then
        echo "$package is already installed, skipping."
    else
        echo "Installing $package..."
        brew install "$package"
    fi
done

# Install curl and ace from custom formulas
TAP_PATH="$(brew --repo)/Library/Taps/laoshanxi/homebrew-custom-core/Formula"
mkdir -p "$TAP_PATH"
for formula in curl ace boost; do
    wget -q -O "${TAP_PATH}/${formula}.rb" "https://github.com/laoshanxi/homebrew-core/raw/refs/heads/master/Formula/${formula:0:1}/${formula}.rb"
    HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew reinstall --build-from-source --verbose "laoshanxi/homebrew-custom-core/${formula}"
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

echo "Installing linenoise-ng..."
cd ${TMP_DIR}
git clone --depth=1 https://github.com/arangodb/linenoise-ng.git
sed -i '' -E 's/cmake_minimum_required\(VERSION[[:space:]]+[0-9.]+\)/cmake_minimum_required(VERSION 3.20)/' linenoise-ng/CMakeLists.txt
cd linenoise-ng; mkdir build; cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make linenoise && sudo make install

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
sed -i '' 's/\$(AR) -crs $@ --/\$(AR) -crs $@/' Makefile
make
sudo cp qrcodegen.hpp /usr/local/include/
sudo cp libqrcodegencpp.a /usr/local/lib/

echo "Installing Catch2..."
cd ${TMP_DIR}
git clone --depth=1 -b v2.x https://github.com/catchorg/Catch2.git
sudo cp Catch2/single_include/catch2/catch.hpp /usr/local/include/

echo "Installing concurrentqueue..."
cd ${TMP_DIR}
git clone --depth=1 https://github.com/cameron314/concurrentqueue.git
sudo cp -rf concurrentqueue /usr/local/include/

echo "Building and installing libwebsockets..."
cd $TMP_DIR
git clone --depth=1 https://libwebsockets.org/repo/libwebsockets
cd libwebsockets/ && mkdir build && cd build && cmake -DLWS_WITHOUT_TESTAPPS=ON ..
make
sudo make install

echo "Installing uWebSockets..."
cd $TMP_DIR
git clone --recurse-submodules --shallow-submodules --depth=1 https://github.com/uNetworking/uWebSockets.git
cd uWebSockets
make && sudo make install
sudo cp uSockets/src/libusockets.h /usr/local/include/
sudo cp uSockets/uSockets.a /usr/local/lib/libuSockets.a

echo "Building and installing uriparser..."
cd $TMP_DIR
git clone --depth=1 https://github.com/uriparser/uriparser.git
cd uriparser && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF ..
make
sudo make install

echo "Build completed successfully!"
