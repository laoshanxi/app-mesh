#!/usr/bin/env bash
################################################################################
## This script is used to install all 3rd-party dependency libraries for macOS
################################################################################
set -x
set -e
WGET_A="wget --continue --quiet --backups=1 --tries=30 --no-check-certificate"

# Detect architecture
architecture="arm64"
case $(uname -m) in
x86_64) architecture="amd64" ;;
arm64) architecture="arm64" ;;
esac

SRC_DIR=$(dirname $(readlink -f "$0"))
export ROOTDIR=$(pwd)/appmesh.tmp
mkdir -p ${ROOTDIR}
cd ${ROOTDIR}

# Install Xcode Command Line Tools if not installed
if ! command -v xcode-select &>/dev/null; then
	xcode-select --install
fi

#proxy
#export HTTP_PROXY=http:127.0.0.1:7890
#export HTTPS_PROXY=$HTTP_PROXY
#export http_proxy=$HTTP_PROXY
#export https_proxy=$HTTP_PROXY
#git config --global http.proxy $HTTP_PROXY
#git config --global https.proxy $HTTP_PROXY

# Install Homebrew if not installed
if ! command -v brew &>/dev/null; then
	/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	# brew config
	# cd "$(brew --repo)" && git remote set-url origin https://mirrors.ustc.edu.cn/brew.git
	# brew update
	# brew config
fi

brew install wget cmake git go

# Install core libraries
brew install openssl@3 boost log4cpp

# Install security-related libraries
brew install openldap cryptopp oath-toolkit

# Install C++ libraries
brew install curlpp yaml-cpp nlohmann-json msgpack-cxx

# Set up environment variables
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
export OPENSSL_INCLUDE_DIR=$OPENSSL_ROOT_DIR/include
export OPENSSL_LIB_DIR=$OPENSSL_ROOT_DIR/lib

# Install ace
curl -o ace.rb https://raw.githubusercontent.com/laoshanxi/homebrew-core/refs/heads/master/Formula/a/ace.rb
brew install --build-from-source --verbose ./ace.rb

# Install Python packages
if ! command -v python3 &>/dev/null; then
	brew install python3
fi
python3 -m pip install --upgrade pip
python3 -m pip install msgpack requests requests_toolbelt aniso8601 twine wheel

# Go environment setup
export GO111MODULE=on
export GOBIN=/usr/local/bin

# Install Go tools
go install github.com/cloudflare/cfssl/cmd/cfssl@latest
go install github.com/cloudflare/cfssl/cmd/cfssljson@latest
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

cd ${ROOTDIR}

# Install header-only and source libraries
# hashidsxx
git clone --depth=1 https://github.com/schoentoon/hashidsxx.git
sudo cp -rf hashidsxx /usr/local/include/hashidsxx

# croncpp
git clone --depth=1 https://github.com/mariusbancila/croncpp.git
sudo cp croncpp/include/croncpp.h /usr/local/include/

# wildcards
git clone --depth=1 https://github.com/laoshanxi/wildcards.git
sudo cp -rf wildcards/single_include/ /usr/local/include/wildcards

# prometheus-cpp
sudo mkdir -p /usr/local/src/
git clone --depth=1 https://github.com/jupp0r/prometheus-cpp.git
sudo cp -rf prometheus-cpp/core/src /usr/local/src/prometheus
sudo cp -rf prometheus-cpp/core/include/prometheus /usr/local/include/
sudo tee /usr/local/include/prometheus/detail/core_export.h <<EOF
#ifndef PROMETHEUS_CPP_CORE_EXPORT
#define PROMETHEUS_CPP_CORE_EXPORT
#endif
EOF

# jwt-cpp
git clone --depth=1 https://github.com/Thalhammer/jwt-cpp.git
sudo cp -rf jwt-cpp/include/jwt-cpp /usr/local/include/

# ldap-cpp
git clone --depth=1 https://github.com/AndreyBarmaley/ldap-cpp.git
cd ldap-cpp
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF ..
make
sudo make install
cd ${ROOTDIR}

# QR-Code-generator
git clone --depth=1 https://github.com/nayuki/QR-Code-generator.git
cd QR-Code-generator/cpp
sudo cp qrcodegen.* /usr/local/include/
make
sudo cp libqrcodegencpp.a /usr/local/lib/
cd ${ROOTDIR}

# Catch2
git clone --depth=1 -b v2.x https://github.com/catchorg/Catch2.git
sudo cp Catch2/single_include/catch2/catch.hpp /usr/local/include/

# Clean up
go clean -cache
go clean -fuzzcache
go clean --modcache
pip3 cache purge

# Return to source directory and build
cd $SRC_DIR
mkdir -p b
cd b
cmake ..
make agent

# clean
#go clean -cache
#go clean -fuzzcache
#go clean --modcache
#pip3 cache purge

# Clean up temporary directory
rm -rf ${ROOTDIR}
