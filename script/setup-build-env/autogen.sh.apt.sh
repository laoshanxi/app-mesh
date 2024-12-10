#!/usr/bin/env bash
################################################################################
## This script is used to install 3rd-party dependency libraries by apt
################################################################################
set -x
set -e
WGET_A="wget --continue --quiet --backups=1 --tries=30 --no-check-certificate"
architecture="arm64" # TODO: can not get arm64, set to default
case $(uname -m) in
    i386)   architecture="386" ;;
    i686)   architecture="386" ;;
    x86_64) architecture="amd64" ;;
    arm)    dpkg --print-architecture | grep -q "arm64" && architecture="arm64" || architecture="arm" ;;
esac
export DEBIAN_FRONTEND=noninteractive
SRC_DIR=$(dirname $(dirname $(dirname $(readlink -f "$0"))))
export ROOTDIR=$(pwd)/appmesh.tmp
mkdir -p ${ROOTDIR}
cd ${ROOTDIR}

apt update
# apt full-upgrade -q -y
# apt install -y build-essential
apt install -y wget curl libcurl4-openssl-dev libssl-dev
apt install -y g++ cmake make

# memory tool for debug
# apt install -y valgrind libasan6

# security
apt install -y libldap-dev liboath-dev
apt install -y alien gettext unzip

# cpplint tools
# apt install -y clang
# apt install -y cppcheck
apt install -y git

# dependency libraries
apt install -y liblog4cpp5-dev
apt install -y libboost-all-dev
apt install -y libcrypto++-dev
apt install -y libreadline-dev patchelf

# build ACE
apt install -y libace-dev libace-ssl-dev

# yaml-cpp
apt install -y libyaml-cpp-dev

# json
$WGET_A https://github.com/nlohmann/json/releases/download/v3.11.3/include.zip
unzip -o include.zip
mv include/nlohmann /usr/local/include/

# syft for SBOM
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Golang
# apt install -y golang
# go env -w GOPROXY=https://goproxy.io,direct;go env -w GOBIN=/usr/local/bin;go env -w GO111MODULE=on
if command -v go >/dev/null 2>&1; then
	echo "Go is installed: $(go version)"
else
	GO_ARCH=$architecture
	GO_VER=1.23.1
	$WGET_A https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz
	rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VER}.linux-${GO_ARCH}.tar.gz
	rm -rf /usr/bin/go && ln -s /usr/local/go/bin/go /usr/bin/go
	go version
fi
# Golang third party library
export GO111MODULE=on
#export GOPROXY=https://goproxy.io,direct
# go binaries
export GOBIN=/usr/local/bin
go install github.com/cloudflare/cfssl/cmd/cfssl@latest
go install github.com/cloudflare/cfssl/cmd/cfssljson@latest
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

#messagepack Python pip
apt install -y python3-pip
if [ true ]; then
	git clone -b cpp_master --depth 1 https://github.com/msgpack/msgpack-c.git
	cd msgpack-c
	cmake .
	cmake --build . --target install
fi
python3 -m pip install --break-system-packages --upgrade --ignore-installed msgpack requests requests_toolbelt aniso8601 twine wheel

git clone --depth=1 https://github.com/schoentoon/hashidsxx.git
cp -rf hashidsxx /usr/local/include/

git clone --depth=1 https://github.com/mariusbancila/croncpp.git
cp croncpp/include/croncpp.h /usr/local/include/

git clone --depth=1 https://github.com/laoshanxi/wildcards.git
cp -rf wildcards/single_include/ /usr/local/include/wildcards

git clone --depth=1 https://github.com/jupp0r/prometheus-cpp.git
cp -rf prometheus-cpp/core/src /usr/local/src/prometheus
cp -rf prometheus-cpp/core/include/prometheus /usr/local/include/
cat <<EOF >/usr/local/include/prometheus/detail/core_export.h
#ifndef PROMETHEUS_CPP_CORE_EXPORT
#define PROMETHEUS_CPP_CORE_EXPORT
#endif
EOF

git clone --depth=1 https://github.com/Thalhammer/jwt-cpp.git
cp -rf jwt-cpp/include/jwt-cpp /usr/local/include/

git clone --depth=1 https://github.com/AndreyBarmaley/ldap-cpp.git
cd ldap-cpp; mkdir build; cd build; cmake -DBUILD_SHARED_LIBS=OFF ..; make; make install

git clone --depth=1 https://github.com/nayuki/QR-Code-generator.git
cd QR-Code-generator/cpp && cp qrcodegen.* /usr/local/include/ && make && cp libqrcodegencpp.a /usr/local/lib/

git clone --depth=1 -b v2.x https://github.com/catchorg/Catch2.git
cp Catch2/single_include/catch2/catch.hpp /usr/local/include/

# clean
go clean -cache -fuzzcache -modcache
pip3 cache purge
if [ -f "/usr/bin/yum" ]; then
	yum clean all
else
	apt-get clean
fi

cd $SRC_DIR; mkdir -p b; cd b; cmake ..; make agent
rm -rf ${ROOTDIR}