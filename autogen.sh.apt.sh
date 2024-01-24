#!/bin/bash
################################################################################
## This script is used to install 3rd-party dependency libraries by apt
################################################################################
set -x
set -e
export DEBIAN_FRONTEND=noninteractive
SRC_DIR=$(dirname $(readlink -f "$0"))
export ROOTDIR=$(pwd)/appmesh.tmp
mkdir -p ${ROOTDIR}
cd ${ROOTDIR}

apt update
# apt full-upgrade -q -y
# apt install -y build-essential
apt install -y wget curl
apt install -y g++ cmake make

# memory tool for debug
apt install -y valgrind libasan6

# security
apt install -y libldap-dev liboath-dev

# cpplint tools
apt install -y clang
apt install -y cppcheck
apt install -y git

# dependency libraries
apt install -y liblog4cpp5-dev
apt install -y libace-dev libace-ssl-dev
apt install -y libboost-all-dev
apt install -y libcrypto++-dev

# curlcpp
git clone --depth=1 https://github.com/jpbarrette/curlpp.git
cd curlpp && mkdir -p build && cd build
cmake ..
cmake --build .
make install

# json
wget https://github.com/nlohmann/json/releases/download/v3.11.2/include.zip
unzip -o include.zip
mv include/nlohmann /usr/local/include/

# Golang
apt install -y golang
# Golang third party library
export GO111MODULE=on
export GOPROXY=https://goproxy.io,direct
# go binaries
export GOBIN=/usr/local/bin
go install github.com/laoshanxi/qrc/cmd/qrc@latest
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
python3 -m pip install --upgrade msgpack requests requests_toolbelt aniso8601 twine wheel

git clone --depth=1 https://github.com/schoentoon/hashidsxx.git
cp -rf hashidsxx /usr/local/include/

git clone --depth=1 https://github.com/mariusbancila/croncpp.git
cp croncpp/include/croncpp.h /usr/local/include/

git clone --depth=1 https://github.com/laoshanxi/wildcards.git
cp -rf wildcards/single_include/ /usr/local/include/wildcards

git clone --depth=1 https://github.com/jupp0r/prometheus-cpp.git
cp -rf prometheus-cpp/core/src /usr/local/src/prometheus
cp -rf prometheus-cpp/core/include/prometheus /usr/local/include/
cat << EOF > /usr/local/include/prometheus/detail/core_export.h
#ifndef PROMETHEUS_CPP_CORE_EXPORT
#define PROMETHEUS_CPP_CORE_EXPORT
#endif
EOF

git clone --depth=1 https://github.com/Thalhammer/jwt-cpp.git
cp -rf jwt-cpp/include/jwt-cpp /usr/local/include/

git clone --depth=1 https://github.com/AndreyBarmaley/ldap-cpp.git
cd ldap-cpp; mkdir build; cd build; cmake -DBUILD_SHARED_LIBS=OFF ..; make; make install

cd $SRC_DIR; mkdir -p b; cd b; cmake ..; make agent

# clean
rm -rf ${ROOTDIR}
go clean -cache
go clean -fuzzcache
go clean --modcache
pip3 cache purge
if [ -f "/usr/bin/yum" ]; then
	yum clean all
else
	apt-get clean
fi
