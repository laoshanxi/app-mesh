#!/bin/bash
################################################################################
## This script is used to install 3rd-party dependency libraries by apt
################################################################################
set -x
set -e
export DEBIAN_FRONTEND=noninteractive
SRC_DIR=$(dirname $(readlink -f "$0"))

apt update
# apt full-upgrade -q -y
# apt install -y build-essential
apt install -y wget curl
apt install -y g++ cmake make

# memory tool for debug
apt install -y valgrind libasan6

# security
apt install -y libldap-dev liboath-dev

# fpm
apt install -y ruby ruby-dev rubygems alien
apt install -y lsb-release
apt install -y ca-certificates
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ruby -rnet/http -e "Net::HTTP.get URI('https://gem.fury.io')"
gem install fpm

# cpplint tools
apt install -y clang
apt install -y cppcheck
apt install -y git

# dependency libraries
apt install -y liblog4cpp5-dev
apt install -y libace-dev libace-ssl-dev
apt install -y libboost-all-dev
apt install -y libcrypto++-dev

# tool
apt install -y golang-cfssl

# cpr
# https://github.com/libcpr/cpr
git clone --depth=1 -b 1.9.x https://github.com/libcpr/cpr.git
cd cpr && mkdir -p build && cd build
cmake .. -DCPR_USE_SYSTEM_CURL=ON
cmake --build .
make install

# json
wget https://github.com/nlohmann/json/releases/download/v3.11.2/include.zip
unzip -o include.zip
mv include/nlohmann /usr/local/include/

# qr code
wget --output-document=qrc https://github.com/laoshanxi/qrc/releases/download/v0.1.2/qrc_linux_amd64
chmod +x qrc && mv qrc /usr/local/bin

# Golang
apt install -y golang
# Golang third party library
export GO111MODULE=on
export GOPROXY=https://goproxy.io,direct

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
