#!/bin/bash
################################################################################
## This script is used to install 3rd-party dependency libraries by apt
################################################################################
set -x
set -e
export DEBIAN_FRONTEND=noninteractive

apt update
# apt full-upgrade -q -y
# apt install -y build-essential
apt install -y wget
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

# protobuf
apt install -y libprotobuf-dev
apt install -y protobuf-compiler

# cpplint tools
apt install -y clang
apt install -y cppcheck
apt install -y git

# dependency libraries
apt install -y liblog4cpp5-dev
apt install -y libace-dev
apt install -y libcpprest-dev
apt install -y libboost-all-dev
apt install -y libcrypto++-dev

# tool
apt install -y golang-cfssl
apt install -y upx-ucl

# cpr
# https://github.com/libcpr/cpr
git clone --depth=1 -b 1.9.2 https://github.com/libcpr/cpr.git
cd cpr && mkdir build && cd build
cmake .. -DCPR_USE_SYSTEM_CURL=ON
cmake --build .
make install

# json
wget https://github.com/nlohmann/json/releases/download/v3.11.2/include.zip
unzip -o include.zip
mv include/nlohmann /usr/local/include/

# qr code
wget --output-document=qrc https://github.com/laoshanxi/qrc/releases/download/v0.1.2/qrc_linux_amd64
chmod +x qrc && mv qrc /usr/bin/

# Golang
apt install -y golang
# Golang third party library
export GO111MODULE=on
export GOPROXY=https://goproxy.io,direct
go get -v github.com/valyala/fasthttp@v1.37.0
go get github.com/buaazp/fasthttprouter
go get github.com/klauspost/compress@v1.15.5
go get -v github.com/rs/xid
# Golang tools for VSCode
go install -v github.com/cweill/gotests/gotests@latest
go install -v github.com/fatih/gomodifytags@latest
go install -v github.com/josharian/impl@latest
go install -v github.com/haya14busa/goplay/cmd/goplay@latest
go install -v github.com/go-delve/delve/cmd/dlv@latest
go install -v honnef.co/go/tools/cmd/staticcheck@latest
go install -v golang.org/x/tools/gopls@latest
# protoc
go get -v google.golang.org/protobuf@latest
go install -v github.com/golang/protobuf/protoc-gen-go@latest
ln -s ~/go/bin/protoc-gen-go /usr/bin/protoc-gen-go
