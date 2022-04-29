#!/bin/bash
################################################################################
## This script is used to install 3rd-party dependency libraries by apt
################################################################################
export DEBIAN_FRONTEND=noninteractive

apt update
# apt install -y build-essential
apt install -y wget
apt install -y g++ cmake make

# security
apt install -y libldap2-dev liboath-dev

# fpm
apt install -y ruby ruby-dev rubygems alien
apt install -y lsb-release
apt install -y ca-certificates
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ruby -rnet/http -e "Net::HTTP.get URI('https://gem.fury.io')"
gem install fpm

# golang
apt install -y golang
export GO111MODULE=on
export GOPROXY=https://goproxy.io,direct
go get github.com/valyala/fasthttp@v1.34.0

# cpplint tools
apt install -y clang
apt install -y cppcheck
apt install -y gh git

# protobuf
apt install -y libprotobuf-dev
apt install -y protobuf-compiler

# dependency libraries
apt install -y liblog4cpp5-dev
apt install -y libace-dev
apt install -y libcpprest-dev
apt install -y libboost-all-dev
apt install -y libcrypto++-dev

# tool
apt install -y golang-cfssl
apt install -y upx-ucl

# qr code
wget --output-document=qrc https://github.com/laoshanxi/qrc/releases/download/v0.1.2/qrc_linux_amd64
chmod +x qrc && mv qrc /usr/bin/
