#!/bin/sh
################################################################################
## This Script file is used to update OS openssl version to 1.1.1d for CentOS 7.x
################################################################################
set -x
mkdir ssl_build
cd ssl_build

yum install -y openssl-devel gcc-c++ wget make perl
wget https://www.openssl.org/source/openssl-1.1.1d.tar.gz

tar zxvf openssl-1.1.1d.tar.gz
cd openssl-1.1.1d/
yum install -y zlib  zlib-devel

./config shared zlib
#./config shared zlib --prefix=/usr/local/openssl --openssldir=/usr/local/openssl/ssl

make; make install

# include files
mv /usr/include/openssl /usr/include/openssl.bak
ln -s /usr/local/include/openssl  /usr/include/openssl
ln -s /usr/local/lib64/libssl.so.1.1 /usr/lib64/libssl.so.1.1
ln -s /usr/local/lib64/libcrypto.so.1.1 /usr/lib64/libcrypto.so.1.1

cd ..
rm -rf ssl_build

cd /usr/lib64/
rm -f libssl.so
ln -s libssl.so.1.1 libssl.so
rm -f libcrypto.so
ln -s libcrypto.so.1.1 libcrypto.so

find / -name ssl.h | xargs ls -al
find / -name libssl.so | xargs ls -al
find / -name libcrypto.so | xargs ls -al
