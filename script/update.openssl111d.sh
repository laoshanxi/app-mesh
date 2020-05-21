#!/bin/sh
################################################################################
## This Script file is used to update OS openssl version to 1.1.1d for CentOS 7.x
################################################################################
set -x
mkdir ssl_build
cd ssl_build
if [ -f "/usr/bin/yum" ]; then
  yum install -y openssl-devel gcc-c++ wget make perl
  yum install -y zlib zlib-devel
elif [ -f "/usr/bin/apt" ]; then
  apt-get update
  apt-get remove -y openssl
  apt-get -y install wget g++ make perl
  apt-get -y install zlib1g zlib1g-dev
fi
wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz

tar zxvf openssl-1.1.1g.tar.gz
cd openssl-1.1.1g/

./config shared zlib
make; make install

# include files
rm -rf /usr/include/openssl
ln -s /usr/local/include/openssl /usr/include/openssl
\cp /usr/local/bin/openssl /usr/bin/

if [ -f "/usr/bin/yum" ]; then
  ln -s /usr/local/lib64/libssl.so.1.1 /usr/lib64/libssl.so.1.1
  ln -s /usr/local/lib64/libcrypto.so.1.1 /usr/lib64/libcrypto.so.1.1
elif [ -f "/usr/bin/apt" ]; then
  \cp /usr/local/lib/libssl.* /lib/x86_64-linux-gnu/
  \cp /usr/local/lib/libcrypto.* /lib/x86_64-linux-gnu/
fi

cd ..
rm -rf ssl_build

if [ -f "/usr/bin/yum" ]; then
  cd /usr/lib64/
elif [ -f "/usr/bin/apt" ]; then
  cd /lib/x86_64-linux-gnu/
fi
rm -f libssl.so
ln -s libssl.so.1.1 libssl.so
rm -f libcrypto.so
ln -s libcrypto.so.1.1 libcrypto.so

find / -name ssl.h | xargs ls -al
find / -name libssl.so | xargs ls -al
find / -name libcrypto.so | xargs ls -al
