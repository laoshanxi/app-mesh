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
  apt-get -y install libssl-dev wget g++ make perl
  apt-get -y install zlib1g zlib1g.dev
  rm -rf /lib/x86_64-linux-gnu/libcrypto.so*
  rm -rf /lib/x86_64-linux-gnu/libssl.so*
fi
wget https://www.openssl.org/source/openssl-1.1.1d.tar.gz

tar zxvf openssl-1.1.1d.tar.gz
cd openssl-1.1.1d/

./config shared zlib
#./config shared zlib --prefix=/usr/local/openssl --openssldir=/usr/local/openssl/ssl

make; make install

# include files
mv /usr/include/openssl /usr/include/openssl.bak
ln -s /usr/local/include/openssl  /usr/include/openssl

if [ -f "/usr/bin/yum" ]; then
  ln -s /usr/local/lib64/libssl.so.1.1 /usr/lib64/libssl.so.1.1
  ln -s /usr/local/lib64/libcrypto.so.1.1 /usr/lib64/libcrypto.so.1.1
elif [ -f "/usr/bin/apt" ]; then
  ln -s /usr/local/lib/libssl.so.1.1 /lib/x86_64-linux-gnu/libssl.so.1.1
  ln -s /usr/local/lib/libcrypto.so.1.1 /lib/x86_64-linux-gnu/libcrypto.so.1.1

  mv /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libssl.a.bak
  mv /usr/lib/x86_64-linux-gnu/libcrypto.a /usr/lib/x86_64-linux-gnu/libcrypto.a.bak
  cp /usr/local/lib/libssl.a /usr/lib/x86_64-linux-gnu/libssl.a
  cp /usr/local/lib/libcrypto.a /usr/lib/x86_64-linux-gnu/libcrypto.a
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
