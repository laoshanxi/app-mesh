#!/bin/sh
################################################################################
## This Script file is used to build openssl for CentOS and Ubuntu to location:
##  /usr/local/ssl/lib
##  /usr/local/ssl/include
################################################################################
set -x
set -e

export ROOTDIR=$(pwd)/openssl.tmp
mkdir -p ${ROOTDIR}
cd ${ROOTDIR}

if [ -f "/usr/bin/yum" ]; then
  RHEL_VER=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/')
  if [[ $RHEL_VER = "8" ]]; then
    sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-*
    sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
  fi
  yum install -y gcc-c++ wget make perl-core zlib-devel
elif [ -f "/usr/bin/apt" ]; then
  apt update
  apt -y install g++ wget make perl zlib1g-dev
fi

OPEN_SSL_VERSION=openssl-3.0.13
wget --quiet --no-check-certificate https://www.openssl.org/source/${OPEN_SSL_VERSION}.tar.gz
tar zxvf ${OPEN_SSL_VERSION}.tar.gz >/dev/null
cd ${OPEN_SSL_VERSION}

# https://www.openssl.org/news/cl31.txt
# https://blog.csdn.net/weixin_42645653/article/details/121416399
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl --libdir=lib shared
make -j 4 >/dev/null
make install_sw

# https://blog.csdn.net/liuxin638507/article/details/132450367
rm -f /usr/bin/openssl && ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl

echo "/usr/local/ssl/lib" >/etc/ld.so.conf.d/openssl.conf
ldconfig
ldd /usr/bin/openssl
export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH
ldd /usr/bin/openssl
/usr/bin/openssl version -a

cd ..
rm -rf ${ROOTDIR}

find / -name ssl.h | xargs ls -al
find / -name libssl.so | xargs ls -al
find / -name libcrypto.so | xargs ls -al
