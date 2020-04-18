#!/bin/sh

# download
wget http://ftp.gnu.org/gnu/gcc/gcc-8.4.0/gcc-8.4.0.tar.gz

# install base gcc
yum install -y make gcc-c++

# uncompress and build
tar zxvf gcc-8.4.0.tar.gz
cd gcc-8.4.0
./contrib/download_prerequisites
mkdir build
cd build
../configure -enable-checking=release -enable-languages=c,c++ -disable-multilib
make -j 4
make install

# update default lib
\cp -df /usr/local/lib64/libstdc++.so.6* /usr/lib64
gcc -v
# reboot is needed


# Reference
# https://yq.aliyun.com/articles/673834
# https://www.linuxidc.com/Linux/2017-10/147256.htm