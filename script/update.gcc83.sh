#!/bin/sh

# install base gcc
yum install -y make gcc-c++ wget bzip2

# download
wget http://ftp.gnu.org/gnu/gcc/gcc-8.3.0/gcc-8.3.0.tar.gz

# uncompress and build
tar zxvf gcc-8.3.0.tar.gz
cd gcc-8.3.0
./contrib/download_prerequisites
mkdir build
cd build
../configure --prefix=/usr/ -enable-checking=release -enable-languages=c,c++ -disable-multilib
make
make install

# update default lib
# \cp -df /usr/local/lib64/libstdc++.so.6* /usr/lib64
# \cp -df /usr/local/bin/g++* /usr/bin/
# \cp -df /usr/local/bin/gcc* /usr/bin/

# Save this to /etc/profile
# export LD_LIBRARY_PATH=/usr/local/gcc84/lib64/:$LD_LIBRARY_PATH
# export PATH=/usr/local/gcc84/bin:$PATH
# gcc -v
# reboot is needed

# https://ubuntuqa.com/article/315.html
# https://www.cnblogs.com/liranowen/p/11639929.html
# mv /usr/bin/gcc /usr/bin/gcc-4.8.5
# mv /usr/bin/g++ /usr/bin/g++-4.8.5
# mv /usr/local/bin/gcc /usr/local/bin/gcc-8.3.0
# mv /usr/local/bin/g++ /usr/local/bin/g++-8.3.0

# alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8.5       10 --slave /usr/bin/g++ g++ /usr/bin/g++-4.8.5
# alternatives --install /usr/bin/gcc gcc /usr/local/bin/gcc-8.3.0 20 --slave /usr/bin/g++ g++ /usr/local/bin/g++-8.3.0
# alternatives --config gcc

# if no bellow link, cmake detect compiler will fail
#ln -s /usr/local/bin/cc /usr/bin/gcc
#ln -s /usr/local/bin/c++ /usr/bin/c++
#ln -s /usr/local/bin/gcc /usr/bin/gcc
#ln -s /usr/local/bin/g++ /usr/bin/g++

# Reference
# https://yq.aliyun.com/articles/673834
# https://www.linuxidc.com/Linux/2017-10/147256.htm