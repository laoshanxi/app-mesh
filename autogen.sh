#!/bin/bash
################################################################################
## This script is used to install all 3rd-party dependency libraries
################################################################################
set -x
set -e
WGET_A="wget --continue --quiet --backups=1 --tries=30 --no-check-certificate"
# https://stackoverflow.com/questions/48678152/how-to-detect-386-amd64-arm-or-arm64-os-architecture-via-shell-bash
architecture="arm64" # TODO: can not get arm64, set to default
case $(uname -m) in
    i386)   architecture="386" ;;
    i686)   architecture="386" ;;
    x86_64) architecture="amd64" ;;
    arm)    dpkg --print-architecture | grep -q "arm64" && architecture="arm64" || architecture="arm" ;;
esac

SRC_DIR=$(dirname $(readlink -f "$0"))
export ROOTDIR=$(pwd)/appmesh.tmp
mkdir -p ${ROOTDIR}
cd ${ROOTDIR}

# check root permission
if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root"
	exit 1
fi

# install compiler and tools
if [ -f "/usr/bin/yum" ]; then
	#RHEL
	# yum update -q -y
	RHEL_VER=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/')
	if [[ $RHEL_VER = "8" ]]; then
		sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-*
		sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
	fi
	yum install -y epel-release
	if [[ $RHEL_VER = "7" ]]; then
		yum install -y https://repo.ius.io/ius-release-el7.rpm
		yum remove git -y
		yum install git236 -y
	else
		yum install git -y
	fi
	yum install -y make gcc-c++ libtool openldap-devel liboath-devel
	yum install -y dos2unix wget which

	#yum install -y boost169-devel boost169-static
	#export BOOST_LIBRARYDIR=/usr/lib64/boost169
	#export BOOST_INCLUDEDIR=/usr/include/boost169
	#ln -s /usr/include/boost169/boost /usr/local/include/boost
	#ln -s /usr/lib64/boost169/ /usr/local/lib64/boost

	# https://www.cnblogs.com/fujinzhou/p/5735578.html
	yum install -y ruby rubygems ruby-devel
	yum install -y rpm-build
	yum install -y python3-pip
elif [ -f "/usr/bin/apt" ]; then
	#Ubuntu
	# for old archived ubuntu version, the apt update may fail, run below command before update
	# sed -i s/archive.ubuntu/old-releases.ubuntu/g /etc/apt/sources.list
	# sed -i s/security.ubuntu/old-releases.ubuntu/g /etc/apt/sources.list
	export DEBIAN_FRONTEND=noninteractive
	apt update
	# apt full-upgrade -q -y
	apt install -y dos2unix g++ git wget make automake libtool zlib1g-dev alien libldap-dev liboath-dev
	#apt install -y libboost-all-dev libace-dev libace
	#apt install -y liblog4cpp5-dev
	apt install -y ruby ruby-dev rubygems
	# reduce binary size
	apt-get update && apt-get install -y lsb-release
	# https://gemfury.com/help/could-not-verify-ssl-certificate/
	apt install -y ca-certificates
	export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
	ruby -rnet/http -e "Net::HTTP.get URI('https://gem.fury.io')"
	apt install -y python3-pip
fi
python3 -m pip install --upgrade pip

# memoty test tool
# https://docs.microsoft.com/en-us/cpp/linux/linux-asan-configuration?view=msvc-170#install-the-asan-debug-symbols
asanversion="0"
case $(gcc -dumpversion) in
    5)   asanversion="2" ;;
    6)   asanversion="3" ;;
    7)   asanversion="4" ;;
    8)   asanversion="5" ;;
    9)   asanversion="6" ;;
    10)   asanversion="7" ;;
    11)   asanversion="8" ;;
    12)   asanversion="9" ;;
    *)   asanversion="0"
esac
if [ -f "/usr/bin/yum" ]; then
    yum install -y valgrind libasan
elif [ -f "/usr/bin/apt" ]; then
    apt install -y valgrind libasan$asanversion
fi

# yum install -y golang
# apt install -y golang
GO_ARCH=$architecture
GO_VER=1.21.5
$WGET_A https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VER}.linux-${GO_ARCH}.tar.gz
rm -rf /usr/bin/go && ln -s /usr/local/go/bin/go /usr/bin/go
go version

# check libssl in case of openssl_update.sh not executed
if [ -f "/usr/include/openssl/ssl.h" ] || [ -f "/usr/local/include/openssl/ssl.h" ]; then
	echo 'ssl installed'
else
	if [ -f "/usr/bin/yum" ]; then
		yum install -y openssl-devel
	else
		apt install -y libssl-dev
	fi
fi

# install cmake (depend on g++, make, openssl-devel)
# https://askubuntu.com/questions/355565/how-do-i-install-the-latest-version-of-cmake-from-the-command-line
if [ true ]; then
	version=3.22
	build=1
	os="linux"
	platform="x86_64"
	if [ "$architecture" = "arm64" ]; then
		platform="aarch64"
	fi
	$WGET_A https://cmake.org/files/v$version/cmake-$version.$build-$os-$platform.sh
	sh cmake-$version.$build-$os-$platform.sh --prefix=/usr/local/ --skip-license
fi

# Golang third party library
export GO111MODULE=on
export GOPROXY=https://goproxy.io,direct

# install fpm
gem install fpm || gem update --system && gem install fpm
if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
	yum install -y curl
	gpg2 --keyserver hkp://keyserver.ubuntu.com --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
	curl -sSL https://get.rvm.io | bash -s stable
	yum install -y gcc-c++ patch readline readline-devel zlib zlib-devel libyaml-devel libffi-devel openssl-devel make bzip2 autoconf automake libtool bison sqlite-devel
	source /usr/local/rvm/scripts/rvm
	/usr/local/rvm/bin/rvm install 2.7.0
	rvm reinstall ruby-2.7.0
	gem install fpm
fi

# build curl & libcurl
$WGET_A https://curl.se/download/curl-8.5.0.tar.gz
tar zxvf curl-8.5.0.tar.gz > /dev/null; cd curl-8.5.0
mkdir build; cd build; cmake ..; make; make install
cd $ROOTDIR

# build boost
if [ true ]; then
	BOOST_VER=76
	# https://www.boost.org/users/download/
	$WGET_A https://cytranet.dl.sourceforge.net/project/boost/boost/1.${BOOST_VER}.0/boost_1_${BOOST_VER}_0.tar.gz
	tar zxvf boost_1_${BOOST_VER}_0.tar.gz > /dev/null
	cd ./boost_1_${BOOST_VER}_0
	./bootstrap.sh --without-libraries=python,mpi,test,wave,container,graph,graph_parallel
	./b2 -j4
	./b2 install
	ls -al /usr/local/lib/libboost_system.so.1.${BOOST_VER}.0 /usr/local/include/boost/thread.hpp
fi
cd $ROOTDIR

# curlcpp
git clone --depth=1 https://github.com/jpbarrette/curlpp.git
cd curlpp; mkdir build; cd build; cmake ..; make; make install
cd $ROOTDIR

# json
$WGET_A https://github.com/nlohmann/json/releases/download/v3.11.3/include.zip
unzip -o include.zip
mv include/nlohmann /usr/local/include/

# build log4cpp:
# https://my.oschina.net/u/1983790/blog/1587568
if [ "$architecture" = "arm64" ]; then
	# arm64 will failed with log4cpp build, use package directly
	apt install -y liblog4cpp5-dev
else
	# yum install log4cpp -y
	if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
		$WGET_A https://jaist.dl.sourceforge.net/project/log4cpp/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.3.tar.gz
		tar zxvf log4cpp-1.1.3.tar.gz > /dev/null
	else
		$WGET_A https://jaist.dl.sourceforge.net/project/log4cpp/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.4.tar.gz
		tar zxvf log4cpp-1.1.4.tar.gz > /dev/null
	fi
	cd log4cpp/
	./autogen.sh
	./configure
	make
	make install
	ls -al /usr/local/lib*/liblog4cpp.a
fi
cd $ROOTDIR

# build ACE
if [ true ]; then
	# ubuntu does not need build ACE
	# ACE:
	# https://www.cnblogs.com/tanzi-888/p/5342431.html
	# http://download.dre.vanderbilt.edu/
	# https://www.dre.vanderbilt.edu/~schmidt/DOC_ROOT/ACE/ACE-INSTALL.html#aceinstall
	if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
		$WGET_A https://github.com/DOCGroup/ACE_TAO/releases/download/ACE%2BTAO-6_5_16/ACE-6.5.16.tar.gz
		tar zxvf ACE-6.5.16.tar.gz > /dev/null
	else
		$WGET_A https://github.com/DOCGroup/ACE_TAO/releases/download/ACE%2BTAO-7_1_2/ACE-7.1.2.tar.gz
		tar zxvf ACE-7.1.2.tar.gz > /dev/null
	fi
	cd ACE_wrappers
	export ACE_ROOT=$(pwd)
	cp ace/config-linux.h ace/config.h
	cp include/makeinclude/platform_linux.GNU include/makeinclude/platform_macros.GNU
	cd ${ACE_ROOT}/ace
	make ssl=1 -j6
	make install ssl=1 INSTALL_PREFIX=/usr/local
	cd ${ACE_ROOT}/protocols/ace
	make ssl=1 -j6
	make install ssl=1 INSTALL_PREFIX=/usr/local
	ls -al /usr/local/lib*/libACE.so
fi
cd $ROOTDIR

# cryptopp: AES encrypt https://www.cryptopp.com/
mkdir -p cryptopp
cd cryptopp/
$WGET_A https://github.com/weidai11/cryptopp/releases/download/CRYPTOPP_8_9_0/cryptopp890.zip
unzip -o cryptopp890.zip
export CXXFLAGS="-DNDEBUG -Os -std=c++11"
make -j6
make install

cd $ROOTDIR
# cfssl: generate SSL certification file
export GOBIN=/usr/local/bin
go install github.com/cloudflare/cfssl/cmd/cfssl@latest
go install github.com/cloudflare/cfssl/cmd/cfssljson@latest

# qrc
if [ "$architecture" = "arm64" ]; then
	$WGET_A --output-document=qrc https://github.com/laoshanxi/qrc/releases/download/v0.1.2/qrc_linux_arm64
	chmod +x qrc && mv qrc /usr/local/bin
else
	$WGET_A --output-document=qrc https://github.com/laoshanxi/qrc/releases/download/v0.1.2/qrc_linux_amd64
	chmod +x qrc && mv qrc /usr/local/bin
fi

cd $ROOTDIR
# Message Pack
# https://github.com/msgpack/msgpack-c/tree/cpp_master
if [ true ]; then
	git clone -b cpp_master --depth 1 https://github.com/msgpack/msgpack-c.git
	cd msgpack-c
	cmake .
	cmake --build . --target install
fi
python3 -m pip install --upgrade msgpack requests requests_toolbelt aniso8601 twine wheel

cd $ROOTDIR
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

git clone https://github.com/AndreyBarmaley/ldap-cpp.git
cd ldap-cpp;
if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
	git checkout 81c84ebb50185efe6525b74570acd8e6406d3140
fi
mkdir build; cd build; cmake -DBUILD_SHARED_LIBS=OFF ..; make; make install

cd $SRC_DIR; mkdir -p b; cd b; cmake ..; make agent

rm -rf ${ROOTDIR}
