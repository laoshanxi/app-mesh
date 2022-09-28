#!/bin/bash
################################################################################
## This script is used to install all 3rd-party dependency libraries
################################################################################
set -x
set -e
WGWT_A="wget --continue --quiet --backups=1 --tries=30 --no-check-certificate"
# https://stackoverflow.com/questions/48678152/how-to-detect-386-amd64-arm-or-arm64-os-architecture-via-shell-bash
architecture=""
case $(uname -m) in
    i386)   architecture="386" ;;
    i686)   architecture="386" ;;
    x86_64) architecture="amd64" ;;
    arm)    dpkg --print-architecture | grep -q "arm64" && architecture="arm64" || architecture="arm" ;;
esac

SHELL_FOLDER=$(dirname $(readlink -f "$0"))
export ROOTDIR=${SHELL_FOLDER}/dep
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
	# reduce binary size
	# https://stackoverflow.com/questions/15996699/what-modifications-will-lead-to-size-reduction-of-binary-size-in-c-code
	# yum install -y http://ftp.tu-chemnitz.de/pub/linux/dag/redhat/el7/en/x86_64/rpmforge/RPMS/ucl-1.03-2.el7.rf.x86_64.rpm
	# yum install -y http://ftp.tu-chemnitz.de/pub/linux/dag/redhat/el7/en/x86_64/rpmforge/RPMS/upx-3.91-1.el7.rf.x86_64.rpm
	# other platform package download
	# https://centos.pkgs.org/7/repoforge-x86_64/upx-3.91-1.el7.rf.x86_64.rpm.html
elif [ -f "/usr/bin/apt" ]; then
	#Ubuntu
	# for old archived ubuntu version, the apt update may fail, run below command before update
	# sed -i s/archive.ubuntu/old-releases.ubuntu/g /etc/apt/sources.list
	# sed -i s/security.ubuntu/old-releases.ubuntu/g /etc/apt/sources.list
	export DEBIAN_FRONTEND=noninteractive
	apt update
	# apt full-upgrade -q -y
	apt install -y dos2unix g++ git wget make automake libtool zlib1g-dev alien libldap-dev liboath-dev
	#apt install -y libboost-all-dev libace-dev
	#apt install -y libcpprest-dev liblog4cpp5-dev
	apt install -y ruby ruby-dev rubygems
	# reduce binary size
	apt-get update && apt-get install -y lsb-release
	# https://gemfury.com/help/could-not-verify-ssl-certificate/
	apt install -y ca-certificates
	export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
	ruby -rnet/http -e "Net::HTTP.get URI('https://gem.fury.io')"
fi

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

# apt install -y upx-ucl
UPX_ARCH=$architecture
UPX_VER=3.96
$WGWT_A https://github.com/upx/upx/releases/download/v${UPX_VER}/upx-${UPX_VER}-amd64_linux.tar.xz
tar xf upx-${UPX_VER}-amd64_linux.tar.xz
mv upx-${UPX_VER}-amd64_linux/upx /usr/bin/

# yum install -y golang
# apt install -y golang
GO_ARCH=$architecture
GO_VER=1.17
$WGWT_A https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VER}.linux-${GO_ARCH}.tar.gz
rm -rf /usr/bin/go && ln -s /usr/local/go/bin/go /usr/bin/go
go version
# go env -w GOPROXY=https://goproxy.io,direct
# go env -w GO111MODULE=on
export GO111MODULE=on
export GOPROXY=https://goproxy.io,direct
go get github.com/valyala/fasthttp@v1.37.0
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
	$WGWT_A https://cmake.org/files/v$version/cmake-$version.$build-$os-x86_64.sh
	sh cmake-$version.$build-$os-x86_64.sh --prefix=/usr/local/ --skip-license
fi

# install fpm
gem install fpm || gem update --system && gem install fpm

# build boost_1_74_0
if [ true ]; then
	# https://www.cnblogs.com/eagle6688/p/5840773.html
	if [ -f "/usr/bin/yum" ]; then
		yum install -y python2-devel
	elif [ -f "/usr/bin/apt" ]; then
		apt install -y python-dev || apt install -y python2-dev
	fi
	# https://www.boost.org/users/download/
	$WGWT_A https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.gz
	tar zxvf boost_1_74_0.tar.gz
	cd ./boost_1_74_0
	./bootstrap.sh
	./b2
	./b2 install
	ls -al /usr/local/lib/libboost_system.so.1.74.0 /usr/local/include/boost/thread.hpp
fi
cd $ROOTDIR

# cpprestsdk (use -DBUILD_SHARED_LIBS=0 for static link):
# https://stackoverflow.com/questions/49877907/cpp-rest-sdk-in-centos-7
git clone --depth=1 -b 2.10.18 https://github.com/microsoft/cpprestsdk.git cpprestsdk
cd cpprestsdk
git submodule update --init
cd Release
cmake .. -DCMAKE_BUILD_TYPE=Release -DBOOST_ROOT=/usr/local -DBUILD_SHARED_LIBS=1 -DCMAKE_CXX_FLAGS="-Wno-error=cast-align -Wno-error=conversion -Wno-error=missing-field-initializers -Wno-format-truncation"
make -j6
make install
ls -al /usr/local/lib*/libcpprest.so
cd $ROOTDIR

# cpr
# https://github.com/libcpr/cpr
git clone --depth=1 -b 1.9.2 https://github.com/libcpr/cpr.git
cd cpr && mkdir build && cd build
cmake .. -DCPR_USE_SYSTEM_CURL=ON
cmake --build .
make install
cd $ROOTDIR

# json
$WGWT_A https://github.com/nlohmann/json/releases/download/v3.11.2/include.zip
unzip -o include.zip
mv include/nlohmann /usr/local/include/

# build log4cpp:
# https://my.oschina.net/u/1983790/blog/1587568
if [[ "$architecture" = "arm64" ]]; then
	# arm64 will failed with log4cpp build, use package directly
	apt install -y liblog4cpp5-dev
else
	# yum install log4cpp -y
	$WGWT_A https://jaist.dl.sourceforge.net/project/log4cpp/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.3.tar.gz
	tar zxvf log4cpp-1.1.3.tar.gz
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
	$WGWT_A https://github.com/DOCGroup/ACE_TAO/releases/download/ACE%2BTAO-6_5_16/ACE-6.5.16.tar.gz
	tar zxvf ACE-6.5.16.tar.gz
	cd ACE_wrappers
	export ACE_ROOT=$(pwd)
	cp ace/config-linux.h ace/config.h
	cp include/makeinclude/platform_linux.GNU include/makeinclude/platform_macros.GNU
	cd ${ACE_ROOT}/ace
	make -j6
	make install INSTALL_PREFIX=/usr/local
	ls -al /usr/local/lib*/libACE.so
fi
cd $ROOTDIR

# cryptopp: AES encrypt https://www.cryptopp.com/
mkdir -p cryptopp
cd cryptopp/
$WGWT_A https://github.com/weidai11/cryptopp/releases/download/CRYPTOPP_8_6_0/cryptopp860.zip
unzip -o cryptopp860.zip
export CXXFLAGS="-DNDEBUG -Os -std=c++11"
make -j6
make install

cd $ROOTDIR
# cfssl: generate SSL certification file
if [[ "$architecture" = "arm64" ]]; then
	# cfssl have no arm64 binary, just use package instead
	apt install -y golang-cfssl

	# qrc
	$WGWT_A --output-document=qrc https://github.com/laoshanxi/qrc/releases/download/v0.1.2/qrc_linux_arm64
	chmod +x qrc && upx qrc && mv qrc /usr/bin/
else
	# SSL
	# https://www.cnblogs.com/fanqisoft/p/10765038.html
	# https://www.bookstack.cn/read/tidb-v2.1/how-to-secure-generate-self-signed-certificates.md
	CFSSL_VER=1.6.1
	$WGWT_A --output-document=cfssl https://github.com/cloudflare/cfssl/releases/download/v${CFSSL_VER}/cfssl_${CFSSL_VER}_linux_amd64
	chmod +x cfssl && upx cfssl && mv cfssl /usr/bin/
	$WGWT_A --output-document=cfssljson https://github.com/cloudflare/cfssl/releases/download/v${CFSSL_VER}/cfssljson_${CFSSL_VER}_linux_amd64
	chmod +x cfssljson && upx cfssljson && mv cfssljson /usr/bin/
	$WGWT_A --output-document=cfssl-certinfo https://github.com/cloudflare/cfssl/releases/download/v${CFSSL_VER}/cfssl-certinfo_${CFSSL_VER}_linux_amd64
	chmod +x cfssl-certinfo && upx cfssl-certinfo

	# qrc
	$WGWT_A --output-document=qrc https://github.com/laoshanxi/qrc/releases/download/v0.1.2/qrc_linux_amd64
	chmod +x qrc && upx qrc && mv qrc /usr/bin/
fi

cd $ROOTDIR
# protocol buffer
# https://developers.google.com/protocol-buffers
if [ true ]; then
	PROTOCOL_BUFFER_VER=3.19.5
	# $WGWT_A https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOCOL_BUFFER_VER}/protoc-${PROTOCOL_BUFFER_VER}-linux-$(arch).zip
	# unzip protoc-${PROTOCOL_BUFFER_VER}-linux-$(arch).zip -d /usr/local/
	$WGWT_A https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOCOL_BUFFER_VER}/protobuf-cpp-${PROTOCOL_BUFFER_VER}.zip
	unzip protobuf-cpp-${PROTOCOL_BUFFER_VER}.zip
	cd protobuf-${PROTOCOL_BUFFER_VER}
	./autogen.sh
	./configure
	make -j 6
	make install
	ldconfig
fi
