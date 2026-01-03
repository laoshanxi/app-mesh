#!/usr/bin/env bash
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

SRC_DIR=$(dirname $(dirname $(dirname $(readlink -f "$0"))))
export ROOTDIR=$(pwd)/appmesh.tmp
mkdir -p ${ROOTDIR}
cd ${ROOTDIR}

# check root permission
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root"
    exit 1
fi

export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH

# install compiler and tools
if [ -f "/usr/bin/yum" ]; then
    #RHEL
    # yum update -q -y
    RHEL_VER=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/')
    if [[ $RHEL_VER = "7" ]]; then
        cp -a /etc/yum.repos.d /etc/yum.repos.d.backup
        rm -f /etc/yum.repos.d/*.repo
        curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
        yum clean all
        yum makecache
    fi
    if [[ $RHEL_VER = "8" ]]; then
        sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-*
        sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
    fi
    yum install -y epel-release
    yum install -y git make gcc-c++ ninja-build
    yum install -y wget which gettext unzip
    yum install -y python3-pip
    yum install -y zlib-devel #for libcurl
    #yum install -y boost169-devel boost169-static
    #export BOOST_LIBRARYDIR=/usr/lib64/boost169
    #export BOOST_INCLUDEDIR=/usr/include/boost169
    #ln -s /usr/include/boost169/boost /usr/local/include/boost
    #ln -s /usr/lib64/boost169/ /usr/local/lib64/boost
    elif [ -f "/usr/bin/apt" ]; then
    #Ubuntu
    # for old archived ubuntu version, the apt update may fail, run below command before update
    # sed -i s/archive.ubuntu/old-releases.ubuntu/g /etc/apt/sources.list
    # sed -i s/security.ubuntu/old-releases.ubuntu/g /etc/apt/sources.list
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y g++ git make ninja-build
    apt install -y wget alien gettext unzip
    apt install -y python3-pip
    apt install -y zlib1g-dev #for libcurl
    #apt install -y libboost-all-dev libace-dev libace
fi
python3 -m pip install --upgrade pip || python3 -m pip install --break-system-packages --upgrade pip || true

# yum install -y golang
# apt install -y golang
GO_ARCH=$architecture
GO_VER=1.25.3
$WGET_A https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VER}.linux-${GO_ARCH}.tar.gz
rm -rf /usr/bin/go && ln -s /usr/local/go/bin/go /usr/bin/go
go version
go env -w GOPROXY=https://goproxy.cn,direct;go env -w GOBIN=/usr/local/bin;go env -w GO111MODULE=on

# check libssl in case of setup_build_env/update_openssl.sh not executed
if [ -f "/usr/local/ssl/include/openssl/ssl.h" ]; then
    echo 'openssl was alreay installed'
    # set for appmesh cmake
    export OPENSSL_ROOT_DIR=/usr/local/ssl
    # set for ACE SSL: https://www.dre.vanderbilt.edu/~schmidt/DOC_ROOT/ACE/ACE-INSTALL.html#sslinstall
    export SSL_ROOT=/usr/local/ssl
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

# build static libcurl
$WGET_A https://curl.se/download/curl-8.5.0.tar.gz
tar zxvf curl-8.5.0.tar.gz >/dev/null; cd curl-8.5.0
mkdir build; cd build; # http2: -DHTTP_ONLY=OFF -DCURL_USE_NGHTTP2=ON
cmake .. -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DHTTP_ONLY=ON -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DOPENSSL_ROOT_DIR=/usr/local/ssl || cmake .. -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DHTTP_ONLY=ON -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCURL_USE_OPENSSL=ON
make -j"$(nproc)" >/dev/null
make install
ldconfig
cd $ROOTDIR

# build boost
if [ true ]; then
    BOOST_VER=76
    # https://www.boost.org/users/download/
    $WGET_A https://zenlayer.dl.sourceforge.net/project/boost/boost/1.${BOOST_VER}.0/boost_1_${BOOST_VER}_0.tar.gz
    tar zxvf boost_1_${BOOST_VER}_0.tar.gz >/dev/null
    cd ./boost_1_${BOOST_VER}_0
    ./bootstrap.sh --without-libraries=context,coroutine,exception,locale,log,math,python,random,serialization,mpi,test,wave,container,graph,graph_parallel,chrono,contract,json,nowide,stacktrace,type_erasure
    ./b2 -j"$(($(nproc) / 2))"
    ./b2 install >/dev/null
    ls -al /usr/local/lib/libboost_system.so.1.${BOOST_VER}.0 /usr/local/include/boost/thread.hpp
fi
cd $ROOTDIR

# json
$WGET_A https://github.com/nlohmann/json/releases/download/v3.11.3/include.zip
unzip -o include.zip
mv include/nlohmann /usr/local/include/

# spdlog
# spdlog - build from source
GCC_MAJOR_VER=$(gcc -dumpversion 2>/dev/null | cut -d'.' -f1 | tr -dc '0-9')
echo "Detected GCC major version: ${GCC_MAJOR_VER:-unknown}"
cd "$ROOTDIR"
if [ -n "$GCC_MAJOR_VER" ] && [ "$GCC_MAJOR_VER" -lt 8 ]; then
    echo "GCC < 8: build spdlog from v1.9.2 branch"
    git clone -b v1.9.2 --depth 1 https://github.com/gabime/spdlog.git
else
    echo "GCC >= 8: build spdlog from default branch"
    git clone --depth 1 https://github.com/gabime/spdlog.git
fi
cd spdlog || exit 1
mkdir -p build && cd build || exit 1
cmake .. -DSPDLOG_BUILD_SHARED=ON -DSPDLOG_BUILD_EXAMPLES=OFF -DSPDLOG_BUILD_TESTS=OFF
cmake --build . --parallel
cmake --install .
cd "$ROOTDIR"

# build ACE
if [ true ]; then
    # https://www.cnblogs.com/tanzi-888/p/5342431.html
    # http://download.dre.vanderbilt.edu/
    # https://www.dre.vanderbilt.edu/~schmidt/DOC_ROOT/ACE/ACE-INSTALL.html#aceinstall
    if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
        $WGET_A https://github.com/DOCGroup/ACE_TAO/releases/download/ACE%2BTAO-6_5_16/ACE-6.5.16.tar.gz
        tar zxvf ACE-6.5.16.tar.gz >/dev/null
    else
        $WGET_A https://github.com/DOCGroup/ACE_TAO/releases/download/ACE%2BTAO-7_1_2/ACE-7.1.2.tar.gz
        tar zxvf ACE-7.1.2.tar.gz >/dev/null
    fi
    cd ACE_wrappers
    export ACE_ROOT=$(pwd)
    cp ace/config-linux.h ace/config.h
    cp include/makeinclude/platform_linux.GNU include/makeinclude/platform_macros.GNU
    cd ${ACE_ROOT}/ace
    make ssl=1 -j"$(($(nproc) / 2))"
    make install ssl=1 INSTALL_PREFIX=/usr/local
    # cd ${ACE_ROOT}/protocols/ace
    # make ssl=1 -j"$(($(nproc) / 2))"
    # make install ssl=1 INSTALL_PREFIX=/usr/local
    ls -al /usr/local/lib*/libACE.so
fi
cd $ROOTDIR

# cryptopp: AES encrypt https://www.cryptopp.com/
mkdir -p cryptopp
cd cryptopp/
$WGET_A https://github.com/weidai11/cryptopp/releases/download/CRYPTOPP_8_9_0/cryptopp890.zip
unzip -o cryptopp890.zip
export CXXFLAGS="-DNDEBUG -Os -std=c++11"
make -j"$(nproc)"
make install

cd $ROOTDIR
# go binaries
export GOBIN=/usr/local/bin
export CGO_ENABLED=0
LDFLAGS="-s -w"
BUILDFLAGS="-trimpath -buildvcs=false"
go install -ldflags="$LDFLAGS" $BUILDFLAGS github.com/cloudflare/cfssl/cmd/cfssl@latest
go install -ldflags="$LDFLAGS" $BUILDFLAGS github.com/cloudflare/cfssl/cmd/cfssljson@latest
go install -ldflags="$LDFLAGS" $BUILDFLAGS github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

cd $ROOTDIR
# Message Pack
# https://github.com/msgpack/msgpack-c/tree/cpp_master
if [ true ]; then
    git clone -b cpp_master --depth 1 https://github.com/laoshanxi/msgpack-c.git
    cd msgpack-c
    cmake .
    cmake --build . --target install
fi

PIP_PACKAGES="msgpack requests requests_toolbelt aniso8601 twine wheel"
python3 -m pip install --upgrade $PIP_PACKAGES || python3 -m pip install --break-system-packages --upgrade --ignore-installed $PIP_PACKAGES

# syft for SBOM
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

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

git clone --depth=1 https://github.com/arangodb/linenoise-ng.git
sed -i -E 's/cmake_minimum_required\(VERSION[[:space:]]+[0-9.]+\)/cmake_minimum_required(VERSION 3.20)/' linenoise-ng/CMakeLists.txt
cd linenoise-ng; mkdir build; cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build . --target linenoise && cmake --install .

git clone --depth=1 https://github.com/Thalhammer/jwt-cpp.git
cp -rf jwt-cpp/include/jwt-cpp /usr/local/include/

cd $ROOTDIR
git clone https://github.com/jbeder/yaml-cpp.git
cd yaml-cpp/ && mkdir build && cd build && cmake -DBUILD_SHARED_LIBS=ON ..
if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
    while ! make; do make clean && git reset --hard HEAD^ && cmake -DBUILD_SHARED_LIBS=ON ..; sleep 0.5; done
fi
make && make install

cd $ROOTDIR
git clone --depth=1 https://github.com/nayuki/QR-Code-generator.git
cd QR-Code-generator/cpp && cp qrcodegen.* /usr/local/include/ && make && cp libqrcodegencpp.a /usr/local/lib/

cd $ROOTDIR
git clone --depth=1 -b v2.x https://github.com/catchorg/Catch2.git
cp Catch2/single_include/catch2/catch.hpp /usr/local/include/

cd ${ROOTDIR}
git clone --depth=1 https://github.com/cameron314/concurrentqueue.git
cp -rf concurrentqueue /usr/local/include/

cd $ROOTDIR
git clone --depth=1 https://libwebsockets.org/repo/libwebsockets
if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
    cd libwebsockets/ && mkdir build && cd build && cmake -DLWS_WITH_SHARED=ON -DLWS_WITH_STATIC=OFF -DLWS_WITHOUT_TESTAPPS=ON -DOPENSSL_ROOT_DIR=/usr/local/ssl -DLWS_HAVE_LINUX_IPV6_H=0 -DCMAKE_C_STANDARD=99 -DCMAKE_C_STANDARD_REQUIRED=ON ..
else
    cd libwebsockets/ && mkdir build && cd build && cmake -DLWS_WITH_SHARED=ON -DLWS_WITH_STATIC=OFF -DLWS_WITHOUT_TESTAPPS=ON -DOPENSSL_ROOT_DIR=/usr/local/ssl ..
fi
make -j"$(nproc)" && make install

if [[ -f "/usr/bin/yum" ]] && [[ $RHEL_VER = "7" ]]; then
    echo "uWebSockets not support C++11"
else
    cd $ROOTDIR
    git clone --recurse-submodules --shallow-submodules --depth=1 https://github.com/uNetworking/uWebSockets.git
    cd uWebSockets
    export OPENSSL_ROOT_DIR=/usr/local/ssl
    make default WITH_OPENSSL=1 CFLAGS="-I${OPENSSL_ROOT_DIR}/include" LDFLAGS="-L${OPENSSL_ROOT_DIR}/lib"
    make install
    cp uSockets/src/libusockets.h /usr/local/include/
    cp uSockets/uSockets.a /usr/local/lib/libuSockets.a
fi

cd $ROOTDIR
git clone --depth=1 https://github.com/uriparser/uriparser.git
cd uriparser && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF ..
make && make install

# clean
go clean -cache -fuzzcache -modcache
pip3 cache purge
if [ -f "/usr/bin/yum" ]; then
    yum clean all
else
    apt-get clean
fi

cd $SRC_DIR; mkdir -p b; cd b; cmake ..; make agent
rm -rf ${ROOTDIR}
# memoty test tool
# https://docs.microsoft.com/en-us/cpp/linux/linux-asan-configuration?view=msvc-170#install-the-asan-debug-symbols
#asanversion="0"
#case $(gcc -dumpversion) in
#    5)   asanversion="2" ;;
#    6)   asanversion="3" ;;
#    7)   asanversion="4" ;;
#    8)   asanversion="5" ;;
#    9)   asanversion="6" ;;
#    10)   asanversion="7" ;;
#    11)   asanversion="8" ;;
#    12)   asanversion="9" ;;
#    *)   asanversion="0"
#esac
#if [ -f "/usr/bin/yum" ]; then
#    yum install -y valgrind libasan
#elif [ -f "/usr/bin/apt" ]; then
#    apt install -y valgrind libasan$asanversion
#fi
