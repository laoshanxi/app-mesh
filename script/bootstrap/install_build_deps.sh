#!/usr/bin/env bash
################################################################################
# Install all 3rd-party build dependencies for Linux, in one of two modes:
#
#   source (default) - build the C++ libraries (OpenSSL-linked Drogon, yaml-cpp,
#       jsoncpp, uriparser, CMake) from source. Pair with install_openssl.sh so
#       the daemon links the self-contained /usr/local/ssl; without it the
#       distro OpenSSL headers are used. Used by Dockerfile.build_centos8 /
#       build_ubuntu22 / build_ubuntu24 and the documented local-host flow.
#
#   --distro - Debian/Ubuntu only: link against the distro libraries (system
#       OpenSSL, libjsoncpp, libyaml-cpp, liburiparser, apt CMake). Used by
#       Dockerfile.build_ubuntu / build_debian13 for distro-integrated
#       packages. Boost and spdlog are still built from source in both modes
#       (distro versions are older than required / unpinned).
#
#   sudo bash script/bootstrap/install_build_deps.sh [--distro]
################################################################################
set -x
set -e

MODE="source"
if [ "${1:-}" = "--distro" ]; then
    MODE="distro"
elif [ -n "${1:-}" ]; then
    echo "Usage: $0 [--distro]" >&2
    exit 1
fi
if [ "$MODE" = "distro" ] && [ ! -f /usr/bin/apt ]; then
    echo "--distro mode requires a Debian/Ubuntu host (apt)" >&2
    exit 1
fi

WGET_A="wget --continue --quiet --backups=1 --tries=30 --no-check-certificate"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")"

# check root permission
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root"
    exit 1
fi

# only used to pick the CMake binary tarball in source mode
# https://stackoverflow.com/questions/48678152/how-to-detect-386-amd64-arm-or-arm64-os-architecture-via-shell-bash
architecture="arm64"
case $(uname -m) in
    i386)    architecture="386" ;;
    i686)    architecture="386" ;;
    x86_64)  architecture="amd64" ;;
    aarch64) architecture="arm64" ;;
    arm)     dpkg --print-architecture | grep -q "arm64" && architecture="arm64" || architecture="arm" ;;
esac

ROOTDIR="$(pwd)/appmesh.tmp"
export ROOTDIR
mkdir -p "${ROOTDIR}"
cd "${ROOTDIR}"

if [ "$MODE" = "source" ]; then
    export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH
fi

# -----------------------------------------------------------------------------
# OS packages: compiler and build tools
# (ninja: the main Dockerfile builds with -G Ninja)
# -----------------------------------------------------------------------------
if [ "$MODE" = "distro" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y g++ cmake make ninja-build git wget curl gettext python3-pip
    # drogon requires libuuid; Boost 1.86+ (Boost.Process V2) and the pinned
    # spdlog are newer than what distros ship, both build from source below.
    apt install -y uuid-dev libssl-dev libjsoncpp-dev libyaml-cpp-dev liburiparser-dev
elif [ -f "/usr/bin/yum" ]; then
    # RHEL family
    RHEL_VER=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/')
    if [[ $RHEL_VER = "8" ]]; then
        sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-*
        sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
    fi
    yum install -y epel-release
    yum install -y git make gcc-c++
    yum install -y wget which gettext
    yum install -y python3-pip
    # old EPEL lacks the ninja-build package
    yum install -y ninja-build 2>/dev/null || pip3 install ninja
    yum install -y libuuid-devel #for drogon
else
    # Debian family
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y g++ git make ninja-build
    apt install -y wget gettext
    apt install -y python3-pip
    apt install -y uuid-dev #for drogon
fi
python3 -m pip install --upgrade pip || python3 -m pip install --break-system-packages --upgrade pip || true

# -----------------------------------------------------------------------------
# Toolchains: Go, Rust, OpenSSL, CMake
# -----------------------------------------------------------------------------
# Golang
bash "$SCRIPT_DIR/install_golang.sh"
go env -w GOPROXY=https://goproxy.cn,direct;go env -w GOBIN=/usr/local/bin;go env -w GO111MODULE=on

# Rust (for CLI build)
bash "$SCRIPT_DIR/install_rust.sh"

if [ "$MODE" = "source" ]; then
    # check libssl in case of bootstrap/install_openssl.sh not executed
    if [ -f "/usr/local/ssl/include/openssl/ssl.h" ]; then
        echo 'openssl was already installed'
        # set for appmesh cmake
        export OPENSSL_ROOT_DIR=/usr/local/ssl
    else
        if [ -f "/usr/bin/yum" ]; then
            yum install -y openssl-devel
        else
            apt install -y libssl-dev
        fi
    fi

    # install cmake (depend on g++, make, openssl-devel)
    # https://askubuntu.com/questions/355565/how-do-i-install-the-latest-version-of-cmake-from-the-command-line
    cmake_version=3.22
    cmake_build=1
    os="linux"
    platform="x86_64"
    if [ "$architecture" = "arm64" ]; then
        platform="aarch64"
    fi
    $WGET_A https://cmake.org/files/v$cmake_version/cmake-$cmake_version.$cmake_build-$os-$platform.sh
    sh cmake-$cmake_version.$cmake_build-$os-$platform.sh --prefix=/usr/local/ --skip-license
fi

# -----------------------------------------------------------------------------
# C++ libraries built from source
# -----------------------------------------------------------------------------
# boost (1.86+: Boost.Process V2), newer than any distro package
# https://www.boost.org/users/download/
BOOST_VER=86
$WGET_A https://zenlayer.dl.sourceforge.net/project/boost/boost/1.${BOOST_VER}.0/boost_1_${BOOST_VER}_0.tar.gz
tar zxvf boost_1_${BOOST_VER}_0.tar.gz >/dev/null
cd ./boost_1_${BOOST_VER}_0
./bootstrap.sh --without-libraries=context,coroutine,exception,locale,log,math,python,random,serialization,mpi,test,wave,container,graph,graph_parallel,chrono,contract,json,nowide,stacktrace,type_erasure
./b2 variant=release optimization=space -j"$(($(nproc) / 2))"
./b2 install variant=release optimization=space >/dev/null
ls -al /usr/local/lib/libboost_system.so.1.${BOOST_VER}.0 /usr/local/include/boost/thread.hpp
cd "$ROOTDIR"

# spdlog - build from source (pinned to v1.17.0 for stable behaviour);
# source mode ships a size-optimized lib, distro mode keeps its historical flags
SPDLOG_FLAGS="-DSPDLOG_BUILD_SHARED=ON -DSPDLOG_BUILD_EXAMPLES=OFF -DSPDLOG_BUILD_TESTS=OFF"
if [ "$MODE" = "source" ]; then
    SPDLOG_FLAGS="-DCMAKE_BUILD_TYPE=MinSizeRel $SPDLOG_FLAGS"
fi
git clone -b v1.17.0 --depth 1 https://github.com/gabime/spdlog.git
cd spdlog
mkdir -p build && cd build
cmake .. $SPDLOG_FLAGS
cmake --build . --parallel
cmake --install .
cd "$ROOTDIR"

# Message Pack
# https://github.com/msgpack/msgpack-c/tree/cpp_master
git clone -b cpp_master --depth 1 https://github.com/msgpack/msgpack-c.git
cd msgpack-c
cmake .
cmake --build . --target install
cd "$ROOTDIR"

if [ "$MODE" = "source" ]; then
    # yaml-cpp
    # Config parsing only: build for size, the lib ships in the package
    git clone https://github.com/jbeder/yaml-cpp.git
    cd yaml-cpp && mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=MinSizeRel -DBUILD_SHARED_LIBS=ON ..
    make && make install
    cd "$ROOTDIR"

    # jsoncpp
    git clone --depth=1 -b 1.9.8 https://github.com/open-source-parsers/jsoncpp.git
    cd jsoncpp && mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DJSONCPP_WITH_TESTS=OFF -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF ..
    make -j"$(nproc)" && make install
    cd "$ROOTDIR"
fi

# drogon (requires C++17, GCC >= 8)
# v1.9.13 omits <iomanip> for std::put_time / std::setprecision on non-Windows.
GCC_MAJOR=$(gcc -dumpversion | cut -d. -f1)
if [[ "$GCC_MAJOR" -lt 8 ]]; then
    echo "Drogon requires C++17 (GCC >= 8), skipping"
else
    git clone --depth=1 -b v1.9.13 --recurse-submodules --shallow-submodules https://github.com/drogonframework/drogon.git
    cd drogon && mkdir build && cd build
    if [ "$MODE" = "source" ]; then
        # $ORIGIN:/usr/local/ssl/lib keeps the packaged libraries self-contained
        # and makes the runtime dependency scan resolve one libcrypto.
        cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_SKIP_INSTALL_RPATH=ON -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-rpath,\$ORIGIN:/usr/local/ssl/lib" -DCMAKE_CXX_FLAGS="-include iomanip" -DBUILD_CTL=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DBUILD_ORM=OFF -DBUILD_BROTLI=OFF -DOPENSSL_ROOT_DIR=/usr/local/ssl ..
    else
        # $ORIGIN keeps the packaged libraries self-contained.
        cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_SKIP_INSTALL_RPATH=ON -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-rpath,\$ORIGIN" -DCMAKE_CXX_FLAGS="-include iomanip" -DBUILD_CTL=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DBUILD_ORM=OFF -DBUILD_BROTLI=OFF ..
    fi
    make -j"$(nproc)" && make install
    cd "$ROOTDIR"
fi

if [ "$MODE" = "source" ]; then
    # uriparser
    git clone --depth=1 https://github.com/uriparser/uriparser.git
    cd uriparser && mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF ..
    make && make install
    cd "$ROOTDIR"
fi

# -----------------------------------------------------------------------------
# Header-only libraries copied to /usr/local/include
# -----------------------------------------------------------------------------
git clone --depth=1 https://github.com/schoentoon/hashidsxx.git
cp -rf hashidsxx /usr/local/include/

git clone --depth=1 https://github.com/mariusbancila/croncpp.git
cp croncpp/include/croncpp.h /usr/local/include/

git clone --depth=1 https://github.com/laoshanxi/wildcards.git
cp -rf wildcards/single_include/ /usr/local/include/wildcards

# prometheus-cpp master needs C++17 (transparent comparator, nested namespace)
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

git clone --depth=1 -b v2.x https://github.com/catchorg/Catch2.git
cp Catch2/single_include/catch2/catch.hpp /usr/local/include/

git clone --depth=1 https://github.com/cameron314/concurrentqueue.git
cp -rf concurrentqueue /usr/local/include/

# -----------------------------------------------------------------------------
# Go binaries: cfssl, nfpm, Dex OIDC server
# -----------------------------------------------------------------------------
export GOBIN=/usr/local/bin
export CGO_ENABLED=0
LDFLAGS="-s -w"
BUILDFLAGS="-trimpath -buildvcs=false"
go install -ldflags="$LDFLAGS" $BUILDFLAGS github.com/cloudflare/cfssl/cmd/cfssl@latest
go install -ldflags="$LDFLAGS" $BUILDFLAGS github.com/cloudflare/cfssl/cmd/cfssljson@latest
go install -ldflags="$LDFLAGS" $BUILDFLAGS github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

# Dex OIDC server: follow the project fork's appmesh branch, which carries the
# refresh-token rotation SQLite deadlock fix, the upstream sync, and the
# pure-Go SQLite driver for CGO-free builds. Keep off the fork's master: it
# is the head of the upstream deadlock-fix PR and must stay clean.
git clone --quiet --depth 1 -b appmesh https://github.com/laoshanxi/dex.git
(cd dex && CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /usr/local/bin/dex ./cmd/dex)
# Dex administration web UI (the fork's examples/example-app, a separate Go
# module): packaged as dexuser and run as the dexuser System App.
(cd dex/examples && CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags "netgo,osusergo" -ldflags "-s -w" -o /usr/local/bin/dexuser ./example-app)

# -----------------------------------------------------------------------------
# Python SDK packages and SBOM tooling
# -----------------------------------------------------------------------------
PIP_PACKAGES="msgpack requests requests_toolbelt aniso8601 twine wheel"
python3 -m pip install --upgrade $PIP_PACKAGES || python3 -m pip install --break-system-packages --upgrade --ignore-installed $PIP_PACKAGES

# syft for SBOM
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# -----------------------------------------------------------------------------
# Cleanup package manager and toolchain caches
# -----------------------------------------------------------------------------
go clean -cache -fuzzcache -modcache
pip3 cache purge
if [ -f "/usr/bin/yum" ]; then
    yum clean all
else
    apt-get clean
fi

# -----------------------------------------------------------------------------
# Smoke build: prove the environment compiles the agent (artifacts discarded)
# -----------------------------------------------------------------------------
cd $SRC_DIR; mkdir -p b; cd b; cmake ..; make agent
rm -rf ${ROOTDIR}
