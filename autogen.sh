mkdir dep
cd dep
export ROOTDIR=`pwd`

if [ "$(id -u)" != "0" ]; then
    log "This script must be run as root"
    exit 1
fi

#RHEL
if [ -f "/usr/bin/yum" ]; then
	yum install -y dos2unix git openssl-devel gcc-c++ make cmake
	# https://www.cnblogs.com/fujinzhou/p/5735578.html
	yum install -y ruby rubygems ruby-devel
	yum install -y rpm-build
fi

#Ubuntu
if [ -f "/usr/bin/apt" ]; then
	apt install -y dos2unix g++ git make zlib1g-dev libssl-dev cmake alien
	apt install -y libboost-all-dev libace-dev 
	#apt install -y libcpprest-dev libjsoncpp-dev liblog4cpp5-dev
	apt install -y ruby ruby-dev rubygems
fi

#install fpm
gem install fpm

# build boost_1_68_0 on RHEL
if [ -f "/usr/bin/yum" ]; then
	# BOOST:
	# https://www.cnblogs.com/eagle6688/p/5840773.html
	wget https://dl.bintray.com/boostorg/release/1.68.0/source/boost_1_68_0.tar.gz
	tar zxvf boost_1_68_0.tar.gz
	cd ./boost_1_68_0
	./bootstrap.sh
	./b2
	./b2 install
	ls -al /usr/local/lib*/libboost_system.so.1.68.0
	cd $ROOTDIR
fi

CMAKE=$(which cmake)
# update cmake on RHEL
if [ -f "/usr/bin/yum" ]; then
	yum install epel-release -y
	yum install cmake3 -y
	CMAKE=$(which cmake3)
fi

# cpprestsdk (use -DBUILD_SHARED_LIBS=0 for static link):
# https://stackoverflow.com/questions/49877907/cpp-rest-sdk-in-centos-7
git clone https://github.com/microsoft/cpprestsdk.git cpprestsdk
cd cpprestsdk
git submodule update --init
cd Release
$CMAKE .. -DCMAKE_BUILD_TYPE=Release -DBOOST_ROOT=/usr/local -DBUILD_SHARED_LIBS=1 -DCMAKE_CXX_FLAGS="-Wno-error=cast-align" 
make
make install
ls -al /usr/local/lib*/libcpprest.so
cd $ROOTDIR


# build log4cpp:
# https://my.oschina.net/u/1983790/blog/1587568
wget https://jaist.dl.sourceforge.net/project/log4cpp/log4cpp-1.1.x%20(new)/log4cpp-1.1/log4cpp-1.1.3.tar.gz
tar zxvf log4cpp-1.1.3.tar.gz
cd log4cpp/
./autogen.sh
./configure
make
make install
ls -al /usr/local/lib*/liblog4cpp.a
cd $ROOTDIR
	
# build jsoncpp:
git clone https://github.com/open-source-parsers/jsoncpp.git jsoncpp
cd jsoncpp
mkdir -p build/release
cd build/release
$CMAKE -DCMAKE_BUILD_TYPE=release -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DARCHIVE_INSTALL_DIR=. -G "Unix Makefiles" ../..
make
make install
ls -al /usr/local/lib*/libjsoncpp.a
cd $ROOTDIR

# build ACE on RHEL
if [ -f "/usr/bin/yum" ]; then
	# ubuntu does not need build ACE
	# ACE:
	# https://www.cnblogs.com/tanzi-888/p/5342431.html
	# http://download.dre.vanderbilt.edu/
	wget ftp://download.dre.vanderbilt.edu/previous_versions/ACE-6.5.0.tar.gz
	tar zxvf ACE-6.5.0.tar.gz
	cd ACE_wrappers
	export ACE_ROOT=`pwd`
	cp ace/config-linux.h ace/config.h
	cp include/makeinclude/platform_linux.GNU include/makeinclude/platform_macros.GNU
	make
	make install INSTALL_PREFIX=/usr/local/ace
	ls -al /usr/local/ace/lib*/libACE.so
	cd $ROOTDIR
	exit 1
fi
