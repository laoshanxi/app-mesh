# cmake/Dependencies.cmake

# Unified Dependency Finding

##########################################################################
# Boost - modern, formal, cross-platform
##########################################################################
# Minimal Boost options
set(Boost_USE_STATIC_LIBS OFF)   # Use shared libraries
# Optional: set Boost_ROOT if installed in non-standard path (macOS Homebrew).
# <PackageName>_ROOT works on every CMake; the upper-case form needs CMP0144.
if(APPLE)
    set(Boost_ROOT /opt/homebrew)
endif()
# 1.86 is the first release with the Boost.Process V2 asio engine the daemon uses.
find_package(Boost 1.86 REQUIRED COMPONENTS
    system
    regex
    thread
    program_options
    date_time
    process
)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Boost not found")
endif()
# Debug info
message(STATUS "Boost version: ${Boost_VERSION}")
message(STATUS "Boost include dirs: ${Boost_INCLUDE_DIRS}")

##########################################################################
# MessagePack    https://msgpack.org/
##########################################################################
find_path(MSGPACK_INCLUDE_DIR msgpack.hpp)
if(NOT MSGPACK_INCLUDE_DIR)
  message(FATAL_ERROR "msgpack-cxx not found. Please install it.")
endif()
add_library(msgpack-cxx INTERFACE)
target_include_directories(msgpack-cxx INTERFACE ${MSGPACK_INCLUDE_DIR})

##########################################################################
# spdlog
##########################################################################
find_package(spdlog REQUIRED)

##########################################################################
# openssl
##########################################################################
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    if(NOT WIN32)
        # Ensure linker can resolve bare -lssl/-lcrypto from third-party libs
        # when OpenSSL is installed in a non-standard path like /usr/local/ssl
        # Skip on Windows: vcpkg toolchain handles library paths, and OPENSSL_SSL_LIBRARY
        # contains optimized/debug generator expressions that break get_filename_component.
        get_filename_component(_openssl_lib_dir "${OPENSSL_SSL_LIBRARY}" DIRECTORY)
        link_directories("${_openssl_lib_dir}")
        message(STATUS "openssl library dir: ${_openssl_lib_dir}")
    endif()
    message(STATUS "openssl include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "openssl library ver: ${OPENSSL_VERSION}.")
else()
    message(FATAL_ERROR "openssl library not found")
endif()

find_package(yaml-cpp REQUIRED)

find_package(uriparser REQUIRED)

##########################################################################
# pthread
##########################################################################
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

##########################################################################
# Drogon (HTTPS/WSS/TCP transport)
##########################################################################
find_package(Drogon CONFIG REQUIRED)
message(STATUS "HTTPS/WSS transport: Drogon ${Drogon_VERSION}")

##########################################################################
# jsoncpp (JSON DOM shared with Drogon)
##########################################################################
# Drogon's package config looks jsoncpp up itself, and the homebrew
# jsoncppConfig.cmake defines its target without a guard, so a second lookup
# fails with a duplicate target.
if(TARGET jsoncpp_lib)
    get_target_property(JSONCPP_INCLUDE_DIRS jsoncpp_lib INTERFACE_INCLUDE_DIRECTORIES)
else()
    find_package(jsoncpp CONFIG REQUIRED)
endif()
# json/json.h sits in a non-default prefix on apt; not all targets link common
include_directories(${JSONCPP_INCLUDE_DIRS})
