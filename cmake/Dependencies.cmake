# cmake/Dependencies.cmake

# Unified Dependency Finding

##########################################################################
# Boost - modern, formal, cross-platform
##########################################################################
# Minimal Boost options
set(Boost_USE_STATIC_LIBS OFF)   # Use shared libraries
find_package(Boost 1.76 REQUIRED COMPONENTS
    system
    filesystem
    regex
    thread
    program_options
    date_time
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
# libwebsockets  https://libwebsockets.org/
##########################################################################
find_package(libwebsockets CONFIG REQUIRED)

##########################################################################
# libcurl
##########################################################################
find_library(CURL_LIB NAMES libcurl.a PATHS /usr/local/lib NO_DEFAULT_PATH)
if (NOT CURL_LIB)
    find_package(CURL REQUIRED)
    message(STATUS "Found system libcurl: ${CURL_INCLUDE_DIRS} ${CURL_LIBRARIES}")
    set(CURL_LIB ${CURL_LIBRARIES})
endif()
message(STATUS "Found CURL_LIB: ${CURL_LIB}")

##########################################################################
# openssl
##########################################################################
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    # Ensure linker can resolve bare -lssl/-lcrypto from third-party libs (e.g. libwebsockets)
    # when OpenSSL is installed in a non-standard path like /usr/local/ssl
    get_filename_component(_openssl_lib_dir "${OPENSSL_SSL_LIBRARY}" DIRECTORY)
    link_directories("${_openssl_lib_dir}")
    message(STATUS "openssl library dir: ${_openssl_lib_dir}")
    message(STATUS "openssl include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "openssl library ver: ${OPENSSL_VERSION}.")
else()
    message(FATAL_ERROR "openssl library not found")
endif()

##########################################################################
# cryptopp (unified: apt and source install)
##########################################################################
# 1. First, try finding a modern CMake config
find_package(cryptopp CONFIG QUIET)

# 2. Fallback for Manual Search (Source install, Apt)
if(NOT TARGET cryptopp::cryptopp)
    find_path(CRYPTOPP_INCLUDE_DIR cryptopp/cryptlib.h
        PATHS
            /usr/include
            /usr/local/include
    )

    find_library(CRYPTOPP_LIBRARY
        NAMES cryptopp libcryptopp
        PATHS
            /usr/lib
            /usr/local/lib
            /usr/lib/x86_64-linux-gnu  # Common for multi-arch apt
    )

    if(CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_LIBRARY)
        add_library(cryptopp::cryptopp UNKNOWN IMPORTED)
        set_target_properties(cryptopp::cryptopp PROPERTIES
            IMPORTED_LOCATION "${CRYPTOPP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTOPP_INCLUDE_DIR}"
        )
    else()
        message(FATAL_ERROR "Crypto++ not found! \n"
                "  Linux: sudo apt install libcrypto++-dev\n"
                "  Source: ensure 'make install' was run.")
    endif()
endif()

set(CRYPTOPP_TARGET cryptopp::cryptopp)

##########################################################################
# ACE
##########################################################################
find_library(ACE_LIBRARY ACE REQUIRED)
find_library(ACE_SSL_LIBRARY ACE_SSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(yaml-cpp REQUIRED)

find_package(uriparser REQUIRED)

##########################################################################
# pthread
##########################################################################
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

