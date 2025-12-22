# cmake/Dependencies.cmake

# Unified Dependency Finding

##########################################################################
# Boost - modern, formal, cross-platform
##########################################################################
# Minimal Boost options
set(Boost_USE_STATIC_LIBS OFF)   # Use shared libraries
# Optional: set BOOST_ROOT if installed in non-standard path (macOS Homebrew)
if(APPLE)
    set(BOOST_ROOT /opt/homebrew)
endif()
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
if (APPLE)
    # Explicitly set paths for Homebrew curl
    set(CURL_ROOT "/opt/homebrew/opt/curl")
    set(CURL_INCLUDE_DIR "${CURL_ROOT}/include")
    set(CURL_LIB "${CURL_ROOT}/lib/libcurl.dylib")

    # Verify paths manually
    find_path(CURL_INCLUDE_DIR curl/curl.h PATHS ${CURL_INCLUDE_DIR})
    find_library(CURL_LIB NAMES curl PATHS ${CURL_ROOT}/lib)

    if(NOT CURL_INCLUDE_DIR OR NOT CURL_LIB)
        message(FATAL_ERROR "Could not find CURL. Ensure CURL is installed via Homebrew.")
    endif()

    message(STATUS "CURL include dir: ${CURL_INCLUDE_DIR}")
    message(STATUS "CURL library dir: ${CURL_LIB}")

    # Include directories and link libraries
    include_directories(${CURL_INCLUDE_DIR})
    link_directories(${CURL_LIBRARY})
elseif (WIN32)
    # For Windows, use vcpkg or other package manager to find libcurl
    find_package(CURL REQUIRED)
    if (CURL_FOUND)
        message(STATUS "Found CURL: ${CURL_INCLUDE_DIRS} ${CURL_LIBRARIES}")
        set(CURL_LIB ${CURL_LIBRARIES})
    else()
        message(FATAL_ERROR "libcurl not found")
    endif()
else()
    find_library(CURL_LIB NAMES libcurl.a PATHS /usr/local/lib NO_DEFAULT_PATH)
    if (NOT CURL_LIB)
        find_package(CURL REQUIRED)
        message(STATUS "Found system libcurl: ${CURL_INCLUDE_DIRS} ${CURL_LIBRARIES}")
        set(CURL_LIB ${CURL_LIBRARIES})
    endif()
endif()
message(STATUS "Found CURL_LIB: ${CURL_LIB}")

##########################################################################
# openssl
##########################################################################
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "openssl include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "openssl library dir: ${OPENSSL_LIBRARIES}")
    message(STATUS "openssl library ver: ${OPENSSL_VERSION}.")
else()
    message(FATAL_ERROR "openssl library not found")
endif()

##########################################################################
# cryptopp (unified: vcpkg, apt, brew, and source install)
##########################################################################
# 1. First, try finding a modern CMake config (works for vcpkg/Conan)
find_package(cryptopp CONFIG QUIET)

# 2. Fallback for Manual Search (Source install, Apt, Brew)
if(NOT TARGET cryptopp::cryptopp)
    # macOS: Auto-detect Homebrew prefix for Apple Silicon/Intel
    if(APPLE)
        execute_process(
            COMMAND brew --prefix
            OUTPUT_VARIABLE BREW_PREFIX
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
    endif()

    # Search paths covering:
    # - /usr/local (Source install default)
    # - /usr/ (Apt/System default)
    # - /opt/homebrew (Apple Silicon)
    # - BREW_PREFIX (Dynamic brew)
    find_path(CRYPTOPP_INCLUDE_DIR cryptopp/cryptlib.h
        PATHS 
            ${BREW_PREFIX}/include 
            /usr/include 
            /usr/local/include 
            /opt/homebrew/include
    )

    find_library(CRYPTOPP_LIBRARY
        NAMES cryptopp libcryptopp
        PATHS 
            ${BREW_PREFIX}/lib 
            /usr/lib 
            /usr/local/lib 
            /usr/lib/x86_64-linux-gnu  # Common for multi-arch apt
            /opt/homebrew/lib
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
                "  macOS: brew install cryptopp\n"
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

if(WIN32)
    find_package(unofficial-uwebsockets CONFIG REQUIRED)
endif()
