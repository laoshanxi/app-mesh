cmake_minimum_required(VERSION 3.21)
if(WIN32)
    include(cmake/WindowsConfig.cmake) # Load platform config BEFORE project()
endif()

project(appmesh LANGUAGES CXX C VERSION 2.2.1)

# --- Standards ---
if(WIN32)
    set(CMAKE_CXX_STANDARD 20)
    find_package(unofficial-uwebsockets CONFIG REQUIRED)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
    set(CMAKE_CXX_STANDARD 14)
else()
    set(CMAKE_CXX_STANDARD 17)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
message(STATUS "CMAKE_CXX_STANDARD: ${CMAKE_CXX_STANDARD}")

set(BUILD_TAG ${PROJECT_NAME}_${PROJECT_VERSION}_${APPMESH_BUILD_DATE})
add_compile_options(-DBUILD_TAG=${BUILD_TAG})
message(BUILD_TAG=${BUILD_TAG})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/gen/)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/gen/)

##########################################################################
# Default to a local staging directory for packaging
##########################################################################
if(NOT DEFINED CMAKE_INSTALL_PREFIX OR CMAKE_INSTALL_PREFIX STREQUAL "" OR CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/package_root" CACHE PATH "Package staging root" FORCE)
endif()
include(GNUInstallDirs) # Standard install locations
message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")

include(${CMAKE_SOURCE_DIR}/cmake/CopyDLLs.cmake)

##########################################################################
# debug / release
##########################################################################
# Set the default build type if not specified and cache it (optional: add FORCE)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()
string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPERCASE)
message(STATUS "CMAKE_BUILD_TYPE: ${BUILD_TYPE_UPPERCASE}")

# Explicitly set flags using CMAKE_CXX_FLAGS_<CONFIG> for better control.
if (BUILD_TYPE_UPPERCASE STREQUAL "DEBUG")
    # Ensure -O0 (no optimization) for Debug
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -ggdb3 -O0")
elseif (BUILD_TYPE_UPPERCASE STREQUAL "RELEASE")
    # Ensure -O3 (high optimization) and -DNDEBUG (disable assertions) for Release
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -O3 -DNDEBUG")
elseif (BUILD_TYPE_UPPERCASE STREQUAL "MINSIZEREL")
    # Ensure -Os (size optimization) and -DNDEBUG
    set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -Wall -Os -DNDEBUG")
elseif (BUILD_TYPE_UPPERCASE STREQUAL "ASAN")
    # ASAN block remains correct for sanitizer purposes
    # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    set(CMAKE_CXX_FLAGS_ASAN "${CMAKE_CXX_FLAGS_ASAN} -Wall -ggdb3 -O0 -g -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS_ASAN "${CMAKE_EXE_LINKER_FLAGS_ASAN} -fsanitize=address -lasan -lstdc++")
else()
    message(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}")
endif()

# Print compile parameters: show the active configuration's flags (avoid duplicating the global flags in the message)
set(CMAKE_CXX_FLAGS_NAME "CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPERCASE}")
message(STATUS "${CMAKE_CXX_FLAGS_NAME}: ${${CMAKE_CXX_FLAGS_NAME}}")

# Set the library path to prioritize /usr/local/lib64
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /usr/local/lib64)

##########################################################################
# Boost - modern, formal, cross-platform
##########################################################################
# Minimal Boost options
set(BOOST_USE_MULTITHREADED ON)
set(BOOST_USE_STATIC_LIBS OFF)   # Use shared libraries
# Optional: set BOOST_ROOT if installed in non-standard path (macOS Homebrew)
if(APPLE)
    set(BOOST_ROOT /opt/homebrew)
endif()
# Modern Boost CMake: use imported targets
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
# Include Boost headers
include_directories(${Boost_INCLUDE_DIRS})
# Debug info
message(STATUS "Boost version: ${Boost_VERSION}")
message(STATUS "Boost include dirs: ${Boost_INCLUDE_DIRS}")

##########################################################################
# MessagePack    https://msgpack.org/
##########################################################################
find_package(msgpack-cxx REQUIRED)

##########################################################################
# spdlog
##########################################################################
find_package(spdlog REQUIRED)

##########################################################################
# libwebsockets  https://libwebsockets.org/
##########################################################################
find_package(libwebsockets REQUIRED)

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
message("Found CURL_LIB: ${CURL_LIB}")

##########################################################################
# openssl
##########################################################################
find_package(OpenSSL REQUIRED)
message("OPENSSL_FOUND: ${OPENSSL_FOUND}")
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "openssl include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "openssl library dir: ${OPENSSL_LIBRARIES}")
    message(STATUS "openssl library ver: ${OPENSSL_VERSION}.")
else()
    message(FATAL_ERROR "openssl library not found")
endif()
if (WIN32)
    find_package(cryptopp REQUIRED)
endif()

##########################################################################
# ACE
##########################################################################
find_library(ACE_LIBRARY ACE REQUIRED)
find_library(ACE_SSL_LIBRARY ACE_SSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(yaml-cpp REQUIRED)

##########################################################################
# openldap for none-WIN32
##########################################################################
if (NOT WIN32)
    set(LDAP_LIBRARIES ldap lber)
    find_library(${LDAP_LIBRARIES} REQUIRED)
endif()

find_package(uriparser REQUIRED)

##########################################################################
# pthread
##########################################################################
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

##########################################################################
# Include dir
##########################################################################
if(EXISTS /usr/local/include)
    include_directories(/usr/local/include)
endif()

##########################################################################
# Library dir
##########################################################################
if(EXISTS /usr/local/lib64)
    link_directories(/usr/local/lib64)
endif()
if(EXISTS /usr/local/lib)
    link_directories(/usr/local/lib)
endif()

if(APPLE)
    # Detect Apple Silicon vs Intel
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        set(HOMEBREW_PREFIX "/opt/homebrew")
        set(CMAKE_INSTALL_RPATH "/opt/homebrew/lib;/opt/appmesh/lib64")
    else()
        set(HOMEBREW_PREFIX "/usr/local")
        set(CMAKE_INSTALL_RPATH "/usr/local/lib;/opt/appmesh/lib64")
    endif()

    # Enable C++17 (used for ACE 8.0)
    # set(CMAKE_CXX_STANDARD 17)
    # set(CMAKE_CXX_STANDARD_REQUIRED ON)
    # set(CMAKE_CXX_EXTENSIONS OFF)

    # Add Homebrew include and library paths
    include_directories(${HOMEBREW_PREFIX}/include)
    link_directories(${HOMEBREW_PREFIX}/lib)

    # Add Homebrew path to CMAKE_PREFIX_PATH
    list(APPEND CMAKE_PREFIX_PATH ${HOMEBREW_PREFIX})

    # Ignore warning: 'vsprintf' is deprecated
    add_compile_options(-Wno-deprecated-declarations)

    # Optional: Add pkg-config path if needed
    set(ENV{PKG_CONFIG_PATH} "${HOMEBREW_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()

##########################################################################
# sub dir
##########################################################################
add_subdirectory(src)
# add_subdirectory(test/websockets)

##########################################################################
# Test
# cmake -APPMESH_NO_TESTS=1 ..
# make & make test ARGS="-V"
# https://cmake.org/pipermail/cmake/2005-December/007778.html
# https://stackoverflow.com/questions/49923562/how-to-force-cmake-to-write-test-output-after-make-test?r=SearchResults
##########################################################################
macro(add_catch_test name)
    if (TEST_REPORT_FORMAT)
        add_test(NAME ${name} COMMAND ${name} -r ${TEST_REPORT_FORMAT} -o "${name}.test_out.xml")
    else()
        add_test(NAME ${name} COMMAND ${name})
    endif()
    if(APPLE)
        set(LIB_PATH_VAR DYLD_LIBRARY_PATH)
    else()
        set(LIB_PATH_VAR LD_LIBRARY_PATH)
    endif()
    set_tests_properties(${name} PROPERTIES ENVIRONMENT "${LIB_PATH_VAR}=/usr/local/lib64:/usr/local/lib:$ENV{${LIB_PATH_VAR}}")

endmacro()

if(NOT APPMESH_NO_TESTS)
    enable_testing()
    # add_subdirectory(test)
    # Python test
    #add_test(
    #    NAME python_tests
    #    COMMAND python3 -m unittest ${CMAKE_SOURCE_DIR}/src/sdk/python/test/test_appmesh_client.py 
    #)
    # Golang test
    #add_test(
    #    NAME go_tests
    #    COMMAND go test ${CMAKE_SOURCE_DIR}/src/sdk/go/ -test.v
    #)
    add_custom_target(python_tests
        COMMAND python3 -m unittest
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/sdk/python/test/
        COMMENT "Running Python tests..."
        VERBATIM
    )
    add_custom_target(go_tests
        COMMAND go test ${CMAKE_SOURCE_DIR}/src/sdk/go/ -test.v
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Running Golang tests..."
        VERBATIM
    )
endif()

##########################################################################
# package [make pack]
##########################################################################
if(WIN32)
    set(PACKAGING_COMMAND powershell -ExecutionPolicy Bypass -NoProfile -File ${CMAKE_SOURCE_DIR}/script/pack/build_package.ps1)
    set(BUILD_TYPE_ENV $<CONFIG>)
else()
    set(PACKAGING_COMMAND bash ${CMAKE_SOURCE_DIR}/script/pack/build_package.sh)
    set(BUILD_TYPE_ENV ${CMAKE_BUILD_TYPE})
endif()

add_custom_target(pack
    COMMENT "Packing ${CMAKE_CURRENT_BINARY_DIR}"
    COMMAND ${CMAKE_COMMAND} -E env 
        PROJECT_NAME=${PROJECT_NAME} 
        PROJECT_VERSION=${PROJECT_VERSION} 
        CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR} 
        CMAKE_BINARY_DIR=${CMAKE_BINARY_DIR} 
        CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        BUILD_TYPE=${BUILD_TYPE_ENV}
        ${PACKAGING_COMMAND}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS appc appsvc agent
)


##########################################################################
# Golang agent build
##########################################################################
set(AGENT_BIN ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/agent${CMAKE_EXECUTABLE_SUFFIX})

add_custom_target(agent ALL
    COMMAND go build -buildvcs=false -o ${AGENT_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/agent/cmd
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/agent/cmd
    COMMENT "Golang build agent"
    VERBATIM
)

##########################################################################
# cppcheck
##########################################################################
add_custom_target(cppcheck
    COMMENT "code static check ${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND cppcheck --enable=all --quiet --std=c++11 --platform=native ${CMAKE_CURRENT_SOURCE_DIR}
)

##########################################################################
# SBOM
# in-order to include Python packages:
#   create venv under home and use pip install appmesh
##########################################################################
add_custom_target(sbom
    COMMENT "Generate SBOM dependency list from ${CMAKE_INSTALL_PREFIX} with configuration file: ${CMAKE_CURRENT_SOURCE_DIR}/script/sbom/syft.yaml"
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/script/sbom/syft_dpkg_generate.sh
    COMMAND syft ${CMAKE_INSTALL_PREFIX}/ -c ${CMAKE_CURRENT_SOURCE_DIR}/script/sbom/syft.yaml --source-name ${PROJECT_NAME} --source-version ${PROJECT_VERSION}
)
