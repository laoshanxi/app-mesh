cmake_minimum_required(VERSION 3.10)
string(TIMESTAMP APPMESH_BUILD_DATE "%Y-%m-%dT%H:%M:%SZ")

##########################################################################
# project
##########################################################################
cmake_policy(SET CMP0048 NEW)
project(appmesh LANGUAGES CXX VERSION 2.1.2)

##########################################################################
# C++ flag
##########################################################################
if(NOT WIN32)
    set(CMAKE_CXX_STANDARD 14)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BUILD_TAG ${PROJECT_NAME}_${PROJECT_VERSION}_${APPMESH_BUILD_DATE})
add_compile_options(-DBUILD_TAG=${BUILD_TAG})
message(BUILD_TAG=${BUILD_TAG})
# set(CMAKE_C_COMPILER "/usr/bin/gcc")
# set(CMAKE_CXX_COMPILER "/usr/bin/g++")
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/gen/)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/gen/)

##########################################################################
# debug / release
##########################################################################
# Set the default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPERCASE)
message(STATUS "CMAKE_BUILD_TYPE: ${BUILD_TYPE_UPPERCASE}")

# Set compiler flags based on the build type
if (BUILD_TYPE_UPPERCASE STREQUAL "DEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -ggdb3 -O0")
elseif (BUILD_TYPE_UPPERCASE STREQUAL "RELEASE")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")
elseif (BUILD_TYPE_UPPERCASE STREQUAL "MINSIZEREL")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL}")
elseif (BUILD_TYPE_UPPERCASE STREQUAL "ASAN")
    # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    set(CMAKE_CXX_FLAGS_ASAN "${CMAKE_CXX_FLAGS_ASAN} -Wall -ggdb3 -O0 -g -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS_ASAN "${CMAKE_EXE_LINKER_FLAGS_ASAN} -fsanitize=address -lasan -lstdc++")
else ()
    message(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}")
endif()
# Print compile parameters: FLAGS = CMAKE_CXX_FLAGS + CMAKE_CXX_FLAGS_RELEASE
set(CMAKE_CXX_FLAGS_NAME "CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPERCASE}")
message(STATUS "${CMAKE_CXX_FLAGS_NAME}: ${CMAKE_CXX_FLAGS} ${${CMAKE_CXX_FLAGS_NAME}}")

# Set the library path to prioritize /usr/local/lib64
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /usr/local/lib64)

##########################################################################
# boost
##########################################################################
set(Boost_USE_STATIC_LIBS        OFF)
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     OFF)
set(BOOST_ALL_DYN_LINK           ON)
find_package(Boost REQUIRED COMPONENTS
    system
    filesystem
    regex
    thread
    program_options
    date_time
)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR})
    link_directories(${Boost_LIBRARY_DIRS})
    message(STATUS "boost include dir: ${Boost_INCLUDE_DIRS}")
    message(STATUS "boost library dir: ${Boost_LIBRARIES}")
    message(STATUS "boost library ver: ${Boost_LIB_VERSION}.")
else()
    message(FATAL_ERROR "boost library not found")
endif()

##########################################################################
# MessagePack    https://msgpack.org/
##########################################################################
find_package(msgpack-cxx REQUIRED)

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
    COMMENT "Generate SBOM dependency list from ${CMAKE_BINARY_DIR}/nfpm_home/ with configuration file: ${CMAKE_CURRENT_SOURCE_DIR}/script/sbom/syft.yaml"
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/script/sbom/syft_dpkg_generate.sh
    COMMAND syft ${CMAKE_BINARY_DIR}/nfpm_home/ -c ${CMAKE_CURRENT_SOURCE_DIR}/script/sbom/syft.yaml --source-name ${PROJECT_NAME} --source-version ${PROJECT_VERSION}
)
