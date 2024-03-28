cmake_minimum_required(VERSION 3.1)
string(TIMESTAMP APPMESH_BUILD_DATE "%Y-%m-%dT%H:%M:%SZ")

##########################################################################
# project
##########################################################################
cmake_policy(SET CMP0048 NEW)
project(appmesh LANGUAGES CXX VERSION 2.1.2)

##########################################################################
# C++ flag
##########################################################################
set(CMAKE_CXX_STANDARD 14)
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
find_library(CURL_LIB NAMES libcurl.a PATHS /usr/local/lib NO_DEFAULT_PATH)
if (NOT CURL_LIB)
    find_package(CURL REQUIRED)
    message(STATUS "Found system libcurl: ${CURL_INCLUDE_DIRS} ${CURL_LIBRARIES}")
    set(CURL_LIB ${CURL_LIBRARIES})
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

##########################################################################
# openldap
##########################################################################
set(LDAP_LIBRARIES ldap lber)
find_library(${LDAP_LIBRARIES} REQUIRED)

##########################################################################
# pthread
##########################################################################
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

##########################################################################
# library dir
##########################################################################
link_directories(
    /usr/local/lib64
    /usr/local/lib
)

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
    set_tests_properties(${name} PROPERTIES ENVIRONMENT "LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib:${LD_LIBRARY_PATH}")
endmacro()

if(NOT APPMESH_NO_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

##########################################################################
# package [make pack]
##########################################################################
add_custom_target(pack
    COMMENT "Packing ${CMAKE_CURRENT_BINARY_DIR}"
    COMMAND make install
    COMMAND ${CMAKE_COMMAND} -E env PROJECT_NAME=${PROJECT_NAME} PROJECT_VERSION=${PROJECT_VERSION} CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR} CMAKE_BINARY_DIR=${CMAKE_BINARY_DIR} sh ${CMAKE_SOURCE_DIR}/script/build_package.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS appc appsvc agent
)

##########################################################################
# Golang agent build
##########################################################################
add_custom_target(agent
    COMMENT "Golang build agent"
    COMMAND go build -buildvcs=false -o ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/agent ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/agent/cmd
)
file(REMOVE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/agent)

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
    COMMENT "Generate SBOM file: ${CMAKE_BINARY_DIR}/home/ with configuration file: ${CMAKE_CURRENT_SOURCE_DIR}/script/syft.yaml"
    COMMAND syft ${CMAKE_BINARY_DIR}/home/ -c ${CMAKE_CURRENT_SOURCE_DIR}/script/syft.yaml --source-name ${PROJECT_NAME} --source-version ${PROJECT_VERSION}
)
