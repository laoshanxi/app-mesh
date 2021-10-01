cmake_minimum_required(VERSION 2.8.11)
string(TIMESTAMP APPMESH_BUILD_DATE "%Y-%m-%dT%H:%M:%SZ")

##########################################################################
# project
##########################################################################
cmake_policy(SET CMP0048 NEW)
project(appmesh LANGUAGES CXX VERSION 2.0.0)

##########################################################################
# C++ flag
##########################################################################
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(BUILD_TAG ${PROJECT_NAME}_${PROJECT_VERSION}_${APPMESH_BUILD_DATE})
add_compile_options(-DBUILD_TAG=${BUILD_TAG})
message(BUILD_TAG=${BUILD_TAG})

##########################################################################
# debug / release
##########################################################################
if (CMAKE_BUILD_TYPE MATCHES "Debug" OR CMAKE_BUILD_TYPE MATCHES "DEBUG")
    message("Debug mode")
    set(CMAKE_CXX_FLAGS_DEBUG   "$ENV{CXXFLAGS} -Wall -ggdb3 -O0 -g")
else()
    message("Release mode")
    set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -Wall -ggdb3 -Os")
endif()
message("COMPILE_OPTIONS: ${COMPILE_OPTIONS}")

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
# openssl
##########################################################################
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
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
    /usr/lib64
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
    COMMAND ${CMAKE_COMMAND} -E env PROJECT_NAME=${PROJECT_NAME} PROJECT_VERSION=${PROJECT_VERSION} CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR} CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} sh ${CMAKE_CURRENT_SOURCE_DIR}/script/build_package.sh
    WORKING_DIRECTORY ${CMAKE_PROJECT_DIR}
    DEPENDS appc appsvc dockeragent
)

##########################################################################
# Golang dockeragent build
##########################################################################
add_custom_target(dockeragent
    COMMENT "Golang build dockeragent"
    COMMAND go build -o ${CMAKE_CURRENT_BINARY_DIR}/dockeragent ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/docker/dockeragent.go
)

##########################################################################
# cppcheck
##########################################################################
add_custom_target(cppcheck
    COMMENT "code static check ${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND cppcheck --enable=all --quiet --std=c++11 --platform=native ${CMAKE_CURRENT_SOURCE_DIR}
)
