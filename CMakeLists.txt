cmake_minimum_required(VERSION 2.8.8)

##########################################################################
# project
##########################################################################
cmake_policy(SET CMP0048 NEW)
project(appmesh LANGUAGES CXX VERSION 1.8.3)

##########################################################################
# C++ flag
##########################################################################
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

##########################################################################
# debug / release
##########################################################################
if (CMAKE_BUILD_TYPE MATCHES "Debug" OR CMAKE_BUILD_TYPE MATCHES "DEBUG")
    message("Debug mode")
    set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
else()
    message("Release mode")
    set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
endif()

##########################################################################
# boost
##########################################################################
set(Boost_USE_STATIC_LIBS        OFF)
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     OFF)
set(BOOST_ALL_DYN_LINK           ON)
find_package(Boost REQUIRED COMPONENTS
    system
    regex
    thread
    program_options
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
