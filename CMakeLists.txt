cmake_minimum_required(VERSION 3.21)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
if(WIN32)
    include(cmake/WindowsConfig.cmake) # Load platform config BEFORE project()
endif()

project(appmesh LANGUAGES CXX C VERSION 2.2.1)

# --- Standards ---
if(WIN32)
    set(CMAKE_CXX_STANDARD 20)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
    set(CMAKE_CXX_STANDARD 14)
else()
    set(CMAKE_CXX_STANDARD 17)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
message(STATUS "CMAKE_CXX_STANDARD: ${CMAKE_CXX_STANDARD}")

string(TIMESTAMP APPMESH_BUILD_DATE "%Y-%m-%dT%H:%M:%SZ")
set(BUILD_TAG ${PROJECT_NAME}_${PROJECT_VERSION}_${APPMESH_BUILD_DATE})
add_compile_options(-DBUILD_TAG=${BUILD_TAG})
message(STATUS BUILD_TAG=${BUILD_TAG})

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/gen/)

##########################################################################
# Default to a local staging directory for packaging
##########################################################################
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/package_root" CACHE PATH "Package staging root" FORCE)
endif()
include(GNUInstallDirs) # Standard install locations
message(STATUS "Package staging root: ${CMAKE_INSTALL_PREFIX}")

include(${CMAKE_SOURCE_DIR}/cmake/CopyDLLs.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/Dependencies.cmake)

##########################################################################
# Build Type
##########################################################################
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
endif()
# Common warnings
add_compile_options(-Wall)
# ASAN (optional)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address)
endif()

##########################################################################
# APPLE
##########################################################################
if(APPLE)
    # Detect Homebrew prefix
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(HOMEBREW_PREFIX "/opt/homebrew")
    else()
        set(HOMEBREW_PREFIX "/usr/local")
    endif()

    # Prefer Homebrew packages
    list(PREPEND CMAKE_PREFIX_PATH "${HOMEBREW_PREFIX}")

    # RPATH: append, do not overwrite
    list(APPEND CMAKE_INSTALL_RPATH
        "${HOMEBREW_PREFIX}/lib"
        "/opt/appmesh/lib64"
    )

    # pkg-config (optional but explicit)
    set(ENV{PKG_CONFIG_PATH} "${HOMEBREW_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()

##########################################################################
# sub dir
##########################################################################
add_subdirectory(src)
add_subdirectory(script/sbom)

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
# cppcheck
##########################################################################
add_custom_target(cppcheck
    COMMENT "code static check ${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND cppcheck --enable=all --quiet --std=c++11 --platform=native ${CMAKE_CURRENT_SOURCE_DIR}
)
